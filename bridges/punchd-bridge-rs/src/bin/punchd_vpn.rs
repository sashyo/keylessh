///! punchd-vpn: VPN client that tunnels IP traffic through a punchd-bridge-rs gateway.
///!
///! Creates a local TUN interface and routes IP packets through a WebRTC
///! DataChannel to a punchd-bridge gateway, which forwards them to its LAN.
///!
///! Usage:
///!   punchd-vpn --stun-server wss://stun.example.com --gateway-id my-gateway --config tidecloak.json

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use bytes::Bytes;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_tungstenite::tungstenite::Message;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

const VPN_TUNNEL_MAGIC: u8 = 0x04;
const AGENT_PORT: u16 = 19877;

#[derive(Parser, Debug)]
#[command(name = "punchd-vpn", about = "VPN client for punchd-bridge gateways")]
struct Args {
    /// STUN signaling server WebSocket URL
    #[arg(long)]
    stun_server: Option<String>,

    /// Target gateway ID to connect to
    #[arg(long)]
    gateway_id: Option<String>,

    /// Path to tidecloak.json config file
    #[arg(long)]
    config: Option<String>,

    /// Base64-encoded tidecloak.json (alternative to --config file)
    #[arg(long)]
    config_b64: Option<String>,

    /// ICE/STUN server URL (e.g., stun:turn.example.com:3478)
    #[arg(long)]
    ice_server: Option<String>,

    /// TURN server URL
    #[arg(long)]
    turn_server: Option<String>,

    /// TURN secret for credential generation
    #[arg(long)]
    turn_secret: Option<String>,

    /// TUN device name (default: punchd-vpn0)
    #[arg(long, default_value = "punchd-vpn0")]
    tun_name: String,

    /// Set default route through VPN
    #[arg(long, default_value_t = false)]
    default_route: bool,

    /// Run in standalone CLI mode (OIDC login, single connection). Default is agent mode.
    #[arg(long, default_value_t = false)]
    standalone: bool,

    /// Run as a Windows Service (used by the service control manager, not manually)
    #[arg(long, default_value_t = false)]
    service: bool,

    /// Install as a Windows Service
    #[arg(long, default_value_t = false)]
    install_service: bool,

    /// Uninstall the Windows Service
    #[arg(long, default_value_t = false)]
    uninstall_service: bool,

    /// Pre-authenticated access token (skip OIDC login)
    #[arg(long)]
    token: Option<String>,
}

/// Saved config file (vpn-config.toml next to the exe)
#[derive(Deserialize, serde::Serialize, Clone, Debug, Default)]
struct VpnFileConfig {
    #[serde(default)]
    stun_server: Option<String>,
    #[serde(default)]
    gateway_id: Option<String>,
    #[serde(default)]
    tidecloak_config_path: Option<String>,
    #[serde(default)]
    tidecloak_config_b64: Option<String>,
    #[serde(default)]
    ice_server: Option<String>,
    #[serde(default)]
    turn_server: Option<String>,
    #[serde(default)]
    turn_secret: Option<String>,
    #[serde(default)]
    default_route: Option<bool>,
}

#[derive(Deserialize, Clone, Debug)]
struct TcConfig {
    realm: String,
    #[serde(rename = "auth-server-url")]
    auth_server_url: String,
    resource: String,
}

/// Resolve the config file path.
/// Windows: C:\ProgramData\punchd-vpn\vpn-config.toml (accessible by service + user)
/// Linux: next to the exe
fn config_file_path() -> std::path::PathBuf {
    #[cfg(target_os = "windows")]
    {
        let dir = std::path::PathBuf::from(r"C:\ProgramData\punchd-vpn");
        let _ = std::fs::create_dir_all(&dir);
        dir.join("vpn-config.toml")
    }
    #[cfg(not(target_os = "windows"))]
    {
        let etc_path = std::path::PathBuf::from("/etc/punchd-vpn/vpn-config.toml");
        if etc_path.exists() || etc_path.parent().map(|p| p.exists()).unwrap_or(false) {
            etc_path
        } else {
            // Fallback: next to the exe (development/portable mode)
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("vpn-config.toml")))
                .unwrap_or_else(|| std::path::PathBuf::from("vpn-config.toml"))
        }
    }
}

/// Load saved config from vpn-config.toml
fn load_file_config() -> VpnFileConfig {
    let path = config_file_path();
    if path.exists() {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        toml::from_str(&text).unwrap_or_default()
    } else {
        VpnFileConfig::default()
    }
}

/// Merge CLI args with file config (CLI takes priority)
fn merge_args(args: &Args, file_cfg: &VpnFileConfig) -> (String, String, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>, bool) {
    let stun = args.stun_server.clone()
        .or_else(|| file_cfg.stun_server.clone())
        .unwrap_or_default();
    let gw = args.gateway_id.clone()
        .or_else(|| file_cfg.gateway_id.clone())
        .unwrap_or_default();
    let tc_path = args.config.clone()
        .or_else(|| file_cfg.tidecloak_config_path.clone());
    let tc_b64 = args.config_b64.clone()
        .or_else(|| file_cfg.tidecloak_config_b64.clone());
    let ice = args.ice_server.clone()
        .or_else(|| file_cfg.ice_server.clone());
    let turn = args.turn_server.clone()
        .or_else(|| file_cfg.turn_server.clone());
    let turn_secret = args.turn_secret.clone()
        .or_else(|| file_cfg.turn_secret.clone());
    let default_route = args.default_route || file_cfg.default_route.unwrap_or(false);
    (stun, gw, tc_path, tc_b64, ice, turn, turn_secret, default_route)
}

/// Interactive first-run setup — prompts user in the terminal
fn run_first_time_setup() -> VpnFileConfig {
    #[cfg(target_os = "windows")]
    {
        run_gui_setup()
    }
    #[cfg(not(target_os = "windows"))]
    {
        run_cli_setup()
    }
}

#[cfg(target_os = "windows")]
fn run_gui_setup() -> VpnFileConfig {
    use rfd::{FileDialog, MessageDialog, MessageLevel, MessageButtons};

    // Ask user to select their vpn-config.toml
    MessageDialog::new()
        .set_title("Punchd VPN Setup")
        .set_description("Welcome to Punchd VPN.\n\nPlease select your vpn-config.toml file.")
        .set_level(MessageLevel::Info)
        .set_buttons(MessageButtons::Ok)
        .show();

    let source = FileDialog::new()
        .set_title("Select vpn-config.toml")
        .add_filter("TOML Config", &["toml"])
        .add_filter("All Files", &["*"])
        .pick_file();

    let source = match source {
        Some(p) => p,
        None => {
            MessageDialog::new()
                .set_title("Punchd VPN")
                .set_description("Setup cancelled. No config file selected.")
                .set_level(MessageLevel::Warning)
                .set_buttons(MessageButtons::Ok)
                .show();
            std::process::exit(0);
        }
    };

    // Validate the config
    let content = match std::fs::read_to_string(&source) {
        Ok(s) => s,
        Err(e) => {
            MessageDialog::new()
                .set_title("Punchd VPN — Error")
                .set_description(&format!("Could not read file:\n{e}"))
                .set_level(MessageLevel::Error)
                .set_buttons(MessageButtons::Ok)
                .show();
            std::process::exit(1);
        }
    };

    let cfg: VpnFileConfig = match toml::from_str(&content) {
        Ok(c) => c,
        Err(e) => {
            MessageDialog::new()
                .set_title("Punchd VPN — Error")
                .set_description(&format!("Invalid config file:\n{e}"))
                .set_level(MessageLevel::Error)
                .set_buttons(MessageButtons::Ok)
                .show();
            std::process::exit(1);
        }
    };

    if cfg.stun_server.is_none() || cfg.gateway_id.is_none() {
        MessageDialog::new()
            .set_title("Punchd VPN — Error")
            .set_description("Config file is missing required fields:\n- stun_server\n- gateway_id")
            .set_level(MessageLevel::Error)
            .set_buttons(MessageButtons::Ok)
            .show();
        std::process::exit(1);
    }

    // Copy to ProgramData
    let dest = config_file_path();
    if let Some(parent) = dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::copy(&source, &dest) {
        MessageDialog::new()
            .set_title("Punchd VPN — Error")
            .set_description(&format!("Could not save config to {}:\n{e}", dest.display()))
            .set_level(MessageLevel::Error)
            .set_buttons(MessageButtons::Ok)
            .show();
        std::process::exit(1);
    }

    cfg
}

#[cfg(not(target_os = "windows"))]
fn run_cli_setup() -> VpnFileConfig {
    use std::io::{self, Write};

    println!("╔══════════════════════════════════════╗");
    println!("║    Punchd VPN — First Time Setup     ║");
    println!("╚══════════════════════════════════════╝");
    println!();

    let prompt = |label: &str, hint: &str| -> String {
        print!("{label}");
        if !hint.is_empty() {
            print!(" ({hint})");
        }
        print!(": ");
        io::stdout().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        input.trim().to_string()
    };

    let stun = prompt("STUN server URL", "e.g. wss://stun.example.com");
    let gw = prompt("Gateway ID", "e.g. SashasKC");
    let tc_path = prompt("Path to tidecloak.json", "or press Enter to paste base64");

    let mut cfg = VpnFileConfig {
        stun_server: if stun.is_empty() { None } else { Some(stun) },
        gateway_id: if gw.is_empty() { None } else { Some(gw) },
        ..Default::default()
    };

    if tc_path.is_empty() {
        let b64 = prompt("Paste tidecloak.json as base64", "");
        if !b64.is_empty() {
            cfg.tidecloak_config_b64 = Some(b64);
        }
    } else {
        cfg.tidecloak_config_path = Some(tc_path);
    }

    let ice = prompt("ICE/STUN server", "e.g. stun:turn.example.com:3478, or Enter to skip");
    if !ice.is_empty() {
        cfg.ice_server = Some(ice);
    }

    let turn = prompt("TURN server", "e.g. turn:turn.example.com:3478, or Enter to skip");
    if !turn.is_empty() {
        cfg.turn_server = Some(turn);
        let secret = prompt("TURN secret", "or Enter to skip");
        if !secret.is_empty() {
            cfg.turn_secret = Some(secret);
        }
    }

    let dest = config_file_path();
    if let Some(parent) = dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    match toml::to_string_pretty(&cfg) {
        Ok(toml_str) => {
            if let Err(e) = std::fs::write(&dest, &toml_str) {
                eprintln!("Warning: could not save config to {}: {e}", dest.display());
            } else {
                println!("\nConfig saved to: {}", dest.display());
            }
        }
        Err(e) => eprintln!("Warning: could not serialize config: {e}"),
    }

    println!();
    cfg
}

// Import the TUN device from the main crate
#[path = "../vpn/tun_device.rs"]
mod tun_device;

#[path = "../quic/transport.rs"]
mod quic_transport;

#[path = "../quic/turn_client.rs"]
mod turn_client;

#[path = "../vpn/webview_auth.rs"]
mod webview_auth;

// ── Windows Service support ───────────────────────────────────────────

const SERVICE_NAME: &str = "punchd-vpn";
const SERVICE_DISPLAY_NAME: &str = "Punchd VPN Service";

#[cfg(target_os = "windows")]
mod win_service {
    use super::*;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    static SERVICE_STOP: std::sync::OnceLock<Arc<Notify>> = std::sync::OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    pub fn run_as_service() -> Result<(), String> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
            .map_err(|e| format!("Failed to start service dispatcher: {e}"))
    }

    fn service_main(_arguments: Vec<std::ffi::OsString>) {
        if let Err(e) = run_service() {
            tracing::error!("[Service] Fatal error: {e}");
        }
    }

    fn run_service() -> Result<(), String> {
        let stop_notify = Arc::new(Notify::new());
        SERVICE_STOP.set(stop_notify.clone()).ok();

        let event_handler = move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    tracing::info!("[Service] Stop requested");
                    if let Some(n) = SERVICE_STOP.get() {
                        n.notify_waiters();
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        };

        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
            .map_err(|e| format!("Failed to register service control handler: {e}"))?;

        // Report running
        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: std::time::Duration::default(),
                process_id: None,
            })
            .map_err(|e| format!("Failed to set service status: {e}"))?;

        // Build and run the tokio runtime
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| format!("Failed to create tokio runtime: {e}"))?;

        rt.block_on(async {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("Failed to install rustls crypto provider");

            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("punchd_vpn=debug,warn")),
                )
                .init();

            tracing::info!("[Service] Punchd VPN service started");

            // Start agent HTTP server
            tokio::spawn(async {
                if let Err(e) = run_agent().await {
                    tracing::error!("Agent error: {e}");
                }
            });

            // Auto-connect if config exists
            let file_cfg = load_file_config();
            let has_config = file_cfg.stun_server.is_some() && file_cfg.gateway_id.is_some();

            if has_config {
                let args = Args::parse_from::<[&str; 0], &str>([]);
                let (stun_server, gateway_id, tc_path, tc_b64, ice_server, turn_server, turn_secret, default_route) =
                    merge_args(&args, &file_cfg);

                if !stun_server.is_empty() && !gateway_id.is_empty() {
                    let resolved = ResolvedConfig {
                        stun_server,
                        gateway_id,
                        tc_path,
                        tc_b64,
                        ice_server,
                        turn_server,
                        turn_secret,
                        tun_name: "punchd-vpn0".to_string(),
                        default_route,
                        token: args.token.clone(),
                    };

                    let resolved = Arc::new(resolved);
                    let stop = stop_notify.clone();
                    tokio::spawn(async move {
                        let mut backoff_secs: u64 = 2;
                        const MAX_BACKOFF: u64 = 60;

                        loop {
                            tracing::info!("[VPN] Connecting...");
                            tokio::select! {
                                result = run_vpn((*resolved).clone()) => {
                                    match result {
                                        Ok(()) => {
                                            tracing::info!("[VPN] Disconnected cleanly");
                                            backoff_secs = 2;
                                        }
                                        Err(e) => {
                                            tracing::error!("[VPN] Connection error: {e}");
                                        }
                                    }
                                    tracing::info!("[VPN] Reconnecting in {backoff_secs}s...");
                                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                                    backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF);
                                }
                                _ = stop.notified() => {
                                    tracing::info!("[VPN] Service stop — disconnecting");
                                    break;
                                }
                            }
                        }
                    });
                }
            }

            // Wait for stop signal
            stop_notify.notified().await;
            tracing::info!("[Service] Shutting down...");
        });

        // Report stopped
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: std::time::Duration::default(),
            process_id: None,
        });

        Ok(())
    }

    pub fn install() -> Result<(), String> {
        use windows_service::service::{ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType};
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CREATE_SERVICE | ServiceManagerAccess::CONNECT,
        ).map_err(|e| format!("Failed to open service manager (run as admin): {e}"))?;

        // If already installed, stop and delete first
        if let Ok(existing) = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::STOP) {
            let _ = existing.stop();
            std::thread::sleep(std::time::Duration::from_secs(1));
            let _ = existing.delete();
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Failed to get exe path: {e}"))?;

        let service_info = ServiceInfo {
            name: SERVICE_NAME.into(),
            display_name: SERVICE_DISPLAY_NAME.into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe_path,
            launch_arguments: vec!["--service".into()],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };

        let service = manager
            .create_service(&service_info, ServiceAccess::START | ServiceAccess::CHANGE_CONFIG)
            .map_err(|e| format!("Failed to create service: {e}"))?;

        // Start it immediately
        service.start::<&str>(&[])
            .map_err(|e| format!("Service installed but failed to start: {e}"))?;

        println!("Service '{SERVICE_DISPLAY_NAME}' installed and started.");
        Ok(())
    }

    /// Check if we're running with admin privileges
    pub fn is_elevated() -> bool {
        windows_service::service_manager::ServiceManager::local_computer(
            None::<&str>,
            windows_service::service_manager::ServiceManagerAccess::CONNECT,
        ).is_ok()
    }

    /// Re-launch ourselves as admin (UAC prompt)
    pub fn elevate_and_install() -> ! {
        use std::os::windows::ffi::OsStrExt;
        use std::ffi::OsStr;
        use std::ptr;

        let exe = std::env::current_exe().expect("Failed to get exe path");
        let exe_wide: Vec<u16> = OsStr::new(&exe).encode_wide().chain(std::iter::once(0)).collect();
        let args = OsStr::new("--install-service");
        let args_wide: Vec<u16> = args.encode_wide().chain(std::iter::once(0)).collect();
        let verb = OsStr::new("runas");
        let verb_wide: Vec<u16> = verb.encode_wide().chain(std::iter::once(0)).collect();

        #[repr(C)]
        struct ShellExecuteInfoW {
            cb_size: u32,
            f_mask: u32,
            hwnd: *mut std::ffi::c_void,
            lp_verb: *const u16,
            lp_file: *const u16,
            lp_parameters: *const u16,
            lp_directory: *const u16,
            n_show: i32,
            h_inst_app: *mut std::ffi::c_void,
            lp_id_list: *mut std::ffi::c_void,
            lp_class: *const u16,
            hkey_class: *mut std::ffi::c_void,
            dw_hot_key: u32,
            h_icon_or_monitor: *mut std::ffi::c_void,
            h_process: *mut std::ffi::c_void,
        }

        unsafe extern "system" {
            fn ShellExecuteExW(info: *mut ShellExecuteInfoW) -> i32;
        }

        let mut info = ShellExecuteInfoW {
            cb_size: std::mem::size_of::<ShellExecuteInfoW>() as u32,
            f_mask: 0,
            hwnd: ptr::null_mut(),
            lp_verb: verb_wide.as_ptr(),
            lp_file: exe_wide.as_ptr(),
            lp_parameters: args_wide.as_ptr(),
            lp_directory: ptr::null(),
            n_show: 1, // SW_SHOWNORMAL
            h_inst_app: ptr::null_mut(),
            lp_id_list: ptr::null_mut(),
            lp_class: ptr::null(),
            hkey_class: ptr::null_mut(),
            dw_hot_key: 0,
            h_icon_or_monitor: ptr::null_mut(),
            h_process: ptr::null_mut(),
        };

        unsafe {
            ShellExecuteExW(&mut info);
        }

        std::process::exit(0);
    }

    pub fn uninstall() -> Result<(), String> {
        use windows_service::service::ServiceAccess;
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT,
        ).map_err(|e| format!("Failed to open service manager (run as admin): {e}"))?;

        let service = manager
            .open_service(SERVICE_NAME, ServiceAccess::DELETE | ServiceAccess::STOP)
            .map_err(|e| format!("Service not found: {e}"))?;

        // Try to stop first
        let _ = service.stop();
        std::thread::sleep(std::time::Duration::from_secs(1));

        service.delete()
            .map_err(|e| format!("Failed to delete service: {e}"))?;

        println!("Service '{SERVICE_DISPLAY_NAME}' uninstalled.");
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("punchd_vpn=debug,warn")),
        )
        .init();

    let args = Args::parse();

    // Handle Windows Service modes
    #[cfg(target_os = "windows")]
    {
        if args.service {
            // Running as a Windows Service — hand off to the service dispatcher
            match win_service::run_as_service() {
                Ok(()) => std::process::exit(0),
                Err(e) => {
                    eprintln!("Service error: {e}");
                    std::process::exit(1);
                }
            }
        }

        if args.install_service {
            match win_service::install() {
                Ok(()) => {
                    rfd::MessageDialog::new()
                        .set_title("Punchd VPN")
                        .set_description("Punchd VPN service installed and started.\n\nIt will start automatically on boot.")
                        .set_level(rfd::MessageLevel::Info)
                        .set_buttons(rfd::MessageButtons::Ok)
                        .show();
                    std::process::exit(0);
                }
                Err(e) => {
                    rfd::MessageDialog::new()
                        .set_title("Punchd VPN — Error")
                        .set_description(&format!("Failed to install service:\n{e}"))
                        .set_level(rfd::MessageLevel::Error)
                        .set_buttons(rfd::MessageButtons::Ok)
                        .show();
                    std::process::exit(1);
                }
            }
        }

        if args.uninstall_service {
            match win_service::uninstall() {
                Ok(()) => {
                    rfd::MessageDialog::new()
                        .set_title("Punchd VPN")
                        .set_description("Punchd VPN service uninstalled.")
                        .set_level(rfd::MessageLevel::Info)
                        .set_buttons(rfd::MessageButtons::Ok)
                        .show();
                    std::process::exit(0);
                }
                Err(e) => {
                    rfd::MessageDialog::new()
                        .set_title("Punchd VPN — Error")
                        .set_description(&format!("Failed to uninstall service:\n{e}"))
                        .set_level(rfd::MessageLevel::Error)
                        .set_buttons(rfd::MessageButtons::Ok)
                        .show();
                    std::process::exit(1);
                }
            }
        }

        // Double-click or exe run: check config, then run as agent
        // Use --install-service flag explicitly to install as Windows Service
        if !args.standalone && !args.install_service {
            // Check if config exists — run setup wizard if not
            let file_cfg = load_file_config();
            let has_config = file_cfg.stun_server.is_some() && file_cfg.gateway_id.is_some();

            if !has_config {
                run_first_time_setup();
            }
            // Skip service install — just fall through to agent mode below
        }

        if args.install_service {
            if win_service::is_elevated() {
                match win_service::install() {
                    Ok(()) => {
                        rfd::MessageDialog::new()
                            .set_title("Punchd VPN")
                            .set_description("Punchd VPN service installed and started.\n\nIt will start automatically on boot.\nConfig: C:\\ProgramData\\punchd-vpn\\vpn-config.toml")
                            .set_level(rfd::MessageLevel::Info)
                            .set_buttons(rfd::MessageButtons::Ok)
                            .show();
                        std::process::exit(0);
                    }
                    Err(e) => {
                        rfd::MessageDialog::new()
                            .set_title("Punchd VPN — Error")
                            .set_description(&format!("Failed to install service:\n{e}"))
                            .set_level(rfd::MessageLevel::Error)
                            .set_buttons(rfd::MessageButtons::Ok)
                            .show();
                        std::process::exit(1);
                    }
                }
            } else {
                win_service::elevate_and_install();
            }
        }
    }

    // Start agent HTTP server in the background (unless --standalone)
    if !args.standalone {
        tracing::info!("punchd-vpn starting (agent on port {AGENT_PORT})");
        tokio::spawn(async {
            if let Err(e) = run_agent().await {
                tracing::error!("Agent error: {e}");
            }
        });
    } else {
        tracing::info!("punchd-vpn starting (standalone mode)");
    }

    // If vpn-config.toml exists, auto-connect on startup
    let file_cfg = load_file_config();
    let has_config = file_cfg.stun_server.is_some() && file_cfg.gateway_id.is_some();

    if has_config || args.standalone {
        let file_cfg = if !has_config && args.standalone {
            run_first_time_setup()
        } else {
            file_cfg
        };

        let (stun_server, gateway_id, tc_path, tc_b64, ice_server, turn_server, turn_secret, default_route) =
            merge_args(&args, &file_cfg);

        if !stun_server.is_empty() && !gateway_id.is_empty() {
            tracing::info!("  STUN server: {}", stun_server);
            tracing::info!("  Gateway: {}", gateway_id);

            let mut resolved = ResolvedConfig {
                stun_server,
                gateway_id,
                tc_path,
                tc_b64,
                ice_server,
                turn_server,
                turn_secret,
                tun_name: args.tun_name.clone(),
                default_route,
                token: args.token.clone(),
            };

            if args.standalone {
                // Standalone: auto-reconnect with backoff
                let mut backoff_secs: u64 = 2;
                loop {
                    match run_vpn(resolved.clone()).await {
                        Ok(()) => {
                            tracing::info!("VPN disconnected cleanly");
                            backoff_secs = 2;
                        }
                        Err(e) if e.contains("access denied") || e.contains("Access denied") => {
                            tracing::error!("VPN access denied: {e}");
                            eprintln!("\n*** VPN ACCESS DENIED ***");
                            eprintln!("Your account does not have the required VPN role.");
                            eprintln!("Ask your admin to assign the role, then re-login.");
                            eprintln!("Re-opening browser login in 60s (or press Ctrl+C to exit)...\n");
                            // Wait longer — role change requires a fresh token
                            tokio::time::sleep(Duration::from_secs(60)).await;
                            // Clear cached token so next attempt re-authenticates
                            resolved.token = None;
                            backoff_secs = 2;
                            continue;
                        }
                        Err(e) => {
                            tracing::error!("VPN error: {e}");
                        }
                    }
                    tracing::info!("Reconnecting in {backoff_secs}s...");
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(30);
                }
            } else {
                // Agent mode: auto-reconnect with exponential backoff
                let resolved = Arc::new(resolved);
                tokio::spawn(async move {
                    let mut backoff_secs: u64 = 2;
                    const MAX_BACKOFF: u64 = 60;

                    loop {
                        tracing::info!("[VPN] Connecting...");
                        match run_vpn((*resolved).clone()).await {
                            Ok(()) => {
                                tracing::info!("[VPN] Disconnected cleanly");
                                backoff_secs = 2; // reset on clean disconnect
                            }
                            Err(e) => {
                                tracing::error!("[VPN] Connection error: {e}");
                            }
                        }
                        tracing::info!("[VPN] Reconnecting in {backoff_secs}s...");
                        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF);
                    }
                });
            }
        }
    }

    // If not standalone, keep agent running (HTTP server + reconnect loop in background)
    if !args.standalone {
        tracing::info!("Agent running. Waiting for browser connections...");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }
}

// ── Agent mode: local HTTP server for browser control ───────────────
// Supports multiple simultaneous VPN connections (one per gateway).

use std::collections::HashMap;

struct VpnConnection {
    handle: tokio::task::JoinHandle<()>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    info: serde_json::Value,
    logs: Vec<String>,
}

struct AgentState {
    connections: HashMap<String, VpnConnection>,
    global_logs: Vec<String>,
    tun_counter: u32,
}

impl AgentState {
    fn new() -> Self {
        Self { connections: HashMap::new(), global_logs: Vec::new(), tun_counter: 0 }
    }

    fn log(&mut self, gw_id: Option<&str>, msg: &str) {
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let line = if let Some(gw) = gw_id {
            format!("{ts} [{gw}] {msg}")
        } else {
            format!("{ts} {msg}")
        };
        tracing::info!("{}", line);
        self.global_logs.push(line.clone());
        if self.global_logs.len() > 500 { self.global_logs.drain(0..250); }
        if let Some(gw) = gw_id {
            if let Some(conn) = self.connections.get_mut(gw) {
                conn.logs.push(line);
                if conn.logs.len() > 200 { conn.logs.drain(0..100); }
            }
        }
    }

    fn next_tun_name(&mut self) -> String {
        let name = format!("punchd-vpn{}", self.tun_counter);
        self.tun_counter += 1;
        name
    }
}

fn agent_log(msg: &str) {
    tracing::info!("{}", msg);
}

async fn run_agent() -> Result<(), String> {
    let state: Arc<Mutex<AgentState>> = Arc::new(Mutex::new(AgentState::new()));

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{AGENT_PORT}"))
        .await
        .map_err(|e| format!("Failed to bind agent port {AGENT_PORT}: {e}"))?;

    tracing::info!("Agent listening on http://127.0.0.1:{AGENT_PORT}");

    loop {
        let (stream, _) = listener.accept().await.map_err(|e| format!("Accept error: {e}"))?;
        let state = state.clone();

        tokio::spawn(async move {
            let mut stream = stream;
            let mut buf = vec![0u8; 65536];
            let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                Ok(n) => n,
                Err(_) => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let first_line = request.lines().next().unwrap_or("");
            let method = first_line.split_whitespace().next().unwrap_or("");
            let path = first_line.split_whitespace().nth(1).unwrap_or("");

            if method == "OPTIONS" {
                let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, resp.as_bytes()).await;
                return;
            }

            let body = request.split("\r\n\r\n").nth(1).unwrap_or("").to_string();

            let (status, response_body) = match (method, path) {
                // GET /status — list all connections
                ("GET", "/status") => {
                    let s = state.lock().await;
                    let connections: Vec<serde_json::Value> = s.connections.iter().map(|(gw_id, conn)| {
                        json!({
                            "gatewayId": gw_id,
                            "info": conn.info,
                        })
                    }).collect();
                    ("200 OK", json!({
                        "running": true,
                        "connections": connections,
                        "connected": !s.connections.is_empty(),
                    }).to_string())
                }

                // POST /connect — connect to a gateway (can have multiple)
                ("POST", "/connect") => {
                    match serde_json::from_str::<serde_json::Value>(&body) {
                        Ok(params) => {
                            let stun_server = params["stunServer"].as_str().unwrap_or("").to_string();
                            let gateway_id = params["gatewayId"].as_str().unwrap_or("").to_string();
                            let token = params["token"].as_str().unwrap_or("").to_string();
                            let ice_server = params["iceServer"].as_str().map(|s| s.to_string());
                            let turn_server = params["turnServer"].as_str().map(|s| s.to_string());
                            let turn_secret = params["turnSecret"].as_str().map(|s| s.to_string());

                            if stun_server.is_empty() || gateway_id.is_empty() || token.is_empty() {
                                ("400 Bad Request", json!({"error": "Missing stunServer, gatewayId, or token"}).to_string())
                            } else {
                                let mut s = state.lock().await;

                                // Check if already connected to this gateway
                                if s.connections.contains_key(&gateway_id) {
                                    ("400 Bad Request", json!({"error": format!("Already connected to {gateway_id}")}).to_string())
                                } else {
                                    let tun_name = s.next_tun_name();
                                    s.log(Some(&gateway_id), &format!("Connecting (TUN: {tun_name})..."));

                                    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
                                    let gw_id = gateway_id.clone();
                                    let state_clone = state.clone();
                                    let tun_clone = tun_name.clone();

                                    let handle = tokio::spawn(async move {
                                        let cfg = ResolvedConfig {
                                            stun_server,
                                            gateway_id: gw_id.clone(),
                                            tc_path: None,
                                            tc_b64: None,
                                            ice_server,
                                            turn_server,
                                            turn_secret,
                                            tun_name: tun_clone,
                                            default_route: false,
                                            token: Some(token.clone()),
                                        };

                                        match run_vpn_with_token(cfg, token, shutdown_rx).await {
                                            Ok(_) => {
                                                let mut s = state_clone.lock().await;
                                                s.log(Some(&gw_id), "Disconnected cleanly");
                                                s.connections.remove(&gw_id);
                                            }
                                            Err(e) => {
                                                let mut s = state_clone.lock().await;
                                                s.log(Some(&gw_id), &format!("Error: {e}"));
                                                s.connections.remove(&gw_id);
                                            }
                                        }
                                    });

                                    s.connections.insert(gateway_id.clone(), VpnConnection {
                                        handle,
                                        shutdown: shutdown_tx,
                                        info: json!({ "gatewayId": gateway_id, "tunName": tun_name, "status": "connecting" }),
                                        logs: Vec::new(),
                                    });

                                    ("200 OK", json!({"success": true, "message": "Connecting..."}).to_string())
                                }
                            }
                        }
                        Err(e) => ("400 Bad Request", json!({"error": format!("Invalid JSON: {e}")}).to_string()),
                    }
                }

                // POST /disconnect — disconnect a specific gateway or all
                ("POST", "/disconnect") => {
                    let gw_id = serde_json::from_str::<serde_json::Value>(&body)
                        .ok()
                        .and_then(|v| v["gatewayId"].as_str().map(|s| s.to_string()));

                    let mut s = state.lock().await;

                    if let Some(gw_id) = gw_id {
                        // Disconnect specific gateway
                        if let Some(conn) = s.connections.remove(&gw_id) {
                            let _ = conn.shutdown.send(());
                            conn.handle.abort();
                            s.log(Some(&gw_id), "Disconnected by user");
                            ("200 OK", json!({"success": true, "gatewayId": gw_id}).to_string())
                        } else {
                            ("404 Not Found", json!({"error": format!("Not connected to {gw_id}")}).to_string())
                        }
                    } else {
                        // Disconnect all
                        let gw_ids: Vec<String> = s.connections.keys().cloned().collect();
                        for gw_id in &gw_ids {
                            if let Some(conn) = s.connections.remove(gw_id) {
                                let _ = conn.shutdown.send(());
                                conn.handle.abort();
                            }
                        }
                        s.log(None, &format!("Disconnected all ({} connections)", gw_ids.len()));
                        ("200 OK", json!({"success": true, "disconnected": gw_ids}).to_string())
                    }
                }

                // GET /logs or /logs?gatewayId=xxx
                (method, path) if method == "GET" && path.starts_with("/logs") => {
                    let gw_filter = path.split("gatewayId=").nth(1).map(|s| s.split('&').next().unwrap_or(s).to_string());
                    let s = state.lock().await;

                    let logs = if let Some(ref gw_id) = gw_filter {
                        s.connections.get(gw_id).map(|c| c.logs.clone()).unwrap_or_default()
                    } else {
                        s.global_logs.clone()
                    };
                    ("200 OK", json!({"logs": logs}).to_string())
                }

                _ => ("404 Not Found", json!({"error": "Not found"}).to_string()),
            };

            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            );
            let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;
        });
    }
}

#[derive(Clone)]
struct ResolvedConfig {
    stun_server: String,
    gateway_id: String,
    tc_path: Option<String>,
    tc_b64: Option<String>,
    ice_server: Option<String>,
    turn_server: Option<String>,
    turn_secret: Option<String>,
    tun_name: String,
    default_route: bool,
    token: Option<String>,
}

// ── OIDC browser login ──────────────────────────────────────────────

fn load_tc_config(tc_path: &Option<String>, tc_b64: &Option<String>) -> Result<TcConfig, String> {
    // Collect any b64 value — could be in tc_b64, or user may have pasted it into tc_path
    let b64_value = tc_b64.as_deref().or_else(|| {
        tc_path.as_deref().filter(|s| s.len() > 50 && !s.contains('/') && !s.contains('\\') && !s.ends_with(".json"))
    });

    let json_str = if let Some(b64) = b64_value {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("Invalid base64: {e}"))?;
        String::from_utf8(bytes).map_err(|e| format!("Invalid UTF-8: {e}"))?
    } else {
        let path = tc_path.as_deref().unwrap_or("tidecloak.json");
        // Try next to the exe first, then current dir
        let exe_dir_path = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join(path)));
        let resolved = match &exe_dir_path {
            Some(p) if p.exists() => p.to_string_lossy().to_string(),
            _ => path.to_string(),
        };
        std::fs::read_to_string(&resolved)
            .map_err(|e| format!("Failed to read {resolved}: {e}"))?
    };
    serde_json::from_str(&json_str).map_err(|e| format!("Invalid config: {e}"))
}

/// Generate a DPoP proof JWT (required by TideCloak for token exchange).
/// Uses an ephemeral Ed25519 keypair.
fn generate_dpop_proof(method: &str, url: &str) -> Result<String, String> {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use base64::Engine;
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    // Generate ephemeral Ed25519 key
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| format!("Key gen error: {e}"))?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|e| format!("Key load error: {e}"))?;

    // Public key in JWK format
    let pub_key_bytes = key_pair.public_key().as_ref();
    let x = b64url.encode(pub_key_bytes);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // DPoP JWT header
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
        }
    });

    // DPoP JWT payload
    let payload = serde_json::json!({
        "jti": uuid::Uuid::new_v4().to_string(),
        "htm": method,
        "htu": url,
        "iat": now,
    });

    let header_b64 = b64url.encode(serde_json::to_string(&header).unwrap().as_bytes());
    let payload_b64 = b64url.encode(serde_json::to_string(&payload).unwrap().as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signature = key_pair.sign(signing_input.as_bytes());
    let sig_b64 = b64url.encode(signature.as_ref());

    Ok(format!("{signing_input}.{sig_b64}"))
}

fn generate_dpop_proof_with_nonce(method: &str, url: &str, nonce: &str) -> Result<String, String> {
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use base64::Engine;
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| format!("Key gen error: {e}"))?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|e| format!("Key load error: {e}"))?;
    let pub_key_bytes = key_pair.public_key().as_ref();
    let x = b64url.encode(pub_key_bytes);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

    let header = serde_json::json!({
        "typ": "dpop+jwt", "alg": "EdDSA",
        "jwk": { "kty": "OKP", "crv": "Ed25519", "x": x }
    });
    let payload = serde_json::json!({
        "jti": uuid::Uuid::new_v4().to_string(),
        "htm": method, "htu": url, "iat": now, "nonce": nonce,
    });

    let header_b64 = b64url.encode(serde_json::to_string(&header).unwrap().as_bytes());
    let payload_b64 = b64url.encode(serde_json::to_string(&payload).unwrap().as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = key_pair.sign(signing_input.as_bytes());
    let sig_b64 = b64url.encode(signature.as_ref());
    Ok(format!("{signing_input}.{sig_b64}"))
}

async fn oidc_login(_tc: &TcConfig) -> Result<String, String> {
    let app_url = std::env::var("SERVER_URL")
        .unwrap_or_else(|_| "https://demo.keylessh.com".to_string());

    // If WebView is running in background, it may have a refreshed token already
    if let Some(token) = webview_auth::get_latest_token() {
        tracing::info!("Using refreshed token from WebView");
        return Ok(token);
    }

    // Open embedded WebView for OIDC login (full DPoP via Heimdall)
    tracing::info!("Opening embedded login window (WebView)...");
    webview_auth::webview_oidc_login(&app_url).await
}

// ── VPN connection ──────────────────────────────────────────────────

async fn run_vpn(cfg: ResolvedConfig) -> Result<(), String> {
    run_vpn_quic(cfg).await
}

/// QUIC-based VPN connection — no WebRTC, no SDP, no ICE.
/// Connects to signaling, receives gateway's QUIC address, connects directly.
async fn run_vpn_quic(cfg: ResolvedConfig) -> Result<(), String> {
    run_vpn_quic_inner(cfg, None).await
}

async fn run_vpn_quic_inner(cfg: ResolvedConfig, shutdown_rx: Option<tokio::sync::oneshot::Receiver<()>>) -> Result<(), String> {
    let tc = load_tc_config(&cfg.tc_path, &cfg.tc_b64)?;
    tracing::info!("[QUIC-VPN] TideCloak: realm={}, auth={}", tc.realm, tc.auth_server_url);

    let token = if let Some(ref t) = cfg.token {
        tracing::info!("[QUIC-VPN] Using provided access token");
        t.clone()
    } else {
        oidc_login(&tc).await?
    };

    // Connect to signaling server
    tracing::info!("[QUIC-VPN] Connecting to signaling server...");
    let connector = {
        let tls = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| format!("TLS error: {e}"))?;
        Some(tokio_tungstenite::Connector::NativeTls(tls))
    };

    let (ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(
        &cfg.stun_server, None, false, connector,
    ).await.map_err(|e| format!("Failed to connect to signaling: {e}"))?;

    let (ws_sink, mut ws_stream) = ws_stream.split();
    let ws_sink = Arc::new(Mutex::new(ws_sink));
    let peer_id = format!("vpn-{}", &uuid::Uuid::new_v4().to_string()[..8]);

    // Register as client
    {
        let msg = json!({
            "type": "register",
            "role": "client",
            "id": peer_id,
            "targetGatewayId": cfg.gateway_id,
            "token": token,
        });
        let mut sink = ws_sink.lock().await;
        sink.send(Message::Text(msg.to_string())).await
            .map_err(|e| format!("Failed to register: {e}"))?;
    }
    tracing::info!("[QUIC-VPN] Registered as: {peer_id}");

    // Bind ONE UDP socket for STUN + QUIC (same port = same NAT pinhole)
    let std_socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| format!("UDP socket bind error: {e}"))?;
    std_socket.set_nonblocking(true).map_err(|e| format!("Nonblocking error: {e}"))?;
    let local_addr = std_socket.local_addr().map_err(|e| format!("Local addr error: {e}"))?;
    tracing::info!("[QUIC-VPN] UDP socket bound on {local_addr}");

    // Resolve public address via STUN on the same socket
    let stun_socket_clone = std_socket.try_clone().map_err(|e| format!("Clone error: {e}"))?;
    let public_addr = if let Some(ref ice) = cfg.ice_server {
        let stun_addr = ice.trim_start_matches("stun:");
        let tokio_sock = tokio::net::UdpSocket::from_std(stun_socket_clone)
            .map_err(|e| format!("Tokio socket error: {e}"))?;
        match quic_transport::stun_resolve(&tokio_sock, stun_addr).await {
            Ok(addr) => {
                tracing::info!("[QUIC-VPN] STUN resolved: {addr} (same socket as QUIC)");
                addr
            }
            Err(e) => {
                tracing::warn!("[QUIC-VPN] STUN failed: {e}, using local address");
                local_addr
            }
        }
    } else {
        local_addr
    };

    // Create QUIC client endpoint on the SAME socket (preserves NAT pinhole)
    let runtime = quinn::default_runtime().ok_or("No async runtime")?;
    let mut quic_endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        runtime.wrap_udp_socket(std_socket).map_err(|e| format!("Wrap socket error: {e}"))?,
        runtime,
    ).map_err(|e| format!("QUIC endpoint error: {e}"))?;
    quic_endpoint.set_default_client_config(quic_transport::make_client_config());
    tracing::info!("[QUIC-VPN] QUIC endpoint on same socket as STUN");

    // Wait for pairing and gateway's QUIC address
    let gateway_addr: Arc<Mutex<Option<std::net::SocketAddr>>> = Arc::new(Mutex::new(None));
    let gateway_addr_notify = Arc::new(Notify::new());

    let gateway_addr_clone = gateway_addr.clone();
    let gateway_addr_notify_clone = gateway_addr_notify.clone();
    let ws_sink_sig = ws_sink.clone();
    let peer_id_clone = peer_id.clone();
    let gateway_id = cfg.gateway_id.clone();
    let public_addr_str = public_addr.to_string();

    // Process signaling messages
    let sig_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_stream.next().await {
            if let Message::Text(text) = msg {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                    let msg_type = parsed["type"].as_str().unwrap_or("");
                    match msg_type {
                        "registered" => tracing::info!("[QUIC-VPN] Registered with signaling"),
                        "paired" => {
                            tracing::info!("[QUIC-VPN] Paired with gateway");
                            // Send our STUN-resolved QUIC address to the gateway
                            let msg = json!({
                                "type": "quic_address",
                                "targetId": gateway_id,
                                "fromId": peer_id_clone,
                                "address": public_addr_str,
                            });
                            let mut sink = ws_sink_sig.lock().await;
                            let _ = sink.send(Message::Text(msg.to_string())).await;
                        }
                        "quic_address" => {
                            // Gateway sent its QUIC address
                            let addr_str = parsed["address"].as_str();
                            if let Some(addr_str) = addr_str {
                                if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
                                    tracing::info!("[QUIC-VPN] Gateway native QUIC address: {addr}");
                                    *gateway_addr_clone.lock().await = Some(addr);
                                    gateway_addr_notify_clone.notify_one();
                                }
                            }
                        }
                        "error" => {
                            let message = parsed["message"].as_str().unwrap_or("unknown");
                            tracing::error!("[QUIC-VPN] Signaling error: {message}");
                        }
                        _ => tracing::debug!("[QUIC-VPN] Signaling: {msg_type}"),
                    }
                }
            }
        }
    });

    // Wait for gateway address
    tokio::select! {
        _ = gateway_addr_notify.notified() => {}
        _ = tokio::time::sleep(Duration::from_secs(30)) => {
            return Err("Timeout waiting for gateway QUIC address".into());
        }
    }

    let gateway_addr = gateway_addr.lock().await
        .ok_or_else(|| "No gateway address received".to_string())?;

    // Send UDP punch packets to the gateway's address (opens NAT pinhole)
    // The gateway also punches us (via the "punch" signaling message)
    // Send punch packets to the gateway to open OUR NAT pinhole
    // This must happen before the gateway's punch arrives, so both NATs are open
    tracing::info!("[QUIC-VPN] Sending punch packets to {gateway_addr}...");

    // Send our quic_address to the gateway (triggers gateway to punch us)
    // Then immediately start punching from our side
    {
        let mut sink = ws_sink.lock().await;
        let _ = sink.send(Message::Text(serde_json::json!({
            "type": "quic_address",
            "targetId": cfg.gateway_id,
            "fromId": peer_id,
            "address": public_addr.to_string(),
        }).to_string())).await;
    }

    // Use quinn's rebind trick: the QUIC endpoint can't send raw UDP, but
    // we can use connect() as a punch — it sends a QUIC Initial packet.
    // Send multiple rapid connect attempts to punch the NAT:
    for i in 0..3 {
        let _ = quic_endpoint.connect(gateway_addr, "punchd-gateway");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Small delay to let gateway's return punch arrive
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Try direct QUIC connection (our connect = our punch)
    tracing::info!("[QUIC-VPN] Connecting QUIC to {gateway_addr}...");
    let conn = match tokio::time::timeout(
        Duration::from_secs(5),
        quic_endpoint.connect(gateway_addr, "punchd-gateway")
            .map_err(|e| format!("QUIC connect error: {e}"))
            .expect("QUIC connect setup failed"),
    ).await {
        Ok(Ok(c)) => {
            tracing::info!("[QUIC-VPN] Direct QUIC connection established");
            c
        }
        Ok(Err(e)) => {
            tracing::warn!("[QUIC-VPN] Direct QUIC failed: {e}");
            try_turn_relay(&cfg, &quic_endpoint, gateway_addr, &peer_id).await?
        }
        Err(_) => {
            tracing::warn!("[QUIC-VPN] Direct QUIC timed out (5s)");
            try_turn_relay(&cfg, &quic_endpoint, gateway_addr, &peer_id).await?
        }
    };

    tracing::info!("[QUIC-VPN] QUIC connected to gateway");

    // Auth stream: send JWT + DPoP proof
    let (mut auth_send, mut auth_recv) = conn.open_bi().await
        .map_err(|e| format!("Failed to open auth stream: {e}"))?;

    // Try to generate a DPoP proof via WebView (if available)
    let dpop_proof = match webview_auth::request_dpop_proof("POST", "quic://gateway/auth").await {
        Ok(proof) if !proof.starts_with("ERROR:") => {
            tracing::info!("[QUIC-VPN] DPoP proof generated");
            Some(proof)
        }
        Ok(err) => {
            tracing::warn!("[QUIC-VPN] DPoP proof failed: {err}");
            None
        }
        Err(e) => {
            tracing::debug!("[QUIC-VPN] DPoP not available: {e}");
            None
        }
    };

    // [type=0x01][token_len:u16][token_bytes][dpop_len:u16][dpop_bytes]
    auth_send.write_all(&[0x01u8 /* AUTH */]).await
        .map_err(|e| format!("Auth write error: {e}"))?;
    let token_bytes = token.as_bytes();
    auth_send.write_all(&(token_bytes.len() as u16).to_be_bytes()).await
        .map_err(|e| format!("Auth write error: {e}"))?;
    auth_send.write_all(token_bytes).await
        .map_err(|e| format!("Auth write error: {e}"))?;

    // DPoP proof (0 length = no DPoP)
    if let Some(ref proof) = dpop_proof {
        let proof_bytes = proof.as_bytes();
        auth_send.write_all(&(proof_bytes.len() as u16).to_be_bytes()).await
            .map_err(|e| format!("Auth write error: {e}"))?;
        auth_send.write_all(proof_bytes).await
            .map_err(|e| format!("Auth write error: {e}"))?;
    } else {
        auth_send.write_all(&0u16.to_be_bytes()).await
            .map_err(|e| format!("Auth write error: {e}"))?;
    }
    auth_send.finish().map_err(|e| format!("Auth finish error: {e}"))?;

    // Read auth response
    let mut auth_resp = vec![0u8; 10];
    let n = auth_recv.read(&mut auth_resp).await
        .map_err(|e| format!("Auth read error: {e}"))?
        .ok_or_else(|| "Auth stream closed".to_string())?;
    let resp = String::from_utf8_lossy(&auth_resp[..n]);
    if resp != "OK" {
        return Err(format!("Auth rejected: {resp}"));
    }
    tracing::info!("[QUIC-VPN] Authenticated");

    // VPN control stream: request tunnel
    let (mut vpn_send, mut vpn_recv) = conn.open_bi().await
        .map_err(|e| format!("Failed to open VPN stream: {e}"))?;

    // Send stream type + vpn_open request
    let vpn_open = json!({
        "type": "vpn_open",
        "id": uuid::Uuid::new_v4().to_string(),
        "token": token,
    });
    let vpn_open_bytes = vpn_open.to_string();
    vpn_send.write_all(&[0x04u8 /* VPN */]).await
        .map_err(|e| format!("VPN write error: {e}"))?;
    vpn_send.write_all(&(vpn_open_bytes.len() as u32).to_be_bytes()).await
        .map_err(|e| format!("VPN write error: {e}"))?;
    vpn_send.write_all(vpn_open_bytes.as_bytes()).await
        .map_err(|e| format!("VPN write error: {e}"))?;

    // Read vpn_opened response
    let mut resp_len_buf = [0u8; 4];
    vpn_recv.read_exact(&mut resp_len_buf).await
        .map_err(|e| format!("VPN read error: {e}"))?;
    let resp_len = u32::from_be_bytes(resp_len_buf) as usize;
    let mut resp_buf = vec![0u8; resp_len];
    vpn_recv.read_exact(&mut resp_buf).await
        .map_err(|e| format!("VPN read error: {e}"))?;

    let vpn_resp: serde_json::Value = serde_json::from_slice(&resp_buf)
        .map_err(|e| format!("Invalid VPN response: {e}"))?;

    if vpn_resp["type"].as_str() != Some("vpn_opened") {
        let err_msg = vpn_resp["message"].as_str().unwrap_or("unknown error");
        return Err(format!("VPN denied: {err_msg}"));
    }

    let client_ip: Ipv4Addr = vpn_resp["clientIp"].as_str().unwrap_or("10.66.0.2")
        .parse().unwrap_or(Ipv4Addr::new(10, 66, 0, 2));
    let server_ip: Ipv4Addr = vpn_resp["serverIp"].as_str().unwrap_or("10.66.0.1")
        .parse().unwrap_or(Ipv4Addr::new(10, 66, 0, 1));
    let netmask: Ipv4Addr = vpn_resp["netmask"].as_str().unwrap_or("255.255.255.0")
        .parse().unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
    let mtu = vpn_resp["mtu"].as_u64().unwrap_or(1400) as u16;
    let routes: Vec<String> = vpn_resp["routes"].as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    tracing::info!("[QUIC-VPN] Tunnel opened: client={client_ip}, server={server_ip}, mtu={mtu}");

    // Create TUN device
    let tun_cfg = tun_device::TunConfig {
        name: cfg.tun_name.clone(),
        address: client_ip,
        netmask,
        mtu,
    };
    let mut tun = tun_device::TunDevice::create(&tun_cfg)
        .map_err(|e| format!("Failed to create TUN device: {e}"))?;

    tracing::info!("[QUIC-VPN] TUN device created");

    if cfg.default_route {
        setup_routing(&cfg.tun_name, &server_ip.to_string());
    }
    for route in &routes {
        install_route(route, &server_ip.to_string());
    }

    tracing::info!("[QUIC-VPN] VPN active! Local={client_ip} Gateway={server_ip}");

    // Packet forwarding loop using QUIC datagrams
    let mut read_buf = vec![0u8; 65536];
    let mut shutdown_fuse = shutdown_rx;

    loop {
        tokio::select! {
            // TUN → QUIC datagram (client to gateway)
            result = tun.read(&mut read_buf) => {
                match result {
                    Ok(n) if n >= 20 => {
                        if (read_buf[0] >> 4) != 4 { continue; } // Drop non-IPv4
                        if let Err(e) = conn.send_datagram(Bytes::copy_from_slice(&read_buf[..n])) {
                            tracing::error!("[QUIC-VPN] Datagram send error: {e}");
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("[QUIC-VPN] TUN read error: {e}");
                        break;
                    }
                }
            }
            // QUIC datagram → TUN (gateway to client)
            result = conn.read_datagram() => {
                match result {
                    Ok(data) => {
                        if data.len() >= 20 && (data[0] >> 4) == 4 {
                            if let Err(e) = tun.write(&data).await {
                                tracing::error!("[QUIC-VPN] TUN write error: {e}");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("[QUIC-VPN] Datagram recv error: {e}");
                        break;
                    }
                }
            }
            // Agent shutdown request
            _ = async {
                match shutdown_fuse.as_mut() {
                    Some(rx) => { let _ = rx.await; }
                    None => std::future::pending::<()>().await,
                }
            } => {
                tracing::info!("[QUIC-VPN] Shutdown requested by agent");
                break;
            }
            // Ctrl+C
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("[QUIC-VPN] Shutting down...");
                break;
            }
        }
    }

    // Cleanup
    for route in &routes {
        remove_route(route);
    }
    conn.close(0u32.into(), b"bye");
    sig_task.abort();
    tracing::info!("[QUIC-VPN] Disconnected");
    Ok(())
}

/// Try TURN relay when direct QUIC connection fails.
///
/// Architecture: quinn can't speak TURN natively, so we:
/// 1. Allocate a relay on the TURN server (with ChannelBind)
/// 2. Start a local UDP proxy (localhost) that wraps/unwraps ChannelData
/// 3. Create a new quinn endpoint that connects through the proxy
///
/// quinn -> localhost:proxy -> TURN server -> gateway
async fn try_turn_relay(
    cfg: &ResolvedConfig,
    _quic_endpoint: &quinn::Endpoint, // unused — we create a new endpoint for TURN
    gateway_addr: std::net::SocketAddr,
    peer_id: &str,
) -> Result<quinn::Connection, String> {
    let turn_server = cfg.turn_server.as_deref()
        .ok_or_else(|| "No TURN server configured — direct connection failed and no relay available".to_string())?;
    let turn_secret = cfg.turn_secret.as_deref()
        .ok_or_else(|| "No TURN secret — cannot authenticate with relay".to_string())?;

    tracing::info!("[QUIC-VPN] Falling back to TURN relay via {turn_server}...");

    let (username, credential) = turn_client::generate_credentials(turn_secret, peer_id);

    // Separate UDP socket for TURN control
    let turn_socket = Arc::new(
        tokio::net::UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| format!("TURN socket bind: {e}"))?
    );

    // Allocate relay + bind channel for the gateway peer
    let allocation = turn_client::allocate(
        turn_socket.clone(),
        turn_server,
        &username,
        &credential,
        gateway_addr,
    ).await?;

    let relay_addr = allocation.relay_addr();
    tracing::info!("[QUIC-VPN] TURN relay allocated: {relay_addr}");

    // Start local UDP proxy: quinn <-> ChannelData <-> TURN server
    let (proxy_addr, _shutdown_tx) = turn_client::start_turn_proxy(allocation).await?;

    tracing::info!("[QUIC-VPN] Connecting QUIC through TURN proxy {proxy_addr}...");

    // Create a new quinn endpoint that sends to the proxy
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
        .map_err(|e| format!("QUIC TURN endpoint: {e}"))?;
    endpoint.set_default_client_config(quic_transport::make_client_config());

    // Connect to the proxy address — proxy forwards to TURN -> gateway
    let conn = endpoint
        .connect(proxy_addr, "punchd-gateway")
        .map_err(|e| format!("QUIC connect via TURN: {e}"))?
        .await
        .map_err(|e| format!("QUIC via TURN failed: {e}"))?;

    tracing::info!("[QUIC-VPN] Connected via TURN relay");
    Ok(conn)
}

/// Agent-mode VPN connection — takes token directly, no OIDC login.
/// Accepts a shutdown receiver to disconnect on demand.
/// Agent-mode VPN connection — uses QUIC + WebView DPoP (same as standalone).
/// The token parameter is ignored — WebView handles authentication.
/// Accepts a shutdown receiver to disconnect on demand.
async fn run_vpn_with_token(
    cfg: ResolvedConfig,
    _token: String,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), String> {
    // Use the QUIC path with WebView auth (token: None forces oidc_login → WebView)
    let mut cfg = cfg;
    cfg.token = None; // Force WebView login for DPoP support
    run_vpn_quic_inner(cfg, Some(shutdown_rx)).await
}

#[derive(Clone)]
struct VpnConfig {
    client_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: u16,
    routes: Vec<String>,
}

/// Install a route for a LAN subnet through the VPN gateway.
/// `cidr` is e.g. "192.168.0.0/24", `gateway` is e.g. "10.66.0.1".
fn install_route(cidr: &str, gateway: &str) {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 { return; }
    let network = parts[0];
    let prefix: u32 = parts[1].parse().unwrap_or(24);

    #[cfg(target_os = "windows")]
    {
        let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
        let m = mask.to_be_bytes();
        let mask_str = format!("{}.{}.{}.{}", m[0], m[1], m[2], m[3]);
        let status = std::process::Command::new("route")
            .args(["add", network, "MASK", &mask_str, gateway])
            .status();
        match status {
            Ok(s) if s.success() => tracing::info!("[VPN] Route added: {} via {}", cidr, gateway),
            Ok(s) => tracing::warn!("[VPN] Failed to add route {} (exit {})", cidr, s),
            Err(e) => tracing::warn!("[VPN] Failed to add route {}: {}", cidr, e),
        }
    }

    #[cfg(target_os = "linux")]
    {
        let status = std::process::Command::new("ip")
            .args(["route", "add", cidr, "via", gateway])
            .status();
        match status {
            Ok(s) if s.success() => tracing::info!("[VPN] Route added: {} via {}", cidr, gateway),
            _ => tracing::warn!("[VPN] Failed to add route {}", cidr),
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = (network, prefix, gateway);
        tracing::warn!("[VPN] Auto route not supported on this platform: {}", cidr);
    }
}

/// Remove a previously installed route.
fn remove_route(cidr: &str) {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 { return; }
    let network = parts[0];

    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("route")
            .args(["delete", network])
            .status();
        tracing::info!("[VPN] Route removed: {}", cidr);
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("ip")
            .args(["route", "del", cidr])
            .status();
        tracing::info!("[VPN] Route removed: {}", cidr);
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        let _ = network;
    }
}

fn generate_turn_credentials(secret: &str, username_base: &str) -> (String, String) {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86400;
    let username = format!("{}:{}", timestamp, username_base);
    let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).expect("HMAC can take any key size");
    mac.update(username.as_bytes());
    let credential = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        mac.finalize().into_bytes(),
    );
    (username, credential)
}

fn setup_routing(tun_name: &str, gateway_ip: &str) {
    #[cfg(target_os = "linux")]
    {
        tracing::info!("Setting up routes...");
        let _ = std::process::Command::new("ip")
            .args(["route", "add", "default", "via", gateway_ip, "dev", tun_name, "metric", "100"])
            .status();
    }

    #[cfg(target_os = "windows")]
    {
        tracing::info!("Setting up routes...");
        let _ = std::process::Command::new("route")
            .args(["add", "0.0.0.0", "mask", "0.0.0.0", gateway_ip, "metric", "100"])
            .status();
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (tun_name, gateway_ip);
        tracing::warn!("Automatic route setup not implemented for this platform");
    }
}
