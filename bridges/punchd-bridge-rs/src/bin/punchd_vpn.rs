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
const CALLBACK_PORT: u16 = 19876;
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

/// Resolve the config file path (next to the exe)
fn config_file_path() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("vpn-config.toml")))
        .unwrap_or_else(|| std::path::PathBuf::from("vpn-config.toml"))
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

    // Save config
    let path = config_file_path();
    match toml::to_string_pretty(&cfg) {
        Ok(toml_str) => {
            if let Err(e) = std::fs::write(&path, &toml_str) {
                eprintln!("Warning: could not save config to {}: {e}", path.display());
            } else {
                println!();
                println!("Config saved to: {}", path.display());
                println!("You can edit this file to change settings.");
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

            let resolved = ResolvedConfig {
                stun_server,
                gateway_id,
                tc_path,
                tc_b64,
                ice_server,
                turn_server,
                turn_secret,
                tun_name: args.tun_name.clone(),
                default_route,
            };

            if let Err(e) = run_vpn(resolved).await {
                tracing::error!("VPN error: {}", e);
                if args.standalone {
                    eprintln!("\nPress Enter to exit...");
                    let _ = std::io::Read::read(&mut std::io::stdin(), &mut [0u8]);
                    std::process::exit(1);
                }
            }
        }
    }

    // If not standalone and no config to auto-connect, just keep agent running
    if !args.standalone {
        tracing::info!("Agent running. Waiting for browser connections...");
        // Keep alive — agent runs in the background task
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

async fn oidc_login(tc: &TcConfig) -> Result<String, String> {
    let base = tc.auth_server_url.trim_end_matches('/');
    let realm_path = format!("{base}/realms/{}/protocol/openid-connect", tc.realm);
    let auth_url = format!("{realm_path}/auth");
    let token_url = format!("{realm_path}/token");
    let redirect_uri = format!("http://localhost:{CALLBACK_PORT}/callback");

    // Generate state for CSRF protection
    let state: String = (0..16)
        .map(|_| format!("{:02x}", rand::Rng::random::<u8>(&mut rand::rng())))
        .collect();

    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &tc.resource)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "openid")
        .append_pair("state", &state)
        .finish();
    let login_url = format!("{auth_url}?{query}");

    tracing::info!("Opening browser for login...");
    tracing::info!("If the browser doesn't open, visit:");
    tracing::info!("  {}", login_url);

    // Open browser
    open_browser(&login_url);

    // Start local HTTP server to receive the callback
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], CALLBACK_PORT)))
        .await
        .map_err(|e| format!("Failed to bind callback server on port {CALLBACK_PORT}: {e}"))?;

    tracing::info!("Waiting for login callback on port {CALLBACK_PORT}...");

    // Accept one connection
    let (stream, _) = tokio::time::timeout(Duration::from_secs(120), listener.accept())
        .await
        .map_err(|_| "Login timeout (120s)".to_string())?
        .map_err(|e| format!("Accept error: {e}"))?;

    // Read the HTTP request
    let mut stream = stream;
    let mut buf = vec![0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
        .await
        .map_err(|e| format!("Read error: {e}"))?;
    let request = String::from_utf8_lossy(&buf[..n]);

    // Extract the code from GET /callback?code=...&state=...
    let first_line = request.lines().next().unwrap_or("");
    let path = first_line.split_whitespace().nth(1).unwrap_or("");
    let query = path.split('?').nth(1).unwrap_or("");

    let mut code = None;
    let mut recv_state = None;
    for pair in query.split('&') {
        let mut kv = pair.splitn(2, '=');
        match (kv.next(), kv.next()) {
            (Some("code"), Some(v)) => code = Some(urldecoded(v)),
            (Some("state"), Some(v)) => recv_state = Some(urldecoded(v)),
            _ => {}
        }
    }

    // Send success response to browser
    let html = "<html><body><h2>Login successful!</h2><p>You can close this tab and return to the terminal.</p><script>window.close()</script></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{html}",
        html.len()
    );
    let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await;

    // Validate state
    if recv_state.as_deref() != Some(&state) {
        return Err("OIDC state mismatch — possible CSRF attack".into());
    }

    let code = code.ok_or("No authorization code in callback")?;
    tracing::info!("Authorization code received, exchanging for token...");

    // Exchange code for tokens
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", &tc.resource)
        .append_pair("code", &code)
        .append_pair("redirect_uri", &redirect_uri)
        .finish();

    let resp = client
        .post(&token_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|e| format!("Token exchange error: {e}"))?;

    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("Read error: {e}"))?;

    if !status.is_success() {
        return Err(format!("Token exchange failed ({status}): {text}"));
    }

    #[derive(Deserialize)]
    struct TokenResp {
        access_token: String,
    }
    let tokens: TokenResp =
        serde_json::from_str(&text).map_err(|e| format!("Invalid token response: {e}"))?;

    tracing::info!("Login successful!");
    Ok(tokens.access_token)
}

fn urldecoded(s: &str) -> String {
    url::form_urlencoded::parse(s.as_bytes())
        .next()
        .map(|(k, v)| {
            if v.is_empty() {
                k.to_string()
            } else {
                format!("{k}={v}")
            }
        })
        .unwrap_or_else(|| s.to_string())
}

fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    {
        // Use rundll32 to open URL — cmd /C start breaks on & in URLs
        let _ = std::process::Command::new("rundll32")
            .args(["url.dll,FileProtocolHandler", url])
            .spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
}

// ── VPN connection ──────────────────────────────────────────────────

async fn run_vpn(cfg: ResolvedConfig) -> Result<(), String> {
    // Load TideCloak config and login
    let tc = load_tc_config(&cfg.tc_path, &cfg.tc_b64)?;
    tracing::info!("TideCloak: realm={}, auth={}", tc.realm, tc.auth_server_url);

    let token = oidc_login(&tc).await?;

    // Connect to STUN signaling server
    tracing::info!("Connecting to STUN server...");

    let connector = {
        let tls = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| format!("TLS error: {e}"))?;
        Some(tokio_tungstenite::Connector::NativeTls(tls))
    };

    let (ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(
        &cfg.stun_server,
        None,
        false,
        connector,
    )
    .await
    .map_err(|e| format!("Failed to connect to STUN server: {e}"))?;

    tracing::info!("Connected to STUN server");

    let (ws_sink, ws_stream) = ws_stream.split();

    // Register as a client
    let peer_id = uuid::Uuid::new_v4().to_string();
    let register_msg = json!({
        "type": "register",
        "role": "client",
        "id": peer_id,
        "targetGatewayId": cfg.gateway_id,
    });

    let ws_sink = Arc::new(Mutex::new(ws_sink));
    {
        let mut sink = ws_sink.lock().await;
        sink.send(Message::Text(register_msg.to_string()))
            .await
            .map_err(|e| format!("Failed to send register: {e}"))?;
    }

    tracing::info!("Registered as client: {}", peer_id);

    // Build WebRTC API
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs().ok();
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut media_engine)
        .expect("Failed to register interceptors");
    let setting_engine = SettingEngine::default();
    let api = Arc::new(
        APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .with_setting_engine(setting_engine)
            .build(),
    );

    // Build ICE server list
    let mut ice_servers = Vec::new();
    if let Some(ref ice) = cfg.ice_server {
        ice_servers.push(RTCIceServer {
            urls: vec![ice.clone()],
            ..Default::default()
        });
    }
    if let Some(ref turn) = cfg.turn_server {
        let (username, credential) = if let Some(ref secret) = cfg.turn_secret {
            generate_turn_credentials(secret, &peer_id)
        } else {
            (String::new(), String::new())
        };
        ice_servers.push(RTCIceServer {
            urls: vec![turn.clone()],
            username,
            credential,
            ..Default::default()
        });
    }

    let rtc_config = RTCConfiguration {
        ice_servers,
        ..Default::default()
    };

    let pc = api
        .new_peer_connection(rtc_config)
        .await
        .map_err(|e| format!("Failed to create peer connection: {e}"))?;
    let pc = Arc::new(pc);

    // Create DataChannels (client creates them, bridge receives)
    let control_dc = pc
        .create_data_channel("http-tunnel", None)
        .await
        .map_err(|e| format!("Failed to create control channel: {e}"))?;

    // Unordered + unreliable for VPN packets — eliminates head-of-line blocking.
    // TCP retransmits at the app layer, so SCTP reliability is redundant and harmful.
    let bulk_dc = pc
        .create_data_channel("bulk-data", Some({
            let mut init = webrtc::data_channel::data_channel_init::RTCDataChannelInit::default();
            init.ordered = Some(false);
            init.max_retransmits = Some(3);
            init
        }))
        .await
        .map_err(|e| format!("Failed to create bulk channel: {e}"))?;

    // Channels for VPN packet flow
    let (tun_write_tx, tun_write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let vpn_ready = Arc::new(Notify::new());
    let vpn_config: Arc<Mutex<Option<VpnConfig>>> = Arc::new(Mutex::new(None));

    // Control channel: handle vpn_opened response
    let vpn_config_ctrl = vpn_config.clone();
    let vpn_ready_ctrl = vpn_ready.clone();
    control_dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let vpn_config = vpn_config_ctrl.clone();
        let vpn_ready = vpn_ready_ctrl.clone();
        Box::pin(async move {
            let buf = msg.data.to_vec();
            if let Ok(text) = String::from_utf8(buf) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                    let msg_type = parsed["type"].as_str().unwrap_or("");
                    match msg_type {
                        "vpn_opened" => {
                            let client_ip: Ipv4Addr = parsed["clientIp"]
                                .as_str()
                                .unwrap_or("10.66.0.2")
                                .parse()
                                .unwrap_or(Ipv4Addr::new(10, 0, 0, 2));
                            let server_ip: Ipv4Addr = parsed["serverIp"]
                                .as_str()
                                .unwrap_or("10.66.0.1")
                                .parse()
                                .unwrap_or(Ipv4Addr::new(10, 0, 0, 1));
                            let netmask: Ipv4Addr = parsed["netmask"]
                                .as_str()
                                .unwrap_or("255.255.255.0")
                                .parse()
                                .unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
                            let mtu = parsed["mtu"].as_u64().unwrap_or(1400) as u16;

                            let routes: Vec<String> = parsed["routes"]
                                .as_array()
                                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                .unwrap_or_default();

                            tracing::info!(
                                "VPN opened: client={}, server={}, mtu={}, routes={:?}",
                                client_ip, server_ip, mtu, routes
                            );

                            let mut cfg = vpn_config.lock().await;
                            *cfg = Some(VpnConfig { client_ip, server_ip, netmask, mtu, routes });
                            vpn_ready.notify_one();
                        }
                        "vpn_error" => {
                            let message = parsed["message"].as_str().unwrap_or("unknown");
                            tracing::error!("VPN error from gateway: {}", message);
                        }
                        "vpn_blocked" => {
                            let dst = parsed["destination"].as_str().unwrap_or("?");
                            let port = parsed["port"].as_u64().unwrap_or(0);
                            let message = parsed["message"].as_str().unwrap_or("");
                            tracing::warn!("ACCESS DENIED: {}:{} — {}", dst, port, message);
                        }
                        "capabilities" => {
                            let features = parsed["features"]
                                .as_array()
                                .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
                                .unwrap_or_default();
                            tracing::info!("Gateway capabilities: {}", features);
                        }
                        _ => {
                            tracing::debug!("Control message: {}", msg_type);
                        }
                    }
                }
            }
        })
    }));

    // Bulk channel: receive VPN packets from bridge
    let tun_write_tx_bulk = tun_write_tx.clone();
    bulk_dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let tx = tun_write_tx_bulk.clone();
        Box::pin(async move {
            let buf = msg.data.to_vec();
            if buf.len() > 1 && buf[0] == VPN_TUNNEL_MAGIC {
                let _ = tx.send(buf[1..].to_vec());
            }
        })
    }));

    // Wait for control channel to open, then send vpn_open
    let control_dc_open = control_dc.clone();
    let token_clone = token.clone();
    control_dc.on_open(Box::new(move || {
        let dc = control_dc_open.clone();
        let token = token_clone.clone();
        Box::pin(async move {
            tracing::info!("Control channel open, requesting VPN tunnel...");

            let caps = json!({
                "type": "capabilities",
                "features": ["bulk-channel", "vpn-tunnel"],
            });
            let _ = dc.send_text(caps.to_string()).await;

            let vpn_open = json!({
                "type": "vpn_open",
                "id": uuid::Uuid::new_v4().to_string(),
                "token": token,
            });
            let _ = dc.send_text(vpn_open.to_string()).await;
        })
    }));

    // ICE candidate handling
    let ws_sink_ice = ws_sink.clone();
    let gw_id = cfg.gateway_id.clone();
    let cid = peer_id.clone();
    pc.on_ice_candidate(Box::new(move |candidate| {
        let ws_sink = ws_sink_ice.clone();
        let gw_id = gw_id.clone();
        let cid = cid.clone();
        Box::pin(async move {
            if let Some(c) = candidate {
                if let Ok(json_str) = c.to_json() {
                    let msg = json!({
                        "type": "candidate",
                        "fromId": cid,
                        "targetId": gw_id,
                        "candidate": {
                            "candidate": json_str.candidate,
                            "mid": json_str.sdp_mid.unwrap_or_default(),
                        },
                    });
                    let mut sink = ws_sink.lock().await;
                    let _ = sink.send(Message::Text(msg.to_string())).await;
                }
            }
        })
    }));

    // Create and send SDP offer
    let offer = pc.create_offer(None).await
        .map_err(|e| format!("Failed to create offer: {e}"))?;
    pc.set_local_description(offer.clone()).await
        .map_err(|e| format!("Failed to set local description: {e}"))?;

    let offer_msg = json!({
        "type": "sdp_offer",
        "fromId": peer_id,
        "targetId": cfg.gateway_id,
        "sdp": offer.sdp,
    });
    {
        let mut sink = ws_sink.lock().await;
        sink.send(Message::Text(offer_msg.to_string())).await
            .map_err(|e| format!("Failed to send offer: {e}"))?;
    }

    tracing::info!("SDP offer sent, waiting for answer...");

    // Process STUN signaling messages
    let pc_sig = pc.clone();
    let mut ws_stream = ws_stream;
    tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_stream.next().await {
            if let Message::Text(text) = msg {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                    let msg_type = parsed["type"].as_str().unwrap_or("");
                    match msg_type {
                        "sdp_answer" => {
                            let sdp = parsed["sdp"].as_str().unwrap_or("");
                            match RTCSessionDescription::answer(sdp.to_string()) {
                                Ok(answer) => {
                                    if let Err(e) = pc_sig.set_remote_description(answer).await {
                                        tracing::error!("Failed to set remote description: {}", e);
                                    } else {
                                        tracing::info!("SDP answer applied");
                                    }
                                }
                                Err(e) => tracing::error!("Invalid SDP answer: {}", e),
                            }
                        }
                        "candidate" => {
                            // Gateway sends nested: { candidate: { candidate: "...", mid: "..." } }
                            // or flat: { candidate: "...", sdpMid: "..." }
                            let (candidate_str, sdp_mid) = if let Some(obj) = parsed["candidate"].as_object() {
                                (
                                    obj.get("candidate").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                    obj.get("mid").and_then(|v| v.as_str()).map(|s| s.to_string()),
                                )
                            } else {
                                (
                                    parsed["candidate"].as_str().unwrap_or("").to_string(),
                                    parsed["sdpMid"].as_str().map(|s| s.to_string()),
                                )
                            };
                            if !candidate_str.is_empty() {
                                let init = RTCIceCandidateInit {
                                    candidate: candidate_str,
                                    sdp_mid,
                                    ..Default::default()
                                };
                                if let Err(e) = pc_sig.add_ice_candidate(init).await {
                                    tracing::error!("Failed to add ICE candidate: {}", e);
                                }
                            }
                        }
                        "registered" => tracing::info!("Registered with STUN server"),
                        "paired" => tracing::info!("Paired with gateway"),
                        "error" => {
                            let message = parsed["message"].as_str().unwrap_or("unknown");
                            tracing::error!("STUN server error: {}", message);
                        }
                        _ => tracing::debug!("STUN message: {}", msg_type),
                    }
                }
            }
        }
        tracing::warn!("STUN WebSocket closed");
    });

    // Wait for VPN to be established
    tracing::info!("Waiting for VPN tunnel...");
    tokio::select! {
        _ = vpn_ready.notified() => {}
        _ = tokio::time::sleep(Duration::from_secs(30)) => {
            return Err("Timeout waiting for VPN tunnel".into());
        }
    }

    let vpn_cfg = vpn_config.lock().await.clone().unwrap();

    // Create TUN device
    tracing::info!("Creating TUN device: {} ({})", cfg.tun_name, vpn_cfg.client_ip);

    let tun_cfg = tun_device::TunConfig {
        name: cfg.tun_name.clone(),
        address: vpn_cfg.client_ip,
        netmask: vpn_cfg.netmask,
        mtu: vpn_cfg.mtu,
    };

    let mut tun = tun_device::TunDevice::create(&tun_cfg)
        .map_err(|e| format!("Failed to create TUN device: {e}"))?;

    tracing::info!("TUN device created successfully");

    if cfg.default_route {
        setup_routing(&cfg.tun_name, &vpn_cfg.server_ip.to_string());
    }

    // Install LAN routes pushed by the gateway
    let gateway_ip_str = vpn_cfg.server_ip.to_string();
    for route in &vpn_cfg.routes {
        install_route(route, &gateway_ip_str);
    }

    tracing::info!("VPN tunnel active! Press Ctrl+C to disconnect.");
    tracing::info!("  Local IP:   {}", vpn_cfg.client_ip);
    tracing::info!("  Gateway IP: {}", vpn_cfg.server_ip);
    tracing::info!("  MTU:        {}", vpn_cfg.mtu);
    if !vpn_cfg.routes.is_empty() {
        tracing::info!("  Routes:     {:?}", vpn_cfg.routes);
    }

    // Packet forwarding loop
    let bulk_dc_send = bulk_dc.clone();
    let mut tun_write_rx = tun_write_rx;
    let mut read_buf = vec![0u8; 65536];

    loop {
        tokio::select! {
            result = tun.read(&mut read_buf) => {
                match result {
                    Ok(n) if n >= 20 => {
                        // Drop non-IPv4 packets (IPv6 noise, etc.)
                        if (read_buf[0] >> 4) != 4 {
                            continue;
                        }
                        let src = std::net::Ipv4Addr::new(read_buf[12], read_buf[13], read_buf[14], read_buf[15]);
                        let dst = std::net::Ipv4Addr::new(read_buf[16], read_buf[17], read_buf[18], read_buf[19]);
                        let proto = read_buf[9];
                        tracing::debug!("[VPN] TUN read: {} -> {} proto={} ({} bytes)", src, dst, proto, n);
                        let mut frame = Vec::with_capacity(1 + n);
                        frame.push(VPN_TUNNEL_MAGIC);
                        frame.extend_from_slice(&read_buf[..n]);
                        if let Err(e) = bulk_dc_send.send(&Bytes::from(frame)).await {
                            tracing::error!("Failed to send to bulk channel: {}", e);
                            break;
                        }
                    }
                    Ok(n) => {
                        tracing::debug!("[VPN] TUN read: short packet ({} bytes)", n);
                    }
                    Err(e) => {
                        tracing::error!("TUN read error: {}", e);
                        break;
                    }
                }
            }
            data = tun_write_rx.recv() => {
                match data {
                    Some(packet) => {
                        if packet.len() >= 20 {
                            let src = std::net::Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
                            let dst = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                            tracing::debug!("[VPN] TUN write: {} -> {} ({} bytes)", src, dst, packet.len());
                        }
                        if let Err(e) = tun.write(&packet).await {
                            tracing::error!("TUN write error: {}", e);
                            break;
                        }
                    }
                    None => {
                        tracing::info!("Bulk channel closed");
                        break;
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("Shutting down VPN...");
                break;
            }
        }
    }

    // Remove LAN routes on disconnect
    for route in &vpn_cfg.routes {
        remove_route(route);
    }

    let _ = pc.close().await;
    tracing::info!("VPN disconnected");
    Ok(())
}

/// Agent-mode VPN connection — takes token directly, no OIDC login.
/// Accepts a shutdown receiver to disconnect on demand.
async fn run_vpn_with_token(
    cfg: ResolvedConfig,
    token: String,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), String> {
    agent_log("Connecting to STUN server...");

    let connector = {
        let tls = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .map_err(|e| format!("TLS error: {e}"))?;
        Some(tokio_tungstenite::Connector::NativeTls(tls))
    };

    let (ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(
        &cfg.stun_server, None, false, connector,
    )
    .await
    .map_err(|e| format!("Failed to connect to STUN server: {e}"))?;

    agent_log("Connected to STUN server");

    let (ws_sink, ws_stream) = ws_stream.split();
    let peer_id = uuid::Uuid::new_v4().to_string();

    let ws_sink = Arc::new(Mutex::new(ws_sink));
    {
        let register_msg = json!({
            "type": "register",
            "role": "client",
            "id": peer_id,
            "targetGatewayId": cfg.gateway_id,
        });
        let mut sink = ws_sink.lock().await;
        sink.send(Message::Text(register_msg.to_string())).await
            .map_err(|e| format!("Failed to register: {e}"))?;
    }

    // Build WebRTC (same as run_vpn)
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs().ok();
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut media_engine).expect("interceptors");
    let api = Arc::new(APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .with_setting_engine(SettingEngine::default())
        .build());

    let mut ice_servers = Vec::new();
    if let Some(ref ice) = cfg.ice_server {
        ice_servers.push(RTCIceServer { urls: vec![ice.clone()], ..Default::default() });
    }
    if let Some(ref turn) = cfg.turn_server {
        let (username, credential) = if let Some(ref secret) = cfg.turn_secret {
            generate_turn_credentials(secret, &peer_id)
        } else { (String::new(), String::new()) };
        ice_servers.push(RTCIceServer { urls: vec![turn.clone()], username, credential, ..Default::default() });
    }

    let pc = Arc::new(api.new_peer_connection(RTCConfiguration { ice_servers, ..Default::default() }).await
        .map_err(|e| format!("PeerConnection error: {e}"))?);

    let control_dc = pc.create_data_channel("http-tunnel", None).await
        .map_err(|e| format!("Control channel error: {e}"))?;
    let bulk_dc = pc.create_data_channel("bulk-data", Some({
        let mut init = webrtc::data_channel::data_channel_init::RTCDataChannelInit::default();
        init.ordered = Some(false);
        init.max_retransmits = Some(3);
        init
    })).await.map_err(|e| format!("Bulk channel error: {e}"))?;

    let (tun_write_tx, tun_write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let vpn_ready = Arc::new(Notify::new());
    let vpn_config: Arc<Mutex<Option<VpnConfig>>> = Arc::new(Mutex::new(None));

    // Control channel handler
    let vpn_config_ctrl = vpn_config.clone();
    let vpn_ready_ctrl = vpn_ready.clone();
    control_dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let vpn_config = vpn_config_ctrl.clone();
        let vpn_ready = vpn_ready_ctrl.clone();
        Box::pin(async move {
            if let Ok(text) = String::from_utf8(msg.data.to_vec()) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                    match parsed["type"].as_str().unwrap_or("") {
                        "vpn_opened" => {
                            let client_ip: Ipv4Addr = parsed["clientIp"].as_str().unwrap_or("10.66.0.2").parse().unwrap_or(Ipv4Addr::new(10, 66, 0, 2));
                            let server_ip: Ipv4Addr = parsed["serverIp"].as_str().unwrap_or("10.66.0.1").parse().unwrap_or(Ipv4Addr::new(10, 66, 0, 1));
                            let netmask: Ipv4Addr = parsed["netmask"].as_str().unwrap_or("255.255.255.0").parse().unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
                            let mtu = parsed["mtu"].as_u64().unwrap_or(1400) as u16;
                            let routes: Vec<String> = parsed["routes"].as_array()
                                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                .unwrap_or_default();
                            let mut cfg = vpn_config.lock().await;
                            *cfg = Some(VpnConfig { client_ip, server_ip, netmask, mtu, routes });
                            vpn_ready.notify_one();
                        }
                        "vpn_error" => { agent_log(&format!("VPN error: {}", parsed["message"].as_str().unwrap_or("unknown"))); }
                        "vpn_blocked" => {
                            let dst = parsed["destination"].as_str().unwrap_or("?");
                            let port = parsed["port"].as_u64().unwrap_or(0);
                            agent_log(&format!("ACCESS DENIED: {}:{}", dst, port));
                        }
                        _ => {}
                    }
                }
            }
        })
    }));

    // Bulk channel handler
    let tun_write_tx_bulk = tun_write_tx.clone();
    bulk_dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let tx = tun_write_tx_bulk.clone();
        Box::pin(async move {
            let buf = msg.data.to_vec();
            if buf.len() > 1 && buf[0] == VPN_TUNNEL_MAGIC {
                let _ = tx.send(buf[1..].to_vec());
            }
        })
    }));

    // Send vpn_open on control channel open
    let control_dc_open = control_dc.clone();
    let token_clone = token.clone();
    control_dc.on_open(Box::new(move || {
        let dc = control_dc_open.clone();
        let token = token_clone.clone();
        Box::pin(async move {
            let _ = dc.send_text(json!({"type": "capabilities", "features": ["bulk-channel", "vpn-tunnel"]}).to_string()).await;
            let _ = dc.send_text(json!({"type": "vpn_open", "id": uuid::Uuid::new_v4().to_string(), "token": token}).to_string()).await;
        })
    }));

    // ICE candidates
    let ws_sink_ice = ws_sink.clone();
    let gw_id = cfg.gateway_id.clone();
    let cid = peer_id.clone();
    pc.on_ice_candidate(Box::new(move |candidate| {
        let ws_sink = ws_sink_ice.clone();
        let gw_id = gw_id.clone();
        let cid = cid.clone();
        Box::pin(async move {
            if let Some(c) = candidate {
                if let Ok(j) = c.to_json() {
                    let msg = json!({"type": "candidate", "fromId": cid, "targetId": gw_id, "candidate": {"candidate": j.candidate, "mid": j.sdp_mid.unwrap_or_default()}});
                    let mut sink = ws_sink.lock().await;
                    let _ = sink.send(Message::Text(msg.to_string())).await;
                }
            }
        })
    }));

    // Send SDP offer
    let offer = pc.create_offer(None).await.map_err(|e| format!("Offer error: {e}"))?;
    pc.set_local_description(offer.clone()).await.map_err(|e| format!("Set local desc: {e}"))?;
    {
        let msg = json!({"type": "sdp_offer", "fromId": peer_id, "targetId": cfg.gateway_id, "sdp": offer.sdp});
        let mut sink = ws_sink.lock().await;
        sink.send(Message::Text(msg.to_string())).await.map_err(|e| format!("Send offer: {e}"))?;
    }

    // STUN signaling task
    let pc_sig = pc.clone();
    let mut ws_stream = ws_stream;
    tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_stream.next().await {
            if let Message::Text(text) = msg {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                    match parsed["type"].as_str().unwrap_or("") {
                        "sdp_answer" => {
                            if let Ok(answer) = RTCSessionDescription::answer(parsed["sdp"].as_str().unwrap_or("").to_string()) {
                                let _ = pc_sig.set_remote_description(answer).await;
                                agent_log("SDP answer applied");
                            }
                        }
                        "candidate" => {
                            let (cs, mid) = if let Some(obj) = parsed["candidate"].as_object() {
                                (obj.get("candidate").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                 obj.get("mid").and_then(|v| v.as_str()).map(|s| s.to_string()))
                            } else {
                                (parsed["candidate"].as_str().unwrap_or("").to_string(),
                                 parsed["sdpMid"].as_str().map(|s| s.to_string()))
                            };
                            if !cs.is_empty() {
                                let _ = pc_sig.add_ice_candidate(RTCIceCandidateInit { candidate: cs, sdp_mid: mid, ..Default::default() }).await;
                            }
                        }
                        "error" => { agent_log(&format!("STUN error: {}", parsed["message"].as_str().unwrap_or("unknown"))); }
                        _ => {}
                    }
                }
            }
        }
    });

    // Wait for VPN tunnel
    agent_log("Waiting for VPN tunnel...");
    tokio::select! {
        _ = vpn_ready.notified() => {}
        _ = tokio::time::sleep(Duration::from_secs(30)) => {
            return Err("Timeout waiting for VPN tunnel".into());
        }
    }

    let vpn_cfg = vpn_config.lock().await.clone().unwrap();
    agent_log(&format!("VPN connected: {} -> {} routes={:?}", vpn_cfg.client_ip, vpn_cfg.server_ip, vpn_cfg.routes));

    // Agent info is updated by the caller via the AgentState

    // Create TUN
    let tun_cfg = tun_device::TunConfig {
        name: cfg.tun_name.clone(),
        address: vpn_cfg.client_ip,
        netmask: vpn_cfg.netmask,
        mtu: vpn_cfg.mtu,
    };
    let mut tun = tun_device::TunDevice::create(&tun_cfg)
        .map_err(|e| format!("TUN device error: {e}"))?;

    agent_log("TUN device created");

    // Install routes
    let gateway_ip_str = vpn_cfg.server_ip.to_string();
    for route in &vpn_cfg.routes {
        install_route(route, &gateway_ip_str);
        agent_log(&format!("Route added: {} via {}", route, gateway_ip_str));
    }

    // Packet forwarding loop
    let bulk_dc_send = bulk_dc.clone();
    let mut tun_write_rx = tun_write_rx;
    let mut read_buf = vec![0u8; 65536];
    let mut shutdown_rx = shutdown_rx;

    loop {
        tokio::select! {
            result = tun.read(&mut read_buf) => {
                match result {
                    Ok(n) if n >= 20 => {
                        if (read_buf[0] >> 4) != 4 { continue; }
                        let mut frame = Vec::with_capacity(1 + n);
                        frame.push(VPN_TUNNEL_MAGIC);
                        frame.extend_from_slice(&read_buf[..n]);
                        if bulk_dc_send.send(&Bytes::from(frame)).await.is_err() { break; }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            data = tun_write_rx.recv() => {
                match data {
                    Some(packet) => { let _ = tun.write(&packet).await; }
                    None => break,
                }
            }
            _ = &mut shutdown_rx => {
                agent_log("Shutdown signal received");
                break;
            }
        }
    }

    // Cleanup routes
    for route in &vpn_cfg.routes {
        remove_route(route);
    }

    let _ = pc.close().await;
    agent_log("VPN disconnected");
    Ok(())
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
