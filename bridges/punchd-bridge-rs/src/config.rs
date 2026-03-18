#![allow(dead_code)]

use std::env;
use std::fs;
use std::net::UdpSocket;
use std::path::PathBuf;

use base64::Engine;
use rand::Rng;
use serde::Deserialize;

// ── Config file schema (gateway.toml) ───────────────────────────

#[derive(Deserialize, Default, Debug)]
struct GatewayToml {
    #[serde(default)]
    gateway_id: Option<String>,
    #[serde(default)]
    stun_server_url: Option<String>,
    #[serde(default)]
    api_secret: Option<String>,
    #[serde(default)]
    backends: Option<String>,
    #[serde(default)]
    listen_port: Option<u16>,
    #[serde(default)]
    health_port: Option<u16>,
    #[serde(default)]
    https: Option<bool>,
    #[serde(default)]
    tls_hostname: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    ice_servers: Option<String>,
    #[serde(default)]
    turn_server: Option<String>,
    #[serde(default)]
    turn_secret: Option<String>,
    #[serde(default)]
    tidecloak_config_path: Option<String>,
    #[serde(default)]
    tidecloak_config_b64: Option<String>,
    #[serde(default)]
    auth_server_public_url: Option<String>,
    #[serde(default)]
    tc_internal_url: Option<String>,
    #[serde(default)]
    strip_auth_header: Option<bool>,
}

// ── Public types ────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct BackendEntry {
    pub name: String,
    pub url: String,
    pub protocol: String,
    pub no_auth: bool,
    pub strip_auth: bool,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen_port: u16,
    pub health_port: u16,
    pub backend_url: String,
    pub backends: Vec<BackendEntry>,
    pub stun_server_url: String,
    pub gateway_id: String,
    pub strip_auth_header: bool,
    pub auth_server_public_url: Option<String>,
    pub ice_servers: Vec<String>,
    pub turn_server: Option<String>,
    pub turn_secret: String,
    pub api_secret: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub https: bool,
    pub tls_hostname: String,
    pub tc_internal_url: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct JwkKey {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    #[serde(default)]
    pub r#use: String,
    #[serde(default)]
    pub crv: String,
    #[serde(default)]
    pub x: String,
    #[serde(default)]
    pub y: Option<String>,
    #[serde(default)]
    pub n: Option<String>,
    #[serde(default)]
    pub e: Option<String>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct JwkSet {
    pub keys: Vec<JwkKey>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct TidecloakConfig {
    pub realm: String,
    #[serde(rename = "auth-server-url")]
    pub auth_server_url: String,
    pub resource: String,
    #[serde(rename = "public-client", default)]
    pub public_client: Option<bool>,
    pub jwk: JwkSet,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

// ── Config file path ────────────────────────────────────────────

/// Config directory: ~/.keylessh/ (or %APPDATA%\KeyleSSH\ on Windows)
pub fn config_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(appdata) = env::var("APPDATA") {
            return PathBuf::from(appdata).join("KeyleSSH");
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(home).join(".keylessh");
        }
    }
    // Fallback: next to the executable
    env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn config_file_path() -> PathBuf {
    let dir = config_dir();
    // If config already exists next to exe (portable mode), use that
    if let Ok(exe) = env::current_exe() {
        let beside_exe = exe.parent().unwrap_or(exe.as_ref()).join("gateway.toml");
        if beside_exe.exists() {
            return beside_exe;
        }
    }
    dir.join("gateway.toml")
}

fn load_toml() -> GatewayToml {
    let path = config_file_path();
    if path.exists() {
        let content = fs::read_to_string(&path).unwrap_or_else(|e| {
            tracing::error!("Failed to read {}: {e}", path.display());
            std::process::exit(1);
        });
        toml::from_str(&content).unwrap_or_else(|e| {
            tracing::error!("Failed to parse {}: {e}", path.display());
            std::process::exit(1);
        })
    } else {
        GatewayToml::default()
    }
}

// ── Helper: read value from TOML > env var > default ────────────

fn get_val(toml_val: &Option<String>, env_name: &str) -> Option<String> {
    if let Some(v) = toml_val {
        if !v.is_empty() {
            return Some(v.clone());
        }
    }
    env::var(env_name).ok().filter(|v| !v.is_empty())
}

fn get_val_or(toml_val: &Option<String>, env_name: &str, default: &str) -> String {
    get_val(toml_val, env_name).unwrap_or_else(|| default.to_string())
}

fn generate_gateway_id() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 4] = rng.random();
    format!("gateway-{}", hex::encode(&bytes))
}

// ── Main config loader ──────────────────────────────────────────

pub fn load_config() -> ServerConfig {
    let mut toml_cfg = load_toml();

    // If no config file AND no critical env vars, run first-time setup
    let has_config_file = config_file_path().exists();
    let has_env = env::var("STUN_SERVER_URL").is_ok() || env::var("BACKENDS").is_ok();

    if !has_config_file && !has_env {
        tracing::error!("No gateway.toml found and no environment variables set.");
        tracing::error!("Run the gateway once to launch the setup wizard, or create gateway.toml manually.");
        std::process::exit(1);
    }

    // Resolve values: TOML > env var > default
    let stun_server_url = get_val(&toml_cfg.stun_server_url, "STUN_SERVER_URL")
        .unwrap_or_else(|| {
            tracing::error!("STUN_SERVER_URL is required (set in gateway.toml or env)");
            std::process::exit(1);
        });

    let api_secret = get_val(&toml_cfg.api_secret, "API_SECRET")
        .unwrap_or_else(|| {
            tracing::error!("API_SECRET is required (set in gateway.toml or env)");
            std::process::exit(1);
        });

    let backends_str = get_val(&toml_cfg.backends, "BACKENDS")
        .or_else(|| env::var("BACKEND_URL").ok().map(|u| format!("Default={u}")));
    let backends = backends_str
        .map(|s| parse_backends_str(&s))
        .unwrap_or_default();

    let backend_url = backends.first().map(|b| b.url.clone()).unwrap_or_default();
    if backend_url.is_empty() {
        tracing::error!("No backends configured (set backends in gateway.toml or BACKENDS env)");
        std::process::exit(1);
    }

    let gateway_id = get_val(&toml_cfg.gateway_id, "GATEWAY_ID")
        .unwrap_or_else(generate_gateway_id);

    let turn_secret = get_val(&toml_cfg.turn_secret, "TURN_SECRET").unwrap_or_default();
    if turn_secret.is_empty() {
        tracing::warn!("TURN secret is empty — TURN credentials will be disabled");
    }

    let ice_servers = get_val(&toml_cfg.ice_servers, "ICE_SERVERS")
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_else(|| derive_ice_servers(&stun_server_url));

    ServerConfig {
        listen_port: toml_cfg.listen_port
            .or_else(|| env::var("LISTEN_PORT").ok().and_then(|s| s.parse().ok()))
            .unwrap_or(7891),
        health_port: toml_cfg.health_port
            .or_else(|| env::var("HEALTH_PORT").ok().and_then(|s| s.parse().ok()))
            .unwrap_or(7892),
        backend_url,
        backends,
        stun_server_url,
        gateway_id,
        strip_auth_header: toml_cfg.strip_auth_header
            .or_else(|| env::var("STRIP_AUTH_HEADER").ok().map(|v| v == "true"))
            .unwrap_or(false),
        auth_server_public_url: get_val(&toml_cfg.auth_server_public_url, "AUTH_SERVER_PUBLIC_URL"),
        ice_servers,
        turn_server: get_val(&toml_cfg.turn_server, "TURN_SERVER"),
        turn_secret,
        api_secret,
        display_name: get_val(&toml_cfg.display_name, "GATEWAY_DISPLAY_NAME"),
        description: get_val(&toml_cfg.description, "GATEWAY_DESCRIPTION"),
        https: toml_cfg.https
            .or_else(|| env::var("HTTPS").ok().map(|v| v != "false"))
            .unwrap_or(true),
        tls_hostname: get_val_or(&toml_cfg.tls_hostname, "TLS_HOSTNAME", "localhost"),
        tc_internal_url: get_val(&toml_cfg.tc_internal_url, "TC_INTERNAL_URL"),
    }
}

// ── TideCloak config loader ─────────────────────────────────────

pub fn load_tidecloak_config() -> TidecloakConfig {
    let toml_cfg = load_toml();

    let config_data = if let Some(b64) = get_val(&toml_cfg.tidecloak_config_b64, "TIDECLOAK_CONFIG_B64") {
        tracing::info!("Loading JWKS from base64 config");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .expect("Invalid base64 in TideCloak config");
        String::from_utf8(bytes).expect("Invalid UTF-8 in TideCloak config")
    } else {
        let path = get_val(&toml_cfg.tidecloak_config_path, "TIDECLOAK_CONFIG_PATH")
            .map(|p| {
                let pb = PathBuf::from(&p);
                // If relative path, resolve against config dir
                if pb.is_relative() && !pb.exists() {
                    let in_config_dir = config_dir().join(&pb);
                    if in_config_dir.exists() {
                        return in_config_dir;
                    }
                }
                pb
            })
            .unwrap_or_else(|| {
                // Check config dir, then next to exe, then cwd
                let in_config = config_dir().join("tidecloak.json");
                if in_config.exists() {
                    return in_config;
                }
                if let Ok(exe) = env::current_exe() {
                    let beside = exe.parent().unwrap_or(exe.as_ref()).join("tidecloak.json");
                    if beside.exists() {
                        return beside;
                    }
                }
                PathBuf::from("tidecloak.json")
            });
        tracing::info!("Loading JWKS from {}", path.display());
        fs::read_to_string(&path).unwrap_or_else(|e| {
            tracing::error!("Failed to read {}: {e}", path.display());
            tracing::error!("Place tidecloak.json in {} or set tidecloak_config_path in gateway.toml", config_dir().display());
            std::process::exit(1);
        })
    };

    let config: TidecloakConfig = serde_json::from_str(&config_data).unwrap_or_else(|e| {
        tracing::error!("Failed to parse TideCloak config: {e}");
        std::process::exit(1);
    });

    if config.jwk.keys.is_empty() {
        tracing::error!("No JWKS keys found in config");
        std::process::exit(1);
    }

    config
}

// ── Backend string parser ───────────────────────────────────────

fn parse_backends_str(input: &str) -> Vec<BackendEntry> {
    input
        .split(',')
        .filter_map(|entry| {
            let eq = entry.find('=')?;
            let name = entry[..eq].trim().to_string();
            let mut raw_url = entry[eq + 1..].trim().to_string();
            let mut no_auth = false;
            let mut strip_auth = false;

            loop {
                let lower = raw_url.to_lowercase();
                if lower.ends_with(";noauth") {
                    no_auth = true;
                    raw_url.truncate(raw_url.len() - ";noauth".len());
                    raw_url = raw_url.trim().to_string();
                } else if lower.ends_with(";stripauth") {
                    strip_auth = true;
                    raw_url.truncate(raw_url.len() - ";stripauth".len());
                    raw_url = raw_url.trim().to_string();
                } else {
                    break;
                }
            }

            let protocol = if raw_url.starts_with("rdp://") {
                "rdp"
            } else {
                "http"
            };

            if raw_url.is_empty() {
                return None;
            }

            Some(BackendEntry {
                name,
                url: raw_url,
                protocol: protocol.to_string(),
                no_auth,
                strip_auth,
            })
        })
        .collect()
}

// ── Helpers ─────────────────────────────────────────────────────

fn derive_ice_servers(ws_url: &str) -> Vec<String> {
    if let Ok(url) = url::Url::parse(ws_url) {
        let mut host = url.host_str().unwrap_or("localhost").to_string();
        if host == "localhost" || host == "127.0.0.1" {
            host = detect_lan_ip();
        }
        vec![format!("stun:{host}:3478")]
    } else {
        vec![]
    }
}

fn detect_lan_ip() -> String {
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
