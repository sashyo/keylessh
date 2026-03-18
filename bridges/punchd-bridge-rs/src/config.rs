use std::env;
use std::fs;
use std::net::UdpSocket;
use std::path::PathBuf;

use base64::Engine;
use rand::Rng;
use serde::Deserialize;

#[derive(Clone, Debug)]
pub struct BackendEntry {
    pub name: String,
    pub url: String,
    pub protocol: String, // "http" or "rdp"
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
    // Allow extra fields
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

pub fn load_config() -> ServerConfig {
    let stun_server_url = require_env("STUN_SERVER_URL");
    let backends = parse_backends();
    let backend_url = backends.first().map(|b| b.url.clone()).unwrap_or_default();

    if backend_url.is_empty() {
        eprintln!("[Gateway] BACKENDS or BACKEND_URL is required");
        std::process::exit(1);
    }

    let gateway_id = env::var("GATEWAY_ID").unwrap_or_else(|_| {
        let mut rng = rand::rng();
        let bytes: [u8; 8] = rng.random();
        format!("gateway-{}", hex::encode(&bytes))
    });

    ServerConfig {
        listen_port: env::var("LISTEN_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(7891),
        health_port: env::var("HEALTH_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(7892),
        backend_url,
        backends,
        stun_server_url: stun_server_url.clone(),
        gateway_id,
        strip_auth_header: env::var("STRIP_AUTH_HEADER")
            .map(|v| v == "true")
            .unwrap_or(false),
        auth_server_public_url: env::var("AUTH_SERVER_PUBLIC_URL").ok(),
        ice_servers: env::var("ICE_SERVERS")
            .ok()
            .map(|s| s.split(',').map(|s| s.to_string()).collect())
            .unwrap_or_else(|| derive_ice_servers(&stun_server_url)),
        turn_server: env::var("TURN_SERVER").ok(),
        turn_secret: warn_if_empty("TURN_SECRET"),
        api_secret: require_secret("API_SECRET"),
        display_name: env::var("GATEWAY_DISPLAY_NAME").ok(),
        description: env::var("GATEWAY_DESCRIPTION").ok(),
        https: env::var("HTTPS").map(|v| v != "false").unwrap_or(true),
        tls_hostname: env::var("TLS_HOSTNAME").unwrap_or_else(|_| "localhost".into()),
        tc_internal_url: env::var("TC_INTERNAL_URL").ok(),
    }
}

fn parse_backends() -> Vec<BackendEntry> {
    if let Ok(backends_env) = env::var("BACKENDS") {
        return backends_env
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
            .collect();
    }

    if let Ok(backend_url) = env::var("BACKEND_URL") {
        let name = env::var("GATEWAY_DISPLAY_NAME").unwrap_or_else(|_| "Default".into());
        return vec![BackendEntry {
            name,
            url: backend_url,
            protocol: "http".into(),
            no_auth: false,
            strip_auth: false,
        }];
    }

    vec![]
}

pub fn load_tidecloak_config() -> TidecloakConfig {
    let config_data = if let Ok(b64) = env::var("TIDECLOAK_CONFIG_B64") {
        eprintln!("[Gateway] Loading JWKS from TIDECLOAK_CONFIG_B64");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .expect("Invalid base64 in TIDECLOAK_CONFIG_B64");
        String::from_utf8(bytes).expect("Invalid UTF-8 in TIDECLOAK_CONFIG_B64")
    } else {
        let path = resolve_tidecloak_path();
        eprintln!("[Gateway] Loading JWKS from {}", path.display());
        fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("[Gateway] Failed to read {}: {e}", path.display());
            std::process::exit(1);
        })
    };

    let config: TidecloakConfig = serde_json::from_str(&config_data).unwrap_or_else(|e| {
        eprintln!("[Gateway] Failed to parse TideCloak config: {e}");
        std::process::exit(1);
    });

    if config.jwk.keys.is_empty() {
        eprintln!("[Gateway] No JWKS keys found in config");
        std::process::exit(1);
    }

    config
}

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
    // Connect to a public IP to find which local interface is used
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return addr.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}

fn require_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| {
        eprintln!("[Gateway] {name} is required");
        std::process::exit(1);
    })
}

fn require_secret(name: &str) -> String {
    let val = env::var(name).unwrap_or_default();
    if val.is_empty() {
        eprintln!("[Gateway] {name} is required (cannot be empty)");
        std::process::exit(1);
    }
    val
}

fn warn_if_empty(name: &str) -> String {
    let val = env::var(name).unwrap_or_default();
    if val.is_empty() {
        eprintln!("[Gateway] WARNING: {name} is empty — TURN credentials will be disabled");
    }
    val
}

fn resolve_tidecloak_path() -> PathBuf {
    if let Ok(path) = env::var("TIDECLOAK_CONFIG_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from("data/tidecloak.json")
}

// hex encoding helper (avoid adding a dep for this)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
