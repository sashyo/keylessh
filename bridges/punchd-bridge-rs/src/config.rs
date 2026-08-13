#![allow(dead_code)]

use std::env;
use std::fs;
use std::net::UdpSocket;
use std::path::PathBuf;

use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};

// ── Config file schema (gateway.toml) ───────────────────────────

#[derive(Deserialize, Serialize, Default, Debug, Clone)]
struct GatewayToml {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stun_server_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backends: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    listen_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    health_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    https: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls_hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ice_servers: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    turn_server: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    turn_secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tidecloak_config_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tidecloak_config_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_server_public_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tc_internal_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    strip_auth_header: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    server_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quic_port: Option<u16>,
}

// ── Public types ────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum BackendAuth {
    Password,
    EdDSA,
}

#[derive(Clone, Debug)]
pub struct BackendEntry {
    pub name: String,
    pub url: String,
    pub protocol: String,
    pub no_auth: bool,
    pub strip_auth: bool,
    pub auth: BackendAuth,
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
    pub server_url: Option<String>,
    pub quic_port: u16,
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

impl TidecloakConfig {
    /// OIDC issuer this gateway trusts — the tenancy identity advertised to the
    /// signal server so consoles only list gateways sharing their TideCloak realm.
    pub fn issuer(&self) -> String {
        format!(
            "{}/realms/{}",
            self.auth_server_url.trim_end_matches('/'),
            self.realm
        )
    }
}

// ── Config file path ────────────────────────────────────────────

/// Config directory: ~/.keylessh/ (or %APPDATA%\KeyleSSH\ on Windows)
pub fn config_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        // Service mode: ProgramData\punchd-gateway (MSI installer puts config here)
        let programdata = PathBuf::from(env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string()))
            .join("punchd-gateway");
        if programdata.exists() {
            return programdata;
        }
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

static ON_CONFIG_CHANGE: std::sync::OnceLock<Box<dyn Fn() + Send + Sync>> = std::sync::OnceLock::new();

/// Register a callback that fires when config files change.
pub fn on_config_change(cb: impl Fn() + Send + Sync + 'static) {
    let _ = ON_CONFIG_CHANGE.set(Box::new(cb));
}

/// Run the reload callback now. Used after a remote config push, which writes
/// the file itself and so does not need to wait for the watcher.
pub fn notify_config_changed() {
    if let Some(cb) = ON_CONFIG_CHANGE.get() {
        cb();
    }
}

/// Watch gateway.toml and tidecloak config for changes using OS-native file notifications
/// (inotify on Linux, ReadDirectoryChangesW on Windows, FSEvents on macOS).
/// On change, gracefully exits so the process manager restarts with new config.
pub fn watch_config_and_restart() {
    use notify::{Watcher, RecursiveMode, Event, EventKind};

    let gw_path = config_file_path();
    let tc_path = {
        let toml = load_toml();
        get_val(&toml.tidecloak_config_path, "TIDECLOAK_CONFIG_PATH")
            .map(|p| {
                if std::path::Path::new(&p).is_absolute() {
                    std::path::PathBuf::from(p)
                } else {
                    config_dir().join(p)
                }
            })
    };

    let paths_to_watch: Vec<std::path::PathBuf> = std::iter::once(gw_path.clone())
        .chain(tc_path.iter().cloned())
        .collect();

    std::thread::Builder::new()
        .name("config-watcher".into())
        .spawn(move || {
            // Debounce: ignore events within 2 seconds of startup
            std::thread::sleep(std::time::Duration::from_secs(5));

            let (tx, rx) = std::sync::mpsc::channel();

            let mut watcher = match notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
                if let Ok(event) = res {
                    match event.kind {
                        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_) => {
                            let _ = tx.send(event);
                        }
                        _ => {}
                    }
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    tracing::warn!("[Config] File watcher unavailable: {e}. Config changes require manual restart.");
                    return;
                }
            };

            for path in &paths_to_watch {
                if path.exists() {
                    if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                        tracing::warn!("[Config] Cannot watch {}: {e}", path.display());
                    } else {
                        tracing::info!("[Config] Watching {} for changes", path.display());
                    }
                }
            }

            // Wait for a file change event
            let mut debounce_deadline: Option<std::time::Instant> = None;

            loop {
                let timeout = debounce_deadline
                    .map(|d| d.saturating_duration_since(std::time::Instant::now()))
                    .unwrap_or(std::time::Duration::from_secs(3600));

                match rx.recv_timeout(timeout) {
                    Ok(event) => {
                        let changed_file = event.paths.first()
                            .and_then(|p| p.file_name())
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| "config".into());
                        tracing::info!("[Config] Change detected: {changed_file}");
                        // Debounce: wait 2 seconds for writes to settle
                        debounce_deadline = Some(std::time::Instant::now() + std::time::Duration::from_secs(2));
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if debounce_deadline.is_some() {
                            debounce_deadline = None;
                            tracing::info!("[Config] Config changed — reloading...");
                            // Notify via callback
                            if let Some(ref cb) = ON_CONFIG_CHANGE.get() {
                                cb();
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
        .ok();
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

// ── Remote config push ──────────────────────────────────────────

/// Fields that may never be set from a remote push.
///
/// `tidecloak_config_*`, `auth_server_public_url` and `tc_internal_url` define
/// which TideCloak this gateway trusts — accepting them over the wire would let
/// anyone holding the signal server's shared API secret repoint a gateway at
/// their own IdP and mint access to every backend behind it. `gateway_id`,
/// `stun_server_url` and `api_secret` are this gateway's own identity and
/// bootstrap; letting a push rewrite them would allow hijacking it onto a
/// different signal server. All of these stay a deliberate local action.
pub const PROTECTED_FIELDS: &[&str] = &[
    "gateway_id",
    "stun_server_url",
    "api_secret",
    "tidecloak_config_b64",
    "tidecloak_config_path",
    "auth_server_public_url",
    "tc_internal_url",
];

#[derive(Debug, Default, Serialize)]
pub struct RejectedField {
    pub field: String,
    pub reason: String,
}

#[derive(Debug, Default, Serialize)]
pub struct RemoteConfigOutcome {
    /// Fields whose value actually changed.
    pub applied: Vec<String>,
    /// Fields refused, with why.
    pub rejected: Vec<RejectedField>,
    /// False when every field was already at the requested value.
    pub changed: bool,
    /// Set when the config could not be read or written at all.
    pub error: Option<String>,
}

impl RemoteConfigOutcome {
    fn failed(error: impl Into<String>) -> Self {
        Self { error: Some(error.into()), ..Default::default() }
    }

    fn reject(&mut self, field: &str, reason: impl Into<String>) {
        self.rejected.push(RejectedField { field: field.to_string(), reason: reason.into() });
    }
}

fn try_load_toml() -> Result<GatewayToml, String> {
    let path = config_file_path();
    if !path.exists() {
        return Ok(GatewayToml::default());
    }
    let content = fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    toml::from_str(&content).map_err(|e| format!("parse {}: {e}", path.display()))
}

/// Merge a remotely-pushed config patch into gateway.toml.
///
/// Only the fields outside [`PROTECTED_FIELDS`] are honoured; everything else is
/// reported back as rejected so the console can show what was refused.
pub fn apply_remote_config(patch: &serde_json::Map<String, serde_json::Value>) -> RemoteConfigOutcome {
    let original = match try_load_toml() {
        Ok(c) => c,
        Err(e) => return RemoteConfigOutcome::failed(e),
    };

    let (updated, mut outcome) = merge_remote_config(&original, patch);
    if !outcome.changed {
        return outcome;
    }

    if let Err(e) = write_toml(&updated) {
        outcome.error = Some(e);
        outcome.applied.clear();
        outcome.changed = false;
        return outcome;
    }

    tracing::info!("[Config] Applied remote config: {}", outcome.applied.join(", "));

    // Trigger the reload directly rather than waiting on the file watcher: the
    // watcher follows an inode, and the atomic rename in `write_toml` replaces
    // it, so it cannot be relied on for a second push.
    notify_config_changed();
    outcome
}

/// Pure part of [`apply_remote_config`]: overlay the patch onto a config and
/// report what was applied or refused, touching no files.
fn merge_remote_config(
    original: &GatewayToml,
    patch: &serde_json::Map<String, serde_json::Value>,
) -> (GatewayToml, RemoteConfigOutcome) {
    let mut outcome = RemoteConfigOutcome::default();
    let mut updated = original.clone();

    // Coercion helpers: record a rejection when the pushed JSON type is wrong.
    macro_rules! set_str {
        ($field:ident, $key:expr, $value:expr) => {
            match $value {
                serde_json::Value::Null => updated.$field = None,
                serde_json::Value::String(s) => updated.$field = Some(s.clone()),
                _ => outcome.reject($key, "expected a string"),
            }
        };
    }
    macro_rules! set_port {
        ($field:ident, $key:expr, $value:expr) => {
            match $value.as_u64() {
                Some(n) if n > 0 && n <= u16::MAX as u64 => updated.$field = Some(n as u16),
                _ if $value.is_null() => updated.$field = None,
                _ => outcome.reject($key, "expected a port between 1 and 65535"),
            }
        };
    }
    macro_rules! set_bool {
        ($field:ident, $key:expr, $value:expr) => {
            match $value.as_bool() {
                Some(b) => updated.$field = Some(b),
                None if $value.is_null() => updated.$field = None,
                None => outcome.reject($key, "expected true or false"),
            }
        };
    }

    for (key, value) in patch {
        if PROTECTED_FIELDS.contains(&key.as_str()) {
            outcome.reject(key, "set locally on the gateway only");
            continue;
        }
        match key.as_str() {
            "backends" => set_str!(backends, key, value),
            "display_name" => set_str!(display_name, key, value),
            "description" => set_str!(description, key, value),
            "ice_servers" => set_str!(ice_servers, key, value),
            "turn_server" => set_str!(turn_server, key, value),
            "turn_secret" => set_str!(turn_secret, key, value),
            "tls_hostname" => set_str!(tls_hostname, key, value),
            "server_url" => set_str!(server_url, key, value),
            "listen_port" => set_port!(listen_port, key, value),
            "health_port" => set_port!(health_port, key, value),
            "quic_port" => set_port!(quic_port, key, value),
            "https" => set_bool!(https, key, value),
            "strip_auth_header" => set_bool!(strip_auth_header, key, value),
            _ => outcome.reject(key, "unknown field"),
        }
    }

    // Report only fields that genuinely differ, so a repeated push does not
    // churn the gateway into a pointless reload.
    outcome.applied = changed_fields(original, &updated);
    outcome.changed = !outcome.applied.is_empty();
    (updated, outcome)
}

/// Names of the fields that differ between two configs.
fn changed_fields(a: &GatewayToml, b: &GatewayToml) -> Vec<String> {
    let (av, bv) = (
        serde_json::to_value(a).unwrap_or_default(),
        serde_json::to_value(b).unwrap_or_default(),
    );
    let (ao, bo) = match (av.as_object(), bv.as_object()) {
        (Some(ao), Some(bo)) => (ao, bo),
        _ => return Vec::new(),
    };
    let mut keys: Vec<&String> = ao.keys().chain(bo.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|key| ao.get(*key) != bo.get(*key))
        .cloned()
        .collect()
}

/// Write gateway.toml atomically so a crash mid-write cannot truncate the config
/// the gateway needs to restart.
fn write_toml(config: &GatewayToml) -> Result<(), String> {
    write_toml_to(&config_file_path(), config)
}

fn write_toml_to(path: &std::path::Path, config: &GatewayToml) -> Result<(), String> {
    let body = toml::to_string_pretty(config).map_err(|e| format!("serialize config: {e}"))?;
    let contents = format!(
        "# Punchd Gateway Configuration\n\
         # Managed from the KeyleSSH console — edits here are overwritten on the next push.\n\
         # TideCloak settings and signal server identity are local-only and never pushed.\n\n{body}"
    );

    // A gateway configured purely by environment variables has no config file
    // and no config directory — the container images are set up this way — so
    // the first push has to create it.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
    }

    // Preferred: write beside the target and rename, so a crash mid-write cannot
    // leave a truncated config.
    let tmp = path.with_extension("toml.tmp");
    let atomic = fs::write(&tmp, &contents)
        .map_err(|e| format!("write {}: {e}", tmp.display()))
        .and_then(|_| {
            fs::rename(&tmp, path).map_err(|e| format!("replace {}: {e}", path.display()))
        });

    match atomic {
        Ok(()) => Ok(()),
        Err(rename_err) => {
            // A single-file bind mount (`-v host.toml:/app/gateway.toml`, the
            // documented container setup) is a mount point: renaming over it
            // fails with EBUSY no matter the permissions. Fall back to writing
            // through the mount, which is the only thing that works there.
            let _ = fs::remove_file(&tmp);
            fs::write(path, &contents).map_err(|e| {
                format!("{rename_err}; writing in place also failed: {e}")
            })?;
            tracing::debug!(
                "[Config] Replaced {} in place — atomic rename unavailable ({rename_err})",
                path.display()
            );
            Ok(())
        }
    }
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
    let toml_cfg = load_toml();

    // If no config file AND no critical env vars, run first-time setup
    let has_config_file = config_file_path().exists();
    let has_env = env::var("STUN_SERVER_URL").is_ok() || env::var("BACKENDS").is_ok();

    if !has_config_file && !has_env {
        tracing::error!("No gateway.toml found and no environment variables set.");
        tracing::error!("Run the gateway once to launch the setup wizard, or create gateway.toml manually.");
        std::process::exit(1);
    }

    // Resolve values: TOML > env var > default
    // stun_server_url and api_secret are optional for offline/local mode
    let stun_server_url = get_val(&toml_cfg.stun_server_url, "STUN_SERVER_URL")
        .unwrap_or_default();
    if stun_server_url.is_empty() {
        tracing::info!("No STUN_SERVER_URL — running in offline/local mode (no signal server)");
    }

    let api_secret = get_val(&toml_cfg.api_secret, "API_SECRET")
        .unwrap_or_default();

    let backends_str = get_val(&toml_cfg.backends, "BACKENDS")
        .or_else(|| env::var("BACKEND_URL").ok().map(|u| format!("Default={u}")));
    let backends = backends_str
        .map(|s| parse_backends_str(&s))
        .unwrap_or_default();

    let backend_url = backends.first().map(|b| b.url.clone()).unwrap_or_default();
    if backends.is_empty() {
        tracing::info!("No backends configured — custom IP connections only");
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
        server_url: get_val(&toml_cfg.server_url, "SERVER_URL"),
        quic_port: toml_cfg.quic_port
            .or_else(|| env::var("QUIC_PORT").ok().and_then(|s| s.parse().ok()))
            .unwrap_or(7893),
    }
}

// ── TideCloak config loader ─────────────────────────────────────

pub fn load_tidecloak_config() -> TidecloakConfig {
    let toml_cfg = load_toml();

    let config_data = if let Some(b64) = get_val(&toml_cfg.tidecloak_config_b64, "TIDECLOAK_CONFIG_B64") {
        tracing::info!("Loading JWKS from base64 config");
        let b64_trimmed = b64.trim();
        let bytes = if b64_trimmed.starts_with('{') {
            tracing::info!("Detected raw JSON in tidecloak_config_b64 field");
            b64_trimmed.as_bytes().to_vec()
        } else {
            match base64::engine::general_purpose::STANDARD.decode(b64_trimmed)
                .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64_trimmed))
                .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(b64_trimmed))
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64_trimmed))
            {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!("Invalid base64 in TideCloak config: {e}");
                    std::process::exit(1);
                }
            }
        };
        match String::from_utf8(bytes) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Invalid UTF-8 in TideCloak config: {e}");
                std::process::exit(1);
            }
        }
    } else {
        // Find tidecloak.json file
        let path = get_val(&toml_cfg.tidecloak_config_path, "TIDECLOAK_CONFIG_PATH")
            .map(|p| {
                let pb = PathBuf::from(&p);
                if pb.is_relative() && !pb.exists() {
                    let in_config_dir = config_dir().join(&pb);
                    if in_config_dir.exists() {
                        return in_config_dir;
                    }
                }
                pb
            })
            .unwrap_or_else(|| {
                let in_config = config_dir().join("tidecloak.json");
                if in_config.exists() { return in_config; }
                if let Ok(exe) = env::current_exe() {
                    let beside = exe.parent().unwrap_or(exe.as_ref()).join("tidecloak.json");
                    if beside.exists() { return beside; }
                }
                PathBuf::from("tidecloak.json")
            });

        match fs::read_to_string(&path) {
            Ok(data) => {
                tracing::info!("Loading JWKS from {}", path.display());
                data
            }
            Err(e) => {
                tracing::error!("Failed to read {}: {e}", path.display());
                tracing::error!("Place tidecloak.json in {} or set tidecloak_config_path in gateway.toml", config_dir().display());
                std::process::exit(1);
            }
        }
    };

    let config: TidecloakConfig = match serde_json::from_str(&config_data) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to parse TideCloak config: {e}");
            std::process::exit(1);
        }
    };

    if config.jwk.keys.is_empty() {
        tracing::error!("No JWKS keys found in TideCloak config");
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
            // Strip trailing semicolons
            while raw_url.ends_with(';') {
                raw_url.pop();
            }
            let mut no_auth = false;
            let mut strip_auth = false;
            let mut auth = BackendAuth::Password;

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
                } else if lower.ends_with(";eddsa") {
                    auth = BackendAuth::EdDSA;
                    raw_url.truncate(raw_url.len() - ";eddsa".len());
                    raw_url = raw_url.trim().to_string();
                } else {
                    break;
                }
            }

            let protocol = if raw_url.starts_with("rdp://") {
                "rdp"
            } else if raw_url.starts_with("ssh://") {
                "ssh"
            } else {
                "http"
            };

            if raw_url.is_empty() {
                std::process::exit(1);
            }

            Some(BackendEntry {
                name,
                url: raw_url,
                protocol: protocol.to_string(),
                no_auth,
                strip_auth,
                auth,
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

#[cfg(test)]
mod remote_config_tests {
    use super::*;
    use serde_json::json;

    fn patch(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        value.as_object().expect("patch must be an object").clone()
    }

    fn base() -> GatewayToml {
        GatewayToml {
            gateway_id: Some("gw-1".into()),
            stun_server_url: Some("wss://signal.example.com".into()),
            api_secret: Some("shared-secret".into()),
            backends: Some("App=http://10.0.0.5:8080".into()),
            tidecloak_config_b64: Some("ZXhpc3Rpbmc=".into()),
            auth_server_public_url: Some("https://tc.example.com".into()),
            listen_port: Some(7891),
            https: Some(true),
            ..Default::default()
        }
    }

    fn rejected_reason(outcome: &RemoteConfigOutcome, field: &str) -> Option<String> {
        outcome.rejected.iter().find(|r| r.field == field).map(|r| r.reason.clone())
    }

    #[test]
    fn applies_backends_and_ports() {
        let p = patch(json!({
            "backends": "App=http://10.0.0.5:8080, Db=rdp://10.0.0.9:3389;eddsa",
            "listen_port": 9000,
        }));
        let (updated, outcome) = merge_remote_config(&base(), &p);

        assert!(outcome.changed);
        assert_eq!(outcome.rejected.len(), 0);
        assert_eq!(updated.backends.as_deref(), Some("App=http://10.0.0.5:8080, Db=rdp://10.0.0.9:3389;eddsa"));
        assert_eq!(updated.listen_port, Some(9000));
        let mut applied = outcome.applied.clone();
        applied.sort();
        assert_eq!(applied, vec!["backends", "listen_port"]);
    }

    #[test]
    fn refuses_to_repoint_the_trust_anchor() {
        let p = patch(json!({
            "tidecloak_config_b64": "YXR0YWNrZXI=",
            "auth_server_public_url": "https://attacker.example.com",
            "tc_internal_url": "https://attacker.example.com",
        }));
        let (updated, outcome) = merge_remote_config(&base(), &p);

        assert!(!outcome.changed, "a push must never change the trust anchor");
        assert!(outcome.applied.is_empty());
        assert_eq!(updated.tidecloak_config_b64.as_deref(), Some("ZXhpc3Rpbmc="));
        assert_eq!(updated.auth_server_public_url.as_deref(), Some("https://tc.example.com"));
        for field in ["tidecloak_config_b64", "auth_server_public_url", "tc_internal_url"] {
            assert_eq!(rejected_reason(&outcome, field).as_deref(), Some("set locally on the gateway only"));
        }
    }

    #[test]
    fn refuses_to_hijack_gateway_identity() {
        let p = patch(json!({
            "gateway_id": "someone-elses-gateway",
            "stun_server_url": "wss://attacker.example.com",
            "api_secret": "new-secret",
        }));
        let (updated, outcome) = merge_remote_config(&base(), &p);

        assert!(!outcome.changed);
        assert_eq!(updated.gateway_id.as_deref(), Some("gw-1"));
        assert_eq!(updated.stun_server_url.as_deref(), Some("wss://signal.example.com"));
        assert_eq!(updated.api_secret.as_deref(), Some("shared-secret"));
        assert_eq!(outcome.rejected.len(), 3);
    }

    #[test]
    fn a_rejected_field_does_not_block_the_allowed_ones() {
        let p = patch(json!({ "backends": "App=http://10.0.0.6:8080", "api_secret": "nope" }));
        let (updated, outcome) = merge_remote_config(&base(), &p);

        assert_eq!(outcome.applied, vec!["backends"]);
        assert_eq!(updated.backends.as_deref(), Some("App=http://10.0.0.6:8080"));
        assert_eq!(updated.api_secret.as_deref(), Some("shared-secret"));
    }

    #[test]
    fn repeated_push_of_the_same_values_is_a_no_op() {
        let p = patch(json!({ "backends": "App=http://10.0.0.5:8080", "listen_port": 7891 }));
        let (_, outcome) = merge_remote_config(&base(), &p);

        assert!(!outcome.changed, "unchanged values must not trigger a reload");
        assert!(outcome.applied.is_empty());
    }

    #[test]
    fn wrong_types_are_rejected_not_coerced() {
        let p = patch(json!({ "listen_port": "9000", "https": "yes", "backends": 42 }));
        let (updated, outcome) = merge_remote_config(&base(), &p);

        assert!(!outcome.changed);
        assert_eq!(updated.listen_port, Some(7891));
        assert_eq!(updated.https, Some(true));
        assert_eq!(rejected_reason(&outcome, "listen_port").as_deref(), Some("expected a port between 1 and 65535"));
        assert_eq!(rejected_reason(&outcome, "https").as_deref(), Some("expected true or false"));
        assert_eq!(rejected_reason(&outcome, "backends").as_deref(), Some("expected a string"));
    }

    #[test]
    fn out_of_range_ports_are_rejected() {
        let p = patch(json!({ "listen_port": 0, "health_port": 70000 }));
        let (updated, outcome) = merge_remote_config(&base(), &p);

        assert!(!outcome.changed);
        assert_eq!(updated.listen_port, Some(7891));
        assert_eq!(outcome.rejected.len(), 2);
    }

    #[test]
    fn unknown_fields_are_reported_rather_than_silently_dropped() {
        let p = patch(json!({ "totally_made_up": "x" }));
        let (_, outcome) = merge_remote_config(&base(), &p);

        assert_eq!(rejected_reason(&outcome, "totally_made_up").as_deref(), Some("unknown field"));
    }

    #[test]
    fn null_clears_an_optional_field() {
        let p = patch(json!({ "turn_server": null }));
        let mut original = base();
        original.turn_server = Some("turn:1.2.3.4:3478".into());
        let (updated, outcome) = merge_remote_config(&original, &p);

        assert!(outcome.changed);
        assert_eq!(updated.turn_server, None);
    }

    fn scratch_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("punchd-config-test-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn writes_a_config_that_reads_back() {
        let dir = scratch_dir("write-new");
        let path = dir.join("gateway.toml");

        write_toml_to(&path, &base()).expect("writes");

        let written = fs::read_to_string(&path).expect("readable");
        assert!(written.starts_with("# Punchd Gateway Configuration"));
        let reparsed: GatewayToml = toml::from_str(&written).expect("parses");
        assert_eq!(reparsed.gateway_id.as_deref(), Some("gw-1"));
        assert_eq!(reparsed.listen_port, Some(7891));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn overwrites_an_existing_config_and_leaves_no_temp_file() {
        let dir = scratch_dir("overwrite");
        let path = dir.join("gateway.toml");
        fs::write(&path, "backends = \"Old=http://old:80\"\n").expect("seed");

        let (updated, _) = merge_remote_config(&base(), &patch(json!({ "backends": "New=http://new:80" })));
        write_toml_to(&path, &updated).expect("writes");

        let written = fs::read_to_string(&path).expect("readable");
        assert!(written.contains("New=http://new:80"));
        assert!(!written.contains("Old=http://old:80"));
        assert!(!dir.join("gateway.toml.tmp").exists(), "temp file must not be left behind");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn creates_the_config_directory_when_it_does_not_exist() {
        // Gateways configured only by environment variables (the container
        // images) have no config dir at all until the first push.
        let dir = scratch_dir("no-parent");
        let path = dir.join("nested").join("deeper").join("gateway.toml");
        assert!(!path.parent().unwrap().exists());

        write_toml_to(&path, &base()).expect("creates the directory and writes");

        let reparsed: GatewayToml =
            toml::from_str(&fs::read_to_string(&path).expect("readable")).expect("parses");
        assert_eq!(reparsed.gateway_id.as_deref(), Some("gw-1"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn falls_back_to_in_place_write_when_rename_is_impossible() {
        // Stands in for a single-file bind mount (`-v host.toml:/app/gateway.toml`),
        // where renaming over the target fails with EBUSY. Here the temp path is
        // occupied by a directory, so the rename cannot succeed either way, and
        // only the in-place fallback can complete the write.
        let dir = scratch_dir("no-rename");
        let path = dir.join("gateway.toml");
        fs::write(&path, "backends = \"Old=http://old:80\"\n").expect("seed");
        fs::create_dir_all(path.with_extension("toml.tmp")).expect("block the temp path");

        write_toml_to(&path, &base()).expect("falls back rather than failing");

        let written = fs::read_to_string(&path).expect("readable");
        assert!(written.contains("gateway_id = \"gw-1\""));
        assert!(!written.contains("Old=http://old:80"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn serialized_config_omits_unset_fields() {
        let (updated, _) = merge_remote_config(&base(), &patch(json!({ "listen_port": 9000 })));
        let rendered = toml::to_string_pretty(&updated).expect("serializes");

        assert!(rendered.contains("listen_port = 9000"));
        assert!(!rendered.contains("description"), "unset fields must not be written as empty keys");
        // Round-trips: the gateway must be able to read back what it wrote.
        let reparsed: GatewayToml = toml::from_str(&rendered).expect("parses");
        assert_eq!(reparsed.listen_port, Some(9000));
        assert_eq!(reparsed.gateway_id.as_deref(), Some("gw-1"));
    }
}
