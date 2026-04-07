/// HTTP auth gateway with server-side OIDC login flow.
///
/// Public routes (no auth): /auth/*, /health, /js/*, /wasm/*, /rdp, /webrtc-config
/// Protected routes: everything else -> validate JWT -> proxy to backend
///
/// Auth is extracted from:
///   1. `gateway_access` httpOnly cookie (browser sessions)
///   2. `Authorization: Bearer <jwt>` header (API/programmatic access)
///
/// When the access token expires, the gateway transparently refreshes
/// using the refresh token cookie before proxying.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

// ── Embedded static assets (baked into the binary) ──────────────
static ASSET_RDP_HTML: &str = include_str!("../../public/rdp.html");
static ASSET_JS_SW: &str = include_str!("../../public/js/sw.js");
static ASSET_JS_RDP_CLIENT: &str = include_str!("../../public/js/rdp-client.js");
static ASSET_JS_WEBRTC_UPGRADE: &str = include_str!("../../public/js/webrtc-upgrade.js");
static ASSET_JS_WEBTRANSPORT_UPGRADE: &str = include_str!("../../public/js/webtransport-upgrade.js");
static ASSET_JS_TIDE_E2E: &str = include_str!("../../public/js/tide-e2e.js");
static ASSET_WASM_JS: &str = include_str!("../../public/wasm/ironrdp_web.js");
static ASSET_WASM_BG: &[u8] = include_bytes!("../../public/wasm/ironrdp_web_bg.wasm");
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use axum::http::{Method, Request, StatusCode};
use axum::response::Response;
use axum::routing::{any, get};
use axum::Router;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

use crate::auth::dpop::{extract_cnf_jkt, DPoPVerifier};
use crate::auth::oidc::{
    build_auth_url, build_logout_url, exchange_code, get_oidc_endpoints, parse_state,
    refresh_access_token, OidcEndpoints,
};
use crate::auth::tidecloak::{JwtPayload, TidecloakAuth};
use crate::config::{ServerConfig, TidecloakConfig};

// ── Session types ────────────────────────────────────────────────

#[derive(Clone)]
pub struct TcSession {
    pub cookies: HashMap<String, String>,
    pub last_access: u64,
}

#[derive(Clone)]
pub struct BackendSession {
    pub cookies: HashMap<String, String>,
    pub last_access: u64,
}

#[derive(Clone)]
pub struct RefreshResult {
    pub access_token: String,
    pub expires_in: u64,
    pub refresh_token: Option<String>,
    pub refresh_expires_in: Option<u64>,
    pub timestamp: u64,
}

// ── Rate limiter state ───────────────────────────────────────────

#[allow(dead_code)]
struct RateLimitEntry {
    timestamps: Vec<u64>,
}

// ── Proxy state ──────────────────────────────────────────────────

pub struct ProxyState {
    pub config: ServerConfig,
    pub tc_config: TidecloakConfig,
    pub auth: Arc<TidecloakAuth>,
    pub dpop_verifier: Arc<DPoPVerifier>,
    pub backend_map: HashMap<String, url::Url>,
    pub no_auth_backends: HashSet<String>,
    pub strip_auth_backends: HashSet<String>,
    pub port_to_backend: HashMap<String, String>,
    pub tc_cookie_jar: DashMap<String, TcSession>,
    pub backend_cookie_jar: DashMap<String, BackendSession>,
    pub server_endpoints: OidcEndpoints,
    pub browser_endpoints: Option<OidcEndpoints>,
    pub client_id: String,
    pub role_client_id: String,
    pub refresh_cache: DashMap<String, RefreshResult>,
    pub refresh_in_flight: DashMap<String, Arc<Notify>>,
    pub use_tls: bool,
    pub http_client: reqwest::Client,
    pub session_token_hits: DashMap<String, Vec<u64>>,
    pub tc_proxy_url: url::Url,
    pub tc_public_origin: Option<String>,
    pub gateway_id: Option<String>,
    pub default_backend_name: String,
}

const TC_SESS_MAX_AGE: u64 = 3600;
const BACKEND_SESS_MAX_AGE: u64 = 7 * 24 * 3600;
const MAX_JAR_ENTRIES: usize = 10_000;

// ── Helpers ──────────────────────────────────────────────────────

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn parse_cookies(header: Option<&str>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(header) = header else { return map };
    for pair in header.split(';') {
        if let Some(eq) = pair.find('=') {
            let name = pair[..eq].trim().to_string();
            let value = pair[eq + 1..].trim().to_string();
            map.insert(name, value);
        }
    }
    map
}

fn build_cookie_header(name: &str, value: &str, max_age: u64, same_site: &str, secure: bool) -> String {
    let needs_secure = same_site == "None" || secure;
    let secure_flag = if needs_secure { "; Secure" } else { "" };
    format!(
        "{name}={value}; HttpOnly; Path=/; Max-Age={max_age}; SameSite={same_site}{secure_flag}"
    )
}

fn clear_cookie_header(name: &str, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!("{name}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax{secure_flag}")
}

fn sanitize_redirect(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return "/".to_string();
    }
    if trimmed.starts_with("//") {
        return "/".to_string();
    }
    // Check for scheme like http:, javascript:, etc.
    let has_scheme = trimmed
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
        && trimmed.contains(':')
        && {
            let colon_pos = trimmed.find(':').unwrap();
            trimmed[..colon_pos]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '.' || c == '-')
        };
    if has_scheme {
        return "/".to_string();
    }
    if !trimmed.starts_with('/') {
        return "/".to_string();
    }
    trimmed.to_string()
}

fn is_browser_request(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/html"))
}

fn is_public_resource(path: &str) -> bool {
    let basename = path.rsplit('/').next().unwrap_or("");
    basename == "manifest.json"
        || basename.ends_with(".webmanifest")
        || basename == "browserconfig.xml"
        || basename == "robots.txt"
        || basename.ends_with(".ico")
}

fn get_callback_url(host: &str, is_tls: bool) -> String {
    // If host is loopback (relay/DataChannel), use the gateway's configured server_url
    // so the OIDC redirect goes to the correct public address
    let proto = if is_tls { "https" } else { "http" };
    format!("{proto}://{host}/auth/callback")
}

fn get_callback_url_with_config(host: &str, is_tls: bool, server_url: &Option<String>) -> String {
    // When accessed via relay/DataChannel, Host header is 127.0.0.1 or localhost.
    // Use server_url for the OIDC redirect so it goes to the signal server's public URL.
    if let Some(url) = server_url {
        if host.starts_with("127.0.0.1") || host.starts_with("localhost") || host.starts_with("[::1]") {
            return format!("{}/auth/callback", url.trim_end_matches('/'));
        }
    }
    get_callback_url(host, is_tls)
}

const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

fn security_headers(headers: &mut HeaderMap, is_tls: bool) {
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("SAMEORIGIN"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    if is_tls {
        headers.insert(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
}

/// Rewrite localhost:PORT URLs in Location header to /__b/<name>.
fn rewrite_location(
    location: &str,
    tc_origin: &str,
    port_map: &HashMap<String, String>,
    replacement: &str,
) -> String {
    let result;

    // Rewrite TideCloak origin first (at start of Location)
    if !tc_origin.is_empty() && location.starts_with(tc_origin) {
        let rest = &location[tc_origin.len()..];
        let suffix = if rest.is_empty() { "/" } else { rest };
        result = format!("{replacement}{suffix}");
    } else {
        // Rewrite localhost:PORT at start
        let re = Regex::new(r"^https?://localhost(:\d+)?").unwrap();
        result = re.replace(location, |caps: &regex::Captures| {
            if let Some(port_group) = caps.get(1) {
                let port = &port_group.as_str()[1..]; // strip leading ':'
                if let Some(name) = port_map.get(port) {
                    return format!(
                        "/__b/{}",
                        percent_encoding::utf8_percent_encode(
                            name,
                            percent_encoding::NON_ALPHANUMERIC
                        )
                    );
                }
            }
            replacement.to_string()
        })
        .to_string();
    }

    // NOTE: Do NOT rewrite URL-encoded origins in query params — Tide IDP
    // redirect_uri is signed and must not be modified.

    result
}

/// Rewrite all localhost:PORT URLs in HTML body to /__b/<name>.
fn rewrite_localhost_in_html(html: &str, port_map: &HashMap<String, String>) -> String {
    let re = Regex::new(r"https?://localhost(:\d+)?").unwrap();
    re.replace_all(html, |caps: &regex::Captures| {
        if let Some(port_group) = caps.get(1) {
            let port = &port_group.as_str()[1..];
            if let Some(name) = port_map.get(port) {
                return format!(
                    "/__b/{}",
                    percent_encoding::utf8_percent_encode(
                        name,
                        percent_encoding::NON_ALPHANUMERIC
                    )
                );
            }
        }
        String::new()
    })
    .to_string()
}

/// Prepend /__b/<name> to absolute paths in href/src/action attributes.
fn prepend_prefix(html: &str, prefix: &str) -> String {
    let re = Regex::new(r#"((?:href|src|action|formaction)\s*=\s*["'])(\/(?!\/|__b\/))"#).unwrap();
    re.replace_all(html, |caps: &regex::Captures| {
        format!("{}{}{}", &caps[1], prefix, &caps[2])
    })
    .to_string()
}

/// Build the fetch/XHR interceptor script for path-based backends.
fn build_patch_script(backend_prefix: &str) -> String {
    let safe_prefix = backend_prefix
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('<', "\\x3c");

    format!(
        r#"<script>(function(){{var P="{safe_prefix}";var W=/^\/(js\/|auth\/|login|webrtc-config|rdp|realms\/|resources\/|portal|health)/;function n(u){{return typeof u==="string"&&u[0]==="/"&&u.indexOf("/__b/")!==0&&!W.test(u)}}var F=window.fetch;window.fetch=function(u,i){{if(n(u))u=P+u;else if(u instanceof Request){{var r=new URL(u.url);if(r.origin===location.origin&&n(r.pathname)){{r.pathname=P+r.pathname;u=new Request(r,u)}}}}return F.call(this,u,i)}};var O=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){{if(n(u))arguments[1]=P+u;return O.apply(this,arguments)}};["HTMLMediaElement","HTMLSourceElement","HTMLImageElement","HTMLScriptElement","HTMLIFrameElement"].forEach(function(c){{var E=window[c];if(!E)return;var d=Object.getOwnPropertyDescriptor(E.prototype,"src");if(!d||!d.set)return;Object.defineProperty(E.prototype,"src",{{get:d.get,set:function(v){{d.set.call(this,n(v)?P+v:v)}},configurable:true}})}});var SA=Element.prototype.setAttribute;Element.prototype.setAttribute=function(a,v){{if((a==="src"||a==="href")&&typeof v==="string"&&n(v))v=P+v;return SA.call(this,a,v)}}}})();</script>"#
    )
}

/// Parse Set-Cookie headers and store in a cookie map.
fn store_cookies_in_map(
    map: &mut HashMap<String, String>,
    set_cookie_values: &[String],
) {
    for h in set_cookie_values {
        if let Some(eq) = h.find('=') {
            let name = h[..eq].trim().to_string();
            let rest = &h[eq + 1..];
            let value = if let Some(semi) = rest.find(';') {
                &rest[..semi]
            } else {
                rest
            };
            // Max-Age=0 or empty value means delete
            if value.is_empty() || h.to_lowercase().contains("max-age=0") {
                map.remove(&name);
            } else {
                map.insert(name, value.to_string());
            }
        }
    }
}

fn cookies_to_header(map: &HashMap<String, String>) -> String {
    map.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Extract Set-Cookie header values from a response HeaderMap.
fn extract_set_cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .collect()
}

fn generate_session_id() -> String {
    use rand::Rng;
    let bytes: [u8; 16] = rand::rng().random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── ProxyState constructor ───────────────────────────────────────

impl ProxyState {
    #[allow(dead_code)]
    pub fn new(
        config: ServerConfig,
        tc_config: TidecloakConfig,
        auth: Arc<TidecloakAuth>,
        dpop_verifier: Arc<DPoPVerifier>,
    ) -> Self {
        // Build backend maps (HTTP-only backends)
        let mut backend_map = HashMap::new();
        let mut no_auth_backends = HashSet::new();
        let mut strip_auth_backends = HashSet::new();
        let mut port_to_backend = HashMap::new();

        for b in &config.backends {
            if b.protocol != "http" {
                continue;
            }
            if let Ok(u) = url::Url::parse(&b.url) {
                backend_map.insert(b.name.clone(), u.clone());
                if b.no_auth {
                    no_auth_backends.insert(b.name.clone());
                    tracing::info!("Backend \"{}\" — auth disabled (noauth)", b.name);
                }
                if b.strip_auth {
                    strip_auth_backends.insert(b.name.clone());
                    tracing::info!("Backend \"{}\" — auth header stripped (stripauth)", b.name);
                }
                let host = u.host_str().unwrap_or("");
                if host == "localhost" || host == "127.0.0.1" {
                    let port = u
                        .port()
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| {
                            if u.scheme() == "https" { "443" } else { "80" }.to_string()
                        });
                    port_to_backend.insert(port, b.name.clone());
                }
            }
        }

        let tc_internal_url = config
            .tc_internal_url
            .as_deref()
            .unwrap_or(&tc_config.auth_server_url);

        let tc_proxy_url = url::Url::parse(tc_internal_url).unwrap_or_else(|_| {
            url::Url::parse(&tc_config.auth_server_url).expect("Invalid auth_server_url")
        });

        let tc_public_origin = url::Url::parse(&tc_config.auth_server_url)
            .ok()
            .map(|u| u.origin().ascii_serialization());

        let server_endpoints = get_oidc_endpoints(&tc_config, Some(tc_internal_url));
        let browser_endpoints = config
            .auth_server_public_url
            .as_deref()
            .map(|url| get_oidc_endpoints(&tc_config, Some(url)));

        let client_id = tc_config.resource.clone();

        let default_backend_name = config
            .backends
            .first()
            .map(|b| b.name.clone())
            .unwrap_or_else(|| "Default".to_string());

        tracing::info!("TideCloak internal URL: {tc_internal_url}");
        tracing::info!("TideCloak public origin: {tc_public_origin:?}");

        let http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("Failed to build HTTP client");

        Self {
            use_tls: config.https,
            gateway_id: Some(config.gateway_id.clone()),
            config,
            tc_config,
            auth,
            dpop_verifier,
            backend_map,
            no_auth_backends,
            strip_auth_backends,
            port_to_backend,
            tc_cookie_jar: DashMap::new(),
            backend_cookie_jar: DashMap::new(),
            server_endpoints,
            browser_endpoints,
            role_client_id: client_id.clone(),
            client_id,
            refresh_cache: DashMap::new(),
            refresh_in_flight: DashMap::new(),
            http_client,
            session_token_hits: DashMap::new(),
            tc_proxy_url,
            tc_public_origin,
            default_backend_name,
        }
    }

    /// Get browser-facing OIDC endpoints.
    fn get_browser_endpoints(&self) -> OidcEndpoints {
        if let Some(ref ep) = self.browser_endpoints {
            ep.clone()
        } else {
            // Use relative paths so auth URLs route through the gateway's TC proxy
            get_oidc_endpoints(&self.tc_config, Some(""))
        }
    }

    /// Deduplicated token refresh: cache recent results, coalesce concurrent refreshes.
    async fn deduplicated_refresh(&self, refresh_token: &str) -> Option<RefreshResult> {
        // Check cache (< 60s old)
        if let Some(cached) = self.refresh_cache.get(refresh_token) {
            if now_millis() - cached.timestamp < 60_000 {
                return Some(cached.clone());
            }
        }

        // Check if refresh is already in flight
        if let Some(notify) = self.refresh_in_flight.get(refresh_token) {
            let n = notify.clone();
            drop(notify);
            n.notified().await;
            // Result should now be in cache
            return self.refresh_cache.get(refresh_token).map(|r| r.clone());
        }

        // Start refresh
        let notify = Arc::new(Notify::new());
        self.refresh_in_flight
            .insert(refresh_token.to_string(), notify.clone());

        let result = match refresh_access_token(
            &self.server_endpoints,
            &self.client_id,
            refresh_token,
        )
        .await
        {
            Ok(tokens) => {
                let r = RefreshResult {
                    access_token: tokens.access_token,
                    expires_in: tokens.expires_in,
                    refresh_token: tokens.refresh_token,
                    refresh_expires_in: tokens.refresh_expires_in,
                    timestamp: now_millis(),
                };
                // Evict old cache entries
                if self.refresh_cache.len() > 100 {
                    // Remove first entry
                    if let Some(entry) = self.refresh_cache.iter().next() {
                        let key = entry.key().clone();
                        drop(entry);
                        self.refresh_cache.remove(&key);
                    }
                }
                self.refresh_cache.insert(refresh_token.to_string(), r.clone());
                Some(r)
            }
            Err(e) => {
                tracing::error!("Deduplicated refresh failed: {e}");
                None
            }
        };

        self.refresh_in_flight.remove(refresh_token);
        notify.notify_waiters();
        result
    }

    /// Get or create a TC session from the browser's tc_sess cookie.
    fn get_tc_session_id(&self, cookies: &HashMap<String, String>) -> (String, bool) {
        if let Some(id) = cookies.get("tc_sess") {
            if self.tc_cookie_jar.contains_key(id) {
                if let Some(mut session) = self.tc_cookie_jar.get_mut(id) {
                    session.last_access = now_secs();
                }
                return (id.clone(), false);
            }
        }
        let id = generate_session_id();
        self.tc_cookie_jar.insert(
            id.clone(),
            TcSession {
                cookies: HashMap::new(),
                last_access: now_secs(),
            },
        );
        (id, true)
    }

    /// Store TC Set-Cookie values in the server-side jar.
    fn store_tc_cookies(&self, session_id: &str, set_cookies: &[String]) {
        if set_cookies.is_empty() {
            return;
        }
        if let Some(mut session) = self.tc_cookie_jar.get_mut(session_id) {
            session.last_access = now_secs();
            store_cookies_in_map(&mut session.cookies, set_cookies);
        }
    }

    /// Build a Cookie header from the TC jar for proxied requests.
    fn get_tc_cookie_header(&self, session_id: &str) -> String {
        if let Some(mut session) = self.tc_cookie_jar.get_mut(session_id) {
            if session.cookies.is_empty() {
                return String::new();
            }
            session.last_access = now_secs();
            cookies_to_header(&session.cookies)
        } else {
            String::new()
        }
    }

    /// Store backend Set-Cookie values keyed by userId:backendName.
    fn store_backend_cookies(&self, key: &str, set_cookies: &[String]) {
        if set_cookies.is_empty() || key.is_empty() {
            return;
        }
        let mut entry = self.backend_cookie_jar.entry(key.to_string()).or_insert_with(|| {
            BackendSession {
                cookies: HashMap::new(),
                last_access: now_secs(),
            }
        });
        entry.last_access = now_secs();
        store_cookies_in_map(&mut entry.cookies, set_cookies);
    }

    /// Build a Cookie header from the backend jar.
    fn get_backend_cookie_header(&self, key: &str) -> String {
        if let Some(mut session) = self.backend_cookie_jar.get_mut(key) {
            if session.cookies.is_empty() {
                return String::new();
            }
            session.last_access = now_secs();
            cookies_to_header(&session.cookies)
        } else {
            String::new()
        }
    }

    /// Resolve the target backend URL for a request.
    fn resolve_backend(
        &self,
        active_backend: &str,
        headers: &HeaderMap,
    ) -> url::Url {
        // 1. Path-based /__b/<name> prefix
        if !active_backend.is_empty() {
            if let Some(u) = self.backend_map.get(active_backend) {
                return u.clone();
            }
        }
        // 2. x-gateway-backend header
        if let Some(hdr) = headers
            .get("x-gateway-backend")
            .and_then(|v| v.to_str().ok())
        {
            if let Some(u) = self.backend_map.get(hdr) {
                return u.clone();
            }
        }
        // 3. Default backend
        url::Url::parse(&self.config.backend_url).expect("Invalid default backend URL")
    }

    /// Evict expired sessions from both jars. Called periodically.
    pub fn evict_stale_sessions(&self) {
        let now = now_secs();

        // TC sessions
        self.tc_cookie_jar
            .retain(|_, session| now - session.last_access < TC_SESS_MAX_AGE);
        if self.tc_cookie_jar.len() > MAX_JAR_ENTRIES {
            // Simple LRU: remove oldest
            let mut entries: Vec<_> = self
                .tc_cookie_jar
                .iter()
                .map(|e| (e.key().clone(), e.last_access))
                .collect();
            entries.sort_by_key(|(_, t)| *t);
            let to_remove = entries.len() - MAX_JAR_ENTRIES;
            for (id, _) in entries.into_iter().take(to_remove) {
                self.tc_cookie_jar.remove(&id);
            }
        }

        // Backend sessions
        self.backend_cookie_jar
            .retain(|_, session| now - session.last_access < BACKEND_SESS_MAX_AGE);
        if self.backend_cookie_jar.len() > MAX_JAR_ENTRIES {
            let mut entries: Vec<_> = self
                .backend_cookie_jar
                .iter()
                .map(|e| (e.key().clone(), e.last_access))
                .collect();
            entries.sort_by_key(|(_, t)| *t);
            let to_remove = entries.len() - MAX_JAR_ENTRIES;
            for (id, _) in entries.into_iter().take(to_remove) {
                self.backend_cookie_jar.remove(&id);
            }
        }

        // Rate limiter stale IPs
        let now_ms = now_millis();
        self.session_token_hits
            .retain(|_, times| !times.is_empty() && now_ms - *times.last().unwrap() < 120_000);
    }
}

// ── State builder ────────────────────────────────────────────────

pub fn build_proxy_state(
    config: &ServerConfig,
    tc_config: &TidecloakConfig,
    auth: Arc<TidecloakAuth>,
    use_tls: bool,
) -> Arc<ProxyState> {
    let base_url = config
        .tc_internal_url
        .as_deref()
        .unwrap_or(&tc_config.auth_server_url)
        .trim_end_matches('/');
    let realm = &tc_config.realm;

    // Build OIDC endpoint URLs for the TideCloak server
    let server_endpoints = OidcEndpoints {
        authorization: format!("{base_url}/realms/{realm}/protocol/openid-connect/auth"),
        token: format!("{base_url}/realms/{realm}/protocol/openid-connect/token"),
        logout: format!("{base_url}/realms/{realm}/protocol/openid-connect/logout"),
    };

    // If there is a separate public auth URL, build browser-facing endpoints
    let browser_endpoints = config.auth_server_public_url.as_ref().map(|public_url| {
        let pub_base = public_url.trim_end_matches('/');
        OidcEndpoints {
            authorization: format!("{pub_base}/realms/{realm}/protocol/openid-connect/auth"),
            token: format!("{pub_base}/realms/{realm}/protocol/openid-connect/token"),
            logout: format!("{pub_base}/realms/{realm}/protocol/openid-connect/logout"),
        }
    });

    // Build backend map
    let mut backend_map = HashMap::new();
    let mut no_auth_backends = HashSet::new();
    let mut strip_auth_backends = HashSet::new();
    let mut port_to_backend = HashMap::new();
    let mut default_backend_name = String::new();

    for (i, b) in config.backends.iter().enumerate() {
        if b.protocol == "http" {
            if let Ok(parsed) = url::Url::parse(&b.url) {
                backend_map.insert(b.name.clone(), parsed.clone());
                if let Some(port) = parsed.port() {
                    port_to_backend.insert(port.to_string(), b.name.clone());
                }
            }
        }
        if b.no_auth {
            no_auth_backends.insert(b.name.clone());
        }
        if b.strip_auth {
            strip_auth_backends.insert(b.name.clone());
        }
        if i == 0 {
            default_backend_name = b.name.clone();
        }
    }

    let tc_proxy_url = url::Url::parse(&format!("{}/", base_url)).unwrap();
    let tc_public_origin = config.auth_server_public_url.clone();

    // Resolve public directory: check next to executable first, then cwd
    let http_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    Arc::new(ProxyState {
        config: config.clone(),
        tc_config: tc_config.clone(),
        auth,
        dpop_verifier: Arc::new(DPoPVerifier::new()),
        backend_map,
        no_auth_backends,
        strip_auth_backends,
        port_to_backend,
        tc_cookie_jar: DashMap::new(),
        backend_cookie_jar: DashMap::new(),
        server_endpoints,
        browser_endpoints,
        client_id: tc_config.resource.clone(),
        role_client_id: tc_config.resource.clone(),
        refresh_cache: DashMap::new(),
        refresh_in_flight: DashMap::new(),
        use_tls,
        http_client,
        session_token_hits: DashMap::new(),
        tc_proxy_url,
        tc_public_origin,
        gateway_id: Some(config.gateway_id.clone()),
        default_backend_name,
    })
}

// ── Gateway info endpoint for local discovery ───────────────────

async fn handle_api_info(
    State(state): State<SharedState>,
) -> axum::Json<serde_json::Value> {
    let s = state.load();
    let backends: Vec<serde_json::Value> = s.config.backends.iter().map(|b| {
        serde_json::json!({
            "name": b.name,
            "protocol": b.protocol,
        })
    }).collect();

    axum::Json(serde_json::json!({
        "status": "ok",
        "gatewayId": s.gateway_id,
        "displayName": s.config.display_name,
        "backends": backends,
    }))
}

// ── Router builder ───────────────────────────────────────────────

/// Shared handle for hot-reloading ProxyState.
pub type SharedState = Arc<ArcSwap<ProxyState>>;

pub fn build_router(state: Arc<ProxyState>) -> (Router, SharedState) {
    let shared = Arc::new(ArcSwap::new(state));

    // Spawn periodic session eviction (every 10 minutes)
    let evict_state = shared.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(600));
        loop {
            interval.tick().await;
            evict_state.load().evict_stale_sessions();
        }
    });

    let router = Router::new()
        .route("/ws/rdcleanpath", get(handle_rdcleanpath_ws))
        .route("/ws/tcp-forward", get(handle_tcp_forward_ws))
        .route("/ws/ssh", get(handle_ssh_ws))
        .route("/api/info", get(handle_api_info))
        .fallback(any(handle_request))
        .with_state(shared.clone());

    (router, shared)
}

/// Reload the proxy state from disk. Preserves session caches.
pub fn reload_state(
    shared: &SharedState,
    config: &crate::config::ServerConfig,
    tc_config: &crate::config::TidecloakConfig,
    auth: Arc<crate::auth::tidecloak::TidecloakAuth>,
    use_tls: bool,
) {
    let old = shared.load();

    let new_state = build_proxy_state(config, tc_config, auth, use_tls);

    // Preserve session caches from old state
    for entry in old.tc_cookie_jar.iter() {
        new_state.tc_cookie_jar.insert(entry.key().clone(), (*entry.value()).clone());
    }
    for entry in old.backend_cookie_jar.iter() {
        new_state.backend_cookie_jar.insert(entry.key().clone(), (*entry.value()).clone());
    }

    shared.store(new_state);
    tracing::info!("[Config] ProxyState hot-reloaded (backends, auth, VPN settings updated)");
}

// ── RDCleanPath WebSocket handler ────────────────────────────────

async fn handle_rdcleanpath_ws(
    State(shared): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> Response {
    let state = shared.load_full();
    // Recording token: prefer query param, then keylessh_token cookie (original myclient token preserved by signal server)
    let recording_token = params.get("recording_token").cloned()
        .or_else(|| {
            headers.get(header::COOKIE)
                .and_then(|v| v.to_str().ok())
                .and_then(|cookies| {
                    cookies.split(';')
                        .find_map(|c| {
                            let c = c.trim();
                            if c.starts_with("keylessh_token=") {
                                Some(c["keylessh_token=".len()..].to_string())
                            } else {
                                None
                            }
                        })
                })
        });
    ws.protocols(["rdcleanpath"])
        .on_upgrade(move |socket| handle_rdcleanpath_socket(socket, state, recording_token))
}

async fn handle_rdcleanpath_socket(socket: WebSocket, state: Arc<ProxyState>, recording_token: Option<String>) {
    use futures_util::{SinkExt, StreamExt};

    tracing::info!("[RDCleanPath-WS] Handler started");

    let (mut ws_sink, mut ws_stream) = socket.split();

    // Use an ordered channel for outgoing WS messages to preserve data ordering.
    // The send_binary callback must NOT spawn independent tasks (they'd race the mutex).
    enum WsOut {
        Binary(Vec<u8>),
        Close(u16, String),
    }
    let (out_tx, mut out_rx) = tokio::sync::mpsc::unbounded_channel::<WsOut>();

    let send_binary: crate::rdcleanpath::rdcleanpath_handler::SendBinaryFn = {
        let tx = out_tx.clone();
        Arc::new(move |data: Vec<u8>| {
            let _ = tx.send(WsOut::Binary(data));
        })
    };

    let send_close: crate::rdcleanpath::rdcleanpath_handler::SendCloseFn = {
        let tx = out_tx.clone();
        Arc::new(move |code: u16, reason: String| {
            let _ = tx.send(WsOut::Close(code, reason));
        })
    };
    drop(out_tx); // Only the callbacks hold references now

    let session = crate::rdcleanpath::rdcleanpath_handler::RDCleanPathSession::new(
        crate::rdcleanpath::rdcleanpath_handler::RDCleanPathSessionOptions {
            send_binary,
            send_close,
            backends: state.config.backends.clone(),
            auth: state.auth.clone(),
            gateway_id: state.gateway_id.clone(),
            server_url: state.config.server_url.clone(),
            recording: None,
            recording_token,
        },
    );

    // Single writer task — drains the channel in order, no races.
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            let result = match msg {
                WsOut::Binary(data) => ws_sink.send(Message::Binary(data.into())).await,
                WsOut::Close(code, reason) => {
                    tracing::info!("[RDCleanPath-WS] Session sending close: {} {}", code, reason);
                    let _r = ws_sink
                        .send(Message::Close(Some(axum::extract::ws::CloseFrame {
                            code,
                            reason: reason.into(),
                        })))
                        .await;
                    return; // Close sent — stop writing
                }
            };
            if let Err(e) = result {
                tracing::warn!("[RDCleanPath-WS] Write error: {}", e);
                return;
            }
        }
    });

    // Forward incoming WebSocket messages to the RDCleanPath session.
    loop {
        match ws_stream.next().await {
            Some(Ok(Message::Binary(data))) => {
                session.handle_message(data.to_vec());
            }
            Some(Ok(Message::Close(_))) => {
                tracing::info!("[RDCleanPath-WS] Received close frame");
                break;
            }
            Some(Ok(_)) => {} // Ping/Pong/Text — ignore
            Some(Err(e)) => {
                tracing::warn!("[RDCleanPath-WS] Read error: {}, continuing", e);
            }
            None => {
                tracing::info!("[RDCleanPath-WS] Stream ended");
                break;
            }
        }
    }

    writer_task.abort();
    tracing::info!("[RDCleanPath-WS] Handler exiting");
}

// ── TCP-forward WebSocket handler (trustless/blind proxy) ────────

async fn handle_tcp_forward_ws(
    State(shared): State<SharedState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let state = shared.load_full();
    ws.on_upgrade(move |socket| handle_tcp_forward_socket(socket, state))
}

/// Trustless TCP forwarder: browser sends a JSON routing header, then raw bytes
/// flow bidirectionally between the WebSocket and the backend TCP socket.
/// The proxy never inspects the payload — IronRDP WASM does TLS end-to-end.
async fn handle_tcp_forward_socket(socket: WebSocket, state: Arc<ProxyState>) {
    use futures_util::{SinkExt, StreamExt};

    tracing::info!("[TCP-Forward] Handler started");

    let (mut ws_sink, mut ws_stream) = socket.split();

    // Step 1: Read routing header (first WS message — Text or Binary JSON)
    let routing = match ws_stream.next().await {
        Some(Ok(Message::Text(text))) => {
            match serde_json::from_str::<serde_json::Value>(&text) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("[TCP-Forward] Invalid routing JSON (text): {e}");
                    let _ = ws_sink.send(Message::Close(None)).await;
                    return;
                }
            }
        }
        Some(Ok(Message::Binary(data))) => {
            match serde_json::from_slice::<serde_json::Value>(&data) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("[TCP-Forward] Invalid routing JSON (binary): {e}");
                    let _ = ws_sink.send(Message::Close(None)).await;
                    return;
                }
            }
        }
        other => {
            tracing::error!("[TCP-Forward] Expected JSON routing header as first message, got: {other:?}");
            let _ = ws_sink.send(Message::Close(None)).await;
            return;
        }
    };

    let destination = routing["destination"].as_str().unwrap_or("").to_string();
    let auth_token = routing["authToken"].as_str().unwrap_or("").to_string();

    if destination.is_empty() || auth_token.is_empty() {
        tracing::error!("[TCP-Forward] Missing destination or authToken");
        let _ = ws_sink.send(Message::Text(
            serde_json::json!({"error": "missing destination or authToken"}).to_string().into(),
        )).await;
        let _ = ws_sink.send(Message::Close(None)).await;
        return;
    }

    // Step 2: Verify JWT and check destination access
    let payload = match state.auth.verify_token(&auth_token).await {
        Some(p) => p,
        None => {
            tracing::error!("[TCP-Forward] Auth failed");
            let _ = ws_sink.send(Message::Text(
                serde_json::json!({"error": "auth failed"}).to_string().into(),
            )).await;
            let _ = ws_sink.send(Message::Close(None)).await;
            return;
        }
    };

    // Check destination role
    if crate::rdcleanpath::rdcleanpath_handler::check_dest_roles(&payload, &destination, &state.role_client_id).is_none() {
        tracing::error!("[TCP-Forward] Access denied for dest={destination} user={:?}", payload.sub);
        let _ = ws_sink.send(Message::Text(
            serde_json::json!({"error": "access denied"}).to_string().into(),
        )).await;
        let _ = ws_sink.send(Message::Close(None)).await;
        return;
    }

    // Step 3: Resolve backend
    let backend = state.config.backends.iter().find(|b| b.name == destination);
    let backend = match backend {
        Some(b) => b.clone(),
        None => {
            tracing::error!("[TCP-Forward] Unknown backend: {destination}");
            let _ = ws_sink.send(Message::Text(
                serde_json::json!({"error": "unknown backend"}).to_string().into(),
            )).await;
            let _ = ws_sink.send(Message::Close(None)).await;
            return;
        }
    };

    let parsed_url = match url::Url::parse(&backend.url) {
        Ok(u) => u,
        Err(_) => {
            let _ = ws_sink.send(Message::Text(
                serde_json::json!({"error": "invalid backend URL"}).to_string().into(),
            )).await;
            let _ = ws_sink.send(Message::Close(None)).await;
            return;
        }
    };

    let host = parsed_url.host_str().unwrap_or("127.0.0.1").to_string();
    let port = parsed_url.port().unwrap_or(3389);

    // Step 4: TCP connect to backend
    tracing::info!("[TCP-Forward] Connecting to {host}:{port} for dest={destination}");
    let tcp_stream = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(format!("{host}:{port}")),
    ).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::error!("[TCP-Forward] TCP connect failed: {e}");
            let _ = ws_sink.send(Message::Text(
                serde_json::json!({"error": format!("TCP connect failed: {e}")}).to_string().into(),
            )).await;
            let _ = ws_sink.send(Message::Close(None)).await;
            return;
        }
        Err(_) => {
            tracing::error!("[TCP-Forward] TCP connect timeout");
            let _ = ws_sink.send(Message::Text(
                serde_json::json!({"error": "TCP connect timeout"}).to_string().into(),
            )).await;
            let _ = ws_sink.send(Message::Close(None)).await;
            return;
        }
    };

    // Step 5: Send OK to client
    tracing::info!("[TCP-Forward] Connected to {host}:{port}, entering relay mode");
    if ws_sink.send(Message::Text(
        serde_json::json!({"ok": true, "host": host, "port": port}).to_string().into(),
    )).await.is_err() {
        return;
    }

    // Step 6: Blind bidirectional relay (WS <-> TCP)
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // TCP -> WS
    let mut ws_sink_relay = ws_sink;
    let tcp_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if ws_sink_relay.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // WS -> TCP
    let ws_to_tcp = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_stream.next().await {
            match msg {
                Message::Binary(data) => {
                    if tcp_write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = tcp_to_ws => {}
        _ = ws_to_tcp => {}
    }

    tracing::info!("[TCP-Forward] Session ended for dest={destination}");
}

// ── SSH WebSocket handler ────────────────────────────────────────
// Bidirectional TCP relay to an SSH server. The browser SSH terminal
// opens a WebSocket to /ws/ssh?host=X&port=Y&token=Z, gateway verifies
// the JWT and relays bytes to the SSH server.

async fn handle_ssh_ws(
    State(shared): State<SharedState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> Response {
    let state = shared.load_full();
    ws.on_upgrade(move |socket| handle_ssh_socket(socket, state, params))
}

async fn handle_ssh_socket(
    socket: WebSocket,
    state: Arc<ProxyState>,
    params: std::collections::HashMap<String, String>,
) {
    use futures_util::{SinkExt, StreamExt};

    let host = params.get("host").cloned().unwrap_or_default();
    let port: u16 = params.get("port").and_then(|p| p.parse().ok()).unwrap_or(22);
    let token = params.get("token").cloned().unwrap_or_default();

    if host.is_empty() || token.is_empty() {
        tracing::error!("[SSH] Missing host or token");
        return;
    }

    // Resolve backend name to actual host:port from config
    let (resolved_host, resolved_port) = if let Some(backend) = state.config.backends.iter().find(|b| b.protocol == "ssh" && b.name == host) {
        let url = backend.url.trim_start_matches("ssh://");
        if let Some((h, p)) = url.rsplit_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(22))
        } else {
            (url.to_string(), 22)
        }
    } else {
        (host.clone(), port)
    };

    tracing::info!("[SSH] Connection request: {host} -> {resolved_host}:{resolved_port}");

    // Verify JWT
    let payload = match state.auth.verify_token(&token).await {
        Some(p) => p,
        None => {
            tracing::error!("[SSH] JWT verification failed");
            let (mut sink, _) = socket.split();
            let _ = sink.send(Message::Text(
                serde_json::json!({"type": "error", "message": "Unauthorized"}).to_string().into()
            )).await;
            let _ = sink.send(Message::Close(None)).await;
            return;
        }
    };

    let user = payload.sub.as_deref().unwrap_or("unknown");
    tracing::info!("[SSH] Authenticated: {user} -> {host}:{port}");

    // Find the SSH backend
    let backend = state.config.backends.iter().find(|b| {
        b.protocol == "ssh" && (b.url == format!("{host}:{port}") || b.name == host)
    });

    let backend_name = backend.map(|b| b.name.clone()).unwrap_or_else(|| host.clone());

    // Check ssh: role — same pattern as dest: roles for RDP
    // Looks in all resource_access entries for ssh:<gateway>:<backend> or ssh:<gateway>:<backend>:<username>
    if !backend.map(|b| b.no_auth).unwrap_or(false) {
        let gateway_id = state.gateway_id.as_deref().unwrap_or("");
        let required_prefix = format!("ssh:{gateway_id}:{backend_name}");

        let mut all_roles: Vec<String> = Vec::new();
        if let Some(ref ra) = payload.realm_access {
            all_roles.extend(ra.roles.clone());
        }
        if let Some(ref ra) = payload.resource_access {
            if let Some(obj) = ra.as_object() {
                for (_, access) in obj {
                    if let Some(roles) = access.get("roles").and_then(|r| r.as_array()) {
                        for role in roles {
                            if let Some(r) = role.as_str() {
                                all_roles.push(r.to_string());
                            }
                        }
                    }
                }
            }
        }

        let has_access = all_roles.iter().any(|r| {
            r == &required_prefix || r.starts_with(&format!("{required_prefix}:"))
        });

        if !has_access {
            tracing::warn!("[SSH] Access denied for {user} to {backend_name} (need role {required_prefix})");
            let (mut sink, _) = socket.split();
            let _ = sink.send(Message::Text(
                serde_json::json!({"type": "error", "message": format!("Access denied: role '{}' required", required_prefix)}).to_string().into()
            )).await;
            let _ = sink.send(Message::Close(None)).await;
            return;
        }

        // Extract SSH username from role if present (ssh:<gw>:<backend>:<username>)
        let _ssh_username = all_roles.iter().find_map(|r| {
            if r.starts_with(&format!("{required_prefix}:")) {
                Some(r[required_prefix.len()+1..].to_string())
            } else {
                None
            }
        });
    }

    let (mut ws_sink, mut ws_stream) = socket.split();

    // Connect to SSH server (use resolved address from backend config)
    let addr = format!("{resolved_host}:{resolved_port}");
    let tcp_stream = match tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect(&addr),
    ).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::error!("[SSH] TCP connect to {addr} failed: {e}");
            let _ = ws_sink.send(Message::Text(
                serde_json::json!({"type": "error", "message": format!("Connection failed: {e}")}).to_string().into()
            )).await;
            let _ = ws_sink.send(Message::Close(None)).await;
            return;
        }
        Err(_) => {
            tracing::error!("[SSH] TCP connect to {addr} timed out");
            let _ = ws_sink.send(Message::Text(
                serde_json::json!({"type": "error", "message": "Connection timed out"}).to_string().into()
            )).await;
            let _ = ws_sink.send(Message::Close(None)).await;
            return;
        }
    };

    tracing::info!("[SSH] TCP connected to {addr}");

    // Send connected notification
    let _ = ws_sink.send(Message::Text(
        serde_json::json!({"type": "connected"}).to_string().into()
    )).await;

    let (tcp_read, tcp_write) = tcp_stream.into_split();

    // TCP → WebSocket
    let tcp_to_ws = {
        let mut tcp_read = tcp_read;
        let mut ws_sink = ws_sink;
        async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match tcp_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if ws_sink.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("[SSH] TCP read error: {e}");
                        break;
                    }
                }
            }
            let _ = ws_sink.send(Message::Close(None)).await;
        }
    };

    // WebSocket → TCP
    let ws_to_tcp = {
        let mut tcp_write = tcp_write;
        async move {
            while let Some(Ok(msg)) = ws_stream.next().await {
                match msg {
                    Message::Binary(data) => {
                        if tcp_write.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        }
    };

    tokio::select! {
        _ = tcp_to_ws => {}
        _ = ws_to_tcp => {}
    }

    tracing::info!("[SSH] Session ended: {user} -> {addr}");
}

// ── Main request handler ─────────────────────────────────────────

async fn handle_request(
    State(shared): State<SharedState>,
    req: Request<Body>,
) -> Response {
    let state = shared.load_full();
    let mut resp_headers = HeaderMap::new();
    security_headers(&mut resp_headers, state.use_tls);

    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();

    let remote_addr = req
        .headers()
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let method = req.method().clone();
    let original_uri = req.uri().clone();
    let url_path = original_uri.path().to_string();
    let query_string = original_uri.query().unwrap_or("").to_string();
    let full_url = if query_string.is_empty() {
        url_path.clone()
    } else {
        format!("{url_path}?{query_string}")
    };
    let req_headers = req.headers().clone();
    let req_body = req.into_body();

    let mut backend_prefix = String::new();
    let mut active_backend = String::new();
    let mut effective_url = full_url.clone();
    let mut effective_path = url_path.clone();

    // ── Path-based backend routing ──────────────────────
    if effective_path.starts_with("/__b/") {
        let rest = effective_path["/__b/".len()..].to_string();
        let slash_idx = rest.find('/');
        let encoded_name = if let Some(idx) = slash_idx {
            &rest[..idx]
        } else {
            rest.as_str()
        };
        let name = percent_encoding::percent_decode_str(encoded_name)
            .decode_utf8_lossy()
            .to_string();
        if state.backend_map.contains_key(&name) {
            active_backend = name;
            backend_prefix = format!("/__b/{encoded_name}");
            let stripped = if let Some(idx) = slash_idx {
                rest[idx..].to_string()
            } else {
                "/".to_string()
            };
            effective_url = if query_string.is_empty() {
                stripped.clone()
            } else {
                format!("{stripped}?{query_string}")
            };
            effective_path = stripped;
        }
    }

    // ── TideCloak /_idp prefix stripping ────────────────
    if effective_path.starts_with("/_idp/") {
        effective_url = effective_url["/_idp".len()..].to_string();
        effective_path = effective_path["/_idp".len()..].to_string();
    }

    // ── Public routes ───────────────────────────────────

    // Favicon
    if effective_path == "/favicon.ico" {
        return make_response(StatusCode::NO_CONTENT, resp_headers, "");
    }

    // WASM files (embedded)
    if effective_path == "/wasm/ironrdp_web_bg.wasm" {
        resp_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/wasm"));
        return make_binary_response(StatusCode::OK, resp_headers, ASSET_WASM_BG);
    }
    if effective_path == "/wasm/ironrdp_web.js" {
        resp_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/javascript; charset=utf-8"));
        return make_response(StatusCode::OK, resp_headers, ASSET_WASM_JS);
    }

    // Static JS files (embedded)
    if effective_path.starts_with("/js/") && effective_path.ends_with(".js") {
        let content = match effective_path.as_str() {
            "/js/sw.js" => {
                resp_headers.insert(
                    HeaderName::from_static("service-worker-allowed"),
                    HeaderValue::from_static("/"),
                );
                resp_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
                Some(ASSET_JS_SW)
            }
            "/js/rdp-client.js" => Some(ASSET_JS_RDP_CLIENT),
            "/js/webrtc-upgrade.js" => Some(ASSET_JS_WEBRTC_UPGRADE),
            "/js/webtransport-upgrade.js" => Some(ASSET_JS_WEBTRANSPORT_UPGRADE),
            "/js/tide-e2e.js" => Some(ASSET_JS_TIDE_E2E),
            _ => None,
        };
        if let Some(body) = content {
            resp_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/javascript; charset=utf-8"));
            return make_response(StatusCode::OK, resp_headers, body);
        }
        return make_response(StatusCode::NOT_FOUND, resp_headers, "Not found");
    }

    // RDP client page (embedded) — legacy fallback when not using keylessh-hosted page
    if effective_path == "/rdp" {
        resp_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        return make_response(StatusCode::OK, resp_headers, ASSET_RDP_HTML);
    }

    // WebRTC config
    if effective_path == "/webrtc-config" {
        return handle_webrtc_config(&state, &req_headers, &host, resp_headers).await;
    }

    // Auth: login
    if effective_path == "/auth/login" {
        return handle_auth_login(&state, &query_string, &host, resp_headers);
    }

    // Auth: callback
    if effective_path == "/auth/callback" {
        return handle_auth_callback(&state, &req_headers, &query_string, &host, resp_headers).await;
    }

    // Auth: silent callback (for iframe PKCE — posts code back to parent)
    if effective_path == "/auth/silent-callback" {
        resp_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
        let html = format!(
            "<html><body><script>\
            var params = new URLSearchParams(location.search);\
            var code = params.get('code');\
            var error = params.get('error');\
            if (window.parent !== window) {{\
                window.parent.postMessage({{type:'silent-auth-callback',code:code,error:error}},'*');\
            }}\
            </script></body></html>"
        );
        return make_response(StatusCode::OK, resp_headers, &html);
    }

    // Auth: session-token
    if effective_path == "/auth/session-token" {
        return handle_session_token(&state, &req_headers, &remote_addr, resp_headers).await;
    }

    // Auth: logout
    if effective_path == "/auth/logout" {
        return handle_auth_logout(&state, &req_headers, &host, resp_headers).await;
    }

    // Health check
    if effective_path == "/health" {
        resp_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return make_response(StatusCode::OK, resp_headers, r#"{"status":"ok"}"#);
    }

    // Logs page
    if effective_path == "/logs" {
        resp_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
        return make_response(StatusCode::OK, resp_headers, LOGS_HTML);
    }

    // Logs SSE stream
    if effective_path == "/logs/stream" {
        return handle_logs_stream(resp_headers);
    }

    // Logs buffer (polling fallback for STUN relay)
    if effective_path == "/logs/buffer" {
        let lines = crate::logstream::recent_lines();
        let json = serde_json::to_string(&lines).unwrap_or_else(|_| "[]".to_string());
        resp_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        return make_response(StatusCode::OK, resp_headers, &json);
    }

    // ── TideCloak reverse proxy (/realms/*, /resources/*, /admin) ──
    if effective_path.starts_with("/realms/")
        || effective_path.starts_with("/resources/")
        || effective_path.starts_with("/admin")
    {
        return handle_tc_proxy(
            &state,
            &req_headers,
            &method,
            &effective_url,
            &host,
            req_body,
            resp_headers,
        )
        .await;
    }

    // ── Protected routes ────────────────────────────────

    let cookies = parse_cookies(
        req_headers
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok()),
    );

    // Check if this backend skips JWT validation
    let effective_backend = if active_backend.is_empty() {
        &state.default_backend_name
    } else {
        &active_backend
    };
    let is_no_auth = is_public_resource(&effective_path)
        || state.no_auth_backends.contains(effective_backend);

    let mut payload: Option<JwtPayload> = None;
    let mut access_token: Option<String> = None;
    let mut refresh_cookies: Vec<String> = Vec::new();

    if is_no_auth {
        // Backend handles its own auth
    } else {
        // Extract JWT: cookie first, then Authorization header
        let mut token: Option<String> = cookies.get("gateway_access").cloned();
        let mut is_dpop = false;

        if token.is_none() {
            if let Some(auth_header) = req_headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
            {
                if let Some(t) = auth_header.strip_prefix("DPoP ") {
                    token = Some(t.to_string());
                    is_dpop = true;
                } else if let Some(t) = auth_header.strip_prefix("Bearer ") {
                    token = Some(t.to_string());
                }
            }
        }

        // Validate JWT
        if let Some(ref t) = token {
            payload = state.auth.verify_token(t).await;
        }

        // DPoP proof verification
        if payload.is_some() {
            if let Some(ref t) = token {
                let cnf_jkt = extract_cnf_jkt(t);

                if is_dpop {
                    let dpop_proof = req_headers
                        .get("dpop")
                        .and_then(|v| v.to_str().ok());
                    let Some(proof) = dpop_proof else {
                        resp_headers.insert(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/json"),
                        );
                        return make_response(
                            StatusCode::UNAUTHORIZED,
                            resp_headers,
                            r#"{"error":"DPoP proof required"}"#,
                        );
                    };

                    let proto = if state.use_tls { "https" } else { "http" };
                    let request_url = format!(
                        "{proto}://{host}{}",
                        url_path // use original path before /__b/ and /_idp/ stripping
                    );
                    if let Err(e) = state.dpop_verifier.verify_proof(
                        proof,
                        method.as_str(),
                        &request_url,
                        cnf_jkt.as_deref(),
                    ) {
                        tracing::error!("DPoP proof verification failed: {e}");
                        resp_headers.insert(
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/json"),
                        );
                        return make_response(
                            StatusCode::UNAUTHORIZED,
                            resp_headers,
                            &format!(r#"{{"error":"DPoP proof invalid: {e}"}}"#),
                        );
                    }
                } else if cnf_jkt.is_some() {
                    // Token is DPoP-bound but used Bearer/cookie
                    resp_headers.insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    );
                    return make_response(
                        StatusCode::UNAUTHORIZED,
                        resp_headers,
                        r#"{"error":"DPoP-bound token requires DPoP authorization scheme"}"#,
                    );
                }
            }
        }

        // If token expired, try refresh
        if payload.is_none() {
            if let Some(refresh_token) = cookies.get("gateway_refresh") {
                if let Some(result) = state.deduplicated_refresh(refresh_token).await {
                    let refreshed = state.auth.verify_token(&result.access_token).await;
                    if refreshed.is_some() {
                        payload = refreshed;
                        access_token = Some(result.access_token.clone());
                        refresh_cookies.push(build_cookie_header(
                            "gateway_access",
                            &result.access_token,
                            result.expires_in,
                            "Lax",
                            state.use_tls,
                        ));
                        if let Some(ref rt) = result.refresh_token {
                            refresh_cookies.push(build_cookie_header(
                                "gateway_refresh",
                                rt,
                                result.refresh_expires_in.unwrap_or(1800),
                                "Strict",
                                state.use_tls,
                            ));
                        }
                        token = access_token.clone();
                    }
                }
            }
        }

        // No valid token — redirect or 401
        if payload.is_none() {
            if is_browser_request(&req_headers) {
                let full_redirect = format!("{backend_prefix}{effective_url}");
                let encoded = percent_encoding::utf8_percent_encode(
                    &full_redirect,
                    percent_encoding::NON_ALPHANUMERIC,
                );
                resp_headers.insert(
                    header::LOCATION,
                    HeaderValue::from_str(&format!("/auth/login?redirect={encoded}")).unwrap(),
                );
                return make_response(StatusCode::FOUND, resp_headers, "");
            } else {
                resp_headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                return make_response(
                    StatusCode::UNAUTHORIZED,
                    resp_headers,
                    r#"{"error":"Missing or invalid authorization"}"#,
                );
            }
        }

        // If access_token was not set by refresh flow, use original token
        #[allow(unused_assignments)]
        if access_token.is_none() {
            access_token = token;
        }

        // ── dest: role enforcement ─────────────────────────
        if let (Some(gw_id), Some(jwt)) = (&state.gateway_id, &payload) {
            let backend = if active_backend.is_empty() {
                &state.default_backend_name
            } else {
                &active_backend
            };

            let realm_roles: Vec<&str> = jwt
                .realm_access
                .as_ref()
                .map(|ra| ra.roles.iter().map(|s| s.as_str()).collect())
                .unwrap_or_default();

            let client_roles: Vec<&str> = jwt
                .resource_access
                .as_ref()
                .and_then(|ra| ra.get(&state.role_client_id))
                .and_then(|v| v.get("roles"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect()
                })
                .unwrap_or_default();

            let all_roles: Vec<&str> = realm_roles
                .iter()
                .chain(client_roles.iter())
                .copied()
                .collect();

            let has_access = all_roles.iter().any(|r| {
                if !r.to_lowercase().starts_with("dest:") {
                    return false;
                }
                let parts: Vec<&str> = r[5..].splitn(4, ':').collect();
                match parts.len() {
                    // dest:<endpoint>
                    1 => parts[0].eq_ignore_ascii_case(backend),
                    // dest:<gateway>:<endpoint>
                    2 => parts[0].eq_ignore_ascii_case(gw_id) && parts[1].eq_ignore_ascii_case(backend),
                    // dest:<gateway>:<endpoint>:<username>
                    3 => parts[0].eq_ignore_ascii_case(gw_id) && parts[1].eq_ignore_ascii_case(backend),
                    _ => false,
                }
            });

            if !has_access {
                tracing::error!(
                    "dest role denied: gwId={gw_id} backend=\"{backend}\" clientId=\"{}\"",
                    state.client_id
                );
                resp_headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                return make_response(
                    StatusCode::FORBIDDEN,
                    resp_headers,
                    r#"{"error":"Forbidden: no dest role for this backend"}"#,
                );
            }
        }
    }

    // ── Proxy to backend ─────────────────────────────────

    // Validate HTTP method
    if !ALLOWED_METHODS.contains(&method.as_str()) {
        resp_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return make_response(
            StatusCode::METHOD_NOT_ALLOWED,
            resp_headers,
            r#"{"error":"Method not allowed"}"#,
        );
    }

    let target = state.resolve_backend(&active_backend, &req_headers);
    let target_url = format!(
        "{}://{}{}{}",
        target.scheme(),
        target.host_str().unwrap_or("localhost"),
        target
            .port()
            .map(|p| format!(":{p}"))
            .unwrap_or_default(),
        &effective_url,
    );

    let is_dc_request = req_headers.contains_key("x-dc-request");

    // Build proxy request headers
    let mut proxy_headers = HeaderMap::new();
    for (name, value) in req_headers.iter() {
        let name_str = name.as_str();
        // Skip hop-by-hop and gateway-internal headers
        if name_str == "host"
            || name_str == "x-forwarded-user"
            || name_str == "x-forwarded-for"
            || name_str == "x-forwarded-proto"
            || name_str == "x-forwarded-host"
            || name_str == "x-forwarded-port"
            || name_str == "x-dc-request"
            || name_str == "x-gateway-backend"
            || name_str == "accept-encoding"
        {
            continue;
        }
        if name_str == "authorization"
            && (state.config.strip_auth_header
                || state.strip_auth_backends.contains(&active_backend))
        {
            continue;
        }
        proxy_headers.insert(name.clone(), value.clone());
    }

    // Set forwarded headers from trusted source
    if let Some(ref jwt) = payload {
        if let Some(ref sub) = jwt.sub {
            if let Ok(v) = HeaderValue::from_str(sub) {
                proxy_headers.insert(
                    HeaderName::from_static("x-forwarded-user"),
                    v,
                );
            }
        }
    }
    if let Ok(v) = HeaderValue::from_str(&remote_addr) {
        proxy_headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            v,
        );
    }

    // DataChannel requests: inject backend cookies from jar
    let backend_key = if active_backend.is_empty() {
        state.default_backend_name.clone()
    } else {
        active_backend.clone()
    };
    if is_dc_request {
        if let Some(ref jwt) = payload {
            if let Some(ref sub) = jwt.sub {
                let jar_key = format!("{sub}:{backend_key}");
                let jar_cookies = state.get_backend_cookie_header(&jar_key);
                if !jar_cookies.is_empty() {
                    let existing = proxy_headers
                        .get(header::COOKIE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let merged = if existing.is_empty() {
                        jar_cookies
                    } else {
                        format!("{existing}; {jar_cookies}")
                    };
                    if let Ok(v) = HeaderValue::from_str(&merged) {
                        proxy_headers.insert(header::COOKIE, v);
                    }
                }
            }
        }
    }

    // Forward to backend
    let body_bytes = match axum::body::to_bytes(req_body, 50 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            resp_headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            return make_response(
                StatusCode::BAD_REQUEST,
                resp_headers,
                r#"{"error":"Request body too large"}"#,
            );
        }
    };

    let backend_resp = match state
        .http_client
        .request(method, &target_url)
        .headers(proxy_headers)
        .body(body_bytes)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Backend error: {e}");
            resp_headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            if e.is_timeout() {
                return make_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    resp_headers,
                    r#"{"error":"Backend timeout"}"#,
                );
            }
            return make_response(
                StatusCode::BAD_GATEWAY,
                resp_headers,
                r#"{"error":"Backend unavailable"}"#,
            );
        }
    };

    let status = backend_resp.status();
    let backend_headers = backend_resp.headers().clone();

    // Store backend cookies in jar for DC sessions
    let cookie_jar_user = payload.as_ref().and_then(|p| p.sub.as_deref()).unwrap_or("");
    let set_cookies = extract_set_cookies(&backend_headers);
    if !cookie_jar_user.is_empty() && !set_cookies.is_empty() {
        state.store_backend_cookies(
            &format!("{cookie_jar_user}:{backend_key}"),
            &set_cookies,
        );
    }

    // Build response headers from backend
    for (name, value) in backend_headers.iter() {
        let name_str = name.as_str();
        if name_str == "transfer-encoding" || name_str == "content-encoding" {
            continue;
        }
        resp_headers.append(name.clone(), value.clone());
    }

    // Rewrite Location header
    if let Some(location) = resp_headers.get(header::LOCATION).and_then(|v| v.to_str().ok()) {
        let location = location.to_string();
        let tc_origin = state.tc_proxy_url.origin().ascii_serialization();
        let mut rewritten = rewrite_location(&location, &tc_origin, &state.port_to_backend, "");

        // Prepend backend prefix to relative redirects
        if !backend_prefix.is_empty()
            && rewritten.starts_with('/')
            && !rewritten.starts_with("/__b/")
        {
            rewritten = format!("{backend_prefix}{rewritten}");
        }

        if let Ok(v) = HeaderValue::from_str(&rewritten) {
            resp_headers.insert(header::LOCATION, v);
        }
    }

    // Append refresh cookies
    for cookie in &refresh_cookies {
        if let Ok(v) = HeaderValue::from_str(cookie) {
            resp_headers.append(header::SET_COOKIE, v);
        }
    }

    // Check if response is HTML — buffer and rewrite
    let content_type = resp_headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if content_type.contains("text/html") {
        let body_bytes = match backend_resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("Error reading backend response: {e}");
                resp_headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                return make_response(
                    StatusCode::BAD_GATEWAY,
                    resp_headers,
                    r#"{"error":"Backend response error"}"#,
                );
            }
        };

        let mut html = String::from_utf8_lossy(&body_bytes).to_string();

        // Rewrite localhost:PORT → /__b/<name>
        html = rewrite_localhost_in_html(&html, &state.port_to_backend);

        // Prepend backend prefix to absolute paths
        if !backend_prefix.is_empty() {
            html = prepend_prefix(&html, &backend_prefix);

            // Inject fetch/XHR interceptor script
            let patch_script = build_patch_script(&backend_prefix);
            if html.contains("<head>") {
                html = html.replacen("<head>", &format!("<head>{patch_script}"), 1);
            } else {
                html = format!("{patch_script}{html}");
            }
        }

        // Inject WebTransport (QUIC) + WebRTC upgrade scripts
        // WebTransport loads first — exits early on unsupported browsers, letting WebRTC take over
        if !state.config.ice_servers.is_empty() {
            let script = format!(
                r#"<script src="{backend_prefix}/js/webtransport-upgrade.js"></script><script src="{backend_prefix}/js/webrtc-upgrade.js"></script>"#
            );
            if html.contains("<head>") {
                html = html.replacen("<head>", &format!("<head>{script}"), 1);
            } else if html.contains("<HEAD>") {
                html = html.replacen("<HEAD>", &format!("<HEAD>{script}"), 1);
            } else {
                html = format!("{script}{html}");
            }
        }

        // Remove content-length since body was rewritten
        resp_headers.remove(header::CONTENT_LENGTH);

        let mut response = Response::builder().status(status);
        for (name, value) in resp_headers.iter() {
            response = response.header(name, value);
        }
        return response
            .body(Body::from(html))
            .unwrap_or_else(|_| Response::new(Body::from("Internal error")));
    }

    // Non-HTML response: stream body through
    let body_bytes = match backend_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Error reading backend response: {e}");
            return make_response(
                StatusCode::BAD_GATEWAY,
                resp_headers,
                r#"{"error":"Backend response error"}"#,
            );
        }
    };

    let mut response = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        response = response.header(name, value);
    }
    response
        .body(Body::from(body_bytes))
        .unwrap_or_else(|_| Response::new(Body::from("Internal error")))
}

// ── Route handlers ───────────────────────────────────────────────

async fn handle_webrtc_config(
    state: &ProxyState,
    headers: &HeaderMap,
    host: &str,
    mut resp_headers: HeaderMap,
) -> Response {
    let ws_proto = if state.use_tls { "wss" } else { "ws" };
    let mut config = serde_json::json!({
        "signalingUrl": format!("{ws_proto}://{host}"),
        "stunServer": state.config.ice_servers.first().map(|s| {
            format!("stun:{}", s.trim_start_matches("stun:"))
        }),
        "targetGatewayId": state.config.gateway_id,
    });

    config["authServerUrl"] = serde_json::json!(state.tc_config.auth_server_url);
    config["realm"] = serde_json::json!(state.tc_config.realm);
    config["e2eTls"] = serde_json::json!(true);

    // Include backendAuth map for eddsa backends (so RDP client auto-connects)
    {
        let mut auth_map = serde_json::Map::new();
        for b in &state.config.backends {
            if b.auth == crate::config::BackendAuth::EdDSA {
                auth_map.insert(b.name.clone(), serde_json::json!("eddsa"));
            }
        }
        if !auth_map.is_empty() {
            config["backendAuth"] = serde_json::Value::Object(auth_map);
        }
    }

    // TURN credentials only for authenticated users
    if let (Some(turn_server), turn_secret) = (
        &state.config.turn_server,
        &state.config.turn_secret,
    ) {
        if !turn_secret.is_empty() {
            let cookies = parse_cookies(
                headers.get(header::COOKIE).and_then(|v| v.to_str().ok()),
            );
            if let Some(token) = cookies.get("gateway_access") {
                if state.auth.verify_token(token).await.is_some() {
                    let expiry = now_secs() + 3600;
                    let username = expiry.to_string();
                    let password = compute_turn_credential(turn_secret, &username);
                    config["turnServer"] = serde_json::json!(turn_server);
                    config["turnUsername"] = serde_json::json!(username);
                    config["turnPassword"] = serde_json::json!(password);
                }
            }
        }
    }

    resp_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    make_response(
        StatusCode::OK,
        resp_headers,
        &serde_json::to_string(&config).unwrap(),
    )
}

fn compute_turn_credential(secret: &str, username: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC key");
    mac.update(username.as_bytes());
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, mac.finalize().into_bytes())
}

fn handle_auth_login(
    state: &ProxyState,
    query: &str,
    host: &str,
    mut resp_headers: HeaderMap,
) -> Response {
    let params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let original_url = sanitize_redirect(params.get("redirect").map(|s| s.as_str()).unwrap_or("/"));
    let force_login = params.contains_key("prompt");
    let callback_url = get_callback_url_with_config(host, state.use_tls, &state.config.server_url);

    // Use browser endpoints for the redirect URL.
    // The STUN server routes /realms/<realm>/... to the gateway that registered
    // that realm, so relative paths work for cross-gateway auth.
    let endpoints = state.get_browser_endpoints();
    let (mut auth_url, state_param) = build_auth_url(&endpoints, &state.client_id, &callback_url, &original_url);
    if force_login {
        auth_url.push_str("&prompt=login&max_age=0");
    }
    let (nonce, _redirect) = parse_state(&state_param);

    let secure = if state.use_tls { "; Secure" } else { "" };
    let nonce_cookie = format!(
        "oidc_nonce={nonce}; HttpOnly; Path=/auth/callback; Max-Age=600; SameSite=Lax{secure}"
    );

    resp_headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&auth_url).unwrap(),
    );
    if let Ok(v) = HeaderValue::from_str(&nonce_cookie) {
        resp_headers.insert(header::SET_COOKIE, v);
    }
    make_response(StatusCode::FOUND, resp_headers, "")
}

async fn handle_auth_callback(
    state: &ProxyState,
    headers: &HeaderMap,
    query: &str,
    host: &str,
    mut resp_headers: HeaderMap,
) -> Response {
    let params: HashMap<String, String> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();

    let error = params.get("error");
    if let Some(err) = error {
        tracing::error!(
            "Auth error from TideCloak: {err} — {}",
            params.get("error_description").unwrap_or(&"no description".to_string())
        );
        resp_headers.insert(
            header::LOCATION,
            HeaderValue::from_str(&format!(
                "/auth/login?error={}",
                percent_encoding::utf8_percent_encode(err, percent_encoding::NON_ALPHANUMERIC)
            ))
            .unwrap(),
        );
        return make_response(StatusCode::FOUND, resp_headers, "");
    }

    let Some(code) = params.get("code") else {
        tracing::error!("Auth callback missing code parameter");
        resp_headers.insert(
            header::LOCATION,
            HeaderValue::from_static("/auth/login?error=no_code"),
        );
        return make_response(StatusCode::FOUND, resp_headers, "");
    };

    // CSRF validation
    let cookies = parse_cookies(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()));
    let state_param = params.get("state").map(|s| s.as_str()).unwrap_or("");
    let (nonce, redirect_url) = parse_state(state_param);
    let expected_nonce = cookies.get("oidc_nonce").map(|s| s.as_str()).unwrap_or("");

    if expected_nonce.is_empty() || expected_nonce != nonce {
        tracing::error!("OIDC CSRF check failed: nonce mismatch");
        resp_headers.insert(
            header::LOCATION,
            HeaderValue::from_static("/auth/login?error=csrf_failed"),
        );
        return make_response(StatusCode::FOUND, resp_headers, "");
    }

    let callback_url = get_callback_url_with_config(host, state.use_tls, &state.config.server_url);

    tracing::info!("Token exchange:");
    tracing::info!("  endpoint: {}", state.server_endpoints.token);
    tracing::info!("  client_id: {}", state.client_id);
    tracing::info!("  redirect_uri: {callback_url}");
    tracing::info!("  code: {}...", &code[..8.min(code.len())]);

    match exchange_code(&state.server_endpoints, &state.client_id, code, &callback_url).await {
        Ok(tokens) => {
            tracing::info!("Token exchange succeeded (expires_in={})", tokens.expires_in);

            let mut set_cookies = vec![build_cookie_header(
                "gateway_access",
                &tokens.access_token,
                tokens.expires_in,
                "Lax",
                state.use_tls,
            )];

            if let Some(ref rt) = tokens.refresh_token {
                set_cookies.push(build_cookie_header(
                    "gateway_refresh",
                    rt,
                    tokens.refresh_expires_in.unwrap_or(1800),
                    "Strict",
                    state.use_tls,
                ));
            }

            // Clear CSRF nonce
            set_cookies
                .push("oidc_nonce=; HttpOnly; Path=/auth/callback; Max-Age=0".to_string());

            let safe_redirect = sanitize_redirect(&redirect_url);
            tracing::info!("Auth complete, redirecting to: {safe_redirect}");

            resp_headers.insert(
                header::LOCATION,
                HeaderValue::from_str(&safe_redirect).unwrap(),
            );
            for cookie in &set_cookies {
                if let Ok(v) = HeaderValue::from_str(cookie) {
                    resp_headers.append(header::SET_COOKIE, v);
                }
            }
            make_response(StatusCode::FOUND, resp_headers, "")
        }
        Err(e) => {
            tracing::error!("Token exchange failed: {e}");
            resp_headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            let login_url = format!("/auth/login?prompt=login&redirect={}",
                percent_encoding::utf8_percent_encode(
                    &redirect_url,
                    percent_encoding::NON_ALPHANUMERIC,
                ));
            make_response(
                StatusCode::OK,
                resp_headers,
                &format!(
                    concat!(
                        "<!DOCTYPE html><html><head><title>Login Required</title></head>",
                        "<body style=\"font-family:system-ui;display:flex;justify-content:center;",
                        "align-items:center;height:100vh;margin:0;background:#f5f5f5\">",
                        "<div style=\"text-align:center;max-width:400px;padding:2rem;",
                        "background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1)\">",
                        "<h2 style=\"margin-top:0\">Login Required</h2>",
                        "<p>Your session could not be established. Please log in to continue.</p>",
                        "<a href=\"{}\" style=\"display:inline-block;margin-top:1rem;padding:.6rem 1.5rem;",
                        "background:#4f46e5;color:#fff;text-decoration:none;border-radius:6px\">Log in</a>",
                        "</div></body></html>",
                    ),
                    login_url,
                ),
            )
        }
    }
}

async fn handle_session_token(
    state: &ProxyState,
    headers: &HeaderMap,
    remote_addr: &str,
    mut resp_headers: HeaderMap,
) -> Response {
    // Require X-Requested-With header
    if !headers.contains_key("x-requested-with") {
        resp_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return make_response(
            StatusCode::FORBIDDEN,
            resp_headers,
            r#"{"error":"Missing X-Requested-With header"}"#,
        );
    }

    // Rate limiting: max 6 per 60s per IP
    let now_ms_val = now_millis();
    {
        let mut entry = state
            .session_token_hits
            .entry(remote_addr.to_string())
            .or_insert_with(Vec::new);
        entry.retain(|t| now_ms_val - *t < 60_000);
        if entry.len() >= 30 {
            resp_headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            resp_headers.insert(
                HeaderName::from_static("retry-after"),
                HeaderValue::from_static("10"),
            );
            return make_response(
                StatusCode::TOO_MANY_REQUESTS,
                resp_headers,
                r#"{"error":"Too many requests"}"#,
            );
        }
        entry.push(now_ms_val);
    }

    let cookies = parse_cookies(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()));

    let mut access_token = cookies.get("gateway_access").cloned();
    // Also accept Authorization: Bearer
    if access_token.is_none() {
        if let Some(auth_header) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            if let Some(t) = auth_header.strip_prefix("Bearer ") {
                access_token = Some(t.to_string());
            }
        }
    }

    let mut payload = if let Some(ref t) = access_token {
        state.auth.verify_token(t).await
    } else {
        None
    };

    // Always refresh on session-token endpoint call
    let mut set_cookies = Vec::new();
    if let Some(refresh_token) = cookies.get("gateway_refresh") {
        if let Some(result) = state.deduplicated_refresh(refresh_token).await {
            let refreshed = state.auth.verify_token(&result.access_token).await;
            if refreshed.is_some() {
                payload = refreshed;
                access_token = Some(result.access_token.clone());
                set_cookies.push(build_cookie_header(
                    "gateway_access",
                    &result.access_token,
                    result.expires_in,
                    "Lax",
                    state.use_tls,
                ));
                if let Some(ref rt) = result.refresh_token {
                    set_cookies.push(build_cookie_header(
                        "gateway_refresh",
                        rt,
                        result.refresh_expires_in.unwrap_or(1800),
                        "Strict",
                        state.use_tls,
                    ));
                }
            }
        }
    }

    if payload.is_none() {
        resp_headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return make_response(
            StatusCode::UNAUTHORIZED,
            resp_headers,
            r#"{"error":"Invalid session"}"#,
        );
    }

    resp_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp_headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    resp_headers.insert(
        HeaderName::from_static("pragma"),
        HeaderValue::from_static("no-cache"),
    );
    for cookie in &set_cookies {
        if let Ok(v) = HeaderValue::from_str(cookie) {
            resp_headers.append(header::SET_COOKIE, v);
        }
    }

    let body = serde_json::json!({ "token": access_token.unwrap_or_default() });
    make_response(StatusCode::OK, resp_headers, &body.to_string())
}

async fn handle_auth_logout(
    state: &ProxyState,
    headers: &HeaderMap,
    host: &str,
    mut resp_headers: HeaderMap,
) -> Response {
    let cookies = parse_cookies(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()));

    // Clear backend cookie jar for this user
    if let Some(token) = cookies.get("gateway_access") {
        if let Some(jwt) = state.auth.verify_token(token).await {
            if let Some(ref sub) = jwt.sub {
                let prefix = format!("{sub}:");
                state
                    .backend_cookie_jar
                    .retain(|key, _| !key.starts_with(&prefix));
            }
        }
    }

    let callback_url = get_callback_url_with_config(host, state.use_tls, &state.config.server_url);
    let proto_host = callback_url.split("/auth/callback").next().unwrap_or("");

    let endpoints = state.get_browser_endpoints();
    let logout_url = build_logout_url(&endpoints, &state.client_id, &format!("{proto_host}/auth/login"));

    // Clear tc_sess from jar
    if let Some(tc_sess_id) = cookies.get("tc_sess") {
        state.tc_cookie_jar.remove(tc_sess_id);
    }

    resp_headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&logout_url).unwrap(),
    );

    let clear_cookies = [
        clear_cookie_header("gateway_access", state.use_tls),
        clear_cookie_header("gateway_refresh", state.use_tls),
        clear_cookie_header("tc_sess", state.use_tls),
    ];
    for cookie in &clear_cookies {
        if let Ok(v) = HeaderValue::from_str(cookie) {
            resp_headers.append(header::SET_COOKIE, v);
        }
    }

    make_response(StatusCode::FOUND, resp_headers, "")
}

async fn handle_tc_proxy(
    state: &ProxyState,
    headers: &HeaderMap,
    method: &Method,
    url: &str,
    host: &str,
    body: Body,
    mut resp_headers: HeaderMap,
) -> Response {
    let public_proto = if state.use_tls { "https" } else { "http" };
    let public_base = format!("{public_proto}://{host}");

    let cookies = parse_cookies(headers.get(header::COOKIE).and_then(|v| v.to_str().ok()));
    let (tc_session_id, is_new_session) = state.get_tc_session_id(&cookies);

    // Build proxy headers
    let mut proxy_headers = HeaderMap::new();
    for (name, value) in headers.iter() {
        let name_str = name.as_str();
        if name_str == "host"
            || name_str == "x-forwarded-proto"
            || name_str == "x-forwarded-host"
            || name_str == "x-forwarded-for"
            || name_str == "x-forwarded-port"
            || name_str == "accept-encoding"
        {
            continue;
        }
        proxy_headers.insert(name.clone(), value.clone());
    }

    // Set host to TC internal host
    if let Ok(v) = HeaderValue::from_str(state.tc_proxy_url.host_str().unwrap_or("localhost")) {
        proxy_headers.insert(header::HOST, v);
    }

    // NOTE: Do NOT set X-Forwarded-Proto/Host — KC must generate URLs with its
    // own hostname (localhost:8080) because the Tide IDP redirect_uri is signed.

    // Inject stored TC cookies
    let jar_cookies = state.get_tc_cookie_header(&tc_session_id);
    if !jar_cookies.is_empty() {
        let existing = proxy_headers
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let merged = if existing.is_empty() {
            jar_cookies
        } else {
            format!("{existing}; {jar_cookies}")
        };
        if let Ok(v) = HeaderValue::from_str(&merged) {
            proxy_headers.insert(header::COOKIE, v);
        }
    }

    let tc_base_path = state.tc_proxy_url.path().trim_end_matches('/');
    let tc_url = format!(
        "{}://{}{}{}{}",
        state.tc_proxy_url.scheme(),
        state.tc_proxy_url.host_str().unwrap_or("localhost"),
        state.tc_proxy_url.port().map(|p| format!(":{p}")).unwrap_or_default(),
        tc_base_path,
        url,
    );

    let body_bytes = match axum::body::to_bytes(body, 50 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            resp_headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            return make_response(
                StatusCode::BAD_REQUEST,
                resp_headers,
                r#"{"error":"Request body too large"}"#,
            );
        }
    };

    let tc_resp = match state
        .http_client
        .request(method.clone(), &tc_url)
        .headers(proxy_headers)
        .body(body_bytes)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("TideCloak error: {e}");
            resp_headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            if e.is_timeout() {
                return make_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    resp_headers,
                    r#"{"error":"Auth server timeout"}"#,
                );
            }
            return make_response(
                StatusCode::BAD_GATEWAY,
                resp_headers,
                r#"{"error":"Auth server unavailable"}"#,
            );
        }
    };

    let status = tc_resp.status();
    let tc_headers = tc_resp.headers().clone();

    // Copy headers, rewriting as needed
    for (name, value) in tc_headers.iter() {
        let name_str = name.as_str();
        if name_str == "content-encoding"
            || name_str == "transfer-encoding"
            || name_str == "content-security-policy"
            || name_str == "content-security-policy-report-only"
        {
            continue;
        }
        // Forward KC's Set-Cookie headers (AUTH_SESSION_ID etc.) so the browser
        // can send them directly on IDP callbacks that bypass the tc_sess jar.
        if name_str == "set-cookie" {
            // Rewrite cookie domain/path if KC used internal origin
            let cookie_str = value.to_str().unwrap_or("");
            let tc_origin = state.tc_proxy_url.origin().ascii_serialization();
            let rewritten = cookie_str.replace(&tc_origin, &public_base);
            if let Ok(v) = HeaderValue::from_str(&rewritten) {
                resp_headers.append(name.clone(), v);
            }
            continue;
        }
        resp_headers.append(name.clone(), value.clone());
    }

    // Rewrite Location header
    if let Some(location) = resp_headers.get(header::LOCATION).and_then(|v| v.to_str().ok()) {
        let location = location.to_string();
        let tc_origin = state.tc_proxy_url.origin().ascii_serialization();
        let rewritten = rewrite_location(&location, &tc_origin, &HashMap::new(), &public_base);
        if let Ok(v) = HeaderValue::from_str(&rewritten) {
            resp_headers.insert(header::LOCATION, v);
        }
    }

    // Store TC cookies server-side
    let tc_set_cookies = extract_set_cookies(&tc_headers);
    state.store_tc_cookies(&tc_session_id, &tc_set_cookies);

    // Replace Set-Cookie with tc_sess cookie
    if !tc_set_cookies.is_empty() || is_new_session {
        let tc_sess_cookie = build_cookie_header(
            "tc_sess",
            &tc_session_id,
            TC_SESS_MAX_AGE,
            "None",
            state.use_tls,
        );
        if let Ok(v) = HeaderValue::from_str(&tc_sess_cookie) {
            resp_headers.append(header::SET_COOKIE, v);
        }
    }

    // Check if response is text — buffer and rewrite URLs
    let content_type = resp_headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let is_text = content_type.contains("text/")
        || content_type.contains("application/javascript")
        || content_type.contains("application/json");

    if is_text {
        let body_bytes = match tc_resp.bytes().await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!("Error reading TC response: {e}");
                return make_response(
                    StatusCode::BAD_GATEWAY,
                    resp_headers,
                    r#"{"error":"Auth server response error"}"#,
                );
            }
        };

        let mut body = String::from_utf8_lossy(&body_bytes).to_string();
        let tc_origin = state.tc_proxy_url.origin().ascii_serialization();

        // Rewrite TC internal URLs → public base
        body = body.replace(&tc_origin, &public_base);
        body = body.replace(
            &tc_origin.replace('/', "\\/"),
            &public_base.replace('/', "\\/"),
        );
        body = body.replace(
            &percent_encoding::utf8_percent_encode(
                &tc_origin,
                percent_encoding::NON_ALPHANUMERIC,
            )
            .to_string(),
            &percent_encoding::utf8_percent_encode(
                &public_base,
                percent_encoding::NON_ALPHANUMERIC,
            )
            .to_string(),
        );

        // Also rewrite KC_HOSTNAME public origin
        if let Some(ref tc_pub) = state.tc_public_origin {
            if tc_pub != &tc_origin {
                body = body.replace(tc_pub, &public_base);
                body = body.replace(
                    &tc_pub.replace('/', "\\/"),
                    &public_base.replace('/', "\\/"),
                );
                body = body.replace(
                    &percent_encoding::utf8_percent_encode(
                        tc_pub,
                        percent_encoding::NON_ALPHANUMERIC,
                    )
                    .to_string(),
                    &percent_encoding::utf8_percent_encode(
                        &public_base,
                        percent_encoding::NON_ALPHANUMERIC,
                    )
                    .to_string(),
                );
            }
        }

        resp_headers.remove(header::CONTENT_LENGTH);

        let mut response = Response::builder().status(status);
        for (name, value) in resp_headers.iter() {
            response = response.header(name, value);
        }
        return response
            .body(Body::from(body))
            .unwrap_or_else(|_| Response::new(Body::from("Internal error")));
    }

    // Non-text: pass through
    let body_bytes = match tc_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("Error reading TC response: {e}");
            return make_response(
                StatusCode::BAD_GATEWAY,
                resp_headers,
                r#"{"error":"Auth server response error"}"#,
            );
        }
    };

    let mut response = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        response = response.header(name, value);
    }
    response
        .body(Body::from(body_bytes))
        .unwrap_or_else(|_| Response::new(Body::from("Internal error")))
}

// ── Response builder helper ──────────────────────────────────────

fn make_response(status: StatusCode, headers: HeaderMap, body: &str) -> Response {
    let mut response = Response::builder().status(status);
    for (name, value) in headers.iter() {
        response = response.header(name, value);
    }
    response
        .body(Body::from(body.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from("Internal error")))
}

fn make_binary_response(status: StatusCode, headers: HeaderMap, body: &[u8]) -> Response {
    let mut response = Response::builder().status(status);
    for (name, value) in headers.iter() {
        response = response.header(name, value);
    }
    response
        .body(Body::from(body.to_vec()))
        .unwrap_or_else(|_| Response::new(Body::from("Internal error")))
}

// ── Log streaming via SSE ───────────────────────────────────────

fn handle_logs_stream(mut resp_headers: HeaderMap) -> Response {
    use futures_util::stream::StreamExt;
    use tokio_stream::wrappers::BroadcastStream;

    let rx = match crate::logstream::subscribe() {
        Some(rx) => rx,
        None => {
            return make_response(StatusCode::SERVICE_UNAVAILABLE, resp_headers, "Log stream not available");
        }
    };

    let stream = BroadcastStream::new(rx).filter_map(|result| async move {
        match result {
            Ok(line) => {
                let escaped = line.replace('\\', "\\\\").replace('\n', "\\n").replace('\r', "");
                Some(Ok::<_, std::convert::Infallible>(format!("data: {escaped}\n\n")))
            }
            Err(_) => None,
        }
    });

    resp_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    resp_headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    resp_headers.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));

    let body = Body::from_stream(stream);
    let mut response = Response::builder().status(StatusCode::OK);
    for (name, value) in resp_headers.iter() {
        response = response.header(name, value);
    }
    response.body(body).unwrap_or_else(|_| Response::new(Body::from("Internal error")))
}

// ── Logs HTML page ──────────────────────────────────────────────

pub static LOGS_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Punchd Gateway - Logs</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
         background: #0f172a; color: #e2e8f0; height: 100vh; display: flex; flex-direction: column; }
  .header { padding: 0.75rem 1rem; background: #1e293b; border-bottom: 1px solid #334155;
            display: flex; align-items: center; gap: 1rem; flex-shrink: 0; }
  .header h1 { font-size: 1rem; color: #38bdf8; font-weight: 600; }
  .status { font-size: 0.8rem; padding: 0.2rem 0.6rem; border-radius: 9999px; }
  .status.connected { background: #064e3b; color: #34d399; }
  .status.disconnected { background: #7f1d1d; color: #fca5a5; }
  .controls { margin-left: auto; display: flex; gap: 0.5rem; }
  .controls button { padding: 0.3rem 0.75rem; background: #334155; color: #94a3b8; border: 1px solid #475569;
                     border-radius: 4px; cursor: pointer; font-size: 0.75rem; font-family: inherit; }
  .controls button:hover { background: #475569; color: #e2e8f0; }
  #log { flex: 1; overflow-y: auto; padding: 0.5rem 1rem; font-size: 0.8rem; line-height: 1.5; }
  .line { white-space: pre-wrap; word-break: break-all; padding: 1px 0; }
  .line:hover { background: #1e293b; }
  .level-ERROR { color: #f87171; }
  .level-WARN { color: #fbbf24; }
  .level-INFO { color: #38bdf8; }
  .level-DEBUG { color: #a78bfa; }
  .level-TRACE { color: #64748b; }
  .timestamp { color: #64748b; }
  .filter { padding: 0.3rem 0.5rem; background: #1e293b; color: #e2e8f0; border: 1px solid #334155;
            border-radius: 4px; font-size: 0.75rem; font-family: inherit; width: 200px; outline: none; }
  .filter:focus { border-color: #38bdf8; }
</style>
</head>
<body>
<div class="header">
  <h1>Punchd Gateway Logs</h1>
  <span id="status" class="status disconnected">disconnected</span>
  <div class="controls">
    <input type="text" id="filter" class="filter" placeholder="Filter logs...">
    <button onclick="toggleAutoScroll()">Auto-scroll: ON</button>
    <button onclick="clearLogs()">Clear</button>
  </div>
</div>
<div id="log"></div>
<script>
let autoScroll = true;
let filterText = '';
const logEl = document.getElementById('log');
const statusEl = document.getElementById('status');
const filterInput = document.getElementById('filter');

filterInput.addEventListener('input', (e) => {
  filterText = e.target.value.toLowerCase();
  document.querySelectorAll('.line').forEach(el => {
    el.style.display = el.textContent.toLowerCase().includes(filterText) || !filterText ? '' : 'none';
  });
});

function toggleAutoScroll() {
  autoScroll = !autoScroll;
  event.target.textContent = 'Auto-scroll: ' + (autoScroll ? 'ON' : 'OFF');
}

function clearLogs() {
  logEl.innerHTML = '';
}

function addLine(text) {
  const div = document.createElement('div');
  div.className = 'line';

  // Color by level
  const levels = ['ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE'];
  for (const lvl of levels) {
    if (text.startsWith(lvl + ' ')) {
      div.classList.add('level-' + lvl);
      break;
    }
  }

  div.textContent = text;
  if (filterText && !text.toLowerCase().includes(filterText)) {
    div.style.display = 'none';
  }
  logEl.appendChild(div);

  // Keep max 5000 lines
  while (logEl.children.length > 5000) {
    logEl.removeChild(logEl.firstChild);
  }

  if (autoScroll) {
    logEl.scrollTop = logEl.scrollHeight;
  }
}

let pollMode = false;
let lastLineCount = 0;
let sseFailCount = 0;

function connect() {
  if (pollMode) { startPolling(); return; }

  const es = new EventSource(location.origin + '/logs/stream');
  let opened = false;

  es.onopen = () => {
    opened = true;
    sseFailCount = 0;
    statusEl.textContent = 'live (SSE)';
    statusEl.className = 'status connected';
  };

  es.onmessage = (e) => {
    addLine(e.data);
  };

  es.onerror = () => {
    es.close();
    sseFailCount++;
    if (!opened || sseFailCount >= 3) {
      pollMode = true;
      statusEl.textContent = 'polling';
      statusEl.className = 'status connected';
      startPolling();
    } else {
      statusEl.textContent = 'reconnecting...';
      statusEl.className = 'status disconnected';
      setTimeout(connect, 2000);
    }
  };
}

function startPolling() {
  fetchBuffer();
  setInterval(fetchBuffer, 2000);
}

function fetchBuffer() {
  fetch(location.origin + '/logs/buffer')
    .then(r => r.json())
    .then(lines => {
      if (lines.length !== lastLineCount) {
        logEl.innerHTML = '';
        lines.forEach(l => addLine(l));
        lastLineCount = lines.length;
        statusEl.textContent = 'polling (' + lines.length + ' lines)';
        statusEl.className = 'status connected';
      }
    })
    .catch(() => {
      statusEl.textContent = 'disconnected';
      statusEl.className = 'status disconnected';
    });
}

connect();
</script>
</body>
</html>
"##;
