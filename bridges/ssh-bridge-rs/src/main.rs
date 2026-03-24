#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;

mod logstream;
mod setup;
mod tls;
mod tray;

// ── Config types ─────────────────────────────────────────────────

#[derive(Deserialize, Clone)]
struct JwkKey {
    kid: String,
    #[allow(dead_code)]
    kty: String,
    alg: String,
    #[serde(default)]
    crv: String,
    #[serde(default)]
    x: String,
    #[serde(default)]
    y: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    n: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    e: Option<String>,
}

#[derive(Deserialize, Clone)]
struct JwkSet {
    keys: Vec<JwkKey>,
}

#[derive(Deserialize, Clone)]
struct TidecloakConfig {
    realm: String,
    #[serde(rename = "auth-server-url")]
    auth_server_url: String,
    resource: String,
    jwk: JwkSet,
}

// ── State ────────────────────────────────────────────────────────

struct AppState {
    config: TidecloakConfig,
    active_connections: AtomicUsize,
    seen_jtis: DashMap<String, u64>,
}

// ── Config loading ───────────────────────────────────────────────

fn resolve_config_path() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from("data/tidecloak.json"),
        PathBuf::from("../data/tidecloak.json"),
    ];
    candidates.into_iter().find(|p| p.exists())
}

fn load_config() -> Result<(TidecloakConfig, u16), String> {
    let (config_data, saved_port) = if let Ok(adapter) = env::var("client_adapter") {
        tracing::info!("Loading config from client_adapter env variable");
        (adapter, None)
    } else if let Ok(b64) = env::var("TIDECLOAK_CONFIG_B64") {
        tracing::info!("Loading config from TIDECLOAK_CONFIG_B64");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| format!("Base64 decode error: {e}"))?;
        (String::from_utf8(bytes).map_err(|e| format!("UTF-8 error: {e}"))?, None)
    } else if let Some((json, port)) = setup::load_saved_config() {
        tracing::info!("Loading config from {}", setup::config_file_path().display());
        (json, Some(port))
    } else {
        let path = resolve_config_path().ok_or("No tidecloak.json found. Run the setup wizard or provide config.")?;
        tracing::info!("Loading config from {}", path.display());
        (fs::read_to_string(&path).map_err(|e| format!("Read error: {e}"))?, None)
    };

    let config: TidecloakConfig =
        serde_json::from_str(&config_data).map_err(|e| format!("JSON parse error: {e}"))?;

    if config.jwk.keys.is_empty() {
        return Err("No JWKS keys found in config".into());
    }

    let port = saved_port.unwrap_or(
        env::var("PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8081)
    );

    tracing::info!("JWKS loaded successfully");
    Ok((config, port))
}

// ── Base64url helpers ────────────────────────────────────────────

fn b64url_decode(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| {
            let padded = match s.len() % 4 {
                2 => format!("{s}=="),
                3 => format!("{s}="),
                _ => s.to_string(),
            };
            base64::engine::general_purpose::URL_SAFE.decode(&padded)
        })
        .map_err(|e| format!("base64url decode error: {e}"))
}

fn b64url_encode(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

// ── JWT types ────────────────────────────────────────────────────

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    typ: Option<String>,
    #[allow(dead_code)]
    #[serde(default)]
    jwk: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct JwtPayload {
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    htm: Option<String>,
    #[serde(default)]
    htu: Option<String>,
    #[serde(default)]
    cnf: Option<CnfClaim>,
}

#[derive(Deserialize)]
struct CnfClaim {
    #[serde(default)]
    jkt: Option<String>,
}

fn parse_jwt_parts(token: &str) -> Result<(JwtHeader, JwtPayload), String> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT structure".into());
    }
    let header: JwtHeader = serde_json::from_slice(&b64url_decode(parts[0])?)
        .map_err(|e| format!("Header parse: {e}"))?;
    let payload: JwtPayload = serde_json::from_slice(&b64url_decode(parts[1])?)
        .map_err(|e| format!("Payload parse: {e}"))?;
    Ok((header, payload))
}

// ── Signature verification ───────────────────────────────────────

fn verify_eddsa(sign_input: &[u8], sig: &[u8], x: &str) -> Result<bool, String> {
    let x_bytes = b64url_decode(x)?;
    let pk = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &x_bytes);
    Ok(pk.verify(sign_input, sig).is_ok())
}

fn verify_ec(sign_input: &[u8], sig: &[u8], alg: &str, x: &str, y: &str) -> Result<bool, String> {
    let alg_ring = match alg {
        "ES256" => &ring::signature::ECDSA_P256_SHA256_FIXED,
        "ES384" => &ring::signature::ECDSA_P384_SHA384_FIXED,
        _ => return Err(format!("Unsupported EC alg: {alg}")),
    };
    let x_bytes = b64url_decode(x)?;
    let y_bytes = b64url_decode(y)?;
    let mut point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
    point.push(0x04);
    point.extend_from_slice(&x_bytes);
    point.extend_from_slice(&y_bytes);
    let pk = ring::signature::UnparsedPublicKey::new(alg_ring, &point);
    Ok(pk.verify(sign_input, sig).is_ok())
}

fn verify_jwt_sig_with_jwk_key(token: &str, jwk: &JwkKey) -> Result<bool, String> {
    let parts: Vec<&str> = token.split('.').collect();
    let sign_input = format!("{}.{}", parts[0], parts[1]);
    let sig = b64url_decode(parts[2])?;
    match jwk.crv.as_str() {
        "Ed25519" => verify_eddsa(sign_input.as_bytes(), &sig, &jwk.x),
        "P-256" => verify_ec(
            sign_input.as_bytes(),
            &sig,
            "ES256",
            &jwk.x,
            jwk.y.as_deref().unwrap_or(""),
        ),
        "P-384" => verify_ec(
            sign_input.as_bytes(),
            &sig,
            "ES384",
            &jwk.x,
            jwk.y.as_deref().unwrap_or(""),
        ),
        _ => Err(format!("Unsupported curve: {}", jwk.crv)),
    }
}

fn verify_sig_with_jwk_value(sign_input: &str, sig: &[u8], jwk: &serde_json::Value, alg: &str) -> Result<bool, String> {
    let kty = jwk["kty"].as_str().ok_or("Missing kty")?;
    match (kty, alg) {
        ("OKP", "EdDSA") => {
            let x = jwk["x"].as_str().ok_or("Missing x")?;
            verify_eddsa(sign_input.as_bytes(), sig, x)
        }
        ("EC", alg) => {
            let x = jwk["x"].as_str().ok_or("Missing x")?;
            let y = jwk["y"].as_str().ok_or("Missing y")?;
            verify_ec(sign_input.as_bytes(), sig, alg, x, y)
        }
        _ => Err(format!("Unsupported DPoP key/alg: {kty}/{alg}")),
    }
}

// ── JWT access token verification ────────────────────────────────

fn verify_token(token: &str, config: &TidecloakConfig) -> Option<JwtPayload> {
    let (header, payload) = parse_jwt_parts(token).ok()?;

    let expected_issuer = format!("{}/realms/{}", config.auth_server_url.trim_end_matches('/'), config.realm);
    if payload.iss.as_deref() != Some(&expected_issuer) {
        tracing::warn!("Issuer mismatch: expected {expected_issuer}, got {:?}", payload.iss);
        return None;
    }

    if payload.azp.as_deref() != Some(&config.resource) {
        tracing::warn!("AZP mismatch: expected {}, got {:?}", config.resource, payload.azp);
        return None;
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    if let Some(exp) = payload.exp {
        if now > exp {
            tracing::warn!("Token expired");
            return None;
        }
    }

    let kid = header.kid.as_deref();
    let key = config
        .jwk
        .keys
        .iter()
        .find(|k| kid.is_none_or(|kid_val| k.kid == kid_val) && k.alg == header.alg)
        .or_else(|| config.jwk.keys.first())?;

    match verify_jwt_sig_with_jwk_key(token, key) {
        Ok(true) => Some(payload),
        Ok(false) => {
            tracing::warn!("JWT signature verification failed");
            None
        }
        Err(e) => {
            tracing::error!("JWT verification error: {e}");
            None
        }
    }
}

// ── DPoP Proof Verification (RFC 9449) ──────────────────────────

fn compute_jwk_thumbprint(jwk: &serde_json::Value) -> Result<String, String> {
    let kty = jwk["kty"].as_str().ok_or("Missing kty")?;
    let canonical = match kty {
        "EC" => format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
            jwk["crv"].as_str().ok_or("Missing crv")?,
            kty,
            jwk["x"].as_str().ok_or("Missing x")?,
            jwk["y"].as_str().ok_or("Missing y")?,
        ),
        "OKP" => format!(
            r#"{{"crv":"{}","kty":"{}","x":"{}"}}"#,
            jwk["crv"].as_str().ok_or("Missing crv")?,
            kty,
            jwk["x"].as_str().ok_or("Missing x")?,
        ),
        "RSA" => format!(
            r#"{{"e":"{}","kty":"{}","n":"{}"}}"#,
            jwk["e"].as_str().ok_or("Missing e")?,
            kty,
            jwk["n"].as_str().ok_or("Missing n")?,
        ),
        other => return Err(format!("Unsupported key type: {other}")),
    };
    Ok(b64url_encode(&Sha256::digest(canonical.as_bytes())))
}

fn check_and_store_jti(state: &AppState, jti: &str) -> bool {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    if state.seen_jtis.len() > 1000 {
        state.seen_jtis.retain(|_, exp| *exp > now_ms);
    }
    if state.seen_jtis.contains_key(jti) {
        return false;
    }
    state.seen_jtis.insert(jti.to_string(), now_ms + 120_000);
    true
}

fn verify_dpop_proof(
    state: &AppState,
    proof_jwt: &str,
    http_method: &str,
    http_url: &str,
    expected_jkt: Option<&str>,
) -> Result<(), String> {
    let parts: Vec<&str> = proof_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid JWT structure".into());
    }

    let header: serde_json::Value =
        serde_json::from_slice(&b64url_decode(parts[0])?).map_err(|e| format!("Header: {e}"))?;
    let payload: JwtPayload =
        serde_json::from_slice(&b64url_decode(parts[1])?).map_err(|e| format!("Payload: {e}"))?;
    let sig = b64url_decode(parts[2])?;

    if header["typ"].as_str() != Some("dpop+jwt") {
        return Err("Invalid typ".into());
    }

    let alg = header["alg"].as_str().ok_or("Missing alg")?;
    if !["EdDSA", "ES256", "ES384", "ES512"].contains(&alg) {
        return Err(format!("Unsupported alg: {alg}"));
    }

    let jwk = header.get("jwk").ok_or("Missing jwk in header")?;

    let sign_input = format!("{}.{}", parts[0], parts[1]);
    if !verify_sig_with_jwk_value(&sign_input, &sig, jwk, alg)? {
        return Err("Invalid signature".into());
    }

    if payload.htm.as_deref() != Some(http_method) {
        return Err("htm mismatch".into());
    }

    let expected_htu = http_url.split('?').next().unwrap_or(http_url);
    if payload.htu.as_deref() != Some(expected_htu) {
        return Err("htu mismatch".into());
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let iat = payload.iat.ok_or("Missing iat")?;
    if now.abs_diff(iat) > 120 {
        return Err("iat too far from current time".into());
    }

    let jti = payload.jti.as_deref().ok_or("jti missing")?;
    if !check_and_store_jti(state, jti) {
        return Err("jti replayed".into());
    }

    if let Some(expected) = expected_jkt {
        let thumbprint = compute_jwk_thumbprint(jwk)?;
        if thumbprint != expected {
            return Err("JWK thumbprint does not match cnf.jkt".into());
        }
    }

    Ok(())
}

fn extract_cnf_jkt(token: &str) -> Option<String> {
    let (_, payload) = parse_jwt_parts(token).ok()?;
    payload.cnf?.jkt
}

// ── Query params ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct WsParams {
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    #[serde(rename = "sessionId")]
    session_id: Option<String>,
    #[serde(default)]
    dpop: Option<String>,
}

// ── Handlers ─────────────────────────────────────────────────────

async fn health_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "tcpConnections": state.active_connections.load(Ordering::Relaxed),
    }))
}

async fn ws_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<WsParams>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    // Extract token: Authorization header first, then query param
    let mut token: Option<String> = None;
    let mut is_dpop_scheme = false;

    if let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(t) = auth.strip_prefix("DPoP ") {
            token = Some(t.to_string());
            is_dpop_scheme = true;
        } else if let Some(t) = auth.strip_prefix("Bearer ") {
            token = Some(t.to_string());
        }
    }
    if token.is_none() {
        token = params.token.clone();
    }

    let token = match token {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "Missing token").into_response(),
    };

    let host = match &params.host {
        Some(h) => h.clone(),
        None => return (StatusCode::BAD_REQUEST, "Missing host").into_response(),
    };

    let port = params.port.unwrap_or(22);

    let session_id = match &params.session_id {
        Some(s) => s.clone(),
        None => return (StatusCode::BAD_REQUEST, "Missing sessionId").into_response(),
    };

    // Verify JWT
    let payload = match verify_token(&token, &state.config) {
        Some(p) => p,
        None => return (StatusCode::UNAUTHORIZED, "Invalid token").into_response(),
    };

    // DPoP proof verification
    let cnf_jkt = extract_cnf_jkt(&token);
    let has_auth_header = headers.get("authorization").is_some();

    // Build request URL for DPoP verification
    let forwarded_proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    let host_header = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let request_url = format!("{forwarded_proto}://{host_header}/");

    if is_dpop_scheme {
        let dpop_header = headers.get("dpop").and_then(|v| v.to_str().ok());
        match dpop_header {
            Some(proof) => {
                if let Err(e) = verify_dpop_proof(&state, proof, "GET", &request_url, cnf_jkt.as_deref()) {
                    tracing::warn!("DPoP proof verification failed: {e}");
                    return (StatusCode::UNAUTHORIZED, format!("DPoP proof invalid: {e}")).into_response();
                }
            }
            None => return (StatusCode::UNAUTHORIZED, "DPoP proof required").into_response(),
        }
    } else if let Some(ref dpop_proof) = params.dpop {
        if let Err(e) = verify_dpop_proof(&state, dpop_proof, "GET", &request_url, cnf_jkt.as_deref()) {
            tracing::warn!("DPoP query proof verification failed: {e}");
            return (StatusCode::UNAUTHORIZED, format!("DPoP proof invalid: {e}")).into_response();
        }
    } else if cnf_jkt.is_some() && has_auth_header {
        return (StatusCode::UNAUTHORIZED, "DPoP-bound token requires DPoP authorization scheme").into_response();
    }
    // Note: query-param tokens without dpop proof still accepted (backwards compat)

    let user_id = payload.sub.unwrap_or_else(|| "unknown".into());
    tracing::info!("Connection: {user_id} -> {host}:{port} (session: {session_id})");

    ws.on_upgrade(move |socket| bridge_tcp(state, socket, host, port))
}

// ── TCP bridge logic ─────────────────────────────────────────────

async fn bridge_tcp(state: Arc<AppState>, ws: WebSocket, host: String, port: u16) {
    state.active_connections.fetch_add(1, Ordering::Relaxed);
    let (mut ws_write, mut ws_read) = ws.split();

    // Connect to TCP target
    let tcp = match TcpStream::connect((&*host, port)).await {
        Ok(tcp) => {
            tracing::info!("TCP connected to {host}:{port}");
            let msg = serde_json::json!({"type": "connected"}).to_string();
            if ws_write.send(Message::Text(msg.into())).await.is_err() {
                state.active_connections.fetch_sub(1, Ordering::Relaxed);
                return;
            }
            tcp
        }
        Err(e) => {
            tracing::error!("TCP connect error: {e}");
            let msg = serde_json::json!({"type": "error", "message": e.to_string()}).to_string();
            let _ = ws_write.send(Message::Text(msg.into())).await;
            let _ = ws_write.close().await;
            state.active_connections.fetch_sub(1, Ordering::Relaxed);
            return;
        }
    };

    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let done = Arc::new(Notify::new());

    // TCP -> WS
    let ws_write = Arc::new(tokio::sync::Mutex::new(ws_write));
    {
        let ws_write = ws_write.clone();
        let done = done.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 16384];
            loop {
                match tcp_read.read(&mut buf).await {
                    Ok(0) => {
                        tracing::info!("TCP closed");
                        let mut ws = ws_write.lock().await;
                        let _ = ws.close().await;
                        done.notify_waiters();
                        break;
                    }
                    Ok(n) => {
                        let mut ws = ws_write.lock().await;
                        if ws.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                            done.notify_waiters();
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("TCP read error: {e}");
                        let mut ws = ws_write.lock().await;
                        let msg = serde_json::json!({"type": "error", "message": e.to_string()}).to_string();
                        let _ = ws.send(Message::Text(msg.into())).await;
                        let _ = ws.close().await;
                        done.notify_waiters();
                        break;
                    }
                }
            }
        });
    }

    // WS -> TCP
    {
        let state = state.clone();
        let done = done.clone();
        tokio::spawn(async move {
            while let Some(msg) = ws_read.next().await {
                match msg {
                    Ok(Message::Binary(data)) => {
                        if tcp_write.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    Ok(Message::Close(_)) => {
                        tracing::info!("WebSocket closed");
                        break;
                    }
                    Err(e) => {
                        tracing::error!("WebSocket error: {e}");
                        break;
                    }
                    _ => {}
                }
            }
            let _ = tcp_write.shutdown().await;
            state.active_connections.fetch_sub(1, Ordering::Relaxed);
            done.notify_waiters();
        });
    }

    done.notified().await;
}

// ── Main ─────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Init logging: stderr + broadcast to web UI
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::EnvFilter;
        logstream::init();
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("ssh_bridge=info,warn")
        });
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .with(logstream::BroadcastLayer)
            .init();
    }

    // First-run setup: if no config, serve web UI
    setup::run_setup_if_needed().await;

    let (config, port) = match load_config() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to load TideCloak config: {e}");
            std::process::exit(1);
        }
    };

    let state = Arc::new(AppState {
        config,
        active_connections: AtomicUsize::new(0),
        seen_jtis: DashMap::new(),
    });

    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/logs", get(logs_page_handler))
        .route("/logs/stream", get(logs_stream_handler))
        .route("/logs/buffer", get(logs_buffer_handler))
        .fallback(get(ws_handler))
        .with_state(state);

    let use_tls = env::var("HTTPS").map(|v| v != "false" && v != "0").unwrap_or(true);
    let tls_hostname = env::var("TLS_HOSTNAME").unwrap_or_else(|_| "localhost".to_string());

    let scheme = if use_tls { "https" } else { "http" };
    let ws_scheme = if use_tls { "wss" } else { "ws" };

    let logs_url = format!("{scheme}://localhost:{port}/logs");
    tray::spawn_tray(logs_url);

    tracing::info!("SSH Bridge listening on port {port} ({scheme})");
    tracing::info!("Health:    {scheme}://localhost:{port}/health");
    tracing::info!("Logs:      {scheme}://localhost:{port}/logs");
    tracing::info!("WebSocket: {ws_scheme}://localhost:{port}");

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap();

    if use_tls {
        use tokio_rustls::TlsAcceptor;
        use rustls::ServerConfig as RustlsConfig;

        let tls_cert = tls::generate_self_signed(&tls_hostname);
        tracing::info!("TLS: self-signed cert for {tls_hostname}");

        // Install default crypto provider
        let _ = rustls::crypto::ring::default_provider().install_default();

        let certs = rustls_pemfile::certs(&mut tls_cert.cert_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut tls_cert.key_pem.as_bytes())
            .unwrap()
            .unwrap();

        let rustls_config = RustlsConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let tls_acceptor = TlsAcceptor::from(Arc::new(rustls_config));

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!("Accept error: {e}");
                    continue;
                }
            };
            let acceptor = tls_acceptor.clone();
            let app = app.clone();
            tokio::spawn(async move {
                if let Ok(tls_stream) = acceptor.accept(stream).await {
                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                    let service = hyper::service::service_fn(move |req| {
                        let app = app.clone();
                        async move {
                            use tower::ServiceExt;
                            app.oneshot(req).await
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await;
                }
            });
        }
    } else {
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .unwrap();
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .unwrap()
            .recv()
            .await;
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.ok();
    }
    tracing::info!("Shutting down...");
}

// ── Log endpoints ─────────────────────────────────────────────────

async fn logs_page_handler() -> Html<&'static str> {
    Html(LOGS_HTML)
}

async fn logs_stream_handler() -> Response {
    use tokio_stream::wrappers::BroadcastStream;

    let rx = match logstream::subscribe() {
        Some(rx) => rx,
        None => {
            return (StatusCode::SERVICE_UNAVAILABLE, "Log stream not available").into_response();
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

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("connection", "keep-alive")
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| Response::new(Body::from("Internal error")))
}

async fn logs_buffer_handler() -> Json<Vec<String>> {
    Json(logstream::recent_lines())
}

// ── Logs HTML page ──────────────────────────────────────────────

static LOGS_HTML: &str = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SSH Bridge - Logs</title>
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
  <h1>SSH Bridge Logs</h1>
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
