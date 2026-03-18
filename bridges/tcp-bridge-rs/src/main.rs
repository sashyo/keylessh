use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json};
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

fn load_config() -> Result<TidecloakConfig, String> {
    let config_data = if let Ok(adapter) = env::var("client_adapter") {
        eprintln!("[Bridge] Loading config from client_adapter env variable");
        adapter
    } else if let Ok(b64) = env::var("TIDECLOAK_CONFIG_B64") {
        eprintln!("[Bridge] Loading config from TIDECLOAK_CONFIG_B64");
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| format!("Base64 decode error: {e}"))?;
        String::from_utf8(bytes).map_err(|e| format!("UTF-8 error: {e}"))?
    } else {
        let path = resolve_config_path().ok_or("No tidecloak.json found in data directory")?;
        eprintln!("[Bridge] Loading config from {}", path.display());
        fs::read_to_string(&path).map_err(|e| format!("Read error: {e}"))?
    };

    let config: TidecloakConfig =
        serde_json::from_str(&config_data).map_err(|e| format!("JSON parse error: {e}"))?;

    if config.jwk.keys.is_empty() {
        return Err("No JWKS keys found in config".into());
    }

    eprintln!("[Bridge] JWKS loaded successfully");
    Ok(config)
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

    let expected_issuer = if config.auth_server_url.ends_with('/') {
        format!("{}realms/{}", config.auth_server_url, config.realm)
    } else {
        format!("{}/realms/{}", config.auth_server_url, config.realm)
    };
    if payload.iss.as_deref() != Some(&expected_issuer) {
        eprintln!("[Bridge] Issuer mismatch: expected {expected_issuer}, got {:?}", payload.iss);
        return None;
    }

    if payload.azp.as_deref() != Some(&config.resource) {
        eprintln!("[Bridge] AZP mismatch: expected {}, got {:?}", config.resource, payload.azp);
        return None;
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    if let Some(exp) = payload.exp {
        if now > exp {
            eprintln!("[Bridge] Token expired");
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
            eprintln!("[Bridge] JWT signature verification failed");
            None
        }
        Err(e) => {
            eprintln!("[Bridge] JWT verification error: {e}");
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
                    eprintln!("[Bridge] DPoP proof verification failed: {e}");
                    return (StatusCode::UNAUTHORIZED, format!("DPoP proof invalid: {e}")).into_response();
                }
            }
            None => return (StatusCode::UNAUTHORIZED, "DPoP proof required").into_response(),
        }
    } else if let Some(ref dpop_proof) = params.dpop {
        if let Err(e) = verify_dpop_proof(&state, dpop_proof, "GET", &request_url, cnf_jkt.as_deref()) {
            eprintln!("[Bridge] DPoP query proof verification failed: {e}");
            return (StatusCode::UNAUTHORIZED, format!("DPoP proof invalid: {e}")).into_response();
        }
    } else if cnf_jkt.is_some() && has_auth_header {
        return (StatusCode::UNAUTHORIZED, "DPoP-bound token requires DPoP authorization scheme").into_response();
    }
    // Note: query-param tokens without dpop proof still accepted (backwards compat)

    let user_id = payload.sub.unwrap_or_else(|| "unknown".into());
    eprintln!("[Bridge] Connection: {user_id} -> {host}:{port} (session: {session_id})");

    ws.on_upgrade(move |socket| bridge_tcp(state, socket, host, port))
}

// ── TCP bridge logic ─────────────────────────────────────────────

async fn bridge_tcp(state: Arc<AppState>, ws: WebSocket, host: String, port: u16) {
    state.active_connections.fetch_add(1, Ordering::Relaxed);
    let (mut ws_write, mut ws_read) = ws.split();

    // Connect to TCP target
    let tcp = match TcpStream::connect((&*host, port)).await {
        Ok(tcp) => {
            eprintln!("[Bridge] TCP connected to {host}:{port}");
            let msg = serde_json::json!({"type": "connected"}).to_string();
            if ws_write.send(Message::Text(msg.into())).await.is_err() {
                state.active_connections.fetch_sub(1, Ordering::Relaxed);
                return;
            }
            tcp
        }
        Err(e) => {
            eprintln!("[Bridge] TCP connect error: {e}");
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
                        eprintln!("[Bridge] TCP closed");
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
                        eprintln!("[Bridge] TCP read error: {e}");
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
                        eprintln!("[Bridge] WebSocket closed");
                        break;
                    }
                    Err(e) => {
                        eprintln!("[Bridge] WebSocket error: {e}");
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
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8081);

    let config = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[Bridge] Failed to load TideCloak config: {e}");
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
        .fallback(get(ws_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}"))
        .await
        .unwrap();
    eprintln!("[Bridge] TCP Bridge listening on port {port}");
    eprintln!("[Bridge] Health: http://localhost:{port}/health");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .unwrap()
        .recv()
        .await;
    eprintln!("[Bridge] Shutting down...");
}
