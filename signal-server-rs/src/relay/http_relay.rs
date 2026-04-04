use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use std::time::Duration;
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::state::{AppState, HttpRelayResponse, PendingRequest};

const RELAY_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// HTTP relay handler — proxies requests to gateways via their signaling WebSocket.
pub async fn relay_handler(State(state): State<AppState>, req: Request) -> Response {
    let url = req.uri().path().to_string()
        + req.uri().query().map(|q| format!("?{q}")).as_deref().unwrap_or("");
    let method = req.method().to_string();
    let headers = req.headers().clone();

    // Find target gateway
    let gateway_id = find_gateway(&state, &url, &headers);
    let gateway_id = match gateway_id {
        Some(id) => id,
        None => {
            return (StatusCode::SERVICE_UNAVAILABLE, "No gateway available").into_response();
        }
    };

    // Read body
    let body_bytes = match axum::body::to_bytes(req.into_body(), MAX_BODY_SIZE).await {
        Ok(b) => b,
        Err(_) => {
            return (StatusCode::PAYLOAD_TOO_LARGE, "Request body too large").into_response();
        }
    };
    let body_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &body_bytes,
    );

    // Build relay message
    let request_id = Uuid::new_v4().to_string();
    let headers_json: serde_json::Value = headers.iter()
        .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_str().unwrap_or("").to_string())))
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();

    let relay_msg = serde_json::json!({
        "type": "http_request",
        "id": request_id,
        "method": method,
        "url": url,
        "headers": headers_json,
        "body": body_b64,
    });

    // Send to gateway
    let sent = state.registry.send_to_gateway(
        &gateway_id,
        axum::extract::ws::Message::Text(relay_msg.to_string().into()),
    );
    if !sent {
        return (StatusCode::BAD_GATEWAY, "Failed to reach gateway").into_response();
    }

    // Register pending request
    let (tx, rx) = oneshot::channel::<HttpRelayResponse>();
    state.pending_requests.insert(request_id.clone(), PendingRequest { response_tx: tx });

    // Wait for response with timeout
    match tokio::time::timeout(RELAY_TIMEOUT, rx).await {
        Ok(Ok(resp)) => {
            let mut builder = Response::builder().status(resp.status);

            // Parse response headers
            if let Some(headers_obj) = resp.headers.as_object() {
                for (k, v) in headers_obj {
                    // Skip CORS headers (handled at tower level)
                    if k.to_lowercase().starts_with("access-control-") {
                        continue;
                    }
                    if let Some(val) = v.as_str() {
                        if let Ok(hv) = HeaderValue::from_str(val) {
                            builder = builder.header(k.as_str(), hv);
                        }
                    }
                }
            }

            // Add gateway affinity cookie
            let cookie = format!(
                "gateway_relay={}; Path=/; HttpOnly; SameSite=None; Secure",
                urlencoding::encode(&gateway_id)
            );
            builder = builder.header("set-cookie", cookie);

            builder.body(Body::from(resp.body)).unwrap_or_else(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, "Response build error").into_response()
            })
        }
        Ok(Err(_)) => {
            state.pending_requests.remove(&request_id);
            (StatusCode::BAD_GATEWAY, "Gateway connection lost").into_response()
        }
        Err(_) => {
            state.pending_requests.remove(&request_id);
            (StatusCode::GATEWAY_TIMEOUT, "Gateway response timeout").into_response()
        }
    }
}

fn find_gateway(state: &AppState, url: &str, headers: &HeaderMap) -> Option<String> {
    // Backend-based routing: /__b/<name>/
    if let Some(caps) = url.strip_prefix("/__b/") {
        if let Some(end) = caps.find('/') {
            let backend_name = urlencoding::decode(&caps[..end]).unwrap_or_default().to_string();
            if let Some(id) = state.registry.get_gateway_by_backend(&backend_name) {
                return Some(id);
            }
        }
    }

    // Realm-based routing: /realms/<realm>/, /resources/<realm>/
    for prefix in &["/realms/", "/resources/", "/admin/"] {
        if let Some(rest) = url.strip_prefix(prefix) {
            if let Some(end) = rest.find('/') {
                let realm = &rest[..end];
                if let Some(id) = state.registry.get_gateway_by_realm(realm) {
                    return Some(id);
                }
            }
        }
    }

    // Cookie-based affinity
    if let Some(cookie_header) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        for pair in cookie_header.split(';') {
            let pair = pair.trim();
            if let Some(val) = pair.strip_prefix("gateway_relay=") {
                let gw_id = urlencoding::decode(val).unwrap_or_default().to_string();
                if state.registry.get_gateway(&gw_id).is_some() {
                    return Some(gw_id);
                }
            }
        }
    }

    // Fallback: least-loaded gateway
    state.registry.get_available_gateway()
}
