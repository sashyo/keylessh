use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;

use crate::state::AppState;

pub async fn ssh_ws_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let gateway_id = params.get("gatewayId").cloned().unwrap_or_default();
    let query_string: String = params.iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&");

    ws.on_upgrade(move |socket| handle_ssh_proxy(socket, gateway_id, query_string, state))
}

async fn handle_ssh_proxy(
    client_ws: WebSocket,
    gateway_id: String,
    query_string: String,
    state: AppState,
) {
    // Find gateway
    let gw_id = if !gateway_id.is_empty() {
        if state.registry.get_gateway(&gateway_id).is_some() {
            gateway_id.clone()
        } else {
            tracing::warn!("[SSH-Proxy] Gateway {gateway_id} not found");
            return;
        }
    } else {
        match state.registry.get_available_gateway() {
            Some(id) => id,
            None => {
                tracing::warn!("[SSH-Proxy] No gateway available");
                return;
            }
        }
    };

    // Get gateway's public IP and port
    let (gw_ip, gw_port) = {
        let gw = match state.registry.get_gateway(&gw_id) {
            Some(g) => g,
            None => return,
        };
        let ip = gw.public_ip.clone().unwrap_or_default();
        let port = gw.addresses.first()
            .and_then(|a| a.split(':').last())
            .unwrap_or("7891")
            .to_string();
        (ip, port)
    };

    if gw_ip.is_empty() {
        tracing::error!("[SSH-Proxy] Gateway {gw_id} has no public IP");
        return;
    }

    let gw_ws_url = format!("ws://{}:{}/ws/ssh?{}", gw_ip, gw_port, query_string);
    tracing::info!("[SSH-Proxy] Connecting to gateway: {}", redact_query_secrets(&gw_ws_url));

    // Connect to gateway's /ws/ssh endpoint
    let gw_stream = match tokio_tungstenite::connect_async(&gw_ws_url).await {
        Ok((stream, _)) => {
            tracing::info!("[SSH-Proxy] Connected to gateway {gw_id}");
            stream
        }
        Err(e) => {
            tracing::error!("[SSH-Proxy] Gateway connection failed: {e}");
            return;
        }
    };

    let (mut gw_sink, mut gw_stream) = gw_stream.split();
    let (mut client_sink, mut client_stream) = client_ws.split();

    // Bridge: client → gateway
    let client_to_gw = async {
        while let Some(Ok(msg)) = client_stream.next().await {
            let tung_msg = match msg {
                Message::Text(t) => tokio_tungstenite::tungstenite::Message::Text(t.to_string().into()),
                Message::Binary(b) => tokio_tungstenite::tungstenite::Message::Binary(b.to_vec().into()),
                Message::Close(_) => break,
                _ => continue,
            };
            if gw_sink.send(tung_msg).await.is_err() { break; }
        }
    };

    // Bridge: gateway → client
    let gw_to_client = async {
        while let Some(Ok(msg)) = gw_stream.next().await {
            let axum_msg = match msg {
                tokio_tungstenite::tungstenite::Message::Text(t) => Message::Text(t.to_string().into()),
                tokio_tungstenite::tungstenite::Message::Binary(b) => Message::Binary(b.to_vec().into()),
                tokio_tungstenite::tungstenite::Message::Close(_) => break,
                _ => continue,
            };
            if client_sink.send(axum_msg).await.is_err() { break; }
        }
    };

    tokio::select! {
        _ = client_to_gw => {}
        _ = gw_to_client => {}
    }

    tracing::info!("[SSH-Proxy] Session ended for gateway {gw_id}");
}

/// Strip credential-bearing query parameters before a URL reaches the logs.
///
/// SSH tunnel URLs carry the user's access token. Logged verbatim it lands in a
/// world-readable log file, decodable, complete with the user's roles and email.
pub fn redact_query_secrets(url: &str) -> String {
    const SECRET_PARAMS: &[&str] = &["token", "access_token", "secret", "api_secret", "password"];

    let Some((base, query)) = url.split_once('?') else {
        return url.to_string();
    };

    let redacted: Vec<String> = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _)) if SECRET_PARAMS.contains(&key.to_ascii_lowercase().as_str()) => {
                format!("{key}=<redacted>")
            }
            _ => pair.to_string(),
        })
        .collect();

    format!("{base}?{}", redacted.join("&"))
}

#[cfg(test)]
mod redaction_tests {
    use super::redact_query_secrets;

    #[test]
    fn redacts_the_access_token() {
        let url = "ws://gw:7891/ws/ssh?token=eyJhbGciOiJFZERTQSJ9.payload.sig&host=TideStun&port=22";
        let out = redact_query_secrets(url);
        assert!(!out.contains("eyJhbGciOiJFZERTQSJ9"), "token still present: {out}");
        assert_eq!(out, "ws://gw:7891/ws/ssh?token=<redacted>&host=TideStun&port=22");
    }

    #[test]
    fn keeps_the_parts_that_make_a_log_line_useful() {
        let out = redact_query_secrets("ws://gw:7891/ws/ssh?token=abc&host=TideStun&port=22&serverId=X");
        assert!(out.contains("host=TideStun"));
        assert!(out.contains("port=22"));
        assert!(out.contains("serverId=X"));
    }

    #[test]
    fn redacts_every_known_secret_parameter() {
        let out = redact_query_secrets("ws://h/p?api_secret=s1&password=s2&access_token=s3&secret=s4");
        for leaked in ["s1", "s2", "s3", "s4"] {
            assert!(!out.contains(leaked), "{leaked} leaked: {out}");
        }
    }

    #[test]
    fn is_case_insensitive_on_parameter_names() {
        assert!(!redact_query_secrets("ws://h/p?TOKEN=secret").contains("secret"));
    }

    #[test]
    fn leaves_urls_without_secrets_alone() {
        assert_eq!(redact_query_secrets("ws://h/p"), "ws://h/p");
        assert_eq!(redact_query_secrets("ws://h/p?host=x&port=22"), "ws://h/p?host=x&port=22");
    }

    #[test]
    fn handles_malformed_query_pairs() {
        let out = redact_query_secrets("ws://h/p?token&host=x&=y");
        assert!(out.contains("host=x"));
    }
}
