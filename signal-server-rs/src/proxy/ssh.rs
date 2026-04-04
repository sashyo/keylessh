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
    tracing::info!("[SSH-Proxy] Connecting to gateway: {gw_ws_url}");

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
