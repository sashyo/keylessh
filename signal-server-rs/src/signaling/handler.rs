use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ws::WebSocketUpgrade, ConnectInfo, State};
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use tokio::sync::mpsc;

use crate::state::AppState;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let client_ip = addr.ip().to_string().replace("::ffff:", "");
    ws.on_upgrade(move |socket| handle_signaling(socket, client_ip, state))
}

pub async fn handle_signaling_public(socket: WebSocket, client_ip: String, state: AppState) {
    handle_signaling(socket, client_ip, state).await;
}

async fn handle_signaling(socket: WebSocket, client_ip: String, state: AppState) {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // Forward outbound messages from channel to WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if ws_sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Ping keepalive
    let tx_ping = tx.clone();
    let ping_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            interval.tick().await;
            if tx_ping.send(Message::Ping(vec![].into())).is_err() {
                break;
            }
        }
    });

    let mut registered_id: Option<String> = None;
    let mut is_gateway = false;

    // Process incoming messages
    while let Some(Ok(msg)) = ws_receiver.next().await {
        match msg {
            Message::Text(text) => {
                let parsed: serde_json::Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let msg_type = parsed["type"].as_str().unwrap_or("");

                match msg_type {
                    "register" => {
                        let id = parsed["id"].as_str().unwrap_or("").to_string();
                        let role = parsed["role"].as_str().unwrap_or("");

                        if id.is_empty() || role.is_empty() {
                            let _ = tx.send(Message::Text(
                                serde_json::json!({"type": "error", "message": "Missing id or role"}).to_string().into()
                            ));
                            continue;
                        }

                        if role == "gateway" {
                            // Verify API secret
                            if !state.config.api_secret.is_empty() {
                                let secret = parsed["secret"].as_str().unwrap_or("");
                                if secret != state.config.api_secret {
                                    tracing::warn!("[Signal] Gateway auth failed: {id}");
                                    let _ = tx.send(Message::Text(
                                        serde_json::json!({"type": "error", "message": "Invalid API secret"}).to_string().into()
                                    ));
                                    break;
                                }
                            }

                            let addresses: Vec<String> = parsed["addresses"]
                                .as_array()
                                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                .unwrap_or_default();

                            let metadata = crate::registry::GatewayMetadata {
                                display_name: parsed["metadata"]["displayName"].as_str().map(|s| s.to_string()),
                                description: parsed["metadata"]["description"].as_str().map(|s| s.to_string()),
                                backends: parsed["metadata"]["backends"].as_array().map(|arr| {
                                    arr.iter().map(|b| crate::registry::BackendInfo {
                                        name: b["name"].as_str().unwrap_or("").to_string(),
                                        protocol: b["protocol"].as_str().map(|s| s.to_string()),
                                        auth: b["auth"].as_str().map(|s| s.to_string()),
                                    }).collect()
                                }),
                                realm: parsed["metadata"]["realm"].as_str().map(|s| s.to_string()),
                                public_url: parsed["metadata"]["publicUrl"].as_str().map(|s| s.to_string()),
                            };

                            let public_ip = metadata.public_url.clone()
                                .unwrap_or_else(|| client_ip.clone());

                            let addr_str = addresses.first().cloned().unwrap_or_default();
                            state.registry.register_gateway(
                                id.clone(), addresses, tx.clone(), metadata, Some(public_ip),
                            );

                            tracing::info!("[Signal] Gateway registered: {id} ({id}) at {addr_str}");
                            is_gateway = true;
                            registered_id = Some(id.clone());

                            let _ = tx.send(Message::Text(
                                serde_json::json!({"type": "registered", "role": "gateway", "id": id}).to_string().into()
                            ));
                        } else if role == "client" {
                            let token = parsed["token"].as_str().unwrap_or("").to_string();
                            tracing::info!("[Signal] Client registered: {id}");

                            state.registry.register_client(id.clone(), tx.clone(), token);
                            state.registry.update_client_reflexive(&id, &client_ip);
                            registered_id = Some(id.clone());

                            let _ = tx.send(Message::Text(
                                serde_json::json!({"type": "registered", "role": "client", "id": id}).to_string().into()
                            ));

                            // Auto-pair or explicit pair
                            let target_gw = parsed["targetGatewayId"].as_str().unwrap_or("").to_string();
                            if !target_gw.is_empty() {
                                pair_client_with_gateway(&state, &id, &target_gw);
                            } else {
                                auto_pair_client(&state, &id);
                            }
                        }
                    }
                    "candidate" => {
                        let mut target = parsed["targetId"].as_str().unwrap_or("").to_string();
                        let from = parsed["fromId"].as_str()
                            .or_else(|| registered_id.as_deref())
                            .unwrap_or("unknown")
                            .to_string();
                        tracing::info!("[Signal] candidate from {from} targetId={target} is_gateway={is_gateway}");

                        // If no targetId, resolve from pairing
                        if target.is_empty() {
                            if is_gateway {
                                // Gateway sending candidate → find the paired client
                                // Try to find any client paired with this gateway
                                if let Some(id) = registered_id.as_deref() {
                                    if let Some(gw) = state.registry.get_gateway(id) {
                                        if let Some(client_id) = gw.paired_clients.iter().next() {
                                            target = client_id.clone();
                                        }
                                    }
                                }
                            } else {
                                // Client sending candidate → find the paired gateway
                                if let Some(id) = registered_id.as_deref() {
                                    if let Some(client) = state.registry.get_client(id) {
                                        if let Some(ref gw_id) = client.paired_gateway_id {
                                            target = gw_id.clone();
                                        }
                                    }
                                }
                            }
                        }

                        if !target.is_empty() {
                            let msg = serde_json::json!({
                                "type": "candidate",
                                "fromId": from,
                                "candidate": parsed["candidate"],
                            });
                            forward_to_peer(&state, &target, &msg);
                        }
                    }
                    "sdp_offer" | "sdp_answer" => {
                        let target = parsed["targetId"].as_str().unwrap_or("");
                        let from = parsed["fromId"].as_str()
                            .or_else(|| registered_id.as_deref())
                            .unwrap_or("unknown");
                        tracing::info!("[Signal] {msg_type} from {from} to {target}");
                        if !target.is_empty() {
                            let msg = serde_json::json!({
                                "type": msg_type,
                                "fromId": from,
                                "sdp": parsed["sdp"],
                                "sdpType": parsed["sdpType"],
                            });
                            forward_to_peer(&state, target, &msg);
                        }
                    }
                    "quic_address" => {
                        let target = parsed["targetId"].as_str().unwrap_or("");
                        let from = parsed["fromId"].as_str()
                            .or_else(|| registered_id.as_deref())
                            .unwrap_or("unknown");
                        if target.is_empty() { continue; }

                        let mut address = parsed["address"].as_str().unwrap_or("").to_string();

                        // Replace 0.0.0.0 with gateway's public IP
                        if address.starts_with("0.0.0.0:") {
                            if let Some(gw) = state.registry.get_gateway(from) {
                                if let Some(ref ip) = gw.public_ip {
                                    address = address.replace("0.0.0.0", ip);
                                }
                            }
                        }

                        let msg = serde_json::json!({
                            "type": "quic_address",
                            "fromId": from,
                            "address": address,
                            "certHash": parsed["certHash"],
                            "relayUrl": format!("{}:{}", state.config.relay_host, state.config.relay_port),
                            "gatewayId": from,
                        });
                        forward_to_peer(&state, target, &msg);
                    }
                    "punch" => {
                        // Forwarded internally — not expected from external clients
                    }
                    "http_response" | "http_response_start" | "http_response_chunk" | "http_response_end" | "http_abort" => {
                        // Handle HTTP relay responses
                        let req_id = parsed["id"].as_str().unwrap_or("").to_string();
                        if msg_type == "http_response" {
                            if let Some((_, pending)) = state.pending_requests.remove(&req_id) {
                                let status = parsed["statusCode"].as_u64().unwrap_or(200) as u16;
                                let headers = parsed["headers"].clone();
                                let body = parsed["body"].as_str()
                                    .and_then(|b| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b).ok())
                                    .unwrap_or_default();
                                let _ = pending.response_tx.send(crate::state::HttpRelayResponse {
                                    status, headers, body,
                                });
                            }
                        }
                        // TODO: streaming responses
                    }
                    _ => {}
                }
            }
            Message::Binary(_) => {
                // Binary messages not used (QUIC relay removed)
            }
            Message::Pong(_) => {}
            Message::Close(_) => break,
            _ => {}
        }
    }

    // Cleanup
    ping_task.abort();
    send_task.abort();

    if let Some(ref id) = registered_id {
        if is_gateway {
            state.registry.remove_gateway(id);
        } else {
            tracing::info!("[Signal] Client unregistered: {id}");
            state.registry.remove_client(id);
        }
    }
}

fn pair_client_with_gateway(state: &AppState, client_id: &str, gateway_id: &str) {
    let gw_exists = state.registry.get_gateway(gateway_id).is_some();
    if !gw_exists {
        state.registry.send_to_client(client_id, Message::Text(
            serde_json::json!({"type": "error", "message": format!("Gateway {gateway_id} not found")}).to_string().into()
        ));
        return;
    }

    // Update pairing state
    if let Some(mut client) = state.registry.get_client_mut(client_id) {
        client.paired_gateway_id = Some(gateway_id.to_string());
    }
    if let Some(mut gw) = state.registry.get_gateway_mut(gateway_id) {
        gw.paired_clients.insert(client_id.to_string());
    }

    // Notify client
    let gw_info = state.registry.get_gateway(gateway_id).map(|gw| {
        serde_json::json!({
            "id": gw.id,
            "addresses": gw.addresses,
        })
    });
    state.registry.send_to_client(client_id, Message::Text(
        serde_json::json!({"type": "paired", "gateway": gw_info}).to_string().into()
    ));

    // Notify gateway (include client token)
    let client_info = state.registry.get_client(client_id).map(|c| {
        serde_json::json!({
            "id": c.id,
            "reflexiveAddress": c.reflexive_address,
            "token": c.token,
        })
    });
    state.registry.send_to_gateway(gateway_id, Message::Text(
        serde_json::json!({"type": "paired", "client": client_info}).to_string().into()
    ));

    tracing::info!("[Signal] Paired client {client_id} with gateway {gateway_id} (explicit)");
}

fn auto_pair_client(state: &AppState, client_id: &str) {
    if let Some(gw_id) = state.registry.get_available_gateway() {
        pair_client_with_gateway(state, client_id, &gw_id);
    } else {
        state.registry.send_to_client(client_id, Message::Text(
            serde_json::json!({"type": "error", "message": "No gateway available"}).to_string().into()
        ));
    }
}

fn forward_to_peer(state: &AppState, target_id: &str, msg: &serde_json::Value) {
    let msg_type = msg["type"].as_str().unwrap_or("unknown");
    let text = serde_json::to_string(msg).unwrap_or_default();
    let sent = state.registry.send_to_gateway(target_id, Message::Text(text.clone().into()))
        || state.registry.send_to_client(target_id, Message::Text(text.into()));
    if !sent {
        tracing::warn!("[Signal] Target {target_id} not found for {msg_type}");
    }
}
