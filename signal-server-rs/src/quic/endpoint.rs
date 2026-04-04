use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use wtransport::{Endpoint, Identity, ServerConfig};

use crate::state::AppState;

const FLAG_OPEN: u8 = 0x01;
const FLAG_DATA: u8 = 0x02;
const FLAG_FIN: u8 = 0x03;

struct RelayStream {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

struct SessionState {
    streams: HashMap<u32, RelayStream>,
}

/// Start the WebTransport relay endpoint on the given UDP port.
/// Uses Let's Encrypt certs for trusted browser connections.
pub async fn start_relay_endpoint(state: AppState, cert_path: &str, key_path: &str, port: u16) {
    let identity = match Identity::load_pemfiles(cert_path, key_path).await {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("[Relay] Failed to load TLS certs: {e}");
            return;
        }
    };

    let config = match ServerConfig::builder()
        .with_bind_default(port)
        .with_identity(identity)
        .max_idle_timeout(Some(Duration::from_secs(30)))
    {
        Ok(c) => c.keep_alive_interval(Some(Duration::from_secs(10))).build(),
        Err(e) => {
            tracing::error!("[Relay] Failed to build config: {e}");
            return;
        }
    };

    let endpoint = match Endpoint::server(config) {
        Ok(ep) => ep,
        Err(e) => {
            tracing::error!("[Relay] Failed to create endpoint: {e}");
            return;
        }
    };

    tracing::info!("[Relay] WebTransport relay listening on 0.0.0.0:{port}");

    loop {
        let incoming = endpoint.accept().await;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_session(incoming, state).await {
                tracing::error!("[Relay] Session error: {e}");
            }
        });
    }
}

async fn handle_session(
    incoming: wtransport::endpoint::IncomingSession,
    state: AppState,
) -> Result<(), String> {
    let request = incoming.await.map_err(|e| format!("Connect error: {e}"))?;
    let path = request.path().to_string();

    // Extract gatewayId from query
    let gateway_id = path.split("gateway=")
        .nth(1)
        .and_then(|s| s.split('&').next())
        .map(|s| urlencoding::decode(s).unwrap_or_default().to_string())
        .unwrap_or_default();

    let connection = request.accept().await.map_err(|e| format!("Accept error: {e}"))?;
    let client_addr = connection.remote_address();
    let session_id = uuid::Uuid::new_v4().to_string();

    tracing::info!("[Relay] Session {session_id} — browser at {client_addr}, gateway={gateway_id}");

    // Find the target gateway
    let gw_id = if !gateway_id.is_empty() && state.registry.get_gateway(&gateway_id).is_some() {
        gateway_id.clone()
    } else {
        state.registry.get_available_gateway()
            .ok_or("No gateway available")?
    };

    // Tell gateway to punch the browser's address
    let punch_addr = client_addr.to_string().replace("::ffff:", "");
    state.registry.send_to_gateway(&gw_id, axum::extract::ws::Message::Text(
        serde_json::json!({
            "type": "punch",
            "targetAddress": punch_addr,
            "sessionId": session_id,
        }).to_string().into()
    ));

    // Create response channel for gateway → browser frames
    let (response_tx, mut response_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Store relay session with response channel
    state.relay_sessions.insert(session_id.clone(), crate::state::RelaySession {
        gateway_id: gw_id.clone(),
        client_addr: punch_addr,
        response_tx,
    });

    let session_state = Arc::new(Mutex::new(SessionState {
        streams: HashMap::new(),
    }));

    // Spawn task to dispatch gateway responses to the correct WebTransport streams
    let ss_for_dispatch = session_state.clone();
    let dispatch_task = tokio::spawn(async move {
        while let Some(frame) = response_rx.recv().await {
            if frame.len() < 5 { continue; }
            let stream_id = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
            let _flags = frame[4];
            let payload = &frame[5..];

            let ss = ss_for_dispatch.lock().await;
            if let Some(stream) = ss.streams.get(&stream_id) {
                let _ = stream.tx.send(payload.to_vec());
            }
        }
    });

    // Accept bidi streams from browser
    let mut next_stream_id: u32 = 0;

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let stream_id = next_stream_id;
                next_stream_id += 1;
                tracing::info!("[Relay] Stream {stream_id} accepted for session {session_id}");

                let (stream_tx, stream_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                {
                    let mut ss = session_state.lock().await;
                    ss.streams.insert(stream_id, RelayStream { tx: stream_tx });
                }

                // Send OPEN frame to gateway
                send_to_gateway_binary(&state, &gw_id, &session_id, stream_id, FLAG_OPEN, &[]);

                let state_clone = state.clone();
                let gw_clone = gw_id.clone();
                let sid_clone = session_id.clone();
                let ss_clone = session_state.clone();

                tokio::spawn(async move {
                    relay_stream(
                        stream_id, send, recv, stream_rx,
                        state_clone, gw_clone, sid_clone, ss_clone,
                    ).await;
                });
            }
            Err(e) => {
                tracing::info!("[Relay] Session {session_id} ended: {e}");
                break;
            }
        }
    }

    dispatch_task.abort();
    state.relay_sessions.remove(&session_id);
    Ok(())
}

async fn relay_stream(
    stream_id: u32,
    mut send: wtransport::SendStream,
    mut recv: wtransport::RecvStream,
    mut from_gw: mpsc::UnboundedReceiver<Vec<u8>>,
    state: AppState,
    gateway_id: String,
    session_id: String,
    session_state: Arc<Mutex<SessionState>>,
) {
    // Browser → gateway
    let browser_to_gw = async {
        let mut buf = [0u8; 65536];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) if n > 0 => {
                    tracing::info!("[Relay] Stream {stream_id} browser→gw: {n}b");
                    send_to_gateway_binary(&state, &gateway_id, &session_id, stream_id, FLAG_DATA, &buf[..n]);
                }
                _ => break,
            }
        }
        send_to_gateway_binary(&state, &gateway_id, &session_id, stream_id, FLAG_FIN, &[]);
    };

    // Gateway → browser
    let gw_to_browser = async {
        while let Some(data) = from_gw.recv().await {
            if send.write_all(&data).await.is_err() { break; }
        }
    };

    tokio::join!(browser_to_gw, gw_to_browser);

    {
        let mut ss = session_state.lock().await;
        ss.streams.remove(&stream_id);
    }
}

/// Send a binary relay frame to the gateway via its signaling WebSocket.
/// Frame: [0x52][session_id_len:u16][session_id][stream_id:u32][flags:u8][payload]
fn send_to_gateway_binary(
    state: &AppState,
    gateway_id: &str,
    session_id: &str,
    stream_id: u32,
    flags: u8,
    payload: &[u8],
) {
    let sid_bytes = session_id.as_bytes();
    let mut frame = Vec::with_capacity(3 + sid_bytes.len() + 5 + payload.len());
    frame.push(0x52);
    frame.push((sid_bytes.len() >> 8) as u8);
    frame.push(sid_bytes.len() as u8);
    frame.extend_from_slice(sid_bytes);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.push(flags);
    frame.extend_from_slice(payload);

    state.registry.send_to_gateway(gateway_id, axum::extract::ws::Message::Binary(frame.into()));
}
