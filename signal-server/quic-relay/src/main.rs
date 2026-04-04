//! QUIC Relay Sidecar
//!
//! Runs alongside the signal server on the same VM. Serves two purposes:
//!
//! 1. **Address discovery**: When a browser connects via WebTransport, the relay
//!    reads the browser's source IP:port and tells the signal server, which then
//!    tells the gateway to UDP hole-punch that address. This enables coordinated
//!    NAT traversal for direct QUIC connections.
//!
//! 2. **Relay fallback**: If direct QUIC fails (symmetric NAT), the relay
//!    forwards stream data between the browser's WebTransport session and the
//!    gateway via the signal server's WebSocket infrastructure.
//!
//! Uses the VM's Let's Encrypt TLS certs so browsers connect with trusted certs.
//!
//! Wire protocol over relay WebSocket (binary frames):
//!   [stream_id: u32 BE] [flags: u8] [payload]
//!   flags: 0x01=OPEN, 0x02=DATA, 0x03=FIN
//!
//! JSON control messages (text frames):
//!   {"type": "client_address", "address": "1.2.3.4:5678", "clientId": "..."}
//!   {"type": "gateway_punch", "gatewayId": "...", "targetAddress": "1.2.3.4:5678"}

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_tungstenite::tungstenite::Message;
use wtransport::{Endpoint, Identity, ServerConfig};

const FLAG_OPEN: u8 = 0x01;
const FLAG_DATA: u8 = 0x02;
const FLAG_FIN: u8 = 0x03;

#[derive(Parser)]
#[command(name = "quic-relay")]
struct Args {
    /// UDP port for WebTransport
    #[arg(long, default_value = "7893")]
    port: u16,

    /// Signal server WebSocket URL
    #[arg(long, default_value = "ws://127.0.0.1:9090")]
    signal_url: String,

    /// TLS certificate PEM file (Let's Encrypt fullchain)
    #[arg(long, default_value = "/certs/fullchain.pem")]
    cert: String,

    /// TLS private key PEM file
    #[arg(long, default_value = "/certs/privkey.pem")]
    key: String,
}

struct RelaySession {
    gw_tx: mpsc::UnboundedSender<Vec<u8>>,
    streams: HashMap<u32, mpsc::UnboundedSender<Vec<u8>>>,
}

type Sessions = Arc<RwLock<HashMap<String, Arc<Mutex<RelaySession>>>>>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();

    let identity = Identity::load_pemfiles(&args.cert, &args.key)
        .await
        .expect("Failed to load TLS certs");

    let config = ServerConfig::builder()
        .with_bind_default(args.port)
        .with_identity(identity)
        .max_idle_timeout(Some(Duration::from_secs(30)))
        .expect("Failed to build ServerConfig")
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .build();

    let endpoint = Endpoint::server(config)
        .expect("Failed to create WebTransport endpoint");

    tracing::info!("[Relay] QUIC relay listening on 0.0.0.0:{}", args.port);

    let sessions: Sessions = Arc::new(RwLock::new(HashMap::new()));

    loop {
        let incoming = endpoint.accept().await;
        let sessions = sessions.clone();
        let signal_url = args.signal_url.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_session(incoming, sessions, signal_url).await {
                tracing::error!("[Relay] Session error: {e}");
            }
        });
    }
}

async fn handle_session(
    incoming: wtransport::endpoint::IncomingSession,
    sessions: Sessions,
    signal_url: String,
) -> Result<(), String> {
    let request = incoming.await.map_err(|e| format!("Connect error: {e}"))?;
    let authority = request.authority().to_string();
    tracing::info!("[Relay] Incoming session from {authority}");

    let connection = request.accept().await.map_err(|e| format!("Accept error: {e}"))?;

    // Get browser's real source IP:port (for hole-punching)
    let client_addr = connection.remote_address();
    let session_id = uuid_v4();
    tracing::info!("[Relay] Session {session_id} — browser at {client_addr}");

    // Connect to signal server relay endpoint
    let relay_ws_url = format!(
        "{}/ws/quic-relay?session={}&clientAddr={}",
        signal_url, session_id, client_addr
    );
    let (ws_stream, _) = tokio_tungstenite::connect_async(&relay_ws_url)
        .await
        .map_err(|e| format!("Signal server connect failed: {e}"))?;

    let (mut ws_sink, mut ws_stream_rx) = ws_stream.split();

    // Send client address to signal server (triggers hole-punch on gateway)
    let addr_msg = serde_json::json!({
        "type": "client_address",
        "sessionId": session_id,
        "address": client_addr.to_string(),
    });
    ws_sink.send(Message::Text(addr_msg.to_string().into()))
        .await
        .map_err(|e| format!("Failed to send client address: {e}"))?;

    tracing::info!("[Relay] Sent client address {client_addr} to signal server");

    // Channel for sending frames to gateway
    let (gw_tx, mut gw_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let session = Arc::new(Mutex::new(RelaySession {
        gw_tx: gw_tx.clone(),
        streams: HashMap::new(),
    }));

    {
        let mut sessions_map = sessions.write().await;
        sessions_map.insert(session_id.clone(), session.clone());
    }

    // Gateway → browser: forward frames from signal server WS to WebTransport streams
    let session_for_gw = session.clone();
    let sid_clone = session_id.clone();
    let gw_to_browser = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_stream_rx.next().await {
            match msg {
                Message::Binary(data) => {
                    if data.len() < 5 { continue; }
                    let stream_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    let flags = data[4];
                    let payload = data[5..].to_vec();

                    let sess = session_for_gw.lock().await;
                    match flags {
                        FLAG_DATA => {
                            if let Some(tx) = sess.streams.get(&stream_id) {
                                let _ = tx.send(payload);
                            }
                        }
                        FLAG_FIN => {
                            drop(sess);
                            let mut sess = session_for_gw.lock().await;
                            sess.streams.remove(&stream_id);
                        }
                        _ => {}
                    }
                }
                Message::Text(text) => {
                    // JSON control messages from signal server
                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(&*text) {
                        let msg_type = msg["type"].as_str().unwrap_or("");
                        match msg_type {
                            "punch_sent" => {
                                tracing::info!("[Relay] Gateway sent hole-punch for session {sid_clone}");
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    });

    // Browser → gateway: forward frames from channel to signal server WS
    let browser_to_gw = tokio::spawn(async move {
        while let Some(frame) = gw_rx.recv().await {
            if ws_sink.send(Message::Binary(frame.into())).await.is_err() {
                break;
            }
        }
    });

    // Accept WebTransport bidi streams from browser and relay
    let session_for_streams = session.clone();
    let stream_acceptor = tokio::spawn(async move {
        let mut next_stream_id: u32 = 0;

        loop {
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    let stream_id = next_stream_id;
                    next_stream_id += 1;

                    let (stream_tx, stream_rx) = mpsc::unbounded_channel::<Vec<u8>>();
                    {
                        let mut sess = session_for_streams.lock().await;
                        sess.streams.insert(stream_id, stream_tx);
                    }

                    // Send OPEN frame
                    let gw_tx = {
                        let sess = session_for_streams.lock().await;
                        sess.gw_tx.clone()
                    };
                    let mut open_frame = Vec::with_capacity(5);
                    open_frame.extend_from_slice(&stream_id.to_be_bytes());
                    open_frame.push(FLAG_OPEN);
                    let _ = gw_tx.send(open_frame);

                    let sess = session_for_streams.clone();
                    tokio::spawn(async move {
                        relay_stream(stream_id, send, recv, stream_rx, gw_tx, sess).await;
                    });
                }
                Err(e) => {
                    tracing::info!("[Relay] Stream accept ended: {e}");
                    break;
                }
            }
        }
    });

    tokio::select! {
        _ = gw_to_browser => {}
        _ = browser_to_gw => {}
        _ = stream_acceptor => {}
    }

    {
        let mut sessions_map = sessions.write().await;
        sessions_map.remove(&session_id);
    }
    tracing::info!("[Relay] Session {session_id} cleaned up");

    Ok(())
}

async fn relay_stream(
    stream_id: u32,
    mut send: wtransport::SendStream,
    mut recv: wtransport::RecvStream,
    mut from_gw: mpsc::UnboundedReceiver<Vec<u8>>,
    to_gw: mpsc::UnboundedSender<Vec<u8>>,
    session: Arc<Mutex<RelaySession>>,
) {
    let to_gw_clone = to_gw.clone();

    // Browser → gateway
    let browser_to_gw = async {
        let mut buf = [0u8; 65536];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) if n > 0 => {
                    let mut frame = Vec::with_capacity(5 + n);
                    frame.extend_from_slice(&stream_id.to_be_bytes());
                    frame.push(FLAG_DATA);
                    frame.extend_from_slice(&buf[..n]);
                    if to_gw_clone.send(frame).is_err() { break; }
                }
                _ => break,
            }
        }
        let mut fin = Vec::with_capacity(5);
        fin.extend_from_slice(&stream_id.to_be_bytes());
        fin.push(FLAG_FIN);
        let _ = to_gw_clone.send(fin);
    };

    // Gateway → browser
    let gw_to_browser = async {
        while let Some(data) = from_gw.recv().await {
            if send.write_all(&data).await.is_err() { break; }
        }
    };

    tokio::select! {
        _ = browser_to_gw => {}
        _ = gw_to_browser => {}
    }

    {
        let mut sess = session.lock().await;
        sess.streams.remove(&stream_id);
    }
}

fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        t.as_secs() as u32,
        (t.subsec_nanos() >> 16) & 0xffff,
        0x4000 | (t.subsec_nanos() & 0x0fff),
        0x8000 | ((t.as_nanos() >> 48) as u16 & 0x3fff),
        t.as_nanos() as u64 & 0xffffffffffff,
    )
}
