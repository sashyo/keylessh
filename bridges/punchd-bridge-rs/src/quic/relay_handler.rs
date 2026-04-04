//! Handles relayed QUIC stream frames from the signal server.
//!
//! When the browser connects via the relay sidecar (for NAT traversal),
//! stream data is forwarded through: browser → relay → signal server → gateway.
//!
//! Frame format: [stream_id:u32][flags:u8][payload]
//! Flags: 0x01=OPEN, 0x02=DATA, 0x03=FIN
//!
//! Each stream uses the same type-byte protocol as direct WebTransport:
//! first byte of first DATA frame is the stream type (AUTH, SSH, HTTP, WS).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_tungstenite::tungstenite::Message;

use crate::auth::tidecloak::TidecloakAuth;
use crate::config::BackendEntry;
use crate::stun::stun_client::StunRegistrationOptions;
use crate::quic::transport::stream_type;

const FLAG_OPEN: u8 = 0x01;
const FLAG_DATA: u8 = 0x02;
const FLAG_FIN: u8 = 0x03;

type WsSink = Arc<Mutex<futures_util::stream::SplitSink<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Message,
>>>;

struct RelayStream {
    /// Channel to send data from signal server → this stream's handler
    tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Whether we've read the type byte yet
    type_known: bool,
}

struct RelaySession {
    streams: HashMap<u32, RelayStream>,
    authenticated: bool,
}

static SESSIONS: std::sync::OnceLock<RwLock<HashMap<String, Arc<Mutex<RelaySession>>>>> =
    std::sync::OnceLock::new();

fn sessions() -> &'static RwLock<HashMap<String, Arc<Mutex<RelaySession>>>> {
    SESSIONS.get_or_init(|| RwLock::new(HashMap::new()))
}

pub async fn handle_relay_frame(
    session_id: &str,
    stream_id: u32,
    flags: u8,
    payload: &[u8],
    options: Arc<StunRegistrationOptions>,
    ws_sink: WsSink,
    punch_socket: &std::net::UdpSocket,
) {
    match flags {
        FLAG_OPEN => {
            // New stream opened by browser
            let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();

            // Get or create session
            let session = {
                let mut sessions = sessions().write().await;
                sessions.entry(session_id.to_string())
                    .or_insert_with(|| Arc::new(Mutex::new(RelaySession {
                        streams: HashMap::new(),
                        authenticated: false,
                    })))
                    .clone()
            };

            {
                let mut sess = session.lock().await;
                sess.streams.insert(stream_id, RelayStream { tx, type_known: false });
            }

            // Spawn handler for this stream
            let sid = session_id.to_string();
            let opts = options.clone();
            let sink = ws_sink.clone();
            let sess = session.clone();
            tokio::spawn(async move {
                handle_relayed_stream(sid, stream_id, rx, opts, sink, sess).await;
            });
        }
        FLAG_DATA => {
            // Forward data to the stream handler
            let sessions = sessions().read().await;
            if let Some(session) = sessions.get(session_id) {
                let sess = session.lock().await;
                if let Some(stream) = sess.streams.get(&stream_id) {
                    let _ = stream.tx.send(payload.to_vec());
                }
            }
        }
        FLAG_FIN => {
            // Stream closed
            let sessions = sessions().read().await;
            if let Some(session) = sessions.get(session_id) {
                let mut sess = session.lock().await;
                sess.streams.remove(&stream_id);
            }
        }
        _ => {}
    }
}

async fn handle_relayed_stream(
    session_id: String,
    stream_id: u32,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
    options: Arc<StunRegistrationOptions>,
    ws_sink: WsSink,
    session: Arc<Mutex<RelaySession>>,
) {
    // Read first chunk to determine stream type
    let first_chunk = match rx.recv().await {
        Some(data) => data,
        None => return,
    };

    if first_chunk.is_empty() { return; }
    let stream_type_byte = first_chunk[0];
    let remaining = &first_chunk[1..];

    match stream_type_byte {
        stream_type::AUTH => {
            handle_auth(session_id, stream_id, remaining, &mut rx, options, ws_sink, session).await;
        }
        stream_type::SSH => {
            handle_ssh_relay(session_id, stream_id, remaining, &mut rx, options, ws_sink).await;
        }
        stream_type::HTTP => {
            tracing::info!("[Relay] HTTP stream (session {session_id}, stream {stream_id})");
            // TODO: implement relayed HTTP
        }
        stream_type::WEBSOCKET => {
            handle_ws_relay(session_id, stream_id, remaining, &mut rx, options, ws_sink).await;
        }
        other => {
            tracing::warn!("[Relay] Unknown stream type 0x{other:02x}");
        }
    }
}

async fn handle_auth(
    session_id: String,
    stream_id: u32,
    initial_data: &[u8],
    rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    options: Arc<StunRegistrationOptions>,
    ws_sink: WsSink,
    session: Arc<Mutex<RelaySession>>,
) {
    // Collect all auth data (token is length-prefixed: u16 + bytes)
    let mut buf = initial_data.to_vec();
    // May need more chunks if token is split
    while buf.len() < 2 {
        if let Some(data) = rx.recv().await { buf.extend(data); } else { return; }
    }
    let token_len = ((buf[0] as usize) << 8) | (buf[1] as usize);
    while buf.len() < 2 + token_len {
        if let Some(data) = rx.recv().await { buf.extend(data); } else { return; }
    }
    let token = match String::from_utf8(buf[2..2+token_len].to_vec()) {
        Ok(t) => t,
        Err(_) => {
            send_relay_response(&ws_sink, &session_id, stream_id, b"DENIED").await;
            return;
        }
    };

    // Verify JWT
    let auth_ok = if let Some(ref auth) = options.auth {
        match auth.verify_token(&token).await {
            Some(payload) => {
                let user = payload.sub.as_deref().unwrap_or("unknown");
                tracing::info!("[Relay] Auth OK: {user} (session {session_id})");
                true
            }
            None => {
                tracing::warn!("[Relay] Auth failed (session {session_id})");
                false
            }
        }
    } else {
        true
    };

    if auth_ok {
        {
            let mut sess = session.lock().await;
            sess.authenticated = true;
        }
        send_relay_response(&ws_sink, &session_id, stream_id, b"OK").await;
    } else {
        send_relay_response(&ws_sink, &session_id, stream_id, b"DENIED").await;
    }
}

async fn handle_ssh_relay(
    session_id: String,
    stream_id: u32,
    initial_data: &[u8],
    rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    options: Arc<StunRegistrationOptions>,
    ws_sink: WsSink,
) {
    // Read host and port from initial data
    let mut buf = initial_data.to_vec();
    while buf.len() < 2 {
        if let Some(data) = rx.recv().await { buf.extend(data); } else { return; }
    }
    let host_len = ((buf[0] as usize) << 8) | (buf[1] as usize);
    while buf.len() < 2 + host_len + 2 {
        if let Some(data) = rx.recv().await { buf.extend(data); } else { return; }
    }
    let host = String::from_utf8_lossy(&buf[2..2+host_len]).to_string();
    let port = ((buf[2+host_len] as u16) << 8) | (buf[2+host_len+1] as u16);

    tracing::info!("[Relay] SSH: {host}:{port} (session {session_id})");

    // Resolve backend
    let (resolved_host, resolved_port) = if let Some(backend) = options.backends.iter()
        .find(|b| b.protocol == "ssh" && b.name == host)
    {
        let url = backend.url.trim_start_matches("ssh://");
        if let Some((h, p)) = url.rsplit_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(22))
        } else {
            (url.to_string(), 22)
        }
    } else {
        (host.clone(), port)
    };

    // Connect to SSH server
    let tcp = match tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(format!("{resolved_host}:{resolved_port}")),
    ).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::error!("[Relay] SSH connect failed: {e}");
            send_relay_response(&ws_sink, &session_id, stream_id, &[0x00]).await;
            return;
        }
        Err(_) => {
            tracing::error!("[Relay] SSH connect timeout");
            send_relay_response(&ws_sink, &session_id, stream_id, &[0x00]).await;
            return;
        }
    };

    // Send success
    send_relay_response(&ws_sink, &session_id, stream_id, &[0x01]).await;
    tracing::info!("[Relay] SSH connected, bridging (session {session_id})");

    // Bridge: relay rx ↔ TCP using select loop (no spawned tasks)
    let (tcp_read, tcp_write) = tcp.into_split();
    let mut tcp_read = tokio::io::BufReader::new(tcp_read);
    let mut tcp_write = tokio::io::BufWriter::new(tcp_write);
    let mut tcp_buf = [0u8; 8192];

    loop {
        tokio::select! {
            // TCP → relay (SSH server response → browser)
            n = tcp_read.read(&mut tcp_buf) => {
                match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        send_relay_response(&ws_sink, &session_id, stream_id, &tcp_buf[..n]).await;
                    }
                }
            }
            // Relay → TCP (browser data → SSH server)
            data = rx.recv() => {
                match data {
                    Some(data) => {
                        if tcp_write.write_all(&data).await.is_err() { break; }
                        if tcp_write.flush().await.is_err() { break; }
                    }
                    None => break,
                }
            }
        }
    }

    tracing::info!("[Relay] SSH session ended (session {session_id})");
}

/// WebSocket tunnel relay — proxy to the local WebSocket endpoint (RDP, tcp-forward).
/// Protocol: [path_len:u16][path] then bidirectional bridge.
async fn handle_ws_relay(
    session_id: String,
    stream_id: u32,
    initial_data: &[u8],
    rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    options: Arc<StunRegistrationOptions>,
    ws_sink: WsSink,
) {
    // Read WS path (length-prefixed)
    let mut buf = initial_data.to_vec();
    while buf.len() < 2 {
        if let Some(data) = rx.recv().await { buf.extend(data); } else { return; }
    }
    let path_len = ((buf[0] as usize) << 8) | (buf[1] as usize);
    while buf.len() < 2 + path_len {
        if let Some(data) = rx.recv().await { buf.extend(data); } else { return; }
    }
    let path = String::from_utf8_lossy(&buf[2..2+path_len]).to_string();

    tracing::info!("[Relay] WS relay: {path} (session {session_id})");

    // Connect to local WebSocket endpoint
    let scheme = if options.use_tls { "wss" } else { "ws" };
    let ws_url = format!("{scheme}://127.0.0.1:{}{path}", options.listen_port);

    let connector = tokio_tungstenite::Connector::NativeTls(
        native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap(),
    );

    let ws_result = tokio_tungstenite::connect_async_tls_with_config(
        &ws_url, None, false, Some(connector),
    ).await;

    let (local_ws, _) = match ws_result {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("[Relay] Local WS connect failed: {e}");
            return;
        }
    };

    tracing::info!("[Relay] WS connected to local: {ws_url}");

    let (mut ws_sink_local, mut ws_stream_local) = futures_util::StreamExt::split(local_ws);

    // Bridge: relay rx → local WS, local WS → relay tx
    // Browser sends length-prefixed messages: [len:u32 BE][data]
    let mut recv_buf: Vec<u8> = Vec::new();

    loop {
        tokio::select! {
            // Relay → local WS (browser data → local server)
            // Reassemble length-prefixed messages from the QUIC stream
            data = rx.recv() => {
                match data {
                    Some(data) => {
                        recv_buf.extend_from_slice(&data);
                        // Process complete frames
                        while recv_buf.len() >= 4 {
                            let msg_len = u32::from_be_bytes([recv_buf[0], recv_buf[1], recv_buf[2], recv_buf[3]]) as usize;
                            if recv_buf.len() < 4 + msg_len { break; }
                            let msg_data = recv_buf[4..4+msg_len].to_vec();
                            recv_buf = recv_buf[4+msg_len..].to_vec();
                            use futures_util::SinkExt;
                            if ws_sink_local.send(tokio_tungstenite::tungstenite::Message::Binary(msg_data.into())).await.is_err() {
                                return;
                            }
                        }
                    }
                    None => break,
                }
            }
            // Local WS → relay (local server response → browser)
            // Prefix: 0x00 = binary, 0x01 = text (so browser can reconstruct message type)
            msg = futures_util::StreamExt::next(&mut ws_stream_local) => {
                match msg {
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(data))) => {
                        // Length-prefixed frame: [len:u32][type:u8=0x00][data]
                        let msg_len = (1 + data.len()) as u32;
                        let mut framed = Vec::with_capacity(4 + 1 + data.len());
                        framed.extend_from_slice(&msg_len.to_be_bytes());
                        framed.push(0x00);
                        framed.extend_from_slice(&data);
                        send_relay_response(&ws_sink, &session_id, stream_id, &framed).await;
                    }
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                        let msg_len = (1 + text.len()) as u32;
                        let mut framed = Vec::with_capacity(4 + 1 + text.len());
                        framed.extend_from_slice(&msg_len.to_be_bytes());
                        framed.push(0x01);
                        framed.extend_from_slice(text.as_bytes());
                        send_relay_response(&ws_sink, &session_id, stream_id, &framed).await;
                    }
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | None => break,
                    _ => {}
                }
            }
        }
    }

    tracing::info!("[Relay] WS session ended: {path} (session {session_id})");
}

/// Send a relay response frame back through the signal server WebSocket
async fn send_relay_response(ws_sink: &WsSink, session_id: &str, stream_id: u32, data: &[u8]) {
    use futures_util::SinkExt;

    let sid_bytes = session_id.as_bytes();
    let mut frame = Vec::with_capacity(3 + sid_bytes.len() + 5 + data.len());
    // Magic byte + session ID
    frame.push(0x52); // 'R'
    frame.push((sid_bytes.len() >> 8) as u8);
    frame.push(sid_bytes.len() as u8);
    frame.extend_from_slice(sid_bytes);
    // Stream frame
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.push(FLAG_DATA);
    frame.extend_from_slice(data);

    let mut sink = ws_sink.lock().await;
    let _ = sink.send(Message::Binary(frame.into())).await;
}
