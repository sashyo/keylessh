///! QUIC peer connection handler.
///!
///! Replaces WebRTC DataChannel-based peer handling with QUIC streams.
///! Each client connection is a single QUIC connection with multiplexed streams:
///!   - Auth stream (first): JWT token verification
///!   - HTTP streams: proxied HTTP requests/responses
///!   - WebSocket streams: RDCleanPath, tcp-forward
///!   - SSH streams: terminal sessions
///!   - VPN datagrams: IP packets (unreliable via QUIC datagrams)

use std::collections::HashMap;
use std::sync::Arc;

use quinn::{Connection, RecvStream, SendStream};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, RwLock};

use crate::auth::tidecloak::TidecloakAuth;
use crate::config::BackendEntry;
use crate::vpn::vpn_handler::{VpnSession, VpnState};

use super::transport::stream_type;

const MAX_PEERS: usize = 200;
const VPN_TUNNEL_MAGIC: u8 = 0x04;

pub struct QuicPeerHandlerOptions {
    pub listen_port: u16,
    pub use_tls: bool,
    pub gateway_id: String,
    pub send_signaling: mpsc::UnboundedSender<serde_json::Value>,
    pub backends: Vec<BackendEntry>,
    pub auth: Option<Arc<TidecloakAuth>>,
    pub vpn_state: Option<Arc<Mutex<VpnState>>>,
}

struct PeerState {
    client_id: String,
    connection: Connection,
    vpn_session: Option<VpnSession>,
}

pub struct QuicPeerHandler {
    peers: Arc<RwLock<HashMap<String, Arc<Mutex<PeerState>>>>>,
    options: Arc<QuicPeerHandlerOptions>,
}

impl QuicPeerHandler {
    pub fn new(options: QuicPeerHandlerOptions) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            options: Arc::new(options),
        }
    }

    /// Accept a new QUIC connection from a client.
    /// Called by the STUN client after hole-punching establishes a QUIC connection.
    pub async fn handle_connection(&self, conn: Connection, client_id: String) {
        // Check peer limit
        {
            let peers = self.peers.read().await;
            if peers.len() >= MAX_PEERS {
                tracing::warn!("[QUIC] Max peers reached, rejecting {client_id}");
                conn.close(1u32.into(), b"too many peers");
                return;
            }
        }

        tracing::info!("[QUIC] New connection from client: {client_id}");

        // First stream must be auth
        let (mut send, mut recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("[QUIC] Failed to accept auth stream from {client_id}: {e}");
                return;
            }
        };

        // Read stream type byte
        let mut type_buf = [0u8; 1];
        if recv.read_exact(&mut type_buf).await.is_err() {
            tracing::error!("[QUIC] Failed to read stream type from {client_id}");
            return;
        }

        if type_buf[0] != stream_type::AUTH {
            tracing::error!("[QUIC] First stream must be AUTH, got 0x{:02x}", type_buf[0]);
            conn.close(2u32.into(), b"auth required");
            return;
        }

        // Read JWT token (length-prefixed: u16 big-endian + token bytes)
        let mut len_buf = [0u8; 2];
        if recv.read_exact(&mut len_buf).await.is_err() {
            tracing::error!("[QUIC] Failed to read token length from {client_id}");
            return;
        }
        let token_len = u16::from_be_bytes(len_buf) as usize;
        if token_len == 0 || token_len > 8192 {
            tracing::error!("[QUIC] Invalid token length: {token_len}");
            conn.close(3u32.into(), b"invalid token");
            return;
        }

        let mut token_buf = vec![0u8; token_len];
        if recv.read_exact(&mut token_buf).await.is_err() {
            tracing::error!("[QUIC] Failed to read token from {client_id}");
            return;
        }

        let token = match String::from_utf8(token_buf) {
            Ok(t) => t,
            Err(_) => {
                tracing::error!("[QUIC] Invalid UTF-8 token from {client_id}");
                conn.close(3u32.into(), b"invalid token");
                return;
            }
        };

        // Verify JWT
        if let Some(ref auth) = self.options.auth {
            match auth.verify_token(&token).await {
                Some(payload) => {
                    let user = payload.sub.as_deref().unwrap_or("unknown");
                    tracing::info!("[QUIC] Authenticated: {user} (client: {client_id})");
                    // Send auth OK
                    let _ = send.write_all(b"OK").await;
                    let _ = send.finish();
                }
                None => {
                    tracing::warn!("[QUIC] Auth failed for {client_id}");
                    let _ = send.write_all(b"DENIED").await;
                    let _ = send.finish();
                    conn.close(4u32.into(), b"auth failed");
                    return;
                }
            }
        } else {
            // No auth configured — accept
            let _ = send.write_all(b"OK").await;
            let _ = send.finish();
        }

        // Store peer state
        let peer_state = Arc::new(Mutex::new(PeerState {
            client_id: client_id.clone(),
            connection: conn.clone(),
            vpn_session: None,
        }));

        {
            let mut peers = self.peers.write().await;
            peers.insert(client_id.clone(), peer_state.clone());
        }

        // Spawn stream acceptor — handles all subsequent streams
        let peers = self.peers.clone();
        let options = self.options.clone();
        let client_id_clone = client_id.clone();
        let conn_clone = conn.clone();

        // Handle bidi streams (HTTP, WebSocket, SSH)
        let bidi_task = {
            let conn = conn.clone();
            let options = options.clone();
            let peer_state = peer_state.clone();
            let client_id = client_id.clone();
            tokio::spawn(async move {
                loop {
                    match conn.accept_bi().await {
                        Ok((send, recv)) => {
                            let opts = options.clone();
                            let ps = peer_state.clone();
                            let cid = client_id.clone();
                            tokio::spawn(async move {
                                handle_bidi_stream(send, recv, opts, ps, cid).await;
                            });
                        }
                        Err(e) => {
                            tracing::info!("[QUIC] Connection closed for {client_id}: {e}");
                            break;
                        }
                    }
                }
            })
        };

        // Handle VPN datagrams (unreliable)
        let datagram_task = {
            let conn = conn.clone();
            let peer_state = peer_state.clone();
            let options = options.clone();
            let client_id = client_id.clone();
            tokio::spawn(async move {
                loop {
                    match conn.read_datagram().await {
                        Ok(data) => {
                            handle_vpn_datagram(&data, &peer_state, &options, &client_id).await;
                        }
                        Err(e) => {
                            tracing::debug!("[QUIC] Datagram read ended for {client_id}: {e}");
                            break;
                        }
                    }
                }
            })
        };

        // Wait for connection to close
        tokio::select! {
            _ = bidi_task => {}
            _ = datagram_task => {}
            _ = conn_clone.closed() => {
                tracing::info!("[QUIC] Connection {client_id_clone} closed");
            }
        }

        // Cleanup
        {
            let mut peers = peers.write().await;
            peers.remove(&client_id_clone);
        }
        tracing::info!("[QUIC] Peer {client_id_clone} removed");
    }

    pub async fn cleanup(&self) {
        let mut peers = self.peers.write().await;
        for (id, state) in peers.drain() {
            let s = state.lock().await;
            s.connection.close(0u32.into(), b"shutdown");
            tracing::info!("[QUIC] Closed peer: {id}");
        }
    }
}

/// Handle a single bidi stream — read type byte and dispatch.
async fn handle_bidi_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    options: Arc<QuicPeerHandlerOptions>,
    peer_state: Arc<Mutex<PeerState>>,
    client_id: String,
) {
    // Read stream type
    let mut type_buf = [0u8; 1];
    if recv.read_exact(&mut type_buf).await.is_err() {
        return;
    }

    match type_buf[0] {
        stream_type::HTTP => {
            handle_http_stream(send, recv, options, client_id).await;
        }
        stream_type::WEBSOCKET => {
            handle_ws_stream(send, recv, options, client_id).await;
        }
        stream_type::SSH => {
            handle_ssh_stream(send, recv, options, client_id).await;
        }
        other => {
            tracing::warn!("[QUIC] Unknown stream type 0x{other:02x} from {client_id}");
        }
    }
}

/// HTTP tunnel over QUIC stream.
/// Proxies requests to the gateway's local HTTP server (axum) via localhost.
async fn handle_http_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    options: Arc<QuicPeerHandlerOptions>,
    client_id: String,
) {
    // Read method
    let mut method_len = [0u8; 1];
    if recv.read_exact(&mut method_len).await.is_err() { return; }
    let mut method = vec![0u8; method_len[0] as usize];
    if recv.read_exact(&mut method).await.is_err() { return; }
    let method = String::from_utf8_lossy(&method).to_string();

    // Read URL
    let mut url_len = [0u8; 2];
    if recv.read_exact(&mut url_len).await.is_err() { return; }
    let url_len = u16::from_be_bytes(url_len) as usize;
    let mut url = vec![0u8; url_len];
    if recv.read_exact(&mut url).await.is_err() { return; }
    let url = String::from_utf8_lossy(&url).to_string();

    // Read headers JSON
    let mut headers_len = [0u8; 4];
    if recv.read_exact(&mut headers_len).await.is_err() { return; }
    let headers_len = u32::from_be_bytes(headers_len) as usize;
    let mut headers_json = vec![0u8; headers_len];
    if recv.read_exact(&mut headers_json).await.is_err() { return; }

    // Read body (rest of stream)
    let mut body = Vec::new();
    if let Ok(b) = recv.read_to_end(10 * 1024 * 1024).await { body = b; }

    tracing::info!("[QUIC] HTTP {method} {url} from {client_id}");

    // Proxy to the local axum HTTP server
    let scheme = if options.use_tls { "https" } else { "http" };
    let local_url = format!("{scheme}://127.0.0.1:{}{url}", options.listen_port);

    let http_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let headers_map: std::collections::HashMap<String, String> =
        serde_json::from_slice(&headers_json).unwrap_or_default();

    let mut req_builder = match method.as_str() {
        "GET" => http_client.get(&local_url),
        "POST" => http_client.post(&local_url),
        "PUT" => http_client.put(&local_url),
        "DELETE" => http_client.delete(&local_url),
        "PATCH" => http_client.patch(&local_url),
        "HEAD" => http_client.head(&local_url),
        _ => http_client.get(&local_url),
    };

    for (k, v) in &headers_map {
        req_builder = req_builder.header(k.as_str(), v.as_str());
    }
    if !body.is_empty() {
        req_builder = req_builder.body(body);
    }

    match req_builder.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let resp_headers: std::collections::HashMap<String, String> = resp.headers().iter()
                .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
                .collect();
            let resp_headers_json = serde_json::to_string(&resp_headers).unwrap_or_default();
            let resp_body = resp.bytes().await.unwrap_or_default();

            let _ = send.write_all(&status.to_be_bytes()).await;
            let _ = send.write_all(&(resp_headers_json.len() as u32).to_be_bytes()).await;
            let _ = send.write_all(resp_headers_json.as_bytes()).await;
            let _ = send.write_all(&resp_body).await;
            let _ = send.finish();
        }
        Err(e) => {
            tracing::error!("[QUIC] HTTP proxy error: {e}");
            let status = 502u16;
            let resp_headers = json!({"content-type": "application/json"}).to_string();
            let resp_body = json!({"error": format!("Proxy error: {e}")}).to_string();
            let _ = send.write_all(&status.to_be_bytes()).await;
            let _ = send.write_all(&(resp_headers.len() as u32).to_be_bytes()).await;
            let _ = send.write_all(resp_headers.as_bytes()).await;
            let _ = send.write_all(resp_body.as_bytes()).await;
            let _ = send.finish();
        }
    }
}

/// WebSocket tunnel over QUIC stream (for RDCleanPath, tcp-forward, ssh).
/// The QUIC stream acts as a bidirectional byte pipe — same as a WebSocket
/// but without the framing overhead. Data flows directly.
async fn handle_ws_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    options: Arc<QuicPeerHandlerOptions>,
    client_id: String,
) {
    // Read the WS path (length-prefixed)
    let mut path_len = [0u8; 2];
    if recv.read_exact(&mut path_len).await.is_err() { return; }
    let path_len = u16::from_be_bytes(path_len) as usize;
    let mut path = vec![0u8; path_len];
    if recv.read_exact(&mut path).await.is_err() { return; }
    let path = String::from_utf8_lossy(&path).to_string();

    tracing::info!("[QUIC] WS stream opened: {path} from {client_id}");

    // Parse query params from path (e.g., /ws/ssh?host=X&port=Y&token=Z)
    let (base_path, _query) = path.split_once('?').unwrap_or((&path, ""));

    match base_path {
        "/ws/rdcleanpath" | "/ws/tcp-forward" | "/ws/ssh" => {
            // Proxy to the local HTTP server's WebSocket endpoint
            // The local axum server handles the actual protocol logic
            let scheme = if options.use_tls { "wss" } else { "ws" };
            let ws_url = format!("{scheme}://127.0.0.1:{}{path}", options.listen_port);

            tracing::info!("[QUIC] Proxying WS to local: {ws_url}");

            let connector = tokio_tungstenite::Connector::NativeTls(
                native_tls::TlsConnector::builder()
                    .danger_accept_invalid_certs(true)
                    .build()
                    .unwrap(),
            );

            let ws_result = tokio_tungstenite::connect_async_tls_with_config(
                &ws_url, None, false, Some(connector),
            ).await;

            let (ws_stream, _) = match ws_result {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("[QUIC] Local WS connect failed: {e}");
                    let _ = send.finish();
                    return;
                }
            };

            let (mut ws_sink, mut ws_stream) = futures_util::StreamExt::split(ws_stream);

            // QUIC recv → local WS send
            let quic_to_ws = async {
                let mut buf = vec![0u8; 65536];
                loop {
                    match recv.read(&mut buf).await {
                        Ok(Some(n)) => {
                            use futures_util::SinkExt;
                            if ws_sink.send(tokio_tungstenite::tungstenite::Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            };

            // Local WS recv → QUIC send
            let ws_to_quic = async {
                use futures_util::StreamExt;
                while let Some(Ok(msg)) = ws_stream.next().await {
                    match msg {
                        tokio_tungstenite::tungstenite::Message::Binary(data) => {
                            if send.write_all(&data).await.is_err() { break; }
                        }
                        tokio_tungstenite::tungstenite::Message::Text(text) => {
                            if send.write_all(text.as_bytes()).await.is_err() { break; }
                        }
                        tokio_tungstenite::tungstenite::Message::Close(_) => break,
                        _ => {}
                    }
                }
                let _ = send.finish();
            };

            tokio::join!(quic_to_ws, ws_to_quic);
            tracing::info!("[QUIC] WS stream ended: {path}");
        }
        _ => {
            tracing::warn!("[QUIC] Unknown WS path: {base_path}");
            let _ = send.finish();
        }
    }
}

/// SSH stream — bidirectional byte relay to an SSH server.
async fn handle_ssh_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    options: Arc<QuicPeerHandlerOptions>,
    client_id: String,
) {
    // Read target: [host_len:u16][host][port:u16]
    let mut host_len = [0u8; 2];
    if recv.read_exact(&mut host_len).await.is_err() { return; }
    let host_len = u16::from_be_bytes(host_len) as usize;
    let mut host = vec![0u8; host_len];
    if recv.read_exact(&mut host).await.is_err() { return; }
    let host = String::from_utf8_lossy(&host).to_string();

    let mut port_buf = [0u8; 2];
    if recv.read_exact(&mut port_buf).await.is_err() { return; }
    let port = u16::from_be_bytes(port_buf);

    tracing::info!("[QUIC] SSH stream to {host}:{port} from {client_id}");

    // Connect to SSH server
    let addr = format!("{host}:{port}");
    let tcp_stream = match tokio::net::TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("[QUIC] SSH connect to {addr} failed: {e}");
            let _ = send.write_all(b"\x00").await; // error indicator
            let _ = send.finish();
            return;
        }
    };

    // Send success indicator
    let _ = send.write_all(b"\x01").await;

    // Bidirectional relay
    let (tcp_read, tcp_write) = tcp_stream.into_split();

    let quic_to_tcp = async {
        let mut tcp_write = tcp_write;
        let mut buf = vec![0u8; 65536];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    if tcp_write.write_all(&buf[..n]).await.is_err() { break; }
                }
                _ => break,
            }
        }
    };

    let tcp_to_quic = async {
        let mut tcp_read = tcp_read;
        let mut buf = vec![0u8; 65536];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if send.write_all(&buf[..n]).await.is_err() { break; }
                }
                Err(_) => break,
            }
        }
        let _ = send.finish();
    };

    tokio::join!(quic_to_tcp, tcp_to_quic);
    tracing::info!("[QUIC] SSH stream ended: {addr}");
}

/// Handle a VPN datagram (unreliable IP packet).
async fn handle_vpn_datagram(
    data: &[u8],
    peer_state: &Arc<Mutex<PeerState>>,
    _options: &Arc<QuicPeerHandlerOptions>,
    _client_id: &str,
) {
    if data.len() < 20 { return; }
    if (data[0] >> 4) != 4 { return; } // Drop non-IPv4

    let mut state = peer_state.lock().await;
    if let Some(ref mut vpn) = state.vpn_session {
        // Check firewall rules if present
        if !vpn.firewall.rules.is_empty() {
            let dst = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
            let ip_proto = data[9];
            let dst_port = crate::vpn::vpn_handler::extract_dst_port(data);
            if !vpn.firewall.is_allowed(dst, dst_port, ip_proto) {
                vpn.firewall.log_blocked(dst, dst_port);
                return;
            }
        }

        // Forward to TUN device
        if let Some(tx) = crate::vpn::vpn_handler::TUN_WRITE_TX.get() {
            let _ = tx.send(data.to_vec());
        }
    }
}
