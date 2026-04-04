///! WebTransport server for browser clients.
///!
///! Uses the `wtransport` crate to handle the HTTP/3 + WebTransport handshake
///! that browsers require (via `new WebTransport(url)`).
///!
///! After a session is established, the first bidi stream carries auth (JWT).
///! Subsequent streams use the same type-byte dispatch as the quinn peer handler.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex};
use wtransport::endpoint::IncomingSession;
use wtransport::{Endpoint, Identity, ServerConfig};

use crate::auth::tidecloak::TidecloakAuth;
use crate::config::BackendEntry;
use crate::vpn::vpn_handler::VpnState;

use super::transport::stream_type;

pub struct WebTransportServerOptions {
    pub port: u16,
    pub listen_port: u16,
    pub use_tls: bool,
    pub gateway_id: String,
    pub backends: Vec<BackendEntry>,
    pub auth: Option<Arc<TidecloakAuth>>,
    pub vpn_state: Option<Arc<Mutex<VpnState>>>,
}

pub struct WebTransportServer {
    options: Arc<WebTransportServerOptions>,
    cert_hash: String,
}

impl WebTransportServer {
    /// Create a new WebTransport server. Returns the server and the cert SHA-256 hash
    /// (for browser `serverCertificateHashes`).
    pub fn new(options: WebTransportServerOptions) -> Self {
        Self {
            options: Arc::new(options),
            cert_hash: String::new(),
        }
    }

    /// Start the WebTransport server. Returns the cert hash for signaling.
    /// If `socket` is provided, uses that pre-bound UDP socket (for STUN hole-punching).
    /// Otherwise binds to 0.0.0.0:{port}.
    pub async fn run(mut self, socket: Option<std::net::UdpSocket>) -> Result<String, String> {
        let identity = Identity::self_signed(["punchd-gateway", "localhost"])
            .map_err(|e| format!("Failed to generate identity: {e}"))?;

        // Get cert hash from the identity's certificate chain
        let cert_hash = identity.certificate_chain().as_slice().first()
            .map(|cert| {
                use sha2::{Sha256, Digest};
                let hash = Sha256::digest(cert.der());
                hash.iter().map(|b| format!("{b:02x}")).collect::<String>()
            })
            .ok_or("No certificate in chain")?;
        self.cert_hash = cert_hash.clone();

        let config = if let Some(sock) = socket {
            ServerConfig::builder()
                .with_bind_socket(sock)
                .with_identity(identity)
                .max_idle_timeout(Some(Duration::from_secs(30)))
                .map_err(|e| format!("Failed to build ServerConfig: {e}"))?
                .keep_alive_interval(Some(Duration::from_secs(10)))
                .build()
        } else {
            ServerConfig::builder()
                .with_bind_default(self.options.port)
                .with_identity(identity)
                .max_idle_timeout(Some(Duration::from_secs(30)))
                .map_err(|e| format!("Failed to build ServerConfig: {e}"))?
                .keep_alive_interval(Some(Duration::from_secs(10)))
                .build()
        };

        let endpoint = Endpoint::server(config)
            .map_err(|e| format!("Failed to create WebTransport endpoint: {e}"))?;

        tracing::info!("[WT] WebTransport server listening on 0.0.0.0:{} (cert: {})", self.options.port, cert_hash);

        let opts = self.options.clone();
        tokio::spawn(async move {
            loop {
                let incoming = endpoint.accept().await;
                let opts = opts.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_incoming_session(incoming, opts).await {
                        tracing::error!("[WT] Session error: {e}");
                    }
                });
            }
        });

        Ok(cert_hash)
    }
}

async fn handle_incoming_session(
    incoming: IncomingSession,
    options: Arc<WebTransportServerOptions>,
) -> Result<(), String> {
    let request = incoming.await.map_err(|e| format!("Session connect error: {e}"))?;

    tracing::info!("[WT] Incoming session from {}", request.authority());

    let connection = request.accept().await.map_err(|e| format!("Session accept error: {e}"))?;

    tracing::info!("[WT] Session established");

    // First bidi stream must be auth
    let (mut send, mut recv) = connection.accept_bi().await
        .map_err(|e| format!("Failed to accept auth stream: {e}"))?;

    // Read stream type byte
    let mut type_buf = [0u8; 1];
    recv.read_exact(&mut type_buf).await
        .map_err(|e| format!("Failed to read type byte: {e}"))?;

    if type_buf[0] != stream_type::AUTH {
        let _ = send.write_all(b"DENIED").await;
        return Err(format!("First stream must be AUTH, got 0x{:02x}", type_buf[0]));
    }

    // Read JWT token (length-prefixed: u16 big-endian + token bytes)
    let mut len_buf = [0u8; 2];
    recv.read_exact(&mut len_buf).await
        .map_err(|e| format!("Failed to read token length: {e}"))?;
    let token_len = u16::from_be_bytes(len_buf) as usize;
    if token_len == 0 || token_len > 8192 {
        return Err(format!("Invalid token length: {token_len}"));
    }

    let mut token_buf = vec![0u8; token_len];
    recv.read_exact(&mut token_buf).await
        .map_err(|e| format!("Failed to read token: {e}"))?;

    let token = String::from_utf8(token_buf)
        .map_err(|_| "Invalid UTF-8 token".to_string())?;

    // Verify JWT
    if let Some(ref auth) = options.auth {
        match auth.verify_token(&token).await {
            Some(payload) => {
                let user = payload.sub.as_deref().unwrap_or("unknown");
                tracing::info!("[WT] Authenticated: {user}");
                let _ = send.write_all(b"OK").await;
            }
            None => {
                tracing::warn!("[WT] Auth failed");
                let _ = send.write_all(b"DENIED").await;
                return Err("Auth failed".to_string());
            }
        }
    } else {
        let _ = send.write_all(b"OK").await;
    }

    // Accept subsequent streams
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let opts = options.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(send, recv, opts).await {
                        tracing::error!("[WT] Stream error: {e}");
                    }
                });
            }
            Err(e) => {
                tracing::info!("[WT] Session closed: {e}");
                break;
            }
        }
    }

    Ok(())
}

async fn handle_stream(
    mut send: wtransport::SendStream,
    mut recv: wtransport::RecvStream,
    options: Arc<WebTransportServerOptions>,
) -> Result<(), String> {
    // Read stream type byte
    let mut type_buf = [0u8; 1];
    recv.read_exact(&mut type_buf).await
        .map_err(|e| format!("Failed to read type: {e}"))?;

    match type_buf[0] {
        stream_type::SSH => {
            handle_ssh(send, recv, options).await
        }
        stream_type::HTTP => {
            handle_http(send, recv, options).await
        }
        stream_type::WEBSOCKET => {
            handle_ws(send, recv, options).await
        }
        other => {
            tracing::warn!("[WT] Unknown stream type 0x{other:02x}");
            Ok(())
        }
    }
}

/// Handle SSH stream: read host/port, connect to backend, bridge data.
async fn handle_ssh(
    mut send: wtransport::SendStream,
    mut recv: wtransport::RecvStream,
    options: Arc<WebTransportServerOptions>,
) -> Result<(), String> {
    // Read host (length-prefixed: u16 big-endian + host bytes)
    let mut host_len_buf = [0u8; 2];
    recv.read_exact(&mut host_len_buf).await
        .map_err(|e| format!("Failed to read host length: {e}"))?;
    let host_len = u16::from_be_bytes(host_len_buf) as usize;
    let mut host_buf = vec![0u8; host_len];
    recv.read_exact(&mut host_buf).await
        .map_err(|e| format!("Failed to read host: {e}"))?;
    let host = String::from_utf8_lossy(&host_buf).to_string();

    // Read port (u16 big-endian)
    let mut port_buf = [0u8; 2];
    recv.read_exact(&mut port_buf).await
        .map_err(|e| format!("Failed to read port: {e}"))?;
    let port = u16::from_be_bytes(port_buf);

    tracing::info!("[WT] SSH stream: {host}:{port}");

    // Resolve backend name to actual host:port
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

    tracing::info!("[WT] SSH connecting to {resolved_host}:{resolved_port}");

    // Connect to SSH server
    let tcp = match tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(format!("{resolved_host}:{resolved_port}")),
    ).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            tracing::error!("[WT] SSH TCP connect failed: {e}");
            let _ = send.write_all(&[0x00]).await; // error
            return Err(format!("TCP connect failed: {e}"));
        }
        Err(_) => {
            tracing::error!("[WT] SSH TCP connect timeout");
            let _ = send.write_all(&[0x00]).await;
            return Err("TCP connect timeout".to_string());
        }
    };

    // Send success byte
    let _ = send.write_all(&[0x01]).await;

    tracing::info!("[WT] SSH connected, bridging streams");

    // Bridge: WebTransport bidi stream <-> TCP stream
    let (tcp_read, tcp_write) = tcp.into_split();
    let mut tcp_read = tokio::io::BufReader::new(tcp_read);
    let mut tcp_write = tokio::io::BufWriter::new(tcp_write);

    let wt_to_tcp = async {
        let mut buf = [0u8; 8192];
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) if n > 0 => {
                    if tcp_write.write_all(&buf[..n]).await.is_err() { break; }
                    if tcp_write.flush().await.is_err() { break; }
                }
                _ => break,
            }
        }
    };

    let tcp_to_wt = async {
        let mut buf = [0u8; 8192];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if send.write_all(&buf[..n]).await.is_err() { break; }
                }
            }
        }
    };

    tokio::select! {
        _ = wt_to_tcp => {}
        _ = tcp_to_wt => {}
    }

    tracing::info!("[WT] SSH session ended for {host}");
    Ok(())
}

/// HTTP tunnel over WebTransport stream.
/// Protocol: [method_len:u8][method][url_len:u16][url][headers_len:u32][headers_json][body...]
/// Response: [status:u16][headers_len:u32][headers_json][body...]
async fn handle_http(
    mut send: wtransport::SendStream,
    mut recv: wtransport::RecvStream,
    options: Arc<WebTransportServerOptions>,
) -> Result<(), String> {
    // Read method
    let mut method_len = [0u8; 1];
    recv.read_exact(&mut method_len).await.map_err(|e| format!("method len: {e}"))?;
    let mut method = vec![0u8; method_len[0] as usize];
    recv.read_exact(&mut method).await.map_err(|e| format!("method: {e}"))?;
    let method = String::from_utf8_lossy(&method).to_string();

    // Read URL
    let mut url_len = [0u8; 2];
    recv.read_exact(&mut url_len).await.map_err(|e| format!("url len: {e}"))?;
    let url_len = u16::from_be_bytes(url_len) as usize;
    let mut url = vec![0u8; url_len];
    recv.read_exact(&mut url).await.map_err(|e| format!("url: {e}"))?;
    let url = String::from_utf8_lossy(&url).to_string();

    // Read headers JSON
    let mut headers_len = [0u8; 4];
    recv.read_exact(&mut headers_len).await.map_err(|e| format!("headers len: {e}"))?;
    let headers_len = u32::from_be_bytes(headers_len) as usize;
    let mut headers_json = vec![0u8; headers_len];
    recv.read_exact(&mut headers_json).await.map_err(|e| format!("headers: {e}"))?;

    // Read body (rest of stream)
    let mut body = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match recv.read(&mut buf).await {
            Ok(Some(n)) if n > 0 => body.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }

    tracing::info!("[WT] HTTP {method} {url}");

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
        }
        Err(e) => {
            tracing::error!("[WT] HTTP proxy error: {e}");
            let status = 502u16;
            let resp_headers = serde_json::json!({"content-type": "application/json"}).to_string();
            let resp_body = serde_json::json!({"error": format!("Proxy error: {e}")}).to_string();
            let _ = send.write_all(&status.to_be_bytes()).await;
            let _ = send.write_all(&(resp_headers.len() as u32).to_be_bytes()).await;
            let _ = send.write_all(resp_headers.as_bytes()).await;
            let _ = send.write_all(resp_body.as_bytes()).await;
        }
    }

    Ok(())
}

/// WebSocket tunnel over WebTransport stream (RDCleanPath, tcp-forward).
/// Protocol: [path_len:u16][path] then bidirectional byte bridge to local WS.
async fn handle_ws(
    mut send: wtransport::SendStream,
    mut recv: wtransport::RecvStream,
    options: Arc<WebTransportServerOptions>,
) -> Result<(), String> {
    // Read WS path (length-prefixed)
    let mut path_len = [0u8; 2];
    recv.read_exact(&mut path_len).await.map_err(|e| format!("path len: {e}"))?;
    let path_len = u16::from_be_bytes(path_len) as usize;
    let mut path = vec![0u8; path_len];
    recv.read_exact(&mut path).await.map_err(|e| format!("path: {e}"))?;
    let path = String::from_utf8_lossy(&path).to_string();

    tracing::info!("[WT] WS stream: {path}");

    let (base_path, _) = path.split_once('?').unwrap_or((&path, ""));

    match base_path {
        "/ws/rdcleanpath" | "/ws/tcp-forward" | "/ws/ssh" => {
            let scheme = if options.use_tls { "wss" } else { "ws" };
            let ws_url = format!("{scheme}://127.0.0.1:{}{path}", options.listen_port);

            tracing::info!("[WT] Proxying WS to local: {ws_url}");

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
                    tracing::error!("[WT] Local WS connect failed: {e}");
                    return Err(format!("WS connect failed: {e}"));
                }
            };

            let (mut ws_sink, mut ws_stream) = futures_util::StreamExt::split(ws_stream);

            // WebTransport recv → local WS send
            let wt_to_ws = async {
                let mut buf = vec![0u8; 65536];
                loop {
                    match recv.read(&mut buf).await {
                        Ok(Some(n)) if n > 0 => {
                            use futures_util::SinkExt;
                            if ws_sink.send(tokio_tungstenite::tungstenite::Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            };

            // Local WS recv → WebTransport send
            let ws_to_wt = async {
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
            };

            tokio::join!(wt_to_ws, ws_to_wt);
            tracing::info!("[WT] WS stream ended: {path}");
        }
        _ => {
            tracing::warn!("[WT] Unknown WS path: {base_path}");
        }
    }

    Ok(())
}
