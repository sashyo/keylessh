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
    pub async fn run(mut self) -> Result<String, String> {
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

        let config = ServerConfig::builder()
            .with_bind_default(self.options.port)
            .with_identity(identity)
            .max_idle_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| format!("Failed to build ServerConfig: {e}"))?
            .keep_alive_interval(Some(Duration::from_secs(10)))
            .build();

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
            tracing::info!("[WT] HTTP stream (not yet implemented over WebTransport)");
            Ok(())
        }
        stream_type::WEBSOCKET => {
            tracing::info!("[WT] WS stream (not yet implemented over WebTransport)");
            Ok(())
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
