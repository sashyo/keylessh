// RDCleanPath session handler — port of the TypeScript original.
//
// State machine: AWAITING_REQUEST -> CONNECTING -> RELAY -> CLOSED
// Uses tokio for async TCP/TLS, and an mpsc channel to receive client messages.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_native_tls::TlsStream;

use crate::auth::tidecloak::{JwtPayload, TidecloakAuth};
use crate::config::BackendEntry;

use super::rdcleanpath::{
    build_error, build_response, parse_request, RDCleanPathError, RDCleanPathResponse,
    RDCLEANPATH_ERROR_GENERAL, RDCLEANPATH_ERROR_NEGOTIATION,
};

pub type SendBinaryFn = Arc<dyn Fn(Vec<u8>) + Send + Sync>;
pub type SendCloseFn = Arc<dyn Fn(u16, String) + Send + Sync>;

pub struct RDCleanPathSessionOptions {
    pub send_binary: SendBinaryFn,
    pub send_close: SendCloseFn,
    pub backends: Vec<BackendEntry>,
    pub auth: Arc<TidecloakAuth>,
    pub gateway_id: Option<String>,
    pub tc_client_id: Option<String>,
}

pub struct RDCleanPathSession {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl RDCleanPathSession {
    pub fn new(opts: RDCleanPathSessionOptions) -> Self {
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();

        tokio::spawn(async move {
            if let Err(e) = run_session(opts, rx).await {
                tracing::error!("RDCleanPath session error: {e}");
            }
        });

        Self { tx }
    }

    /// Feed a binary message from the WebSocket client into the session.
    pub fn handle_message(&self, data: Vec<u8>) {
        let _ = self.tx.send(data);
    }

    /// Signal that the client connection has closed.
    pub fn close(&self) {
        // Dropping the sender (or just letting it go out of scope) will cause
        // the receiver side to observe a closed channel.
    }
}

// ---------------------------------------------------------------------------
// Internal session driver
// ---------------------------------------------------------------------------

async fn run_session(
    opts: RDCleanPathSessionOptions,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<(), String> {
    let send_binary = opts.send_binary.clone();
    let send_close = opts.send_close.clone();

    // ------------------------------------------------------------------
    // STATE: AWAITING_REQUEST — wait for the first message
    // ------------------------------------------------------------------
    let first_msg = rx
        .recv()
        .await
        .ok_or_else(|| "channel closed before first message".to_string())?;

    let req = match parse_request(&first_msg) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to parse RDCleanPath request: {e}");
            send_error(&send_binary, RDCLEANPATH_ERROR_GENERAL, None);
            (send_close)(4002, "Invalid RDCleanPath request".into());
            return Err(e);
        }
    };

    tracing::info!(
        "RDCleanPath request: dest={} version={}",
        req.destination,
        req.version
    );

    // ------------------------------------------------------------------
    // Verify JWT
    // ------------------------------------------------------------------
    let payload = match opts.auth.verify_token(&req.proxy_auth).await {
        Some(p) => p,
        None => {
            tracing::error!("JWT verification failed");
            send_error(&send_binary, RDCLEANPATH_ERROR_GENERAL, Some(401));
            (send_close)(4001, "Unauthorized".into());
            return Err("JWT verification failed".into());
        }
    };

    // ------------------------------------------------------------------
    // Check dest: roles
    // ------------------------------------------------------------------
    if !check_dest_roles(&payload, &req.destination, opts.tc_client_id.as_deref()) {
        tracing::error!(
            "Access denied: no dest:{} role for user {:?}",
            req.destination,
            payload.sub
        );
        send_error(&send_binary, RDCLEANPATH_ERROR_GENERAL, Some(403));
        (send_close)(4003, "Forbidden".into());
        return Err("Access denied".into());
    }

    // ------------------------------------------------------------------
    // Resolve backend
    // ------------------------------------------------------------------
    let backend = match find_rdp_backend(&opts.backends, &req.destination) {
        Some(b) => b,
        None => {
            tracing::error!("No RDP backend found for {}", req.destination);
            send_error(&send_binary, RDCLEANPATH_ERROR_GENERAL, Some(404));
            (send_close)(4004, "Backend not found".into());
            return Err("Backend not found".into());
        }
    };

    let (host, port) = parse_rdp_url(&backend.url)?;
    tracing::info!("Connecting to RDP backend {host}:{port}");

    // ------------------------------------------------------------------
    // STATE: CONNECTING — TCP connect with 10s timeout
    // ------------------------------------------------------------------
    let addr = format!("{host}:{port}");
    let tcp_stream = timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("TCP connect to {addr} timed out"))?
        .map_err(|e| format!("TCP connect to {addr} failed: {e}"))?;

    // Send X.224 Connection Request
    tcp_stream
        .writable()
        .await
        .map_err(|e| format!("TCP not writable: {e}"))?;

    let mut tcp_stream = tcp_stream;
    tcp_stream
        .write_all(&req.x224_connection_pdu)
        .await
        .map_err(|e| format!("Failed to send X.224 request: {e}"))?;

    // Read TPKT-framed X.224 response
    let x224_response = read_tpkt_frame(&mut tcp_stream).await?;

    // ------------------------------------------------------------------
    // TLS upgrade (accept invalid / self-signed certs, typical for RDP)
    // ------------------------------------------------------------------
    let tls_connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .map_err(|e| format!("TLS connector build error: {e}"))?;

    let tls_connector = tokio_native_tls::TlsConnector::from(tls_connector);

    let mut tls_stream = tls_connector
        .connect(&host, tcp_stream)
        .await
        .map_err(|e| format!("TLS handshake failed: {e}"))?;

    // ------------------------------------------------------------------
    // Extract server certificate (DER bytes)
    // ------------------------------------------------------------------
    let cert_chain = extract_peer_cert_chain(&tls_stream);

    // ------------------------------------------------------------------
    // Send RDCleanPath Response PDU
    // ------------------------------------------------------------------
    let response_pdu = build_response(&RDCleanPathResponse {
        x224_connection_pdu: x224_response,
        server_cert_chain: cert_chain,
        server_addr: addr.clone(),
    });
    (send_binary)(response_pdu);

    tracing::info!("RDCleanPath connected to {addr}, entering relay mode");

    // ------------------------------------------------------------------
    // STATE: RELAY — bidirectional forwarding
    // ------------------------------------------------------------------
    let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);

    // Task: client -> RDP server
    let send_close_c2s = send_close.clone();
    let c2s = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if let Err(e) = tls_write.write_all(&data).await {
                tracing::error!("Relay c2s write error: {e}");
                break;
            }
        }
        let _ = tls_write.shutdown().await;
    });

    // Task: RDP server -> client
    let send_binary_s2c = send_binary.clone();
    let send_close_s2c = send_close.clone();
    let s2c = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match tls_read.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    (send_binary_s2c)(buf[..n].to_vec());
                }
                Err(e) => {
                    tracing::error!("Relay s2c read error: {e}");
                    break;
                }
            }
        }
        (send_close_s2c)(1000, "RDP session ended".into());
    });

    // Wait for either direction to finish
    tokio::select! {
        _ = c2s => {},
        _ = s2c => {},
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a TPKT frame: 4-byte header [0x03, 0x00, len_hi, len_lo] + payload.
async fn read_tpkt_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| format!("Failed to read TPKT header: {e}"))?;

    if header[0] != 0x03 || header[1] != 0x00 {
        return Err(format!(
            "Invalid TPKT header: [{:#04x}, {:#04x}]",
            header[0], header[1]
        ));
    }

    let total_len = ((header[2] as usize) << 8) | (header[3] as usize);
    if total_len < 4 {
        return Err(format!("Invalid TPKT length: {total_len}"));
    }

    let payload_len = total_len - 4;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|e| format!("Failed to read TPKT payload: {e}"))?;
    }

    // Return the full frame (header + payload)
    let mut frame = Vec::with_capacity(total_len);
    frame.extend_from_slice(&header);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Extract the peer certificate chain from a TLS stream.
/// With native-tls, we can only get the peer certificate (not the full chain),
/// so we return a Vec with at most one entry containing the DER bytes.
fn extract_peer_cert_chain(tls_stream: &TlsStream<TcpStream>) -> Vec<Vec<u8>> {
    let inner = tls_stream.get_ref();
    match inner.peer_certificate() {
        Ok(Some(cert)) => vec![cert.to_der().unwrap_or_default()],
        _ => vec![],
    }
}

/// Check whether the JWT payload has a "dest:<destination>" role.
/// Looks in both realm_access.roles and resource_access[tc_client_id].roles.
fn check_dest_roles(payload: &JwtPayload, destination: &str, tc_client_id: Option<&str>) -> bool {
    // Accept both "dest:<name>" and "dest:<gateway>:<name>" role formats
    let required_simple = format!("dest:{destination}");

    let check_roles = |roles: &[String]| -> bool {
        roles.iter().any(|r| {
            r == &required_simple
                || (r.starts_with("dest:") && r.ends_with(&format!(":{destination}")))
        })
    };

    // Check realm_access.roles
    if let Some(ref ra) = payload.realm_access {
        if check_roles(&ra.roles) {
            return true;
        }
    }

    // Check resource_access[tc_client_id].roles
    if let (Some(ref resource_access), Some(client_id)) = (&payload.resource_access, tc_client_id)
    {
        if let Some(client_obj) = resource_access.get(client_id) {
            if let Some(roles) = client_obj.get("roles").and_then(|v| v.as_array()) {
                let role_strs: Vec<String> = roles
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                if check_roles(&role_strs) {
                    return true;
                }
            }
        }
    }

    false
}

/// Find an RDP backend matching the given destination name.
fn find_rdp_backend<'a>(backends: &'a [BackendEntry], destination: &str) -> Option<&'a BackendEntry> {
    backends
        .iter()
        .find(|b| b.protocol == "rdp" && b.name == destination)
}

/// Parse an rdp://host:port URL.
fn parse_rdp_url(url: &str) -> Result<(String, u16), String> {
    let stripped = url
        .strip_prefix("rdp://")
        .ok_or_else(|| format!("Invalid RDP URL (expected rdp://): {url}"))?;

    if let Some((host, port_str)) = stripped.rsplit_once(':') {
        let port: u16 = port_str
            .parse()
            .map_err(|_| format!("Invalid port in RDP URL: {url}"))?;
        Ok((host.to_string(), port))
    } else {
        // Default RDP port
        Ok((stripped.to_string(), 3389))
    }
}

/// Send an RDCleanPath error PDU to the client.
fn send_error(send_binary: &SendBinaryFn, error_code: u64, http_status: Option<u64>) {
    let pdu = build_error(&RDCleanPathError {
        error_code,
        http_status_code: http_status,
        wsa_last_error: None,
        tls_alert_code: None,
    });
    (send_binary)(pdu);
}
