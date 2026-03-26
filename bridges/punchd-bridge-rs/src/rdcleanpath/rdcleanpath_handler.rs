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
use crate::config::{BackendAuth, BackendEntry};

use super::rdcleanpath::{
    build_error, build_response, parse_request, RDCleanPathError, RDCleanPathResponse,
    RDCLEANPATH_ERROR_GENERAL,
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
    #[allow(dead_code)]
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
    // Verify JWT (skip for noauth backends)
    // ------------------------------------------------------------------
    let backend_peek = opts.backends.iter().find(|b| b.protocol == "rdp" && b.name == req.destination);
    let is_noauth = backend_peek.map(|b| b.no_auth).unwrap_or(false);

    let mut _rdp_username = String::new();
    if !is_noauth {
        let payload = match opts.auth.verify_token(&req.proxy_auth).await {
            Some(p) => p,
            None => {
                tracing::error!("JWT verification failed");
                send_error(&send_binary, RDCLEANPATH_ERROR_GENERAL, Some(401));
                (send_close)(4001, "Unauthorized".into());
                return Err("JWT verification failed".into());
            }
        };

        // Check dest: roles and extract RDP username if present
        // Role format: dest:<gw>:<endpoint>:<username>
        _rdp_username = match check_dest_roles(&payload, &req.destination, opts.tc_client_id.as_deref()) {
            Some(u) => u,
            None => {
                tracing::error!(
                    "Access denied: no dest:{} role for user {:?}",
                    req.destination,
                    payload.sub
                );
                send_error(&send_binary, RDCLEANPATH_ERROR_GENERAL, Some(403));
                (send_close)(4003, "Forbidden".into());
                return Err("Access denied".into());
            }
        };
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

    // For eddsa backends, patch X.224 Connection Request with RESTRICTED_ADMIN flag
    let mut x224_pdu = req.x224_connection_pdu.clone();
    let is_eddsa = backend.auth == BackendAuth::EdDSA;
    if is_eddsa {
        patch_x224_restricted_admin(&mut x224_pdu);
    }

    // Send X.224 Connection Request
    tcp_stream
        .writable()
        .await
        .map_err(|e| format!("TCP not writable: {e}"))?;

    let mut tcp_stream = tcp_stream;
    tcp_stream
        .write_all(&x224_pdu)
        .await
        .map_err(|e| format!("Failed to send X.224 request: {e}"))?;

    // Read TPKT-framed X.224 response
    let mut x224_response = read_tpkt_frame(&mut tcp_stream).await?;

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
    // CredSSP/NLA for eddsa backends
    // ------------------------------------------------------------------
    let mut mcs_patch_protocol: u32 = 0;
    if is_eddsa {
        // Pass gateway:endpoint as username so TideSSP can extract the
        // Windows username from dest:<gateway>:<endpoint>:<username> roles
        let credssp_user = match opts.gateway_id.as_deref() {
            Some(gw) => format!("{gw}:{}", req.destination),
            None => req.destination.clone(),
        };
        tracing::info!("Starting CredSSP with TideSSP/NEGOEX for \"{}\" (credssp_user=\"{}\")", req.destination, credssp_user);
        super::credssp::perform_credssp(&mut tls_stream, &req.proxy_auth, &credssp_user).await?;
        tracing::info!("CredSSP/NLA completed for \"{}\"", req.destination);

        // Read and consume 4-byte Early User Authorization Result PDU
        let mut auth_result = [0u8; 4];
        tls_stream.read_exact(&mut auth_result).await
            .map_err(|e| format!("Failed to read Early User Auth Result: {e}"))?;
        let auth_value = u32::from_le_bytes(auth_result);
        tracing::info!("Early User Auth Result: 0x{auth_value:08x}");
        if auth_value != 0 {
            return Err(format!("Early User Authorization denied: 0x{auth_value:08x}"));
        }

        // Patch X.224 response: save original selectedProtocol, set to PROTOCOL_SSL(1)
        // so IronRDP skips NLA (we already did it). We restore the real value in MCS later.
        if x224_response.len() >= 19 {
            mcs_patch_protocol = u32::from_le_bytes(x224_response[15..19].try_into().unwrap());
            tracing::info!("Original X.224 selectedProtocol={mcs_patch_protocol}");
            x224_response[15] = 0x01; // PROTOCOL_SSL
            x224_response[16] = 0x00;
            x224_response[17] = 0x00;
            x224_response[18] = 0x00;
        }
    }

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
    let _send_close_c2s = send_close.clone();
    let c2s = tokio::spawn(async move {
        let mut first_msg = true;
        let mut mcs_proto = mcs_patch_protocol;
        while let Some(mut data) = rx.recv().await {
            // For eddsa: patch serverSelectedProtocol in first MCS Connect Initial
            if first_msg && mcs_proto > 0 {
                first_msg = false;
                mcs_proto = 0;
                patch_mcs_selected_protocol(&mut data, mcs_patch_protocol);
            } else {
                first_msg = false;
            }
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

/// Check whether the JWT payload has a matching "dest:" role for the given destination.
/// Looks in both realm_access.roles and resource_access[tc_client_id].roles.
///
/// Accepted role formats:
///   - "dest:<endpoint>"                          (simple)
///   - "dest:<gateway>:<endpoint>"                (gateway-scoped)
///   - "dest:<gateway>:<endpoint>:<username>"     (with RDP username)
///
/// Returns Some(username) if a role with an explicit username is found,
/// or Some("") if access is granted but no username is embedded.
fn check_dest_roles(payload: &JwtPayload, destination: &str, tc_client_id: Option<&str>) -> Option<String> {
    let check_roles = |roles: &[String]| -> Option<String> {
        let mut granted = false;
        let mut username: Option<String> = None;
        for r in roles {
            if !r.starts_with("dest:") {
                continue;
            }
            let parts: Vec<&str> = r[5..].splitn(4, ':').collect();
            match parts.len() {
                // dest:<endpoint>
                1 if parts[0].eq_ignore_ascii_case(destination) => {
                    granted = true;
                }
                // dest:<gateway>:<endpoint>
                2 if parts[1].eq_ignore_ascii_case(destination) => {
                    granted = true;
                }
                // dest:<gateway>:<endpoint>:<username>
                3 if parts[1].eq_ignore_ascii_case(destination) => {
                    username = Some(parts[2].to_string());
                    granted = true;
                }
                _ => {}
            }
        }
        if granted {
            Some(username.unwrap_or_default())
        } else {
            None
        }
    };

    // Check realm_access.roles
    if let Some(ref ra) = payload.realm_access {
        if let Some(u) = check_roles(&ra.roles) {
            return Some(u);
        }
    }

    // Check resource_access[tc_client_id].roles
    if let (Some(resource_access), Some(client_id)) = (&payload.resource_access, tc_client_id)
    {
        if let Some(client_obj) = resource_access.get(client_id) {
            if let Some(roles) = client_obj.get("roles").and_then(|v| v.as_array()) {
                let role_strs: Vec<String> = roles
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect();
                if let Some(u) = check_roles(&role_strs) {
                    return Some(u);
                }
            }
        }
    }

    None
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
fn send_error(send_binary: &SendBinaryFn, error_code: i64, http_status: Option<i64>) {
    let pdu = build_error(&RDCleanPathError {
        error_code,
        http_status_code: http_status,
        wsa_last_error: None,
        tls_alert_code: None,
    });
    (send_binary)(pdu);
}

/// Patch X.224 Connection Request to set RESTRICTED_ADMIN_MODE_REQUIRED flag.
/// RDP_NEG_REQ is the last 8 bytes: [type=0x01][flags][length=0x08,0x00][requestedProtocols(4)]
fn patch_x224_restricted_admin(pdu: &mut [u8]) {
    if pdu.len() < 12 {
        return;
    }
    for i in (4..=pdu.len() - 8).rev() {
        if pdu[i] == 0x01 && pdu[i + 2] == 0x08 && pdu[i + 3] == 0x00 {
            let old_flags = pdu[i + 1];
            pdu[i + 1] = old_flags | 0x01; // RESTRICTED_ADMIN_MODE_REQUIRED
            tracing::info!("Set RESTRICTED_ADMIN flag in X.224 CR (offset {i}, flags: 0x{old_flags:02x} → 0x{:02x})", pdu[i + 1]);
            return;
        }
    }
    tracing::warn!("Could not find RDP_NEG_REQ in X.224 Connection Request");
}

/// Patch serverSelectedProtocol in MCS Connect Initial.
/// IronRDP wrote PROTOCOL_SSL(1) because we patched X.224; restore original value.
fn patch_mcs_selected_protocol(data: &mut [u8], target_protocol: u32) {
    if target_protocol == 0 {
        return;
    }
    // Find CS_CORE block (type 0xC001) and patch serverSelectedProtocol at offset 212
    for i in 7..data.len().saturating_sub(216) {
        if data[i] == 0x01 && data[i + 1] == 0xC0 {
            let block_len = u16::from_le_bytes([data[i + 2], data[i + 3]]) as usize;
            if block_len >= 216 && block_len < 1024 && i + block_len <= data.len() {
                let sp_offset = i + 212;
                let current = u32::from_le_bytes(data[sp_offset..sp_offset + 4].try_into().unwrap());
                if current != target_protocol {
                    data[sp_offset..sp_offset + 4].copy_from_slice(&target_protocol.to_le_bytes());
                    tracing::info!("Patched MCS serverSelectedProtocol: {current} → {target_protocol}");
                }
                return;
            }
        }
    }
    tracing::warn!("Could not find CS_CORE in MCS Connect Initial");
}
