// RDCleanPath session handler — port of the TypeScript original.
//
// State machine: AWAITING_REQUEST -> CONNECTING -> RELAY -> CLOSED
// Uses tokio for async TCP/TLS, and an mpsc channel to receive client messages.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use tokio_native_tls::TlsStream;

use crate::auth::tidecloak::{JwtPayload, TidecloakAuth};
use crate::config::{BackendAuth, BackendEntry};

use super::cliprdr;
use super::rdcleanpath::{
    build_error, build_response, parse_request, RDCleanPathError, RDCleanPathResponse,
    RDCLEANPATH_ERROR_GENERAL, RDCLEANPATH_ERROR_NEGOTIATION,
};

pub type SendBinaryFn = Arc<dyn Fn(Vec<u8>) + Send + Sync>;
pub type SendCloseFn = Arc<dyn Fn(u16, String) + Send + Sync>;

#[derive(Clone, Debug)]
pub enum ClipboardEvent {
    Text(String),
    Files(Vec<cliprdr::FileInfo>),
}

pub type ClipboardTx = tokio::sync::broadcast::Sender<ClipboardEvent>;

pub type UploadRx = tokio::sync::mpsc::UnboundedReceiver<Vec<cliprdr::UploadedFile>>;
pub type UploadTx = tokio::sync::mpsc::UnboundedSender<Vec<cliprdr::UploadedFile>>;

pub struct RDCleanPathSessionOptions {
    pub send_binary: SendBinaryFn,
    pub send_close: SendCloseFn,
    pub backends: Vec<BackendEntry>,
    pub auth: Arc<TidecloakAuth>,
    pub gateway_id: Option<String>,
    pub tc_client_id: Option<String>,
    pub clipboard_tx: Option<ClipboardTx>,
    pub clipboard_files: Option<Arc<dashmap::DashMap<String, (String, Vec<u8>)>>>,
    pub upload_rx: Option<UploadRx>,
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
        if let Some(ref ra) = payload.realm_access {
            tracing::info!("Realm roles: {:?}", ra.roles);
        }
        if let Some(ref ra) = payload.resource_access {
            tracing::info!("Resource access: {}", ra);
        }
        tracing::info!("tc_client_id: {:?}, destination: {}", opts.tc_client_id, req.destination);

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
    // STATE: RELAY — bidirectional forwarding with CLIPRDR interception
    // ------------------------------------------------------------------
    let (mut tls_read, mut tls_write) = tokio::io::split(tls_stream);

    // Shared CLIPRDR state
    let clip_session = Arc::new(Mutex::new(cliprdr::ClipSession::new()));

    // Channel for injecting gateway-originated PDUs into the server-bound stream
    let (inject_tx, mut inject_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Task: client -> RDP server (+ gateway injected PDUs)
    let send_close_c2s = send_close.clone();
    let clip_c2s = clip_session.clone();
    let c2s = tokio::spawn(async move {
        let mut cs_net_found = false;
        let mut mcs_patched = false;
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    let Some(mut data) = msg else { break };
                    // Scan early messages for CS_NET (MCS Connect Initial)
                    // The first messages may be CredSSP/NLA, not MCS.
                    if !cs_net_found {
                        let names = cliprdr::parse_cs_net_channel_names(&data);
                        if !names.is_empty() {
                            let has_cliprdr = names.iter().any(|n| n.eq_ignore_ascii_case("cliprdr"));
                            tracing::info!("CLIPRDR: CS_NET channels: {:?} (cliprdr={})", names, has_cliprdr);
                            let mut cs = clip_c2s.lock().await;
                            cs.channel_names = names;
                            cs_net_found = true;
                        }
                        // For eddsa: patch serverSelectedProtocol in MCS Connect Initial
                        if !mcs_patched && mcs_patch_protocol > 0 && data.len() > 100 && data[0] == 0x03 {
                            patch_mcs_selected_protocol(&mut data, mcs_patch_protocol);
                            mcs_patched = true;
                        }
                    }
                    if let Err(e) = tls_write.write_all(&data).await {
                        tracing::error!("Relay c2s write error: {e}");
                        break;
                    }
                }
                injected = inject_rx.recv() => {
                    let Some(data) = injected else { break };
                    if let Err(e) = tls_write.write_all(&data).await {
                        tracing::error!("Relay inject write error: {e}");
                        break;
                    }
                }
            }
        }
        let _ = tls_write.shutdown().await;
    });

    // Task: RDP server -> client (with CLIPRDR interception)
    let send_binary_s2c = send_binary.clone();
    let send_close_s2c = send_close.clone();
    let clip_tx = opts.clipboard_tx.clone();
    let clip_s2c = clip_session.clone();
    let inject_tx_s2c = inject_tx.clone();
    let file_store = opts.clipboard_files.clone();
    let mut upload_rx = opts.upload_rx;
    let s2c = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        let mut framer = cliprdr::TpktFramer::new();
        let mut setup_phase = true; // first few PDUs are MCS Connect

        loop {
            tokio::select! {
                // Poll for uploaded files from browser
                upload = async {
                    match upload_rx {
                        Some(ref mut rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(files) = upload {
                        let mut cs = clip_s2c.lock().await;
                        tracing::info!("CLIPRDR: Upload {} files for paste into RDP", files.len());
                        cs.upload_files = files;
                        cs.upload_active = true;

                        // Announce files to the RDP server via CB_FORMAT_LIST
                        if let Some(ch_id) = cs.channel_id {
                            let format_list = cliprdr::build_format_list_with_files(cs.upload_format_id);
                            let frame = cliprdr::wrap_cliprdr_pdu(&format_list, ch_id, cs.initiator);
                            let _ = inject_tx_s2c.send(frame);
                            tracing::info!("CLIPRDR: Sent FORMAT_LIST announcing files to server");
                        }
                    }
                }

                // Poll RDP server data
                read_result = tls_read.read(&mut buf) => {
                    match read_result {
                Ok(0) => break,
                Ok(n) => {
                    let chunk = &buf[..n];

                    // During setup, scan for SC_NET to discover CLIPRDR channel ID
                    if setup_phase {
                        let ids = cliprdr::parse_sc_net_channel_ids(chunk);
                        if !ids.is_empty() {
                            let mut cs = clip_s2c.lock().await;
                            tracing::info!("CLIPRDR: SC_NET channel IDs: {:?}, client names: {:?}", ids, cs.channel_names);
                            if cs.channel_names.is_empty() {
                                tracing::warn!("CLIPRDR: SC_NET arrived but CS_NET names not yet parsed — IronRDP may not request cliprdr");
                            }
                            if let Some(ch_id) = cliprdr::find_cliprdr_channel_id(&cs.channel_names, &ids) {
                                cs.channel_id = Some(ch_id);
                                tracing::info!("CLIPRDR: channel ID = {ch_id}");
                            }
                            setup_phase = false; // stop scanning regardless
                        }
                    }

                    // Try TPKT-based CLIPRDR interception
                    let cliprdr_channel_id = {
                        let cs = clip_s2c.lock().await;
                        cs.channel_id
                    };

                    if let Some(clip_ch) = cliprdr_channel_id {
                        framer.feed(chunk);
                        let frames = framer.drain_frames();
                        for frame in frames {
                            if let Some((ch_id, vc_total, vc_flags, vc_payload)) = cliprdr::parse_mcs_send_data(&frame) {
                                if ch_id == clip_ch {
                                    let mut cs = clip_s2c.lock().await;
                                    if let Some(complete_pdu) = cliprdr::reassemble_vc_chunk(&mut cs, ch_id, vc_total, vc_flags, &vc_payload) {
                                        handle_cliprdr_s2c(&mut cs, &complete_pdu, &clip_tx, &inject_tx_s2c, &file_store);
                                    }
                                }
                            }
                            (send_binary_s2c)(frame);
                        }
                    } else {
                        if let Some(ref tx) = clip_tx {
                            if let Some(text) = extract_clipboard_text(chunk) {
                                let _ = tx.send(ClipboardEvent::Text(text));
                            }
                        }
                        (send_binary_s2c)(chunk.to_vec());
                    }
                }
                Err(e) => {
                    tracing::error!("Relay s2c read error: {e}");
                    break;
                }
                    } // match read_result
                } // select read_result arm
            } // select!
        } // loop
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
// CLIPRDR PDU handling (server → client)
// ---------------------------------------------------------------------------

fn handle_cliprdr_s2c(
    cs: &mut cliprdr::ClipSession,
    pdu: &[u8],
    clip_tx: &Option<ClipboardTx>,
    inject_tx: &mpsc::UnboundedSender<Vec<u8>>,
    file_store: &Option<Arc<dashmap::DashMap<String, (String, Vec<u8>)>>>,
) {
    let Some(header) = cliprdr::parse_cliprdr_header(pdu) else {
        tracing::warn!("CLIPRDR: Failed to parse PDU header ({} bytes)", pdu.len());
        return;
    };

    let type_name = match header.msg_type {
        cliprdr::CB_MONITOR_READY => "CB_MONITOR_READY",
        cliprdr::CB_FORMAT_LIST => "CB_FORMAT_LIST",
        cliprdr::CB_FORMAT_LIST_RESPONSE => "CB_FORMAT_LIST_RESPONSE",
        cliprdr::CB_FORMAT_DATA_REQUEST => "CB_FORMAT_DATA_REQUEST",
        cliprdr::CB_FORMAT_DATA_RESPONSE => "CB_FORMAT_DATA_RESPONSE",
        cliprdr::CB_FILECONTENTS_REQUEST => "CB_FILECONTENTS_REQUEST",
        cliprdr::CB_FILECONTENTS_RESPONSE => "CB_FILECONTENTS_RESPONSE",
        _ => "UNKNOWN",
    };
    tracing::info!("CLIPRDR: S2C PDU: {} (0x{:04X}) flags=0x{:04X} dataLen={}", type_name, header.msg_type, header.msg_flags, header.data_len);

    match header.msg_type {
        cliprdr::CB_MONITOR_READY => {
            tracing::info!("CLIPRDR: Server sent Monitor Ready");
            // Send our own CB_FORMAT_LIST to advertise clipboard support
            if let Some(ch_id) = cs.channel_id {
                let format_list = cliprdr::build_format_list_with_text();
                let frame = cliprdr::wrap_cliprdr_pdu(&format_list, ch_id, cs.initiator);
                let _ = inject_tx.send(frame);
                tracing::info!("CLIPRDR: Sent FORMAT_LIST (CF_UNICODETEXT) to server");
            }
        }

        cliprdr::CB_FORMAT_LIST => {
            let formats = cliprdr::parse_format_list(pdu);
            tracing::info!("CLIPRDR: Format List ({} formats)", formats.len());
            for f in &formats {
                tracing::info!("CLIPRDR:   format {}: '{}'", f.id, f.name);
                if f.name == "FileGroupDescriptorW" {
                    cs.file_descriptor_format_id = Some(f.id);
                    tracing::info!("CLIPRDR: FileGroupDescriptorW format ID = {}", f.id);
                }
            }

            // Send FORMAT_LIST_RESPONSE to acknowledge (required by CLIPRDR protocol)
            if let Some(ch_id) = cs.channel_id {
                let resp = cliprdr::build_format_list_response();
                let frame = cliprdr::wrap_cliprdr_pdu(&resp, ch_id, cs.initiator);
                let _ = inject_tx.send(frame);
                tracing::info!("CLIPRDR: Sent FORMAT_LIST_RESPONSE");
            }

            // If files are offered, request the file descriptor
            if let (Some(fmt_id), Some(ch_id)) = (cs.file_descriptor_format_id, cs.channel_id) {
                let req = cliprdr::build_format_data_request(fmt_id);
                let frame = cliprdr::wrap_cliprdr_pdu(&req, ch_id, cs.initiator);
                let _ = inject_tx.send(frame);
                tracing::info!("CLIPRDR: Requested FileGroupDescriptorW (format {})", fmt_id);
            }

            // Also check for text (CF_UNICODETEXT = 13)
            let has_text = formats.iter().any(|f| f.id == cliprdr::CF_UNICODETEXT);
            if has_text {
                if let Some(ch_id) = cs.channel_id {
                    let req = cliprdr::build_format_data_request(cliprdr::CF_UNICODETEXT);
                    let frame = cliprdr::wrap_cliprdr_pdu(&req, ch_id, cs.initiator);
                    let _ = inject_tx.send(frame);
                }
            }
        }

        cliprdr::CB_FORMAT_DATA_RESPONSE => {
            if header.msg_flags != cliprdr::CB_RESPONSE_OK {
                tracing::warn!("CLIPRDR: FORMAT_DATA_RESPONSE failed (flags=0x{:04X})", header.msg_flags);
                return;
            }
            let payload = &pdu[8..];

            // Check if this is a FileGroupDescriptorW response
            // FileGroupDescriptorW starts with a count(u32LE) and each descriptor is 592 bytes
            if payload.len() >= 4 {
                let count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
                if count > 0 && payload.len() >= 4 + count * 592 {
                    let descriptors = cliprdr::parse_file_group_descriptor(payload);
                    if !descriptors.is_empty() {
                        tracing::info!("CLIPRDR: Received {} file descriptors", descriptors.len());
                        for (i, fd) in descriptors.iter().enumerate() {
                            tracing::info!("  [{}] {} ({} bytes)", i, fd.name, fd.size);
                        }
                        cs.file_descriptors = descriptors.clone();
                        cs.fetch_queue.clear();
                        cs.fetching = false;

                        // Notify browser about available files
                        if let Some(ref tx) = clip_tx {
                            let files: Vec<cliprdr::FileInfo> = descriptors.iter().enumerate().map(|(i, fd)| {
                                cliprdr::FileInfo {
                                    id: format!("{}", i),
                                    name: fd.name.clone(),
                                    size: fd.size,
                                }
                            }).collect();
                            let _ = tx.send(ClipboardEvent::Files(files));
                        }

                        // Queue file content fetches
                        for i in 0..descriptors.len() {
                            cs.fetch_queue.push(i as u32);
                        }
                        // Start fetching the first file
                        fetch_next_file(cs, inject_tx);
                        return;
                    }
                }
            }

            // Otherwise it might be a text clipboard response
            // Decode as UTF-16LE text
            if payload.len() >= 2 {
                let chars: Vec<u16> = payload
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&c| c != 0)
                    .collect();
                if !chars.is_empty() {
                    if let Ok(text) = String::from_utf16(&chars) {
                        if !text.is_empty() {
                            tracing::info!("CLIPRDR: Text clipboard ({} chars)", text.len());
                            if let Some(ref tx) = clip_tx {
                                let _ = tx.send(ClipboardEvent::Text(text));
                            }
                        }
                    }
                }
            }
        }

        cliprdr::CB_FILECONTENTS_RESPONSE => {
            if let Some((stream_id, data)) = cliprdr::parse_file_contents_response(pdu) {
                if let Some((list_index, ref mut accumulated)) = cs.pending_contents.get_mut(&stream_id) {
                    let list_idx = *list_index;
                    accumulated.extend_from_slice(&data);
                    let received = accumulated.len() as u64;
                    let expected = cs.file_descriptors.get(list_idx as usize).map(|fd| fd.size).unwrap_or(0);

                    if received >= expected || data.is_empty() {
                        // File complete
                        let file_data = cs.pending_contents.remove(&stream_id).unwrap().1;
                        let name = cs.file_descriptors.get(list_idx as usize)
                            .map(|fd| fd.name.clone())
                            .unwrap_or_else(|| format!("file_{}", list_idx));
                        let uuid = uuid::Uuid::new_v4().to_string();
                        tracing::info!("CLIPRDR: File complete: {} ({} bytes) -> {}", name, file_data.len(), uuid);
                        if let Some(ref store) = file_store {
                            store.insert(uuid.clone(), (name.clone(), file_data));
                        }

                        // Notify browser
                        if let Some(ref tx) = clip_tx {
                            let _ = tx.send(ClipboardEvent::Files(vec![cliprdr::FileInfo {
                                id: uuid,
                                name,
                                size: received,
                            }]));
                        }

                        cs.current_fetch = None;
                        cs.fetching = false;
                        fetch_next_file(cs, inject_tx);
                    } else {
                        // More chunks needed — request next range
                        if let Some(ref fetch) = cs.current_fetch.clone() {
                            let new_offset = received;
                            let remaining = expected - new_offset;
                            let chunk_size = remaining.min(CHUNK_SIZE as u64) as u32;
                            cs.current_fetch = Some(cliprdr::ChunkedFetch {
                                offset: new_offset,
                                ..fetch.clone()
                            });

                            if let Some(ch_id) = cs.channel_id {
                                let req = cliprdr::build_file_contents_request(
                                    fetch.stream_id,
                                    fetch.list_index,
                                    cliprdr::FILECONTENTS_RANGE,
                                    new_offset,
                                    chunk_size,
                                );
                                let frame = cliprdr::wrap_cliprdr_pdu(&req, ch_id, cs.initiator);
                                let _ = inject_tx.send(frame);
                                tracing::info!(
                                    "CLIPRDR: Requesting chunk at offset {} ({} bytes, {:.0}%)",
                                    new_offset, chunk_size,
                                    (new_offset as f64 / expected as f64) * 100.0
                                );
                            }
                        }
                    }
                }
            }
        }

        cliprdr::CB_FORMAT_DATA_REQUEST => {
            if !cs.upload_active || cs.upload_files.is_empty() {
                return;
            }
            if let Some(requested_fmt) = cliprdr::parse_format_data_request(pdu) {
                if requested_fmt == cs.upload_format_id {
                    // Server wants the FileGroupDescriptorW — send it
                    tracing::info!("CLIPRDR: Server requested FileGroupDescriptorW, sending {} files", cs.upload_files.len());
                    let resp = cliprdr::build_file_group_descriptor_response(&cs.upload_files);
                    if let Some(ch_id) = cs.channel_id {
                        let frame = cliprdr::wrap_cliprdr_pdu(&resp, ch_id, cs.initiator);
                        let _ = inject_tx.send(frame);
                    }
                }
            }
        }

        cliprdr::CB_FILECONTENTS_REQUEST => {
            if !cs.upload_active || cs.upload_files.is_empty() {
                return;
            }
            if let Some((stream_id, list_index, flags, offset, cb_requested)) =
                cliprdr::parse_file_contents_request(pdu)
            {
                let file = cs.upload_files.get(list_index as usize);
                let Some(file) = file else {
                    tracing::warn!("CLIPRDR: FileContentsRequest for invalid index {}", list_index);
                    return;
                };

                let ch_id = match cs.channel_id {
                    Some(id) => id,
                    None => return,
                };

                if flags & cliprdr::FILECONTENTS_SIZE != 0 {
                    // Respond with file size
                    let resp = cliprdr::build_file_contents_size_response(stream_id, file.data.len() as u64);
                    let frame = cliprdr::wrap_cliprdr_pdu(&resp, ch_id, cs.initiator);
                    let _ = inject_tx.send(frame);
                    tracing::info!("CLIPRDR: Sent file size for [{}] = {} bytes", list_index, file.data.len());
                } else if flags & cliprdr::FILECONTENTS_RANGE != 0 {
                    // Respond with file data chunk
                    let start = (offset as usize).min(file.data.len());
                    let end = (start + cb_requested as usize).min(file.data.len());
                    let chunk = &file.data[start..end];
                    let resp = cliprdr::build_file_contents_range_response(stream_id, chunk);
                    let frame = cliprdr::wrap_cliprdr_pdu(&resp, ch_id, cs.initiator);
                    let _ = inject_tx.send(frame);
                    tracing::debug!(
                        "CLIPRDR: Sent file data [{}] offset={} len={} ({:.0}%)",
                        list_index, offset, chunk.len(),
                        if file.data.is_empty() { 100.0 } else { (end as f64 / file.data.len() as f64) * 100.0 }
                    );

                    // If this was the last chunk, check if all files are done
                    if end >= file.data.len() && list_index as usize == cs.upload_files.len() - 1 {
                        tracing::info!("CLIPRDR: All upload files served to RDP server");
                    }
                }
            }
        }

        _ => {}
    }
}

const CHUNK_SIZE: usize = 64 * 1024; // 64KB per request — safe for all RDP servers

/// Start fetching the next file in the queue using chunked requests.
fn fetch_next_file(
    cs: &mut cliprdr::ClipSession,
    inject_tx: &mpsc::UnboundedSender<Vec<u8>>,
) {
    if cs.fetching || cs.fetch_queue.is_empty() {
        return;
    }
    let Some(ch_id) = cs.channel_id else { return };

    let list_index = cs.fetch_queue.remove(0);
    let size = cs.file_descriptors.get(list_index as usize).map(|fd| fd.size).unwrap_or(0);

    let stream_id = cs.next_stream_id;
    cs.next_stream_id += 1;
    cs.pending_contents.insert(stream_id, (list_index, Vec::with_capacity(size as usize)));
    cs.fetching = true;

    let first_chunk = (size as usize).min(CHUNK_SIZE).max(1) as u32;
    cs.current_fetch = Some(cliprdr::ChunkedFetch {
        stream_id,
        list_index,
        offset: 0,
        total_size: size,
    });

    let req = cliprdr::build_file_contents_request(
        stream_id,
        list_index,
        cliprdr::FILECONTENTS_RANGE,
        0,
        first_chunk,
    );
    let frame = cliprdr::wrap_cliprdr_pdu(&req, ch_id, cs.initiator);
    let _ = inject_tx.send(frame);
    tracing::info!("CLIPRDR: Fetching file [{}] ({} bytes, {} chunks)", list_index, size, (size as usize + CHUNK_SIZE - 1) / CHUNK_SIZE);
}

// ---------------------------------------------------------------------------
// Clipboard extraction (legacy pattern matching for text)
// ---------------------------------------------------------------------------

/// Scan a raw PDU buffer for CLIPRDR Format Data Response (CB_FORMAT_DATA_RESPONSE)
/// containing CF_UNICODETEXT. Returns the extracted text if found.
///
/// CLIPRDR header: msgType(u16LE) + msgFlags(u16LE) + dataLen(u32LE) + data
/// CB_FORMAT_DATA_RESPONSE = 0x0005, CB_RESPONSE_OK = 0x0001
fn extract_clipboard_text(data: &[u8]) -> Option<String> {
    // Scan for CLIPRDR signature anywhere in the buffer.
    // The CLIPRDR PDU is wrapped in TPKT/X.224/MCS/VirtualChannel layers
    // at variable offsets, so we search for the signature pattern.
    let cliprdr_header: [u8; 4] = [0x05, 0x00, 0x01, 0x00]; // msgType=5, msgFlags=1 (LE)

    for i in 0..data.len().saturating_sub(8) {
        if data[i..i + 4] == cliprdr_header {
            let remaining = &data[i + 4..];
            if remaining.len() < 4 {
                continue;
            }
            let data_len = u32::from_le_bytes([remaining[0], remaining[1], remaining[2], remaining[3]]) as usize;
            let payload = &remaining[4..];
            if payload.len() < data_len || data_len < 2 {
                continue;
            }

            // Decode UTF-16LE, strip null terminator
            let utf16_data = &payload[..data_len];
            let chars: Vec<u16> = utf16_data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&c| c != 0)
                .collect();

            if chars.is_empty() {
                continue;
            }

            match String::from_utf16(&chars) {
                Ok(text) if !text.is_empty() => {
                    tracing::info!("Clipboard text extracted ({} chars)", text.len());
                    return Some(text);
                }
                _ => continue,
            }
        }
    }
    None
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
    if let (Some(ref resource_access), Some(client_id)) = (&payload.resource_access, tc_client_id)
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
