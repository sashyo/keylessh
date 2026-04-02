///! WebRTC peer connection handler.
///!
///! Manages WebRTC DataChannel connections from browser clients.
///! When a client sends an SDP offer (via the signaling server),
///! the gateway creates a PeerConnection, establishes DataChannels,
///! and tunnels HTTP requests/responses, WebSocket frames, and TCP
///! streams over them.
///!
///! Supports dual DataChannels for high-throughput scenarios (4K video, gaming):
///!   - "http-tunnel" (control): JSON control messages, small responses
///!   - "bulk-data" (bulk): binary streaming chunks, binary WebSocket frames
///! Falls back to single-channel mode for older clients.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use bytes::Bytes;
use hmac::Mac;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex, RwLock};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::api::API;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

use crate::auth::tidecloak::TidecloakAuth;
use crate::config::BackendEntry;
use crate::vpn::vpn_handler::{VpnSession, VpnState};

const MAX_PEERS: usize = 200;
#[allow(dead_code)]
const CONTROL_MAX_BUFFER: usize = 512_000; // 512KB for control channel
#[allow(dead_code)]
const BULK_MAX_BUFFER: usize = 4_194_304; // 4MB for bulk channel
const COALESCE_TARGET: usize = 65_536; // 64KB target coalesced message size
const BINARY_WS_MAGIC: u8 = 0x02;
const TCP_TUNNEL_MAGIC: u8 = 0x03;
const VPN_TUNNEL_MAGIC: u8 = 0x04;
const MAX_TCP_PER_DC: usize = 5;
const MAX_WS_PER_DC: usize = 50;
const MAX_SINGLE_MSG: usize = 32_000; // 32KB
#[allow(dead_code)]
const DC_MAX_RANGE: usize = 5 * 1024 * 1024; // 5MB per range response
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB
const MAX_BUFFERED_RESPONSE: usize = 10 * 1024 * 1024; // 10MB safety limit

const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

const GATEWAY_FEATURES: &[&str] = &["bulk-channel", "binary-ws", "tcp-tunnel", "vpn-tunnel"];

/// Hop-by-hop headers to strip from proxied responses.
const HOP_BY_HOP: &[&str] = &[
    "transfer-encoding",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "content-encoding",
    "content-length",
];

#[allow(dead_code)]
pub struct PeerHandlerOptions {
    pub ice_servers: Vec<String>,
    pub turn_server: Option<String>,
    pub turn_secret: Option<String>,
    pub listen_port: u16,
    pub use_tls: bool,
    pub gateway_id: String,
    pub send_signaling: mpsc::UnboundedSender<serde_json::Value>,
    pub backends: Vec<BackendEntry>,
    pub auth: Option<Arc<TidecloakAuth>>,
    pub tc_client_id: Option<String>,
    pub vpn_state: Option<Arc<Mutex<VpnState>>>,
}

/// Per-WebSocket tunnel state.
struct WsTunnel {
    tx: mpsc::UnboundedSender<Vec<u8>>,
}

/// Per-TCP tunnel state.
struct TcpTunnel {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

/// Per-peer state shared between control and bulk channels.
struct PeerState {
    ws_connections: HashMap<String, WsTunnel>,
    tcp_connections: HashMap<String, TcpTunnel>,
    capabilities: HashSet<String>,
    control_dc: Option<Arc<RTCDataChannel>>,
    bulk_dc: Option<Arc<RTCDataChannel>>,
    vpn_session: Option<VpnSession>,
    /// Receives VPN packets from the TUN device destined for this peer.
    #[allow(dead_code)]
    vpn_route_rx: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
}

impl PeerState {
    fn new() -> Self {
        Self {
            ws_connections: HashMap::new(),
            tcp_connections: HashMap::new(),
            capabilities: HashSet::new(),
            control_dc: None,
            bulk_dc: None,
            vpn_session: None,
            vpn_route_rx: None,
        }
    }
}

pub struct PeerHandler {
    peers: Arc<RwLock<HashMap<String, Arc<RTCPeerConnection>>>>,
    peer_states: Arc<RwLock<HashMap<String, Arc<Mutex<PeerState>>>>>,
    options: Arc<PeerHandlerOptions>,
    api: Arc<API>,
}

impl PeerHandler {
    pub fn new(options: PeerHandlerOptions) -> Self {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs().ok();

        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media_engine)
            .expect("Failed to register interceptors");

        let setting_engine = SettingEngine::default();

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .with_setting_engine(setting_engine)
            .build();

        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            peer_states: Arc::new(RwLock::new(HashMap::new())),
            options: Arc::new(options),
            api: Arc::new(api),
        }
    }

    /// Handle an incoming SDP offer from a client.
    pub async fn handle_sdp_offer(&self, client_id: &str, sdp: &str) {
        // Clean up existing peer if reconnecting
        {
            let mut peers = self.peers.write().await;
            if let Some(existing) = peers.remove(client_id) {
                existing.close().await.ok();
            }
            self.peer_states.write().await.remove(client_id);

            // Reject if at capacity
            if peers.len() >= MAX_PEERS {
                tracing::warn!(
                    "[WebRTC] Peer limit reached ({}), rejecting {}",
                    MAX_PEERS,
                    client_id
                );
                return;
            }
        }

        tracing::info!("[WebRTC] Creating peer for client: {}", client_id);

        // Build ICE servers configuration
        let mut ice_servers = vec![];

        // Add STUN servers
        let stun_urls: Vec<String> = self
            .options
            .ice_servers
            .iter()
            .filter(|s| s.starts_with("stun:"))
            .cloned()
            .collect();
        if !stun_urls.is_empty() {
            ice_servers.push(RTCIceServer {
                urls: stun_urls,
                ..Default::default()
            });
        }

        // Add TURN server with ephemeral credentials
        if let (Some(turn_server), Some(turn_secret)) =
            (&self.options.turn_server, &self.options.turn_secret)
        {
            if !turn_secret.is_empty() {
                let expiry = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 3600;
                let user = expiry.to_string();
                let mut mac =
                    hmac::Hmac::<sha1::Sha1>::new_from_slice(turn_secret.as_bytes()).unwrap();
                mac.update(user.as_bytes());
                let pass = base64::engine::general_purpose::STANDARD
                    .encode(mac.finalize().into_bytes());

                ice_servers.push(RTCIceServer {
                    urls: vec![turn_server.clone()],
                    username: user,
                    credential: pass,
                    ..Default::default()
                });
            }
        }

        tracing::info!("[WebRTC] ICE servers: {:?}", ice_servers);

        let config = RTCConfiguration {
            ice_servers,
            ..Default::default()
        };

        let pc = match self.api.new_peer_connection(config).await {
            Ok(pc) => Arc::new(pc),
            Err(e) => {
                tracing::error!("[WebRTC] Failed to create peer connection: {}", e);
                return;
            }
        };

        let state = Arc::new(Mutex::new(PeerState::new()));

        // Store peer and state
        {
            let mut peers = self.peers.write().await;
            peers.insert(client_id.to_string(), pc.clone());
            let mut states = self.peer_states.write().await;
            states.insert(client_id.to_string(), state.clone());
        }

        // --- ICE candidate handler ---
        let send_sig = self.options.send_signaling.clone();
        let gateway_id = self.options.gateway_id.clone();
        let cid = client_id.to_string();
        pc.on_ice_candidate(Box::new(move |candidate| {
            let send_sig = send_sig.clone();
            let gateway_id = gateway_id.clone();
            let cid = cid.clone();
            Box::pin(async move {
                if let Some(c) = candidate {
                    let json_init = c.to_json().ok();
                    let candidate_str = json_init.as_ref().map(|j| j.candidate.clone()).unwrap_or_default();
                    let mid = json_init.as_ref().and_then(|j| j.sdp_mid.clone()).unwrap_or_else(|| "0".to_string());

                    // Filter out VPN TUN subnet candidates (10.66.0.x) to prevent routing loops
                    if candidate_str.contains(" 10.66.0.") {
                        tracing::debug!("[WebRTC] Skipping VPN subnet ICE candidate: {}", candidate_str);
                        return;
                    }

                    tracing::info!("[WebRTC] Local ICE candidate: {} (mid={})", candidate_str, mid);
                    let _ = send_sig.send(json!({
                        "type": "candidate",
                        "fromId": gateway_id,
                        "targetId": cid,
                        "candidate": {
                            "candidate": candidate_str,
                            "mid": mid,
                        },
                    }));
                }
            })
        }));

        // --- Peer connection state change ---
        let peers_ref = self.peers.clone();
        let states_ref = self.peer_states.clone();
        let send_sig2 = self.options.send_signaling.clone();
        let cid2 = client_id.to_string();
        pc.on_peer_connection_state_change(Box::new(move |s| {
            let peers_ref = peers_ref.clone();
            let states_ref = states_ref.clone();
            let send_sig2 = send_sig2.clone();
            let cid2 = cid2.clone();
            Box::pin(async move {
                tracing::info!("[WebRTC] Peer {} state: {:?}", cid2, s);
                match s {
                    webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Connected => {
                        let _ = send_sig2.send(json!({
                            "type": "client_status",
                            "clientId": cid2,
                            "connectionType": "p2p",
                        }));
                    }
                    webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Failed
                    | webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState::Closed => {
                        peers_ref.write().await.remove(&cid2);
                        states_ref.write().await.remove(&cid2);
                    }
                    _ => {}
                }
            })
        }));

        // --- DataChannel handler ---
        let state_for_dc = state.clone();
        let opts = self.options.clone();
        let cid3 = client_id.to_string();
        pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            let state = state_for_dc.clone();
            let opts = opts.clone();
            let cid = cid3.clone();
            Box::pin(async move {
                let label = dc.label().to_string();
                tracing::info!(
                    "[WebRTC] DataChannel opened with client: {} (label: {})",
                    cid,
                    label
                );

                match label.as_str() {
                    "http-tunnel" => {
                        setup_control_channel(dc, &cid, state, opts).await;
                    }
                    "bulk-data" => {
                        setup_bulk_channel(dc, &cid, state, opts).await;
                    }
                    _ => {
                        tracing::warn!(
                            "[WebRTC] Unknown DataChannel label: {}, treating as control",
                            label
                        );
                        setup_control_channel(dc, &cid, state, opts).await;
                    }
                }
            })
        }));

        // Set remote description (offer)
        let offer = RTCSessionDescription::offer(sdp.to_string()).unwrap();
        if let Err(e) = pc.set_remote_description(offer).await {
            tracing::error!("[WebRTC] Failed to set remote description: {}", e);
            return;
        }

        // Create answer
        let answer = match pc.create_answer(None).await {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("[WebRTC] Failed to create answer: {}", e);
                return;
            }
        };

        // Set local description
        let answer_sdp = answer.sdp.clone();
        if let Err(e) = pc.set_local_description(answer).await {
            tracing::error!("[WebRTC] Failed to set local description: {}", e);
            return;
        }

        // Send SDP answer back
        tracing::info!("[WebRTC] Sending answer to client: {}", client_id);
        let _ = self.options.send_signaling.send(json!({
            "type": "sdp_answer",
            "fromId": self.options.gateway_id,
            "targetId": client_id,
            "sdp": answer_sdp,
            "sdpType": "answer",
        }));
    }

    /// Add a remote ICE candidate.
    pub async fn handle_candidate(&self, client_id: &str, candidate: &str, mid: &str) {
        tracing::info!(
            "[WebRTC] Remote ICE candidate from {}: {}",
            client_id,
            candidate
        );
        let peers = self.peers.read().await;
        if let Some(pc) = peers.get(client_id) {
            let init = RTCIceCandidateInit {
                candidate: candidate.to_string(),
                sdp_mid: Some(mid.to_string()),
                ..Default::default()
            };
            if let Err(e) = pc.add_ice_candidate(init).await {
                tracing::error!("[WebRTC] Failed to add ICE candidate: {}", e);
            }
        }
    }

    /// Close all peer connections.
    pub async fn cleanup(&self) {
        let mut peers = self.peers.write().await;
        for (id, pc) in peers.drain() {
            tracing::info!("[WebRTC] Closing peer: {}", id);
            pc.close().await.ok();
        }
        self.peer_states.write().await.clear();
    }
}

// --- Helper: send JSON on control channel ---

async fn send_control(state: &Arc<Mutex<PeerState>>, data: serde_json::Value) {
    let s = state.lock().await;
    if let Some(dc) = &s.control_dc {
        if dc.ready_state() == webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
        {
            let bytes = Bytes::from(serde_json::to_vec(&data).unwrap());
            if let Err(e) = dc.send(&bytes).await {
                tracing::error!("[WebRTC] Failed to send on control channel: {}", e);
            }
        }
    }
}

/// Send binary data on the bulk channel (falls back to control if no bulk channel).
async fn send_bulk(state: &Arc<Mutex<PeerState>>, data: Vec<u8>) {
    let s = state.lock().await;
    let dc = if let Some(ref bulk) = s.bulk_dc {
        if bulk.ready_state()
            == webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
        {
            Some(bulk.clone())
        } else {
            s.control_dc.clone()
        }
    } else {
        s.control_dc.clone()
    };
    drop(s);

    if let Some(dc) = dc {
        if dc.ready_state() == webrtc::data_channel::data_channel_state::RTCDataChannelState::Open
        {
            let bytes = Bytes::from(data);
            if let Err(e) = dc.send(&bytes).await {
                tracing::error!("[WebRTC] Failed to send on bulk channel: {}", e);
            }
        }
    }
}

fn send_capabilities(state: &Arc<Mutex<PeerState>>) {
    let state = state.clone();
    tokio::spawn(async move {
        send_control(
            &state,
            json!({
                "type": "capabilities",
                "version": 2,
                "features": GATEWAY_FEATURES,
            }),
        )
        .await;
    });
}

async fn setup_control_channel(
    dc: Arc<RTCDataChannel>,
    client_id: &str,
    state: Arc<Mutex<PeerState>>,
    opts: Arc<PeerHandlerOptions>,
) {
    {
        let mut s = state.lock().await;
        s.control_dc = Some(dc.clone());
    }

    // Send capabilities proactively
    let state_open = state.clone();
    let cid_open = client_id.to_string();
    dc.on_open(Box::new(move || {
        tracing::info!(
            "[WebRTC] Control channel fully open for {}, sending capabilities",
            cid_open
        );
        send_capabilities(&state_open);
        Box::pin(async {})
    }));

    // If already open, send immediately
    if dc.ready_state() == webrtc::data_channel::data_channel_state::RTCDataChannelState::Open {
        tracing::info!(
            "[WebRTC] Sending proactive capabilities to {}",
            client_id
        );
        send_capabilities(&state);
    }

    // Message handler
    let state_msg = state.clone();
    let opts_msg = opts.clone();
    let cid_msg = client_id.to_string();
    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let state = state_msg.clone();
        let opts = opts_msg.clone();
        let cid = cid_msg.clone();
        Box::pin(async move {
            let data = msg.data.to_vec();
            let text = match String::from_utf8(data) {
                Ok(t) => t,
                Err(_) => return,
            };

            let parsed: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("[WebRTC] DataChannel message parse error: {}", e);
                    return;
                }
            };

            let msg_type = parsed["type"].as_str().unwrap_or("");

            match msg_type {
                "http_request" => {
                    handle_dc_http_request(state, opts, &parsed).await;
                }
                "ws_open" => {
                    handle_ws_open(state, opts, &parsed).await;
                }
                "ws_message" => {
                    let id = parsed["id"].as_str().unwrap_or("").to_string();
                    let data_str = parsed["data"].as_str().unwrap_or("");
                    let is_binary = parsed["binary"].as_bool().unwrap_or(false);

                    let s = state.lock().await;
                    if let Some(ws) = s.ws_connections.get(&id) {
                        let payload = if is_binary {
                            base64::engine::general_purpose::STANDARD
                                .decode(data_str)
                                .unwrap_or_default()
                        } else {
                            data_str.as_bytes().to_vec()
                        };
                        let _ = ws.tx.send(payload);
                    }
                }
                "ws_close" => {
                    let id = parsed["id"].as_str().unwrap_or("").to_string();
                    let mut s = state.lock().await;
                    s.ws_connections.remove(&id);
                }
                "tcp_open" => {
                    handle_tcp_open(state, opts, &parsed).await;
                }
                "tcp_close" => {
                    let id = parsed["id"].as_str().unwrap_or("").to_string();
                    let mut s = state.lock().await;
                    if let Some(tunnel) = s.tcp_connections.remove(&id) {
                        let _ = tunnel.shutdown.send(());
                        tracing::info!("[WebRTC] TCP tunnel closed: {}", id);
                    }
                }
                "vpn_open" => {
                    let vpn_id = parsed["id"].as_str().unwrap_or("").to_string();
                    let vpn_token = parsed["token"].as_str();
                    if let Some(ref vpn_state) = opts.vpn_state {
                        match crate::vpn::vpn_handler::handle_vpn_open(
                            vpn_state.clone(),
                            vpn_id.clone(),
                            vpn_token,
                            opts.auth.as_ref(),
                            &opts.gateway_id,
                        ).await {
                            Ok(mut session) => {
                                let vs = vpn_state.lock().await;
                                let response = crate::vpn::vpn_handler::vpn_opened_response(
                                    &session,
                                    vs.pool.gateway_ip,
                                    vs.pool.netmask,
                                );
                                drop(vs);

                                // Spawn task: forward TUN -> bulk channel for this peer
                                if let Some(mut route_rx) = session.route_rx.take() {
                                    let state_fwd = state.clone();
                                    tokio::spawn(async move {
                                        while let Some(frame) = route_rx.recv().await {
                                            send_bulk(&state_fwd, frame).await;
                                        }
                                        tracing::info!("[VPN] Route forwarding task ended");
                                    });
                                }

                                // Spawn task: send firewall block notifications to client
                                if let Some(mut block_rx) = session.block_rx.take() {
                                    let state_block = state.clone();
                                    tokio::spawn(async move {
                                        while let Some((dst_ip, dst_port)) = block_rx.recv().await {
                                            send_control(
                                                &state_block,
                                                json!({
                                                    "type": "vpn_blocked",
                                                    "destination": dst_ip.to_string(),
                                                    "port": dst_port,
                                                    "message": format!("Access denied to {}:{} by firewall policy", dst_ip, dst_port),
                                                }),
                                            )
                                            .await;
                                        }
                                    });
                                }

                                let mut s = state.lock().await;
                                s.vpn_session = Some(session);
                                drop(s);

                                send_control(&state, response).await;
                            }
                            Err(e) => {
                                send_control(
                                    &state,
                                    serde_json::json!({
                                        "type": "vpn_error",
                                        "id": vpn_id,
                                        "message": e,
                                    }),
                                )
                                .await;
                            }
                        }
                    } else {
                        send_control(
                            &state,
                            serde_json::json!({
                                "type": "vpn_error",
                                "id": vpn_id,
                                "message": "VPN not available on this gateway",
                            }),
                        )
                        .await;
                    }
                }
                "vpn_close" => {
                    let mut s = state.lock().await;
                    if let Some(mut vpn) = s.vpn_session.take() {
                        if let Some(shutdown) = vpn.shutdown.take() {
                            let _ = shutdown.send(());
                        }
                        tracing::info!("[WebRTC] VPN session closed: {}", vpn.id);
                    }
                }
                "capabilities" => {
                    let client_features: Vec<String> = parsed["features"]
                        .as_array()
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();

                    let mut s = state.lock().await;
                    for f in &client_features {
                        if GATEWAY_FEATURES.contains(&f.as_str()) {
                            s.capabilities.insert(f.clone());
                        }
                    }
                    let caps: Vec<String> = s.capabilities.iter().cloned().collect();
                    drop(s);

                    tracing::info!(
                        "[WebRTC] Client {} capabilities: {}",
                        cid,
                        caps.join(", ")
                    );
                    send_capabilities(&state);
                }
                _ => {
                    tracing::warn!("[WebRTC] Unknown message type: {}", msg_type);
                }
            }
        })
    }));

    // Close handler
    let state_close = state.clone();
    let cid_close = client_id.to_string();
    dc.on_close(Box::new(move || {
        let state = state_close.clone();
        tracing::info!("[WebRTC] Control channel closed with client: {}", cid_close);
        Box::pin(async move {
            let mut s = state.lock().await;
            s.ws_connections.clear();
            // Close TCP tunnels
            for (_, tunnel) in s.tcp_connections.drain() {
                let _ = tunnel.shutdown.send(());
            }
            // Close VPN session
            if let Some(mut vpn) = s.vpn_session.take() {
                if let Some(shutdown) = vpn.shutdown.take() {
                    let _ = shutdown.send(());
                }
            }
            s.control_dc = None;
        })
    }));
}

async fn setup_bulk_channel(
    dc: Arc<RTCDataChannel>,
    client_id: &str,
    state: Arc<Mutex<PeerState>>,
    _opts: Arc<PeerHandlerOptions>,
) {
    {
        let mut s = state.lock().await;
        s.bulk_dc = Some(dc.clone());
    }

    let state_msg = state.clone();
    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let state = state_msg.clone();
        Box::pin(async move {
            let buf = msg.data.to_vec();
            if buf.is_empty() {
                return;
            }

            // Binary WS fast-path: [0x02][36-byte WS UUID][payload]
            if buf[0] == BINARY_WS_MAGIC && buf.len() >= 37 {
                let ws_id = String::from_utf8_lossy(&buf[1..37]).to_string();
                let payload = buf[37..].to_vec();
                let s = state.lock().await;
                if let Some(ws) = s.ws_connections.get(&ws_id) {
                    let _ = ws.tx.send(payload);
                }
                return;
            }

            // TCP tunnel fast-path: [0x03][36-byte tunnel UUID][payload]
            if buf[0] == TCP_TUNNEL_MAGIC && buf.len() >= 37 {
                let tunnel_id = String::from_utf8_lossy(&buf[1..37]).to_string();
                let payload = buf[37..].to_vec();
                let s = state.lock().await;
                if let Some(tunnel) = s.tcp_connections.get(&tunnel_id) {
                    let _ = tunnel.tx.send(payload);
                }
                return;
            }

            // VPN tunnel fast-path: [0x04][raw IP packet]
            if buf[0] == VPN_TUNNEL_MAGIC && buf.len() > 1 {
                let payload = buf[1..].to_vec();
                tracing::debug!("[VPN] Bulk received {} bytes from client", payload.len());
                let s = state.lock().await;
                if let Some(ref vpn) = s.vpn_session {
                    let _ = vpn.tun_tx.send(payload);
                } else {
                    tracing::warn!("[VPN] Received VPN packet but no session active");
                }
                return;
            }

            // Fallback: try to parse as JSON
            if let Ok(text) = String::from_utf8(buf) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
                    if parsed["type"].as_str() == Some("ws_message") {
                        let id = parsed["id"].as_str().unwrap_or("").to_string();
                        let data_str = parsed["data"].as_str().unwrap_or("");
                        let is_binary = parsed["binary"].as_bool().unwrap_or(false);
                        let s = state.lock().await;
                        if let Some(ws) = s.ws_connections.get(&id) {
                            let payload = if is_binary {
                                base64::engine::general_purpose::STANDARD
                                    .decode(data_str)
                                    .unwrap_or_default()
                            } else {
                                data_str.as_bytes().to_vec()
                            };
                            let _ = ws.tx.send(payload);
                        }
                    }
                }
            }
        })
    }));

    let state_close = state.clone();
    let cid = client_id.to_string();
    dc.on_close(Box::new(move || {
        let state = state_close.clone();
        tracing::info!("[WebRTC] Bulk channel closed with client: {}", cid);
        Box::pin(async move {
            let mut s = state.lock().await;
            s.bulk_dc = None;
        })
    }));
}

// --- HTTP request handler over DataChannel ---

async fn handle_dc_http_request(
    state: Arc<Mutex<PeerState>>,
    opts: Arc<PeerHandlerOptions>,
    msg: &serde_json::Value,
) {
    let request_id = msg["id"].as_str().unwrap_or("").to_string();
    let method = msg["method"].as_str().unwrap_or("GET").to_string();
    let url_path = msg["url"].as_str().unwrap_or("/").to_string();
    let headers_val = msg["headers"].clone();
    let body_b64 = msg["body"].as_str().unwrap_or("").to_string();

    // Validate URL path
    if !url_path.starts_with('/') || url_path.contains('\r') || url_path.contains('\n') {
        send_control(
            &state,
            json!({
                "type": "http_response",
                "id": request_id,
                "statusCode": 400,
                "headers": {"content-type": "application/json"},
                "body": base64::engine::general_purpose::STANDARD.encode(
                    serde_json::to_vec(&json!({"error": "Invalid URL"})).unwrap()
                ),
            }),
        )
        .await;
        return;
    }

    // Validate method
    if !ALLOWED_METHODS.contains(&method.to_uppercase().as_str()) {
        send_control(
            &state,
            json!({
                "type": "http_response",
                "id": request_id,
                "statusCode": 405,
                "headers": {"content-type": "application/json"},
                "body": base64::engine::general_purpose::STANDARD.encode(
                    serde_json::to_vec(&json!({"error": "Method not allowed"})).unwrap()
                ),
            }),
        )
        .await;
        return;
    }

    // Validate body size
    if !body_b64.is_empty() && body_b64.len() > (MAX_BODY_SIZE as f64 * 1.37) as usize {
        send_control(
            &state,
            json!({
                "type": "http_response",
                "id": request_id,
                "statusCode": 413,
                "headers": {"content-type": "application/json"},
                "body": base64::engine::general_purpose::STANDARD.encode(
                    serde_json::to_vec(&json!({"error": "Request body too large"})).unwrap()
                ),
            }),
        )
        .await;
        return;
    }

    tracing::info!("[WebRTC] DC request: {} {}", method, url_path);

    // Build request to local gateway
    let scheme = if opts.use_tls { "https" } else { "http" };
    let target_url = format!("{}://127.0.0.1:{}{}", scheme, opts.listen_port, url_path);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    let reqwest_method = match method.to_uppercase().as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "PATCH" => reqwest::Method::PATCH,
        "DELETE" => reqwest::Method::DELETE,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        _ => reqwest::Method::GET,
    };

    let mut req_builder = client.request(reqwest_method, &target_url);

    // Forward headers, stripping accept-encoding and conditional headers
    if let Some(headers_obj) = headers_val.as_object() {
        for (key, val) in headers_obj {
            let lower = key.to_lowercase();
            if lower == "accept-encoding"
                || lower == "if-none-match"
                || lower == "if-modified-since"
            {
                continue;
            }
            if let Some(s) = val.as_str() {
                req_builder = req_builder.header(key.as_str(), s);
            }
        }
    }
    req_builder = req_builder.header("x-dc-request", "1");

    // Add body
    if !body_b64.is_empty() {
        if let Ok(body_bytes) = base64::engine::general_purpose::STANDARD.decode(&body_b64) {
            req_builder = req_builder.body(body_bytes);
        }
    }

    // Cap Range request size
    // (already handled in headers — we could parse and modify here but for simplicity
    // we trust the client or rely on the proxy to handle it)

    let state_clone = state.clone();
    let rid = request_id.clone();
    tokio::spawn(async move {
        match req_builder.send().await {
            Ok(response) => {
                let status = response.status().as_u16();

                // Collect response headers, stripping hop-by-hop
                let mut resp_headers = serde_json::Map::new();
                for (name, value) in response.headers().iter() {
                    let name_lower = name.as_str().to_lowercase();
                    if HOP_BY_HOP.contains(&name_lower.as_str()) {
                        continue;
                    }
                    if let Ok(v) = value.to_str() {
                        resp_headers.insert(name.as_str().to_string(), json!(v));
                    }
                }

                // Determine if streaming
                let ct = response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_lowercase();
                let content_length: usize = response
                    .headers()
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);

                let is_live = ct.contains("text/event-stream") || ct.contains("application/x-ndjson");
                let is_binary = ct.starts_with("image/")
                    || ct.starts_with("video/")
                    || ct.starts_with("audio/")
                    || ct.starts_with("font/")
                    || ct.contains("application/octet-stream")
                    || ct.contains("application/wasm")
                    || ct.contains("application/zip")
                    || ct.contains("application/pdf");
                let use_streaming =
                    is_live || content_length > MAX_SINGLE_MSG / 2 || is_binary;

                if use_streaming {
                    tracing::info!(
                        "[WebRTC] Streaming DC response: {} for {} ({} bytes, live={})",
                        status,
                        rid,
                        content_length,
                        is_live
                    );

                    // Send ack on control
                    send_control(
                        &state_clone,
                        json!({
                            "type": "http_response_ack",
                            "id": rid,
                        }),
                    )
                    .await;

                    // Send start on bulk
                    let start_msg = json!({
                        "type": "http_response_start",
                        "id": rid,
                        "statusCode": status,
                        "headers": resp_headers,
                        "streaming": true,
                        "live": is_live,
                    });
                    send_bulk(
                        &state_clone,
                        serde_json::to_vec(&start_msg).unwrap(),
                    )
                    .await;

                    // Stream body chunks
                    let stream = response;
                    let mut chunks_sent = 0u64;
                    let id_bytes = rid.as_bytes().to_vec();

                    // Read body in chunks
                    let body_bytes = stream.bytes().await.unwrap_or_default();

                    // Split into COALESCE_TARGET-sized chunks
                    let mut offset = 0;
                    while offset < body_bytes.len() {
                        let end = std::cmp::min(offset + COALESCE_TARGET, body_bytes.len());
                        let chunk = &body_bytes[offset..end];
                        let mut payload = Vec::with_capacity(id_bytes.len() + chunk.len());
                        payload.extend_from_slice(&id_bytes);
                        payload.extend_from_slice(chunk);
                        send_bulk(&state_clone, payload).await;
                        chunks_sent += 1;
                        offset = end;
                    }

                    tracing::info!(
                        "[WebRTC] Streaming complete for {}: {} chunks sent",
                        rid,
                        chunks_sent
                    );

                    // Send end marker
                    let end_msg = json!({
                        "type": "http_response_end",
                        "id": rid,
                    });
                    send_bulk(&state_clone, serde_json::to_vec(&end_msg).unwrap()).await;
                } else {
                    // Small buffered response
                    let body = response.bytes().await.unwrap_or_default();

                    if body.len() > MAX_BUFFERED_RESPONSE {
                        send_control(
                            &state_clone,
                            json!({
                                "type": "http_response",
                                "id": rid,
                                "statusCode": 502,
                                "headers": {"content-type": "application/json"},
                                "body": base64::engine::general_purpose::STANDARD.encode(
                                    br#"{"error":"Response too large"}"#
                                ),
                            }),
                        )
                        .await;
                        return;
                    }

                    let body_b64 =
                        base64::engine::general_purpose::STANDARD.encode(&body);
                    send_control(
                        &state_clone,
                        json!({
                            "type": "http_response",
                            "id": rid,
                            "statusCode": status,
                            "headers": resp_headers,
                            "body": body_b64,
                        }),
                    )
                    .await;
                }
            }
            Err(e) => {
                tracing::error!("[WebRTC] Local request failed: {}", e);
                let status = if e.is_timeout() { 504 } else { 502 };
                let error_msg = if e.is_timeout() {
                    "Gateway timeout"
                } else {
                    "Gateway internal error"
                };
                send_control(
                    &state_clone,
                    json!({
                        "type": "http_response",
                        "id": rid,
                        "statusCode": status,
                        "headers": {"content-type": "application/json"},
                        "body": base64::engine::general_purpose::STANDARD.encode(
                            serde_json::to_vec(&json!({"error": error_msg})).unwrap()
                        ),
                    }),
                )
                .await;
            }
        }
    });
}

// --- WebSocket tunnel handler ---

async fn handle_ws_open(
    state: Arc<Mutex<PeerState>>,
    opts: Arc<PeerHandlerOptions>,
    msg: &serde_json::Value,
) {
    let ws_id = msg["id"].as_str().unwrap_or("").to_string();
    let ws_path = msg["url"].as_str().unwrap_or("/").to_string();
    let protocols: Vec<String> = msg["protocols"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    {
        let s = state.lock().await;
        if s.ws_connections.len() >= MAX_WS_PER_DC {
            drop(s);
            send_control(
                &state,
                json!({
                    "type": "ws_error",
                    "id": ws_id,
                    "message": "Too many WebSocket connections",
                }),
            )
            .await;
            return;
        }
    }

    if !ws_path.starts_with('/') || ws_path.contains('\r') || ws_path.contains('\n') {
        send_control(
            &state,
            json!({
                "type": "ws_error",
                "id": ws_id,
                "message": "Invalid URL",
            }),
        )
        .await;
        return;
    }

    let protocol = if opts.use_tls { "wss" } else { "ws" };
    let ws_url = format!("{}://127.0.0.1:{}{}", protocol, opts.listen_port, ws_path);

    // Extract headers from the ws_open message (e.g., cookie for auth)
    let msg_headers = msg["headers"].as_object();

    // Build a WebSocket request from URL (adds upgrade/sec-websocket-key headers),
    // then append custom headers (auth cookies, protocols).
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = match ws_url.into_client_request() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("[WebRTC] WS request build failed: {}", e);
            send_control(
                &state,
                json!({
                    "type": "ws_error",
                    "id": ws_id,
                    "message": format!("Bad request: {}", e),
                }),
            )
            .await;
            return;
        }
    };
    if let Some(hdrs) = msg_headers {
        for (key, val) in hdrs {
            if let Some(v) = val.as_str() {
                if let (Ok(name), Ok(value)) = (
                    tokio_tungstenite::tungstenite::http::header::HeaderName::from_bytes(key.as_bytes()),
                    tokio_tungstenite::tungstenite::http::HeaderValue::from_str(v),
                ) {
                    request.headers_mut().insert(name, value);
                }
            }
        }
    }
    for p in &protocols {
        if let Ok(v) = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(p) {
            request.headers_mut().append("Sec-WebSocket-Protocol", v);
        }
    }

    tracing::info!("[WebRTC] WS tunnel opened: {} (id: {})", ws_path, ws_id);

    let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    {
        let mut s = state.lock().await;
        s.ws_connections
            .insert(ws_id.clone(), WsTunnel { tx: outgoing_tx });
    }

    let state_clone = state.clone();
    let ws_id_clone = ws_id.clone();

    tokio::spawn(async move {
        // Connect to local WebSocket with auth headers
        let connect_result = if protocol == "wss" {
            // For wss with self-signed certs, use native-tls with danger_accept_invalid_certs
            let connector = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true)
                .build()
                .ok()
                .map(tokio_tungstenite::Connector::NativeTls);
            tokio_tungstenite::connect_async_tls_with_config(
                request,
                None,
                false,
                connector,
            )
            .await
        } else {
            tokio_tungstenite::connect_async(request).await
        };

        let ws_stream = match connect_result {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::error!("[WebRTC] WS connect failed: {}", e);
                let mut s = state_clone.lock().await;
                s.ws_connections.remove(&ws_id_clone);
                drop(s);
                send_control(
                    &state_clone,
                    json!({
                        "type": "ws_error",
                        "id": ws_id_clone,
                        "message": format!("WebSocket connect failed: {}", e),
                    }),
                )
                .await;
                return;
            }
        };

        // Notify client that WS is open
        send_control(
            &state_clone,
            json!({
                "type": "ws_opened",
                "id": ws_id_clone,
                "protocol": protocols.first().unwrap_or(&String::new()),
            }),
        )
        .await;

        let (mut ws_sink, mut ws_stream_rx) = ws_stream.split();

        use futures_util::{SinkExt, StreamExt};

        // Task to forward outgoing messages (client -> backend WS)
        let _ws_id_out = ws_id_clone.clone();
        let outgoing_task = tokio::spawn(async move {
            while let Some(data) = outgoing_rx.recv().await {
                let msg = tokio_tungstenite::tungstenite::Message::Binary(data.into());
                if ws_sink.send(msg).await.is_err() {
                    break;
                }
            }
            let _ = ws_sink
                .send(tokio_tungstenite::tungstenite::Message::Close(None))
                .await;
        });

        // Task to forward incoming messages (backend WS -> client)
        let state_in = state_clone.clone();
        let ws_id_in = ws_id_clone.clone();
        while let Some(msg_result) = ws_stream_rx.next().await {
            match msg_result {
                Ok(ws_msg) => {
                    match ws_msg {
                        tokio_tungstenite::tungstenite::Message::Binary(data) => {
                            // Use binary WS fast-path if capabilities support it
                            let s = state_in.lock().await;
                            let use_fast_path = s.capabilities.contains("binary-ws")
                                && s.bulk_dc.is_some();
                            drop(s);

                            if use_fast_path {
                                let mut header = vec![0u8; 37];
                                header[0] = BINARY_WS_MAGIC;
                                header[1..37]
                                    .copy_from_slice(
                                        &format!("{:<36}", ws_id_in).as_bytes()[..36],
                                    );
                                header.extend_from_slice(&data);
                                send_bulk(&state_in, header).await;
                            } else {
                                let b64 = base64::engine::general_purpose::STANDARD
                                    .encode(&data);
                                send_control(
                                    &state_in,
                                    json!({
                                        "type": "ws_message",
                                        "id": ws_id_in,
                                        "data": b64,
                                        "binary": true,
                                    }),
                                )
                                .await;
                            }
                        }
                        tokio_tungstenite::tungstenite::Message::Text(text) => {
                            send_control(
                                &state_in,
                                json!({
                                    "type": "ws_message",
                                    "id": ws_id_in,
                                    "data": text.to_string(),
                                    "binary": false,
                                }),
                            )
                            .await;
                        }
                        tokio_tungstenite::tungstenite::Message::Close(frame) => {
                            let (code, reason) = frame
                                .map(|f| (f.code.into(), f.reason.to_string()))
                                .unwrap_or((1000u16, String::new()));
                            send_control(
                                &state_in,
                                json!({
                                    "type": "ws_close",
                                    "id": ws_id_in,
                                    "code": code,
                                    "reason": reason,
                                }),
                            )
                            .await;
                            break;
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    tracing::error!("[WebRTC] WS receive error: {}", e);
                    send_control(
                        &state_in,
                        json!({
                            "type": "ws_error",
                            "id": ws_id_in,
                            "message": format!("{}", e),
                        }),
                    )
                    .await;
                    break;
                }
            }
        }

        outgoing_task.abort();

        // Clean up
        let mut s = state_clone.lock().await;
        s.ws_connections.remove(&ws_id_clone);
    });
}

// --- TCP tunnel handler ---

async fn handle_tcp_open(
    state: Arc<Mutex<PeerState>>,
    opts: Arc<PeerHandlerOptions>,
    msg: &serde_json::Value,
) {
    let tunnel_id = msg["id"].as_str().unwrap_or("").to_string();
    let backend_name = msg["backend"].as_str().unwrap_or("").to_string();

    {
        let s = state.lock().await;
        if s.tcp_connections.len() >= MAX_TCP_PER_DC {
            drop(s);
            send_control(
                &state,
                json!({
                    "type": "tcp_error",
                    "id": tunnel_id,
                    "message": "Too many TCP tunnels",
                }),
            )
            .await;
            return;
        }
    }

    // Resolve backend name -> host:port (only rdp:// backends)
    tracing::info!(
        "[WebRTC] tcp_open request: backend=\"{}\", available=[{}]",
        backend_name,
        opts.backends
            .iter()
            .map(|b| format!("{}({})", b.name, b.protocol))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let backend = opts
        .backends
        .iter()
        .find(|b| b.name == backend_name && b.protocol == "rdp");

    let backend = match backend {
        Some(b) => b.clone(),
        None => {
            tracing::warn!(
                "[WebRTC] tcp_open rejected: no matching backend for \"{}\"",
                backend_name
            );
            send_control(
                &state,
                json!({
                    "type": "tcp_error",
                    "id": tunnel_id,
                    "message": "Unknown or disallowed backend",
                }),
            )
            .await;
            return;
        }
    };

    // Parse rdp://host:port
    let parsed_url = match url::Url::parse(&backend.url) {
        Ok(u) => u,
        Err(_) => {
            send_control(
                &state,
                json!({
                    "type": "tcp_error",
                    "id": tunnel_id,
                    "message": "Invalid backend URL",
                }),
            )
            .await;
            return;
        }
    };

    let host = parsed_url.host_str().unwrap_or("127.0.0.1").to_string();
    let port = parsed_url.port().unwrap_or(3389);

    tracing::info!(
        "[WebRTC] TCP tunnel opening: {} -> {}:{} (id: {})",
        backend_name,
        host,
        port,
        tunnel_id
    );

    let (data_tx, mut data_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    {
        let mut s = state.lock().await;
        s.tcp_connections.insert(
            tunnel_id.clone(),
            TcpTunnel {
                tx: data_tx,
                shutdown: shutdown_tx,
            },
        );
    }

    let state_clone = state.clone();
    let tid = tunnel_id.clone();

    tokio::spawn(async move {
        // Connect with timeout
        let connect_result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(format!("{}:{}", host, port)),
        )
        .await;

        let stream = match connect_result {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::error!("[WebRTC] TCP tunnel connect error ({}): {}", tid, e);
                let mut s = state_clone.lock().await;
                s.tcp_connections.remove(&tid);
                drop(s);
                send_control(
                    &state_clone,
                    json!({
                        "type": "tcp_error",
                        "id": tid,
                        "message": format!("{}", e),
                    }),
                )
                .await;
                return;
            }
            Err(_) => {
                tracing::error!(
                    "[WebRTC] TCP tunnel connect timeout ({}): {}:{}",
                    tid,
                    host,
                    port
                );
                let mut s = state_clone.lock().await;
                s.tcp_connections.remove(&tid);
                drop(s);
                send_control(
                    &state_clone,
                    json!({
                        "type": "tcp_error",
                        "id": tid,
                        "message": "Connection timed out",
                    }),
                )
                .await;
                return;
            }
        };

        tracing::info!("[WebRTC] TCP tunnel connected: {} -> {}:{}", tid, host, port);
        send_control(
            &state_clone,
            json!({
                "type": "tcp_opened",
                "id": tid,
            }),
        )
        .await;

        let (mut read_half, mut write_half) = stream.into_split();

        // Task: write data from client to TCP socket
        let _tid_write = tid.clone();
        let write_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    data = data_rx.recv() => {
                        match data {
                            Some(bytes) => {
                                if write_half.write_all(&bytes).await.is_err() {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }
            let _ = write_half.shutdown().await;
        });

        // Task: read data from TCP socket and send to client via bulk channel
        let state_read = state_clone.clone();
        let tid_read = tid.clone();
        let mut buf = vec![0u8; 65536];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    let mut header = vec![0u8; 37];
                    header[0] = TCP_TUNNEL_MAGIC;
                    let id_bytes = format!("{:<36}", tid_read);
                    header[1..37].copy_from_slice(&id_bytes.as_bytes()[..36]);
                    header.extend_from_slice(&buf[..n]);
                    send_bulk(&state_read, header).await;
                }
                Err(e) => {
                    tracing::error!("[WebRTC] TCP tunnel read error ({}): {}", tid_read, e);
                    break;
                }
            }
        }

        write_task.abort();

        // Clean up and notify
        {
            let mut s = state_clone.lock().await;
            s.tcp_connections.remove(&tid);
        }
        send_control(
            &state_clone,
            json!({
                "type": "tcp_close",
                "id": tid,
            }),
        )
        .await;
    });
}
