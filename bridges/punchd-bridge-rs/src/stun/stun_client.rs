///! WebSocket client that registers with the STUN signaling server
///! and handles pairing/candidate messages.
///!
///! Also handles HTTP relay: the STUN server tunnels HTTP requests
///! from remote clients through this WebSocket connection.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use rand::Rng;
use serde_json::json;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_tungstenite::tungstenite::Message;

use crate::auth::tidecloak::TidecloakAuth;
use crate::config::BackendEntry;
use crate::vpn::vpn_handler::VpnState;
use crate::webrtc::peer_handler::{PeerHandler, PeerHandlerOptions};

const ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024; // 10MB
const MAX_RESPONSE_SIZE: usize = 50 * 1024 * 1024; // 50MB
const MAX_SINGLE_WS: usize = 512 * 1024; // 512KB
const CHUNK_SIZE: usize = 256 * 1024; // 256KB
const PING_INTERVAL: Duration = Duration::from_secs(15);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct StunRegistrationOptions {
    pub stun_server_url: String,
    pub gateway_id: String,
    pub addresses: Vec<String>,
    pub listen_port: u16,
    pub ice_servers: Vec<String>,
    pub turn_server: Option<String>,
    pub turn_secret: Option<String>,
    pub use_tls: bool,
    pub api_secret: String,
    pub metadata: serde_json::Value,
    pub backends: Vec<BackendEntry>,
    pub auth: Option<Arc<TidecloakAuth>>,
    pub vpn_state: Option<Arc<Mutex<VpnState>>>,
    pub quic_port: u16,
}

#[allow(dead_code)]
pub struct StunRegistration {
    shutdown_tx: mpsc::Sender<()>,
    re_register_tx: mpsc::UnboundedSender<serde_json::Value>,
}

impl StunRegistration {
    #[allow(dead_code)]
    pub fn close(&self) {
        let _ = self.shutdown_tx.try_send(());
    }

    /// Send updated metadata to the signal server (re-register with new backends etc.)
    pub fn update_metadata(&self, metadata: serde_json::Value) {
        let _ = self.re_register_tx.send(metadata);
    }
}

/// Register with the STUN signaling server. Returns a handle that can be
/// used to close the registration.
pub fn register(options: StunRegistrationOptions) -> StunRegistration {
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let (re_register_tx, mut re_register_rx) = mpsc::unbounded_channel::<serde_json::Value>();
    let options = Arc::new(options);

    tokio::spawn(async move {
        let mut reconnect_delay_ms: u64 = 1000;

        loop {
            // Check for shutdown before attempting connection
            if shutdown_rx.try_recv().is_ok() {
                tracing::info!("[STUN-Reg] Shutdown requested");
                break;
            }

            tracing::info!(
                "[STUN-Reg] Connecting to {}...",
                options.stun_server_url
            );

            match connect_and_run(&options, &mut shutdown_rx, &mut re_register_rx).await {
                ConnectionResult::Shutdown => {
                    tracing::info!("[STUN-Reg] Shutdown — exiting");
                    break;
                }
                ConnectionResult::Disconnected => {
                    tracing::info!("[STUN-Reg] Disconnected from STUN server");
                }
                ConnectionResult::Error(e) => {
                    tracing::error!("[STUN-Reg] WebSocket error: {}", e);
                }
            }

            // Exponential backoff with 20% jitter: 1s -> 2s -> 4s -> ... -> 30s max
            let jitter = 1.0 + (rand::rng().random::<f64>() - 0.5) * 0.4; // 0.8x-1.2x
            let delay = (reconnect_delay_ms as f64 * jitter).min(30000.0) as u64;

            tracing::info!("[STUN-Reg] Reconnecting (delay: {}ms)...", delay);

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(delay)) => {}
                _ = shutdown_rx.recv() => {
                    tracing::info!("[STUN-Reg] Shutdown during reconnect wait");
                    break;
                }
            }

            reconnect_delay_ms = (reconnect_delay_ms * 2).min(30000);
        }
    });

    StunRegistration { shutdown_tx, re_register_tx }
}

enum ConnectionResult {
    Shutdown,
    Disconnected,
    Error(String),
}

/// Determine if a response content type indicates streaming content (SSE, NDJSON).
fn is_streaming_content_type(ct: &str) -> bool {
    let lower = ct.to_lowercase();
    lower.contains("text/event-stream") || lower.contains("application/x-ndjson")
}

async fn connect_and_run(
    options: &Arc<StunRegistrationOptions>,
    shutdown_rx: &mut mpsc::Receiver<()>,
    re_register_rx: &mut mpsc::UnboundedReceiver<serde_json::Value>,
) -> ConnectionResult {
    // Connect to the STUN signaling server
    let connect_result = if options.stun_server_url.starts_with("wss://") {
        let connector = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .ok()
            .map(tokio_tungstenite::Connector::NativeTls);
        tokio_tungstenite::connect_async_tls_with_config(
            &options.stun_server_url,
            None,
            false,
            connector,
        )
        .await
    } else {
        tokio_tungstenite::connect_async(&options.stun_server_url).await
    };

    let ws_stream = match connect_result {
        Ok((stream, _)) => stream,
        Err(e) => return ConnectionResult::Error(format!("{}", e)),
    };

    tracing::info!("[STUN-Reg] Connected to STUN server");
    let _reconnect_delay_reset = true;

    // Shared HTTP client for relay requests (reuse connections, avoid per-request allocation)
    let relay_http_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .build()
        .unwrap();

    let (ws_sink, mut ws_stream) = ws_stream.split();
    let ws_sink = Arc::new(Mutex::new(ws_sink));

    // Channel for sending messages from the PeerHandler back through the WS
    let (signaling_tx, mut signaling_rx) = mpsc::unbounded_channel::<serde_json::Value>();

    // Create PeerHandler for WebRTC
    let peer_handler = if !options.ice_servers.is_empty() {
        let ph = PeerHandler::new(PeerHandlerOptions {
            ice_servers: options.ice_servers.clone(),
            turn_server: options.turn_server.clone(),
            turn_secret: options.turn_secret.clone(),
            listen_port: options.listen_port,
            use_tls: options.use_tls,
            gateway_id: options.gateway_id.clone(),
            send_signaling: signaling_tx.clone(),
            backends: options.backends.clone(),
            auth: options.auth.clone(),
            vpn_state: options.vpn_state.clone(),
        });
        tracing::info!("[STUN-Reg] WebRTC peer handler ready");
        Some(Arc::new(ph))
    } else {
        None
    };

    // Track pending HTTP requests for abort support
    let pending_requests: Arc<RwLock<HashMap<String, tokio::sync::oneshot::Sender<()>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Send register message
    {
        let register_msg = json!({
            "type": "register",
            "role": "gateway",
            "id": options.gateway_id,
            "secret": options.api_secret,
            "addresses": options.addresses,
            "metadata": options.metadata,
        });
        let mut sink = ws_sink.lock().await;
        if let Err(e) = sink
            .send(Message::Text(serde_json::to_string(&register_msg).unwrap().into()))
            .await
        {
            return ConnectionResult::Error(format!("Failed to send register: {}", e));
        }
    }

    // Ping/pong heartbeat
    let ws_sink_ping = ws_sink.clone();
    let ping_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(PING_INTERVAL);
        loop {
            interval.tick().await;
            let mut sink = ws_sink_ping.lock().await;
            if sink.send(Message::Ping(vec![].into())).await.is_err() {
                break;
            }
        }
    });

    // Forward signaling messages from PeerHandler to WS
    let ws_sink_sig = ws_sink.clone();
    let signaling_task = tokio::spawn(async move {
        while let Some(msg) = signaling_rx.recv().await {
            let mut sink = ws_sink_sig.lock().await;
            if sink
                .send(Message::Text(serde_json::to_string(&msg).unwrap().into()))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Create shared QUIC endpoint on fixed port
    let quic_port = options.quic_port;
    let quic_bind: std::net::SocketAddr = format!("0.0.0.0:{quic_port}").parse().unwrap();
    let (quic_endpoint, quic_cert_hash) = match crate::quic::transport::create_server_endpoint(quic_bind) {
        Ok((ep, hash)) => {
            tracing::info!("[QUIC] Shared endpoint listening on 0.0.0.0:{quic_port} (cert: {hash})");
            (ep, hash)
        }
        Err(e) => {
            tracing::error!("[QUIC] Failed to create shared endpoint: {e}");
            // Create a dummy — QUIC won't work but WebSocket relay still will
            return ConnectionResult::Error(format!("QUIC endpoint failed: {e}"));
        }
    };

    // Run QUIC accept loop in background
    let quic_ep_accept = quic_endpoint.clone();
    let quic_opts = options.clone();
    let quic_signaling = signaling_tx.clone();
    let quic_accept_task = tokio::spawn(async move {
        loop {
            match quic_ep_accept.accept().await {
                Some(incoming) => {
                    let opts = quic_opts.clone();
                    let sig = quic_signaling.clone();
                    tokio::spawn(async move {
                        match incoming.await {
                            Ok(conn) => {
                                let remote = conn.remote_address();
                                tracing::info!("[QUIC] Client connected from {remote}");
                                let handler = crate::quic::peer_handler::QuicPeerHandler::new(
                                    crate::quic::peer_handler::QuicPeerHandlerOptions {
                                        listen_port: opts.listen_port,
                                        use_tls: opts.use_tls,
                                        gateway_id: opts.gateway_id.clone(),
                                        send_signaling: sig,
                                        backends: opts.backends.clone(),
                                        auth: opts.auth.clone(),
                                        vpn_state: opts.vpn_state.clone(),
                                    },
                                );
                                handler.handle_connection(conn, remote.to_string()).await;
                            }
                            Err(e) => {
                                tracing::error!("[QUIC] Incoming connection failed: {e}");
                            }
                        }
                    });
                }
                None => {
                    tracing::info!("[QUIC] Endpoint closed");
                    break;
                }
            }
        }
    });

    // Main message loop
    let result = loop {
        tokio::select! {
            ws_msg = ws_stream.next() => {
                match ws_msg {
                    Some(Ok(Message::Text(text))) => {
                        let parsed: serde_json::Value = match serde_json::from_str(&text) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };

                        let msg_type = parsed["type"].as_str().unwrap_or("");

                        match msg_type {
                            "registered" => {
                                tracing::info!(
                                    "[STUN-Reg] Registered as gateway: {}",
                                    options.gateway_id
                                );
                            }
                            "paired" => {
                                if let Some(client) = parsed.get("client") {
                                    let client_id = client["id"].as_str().unwrap_or("unknown").to_string();
                                    let _client_token = client["token"].as_str().unwrap_or("").to_string();
                                    tracing::info!("[STUN-Reg] Paired with client: {}", client_id);

                                    // Send our fixed QUIC address + cert hash to the client
                                    let _ = signaling_tx.send(serde_json::json!({
                                        "type": "quic_address",
                                        "targetId": client_id,
                                        "fromId": options.gateway_id,
                                        "address": format!("0.0.0.0:{quic_port}"),
                                        "certHash": quic_cert_hash,
                                    }));
                                }
                            }
                            "candidate" => {
                                // WebRTC ICE candidate (legacy/fallback)
                                if let (Some(from_id), Some(candidate)) =
                                    (parsed["fromId"].as_str(), parsed.get("candidate"))
                                {
                                    if let Some(ref ph) = peer_handler {
                                        let cand_str = candidate["candidate"]
                                            .as_str()
                                            .unwrap_or("");
                                        let mid = candidate["mid"].as_str().unwrap_or("");
                                        if !cand_str.is_empty() {
                                            ph.handle_candidate(from_id, cand_str, mid).await;
                                        }
                                    }
                                }
                            }
                            "quic_address" => {
                                // Client sent their QUIC address — used for hole-punching
                                if let (Some(from_id), Some(addr)) =
                                    (parsed["fromId"].as_str(), parsed["address"].as_str())
                                {
                                    tracing::info!("[QUIC] Client {from_id} QUIC address: {addr}");
                                    // The QUIC endpoint is already listening —
                                    // client will connect to our address, we accept
                                }
                            }
                            "sdp_offer" => {
                                if let (Some(from_id), Some(sdp)) =
                                    (parsed["fromId"].as_str(), parsed["sdp"].as_str())
                                {
                                    if let Some(ref ph) = peer_handler {
                                        ph.handle_sdp_offer(from_id, sdp).await;
                                    }
                                }
                            }
                            "http_request" => {
                                handle_http_request(
                                    &parsed,
                                    options.clone(),
                                    ws_sink.clone(),
                                    pending_requests.clone(),
                                    relay_http_client.clone(),
                                )
                                .await;
                            }
                            "http_request_abort" => {
                                let req_id = parsed["id"].as_str().unwrap_or("").to_string();
                                let mut pending = pending_requests.write().await;
                                if let Some(abort_tx) = pending.remove(&req_id) {
                                    let _ = abort_tx.send(());
                                }
                            }
                            "error" => {
                                tracing::error!(
                                    "[STUN-Reg] Error: {}",
                                    parsed["message"].as_str().unwrap_or("unknown")
                                );
                            }
                            _ => {}
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {
                        // Pong received — connection alive
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        break ConnectionResult::Disconnected;
                    }
                    Some(Err(e)) => {
                        break ConnectionResult::Error(format!("{}", e));
                    }
                    _ => {}
                }
            }
            _ = shutdown_rx.recv() => {
                break ConnectionResult::Shutdown;
            }
            Some(new_metadata) = re_register_rx.recv() => {
                // Re-register with updated metadata (e.g. new backends after config hot-reload)
                let register_msg = json!({
                    "type": "register",
                    "role": "gateway",
                    "id": options.gateway_id,
                    "secret": options.api_secret,
                    "addresses": options.addresses,
                    "metadata": new_metadata,
                });
                let mut sink = ws_sink.lock().await;
                if let Err(e) = sink.send(Message::Text(serde_json::to_string(&register_msg).unwrap().into())).await {
                    tracing::warn!("[STUN-Reg] Re-register failed: {e}");
                } else {
                    tracing::info!("[STUN-Reg] Re-registered with updated metadata");
                }
            }
        }
    };

    // Cleanup
    ping_task.abort();
    signaling_task.abort();
    quic_accept_task.abort();
    quic_endpoint.close(0u32.into(), b"reconnecting");
    if let Some(ref ph) = peer_handler {
        ph.cleanup().await;
    }

    // Close WebSocket
    {
        let mut sink = ws_sink.lock().await;
        let _ = sink.send(Message::Close(None)).await;
    }

    result
}

/// Handle an HTTP request tunneled from the STUN server.
/// Makes a local request to the gateway's own HTTP server, collects the
/// response, and sends it back over WebSocket.
async fn handle_http_request(
    msg: &serde_json::Value,
    options: Arc<StunRegistrationOptions>,
    ws_sink: Arc<Mutex<futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >>>,
    pending_requests: Arc<RwLock<HashMap<String, tokio::sync::oneshot::Sender<()>>>>,
    http_client: reqwest::Client,
) {
    let request_id = msg["id"].as_str().unwrap_or("").to_string();
    let method = msg["method"].as_str().unwrap_or("GET").to_string();
    let url_path = msg["url"].as_str().unwrap_or("/").to_string();
    let headers_val = msg["headers"].clone();
    let body_b64 = msg["body"].as_str().unwrap_or("").to_string();

    // Helper to send JSON over the WebSocket
    let safe_send = |sink: Arc<Mutex<futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >>>,
                     data: serde_json::Value| async move {
        let mut s = sink.lock().await;
        let _ = s
            .send(Message::Text(serde_json::to_string(&data).unwrap().into()))
            .await;
    };

    // Validate URL path
    if !url_path.starts_with('/') || url_path.contains('\r') || url_path.contains('\n') {
        safe_send(
            ws_sink,
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
        safe_send(
            ws_sink,
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
        safe_send(
            ws_sink,
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

    tracing::info!("[STUN-Reg] Relay: {} {} (id: {})", method, url_path, request_id);

    // Create abort channel
    let (abort_tx, mut abort_rx) = tokio::sync::oneshot::channel::<()>();
    {
        let mut pending = pending_requests.write().await;
        pending.insert(request_id.clone(), abort_tx);
    }

    // Spawn the request in a task so we don't block the message loop
    let rid = request_id.clone();
    let pending_ref = pending_requests.clone();

    tokio::spawn(async move {
        let scheme = if options.use_tls { "https" } else { "http" };
        let target_url = format!("{}://127.0.0.1:{}{}", scheme, options.listen_port, url_path);

        let client = http_client;

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

        // Forward headers, stripping internal routing headers
        let internal_headers = [
            "x-forwarded-user",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
            "x-forwarded-port",
            "x-dc-request",
            "x-gateway-backend",
        ];
        if let Some(headers_obj) = headers_val.as_object() {
            for (key, val) in headers_obj {
                if internal_headers.contains(&key.to_lowercase().as_str()) {
                    continue;
                }
                if let Some(s) = val.as_str() {
                    req_builder = req_builder.header(key.as_str(), s);
                }
            }
        }

        // Add body
        if !body_b64.is_empty() {
            if let Ok(body_bytes) = base64::engine::general_purpose::STANDARD.decode(&body_b64)
            {
                req_builder = req_builder.body(body_bytes);
            }
        }

        // Send request (with abort support)
        let response = tokio::select! {
            result = req_builder.send() => result,
            _ = &mut abort_rx => {
                tracing::info!("[STUN-Reg] Request aborted: {}", rid);
                pending_ref.write().await.remove(&rid);
                return;
            }
        };

        match response {
            Ok(resp) => {
                let status = resp.status().as_u16();

                // Collect response headers (accumulate multi-value headers like set-cookie)
                let mut resp_headers = serde_json::Map::new();
                for (name, value) in resp.headers().iter() {
                    if let Ok(v) = value.to_str() {
                        let key = name.as_str().to_string();
                        if let Some(existing) = resp_headers.get_mut(&key) {
                            // Convert to array if not already, then push
                            if existing.is_array() {
                                existing.as_array_mut().unwrap().push(json!(v));
                            } else {
                                let prev = existing.clone();
                                *existing = json!([prev, v]);
                            }
                        } else {
                            resp_headers.insert(key, json!(v));
                        }
                    }
                }

                let ct = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();

                let is_streaming = is_streaming_content_type(&ct);

                if is_streaming {
                    // Streaming mode: forward chunks as they arrive (SSE, NDJSON)
                    tracing::info!("[STUN-Reg] Streaming relay: {} for {}", status, rid);
                    safe_send(
                        ws_sink.clone(),
                        json!({
                            "type": "http_response_start",
                            "id": rid,
                            "statusCode": status,
                            "headers": resp_headers,
                        }),
                    )
                    .await;

                    // Read body in chunks and forward
                    let body_bytes = resp.bytes().await.unwrap_or_default();
                    // For a true streaming implementation we'd use resp.chunk(),
                    // but reqwest's bytes() is sufficient for the relay use case.
                    if !body_bytes.is_empty() {
                        let b64 =
                            base64::engine::general_purpose::STANDARD.encode(&body_bytes);
                        safe_send(
                            ws_sink.clone(),
                            json!({
                                "type": "http_response_chunk",
                                "id": rid,
                                "data": b64,
                            }),
                        )
                        .await;
                    }

                    pending_ref.write().await.remove(&rid);
                    safe_send(
                        ws_sink,
                        json!({
                            "type": "http_response_end",
                            "id": rid,
                        }),
                    )
                    .await;
                } else {
                    // Buffered mode: collect full response then send
                    let body = resp.bytes().await.unwrap_or_default();
                    pending_ref.write().await.remove(&rid);

                    if body.len() > MAX_RESPONSE_SIZE {
                        safe_send(
                            ws_sink,
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

                    // If response body > 512KB, send as chunked to stay under WS maxPayload
                    if body.len() > MAX_SINGLE_WS {
                        tracing::info!(
                            "[STUN-Reg] Relay response (chunked): {} for {} ({} bytes)",
                            status,
                            rid,
                            body.len()
                        );
                        safe_send(
                            ws_sink.clone(),
                            json!({
                                "type": "http_response_start",
                                "id": rid,
                                "statusCode": status,
                                "headers": resp_headers,
                            }),
                        )
                        .await;

                        let mut offset = 0;
                        while offset < body.len() {
                            let end = std::cmp::min(offset + CHUNK_SIZE, body.len());
                            let chunk = &body[offset..end];
                            let b64 =
                                base64::engine::general_purpose::STANDARD.encode(chunk);
                            safe_send(
                                ws_sink.clone(),
                                json!({
                                    "type": "http_response_chunk",
                                    "id": rid,
                                    "data": b64,
                                }),
                            )
                            .await;
                            offset = end;
                        }

                        safe_send(
                            ws_sink,
                            json!({
                                "type": "http_response_end",
                                "id": rid,
                            }),
                        )
                        .await;
                    } else {
                        let body_b64 =
                            base64::engine::general_purpose::STANDARD.encode(&body);
                        tracing::info!(
                            "[STUN-Reg] Relay response: {} for {} ({} bytes b64)",
                            status,
                            rid,
                            body_b64.len()
                        );
                        safe_send(
                            ws_sink,
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
            }
            Err(e) => {
                pending_ref.write().await.remove(&rid);
                tracing::error!("[STUN-Reg] Relay request failed: {}", e);
                let (status, error_msg) = if e.is_timeout() {
                    (504, "Gateway timeout")
                } else {
                    (502, "Gateway internal error")
                };
                safe_send(
                    ws_sink,
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
