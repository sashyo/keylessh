///! RDP session recording — captures raw PDU bytes with timestamps.
///!
///! Records the bidirectional byte stream between client and RDP server,
///! buffers events, and uploads batches to the keylessh server API.

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde_json::json;
use tokio::sync::mpsc;

/// Direction of the PDU data.
#[derive(Clone, Copy, Debug)]
pub enum Direction {
    /// Client to Server
    C2S,
    /// Server to Client
    S2C,
}

impl Direction {
    fn as_str(&self) -> &'static str {
        match self {
            Direction::C2S => "c2s",
            Direction::S2C => "s2c",
        }
    }
}

/// A single recorded event.
struct RecordingEvent {
    offset_secs: f64,
    direction: Direction,
    data: Vec<u8>,
}

/// Metadata for starting a recording session.
#[derive(Clone, Debug)]
pub struct RecordingMeta {
    pub server_url: String,
    pub token: String,
    pub session_id: String,
    pub server_id: String,
    pub backend_name: String,
    pub gateway_id: String,
    pub user_email: String,
}

/// Lightweight handle for recording — clone and pass to relay tasks.
/// Sending never blocks the relay; if the recording channel is full, events are dropped.
#[derive(Clone)]
pub struct RecordingHandle {
    tx: mpsc::Sender<RecordingEvent>,
    start: Instant,
}

impl RecordingHandle {
    /// Record a client-to-server PDU.
    pub fn record_c2s(&self, data: &[u8]) {
        let event = RecordingEvent {
            offset_secs: self.start.elapsed().as_secs_f64(),
            direction: Direction::C2S,
            data: data.to_vec(),
        };
        let _ = self.tx.try_send(event); // non-blocking, drop if full
    }

    /// Record a server-to-client PDU.
    pub fn record_s2c(&self, data: &[u8]) {
        let event = RecordingEvent {
            offset_secs: self.start.elapsed().as_secs_f64(),
            direction: Direction::S2C,
            data: data.to_vec(),
        };
        let _ = self.tx.try_send(event);
    }
}

/// Maximum events to buffer before flushing to the server.
const FLUSH_BATCH_SIZE: usize = 100;
/// Maximum time between flushes.
const FLUSH_INTERVAL_SECS: u64 = 2;
/// Channel capacity — if recording falls behind, old events are dropped.
const CHANNEL_CAPACITY: usize = 4096;

/// Start a recording session. Returns a handle for the relay tasks.
/// Spawns a background task that buffers events and uploads them to the server.
pub fn start_recording(meta: RecordingMeta) -> RecordingHandle {
    let (tx, rx) = mpsc::channel::<RecordingEvent>(CHANNEL_CAPACITY);
    let start = Instant::now();

    tokio::spawn(recording_uploader(meta, rx));

    RecordingHandle { tx, start }
}

/// Background task: buffer events and POST them to the keylessh server.
async fn recording_uploader(meta: RecordingMeta, mut rx: mpsc::Receiver<RecordingEvent>) {
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("[Recording] Failed to create HTTP client: {e}");
            return;
        }
    };

    let server_url = meta.server_url.trim_end_matches('/');

    // Step 1: Start recording on the server
    let start_url = format!("{server_url}/api/bridge/start-rdp-recording");
    let start_body = json!({
        "token": meta.token,
        "sessionId": meta.session_id,
        "serverId": meta.server_id,
        "backendName": meta.backend_name,
        "gatewayId": meta.gateway_id,
        "userEmail": meta.user_email,
        "timestamp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    });

    let recording_id = match client.post(&start_url).json(&start_body).send().await {
        Ok(resp) if resp.status().is_success() => {
            match resp.json::<serde_json::Value>().await {
                Ok(v) => v["recordingId"].as_str().unwrap_or("").to_string(),
                Err(e) => {
                    tracing::error!("[Recording] Failed to parse start response: {e}");
                    return;
                }
            }
        }
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            tracing::error!("[Recording] Start failed ({status}): {body}");
            return;
        }
        Err(e) => {
            tracing::error!("[Recording] Start request failed: {e}");
            return;
        }
    };

    if recording_id.is_empty() {
        tracing::error!("[Recording] No recordingId returned");
        return;
    }

    tracing::info!("[Recording] Started RDP recording: {recording_id}");

    // Step 2: Buffer and flush events
    let record_url = format!("{server_url}/api/bridge/rdp-record");
    let mut buffer: Vec<serde_json::Value> = Vec::with_capacity(FLUSH_BATCH_SIZE);
    let mut flush_interval = tokio::time::interval(std::time::Duration::from_secs(FLUSH_INTERVAL_SECS));
    let mut total_events = 0u64;

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(evt) => {
                        let b64 = base64::engine::general_purpose::STANDARD.encode(&evt.data);
                        buffer.push(json!([evt.offset_secs, evt.direction.as_str(), b64]));
                        total_events += 1;

                        if buffer.len() >= FLUSH_BATCH_SIZE {
                            flush_events(&client, &record_url, &meta.token, &meta.session_id, &recording_id, &mut buffer).await;
                        }
                    }
                    None => {
                        // Channel closed — session ended
                        break;
                    }
                }
            }
            _ = flush_interval.tick() => {
                if !buffer.is_empty() {
                    flush_events(&client, &record_url, &meta.token, &meta.session_id, &recording_id, &mut buffer).await;
                }
            }
        }
    }

    // Flush remaining events
    if !buffer.is_empty() {
        flush_events(&client, &record_url, &meta.token, &meta.session_id, &recording_id, &mut buffer).await;
    }

    // Step 3: End recording
    let end_url = format!("{server_url}/api/bridge/end-rdp-recording");
    let end_body = json!({
        "token": meta.token,
        "sessionId": meta.session_id,
        "recordingId": recording_id,
    });

    match client.post(&end_url).json(&end_body).send().await {
        Ok(resp) if resp.status().is_success() => {
            tracing::info!("[Recording] RDP recording ended: {recording_id} ({total_events} events)");
        }
        Ok(resp) => {
            let status = resp.status();
            tracing::warn!("[Recording] End recording failed ({status})");
        }
        Err(e) => {
            tracing::warn!("[Recording] End recording request failed: {e}");
        }
    }
}

/// Flush buffered events to the server.
async fn flush_events(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    session_id: &str,
    recording_id: &str,
    buffer: &mut Vec<serde_json::Value>,
) {
    let body = json!({
        "token": token,
        "sessionId": session_id,
        "recordingId": recording_id,
        "events": serde_json::Value::Array(buffer.drain(..).collect()),
    });

    match client.post(url).json(&body).send().await {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => {
            let status = resp.status();
            tracing::warn!("[Recording] Flush failed ({status})");
        }
        Err(e) => {
            tracing::warn!("[Recording] Flush request failed: {e}");
        }
    }
}
