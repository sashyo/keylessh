use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot};

use crate::config::Config;
use crate::registry::Registry;

pub struct PendingRequest {
    pub tx: mpsc::UnboundedSender<RelayMessage>,
}

pub enum RelayMessage {
    /// Complete buffered response (from `http_response`)
    Complete {
        status: u16,
        headers: serde_json::Value,
        body: Vec<u8>,
    },
    /// Start of a streamed response (from `http_response_start`)
    StreamStart {
        status: u16,
        headers: serde_json::Value,
    },
    /// A chunk of streamed data (from `http_response_chunk`)
    StreamChunk(Vec<u8>),
    /// End of stream (from `http_response_end`)
    StreamEnd,
    /// Abort (from `http_abort`)
    Abort,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub registry: Arc<Registry>,
    pub pending_requests: Arc<DashMap<String, PendingRequest>>,
    pub connections_by_ip: Arc<DashMap<String, usize>>,
    /// In-flight config pushes, keyed by request id, awaiting the gateway's ack.
    pub pending_config_acks: Arc<DashMap<String, oneshot::Sender<serde_json::Value>>>,
    /// Config pushed to a gateway that was offline, keyed by gateway id, and
    /// delivered when it next registers. Only the newest push per gateway is
    /// kept — an older one has already been superseded.
    pub pending_configs: Arc<DashMap<String, serde_json::Value>>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
            registry: Arc::new(Registry::new()),
            pending_requests: Arc::new(DashMap::new()),
            connections_by_ip: Arc::new(DashMap::new()),
            pending_config_acks: Arc::new(DashMap::new()),
            pending_configs: Arc::new(DashMap::new()),
        }
    }
}
