use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::oneshot;

use crate::config::Config;
use crate::registry::Registry;

pub struct PendingRequest {
    pub response_tx: oneshot::Sender<HttpRelayResponse>,
}

pub struct HttpRelayResponse {
    pub status: u16,
    pub headers: serde_json::Value,
    pub body: Vec<u8>,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub registry: Arc<Registry>,
    pub pending_requests: Arc<DashMap<String, PendingRequest>>,
    pub connections_by_ip: Arc<DashMap<String, usize>>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
            registry: Arc::new(Registry::new()),
            pending_requests: Arc::new(DashMap::new()),
            connections_by_ip: Arc::new(DashMap::new()),
        }
    }
}
