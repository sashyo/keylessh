//! In-memory log broadcast for the web UI.
//!
//! Captures tracing events and broadcasts them to SSE listeners via `/logs`.

use std::sync::OnceLock;
use tokio::sync::broadcast;

static LOG_TX: OnceLock<broadcast::Sender<String>> = OnceLock::new();

/// Initialize the log broadcast channel. Call once at startup.
pub fn init() -> broadcast::Sender<String> {
    let (tx, _) = broadcast::channel(512);
    LOG_TX.set(tx.clone()).ok();
    tx
}

/// Get a reference to the global log sender.
pub fn sender() -> Option<&'static broadcast::Sender<String>> {
    LOG_TX.get()
}

/// Push a log line into the broadcast channel.
pub fn push(line: String) {
    if let Some(tx) = LOG_TX.get() {
        let _ = tx.send(line);
    }
}

/// Subscribe to the log stream.
pub fn subscribe() -> Option<broadcast::Receiver<String>> {
    LOG_TX.get().map(|tx| tx.subscribe())
}

// ── Tracing layer that forwards to the broadcast channel ────────

use tracing_subscriber::Layer;

pub struct BroadcastLayer;

impl<S> Layer<S> for BroadcastLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);

        let meta = event.metadata();
        let level = meta.level();
        let target = meta.target();
        let line = format!("{level} {target}: {}", visitor.0);

        push(line);
    }
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        } else if !self.0.is_empty() {
            self.0.push_str(&format!(" {}={value:?}", field.name()));
        } else {
            self.0 = format!("{}={value:?}", field.name());
        }
    }
}
