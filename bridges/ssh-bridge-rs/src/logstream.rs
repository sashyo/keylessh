//! In-memory log broadcast for the web UI.
//!
//! Captures tracing events and broadcasts them to SSE listeners via `/logs`.

use std::sync::{Mutex, OnceLock};
use tokio::sync::broadcast;

static LOG_TX: OnceLock<broadcast::Sender<String>> = OnceLock::new();
static LOG_BUFFER: OnceLock<Mutex<LogRingBuffer>> = OnceLock::new();

struct LogRingBuffer {
    lines: Vec<String>,
    next: usize,
    full: bool,
}

impl LogRingBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            lines: vec![String::new(); capacity],
            next: 0,
            full: false,
        }
    }

    fn push(&mut self, line: String) {
        self.lines[self.next] = line;
        self.next += 1;
        if self.next >= self.lines.len() {
            self.next = 0;
            self.full = true;
        }
    }

    fn snapshot(&self) -> Vec<String> {
        if self.full {
            let mut out = Vec::with_capacity(self.lines.len());
            out.extend_from_slice(&self.lines[self.next..]);
            out.extend_from_slice(&self.lines[..self.next]);
            out
        } else {
            self.lines[..self.next].to_vec()
        }
    }
}

/// Initialize the log broadcast channel and ring buffer. Call once at startup.
pub fn init() -> broadcast::Sender<String> {
    let (tx, _) = broadcast::channel(512);
    LOG_TX.set(tx.clone()).ok();
    LOG_BUFFER.set(Mutex::new(LogRingBuffer::new(1000))).ok();
    tx
}

/// Push a log line into the broadcast channel and ring buffer.
pub fn push(line: String) {
    if let Some(buf) = LOG_BUFFER.get() {
        if let Ok(mut buf) = buf.lock() {
            buf.push(line.clone());
        }
    }
    if let Some(tx) = LOG_TX.get() {
        let _ = tx.send(line);
    }
}

/// Get a snapshot of recent log lines.
pub fn recent_lines() -> Vec<String> {
    LOG_BUFFER
        .get()
        .and_then(|buf| buf.lock().ok().map(|b| b.snapshot()))
        .unwrap_or_default()
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
