use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Debug, Default)]
pub struct TelemetryStats {
    pub ringbuf_in: AtomicU64,
    pub ringbuf_drop: AtomicU64,
    pub dedup: AtomicU64,
    pub classify_drop: AtomicU64,
    pub ai_queued: AtomicU64,
    pub ai_dropped: AtomicU64,
    pub ai_verdicts: AtomicU64,
}

impl TelemetryStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn log_line(&self) -> String {
        format!(
            "[stats] ringbuf_in={} ringbuf_drop={} dedup={} classify_drop={} \
             ai_queued={} ai_dropped={} ai_verdicts={}",
            self.ringbuf_in.load(Ordering::Relaxed),
            self.ringbuf_drop.load(Ordering::Relaxed),
            self.dedup.load(Ordering::Relaxed),
            self.classify_drop.load(Ordering::Relaxed),
            self.ai_queued.load(Ordering::Relaxed),
            self.ai_dropped.load(Ordering::Relaxed),
            self.ai_verdicts.load(Ordering::Relaxed),
        )
    }
}
