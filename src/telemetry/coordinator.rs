use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::event::ProcessEvent;

pub struct EventCoordinator {
    recent: HashMap<(u32, u32, u64), Instant>,
    dedup_window: Duration,
}

impl EventCoordinator {
    pub fn new(dedup_ms: u64) -> Self {
        Self {
            recent: HashMap::new(),
            dedup_window: Duration::from_millis(dedup_ms),
        }
    }

    /// Returns `true` when the event is new within the dedup window.
    pub fn accept(&mut self, event: &ProcessEvent) -> bool {
        let key = event.dedup_key();
        let now = Instant::now();
        if let Some(last) = self.recent.get(&key) {
            if now.duration_since(*last) < self.dedup_window {
                return false;
            }
        }
        self.recent.insert(key, now);
        self.prune(now);
        true
    }

    fn prune(&mut self, now: Instant) {
        if self.recent.len() < 4096 {
            return;
        }
        self.recent
            .retain(|_, ts| now.duration_since(*ts) < self.dedup_window);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::event::{EventSource, JETT_EVT_EXEC};

    fn sample(pid: u32, ino: u64) -> ProcessEvent {
        ProcessEvent {
            pid,
            name: "test".into(),
            cmdline: String::new(),
            exe_path: "/tmp/x".into(),
            uid: 1000,
            timestamp: 1,
            source: EventSource::Proc,
            inode: Some((0, ino)),
        }
    }

    #[test]
    fn dedup_key_uses_exec_event_type() {
        let e = sample(1, 42);
        assert_eq!(e.dedup_key(), (1, JETT_EVT_EXEC, 42));
    }

    #[test]
    fn duplicate_within_window_is_rejected() {
        let mut c = EventCoordinator::new(2000);
        let e = sample(99, 7);
        assert!(c.accept(&e));
        assert!(!c.accept(&e));
    }

    #[test]
    fn different_inode_is_not_duplicate() {
        let mut c = EventCoordinator::new(2000);
        assert!(c.accept(&sample(99, 1)));
        assert!(c.accept(&sample(99, 2)));
    }
}
