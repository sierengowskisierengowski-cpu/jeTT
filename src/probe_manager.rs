//! Adaptive probe budget — behavior collection window under load/threat.

/// Manages behavior collection window duration.
pub struct ProbeManager {
    base_window_ms: u64,
    min_window_ms: u64,
    max_window_ms: u64,
    chain_alert_boost: u64,
    recent_chain_alerts: u32,
}

impl Default for ProbeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ProbeManager {
    pub fn new() -> Self {
        Self {
            base_window_ms: 1500,
            min_window_ms: 400,
            max_window_ms: 3000,
            chain_alert_boost: 500,
            recent_chain_alerts: 0,
        }
    }

    /// Record a chain alert to extend probing under active threat.
    pub fn on_chain_alert(&mut self) {
        self.recent_chain_alerts = self.recent_chain_alerts.saturating_add(1).min(8);
    }

    /// Decay chain alert counter (call periodically).
    pub fn decay_alerts(&mut self) {
        self.recent_chain_alerts = self.recent_chain_alerts.saturating_sub(1);
    }

    /// Compute behavior window in milliseconds.
    /// `load_factor` in [0,1]: 0 = idle, 1 = saturated.
    pub fn behavior_window_ms(&self, load_factor: f32) -> u64 {
        let load = load_factor.clamp(0.0, 1.0);
        let reduction = ((self.base_window_ms - self.min_window_ms) as f32 * load) as u64;
        let mut window = self.base_window_ms.saturating_sub(reduction);
        let boost = (self.recent_chain_alerts as u64).saturating_mul(self.chain_alert_boost);
        window = window.saturating_add(boost).min(self.max_window_ms);
        window.max(self.min_window_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_load_reduces_window() {
        let pm = ProbeManager::new();
        let idle = pm.behavior_window_ms(0.0);
        let loaded = pm.behavior_window_ms(1.0);
        assert!(loaded < idle);
        assert!(loaded >= pm.min_window_ms);
    }

    #[test]
    fn chain_alerts_extend_window() {
        let mut pm = ProbeManager::new();
        pm.on_chain_alert();
        pm.on_chain_alert();
        let boosted = pm.behavior_window_ms(0.0);
        let base = ProbeManager::new().behavior_window_ms(0.0);
        assert!(boosted > base);
    }

    #[test]
    fn window_stays_in_bounds() {
        let mut pm = ProbeManager::new();
        for _ in 0..20 {
            pm.on_chain_alert();
        }
        let w = pm.behavior_window_ms(0.5);
        assert!(w >= pm.min_window_ms && w <= pm.max_window_ms);
    }
}
