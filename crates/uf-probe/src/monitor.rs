//! Passive monitoring and automatic fallback (master prompt §5.6 steps 6–7).
//!
//! While a chosen strategy runs, the engine reports each flow's outcome here.
//! Two decisions come out of it:
//! - per target: after a run of failures, silently fall back to a backup
//!   strategy (the engine retries that flow);
//! - globally: if the active strategy's success rate drops below a threshold
//!   (the ISP changed its DPI signature), trigger a full re-scan.
//!
//! Bookkeeping only — it decides *when* to switch, not *how* to rewrite packets.

use serde::{Deserialize, Serialize};

/// Outcome of a flow under the active strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowOutcome {
    /// Reached the destination with a valid response.
    Ok,
    /// Got a reset (often DPI-injected).
    Rst,
    /// No response within the deadline.
    Timeout,
    /// Got a block page.
    BlockPage,
}

impl FlowOutcome {
    fn is_failure(self) -> bool {
        !matches!(self, FlowOutcome::Ok)
    }
}

/// Thresholds controlling fallback and re-scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// Consecutive failures on one target before falling back to a backup.
    pub failover_after: u32,
    /// Minimum samples before the global success-rate check applies.
    pub min_samples: u32,
    /// Success rate (permille, 0–1000) below which a full re-scan is triggered.
    pub rescan_below_permille: u32,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        MonitorConfig {
            failover_after: 2,
            min_samples: 20,
            rescan_below_permille: 600, // 60%
        }
    }
}

/// Tracks outcomes for the active strategy and the current failure streak.
#[derive(Debug, Clone, Default)]
pub struct Monitor {
    config: MonitorConfig,
    attempts: u32,
    failures: u32,
    streak: u32,
}

/// What the monitor advises after an outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advice {
    /// Keep going.
    Continue,
    /// Fall back to a backup strategy for this target.
    Failover,
    /// The active strategy is failing broadly; re-scan from scratch.
    Rescan,
}

impl Monitor {
    /// A monitor with the given thresholds.
    pub fn new(config: MonitorConfig) -> Self {
        Monitor {
            config,
            ..Default::default()
        }
    }

    /// Current global success rate in permille (0–1000).
    pub fn success_permille(&self) -> u32 {
        if self.attempts == 0 {
            1000
        } else {
            ((self.attempts - self.failures) as u64 * 1000 / self.attempts as u64) as u32
        }
    }

    /// Record a flow outcome and get advice. A global re-scan takes priority
    /// over a per-target failover.
    pub fn record(&mut self, outcome: FlowOutcome) -> Advice {
        self.attempts = self.attempts.saturating_add(1);
        if outcome.is_failure() {
            self.failures = self.failures.saturating_add(1);
            self.streak = self.streak.saturating_add(1);
        } else {
            self.streak = 0;
        }

        if self.attempts >= self.config.min_samples
            && self.success_permille() < self.config.rescan_below_permille
        {
            return Advice::Rescan;
        }
        if self.streak >= self.config.failover_after {
            return Advice::Failover;
        }
        Advice::Continue
    }

    /// Reset after a re-scan or strategy switch.
    pub fn reset(&mut self) {
        self.attempts = 0;
        self.failures = 0;
        self.streak = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failover_after_consecutive_failures() {
        let mut m = Monitor::new(MonitorConfig::default());
        assert_eq!(m.record(FlowOutcome::Rst), Advice::Continue);
        assert_eq!(m.record(FlowOutcome::Timeout), Advice::Failover);
    }

    #[test]
    fn success_resets_streak() {
        let mut m = Monitor::new(MonitorConfig::default());
        m.record(FlowOutcome::Rst);
        assert_eq!(m.record(FlowOutcome::Ok), Advice::Continue);
        // One failure again is not yet a failover.
        assert_eq!(m.record(FlowOutcome::Rst), Advice::Continue);
    }

    #[test]
    fn low_success_rate_triggers_rescan() {
        let cfg = MonitorConfig {
            failover_after: 1000, // disable failover to isolate the rescan path
            min_samples: 10,
            rescan_below_permille: 600,
        };
        let mut m = Monitor::new(cfg);
        // 10 outcomes, 5 failures = 50% < 60%.
        for i in 0..10 {
            let adv = m.record(if i % 2 == 0 {
                FlowOutcome::Ok
            } else {
                FlowOutcome::Rst
            });
            if i == 9 {
                assert_eq!(adv, Advice::Rescan);
            }
        }
    }

    #[test]
    fn healthy_strategy_keeps_going() {
        let mut m = Monitor::new(MonitorConfig::default());
        for _ in 0..50 {
            assert_eq!(m.record(FlowOutcome::Ok), Advice::Continue);
        }
        assert_eq!(m.success_permille(), 1000);
    }
}
