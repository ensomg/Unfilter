//! Scoring: how well a candidate strategy performed, so the prober can keep the
//! best plus two backups per network (master prompt §5.6 step 5).
//!
//! Score ranks on success rate first, then lower latency. All bookkeeping — this
//! records outcomes the engine reports; it does not itself touch packets.

use serde::{Deserialize, Serialize};

/// Running score for one strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StrategyScore {
    /// Total probe/flow attempts observed.
    pub attempts: u32,
    /// How many succeeded (valid response, not a block page / RST / timeout).
    pub successes: u32,
    /// Exponentially-weighted mean added latency, microseconds.
    pub latency_us_ewma: u32,
}

impl StrategyScore {
    /// Record one outcome. `latency_us` is only meaningful on success.
    pub fn record(&mut self, success: bool, latency_us: u32) {
        self.attempts = self.attempts.saturating_add(1);
        if success {
            self.successes = self.successes.saturating_add(1);
            // EWMA with alpha = 1/4, integer math.
            self.latency_us_ewma = if self.latency_us_ewma == 0 {
                latency_us
            } else {
                (self.latency_us_ewma * 3 + latency_us) / 4
            };
        }
    }

    /// Success rate in [0, 1]; a strategy with no attempts scores 0.
    pub fn success_rate(&self) -> f32 {
        if self.attempts == 0 {
            0.0
        } else {
            self.successes as f32 / self.attempts as f32
        }
    }

    /// Order key: higher is better. Success rate dominates; lower latency breaks
    /// ties. Returns a tuple usable with `sort_by`.
    fn rank_key(&self) -> (u32, i64) {
        // Quantise success rate to permille to keep it integer/stable.
        let permille = (self.success_rate() * 1000.0) as u32;
        (permille, -(self.latency_us_ewma as i64))
    }
}

/// Scores for a set of candidate strategies, indexed by candidate position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ScoreBoard {
    /// One score per candidate, same order as the ladder.
    pub scores: Vec<StrategyScore>,
}

impl ScoreBoard {
    /// A fresh board for `n` candidates.
    pub fn new(n: usize) -> Self {
        ScoreBoard {
            scores: vec![StrategyScore::default(); n],
        }
    }

    /// Record an outcome for candidate `idx`.
    pub fn record(&mut self, idx: usize, success: bool, latency_us: u32) {
        if let Some(s) = self.scores.get_mut(idx) {
            s.record(success, latency_us);
        }
    }

    /// The candidate indices ranked best-first. Only strategies with at least
    /// one success are returned.
    pub fn ranked(&self) -> Vec<usize> {
        let mut idx: Vec<usize> = (0..self.scores.len())
            .filter(|&i| self.scores[i].successes > 0)
            .collect();
        idx.sort_by(|&a, &b| self.scores[b].rank_key().cmp(&self.scores[a].rank_key()));
        idx
    }

    /// Best plus up to `backups` alternates (§5.6: best + 2 backups).
    pub fn best_with_backups(&self, backups: usize) -> Vec<usize> {
        let mut r = self.ranked();
        r.truncate(1 + backups);
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn higher_success_rate_ranks_first() {
        let mut b = ScoreBoard::new(2);
        // Candidate 0: 1/2 success. Candidate 1: 3/3 success.
        b.record(0, true, 1000);
        b.record(0, false, 0);
        b.record(1, true, 2000);
        b.record(1, true, 2000);
        b.record(1, true, 2000);
        assert_eq!(b.ranked(), vec![1, 0]);
    }

    #[test]
    fn latency_breaks_ties() {
        let mut b = ScoreBoard::new(2);
        b.record(0, true, 5000); // 1/1, slow
        b.record(1, true, 500); // 1/1, fast
        assert_eq!(b.ranked(), vec![1, 0]);
    }

    #[test]
    fn untried_strategies_excluded() {
        let mut b = ScoreBoard::new(3);
        b.record(1, true, 100);
        assert_eq!(b.ranked(), vec![1]);
        assert_eq!(b.best_with_backups(2), vec![1]);
    }
}
