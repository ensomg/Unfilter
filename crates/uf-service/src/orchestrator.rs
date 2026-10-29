//! The service control plane: the state machine behind the UI, and the policy
//! that picks which strategy a flow should use.
//!
//! This is deliberately free of I/O (no sockets, no WinDivert, no pipe) so the
//! whole control logic — connect/disconnect/rescan/failover, strategy selection
//! from the profile cache and ladder, scoring bookkeeping — is unit-tested with
//! no network and no privileges. The Windows service (`main`) owns the engine,
//! the resolver and the pipe, and drives this type: it feeds probe/flow results
//! in and turns [`Event`]s out to connected clients.

use uf_ipc::{BlockKind, ConnState, Event, Mode, Request, ResponsePayload, SiteTest, Status};
use uf_probe::FlowOutcome;
use uf_probe::monitor::Advice;
use uf_probe::{
    Candidate, Fingerprint, Monitor, MonitorConfig, Profile, ProfileCache, ScoreBoard,
    default_ladder,
};

use crate::config::Config;

/// How many backups to keep alongside the best strategy (master prompt §5.6).
const BACKUPS: usize = 2;

/// The control-plane state machine and strategy policy.
pub struct Orchestrator {
    state: ConnState,
    mode: Mode,
    /// The candidate ladder (cheapest first).
    ladder: Vec<Candidate>,
    /// Index into `ladder` of the currently active strategy, if connected.
    active: Option<usize>,
    /// Per-network profile cache (persisted by the caller).
    cache: ProfileCache,
    /// This network's fingerprint.
    fingerprint: Fingerprint,
    /// Live scoring for the current scan.
    scores: ScoreBoard,
    /// The order the prober will try candidates in this scan (indices into
    /// `ladder`): the cached preference first, then the rest cheapest-first.
    try_order: Vec<usize>,
    /// Which position in `try_order` the scan is at.
    try_pos: usize,
    /// Passive monitor for the active strategy.
    monitor: Monitor,
    /// Added latency estimate (µs) shown in the UI.
    added_latency_us: u32,
    /// Forced strategy name from config, if any.
    forced: Option<String>,
    /// Whether auto-probe is enabled.
    auto_probe: bool,
}

impl Orchestrator {
    /// Build an orchestrator for a network fingerprint, seeded from config and a
    /// (possibly empty) profile cache.
    pub fn new(cfg: &Config, fingerprint: Fingerprint, cache: ProfileCache) -> Self {
        let ladder = default_ladder();
        let forced = if cfg.engine.strategy.is_empty() {
            None
        } else {
            Some(cfg.engine.strategy.clone())
        };
        let mut o = Orchestrator {
            state: ConnState::Ready,
            mode: cfg.general.mode.into(),
            scores: ScoreBoard::new(ladder.len()),
            try_order: Vec::new(),
            try_pos: 0,
            monitor: Monitor::new(MonitorConfig::default()),
            added_latency_us: 0,
            forced,
            auto_probe: cfg.engine.auto_probe,
            active: None,
            cache,
            fingerprint,
            ladder,
        };
        o.rebuild_try_order();
        o
    }

    /// The current status snapshot.
    pub fn status(&self) -> Status {
        Status {
            state: self.state,
            strategy: self.active.map(|i| self.ladder[i].name().to_string()),
            added_latency_us: self.added_latency_us,
            mode: self.mode,
        }
    }

    /// Handle one client request, returning the response and any events to push
    /// to all connected clients (e.g. a status change).
    pub fn handle(&mut self, req: Request) -> (ResponsePayload, Vec<Event>) {
        match req {
            Request::Connect => {
                self.begin_scan();
                self.status_response_with_event()
            }
            Request::Disconnect => {
                self.state = ConnState::Ready;
                self.active = None;
                self.added_latency_us = 0;
                self.status_response_with_event()
            }
            Request::Rescan => {
                self.begin_scan();
                self.status_response_with_event()
            }
            Request::SetMode { mode } => {
                self.mode = mode;
                self.status_response_with_event()
            }
            // Repair re-runs the scan from scratch (the runtime restarts capture).
            Request::Repair => {
                self.begin_scan();
                self.status_response_with_event()
            }
            Request::GetStatus => (
                ResponsePayload::Status {
                    status: self.status(),
                },
                Vec::new(),
            ),
            Request::TestSite { host } => (
                ResponsePayload::SiteTest {
                    test: self.test_site(&host),
                },
                Vec::new(),
            ),
            _ => (ResponsePayload::Ok, Vec::new()),
        }
    }

    /// The next candidate the scan should try, or `None` if the ladder is
    /// exhausted. Advances the scan position.
    pub fn next_candidate(&mut self) -> Option<Candidate> {
        self.next_candidate_indexed().map(|(_, c)| c)
    }

    /// Like [`Self::next_candidate`], but also returns the candidate's ladder
    /// index (what [`Self::record_probe`] takes).
    pub fn next_candidate_indexed(&mut self) -> Option<(usize, Candidate)> {
        if self.state != ConnState::Scanning {
            return None;
        }
        let &idx = self.try_order.get(self.try_pos)?;
        self.try_pos += 1;
        Some((idx, self.ladder[idx].clone()))
    }

    /// The current connection state.
    pub fn state(&self) -> ConnState {
        self.state
    }

    /// The strategy the engine should run while connected, if any.
    pub fn active_spec(&self) -> Option<uf_core::strategy::StrategySpec> {
        self.active.map(|i| self.ladder[i].spec.clone())
    }

    /// End a scan where no candidate passed every target by settling on the
    /// best partial one (`ladder_index`), rather than faulting. No-op unless
    /// scanning. Returns events to push.
    pub fn accept_partial(&mut self, ladder_index: usize, latency_us: u32) -> Vec<Event> {
        if self.state != ConnState::Scanning || ladder_index >= self.ladder.len() {
            return Vec::new();
        }
        self.activate(ladder_index, latency_us);
        self.persist_scores();
        vec![Event::Status {
            status: self.status(),
        }]
    }

    /// The runtime could not start (no driver / not elevated): show a fault so
    /// the user sees it and can hit Repair. Returns events to push.
    pub fn fault(&mut self) -> Vec<Event> {
        if self.state == ConnState::Fault {
            return Vec::new();
        }
        self.state = ConnState::Fault;
        self.active = None;
        self.added_latency_us = 0;
        vec![Event::Status {
            status: self.status(),
        }]
    }

    /// Record a probe result for `ladder_index`. When a candidate succeeds it
    /// becomes active and the connection moves to [`ConnState::Connected`];
    /// scores are folded into the profile cache for next time. Returns events to
    /// push.
    pub fn record_probe(
        &mut self,
        ladder_index: usize,
        success: bool,
        latency_us: u32,
    ) -> Vec<Event> {
        self.scores.record(ladder_index, success, latency_us);
        if success && self.state == ConnState::Scanning {
            self.activate(ladder_index, latency_us);
            self.persist_scores();
            return vec![Event::Status {
                status: self.status(),
            }];
        }
        Vec::new()
    }

    /// Mark the scan as failed (no candidate worked): the engine passes traffic
    /// through and the UI shows a fault so the user can hit Repair.
    pub fn scan_exhausted(&mut self) -> Vec<Event> {
        if self.state == ConnState::Scanning {
            self.state = ConnState::Fault;
            self.active = None;
            vec![Event::Status {
                status: self.status(),
            }]
        } else {
            Vec::new()
        }
    }

    /// Feed a live flow outcome to the passive monitor while connected. A run of
    /// failures silently fails over to a backup; a sustained low success rate
    /// triggers a rescan. Returns events to push.
    pub fn record_flow(&mut self, outcome: FlowOutcome) -> Vec<Event> {
        if self.state != ConnState::Connected {
            return Vec::new();
        }
        match self.monitor.record(outcome) {
            Advice::Continue => Vec::new(),
            Advice::Failover => {
                if self.failover() {
                    vec![Event::Status {
                        status: self.status(),
                    }]
                } else {
                    self.begin_scan();
                    vec![Event::Status {
                        status: self.status(),
                    }]
                }
            }
            Advice::Rescan => {
                self.begin_scan();
                vec![Event::Status {
                    status: self.status(),
                }]
            }
        }
    }

    /// The profile cache, for the caller to persist to disk.
    pub fn cache(&self) -> &ProfileCache {
        &self.cache
    }

    // --- internals ---

    fn begin_scan(&mut self) {
        self.state = ConnState::Scanning;
        self.active = None;
        self.scores = ScoreBoard::new(self.ladder.len());
        self.monitor.reset();
        self.rebuild_try_order();
        self.try_pos = 0;
        // A forced strategy skips scanning entirely.
        if let Some(name) = self.forced.clone() {
            if let Some(idx) = self.ladder.iter().position(|c| c.name() == name) {
                self.activate(idx, 0);
            }
        } else if !self.auto_probe {
            // Auto-probe off and nothing forced: use the cheapest candidate.
            self.activate(0, 0);
        }
    }

    fn activate(&mut self, idx: usize, latency_us: u32) {
        self.active = Some(idx);
        self.state = ConnState::Connected;
        self.added_latency_us = latency_us;
        self.monitor.reset();
    }

    fn failover(&mut self) -> bool {
        let ranked = self.scores.best_with_backups(BACKUPS);
        let current = self.active;
        for &idx in &ranked {
            if Some(idx) != current {
                self.activate(idx, self.added_latency_us);
                return true;
            }
        }
        false
    }

    /// Rebuild the try order: the cached preferred indices first (if the profile
    /// is for the current ladder), then every remaining candidate cheapest-first.
    fn rebuild_try_order(&mut self) {
        let n = self.ladder.len();
        let mut order: Vec<usize> = Vec::with_capacity(n);
        if let Some(profile) = self.cache.get(self.fingerprint) {
            if profile.ladder_version == n as u32 {
                for &i in &profile.preferred {
                    if i < n && !order.contains(&i) {
                        order.push(i);
                    }
                }
            }
        }
        for i in 0..n {
            if !order.contains(&i) {
                order.push(i);
            }
        }
        self.try_order = order;
    }

    fn persist_scores(&mut self) {
        let preferred: Vec<usize> = self.scores.best_with_backups(BACKUPS);
        let mut profile = Profile::empty(self.ladder.len() as u32, self.ladder.len());
        profile.scores = self.scores.clone();
        profile.preferred = preferred;
        self.cache.put(self.fingerprint, profile);
    }

    fn status_response_with_event(&self) -> (ResponsePayload, Vec<Event>) {
        (
            ResponsePayload::Status {
                status: self.status(),
            },
            vec![Event::Status {
                status: self.status(),
            }],
        )
    }

    fn test_site(&self, host: &str) -> SiteTest {
        // Without live probing the control plane reports what it knows: when
        // connected, the active strategy is the via; block kind is unknown until
        // a live probe fills it. The Windows service overrides this with real
        // DNS/TCP/TLS results when it has them.
        let connected = self.state == ConnState::Connected;
        SiteTest {
            host: host.to_string(),
            dns_ok: connected || self.state == ConnState::Ready,
            tcp_ok: connected,
            tls_ok: connected,
            block: if connected {
                None
            } else {
                Some(BlockKind::Dpi)
            },
            via: self.active.map(|i| self.ladder[i].name().to_string()),
        }
    }
}

/// Convenience accessor for a candidate's strategy name.
trait CandidateName {
    fn name(&self) -> &str;
}
impl CandidateName for Candidate {
    fn name(&self) -> &str {
        &self.spec.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn orch() -> Orchestrator {
        Orchestrator::new(&Config::default(), Fingerprint(0x1234), ProfileCache::new())
    }

    #[test]
    fn starts_ready() {
        let o = orch();
        assert_eq!(o.status().state, ConnState::Ready);
        assert!(o.status().strategy.is_none());
    }

    #[test]
    fn connect_scans_then_first_success_connects() {
        let mut o = orch();
        let (_resp, events) = o.handle(Request::Connect);
        assert_eq!(o.status().state, ConnState::Scanning);
        assert!(!events.is_empty());

        // Prober tries candidates; first one fails, second works.
        let c0 = o.next_candidate().unwrap();
        assert_eq!(c0.name(), "dns_only"); // cheapest first
        o.record_probe(0, false, 0);
        assert_eq!(o.status().state, ConnState::Scanning);

        let _c1 = o.next_candidate().unwrap();
        let ev = o.record_probe(1, true, 1500);
        assert_eq!(o.status().state, ConnState::Connected);
        assert_eq!(o.status().added_latency_us, 1500);
        assert!(o.status().strategy.is_some());
        assert!(!ev.is_empty());
    }

    #[test]
    fn success_is_persisted_and_preferred_next_time() {
        let mut o = orch();
        o.handle(Request::Connect);
        o.next_candidate();
        o.next_candidate();
        o.record_probe(2, true, 900);
        let cache = o.cache().clone();
        assert!(cache.get(Fingerprint(0x1234)).is_some());

        // A fresh orchestrator with that cache tries the remembered strategy first.
        let mut o2 = Orchestrator::new(&Config::default(), Fingerprint(0x1234), cache);
        o2.handle(Request::Connect);
        let first = o2.next_candidate().unwrap();
        assert_eq!(first.name(), o.status().strategy.unwrap());
    }

    #[test]
    fn disconnect_returns_to_ready() {
        let mut o = orch();
        o.handle(Request::Connect);
        o.next_candidate();
        o.record_probe(0, true, 100);
        assert_eq!(o.status().state, ConnState::Connected);
        o.handle(Request::Disconnect);
        assert_eq!(o.status().state, ConnState::Ready);
        assert!(o.status().strategy.is_none());
    }

    #[test]
    fn scan_exhausted_is_fault() {
        let mut o = orch();
        o.handle(Request::Connect);
        while let Some(_c) = o.next_candidate() {}
        let ev = o.scan_exhausted();
        assert_eq!(o.status().state, ConnState::Fault);
        assert!(!ev.is_empty());
    }

    #[test]
    fn repeated_failures_fail_over_to_backup() {
        let mut o = orch();
        o.handle(Request::Connect);
        // Two candidates work (so there is a backup to fail over to).
        o.next_candidate();
        o.record_probe(1, true, 1000); // becomes active
        o.record_probe(2, true, 1200); // scored as a backup
        let active_before = o.status().strategy.clone();
        // Drive failures until the monitor advises failover.
        let mut switched = false;
        for _ in 0..5 {
            let ev = o.record_flow(FlowOutcome::Rst);
            if !ev.is_empty() && o.status().strategy != active_before {
                switched = true;
                break;
            }
        }
        assert!(switched, "ardışık başarısızlık yedeğe geçmeli");
        assert_eq!(o.status().state, ConnState::Connected);
    }

    #[test]
    fn forced_strategy_skips_scan() {
        let mut cfg = Config::default();
        cfg.engine.strategy = "split_sni".into();
        let mut o = Orchestrator::new(&cfg, Fingerprint(1), ProfileCache::new());
        o.handle(Request::Connect);
        assert_eq!(o.status().state, ConnState::Connected);
        assert_eq!(o.status().strategy.as_deref(), Some("split_sni"));
    }

    #[test]
    fn partial_accept_connects_and_repair_rescans() {
        let mut o = orch();
        o.handle(Request::Connect);
        let (idx, _) = o.next_candidate_indexed().unwrap();
        o.record_probe(idx, false, 0);
        let ev = o.accept_partial(idx, 900);
        assert_eq!(ev.len(), 1);
        assert_eq!(o.state(), ConnState::Connected);
        assert!(o.active_spec().is_some());
        o.handle(Request::Repair);
        assert_eq!(o.state(), ConnState::Scanning);
        assert!(o.active_spec().is_none());
    }

    #[test]
    fn fault_clears_active() {
        let mut o = orch();
        o.handle(Request::Connect);
        assert_eq!(o.fault().len(), 1);
        assert_eq!(o.state(), ConnState::Fault);
        assert!(o.fault().is_empty());
    }

    #[test]
    fn set_mode_updates_status() {
        let mut o = orch();
        o.handle(Request::SetMode { mode: Mode::Normal });
        assert_eq!(o.status().mode, Mode::Normal);
    }

    #[test]
    fn test_site_reports_via_when_connected() {
        let mut o = orch();
        o.handle(Request::Connect);
        o.next_candidate();
        o.record_probe(1, true, 500);
        let (resp, _) = o.handle(Request::TestSite {
            host: "blocked.example".into(),
        });
        match resp {
            ResponsePayload::SiteTest { test } => {
                assert_eq!(test.host, "blocked.example");
                assert!(test.tls_ok);
                assert!(test.via.is_some());
            }
            _ => panic!("expected SiteTest"),
        }
    }
}
