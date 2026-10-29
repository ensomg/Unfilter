//! The live data plane (Windows): the WinDivert packet engine, the port-53
//! interceptor, and the strategy scan that connects them to the control plane.
//!
//! A supervisor thread follows the [`Orchestrator`]'s state:
//!
//! - **Scanning**: capture is started (engine + DNS), then each ladder
//!   candidate is installed in the engine and checked with live HTTPS probes
//!   against the target set; the first that reaches every target wins. If none
//!   does, the best partial candidate is kept; if nothing reached anything, the
//!   state becomes Fault.
//! - **Connected**: capture runs with the active strategy (failover/forced
//!   changes are picked up on the next tick).
//! - **Ready / Fault**: capture is stopped, so the driver removes its filters
//!   and traffic flows untouched (fail-open).
//!
//! Each capture loop owns its WinDivert handle on its own thread; stopping
//! triggers the handle's [`ShutdownToken`], which unblocks `recv` and lets the
//! loop drop the handle.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use uf_capture::windivert::ShutdownToken;
use uf_capture::{WinDivert, WinDivertError};
use uf_core::{
    DataStrategy, Direction, Engine, Error, PacketBuf, PacketIO, PacketMeta, Strategy, StrategyId,
    StrategySpec,
};
use uf_ipc::{ConnState, Event, ServerMessage};
use uf_probe::targets::{TargetCategory, TargetList};

use crate::config::Config;
use crate::dns::DnsService;
use crate::dnsproxy::{self, Answer, Policy};
use crate::ipc::Clients;
use crate::orchestrator::Orchestrator;
use crate::probe;

/// How often the supervisor re-reads the orchestrator state.
const TICK: Duration = Duration::from_millis(250);
/// DNS interception filter: outbound IPv4/IPv6 UDP queries, never loopback
/// (that is a local resolver talking to itself).
const DNS_FILTER: &str = "outbound and !loopback and udp.DstPort == 53";
/// Above the engine's priority (0), so queries reach the interceptor first;
/// the ones it lets through continue to the engine, which passes them.
const DNS_PRIORITY: i16 = 1;
/// DNS resolver workers (each with its own upstream connections and cache).
const DNS_WORKERS: usize = 4;
/// Queries waiting for a worker before new ones are passed through.
const DNS_QUEUE: usize = 256;
/// Sweep the engine's flow table every this many packets.
const SWEEP_EVERY: u64 = 4096;

/// The strategy the engine thread should run, published by the supervisor.
#[derive(Default)]
struct StrategySlot {
    generation: AtomicU64,
    spec: Mutex<Option<StrategySpec>>,
}

impl StrategySlot {
    /// Publish `spec` if it differs from the current one.
    fn set(&self, spec: Option<StrategySpec>) {
        let mut cur = self.spec.lock().unwrap_or_else(|e| e.into_inner());
        if *cur != spec {
            *cur = spec;
            self.generation.fetch_add(1, Ordering::Release);
        }
    }

    fn build(&self) -> Option<Box<dyn Strategy>> {
        let cur = self.spec.lock().unwrap_or_else(|e| e.into_inner());
        cur.as_ref()
            .map(|s| Box::new(DataStrategy::new(StrategyId(0), s)) as Box<dyn Strategy>)
    }
}

/// A capture loop running on its own thread.
struct Loop {
    token: ShutdownToken,
    thread: JoinHandle<()>,
}

impl Loop {
    /// Open a WinDivert handle on a new thread and run `body` over it. Returns
    /// once the handle is open (or failed to open).
    fn spawn<F>(filter: &'static str, priority: i16, body: F) -> Result<Loop, WinDivertError>
    where
        F: FnOnce(WinDivert) + Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        let thread = thread::spawn(move || match WinDivert::open(filter, priority) {
            Ok(wd) => {
                let _ = tx.send(Ok(wd.shutdown_token()));
                body(wd);
            }
            Err(e) => {
                let _ = tx.send(Err(e));
            }
        });
        match rx.recv() {
            Ok(Ok(token)) => Ok(Loop { token, thread }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(WinDivertError::Open(0))
            }
        }
    }

    /// Shut the handle down and wait for the loop to drop it.
    fn stop(self) {
        self.token.trigger();
        let _ = self.thread.join();
    }
}

/// The running capture: packet engine plus (optionally) DNS interception.
struct Capture {
    engine: Loop,
    dns: Option<Loop>,
}

impl Capture {
    fn start(slot: Arc<StrategySlot>, cfg: &Config) -> Result<Capture, WinDivertError> {
        let engine = Loop::spawn(uf_capture::windivert::DEFAULT_FILTER, 0, move |wd| {
            run_engine(wd, &slot);
        })?;
        let dns = if cfg.dns.enabled {
            let cfg = cfg.clone();
            match Loop::spawn(DNS_FILTER, DNS_PRIORITY, move |wd| run_dns(wd, &cfg)) {
                Ok(l) => Some(l),
                Err(e) => {
                    log(&format!("DNS yakalama açılamadı: {e}"));
                    None
                }
            }
        } else {
            None
        };
        Ok(Capture { engine, dns })
    }

    fn stop(self) {
        if let Some(dns) = self.dns {
            dns.stop();
        }
        self.engine.stop();
    }
}

/// The engine loop: process packets, picking up strategy changes between
/// packets. Ends when the handle is shut down.
fn run_engine(wd: WinDivert, slot: &StrategySlot) {
    let mut engine = Engine::new(wd);
    let mut seen_gen = u64::MAX;
    let mut packets: u64 = 0;
    loop {
        let generation = slot.generation.load(Ordering::Acquire);
        if generation != seen_gen {
            seen_gen = generation;
            engine.set_strategy(slot.build());
        }
        match engine.step() {
            Err(Error::Shutdown) => break,
            _ => {
                packets += 1;
                if packets % SWEEP_EVERY == 0 {
                    engine.sweep();
                }
            }
        }
    }
}

/// The port-53 loop: answer A/AAAA from the trusted resolver, blank out
/// SVCB/HTTPS, let everything else (and every failure) through unchanged.
///
/// The receive thread only parses; queries that need a resolver go to a small
/// worker pool so one slow upstream never stalls the rest. Each worker owns a
/// resolver and a send-only WinDivert handle (filter `false`, same priority).
fn run_dns(mut wd: WinDivert, cfg: &Config) {
    let (tx, rx) = mpsc::sync_channel::<(Vec<u8>, PacketMeta)>(DNS_QUEUE);
    let rx = Arc::new(Mutex::new(rx));
    let mut workers = 0;
    for _ in 0..DNS_WORKERS {
        let (rx, cfg) = (Arc::clone(&rx), cfg.clone());
        let (ready_tx, ready_rx) = mpsc::channel();
        thread::spawn(move || dns_worker(&rx, &cfg, &ready_tx));
        if ready_rx.recv().unwrap_or(false) {
            workers += 1;
        }
    }
    if workers == 0 {
        log("DNS yakalama: çözümleyici kurulamadı, sorgular olduğu gibi geçiyor");
    }

    let mut buf = PacketBuf::new();
    loop {
        let meta = match wd.recv(&mut buf) {
            Ok(m) => m,
            Err(Error::Shutdown) => return, // dropping `tx` stops the workers
            Err(_) => continue,
        };
        let wanted = workers > 0
            && dnsproxy::parse_query(buf.as_slice()).is_some_and(|q| q.policy() != Policy::Pass);
        // Queue full or not ours: pass it on unchanged (fail-open).
        if !wanted || tx.try_send((buf.as_slice().to_vec(), meta)).is_err() {
            let _ = wd.send(buf.as_slice(), &meta);
        }
    }
}

/// One DNS worker: resolve queued queries and inject the replies.
fn dns_worker(
    rx: &Mutex<mpsc::Receiver<(Vec<u8>, PacketMeta)>>,
    cfg: &Config,
    ready: &mpsc::Sender<bool>,
) {
    let (Some(dns), Ok(mut out)) = (
        DnsService::build(cfg),
        WinDivert::open("false", DNS_PRIORITY),
    ) else {
        let _ = ready.send(false);
        return;
    };
    let _ = ready.send(true);
    loop {
        let job = rx.lock().unwrap_or_else(|e| e.into_inner()).recv();
        let Ok((pkt, meta)) = job else {
            return; // capture stopped
        };
        let reply = dnsproxy::parse_query(&pkt).and_then(|q| {
            let answer = match q.policy() {
                Policy::Resolve => dns.answer(&q.name, q.qtype)?,
                Policy::Empty => Answer::Addrs(Vec::new()),
                Policy::Pass => return None,
            };
            Some(dnsproxy::build_reply(&q, &answer))
        });
        let sent = reply.is_some_and(|r| {
            let mut m = meta;
            m.direction = Direction::Inbound;
            m.impostor = false;
            m.loopback = false;
            m.checksums_valid = false;
            out.send(&r, &m).is_ok()
        });
        if !sent {
            let _ = out.send(&pkt, &meta);
        }
    }
}

/// One probe host per category: the scan's target set.
fn scan_targets() -> Vec<String> {
    let list = TargetList::builtin();
    [
        TargetCategory::Generic,
        TargetCategory::Social,
        TargetCategory::Video,
        TargetCategory::Messaging,
        TargetCategory::News,
    ]
    .iter()
    .filter_map(|&c| list.in_category(c).next().map(str::to_string))
    .collect()
}

/// Service-side log line (stderr in console mode; discarded under the SCM).
fn log(msg: &str) {
    eprintln!("uf-service: {msg}");
}

/// Owns the data plane and keeps it in step with the orchestrator.
pub struct Runtime {
    orch: Arc<Mutex<Orchestrator>>,
    clients: Clients,
    cfg: Config,
    cache_path: PathBuf,
    slot: Arc<StrategySlot>,
    capture: Option<Capture>,
}

impl Runtime {
    /// Build a runtime over the shared control plane.
    pub fn new(
        orch: Arc<Mutex<Orchestrator>>,
        clients: Clients,
        cfg: Config,
        cache_path: PathBuf,
    ) -> Runtime {
        Runtime {
            orch,
            clients,
            cfg,
            cache_path,
            slot: Arc::new(StrategySlot::default()),
            capture: None,
        }
    }

    /// Run the supervisor on a background thread for the service's lifetime.
    pub fn spawn(self) -> JoinHandle<()> {
        thread::spawn(move || self.supervise())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Orchestrator> {
        self.orch.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn broadcast(&self, events: Vec<Event>) {
        for event in events {
            self.clients.broadcast(&ServerMessage::Event { event });
        }
    }

    fn supervise(mut self) {
        loop {
            let state = self.lock().state();
            match state {
                ConnState::Scanning => {
                    if self.ensure_capture() {
                        self.scan();
                    }
                }
                ConnState::Connected => {
                    if self.ensure_capture() {
                        let spec = self.lock().active_spec();
                        self.slot.set(spec);
                    }
                }
                _ => self.stop_capture(),
            }
            thread::sleep(TICK);
        }
    }

    /// Start capture if it is not running. On failure the control plane goes
    /// to Fault (the user sees it and can Repair once the cause is fixed).
    fn ensure_capture(&mut self) -> bool {
        if self.capture.is_some() {
            return true;
        }
        match Capture::start(Arc::clone(&self.slot), &self.cfg) {
            Ok(c) => {
                self.capture = Some(c);
                true
            }
            Err(e) => {
                log(&format!(
                    "paket yakalama başlatılamadı ({e}); yönetici hakları ve WinDivert sürücüsü gerekir"
                ));
                let events = self.lock().fault();
                self.broadcast(events);
                false
            }
        }
    }

    fn stop_capture(&mut self) {
        if let Some(c) = self.capture.take() {
            c.stop();
            self.slot.set(None);
        }
    }

    /// Walk the ladder until a candidate reaches every target, the user
    /// cancels (state leaves Scanning), or the ladder runs out.
    fn scan(&mut self) {
        let targets = scan_targets();
        // Best partial candidate: (successes, -latency) ordering.
        let mut best: Option<(usize, usize, u32)> = None;
        loop {
            let Some((idx, cand)) = self.lock().next_candidate_indexed() else {
                break;
            };
            self.slot.set(Some(cand.spec.clone()));
            // Two failures rule a candidate out (one could be a flaky site).
            let sweep = probe::sweep(&targets, probe::SCAN_TIMEOUT, 2);
            let (ok, latency, all_ok) = (sweep.ok, sweep.latency_us, sweep.all_ok());
            log(&format!(
                "tarama: {} -> {}/{} hedef",
                cand.spec.name, ok, sweep.total
            ));
            if ok > 0 && best.is_none_or(|(_, n, l)| ok > n || (ok == n && latency < l)) {
                best = Some((idx, ok, latency));
            }
            let events = self.lock().record_probe(idx, all_ok, latency);
            self.broadcast(events);
            if self.lock().state() != ConnState::Scanning {
                break;
            }
        }

        let events = {
            let mut orch = self.lock();
            if orch.state() != ConnState::Scanning {
                Vec::new()
            } else if let Some((idx, _, latency)) = best {
                orch.accept_partial(idx, latency)
            } else {
                orch.scan_exhausted()
            }
        };
        self.broadcast(events);
        if let Err(e) = self.lock().cache().save(&self.cache_path) {
            log(&format!("profil önbelleği kaydedilemedi: {e}"));
        }
    }
}
