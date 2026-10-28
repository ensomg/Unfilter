//! The engine: receive a packet, decide its fate, inject the result.
//!
//! Two modes share one control loop and one guarantee — any error or
//! unhandled case re-injects the packet **unchanged** (fail-open):
//!
//! - **Passthrough** ([`Engine::new`]): every packet is re-injected verbatim.
//!   This is the F1 "bit-for-bit identical" baseline and the state the engine
//!   returns to whenever no strategy is active.
//! - **Active strategy** ([`Engine::set_strategy`]): the first payload-bearing
//!   outbound TCP segment of each flow is handed to a [`Strategy`], which may
//!   rewrite it into several packets (split/fake/disorder/…). Every other
//!   packet — later segments, inbound traffic, non-TCP, anything the strategy
//!   passes on — is re-injected unchanged.

use crate::flow::{FlowKey, FlowPhase, FlowTable, Protocol};
use crate::io::{Direction, PacketBuf, PacketIO};
use crate::net;
use crate::strategy::{Emitter, FlowCtx, Strategy, Verdict};
use crate::{Error, Result};

/// Counters exposed for the status UI and the performance report. Plain values,
/// updated on the hot path without locks (the engine owns them).
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    /// Packets received from the backend.
    pub seen: u64,
    /// Packets re-injected unchanged.
    pub passed: u64,
    /// Original packets replaced by a strategy's output.
    pub rewritten: u64,
    /// Replacement packets injected by a strategy.
    pub emitted: u64,
    /// Packets passed through because of a non-fatal error (fail-open).
    pub failed_open: u64,
}

/// How long a flow may sit idle before the table reclaims it (engine ticks).
const FLOW_TTL_TICKS: u64 = 120_000;

/// Drives a [`PacketIO`] backend: receive, decide, inject.
pub struct Engine<IO: PacketIO> {
    io: IO,
    scratch: PacketBuf,
    stats: Stats,
    flows: FlowTable,
    emitter: Emitter,
    strategy: Option<Box<dyn Strategy>>,
    /// Monotonic per-packet tick, used as the flow table's clock (no wall clock
    /// on the hot path; deterministic in tests).
    tick: u64,
}

impl<IO: PacketIO> Engine<IO> {
    /// Build an engine in passthrough mode over the given I/O backend.
    pub fn new(io: IO) -> Self {
        Engine {
            io,
            scratch: PacketBuf::new(),
            stats: Stats::default(),
            flows: FlowTable::new(crate::flow::DEFAULT_CAPACITY, FLOW_TTL_TICKS),
            emitter: Emitter::new(),
            strategy: None,
            tick: 0,
        }
    }

    /// Install (or replace) the active strategy. Pass `None` to return to
    /// passthrough. Existing flows that were already acted on are unaffected;
    /// new flows use the new strategy.
    pub fn set_strategy(&mut self, strategy: Option<Box<dyn Strategy>>) {
        self.strategy = strategy;
    }

    /// Whether a strategy is currently active.
    pub fn is_active(&self) -> bool {
        self.strategy.is_some()
    }

    /// Current counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Number of flows currently tracked.
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Process exactly one packet: receive it and decide its fate.
    ///
    /// Returns `Ok(())` after handling one packet, or [`Error::Shutdown`] when
    /// the backend has stopped. Any other per-packet error becomes a
    /// pass-through (fail-open), never a propagated failure.
    pub fn step(&mut self) -> Result<()> {
        let meta = match self.io.recv(&mut self.scratch) {
            Ok(meta) => meta,
            Err(Error::Shutdown) => return Err(Error::Shutdown),
            // Nothing valid to re-inject: move on.
            Err(_) => return Ok(()),
        };
        self.stats.seen += 1;
        self.tick += 1;

        if self.decide_and_inject(&meta) {
            return Ok(());
        }
        // Fallback arm: re-inject the original unchanged.
        match self.io.send(self.scratch.as_slice(), &meta) {
            Ok(()) => self.stats.passed += 1,
            Err(_) => self.stats.failed_open += 1,
        }
        Ok(())
    }

    /// Returns `true` once the packet has been fully handled (rewritten or
    /// deliberately dropped); `false` means "pass it through unchanged".
    fn decide_and_inject(&mut self, meta: &crate::io::PacketMeta) -> bool {
        let Some(strategy) = self.strategy.as_ref() else {
            return false; // passthrough mode
        };
        // Only outbound TCP flows are candidates; everything else passes.
        if meta.direction != Direction::Outbound {
            return false;
        }
        let Some(ep) = net::tcp_endpoints(self.scratch.as_slice()) else {
            return false;
        };
        let key = FlowKey {
            protocol: Protocol::Tcp,
            src_ip: ep.src_ip,
            dst_ip: ep.dst_ip,
            src_port: ep.src_port,
            dst_port: ep.dst_port,
        };
        let now = self.tick;

        // Does this packet carry application data?
        let has_payload = net::parse_tcp(self.scratch.as_slice())
            .map(|l| l.payload_len > 0)
            .unwrap_or(false);

        let entry = self.flows.get_or_insert(key, now);
        // A flow is reshaped only on its first data segment; afterwards it is
        // locked to Pass so the rest of the stream flows normally.
        if entry.phase == FlowPhase::Pass || !has_payload {
            if has_payload {
                entry.payload_packets = entry.payload_packets.saturating_add(1);
            }
            return false;
        }
        let payload_index = entry.payload_packets;
        entry.payload_packets = entry.payload_packets.saturating_add(1);
        entry.phase = FlowPhase::Pass; // acted (or decided to pass) once
        entry.strategy = Some(0);

        let ctx = FlowCtx {
            key: &key,
            meta,
            payload_index,
        };
        self.emitter.reset();
        let verdict = strategy.apply(&ctx, self.scratch.as_slice(), &mut self.emitter);
        match verdict {
            Verdict::Pass => false,
            Verdict::Drop => true, // handled: inject nothing
            Verdict::Emitted => {
                self.stats.rewritten += 1;
                let mut all_ok = true;
                for pkt in self.emitter.packets() {
                    match self.io.send(pkt.bytes(), pkt.meta()) {
                        Ok(()) => self.stats.emitted += 1,
                        Err(_) => {
                            self.stats.failed_open += 1;
                            all_ok = false;
                        }
                    }
                }
                // If we emitted nothing (empty plan), fall back to passthrough.
                !self.emitter.is_empty() || all_ok
            }
        }
    }

    /// Expire idle flows. Called periodically off the hot path.
    pub fn sweep(&mut self) {
        self.flows.expire(self.tick);
    }

    /// Run until the backend shuts down. On `Shutdown` the loop ends cleanly;
    /// the caller then drops the backend, which tears down capture (fail-open).
    pub fn run(&mut self) {
        while self.step().is_ok() {}
    }

    /// Consume the engine and return its backend (for shutdown/teardown).
    pub fn into_io(self) -> IO {
        self.io
    }
}
