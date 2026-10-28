//! The engine skeleton.
//!
//! Phase 0 ships the control loop and the fail-open guarantee: every packet is
//! re-injected **unchanged** (the core half of the F1 "bit-for-bit identical"
//! acceptance test). Classification and strategy application are wired in in
//! phases 1–2; the loop structure here does not change.

use crate::error::{Error, Result};
use crate::io::{PacketBuf, PacketIO};

/// Counters exposed for the status UI and the performance report. Plain values,
/// updated on the hot path without locks (the engine owns them).
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    /// Packets received from the backend.
    pub seen: u64,
    /// Packets re-injected unchanged.
    pub passed: u64,
    /// Packets rewritten by a strategy.
    pub rewritten: u64,
    /// Packets passed through because of a non-fatal error (fail-open).
    pub failed_open: u64,
}

/// Drives a [`PacketIO`] backend: receive, decide, inject.
pub struct Engine<IO: PacketIO> {
    io: IO,
    scratch: PacketBuf,
    stats: Stats,
}

impl<IO: PacketIO> Engine<IO> {
    /// Build an engine over the given I/O backend.
    pub fn new(io: IO) -> Self {
        Engine {
            io,
            scratch: PacketBuf::new(),
            stats: Stats::default(),
        }
    }

    /// Current counters.
    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Process exactly one packet: receive it and decide its fate.
    ///
    /// Returns `Ok(())` after handling one packet, or [`Error::Shutdown`] when
    /// the backend has stopped. Phase 0 always passes the packet through
    /// unchanged; any other error on an individual packet is turned into a
    /// pass-through (fail-open) rather than propagated.
    pub fn step(&mut self) -> Result<()> {
        let meta = match self.io.recv(&mut self.scratch) {
            Ok(meta) => meta,
            Err(Error::Shutdown) => return Err(Error::Shutdown),
            // A malformed/truncated capture is not our problem to fix: there is
            // nothing to re-inject, so just move on.
            Err(_) => return Ok(()),
        };
        self.stats.seen += 1;

        // Phase 0: unconditional pass-through. This is where Classify → Apply
        // will hook in; the fail-open default stays as the fallback arm.
        match self.io.send(self.scratch.as_slice(), &meta) {
            Ok(()) => self.stats.passed += 1,
            Err(_) => self.stats.failed_open += 1,
        }
        Ok(())
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
