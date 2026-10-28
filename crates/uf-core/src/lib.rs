//! Platform-independent strategy engine, flow table and desync actions.
//!
//! `uf-core` contains no OS calls and no async runtime. All packet I/O enters
//! through the [`PacketIO`] trait, so platform adapters (WinDivert on Windows,
//! nfqueue/eBPF on Linux, NetworkExtension on macOS, VpnService on Android) are
//! added later as new trait implementations without touching this crate.
//!
//! The hot path performs no per-packet heap allocation: buffers come from a
//! pre-sized [`BufferPool`], parsers borrow `&[u8]` slices, and the flow table
//! is a fixed-capacity LRU with TTL.

pub mod action;
pub mod classify;
pub mod engine;
pub mod error;
pub mod flow;
pub mod io;
pub mod parse;
pub mod strategy;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use action::{DesyncAction, FakeKind, Fooling, SplitPos, TtlSpec};
pub use classify::{Classification, L7Proto, TargetCategory};
pub use engine::Engine;
pub use error::{Error, Result};
pub use flow::{Clock, FlowKey, FlowPhase, FlowTable, Protocol};
pub use io::{BufferPool, Direction, MAX_PACKET, PacketBuf, PacketIO, PacketMeta};
pub use strategy::{Emitter, Strategy, StrategyId, StrategySpec, Verdict};
