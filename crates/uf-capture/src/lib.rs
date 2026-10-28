//! Packet capture backends: concrete [`PacketIO`](uf_core::PacketIO)
//! implementations for each platform.
//!
//! v1 ships Windows only, over WinDivert 2.2 (see ADR 002). The engine in
//! `uf-core` never names this crate directly; it is wired to a backend at
//! start-up. This keeps `uf-core` operating-system independent.

pub use uf_core::{Direction, PacketBuf, PacketIO, PacketMeta};

// The WinDivert backend is the only place `unsafe` is permitted in this crate:
// it is an FFI boundary (ADR 002). Every unsafe block inside carries a SAFETY
// note (enforced by `clippy::undocumented_unsafe_blocks`).
#[cfg(windows)]
#[allow(unsafe_code)]
pub mod windivert;

#[cfg(windows)]
pub use windivert::{WinDivert, WinDivertError};
