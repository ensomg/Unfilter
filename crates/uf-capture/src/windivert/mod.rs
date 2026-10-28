//! Safe WinDivert backend: a [`PacketIO`] that captures the configured flows,
//! hands them to the engine, and re-injects the result.
//!
//! Fail-open is layered:
//! 1. Any per-packet error becomes a pass-through (handled by the engine).
//! 2. On [`Drop`] the handle is shut down and closed, so the driver removes its
//!    filter and traffic flows normally — this also covers `panic = "abort"`
//!    and an outright process kill (the OS closes the handle on exit).
//! 3. A [`ShutdownToken`] lets a watchdog thread force (2) if the capture thread
//!    wedges.

pub mod ffi;

use core::fmt;

use ffi::{
    Address, Api, ERROR_INVALID_HANDLE, ERROR_NO_DATA, ERROR_OPERATION_ABORTED, Handle, LoadError,
    MTU_MAX,
};
use uf_core::error::{Error, Result};
use uf_core::io::{Direction, PacketBuf, PacketIO, PacketMeta};

pub use ffi::ShutdownToken;

/// Default capture filter (WinDivert filter language): outbound TCP 80/443,
/// UDP 443 (QUIC) and 53 (DNS), plus the high UDP range Discord voice uses.
/// Everything else never enters the driver (master prompt §5.1).
pub const DEFAULT_FILTER: &str = "outbound and \
     ((tcp and (tcp.DstPort == 80 or tcp.DstPort == 443)) or \
      (udp and (udp.DstPort == 443 or udp.DstPort == 53 or \
                (udp.DstPort >= 50000 and udp.DstPort <= 65535))))";

/// Errors from opening the WinDivert backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WinDivertError {
    /// The DLL could not be loaded or a symbol was missing.
    Load(LoadError),
    /// `WinDivertOpen` failed; carries the OS error code (5 = not elevated,
    /// 2 = driver files missing, 1275 = driver blocked).
    Open(u32),
}

impl fmt::Display for WinDivertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WinDivertError::Load(e) => write!(f, "failed to load WinDivert: {e:?}"),
            WinDivertError::Open(code) => write!(f, "WinDivertOpen failed (os code {code})"),
        }
    }
}

impl std::error::Error for WinDivertError {}

/// An open WinDivert capture handle driving the engine.
pub struct WinDivert {
    api: Api,
    handle: Handle,
    /// Owns the handle's lifetime; `Drop` closes through it.
    token: ShutdownToken,
    /// Receive buffer sized for the largest packet WinDivert can deliver. A
    /// smaller buffer would make the driver swallow oversized (LSO) segments,
    /// which breaks fail-open for large uploads.
    rx: Box<[u8]>,
    /// Scratch copy used to recompute checksums before injecting.
    tx: Box<[u8]>,
}

impl WinDivert {
    /// Open the backend with the [`DEFAULT_FILTER`] at the default priority.
    pub fn open_default() -> std::result::Result<Self, WinDivertError> {
        Self::open(DEFAULT_FILTER, 0)
    }

    /// Open the backend with a custom filter and priority. Requires the signed
    /// WinDivert driver installed next to the executable and administrator
    /// rights.
    pub fn open(filter: &str, priority: i16) -> std::result::Result<Self, WinDivertError> {
        let api = Api::load().map_err(WinDivertError::Load)?;
        // SAFETY: a freshly loaded API; `open` validates the handle and reports
        // the OS error code on failure.
        let handle = unsafe { api.open(filter, priority, 0) }.map_err(WinDivertError::Open)?;
        // SAFETY: `handle` was just opened and is closed only via this token.
        let token = unsafe { api.token(handle) };
        Ok(WinDivert {
            api,
            handle,
            token,
            rx: vec![0u8; MTU_MAX].into_boxed_slice(),
            tx: vec![0u8; MTU_MAX].into_boxed_slice(),
        })
    }

    /// A token the fail-open watchdog can use to shut this handle down from
    /// another thread.
    pub fn shutdown_token(&self) -> ShutdownToken {
        self.token.clone()
    }

    fn meta_from(addr: &Address, captured_at_nanos: u64) -> PacketMeta {
        PacketMeta {
            direction: if addr.outbound() {
                Direction::Outbound
            } else {
                Direction::Inbound
            },
            if_index: addr.if_idx(),
            sub_if_index: addr.sub_if_idx(),
            loopback: addr.loopback(),
            impostor: addr.impostor(),
            ipv6: addr.ipv6(),
            // With checksum offload an outbound packet is captured before the
            // NIC fills its checksums, and the driver says so via these bits.
            // Claiming "valid" on re-inject would put a bad checksum on the
            // wire, so report what was captured; `send` recomputes otherwise.
            checksums_valid: checksums_valid(addr),
            captured_at_nanos,
        }
    }

    fn addr_from(meta: &PacketMeta) -> Address {
        let mut addr = Address::zeroed();
        addr.set_flags(
            matches!(meta.direction, Direction::Outbound),
            meta.loopback,
            meta.impostor,
            meta.ipv6,
        );
        addr.set_network(meta.if_index, meta.sub_if_index);
        addr.set_checksums_valid(meta.checksums_valid);
        addr
    }
}

/// Whether every checksum the packet carries was valid as captured. IPv6 has
/// no header checksum; a packet is TCP or UDP, so one transport bit suffices.
fn checksums_valid(addr: &Address) -> bool {
    (addr.ipv6() || addr.ip_checksum()) && (addr.tcp_checksum() || addr.udp_checksum())
}

impl PacketIO for WinDivert {
    fn recv(&mut self, buf: &mut PacketBuf) -> Result<PacketMeta> {
        loop {
            // SAFETY: `self.handle` is open until `Drop`; `self.rx` is a
            // writable buffer of MTU_MAX bytes for WinDivert to fill.
            let (len, addr) = match unsafe { self.api.recv(self.handle, &mut self.rx) } {
                Ok(got) => got,
                Err(ERROR_NO_DATA | ERROR_INVALID_HANDLE | ERROR_OPERATION_ABORTED) => {
                    return Err(Error::Shutdown);
                }
                Err(code) => return Err(Error::Io(code)),
            };
            let pkt = self.rx.get(..len as usize).ok_or(Error::OutOfBounds)?;
            if buf.set(pkt).is_ok() {
                return Ok(Self::meta_from(&addr, 0));
            }
            // Larger than the engine's buffers (an LSO super-segment or jumbo
            // frame): never ours to rewrite. Re-inject it verbatim with its
            // original address and wait for the next packet (fail-open).
            // SAFETY: `self.handle` is open; `pkt` and `addr` are exactly what
            // the driver just handed us.
            let _ = unsafe { self.api.send(self.handle, pkt, &addr) };
        }
    }

    fn send(&mut self, pkt: &[u8], meta: &PacketMeta) -> Result<()> {
        let mut addr = Self::addr_from(meta);
        let out: &[u8] = if meta.checksums_valid {
            pkt
        } else {
            let tx = self.tx.get_mut(..pkt.len()).ok_or(Error::Capacity)?;
            tx.copy_from_slice(pkt);
            if self.api.calc_checksums(tx, &mut addr) {
                addr.set_checksums_valid(true);
            }
            tx
        };
        // SAFETY: `self.handle` is open; `out` is a valid read-only slice; the
        // address was built to match it.
        match unsafe { self.api.send(self.handle, out, &addr) } {
            Ok(_) => Ok(()),
            Err(code) => Err(Error::Io(code)),
        }
    }

    fn shutdown(&mut self) {
        self.token.trigger();
    }
}

impl Drop for WinDivert {
    fn drop(&mut self) {
        // Shutting down then closing removes the driver filter (fail-open).
        self.token.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_filter_is_well_formed_ascii() {
        assert!(DEFAULT_FILTER.is_ascii());
        assert!(DEFAULT_FILTER.contains("tcp.DstPort == 443"));
        assert!(DEFAULT_FILTER.contains("udp.DstPort == 53"));
    }

    #[test]
    fn address_flag_roundtrip() {
        let mut a = Address::zeroed();
        a.set_flags(true, false, true, false);
        a.set_network(12, 3);
        a.set_checksums_valid(true);
        assert!(a.outbound());
        assert!(!a.loopback());
        assert!(a.impostor());
        assert!(!a.ipv6());
        assert_eq!(a.if_idx(), 12);
        assert_eq!(a.sub_if_idx(), 3);
    }

    #[test]
    fn checksum_bits_drive_meta() {
        let mut a = Address::zeroed();
        a.set_flags(true, false, false, false);
        // Offloaded capture: no checksum bit set -> must be recomputed.
        assert!(!WinDivert::meta_from(&a, 0).checksums_valid);
        a.set_checksums_valid(true);
        assert!(a.ip_checksum() && a.tcp_checksum() && a.udp_checksum());
        assert!(WinDivert::meta_from(&a, 0).checksums_valid);
    }

    #[test]
    fn meta_addr_roundtrip() {
        let meta = PacketMeta {
            direction: Direction::Outbound,
            if_index: 9,
            sub_if_index: 1,
            loopback: false,
            impostor: false,
            ipv6: true,
            checksums_valid: true,
            captured_at_nanos: 0,
        };
        let addr = WinDivert::addr_from(&meta);
        let back = WinDivert::meta_from(&addr, 0);
        assert_eq!(back.direction, Direction::Outbound);
        assert_eq!(back.if_index, 9);
        assert_eq!(back.sub_if_index, 1);
        assert!(back.ipv6);
    }
}
