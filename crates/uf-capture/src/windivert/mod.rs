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

use ffi::{Address, Api, ERROR_NO_DATA, Handle, LoadError};
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
    closed: bool,
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
        Ok(WinDivert {
            api,
            handle,
            closed: false,
        })
    }

    /// A token the fail-open watchdog can use to shut this handle down from
    /// another thread.
    pub fn shutdown_token(&self) -> ShutdownToken {
        self.api.token(self.handle)
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
            // As captured the checksums are valid; we only clear this if we
            // later mutate the packet.
            checksums_valid: true,
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

impl PacketIO for WinDivert {
    fn recv(&mut self, buf: &mut PacketBuf) -> Result<PacketMeta> {
        let region = buf.backing_mut();
        // SAFETY: `self.handle` is open until `close`/`Drop`; `region` is a
        // writable buffer of MAX_PACKET bytes for WinDivert to fill.
        match unsafe { self.api.recv(self.handle, region) } {
            Ok((len, addr)) => {
                buf.set_len(len as usize);
                Ok(Self::meta_from(&addr, 0))
            }
            Err(ERROR_NO_DATA) => Err(Error::Shutdown),
            Err(code) => Err(Error::Io(code)),
        }
    }

    fn send(&mut self, pkt: &[u8], meta: &PacketMeta) -> Result<()> {
        let addr = Self::addr_from(meta);
        // SAFETY: `self.handle` is open; `pkt` is a valid read-only slice; the
        // address was built to match it.
        match unsafe { self.api.send(self.handle, pkt, &addr) } {
            Ok(_) => Ok(()),
            Err(code) => Err(Error::Io(code)),
        }
    }

    fn shutdown(&mut self) {
        if !self.closed {
            // SAFETY: `self.handle` is still open here.
            unsafe { self.api.shutdown(self.handle) };
        }
    }
}

impl Drop for WinDivert {
    fn drop(&mut self) {
        if !self.closed {
            self.closed = true;
            // SAFETY: `self.handle` is open and used nowhere after these calls.
            // Shutting down then closing removes the driver filter (fail-open).
            unsafe {
                self.api.shutdown(self.handle);
                self.api.close(self.handle);
            }
        }
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
