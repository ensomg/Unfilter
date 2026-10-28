//! The [`Fallback`] abstraction: an upstream that can carry a connection to a
//! specific target, and the [`Handshake`] state machine the caller drives to
//! establish that connection.
//!
//! The split is deliberate and the whole reason v1 needs no network: a
//! [`Fallback`] turns a [`Target`] into a [`Handshake`], and a `Handshake` is a
//! *pure* byte pump — feed it what arrived from the upstream, it tells you what
//! to send next and when the tunnel is up. The service (v2) owns the socket and
//! the byte copying after that; it implements neither trait, it just drives them.

use crate::error::Result;
use crate::target::Target;

/// Which concrete upstream a [`Fallback`] is. Lets the service log and the UI
/// show the route a target took without downcasting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackKind {
    /// SOCKS5 proxy (RFC 1928).
    Socks5,
    /// HTTP proxy via the `CONNECT` method.
    HttpConnect,
    /// Userspace WireGuard peer (interface only in v1).
    Wireguard,
}

/// One step of a handshake: bytes to send to the upstream now, and whether the
/// tunnel is established. When `established` is true the caller stops pumping and
/// starts relaying application bytes; `send` is normally empty at that point.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandshakeStep {
    /// Bytes the caller must write to the upstream. May be empty (still waiting
    /// for more of the upstream's reply).
    pub send: Vec<u8>,
    /// Whether the tunnel is now open end-to-end.
    pub established: bool,
}

impl HandshakeStep {
    /// A step that sends `bytes` and is not yet established.
    pub fn send(bytes: Vec<u8>) -> Self {
        HandshakeStep {
            send: bytes,
            established: false,
        }
    }

    /// A step that sends nothing and waits for more upstream bytes.
    pub fn wait() -> Self {
        HandshakeStep::default()
    }

    /// A step that reports the tunnel is established.
    pub fn established() -> Self {
        HandshakeStep {
            send: Vec::new(),
            established: true,
        }
    }
}

/// A client-side proxy/tunnel handshake, driven as a pure state machine.
///
/// Usage (the service's relay loop, v2):
/// 1. call [`pump`](Handshake::pump) with an empty slice to get the opening bytes,
/// 2. write those bytes, read the upstream's reply,
/// 3. call `pump` again with what was read; repeat until a step reports
///    [`established`](HandshakeStep::established).
///
/// Implementations buffer internally, so a reply split across several reads is
/// fine: a short read yields [`HandshakeStep::wait`], never an error.
pub trait Handshake {
    /// Advance the handshake with bytes just received from the upstream (empty on
    /// the first call). Returns the next bytes to send and whether the tunnel is
    /// open, or an error if the upstream rejected the connection.
    fn pump(&mut self, from_upstream: &[u8]) -> Result<HandshakeStep>;

    /// Whether the handshake has completed successfully.
    fn established(&self) -> bool;

    /// Bytes the upstream sent after its handshake reply, in the same read.
    /// They already belong to the tunnelled stream, so the relay must deliver
    /// them to the client before anything it reads next. Empty until the
    /// handshake is established; drained by the call.
    fn take_leftover(&mut self) -> Vec<u8> {
        Vec::new()
    }
}

/// An upstream that can carry a connection to a target.
///
/// The service consults a `Fallback` **only** for a target the prober marked
/// [`IpBlocked`](crate::target::TargetVerdict::IpBlocked) while the feature is
/// enabled, so an implementation that does real work never runs on the default
/// path.
pub trait Fallback {
    /// Which kind of upstream this is.
    fn kind(&self) -> FallbackKind;

    /// Begin a connection to `target` through this upstream, returning the
    /// handshake to drive. Returns [`NotAvailable`](crate::FallbackError::NotAvailable)
    /// if this upstream cannot serve the target in this build (e.g. the WireGuard
    /// upstream in v1).
    fn connect(&self, target: &Target) -> Result<Box<dyn Handshake>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_constructors() {
        assert_eq!(
            HandshakeStep::send(vec![1, 2]),
            HandshakeStep {
                send: vec![1, 2],
                established: false
            }
        );
        assert!(HandshakeStep::wait().send.is_empty());
        assert!(!HandshakeStep::wait().established);
        assert!(HandshakeStep::established().established);
        assert!(HandshakeStep::established().send.is_empty());
    }
}
