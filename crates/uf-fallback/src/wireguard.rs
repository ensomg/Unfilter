//! Userspace WireGuard upstream — **interface and config only in v1**.
//!
//! This module compiles only with the `wireguard` feature. It defines the shape
//! of the upstream so configs and the service wiring are forward compatible, but
//! performs no cryptographic handshake: [`connect`](crate::Fallback::connect)
//! returns [`NotAvailable`](crate::FallbackError::NotAvailable).
//!
//! The v2 implementation plan: a userspace Noise IK handshake (Curve25519 /
//! ChaCha20-Poly1305 / BLAKE2s) against the configured peer, then an in-process
//! TUN-less relay that encapsulates only the IP-blocked target's packets. It
//! stays userspace (no kernel module, no admin WireGuard install) to keep the
//! "zero-config, no driver" promise; the keys come from the user's supplied
//! config. None of that runs on the default path — like every fallback, it is
//! consulted only for a target the prober marked IP-blocked.

use crate::config::WireguardConfig;
use crate::error::{FallbackError, Result};
use crate::fallback::{Fallback, FallbackKind, Handshake};
use crate::target::Target;

/// A configured userspace WireGuard upstream. Built from
/// [`UpstreamConfig::Wireguard`](crate::config::UpstreamConfig::Wireguard).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardUpstream {
    /// The peer and key material.
    pub config: WireguardConfig,
}

impl WireguardUpstream {
    /// Wrap a validated config. Validation beyond the serde shape (key lengths,
    /// endpoint reachability) is deferred to the v2 handshake.
    pub fn new(config: WireguardConfig) -> Self {
        WireguardUpstream { config }
    }
}

impl Fallback for WireguardUpstream {
    fn kind(&self) -> FallbackKind {
        FallbackKind::Wireguard
    }

    /// Always [`NotAvailable`](FallbackError::NotAvailable) in v1. This is an
    /// explicit, non-panicking "not implemented yet" (no `todo!`/`unimplemented!`):
    /// the service treats it like any other upstream that cannot serve a target
    /// and moves on, so enabling the feature never risks a crash.
    fn connect(&self, _target: &Target) -> Result<Box<dyn Handshake>> {
        Err(FallbackError::NotAvailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Endpoint;

    fn cfg() -> WireguardConfig {
        WireguardConfig {
            private_key: "A".repeat(44),
            peer_public_key: "B".repeat(44),
            preshared_key: None,
            endpoint: Endpoint {
                host: "vpn.example".into(),
                port: 51820,
            },
            persistent_keepalive_secs: Some(25),
        }
    }

    #[test]
    fn kind_is_wireguard() {
        assert_eq!(
            WireguardUpstream::new(cfg()).kind(),
            FallbackKind::Wireguard
        );
    }

    #[test]
    fn connect_is_not_available_not_panic() {
        let u = WireguardUpstream::new(cfg());
        // The whole point: no panic, a clean typed error the caller can handle.
        assert_eq!(
            u.connect(&Target::domain("x.example", 443)).err(),
            Some(FallbackError::NotAvailable)
        );
    }
}
