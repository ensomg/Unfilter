//! Optional SOCKS5/HTTP CONNECT/WireGuard fallback for IP-blocked targets.
//!
//! Some targets cannot be fixed by DPI manipulation or a DNS fix at all — the
//! operator blocks the destination IP outright. For those, and only those, the
//! user may opt in to route the connection through an upstream tunnel/proxy. This
//! is a **split tunnel**: the fallback is consulted for a single target the
//! prober marked [`IpBlocked`](target::TargetVerdict::IpBlocked), never for
//! normal traffic.
//!
//! Design (master prompt §5.7), consistent with the rest of the workspace:
//!
//! - **Off by default, explicit opt-in.** [`FallbackConfig::default`] is
//!   `enabled = false` with no upstreams, and [`should_use_fallback`] gates every
//!   consultation on both the opt-in and the per-target verdict — so the default
//!   path has *zero* added latency.
//! - **Config as data.** [`config`] mirrors `uf-core`'s serde model: the service
//!   loads it, the UI edits it, nothing here does I/O.
//! - **Pure, testable framing.** [`socks5`] and [`http_connect`] are complete
//!   client codecs plus a pure [`Handshake`] state machine, unit-tested with no
//!   network. The live relay (owning the socket, copying bytes) lands in the
//!   service in v2 and only *drives* the [`Fallback`] / [`Handshake`] traits.
//! - **WireGuard is v1-interface-only.** Behind the `wireguard` feature, [`wireguard`]
//!   defines the upstream and config; its handshake returns a clean
//!   [`NotAvailable`](FallbackError::NotAvailable) (never a `todo!`/panic).
//!
//! This crate depends only on `uf-core` and `serde` — no async runtime, no OS
//! calls — so nothing is pulled into the default data path.

pub mod config;
pub mod error;
pub mod fallback;
pub mod http_connect;
pub mod socks5;
pub mod target;

#[cfg(feature = "wireguard")]
pub mod wireguard;

pub use config::{Endpoint, FallbackConfig, UpstreamConfig, UserPass, WireguardConfig};
pub use error::{FallbackError, Result};
pub use fallback::{Fallback, FallbackKind, Handshake, HandshakeStep};
pub use http_connect::HttpConnectUpstream;
pub use socks5::Socks5Upstream;
pub use target::{ProbeSummary, Target, TargetAddr, TargetVerdict, should_use_fallback};

#[cfg(feature = "wireguard")]
pub use wireguard::WireguardUpstream;

/// Build the ordered list of live upstreams from a [`FallbackConfig`].
///
/// Returns an empty vec when the fallback is not [`usable`](FallbackConfig::is_usable)
/// (off, or no upstreams), so a caller can treat "fallback disabled" and "fallback
/// has nothing to offer" identically — both mean "leave every target direct".
///
/// WireGuard entries are included only when the `wireguard` feature is built;
/// otherwise they are skipped (a build without the feature cannot serve them).
pub fn build_upstreams(config: &FallbackConfig) -> Vec<Box<dyn Fallback>> {
    if !config.is_usable() {
        return Vec::new();
    }
    let mut out: Vec<Box<dyn Fallback>> = Vec::new();
    for up in &config.upstreams {
        match up {
            UpstreamConfig::Socks5 { endpoint, auth } => {
                out.push(Box::new(Socks5Upstream {
                    endpoint: endpoint.clone(),
                    auth: auth.clone(),
                }));
            }
            UpstreamConfig::HttpConnect { endpoint, auth } => {
                out.push(Box::new(HttpConnectUpstream {
                    endpoint: endpoint.clone(),
                    auth: auth.clone(),
                }));
            }
            #[cfg(feature = "wireguard")]
            UpstreamConfig::Wireguard(wg) => {
                out.push(Box::new(WireguardUpstream::new(wg.clone())));
            }
            #[cfg(not(feature = "wireguard"))]
            UpstreamConfig::Wireguard(_) => {
                // Not buildable without the feature; skip it. The target stays
                // direct rather than erroring, keeping the rest of traffic clean.
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_config_builds_no_upstreams() {
        assert!(build_upstreams(&FallbackConfig::default()).is_empty());
        // enabled but empty is still nothing.
        assert!(
            build_upstreams(&FallbackConfig {
                enabled: true,
                upstreams: vec![],
            })
            .is_empty()
        );
    }

    #[test]
    fn builds_socks5_and_http_upstreams_in_order() {
        let config = FallbackConfig {
            enabled: true,
            upstreams: vec![
                UpstreamConfig::Socks5 {
                    endpoint: Endpoint {
                        host: "127.0.0.1".into(),
                        port: 1080,
                    },
                    auth: None,
                },
                UpstreamConfig::HttpConnect {
                    endpoint: Endpoint {
                        host: "proxy.example".into(),
                        port: 8080,
                    },
                    auth: Some(UserPass {
                        username: "u".into(),
                        password: "p".into(),
                    }),
                },
            ],
        };
        let ups = build_upstreams(&config);
        assert_eq!(ups.len(), 2);
        assert_eq!(ups[0].kind(), FallbackKind::Socks5);
        assert_eq!(ups[1].kind(), FallbackKind::HttpConnect);
    }

    #[test]
    fn end_to_end_only_ip_blocked_targets_route_through_fallback() {
        let config = FallbackConfig {
            enabled: true,
            upstreams: vec![UpstreamConfig::Socks5 {
                endpoint: Endpoint {
                    host: "127.0.0.1".into(),
                    port: 1080,
                },
                auth: None,
            }],
        };
        let ups = build_upstreams(&config);

        // A direct target is never offered to an upstream.
        assert!(!should_use_fallback(config.enabled, TargetVerdict::Direct));
        // An IP-blocked target is, and the upstream yields a working handshake.
        assert!(should_use_fallback(
            config.enabled,
            TargetVerdict::IpBlocked
        ));
        let mut hs = ups[0]
            .connect(&Target::domain("blocked.example", 443))
            .unwrap();
        assert_eq!(hs.pump(&[]).unwrap().send, vec![0x05, 0x01, 0x00]);
    }
}
