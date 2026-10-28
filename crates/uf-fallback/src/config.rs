//! Client configuration for the fallback, modelled as serde data (same approach
//! as `StrategySpec` and the DNS provider list in `uf-core`/`uf-dns`): the
//! service loads it, the UI edits it, nothing here does I/O.
//!
//! The whole feature is **off by default** — [`FallbackConfig::default`] has
//! `enabled = false` and no upstreams — and enabling it is an explicit user
//! opt-in (flipping [`enabled`](FallbackConfig::enabled) and supplying at least
//! one endpoint).

use serde::{Deserialize, Serialize};

/// Top-level fallback configuration.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FallbackConfig {
    /// Master switch. **Default `false`.** While false the fallback is never
    /// consulted, whatever the prober decides (see
    /// [`should_use_fallback`](crate::target::should_use_fallback)).
    pub enabled: bool,
    /// User-supplied upstreams, tried in order for an IP-blocked target. Empty by
    /// default; a non-empty list is required for [`enabled`](Self::enabled) to
    /// have any effect.
    pub upstreams: Vec<UpstreamConfig>,
}

impl FallbackConfig {
    /// Whether the fallback is usable: opted in *and* at least one upstream
    /// configured. An `enabled = true` with no upstreams is a no-op, not an error
    /// (fail-open: the user's other traffic is unaffected).
    pub fn is_usable(&self) -> bool {
        self.enabled && !self.upstreams.is_empty()
    }
}

/// One upstream the fallback can route an IP-blocked target through.
///
/// Tagged by `type` so a config file reads naturally, e.g.
/// `{ "type": "socks5", "endpoint": { "host": "127.0.0.1", "port": 1080 } }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UpstreamConfig {
    /// A SOCKS5 proxy (RFC 1928), optionally with username/password auth.
    Socks5 {
        /// Proxy endpoint.
        endpoint: Endpoint,
        /// Optional username/password credentials (RFC 1929).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<UserPass>,
    },
    /// An HTTP proxy reached with the `CONNECT` method, optionally with Basic
    /// proxy authentication.
    HttpConnect {
        /// Proxy endpoint.
        endpoint: Endpoint,
        /// Optional Basic-auth credentials.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        auth: Option<UserPass>,
    },
    /// A userspace WireGuard peer. **Interface and config only in v1** — see
    /// [`crate::wireguard`]. Present in the schema so configs are forward
    /// compatible; building it yields [`NotAvailable`](crate::FallbackError::NotAvailable)
    /// until the v2 handshake lands.
    Wireguard(WireguardConfig),
}

/// A host/port endpoint. `host` may be a name or a literal IP; it is the
/// user-supplied proxy address, resolved by the service, never by the core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Hostname or IP literal of the proxy.
    pub host: String,
    /// TCP port of the proxy.
    pub port: u16,
}

/// Username/password credentials (SOCKS5 RFC 1929 / HTTP Basic). Both fields are
/// limited to 255 bytes by the SOCKS5 encoding; over-long values are rejected at
/// encode time with [`FieldTooLong`](crate::FallbackError::FieldTooLong).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserPass {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
}

/// Userspace WireGuard client configuration (interface definition only in v1).
///
/// Keys are Curve25519, base64-encoded as in a standard `wg` config. The v1 build
/// stores and validates the shape but performs no handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireguardConfig {
    /// Our private key (base64, 44 chars).
    pub private_key: String,
    /// The peer's public key (base64, 44 chars).
    pub peer_public_key: String,
    /// Optional pre-shared key (base64).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    /// Peer endpoint (`host:port`) the tunnel connects to.
    pub endpoint: Endpoint,
    /// Optional keepalive interval in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_keepalive_secs: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_off_and_unusable() {
        let c = FallbackConfig::default();
        assert!(!c.enabled);
        assert!(c.upstreams.is_empty());
        assert!(!c.is_usable());
    }

    #[test]
    fn enabled_without_upstreams_is_not_usable() {
        let c = FallbackConfig {
            enabled: true,
            upstreams: vec![],
        };
        assert!(!c.is_usable());
    }

    #[test]
    fn missing_fields_default_to_off() {
        // A config file that omits the fallback block entirely deserialises to
        // the default (off), thanks to `#[serde(default)]`.
        let c: FallbackConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(c, FallbackConfig::default());
    }

    #[test]
    fn socks5_upstream_roundtrips() {
        let json = r#"{
            "enabled": true,
            "upstreams": [
                { "type": "socks5", "endpoint": { "host": "127.0.0.1", "port": 1080 } },
                { "type": "http_connect",
                  "endpoint": { "host": "proxy.example", "port": 8080 },
                  "auth": { "username": "u", "password": "p" } }
            ]
        }"#;
        let c: FallbackConfig = serde_json::from_str(json).unwrap();
        assert!(c.is_usable());
        assert_eq!(c.upstreams.len(), 2);
        match &c.upstreams[0] {
            UpstreamConfig::Socks5 { endpoint, auth } => {
                assert_eq!(endpoint.port, 1080);
                assert!(auth.is_none());
            }
            other => panic!("expected socks5, got {other:?}"),
        }
        // Round-trips back to equal data.
        let back: FallbackConfig =
            serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(c, back);
    }
}
