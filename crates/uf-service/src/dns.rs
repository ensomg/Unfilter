//! Live DNS resolution for the service: builds a [`uf_dns::Resolver`] over the
//! configured trusted upstreams (DoH and DoT, via the embedded [`uf_dns::Doh`]
//! and [`uf_dns::Dot`] transports) and answers queries behind a mutex.
//!
//! The bootstrap IPs are *not* taken from config. Each configured upstream is
//! matched by host name to an embedded [`uf_dns::Provider`] whose pinned IPs
//! live in code (master prompt §5.2), so a tampered config can never repoint the
//! resolver at an attacker's address — it can only pick which known provider and
//! transport (DoH/DoT) to use, and in what order.
//!
//! The resolver policy itself is single-threaded (it owns its cache and id
//! counter), so [`DnsService`] is used from the thread that builds it; the
//! packet-level port-53 interception loop that will feed it live queries is a
//! later, Windows-only iteration.

use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use uf_dns::{Cache, Doh, Dot, PoisonConfig, Provider, QType, Resolver, Transport};

use crate::config::Config;

/// The service's trusted resolver, ready to answer queries.
pub struct DnsService {
    resolver: Mutex<Resolver>,
    /// Human-readable names of the wired upstreams, in order (diagnostics).
    upstreams: Vec<String>,
}

impl DnsService {
    /// Build a resolver from `cfg`. Returns `None` when no configured upstream
    /// matches a known provider (DNS redirection then simply stays off and the
    /// engine still passes traffic through).
    pub fn build(cfg: &Config) -> Option<DnsService> {
        let mut transports: Vec<Box<dyn Transport>> = Vec::new();
        let mut upstreams = Vec::new();
        for u in &cfg.dns.upstreams {
            let Some(provider) = provider_for(&u.host) else {
                continue; // unknown host: no pinned IPs we are willing to trust
            };
            let transport: Box<dyn Transport> = match u.kind.as_str() {
                "doh" => Box::new(Doh::new(*provider)),
                "dot" => Box::new(Dot::new(*provider)),
                _ => continue, // validated elsewhere; skip unknown kinds here
            };
            upstreams.push(format!("{} ({})", provider.name, u.kind));
            transports.push(transport);
        }
        if transports.is_empty() {
            return None;
        }
        let resolver = Resolver::new(
            transports,
            Cache::new(cfg.dns.cache_entries, 30),
            PoisonConfig::default(),
        );
        Some(DnsService {
            resolver: Mutex::new(resolver),
            upstreams,
        })
    }

    /// The wired upstreams, in order (for the readiness log).
    pub fn upstreams(&self) -> &[String] {
        &self.upstreams
    }

    /// Resolve `name` as an `A` record through the trusted upstreams, returning
    /// the resolved addresses (empty for a negative answer) or `None` on
    /// failure.
    pub fn resolve_a(&self, name: &str) -> Option<Vec<IpAddr>> {
        let mut resolver = self.resolver.lock().unwrap_or_else(|e| e.into_inner());
        resolver
            .resolve(name, QType::A, unix_now())
            .ok()
            .map(|resolved| resolved.addrs)
    }

    /// Startup health check: resolve a well-known name to confirm at least one
    /// trusted upstream is reachable. Non-fatal — the engine still runs when DNS
    /// is unreachable.
    pub fn health_check(&self) -> bool {
        self.resolve_a("cloudflare.com")
            .is_some_and(|addrs| !addrs.is_empty())
    }
}

/// Match a configured host to an embedded provider by its TLS name.
fn provider_for(host: &str) -> Option<&'static Provider> {
    uf_dns::PROVIDERS
        .iter()
        .find(|p| p.tls_name.eq_ignore_ascii_case(host))
}

/// Current Unix time in seconds (0 if the clock is before the epoch).
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_from_default_config_with_both_transports() {
        // The default config lists DoH Cloudflare + DoT Google, both of which are
        // embedded providers, so the resolver wires two upstreams.
        let cfg = Config::default();
        let dns = DnsService::build(&cfg).expect("default upstreams are known providers");
        assert_eq!(dns.upstreams().len(), 2);
        assert!(dns.upstreams()[0].contains("Cloudflare"));
        assert!(dns.upstreams()[0].contains("doh"));
        assert!(dns.upstreams()[1].contains("Google"));
        assert!(dns.upstreams()[1].contains("dot"));
    }

    #[test]
    fn unknown_host_is_skipped() {
        assert!(provider_for("not-a-real-provider.example").is_none());
        assert!(provider_for("dns.google").is_some());
        assert!(provider_for("DNS.GOOGLE").is_some()); // case-insensitive
    }

    #[test]
    fn no_known_upstreams_yields_none() {
        let mut cfg = Config::default();
        for u in &mut cfg.dns.upstreams {
            u.host = "unknown.example".into();
        }
        assert!(DnsService::build(&cfg).is_none());
    }
}
