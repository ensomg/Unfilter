//! The target of a fallback connection, and the "IP-blocked" decision that gates
//! whether the fallback is consulted at all.
//!
//! The decision type and predicate here are the contract the prober (Faz 5)
//! fills in: it marks a target [`IpBlocked`](TargetVerdict::IpBlocked) only when
//! *every* DPI strategy **and** the DNS fix have failed — a true IP-level block
//! that packet manipulation cannot repair. Only such targets are routed through
//! the fallback (a split tunnel), so the default path pays nothing.

use std::net::IpAddr;

/// The destination a fallback upstream must carry a connection to.
///
/// Mirrors the address forms SOCKS5 can encode: a literal IPv4/IPv6 address, or a
/// domain name left for the upstream to resolve (preferred for blocked targets,
/// since local DNS may itself be poisoned).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Destination address.
    pub addr: TargetAddr,
    /// Destination port.
    pub port: u16,
}

/// A destination address: either resolved, or a name for the upstream to resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    /// A literal IP address.
    Ip(IpAddr),
    /// A domain name (1..=255 bytes). Resolved by the upstream, not locally.
    Domain(String),
}

impl Target {
    /// A target addressed by IP and port.
    pub fn ip(addr: IpAddr, port: u16) -> Self {
        Target {
            addr: TargetAddr::Ip(addr),
            port,
        }
    }

    /// A target addressed by domain name and port.
    pub fn domain(name: impl Into<String>, port: u16) -> Self {
        Target {
            addr: TargetAddr::Domain(name.into()),
            port,
        }
    }
}

/// The prober's per-target verdict after it has exhausted the DPI strategies and
/// the DNS fix. Serde-serialisable so the service can persist and the UI can show
/// it, consistent with the config-as-data model in `uf-core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetVerdict {
    /// Reachable directly, or a DPI/DNS fix worked. Never consult the fallback.
    #[default]
    Direct,
    /// Every DPI strategy and the DNS fix failed: a true IP-level block. Route
    /// this target — and only this target — through the fallback.
    IpBlocked,
}

/// What the prober observed for a target. The prober (Faz 5) builds this; the
/// [`verdict`](ProbeSummary::verdict) method is the single place that decides
/// "IP-blocked", so the rule lives with the types it concerns rather than in the
/// prober.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProbeSummary {
    /// How many DPI bypass strategies were tried for this target.
    pub dpi_strategies_tried: u32,
    /// Whether any DPI strategy produced a working connection.
    pub dpi_succeeded: bool,
    /// Whether a DNS fix (trusted upstream re-resolution) was attempted.
    pub dns_fix_attempted: bool,
    /// Whether the DNS fix produced a working connection.
    pub dns_fix_succeeded: bool,
}

impl ProbeSummary {
    /// Decide the verdict. A target is [`IpBlocked`](TargetVerdict::IpBlocked)
    /// only when the DPI strategies were tried and all failed **and** the DNS fix
    /// was attempted and failed. Any success, or an incomplete probe, stays
    /// [`Direct`](TargetVerdict::Direct) — the fallback is a last resort.
    pub fn verdict(&self) -> TargetVerdict {
        let dpi_exhausted = self.dpi_strategies_tried > 0 && !self.dpi_succeeded;
        let dns_exhausted = self.dns_fix_attempted && !self.dns_fix_succeeded;
        if dpi_exhausted && dns_exhausted {
            TargetVerdict::IpBlocked
        } else {
            TargetVerdict::Direct
        }
    }
}

/// Whether the fallback should be consulted for a target.
///
/// This is the split-tunnel gate and the guarantee of zero added latency on the
/// default path: it is `false` unless the fallback is **enabled** (user opt-in,
/// default off) **and** the prober marked the target IP-blocked. Normal,
/// unblocked, and DPI/DNS-fixable traffic never reaches the fallback.
pub fn should_use_fallback(enabled: bool, verdict: TargetVerdict) -> bool {
    enabled && matches!(verdict, TargetVerdict::IpBlocked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_requires_both_dpi_and_dns_to_fail() {
        // (tried, dpi_ok, dns_tried, dns_ok) -> expected verdict
        let cases = [
            (0, false, false, false, TargetVerdict::Direct), // nothing probed yet
            (3, true, false, false, TargetVerdict::Direct),  // DPI worked
            (3, false, false, false, TargetVerdict::Direct), // DNS fix not tried
            (3, false, true, true, TargetVerdict::Direct),   // DNS fix worked
            (0, false, true, false, TargetVerdict::Direct),  // DPI not tried
            (3, false, true, false, TargetVerdict::IpBlocked), // both exhausted
            (1, false, true, false, TargetVerdict::IpBlocked),
        ];
        for (tried, dpi_ok, dns_tried, dns_ok, want) in cases {
            let s = ProbeSummary {
                dpi_strategies_tried: tried,
                dpi_succeeded: dpi_ok,
                dns_fix_attempted: dns_tried,
                dns_fix_succeeded: dns_ok,
            };
            assert_eq!(s.verdict(), want, "summary {s:?}");
        }
    }

    #[test]
    fn disabled_fallback_is_never_consulted() {
        assert!(!should_use_fallback(false, TargetVerdict::IpBlocked));
        assert!(!should_use_fallback(false, TargetVerdict::Direct));
    }

    #[test]
    fn enabled_fallback_only_for_ip_blocked() {
        assert!(should_use_fallback(true, TargetVerdict::IpBlocked));
        assert!(!should_use_fallback(true, TargetVerdict::Direct));
    }

    #[test]
    fn default_verdict_is_direct() {
        assert_eq!(TargetVerdict::default(), TargetVerdict::Direct);
    }
}
