//! DNS poisoning detection (master prompt §5.2).
//!
//! Turkish ISPs commonly answer blocked domains with a block-page IP, a bogon,
//! or `0.0.0.0`, often with a short TTL. We flag an answer as poisoned when it
//! has those hallmarks, and we treat a trusted (DoH) answer as the tie-breaker
//! when the ISP answer disagrees with it.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::message::DnsMessage;

/// Why (or whether) an answer is considered poisoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Looks genuine.
    Clean,
    /// Contains a sinkhole address (`0.0.0.0` / `::`).
    Sinkhole,
    /// Contains a bogon / private / reserved address for a public name.
    Bogon,
    /// Matches a configured block-page address.
    BlockPage,
    /// Disagrees with the trusted answer and has a suspiciously short TTL.
    TtlMismatch,
}

impl Verdict {
    /// Whether this verdict means the answer should be rejected.
    pub fn is_poisoned(self) -> bool {
        !matches!(self, Verdict::Clean)
    }
}

/// Tunables for detection. Serde so it can be loaded from config; the defaults
/// are sensible for Turkey without naming specific operators.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoisonConfig {
    /// Known block-page IPs (operator-specific; empty by default, filled from
    /// the signed profile update in v1.1).
    pub block_page_ips: Vec<IpAddr>,
    /// A TTL at or below this (seconds) is treated as suspicious when the answer
    /// also disagrees with the trusted one.
    pub short_ttl_secs: u32,
}

impl Default for PoisonConfig {
    fn default() -> Self {
        PoisonConfig {
            block_page_ips: Vec::new(),
            short_ttl_secs: 5,
        }
    }
}

fn is_sinkhole(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

fn is_bogon(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_documentation()
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// Judge a single answer in isolation (no trusted reference available yet).
pub fn judge(msg: &DnsMessage, cfg: &PoisonConfig) -> Verdict {
    for ip in msg.addresses() {
        if is_sinkhole(ip) {
            return Verdict::Sinkhole;
        }
        if cfg.block_page_ips.contains(&ip) {
            return Verdict::BlockPage;
        }
        if is_bogon(ip) {
            return Verdict::Bogon;
        }
    }
    Verdict::Clean
}

/// Judge the ISP answer against a trusted (DoH) answer. If the ISP answer is
/// independently poisoned, that wins; otherwise a disagreement combined with a
/// short TTL is flagged.
pub fn judge_against(isp: &DnsMessage, trusted: &DnsMessage, cfg: &PoisonConfig) -> Verdict {
    let standalone = judge(isp, cfg);
    if standalone.is_poisoned() {
        return standalone;
    }
    let isp_ips: Vec<IpAddr> = isp.addresses();
    let trusted_ips: Vec<IpAddr> = trusted.addresses();
    let disjoint = !isp_ips.is_empty()
        && !trusted_ips.is_empty()
        && !isp_ips.iter().any(|ip| trusted_ips.contains(ip));
    if disjoint && isp.min_ttl().unwrap_or(u32::MAX) <= cfg.short_ttl_secs {
        return Verdict::TtlMismatch;
    }
    Verdict::Clean
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{QType, Record};

    fn msg_with(addrs: &[&str], ttl: u32) -> DnsMessage {
        DnsMessage {
            is_response: true,
            answers: addrs
                .iter()
                .map(|a| Record {
                    qtype: QType::A,
                    ttl,
                    addr: Some(a.parse().unwrap()),
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn sinkhole_flagged() {
        let m = msg_with(&["0.0.0.0"], 300);
        assert_eq!(judge(&m, &PoisonConfig::default()), Verdict::Sinkhole);
    }

    #[test]
    fn private_address_for_public_name_is_bogon() {
        let m = msg_with(&["10.0.0.1"], 300);
        assert_eq!(judge(&m, &PoisonConfig::default()), Verdict::Bogon);
    }

    #[test]
    fn configured_block_page_flagged() {
        let cfg = PoisonConfig {
            block_page_ips: vec!["195.175.254.2".parse().unwrap()],
            ..Default::default()
        };
        let m = msg_with(&["195.175.254.2"], 300);
        assert_eq!(judge(&m, &cfg), Verdict::BlockPage);
    }

    #[test]
    fn clean_public_answer_passes() {
        let m = msg_with(&["93.184.216.34"], 3600);
        assert_eq!(judge(&m, &PoisonConfig::default()), Verdict::Clean);
    }

    #[test]
    fn disagreement_with_short_ttl_flagged() {
        let isp = msg_with(&["93.184.1.1"], 3);
        let trusted = msg_with(&["93.184.216.34"], 3600);
        assert_eq!(
            judge_against(&isp, &trusted, &PoisonConfig::default()),
            Verdict::TtlMismatch
        );
    }

    #[test]
    fn agreement_is_clean() {
        let isp = msg_with(&["93.184.216.34"], 3);
        let trusted = msg_with(&["93.184.216.34"], 3600);
        assert_eq!(
            judge_against(&isp, &trusted, &PoisonConfig::default()),
            Verdict::Clean
        );
    }
}
