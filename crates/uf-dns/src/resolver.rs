//! Resolution policy: query the trusted (DoH/DoT) upstreams with failover,
//! cache the result, and expose poisoning judgement against an ISP answer.
//!
//! The transport (rustls over a socket to a pinned provider IP) is abstracted by
//! [`Transport`], so this whole policy is unit-tested with a mock and no network.
//! The live rustls transport is wired in the service (it needs tokio + a socket);
//! it only has to implement [`Transport`].

use crate::cache::Cache;
use crate::detect::{PoisonConfig, Verdict, judge_against};
use crate::message::{self, DnsMessage, QType};
use std::net::IpAddr;

/// Answers are cached for at most a day, whatever TTL the upstream claims.
const MAX_CACHE_TTL: u32 = 86_400;

const RCODE_NOERROR: u8 = 0;
const RCODE_NXDOMAIN: u8 = 3;

/// A secure upstream: send a DNS query (raw wire bytes), get the response bytes.
/// Implementations connect to a pinned provider IP over TLS (DoH or DoT).
pub trait Transport {
    /// Provider name, for logging and latency scoring.
    fn name(&self) -> &str;
    /// Send `query` and return the raw DNS response.
    fn query(&self, query: &[u8]) -> Result<Vec<u8>, TransportError>;
}

/// Why a transport query failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Could not connect / timed out.
    Network,
    /// Connected but the response was unusable.
    Protocol,
}

/// Why resolution failed overall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// Every upstream failed.
    AllUpstreamsFailed,
    /// The query name was invalid.
    BadName,
}

/// The resolver: trusted upstreams (tried in order, with failover), a cache, and
/// detection config.
pub struct Resolver {
    upstreams: Vec<Box<dyn Transport>>,
    cache: Cache,
    config: PoisonConfig,
    next_id: u16,
}

/// A resolved answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Addresses (empty for a negative answer).
    pub addrs: Vec<IpAddr>,
    /// Whether this was a negative (NXDOMAIN) answer.
    pub negative: bool,
    /// Whether it was served from cache.
    pub from_cache: bool,
    /// The upstream that answered (empty for a cache hit).
    pub via: String,
}

impl Resolver {
    /// Build a resolver over the given trusted upstreams.
    pub fn new(upstreams: Vec<Box<dyn Transport>>, cache: Cache, config: PoisonConfig) -> Self {
        Resolver {
            upstreams,
            cache,
            config,
            next_id: 1,
        }
    }

    fn alloc_id(&mut self) -> u16 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    /// Resolve `name`/`qtype`, using the cache first, then the trusted upstreams
    /// with failover. The verified answer is cached (positive by min TTL,
    /// negative by the cache's negative TTL).
    pub fn resolve(
        &mut self,
        name: &str,
        qtype: QType,
        now: u64,
    ) -> Result<Resolved, ResolveError> {
        if let Some(e) = self.cache.get(name, qtype, now) {
            return Ok(Resolved {
                addrs: e.addrs.clone(),
                negative: e.negative,
                from_cache: true,
                via: String::new(),
            });
        }

        let id = self.alloc_id();
        let query = message::build_query(id, name, qtype).map_err(|_| ResolveError::BadName)?;

        let mut last_err = ResolveError::AllUpstreamsFailed;
        // Collect names up front to avoid borrowing self across the loop body.
        let count = self.upstreams.len();
        for i in 0..count {
            let result = self.upstreams[i].query(&query);
            let via = self.upstreams[i].name().to_string();
            match result {
                Ok(bytes) => match message::parse(&bytes) {
                    // Only NOERROR and NXDOMAIN are answers. SERVFAIL/REFUSED
                    // mean "this upstream could not help": try the next one
                    // rather than caching a failure as a negative answer.
                    Ok(msg)
                        if msg.id == id
                            && msg.is_response
                            && answers_question(&msg, name, qtype)
                            && matches!(msg.rcode, RCODE_NOERROR | RCODE_NXDOMAIN) =>
                    {
                        return Ok(self.store_answer(name, qtype, &msg, &via, now));
                    }
                    _ => last_err = ResolveError::AllUpstreamsFailed,
                },
                Err(_) => last_err = ResolveError::AllUpstreamsFailed,
            }
        }
        Err(last_err)
    }

    fn store_answer(
        &mut self,
        name: &str,
        qtype: QType,
        msg: &DnsMessage,
        via: &str,
        now: u64,
    ) -> Resolved {
        let addrs = msg.addresses();
        // A CNAME-only answer carries no address: as unusable as NODATA.
        if msg.is_nxdomain() || addrs.is_empty() {
            self.cache.put_negative(name, qtype, now);
            return Resolved {
                addrs: Vec::new(),
                negative: true,
                from_cache: false,
                via: via.to_string(),
            };
        }
        let ttl = msg.min_ttl().unwrap_or(0).min(MAX_CACHE_TTL);
        self.cache
            .put_positive(name, qtype, addrs.clone(), ttl, now);
        Resolved {
            addrs,
            negative: false,
            from_cache: false,
            via: via.to_string(),
        }
    }

    /// Judge an ISP (plaintext) answer against a trusted one — the service uses
    /// this to decide whether a fast ISP reply may be served directly or must be
    /// replaced by the DoH answer.
    pub fn judge_isp(&self, isp: &DnsMessage, trusted: &DnsMessage) -> Verdict {
        judge_against(isp, trusted, &self.config)
    }
}

/// Whether `msg` answers the question that was asked (name and type).
fn answers_question(msg: &DnsMessage, name: &str, qtype: QType) -> bool {
    msg.qtype == qtype && msg.qname.eq_ignore_ascii_case(name.trim_end_matches('.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::build_query;
    use std::cell::Cell;

    // A mock upstream that echoes a pre-built response, or fails a configurable
    // number of times first (to exercise failover).
    struct MockUpstream {
        name: String,
        response: Option<Vec<u8>>,
        fail_times: Cell<u32>,
    }

    impl MockUpstream {
        fn ok(name: &str, response: Vec<u8>) -> Box<dyn Transport> {
            Box::new(MockUpstream {
                name: name.into(),
                response: Some(response),
                fail_times: Cell::new(0),
            })
        }
        fn failing(name: &str) -> Box<dyn Transport> {
            Box::new(MockUpstream {
                name: name.into(),
                response: None,
                fail_times: Cell::new(u32::MAX),
            })
        }
    }

    impl Transport for MockUpstream {
        fn name(&self) -> &str {
            &self.name
        }
        fn query(&self, _q: &[u8]) -> Result<Vec<u8>, TransportError> {
            let left = self.fail_times.get();
            if left > 0 {
                self.fail_times.set(left.saturating_sub(1));
                if self.response.is_none() {
                    return Err(TransportError::Network);
                }
            }
            self.response.clone().ok_or(TransportError::Network)
        }
    }

    // Build an A response for `name` -> `ip` echoing the query id the resolver
    // will use (ids start at 1).
    fn a_response(id: u16, name: &str, ip: &str, ttl: u32) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend_from_slice(&0x8180u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes()); // qd
        m.extend_from_slice(&1u16.to_be_bytes()); // an
        m.extend_from_slice(&[0, 0, 0, 0]);
        // question
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        // answer (pointer to offset 12)
        m.extend_from_slice(&[0xC0, 0x0C]);
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&ttl.to_be_bytes());
        let v4: std::net::Ipv4Addr = ip.parse().unwrap();
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&v4.octets());
        m
    }

    #[test]
    fn resolves_and_caches() {
        let resp = a_response(1, "example.com", "93.184.216.34", 120);
        let mut r = Resolver::new(
            vec![MockUpstream::ok("mock", resp)],
            Cache::new(16, 30),
            PoisonConfig::default(),
        );
        let first = r.resolve("example.com", QType::A, 1000).unwrap();
        assert_eq!(
            first.addrs,
            vec!["93.184.216.34".parse::<IpAddr>().unwrap()]
        );
        assert!(!first.from_cache);
        assert_eq!(first.via, "mock");

        let second = r.resolve("example.com", QType::A, 1050).unwrap();
        assert!(second.from_cache);
        assert_eq!(second.addrs, first.addrs);
    }

    #[test]
    fn fails_over_to_second_upstream() {
        let resp = a_response(1, "example.com", "1.2.3.4", 60);
        let mut r = Resolver::new(
            vec![MockUpstream::failing("down"), MockUpstream::ok("up", resp)],
            Cache::new(16, 30),
            PoisonConfig::default(),
        );
        let got = r.resolve("example.com", QType::A, 0).unwrap();
        assert_eq!(got.via, "up");
        assert_eq!(got.addrs, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
    }

    #[test]
    fn all_down_is_error() {
        let mut r = Resolver::new(
            vec![MockUpstream::failing("a"), MockUpstream::failing("b")],
            Cache::new(16, 30),
            PoisonConfig::default(),
        );
        assert_eq!(
            r.resolve("example.com", QType::A, 0),
            Err(ResolveError::AllUpstreamsFailed)
        );
    }

    #[test]
    fn bad_name_rejected() {
        let mut r = Resolver::new(
            vec![MockUpstream::ok("mock", vec![])],
            Cache::new(16, 30),
            PoisonConfig::default(),
        );
        let long = "a".repeat(300);
        assert_eq!(r.resolve(&long, QType::A, 0), Err(ResolveError::BadName));
    }

    #[test]
    fn mismatched_id_is_rejected() {
        // Response carries id 999, but the resolver's first query id is 1.
        let resp = a_response(999, "example.com", "1.2.3.4", 60);
        let mut r = Resolver::new(
            vec![MockUpstream::ok("mock", resp)],
            Cache::new(16, 30),
            PoisonConfig::default(),
        );
        assert_eq!(
            r.resolve("example.com", QType::A, 0),
            Err(ResolveError::AllUpstreamsFailed)
        );
    }

    fn with_rcode(mut resp: Vec<u8>, rcode: u8) -> Vec<u8> {
        resp[3] = (resp[3] & 0xF0) | rcode;
        resp
    }

    #[test]
    fn servfail_fails_over_instead_of_caching_negative() {
        let bad = with_rcode(a_response(1, "example.com", "1.2.3.4", 60), 2);
        let good = a_response(1, "example.com", "5.6.7.8", 60);
        let mut r = Resolver::new(
            vec![
                MockUpstream::ok("servfail", bad),
                MockUpstream::ok("up", good),
            ],
            Cache::new(16, 30),
            PoisonConfig::default(),
        );
        let got = r.resolve("example.com", QType::A, 0).unwrap();
        assert_eq!(got.via, "up");
        assert!(!got.negative);
    }

    #[test]
    fn answer_for_another_name_is_rejected() {
        let resp = a_response(1, "other.example", "1.2.3.4", 60);
        let mut r = Resolver::new(
            vec![MockUpstream::ok("mock", resp)],
            Cache::new(16, 30),
            PoisonConfig::default(),
        );
        assert_eq!(
            r.resolve("example.com", QType::A, 0),
            Err(ResolveError::AllUpstreamsFailed)
        );
    }

    #[test]
    fn query_builds_for_known_name() {
        // Sanity: the id the resolver allocates first is 1, matching a_response.
        let q = build_query(1, "example.com", QType::A).unwrap();
        assert_eq!(message::parse(&q).unwrap().id, 1);
    }
}
