//! Local DoH/DoT resolver and DNS poisoning detection.
//!
//! The service captures outbound port-53 queries (at the packet layer, so the
//! system DNS settings are never changed) and answers them from here. The design
//! (master prompt §5.2):
//!
//! - [`message`]: a small, allocation-checked DNS wire codec (A/AAAA, name
//!   compression) — pure, no I/O.
//! - [`detect`]: decides whether an answer looks poisoned (block-page IP, bogon,
//!   `0.0.0.0`, suspiciously short TTL), and compares an ISP answer against a
//!   trusted one.
//! - [`cache`]: a TTL-respecting positive/negative cache.
//! - [`upstream`]: the embedded DoH/DoT providers with bootstrap IPs (no
//!   bootstrap-DNS needed).
//! - [`resolver`]: the orchestration — race the ISP answer against DoH, let the
//!   verified one win, fail over between providers, and cache.
//!
//! The actual TLS transport (rustls over a socket) is injected through the
//! [`Transport`](resolver::Transport) trait, so the whole resolution policy here
//! is unit-tested against a mock with no network.

pub mod cache;
pub mod detect;
pub mod message;
pub mod resolver;
pub mod upstream;

pub use cache::{Cache, CacheEntry};
pub use detect::{PoisonConfig, Verdict};
pub use message::{DnsMessage, QType, Record};
pub use resolver::{Resolver, Transport, TransportError};
pub use upstream::{PROVIDERS, Provider};
