//! Automatic strategy prober, network fingerprint and per-network cache.
//!
//! This crate is the "zero configuration" promise's bookkeeping half: it
//! identifies the current network, keeps the best known strategy order per
//! network on disk, scores candidates, and tracks per-flow outcomes so a failing
//! flow can fall back to a backup strategy (master prompt §5.5, §5.6).
//!
//! What lives here is pure policy and data: fingerprint hashing, the candidate
//! ladder (cheapest technique first), scoring, the on-disk profile schema, and
//! the passive-monitoring state machine. Gathering the raw network identifiers
//! (gateway MAC, ASN, SSID) is a platform concern behind
//! [`FingerprintSource`](fingerprint::FingerprintSource); actually *running* a
//! candidate against the network and applying a strategy to packets is the
//! engine's job (`uf-core` strategies), not this crate's.

pub mod cache;
pub mod fingerprint;
pub mod ladder;
pub mod monitor;
pub mod score;
pub mod targets;

pub use cache::{Profile, ProfileCache};
pub use fingerprint::{Fingerprint, FingerprintSource, NetworkInputs};
pub use ladder::{Candidate, Cost, default_ladder};
pub use monitor::{FlowOutcome, Monitor, MonitorConfig};
pub use score::{ScoreBoard, StrategyScore};
pub use targets::{Target, TargetCategory, TargetList};
