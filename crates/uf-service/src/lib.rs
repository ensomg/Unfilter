//! Library surface of the Unfilter service: the pieces the `uf-service` binary
//! wires together, exposed so they can be unit-tested and driven independently
//! of the Windows service machinery.
//!
//! - [`config`]: `config/default.toml` schema and load order.
//! - [`orchestrator`]: the pure control-plane state machine and strategy policy.
//! - [`transport`] (feature `live-tls`): the live DoT upstream (rustls + ring).
//! - [`fingerprint`] (Windows): the network fingerprint source.

pub mod config;
pub mod ipc;
pub mod orchestrator;

#[cfg(feature = "live-tls")]
pub mod transport;

#[cfg(windows)]
pub mod fingerprint;

pub use config::Config;
pub use orchestrator::Orchestrator;
