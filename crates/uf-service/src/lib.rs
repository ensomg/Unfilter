//! Library surface of the Unfilter service: the pieces the `uf-service` binary
//! wires together, exposed so they can be unit-tested and driven independently
//! of the Windows service machinery.
//!
//! - [`config`]: `config/default.toml` schema and load order.
//! - [`orchestrator`]: the pure control-plane state machine and strategy policy.
//! - [`dns`]: the live trusted resolver (DoH/DoT via `uf-dns`), built from the
//!   configured upstreams against embedded, pinned providers.
//! - [`fingerprint`] (Windows): the network fingerprint source.

pub mod config;
pub mod dns;
pub mod entry;
pub mod ipc;
pub mod orchestrator;

#[cfg(windows)]
pub mod fingerprint;

pub use config::Config;
pub use entry::run;
pub use orchestrator::Orchestrator;
