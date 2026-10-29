//! Library surface of the Unfilter service: the pieces the `uf-service` binary
//! wires together, exposed so they can be unit-tested and driven independently
//! of the Windows service machinery.
//!
//! - [`config`]: `config/default.toml` schema and load order.
//! - [`orchestrator`]: the pure control-plane state machine and strategy policy.
//! - [`dns`]: the live trusted resolver (DoH/DoT via `uf-dns`), built from the
//!   configured upstreams against embedded, pinned providers.
//! - [`dnsproxy`]: the port-53 interception codec (query → reply packet).
//! - [`probe`]: live HTTPS reachability probes (strategy scan, site test).
//! - [`runtime`] (Windows): WinDivert engine + DNS interception + scan loop.
//! - [`svc`] (Windows): the SCM dispatcher (falls back to console mode).
//! - [`fingerprint`] (Windows): the network fingerprint source.

pub mod config;
pub mod dns;
pub mod dnsproxy;
pub mod entry;
pub mod ipc;
pub mod orchestrator;
pub mod probe;

#[cfg(windows)]
pub mod runtime;
#[cfg(windows)]
pub mod svc;

#[cfg(windows)]
pub mod fingerprint;

pub use config::Config;
pub use entry::run;
pub use orchestrator::Orchestrator;
