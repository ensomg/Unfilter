//! `uf-service`: the privileged Windows service that hosts the engine, the DoT
//! resolver and the strategy prober, and serves the tray/UI over the named
//! pipe.
//!
//! The control plane lives in [`uf_service::orchestrator`] (pure, tested);
//! [`uf_service::config`] loads `config/default.toml`;
//! [`uf_service::transport`] (feature `live-tls`) is the live DoT upstream; on
//! Windows [`uf_service::fingerprint`] identifies the network. The SCM
//! dispatcher and pipe server loop are added once the IPC pipe module lands
//! (F6 integration); until then `main` performs start-up wiring and reports
//! readiness.

use std::path::PathBuf;

use uf_probe::{Fingerprint, ProfileCache};
use uf_service::Orchestrator;
use uf_service::config::Config;

/// Per-user and installed config locations (ProgramData / Program Files).
fn config_paths() -> (PathBuf, PathBuf) {
    let program_data = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let base = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    (
        program_data.join("Unfilter").join("config.toml"),
        base.join("config").join("default.toml"),
    )
}

/// Resolve this network's fingerprint (Windows gathers the real inputs; other
/// targets use a fixed placeholder so the crate still builds cross-platform).
fn current_fingerprint() -> Fingerprint {
    #[cfg(windows)]
    {
        use uf_probe::FingerprintSource;
        Fingerprint::from_inputs(&uf_service::fingerprint::WindowsSource.gather())
    }
    #[cfg(not(windows))]
    {
        use uf_probe::NetworkInputs;
        Fingerprint::from_inputs(&NetworkInputs::default())
    }
}

/// Load config, build the control plane, and (with `live-tls`) the resolver.
fn start_up() -> Orchestrator {
    let (user, default) = config_paths();
    let cfg = Config::load(&user, &default);

    let cache_path = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Unfilter")
        .join("profiles.json");
    let cache = ProfileCache::load(&cache_path);

    #[cfg(feature = "live-tls")]
    {
        // Build the resolver from the configured DoT upstreams; a failure here
        // is non-fatal (the engine still passes traffic through).
        let _resolver = build_resolver(&cfg);
    }

    Orchestrator::new(&cfg, current_fingerprint(), cache)
}

#[cfg(feature = "live-tls")]
fn build_resolver(cfg: &Config) -> Option<uf_dns::Resolver> {
    use uf_dns::{Cache, PoisonConfig, Resolver, Transport};
    use uf_service::transport::{DotTransport, tls_config};
    let tls = tls_config();
    let mut ups: Vec<Box<dyn Transport>> = Vec::new();
    for u in &cfg.dns.upstreams {
        if u.kind != "dot" {
            continue; // DoH (HTTP/2) upstreams are wired in a later iteration.
        }
        if let Ok(ip) = u.ip.parse() {
            if let Ok(t) = DotTransport::new(u.host.clone(), &u.host, ip, tls.clone()) {
                ups.push(Box::new(t));
            }
        }
    }
    if ups.is_empty() {
        return None;
    }
    Some(Resolver::new(
        ups,
        Cache::new(cfg.dns.cache_entries, 30),
        PoisonConfig::default(),
    ))
}

fn main() {
    let orch = start_up();
    let status = orch.status();
    // Until the SCM dispatcher and pipe server land (F6 integration), report
    // readiness on stderr so a manual run is observable. The real service
    // registers with the SCM and serves clients here.
    eprintln!(
        "uf-service hazır: durum={:?}, mod={:?}",
        status.state, status.mode
    );
}
