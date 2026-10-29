//! Service entry point: the privileged background that hosts the engine, the
//! trusted DoH/DoT resolver and the strategy prober, and serves the tray/UI over
//! the named pipe.
//!
//! The control plane lives in [`crate::orchestrator`] (pure, tested);
//! [`crate::config`] loads `config/default.toml`; [`crate::dns`] builds the live
//! trusted resolver (DoH/DoT via `uf-dns` against pinned providers); on Windows
//! [`crate::fingerprint`] identifies the network. A real Windows service still
//! needs an SCM dispatcher wrapper; invoked from a console this performs start-up
//! wiring and serves the control plane over the named pipe.
//!
//! The single `unfilter` binary calls [`run`] in `--service` mode.

use std::path::PathBuf;

use uf_probe::{Fingerprint, ProfileCache};

use crate::Orchestrator;
use crate::config::Config;

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
        Fingerprint::from_inputs(&crate::fingerprint::WindowsSource.gather())
    }
    #[cfg(not(windows))]
    {
        use uf_probe::NetworkInputs;
        Fingerprint::from_inputs(&NetworkInputs::default())
    }
}

/// Load config, build the control plane, and the trusted DNS resolver.
fn start_up() -> (Orchestrator, Option<crate::dns::DnsService>) {
    let (user, default) = config_paths();
    let cfg = Config::load(&user, &default);

    let cache_path = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Unfilter")
        .join("profiles.json");
    let cache = ProfileCache::load(&cache_path);

    // Build the trusted resolver from the configured upstreams (DoH/DoT against
    // pinned providers). A disabled or unknown-only config yields `None`, which
    // is non-fatal: the engine still passes traffic through.
    let dns = if cfg.dns.enabled {
        crate::dns::DnsService::build(&cfg)
    } else {
        None
    };

    let orch = Orchestrator::new(&cfg, current_fingerprint(), cache);
    (orch, dns)
}

/// Run the service: wire up the control plane and resolver, then serve the
/// tray/UI over the named pipe (blocks until the pipe server stops).
pub fn run() {
    let (orch, dns) = start_up();
    let status = orch.status();
    eprintln!(
        "uf-service hazır: durum={:?}, mod={:?}",
        status.state, status.mode
    );

    match &dns {
        Some(dns) => {
            eprintln!("DNS güvenilir upstream'ler: {}", dns.upstreams().join(", "));
            // Bounded by the per-query timeouts; non-fatal either way.
            if dns.health_check() {
                eprintln!("DNS sağlık kontrolü: en az bir güvenilir upstream erişilebilir");
            } else {
                eprintln!(
                    "DNS sağlık kontrolü: güvenilir upstream'e ulaşılamadı (motor yine de çalışır)"
                );
            }
        }
        None => eprintln!("DNS yönlendirme kapalı veya tanımlı güvenilir upstream yok"),
    }

    // Serve tray/UI clients on the ADR-005 named pipe. This blocks. (Running as
    // a real Windows service still needs an SCM dispatcher wrapper; invoked from
    // a console this already serves the control plane. The packet engine — and
    // the port-53 interception that will feed `dns` — are started on Connect and
    // need the WinDivert driver + administrator rights.)
    #[cfg(windows)]
    {
        use std::sync::{Arc, Mutex};
        // Keep the resolver alive for the whole serve lifetime.
        let _dns = dns;
        let shared = Arc::new(Mutex::new(orch));
        if let Err(e) = crate::ipc::serve(uf_ipc::PIPE_NAME, shared) {
            eprintln!("uf-service pipe sunucusu durdu: {e}");
        }
    }
    #[cfg(not(windows))]
    {
        let _ = dns;
    }
}
