//! Service entry point: the privileged background that hosts the engine, the
//! trusted DoH/DoT resolver and the strategy prober, and serves the tray/UI over
//! the named pipe.
//!
//! The control plane lives in [`crate::orchestrator`] (pure, tested);
//! [`crate::config`] loads `config/default.toml`; [`crate::dns`] builds the live
//! trusted resolver (DoH/DoT via `uf-dns` against pinned providers); on Windows
//! [`crate::fingerprint`] identifies the network; [`crate::runtime`] runs the
//! packet engine, port-53 interception and strategy scan; [`crate::svc`] is the
//! SCM wrapper (invoked from a console the same body runs in the foreground).
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

fn cache_path() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("Unfilter")
        .join("profiles.json")
}

/// Load config and build the control plane.
fn start_up() -> (Orchestrator, Config) {
    let (user, default) = config_paths();
    let cfg = Config::load(&user, &default);
    let cache = ProfileCache::load(&cache_path());
    let orch = Orchestrator::new(&cfg, current_fingerprint(), cache);
    (orch, cfg)
}

/// Log which trusted upstreams are wired and whether one is reachable. The
/// resolver used for live queries is built by the port-53 interceptor on its
/// own thread (the resolver policy is single-threaded).
fn dns_health(cfg: &Config) {
    if !cfg.dns.enabled {
        eprintln!("DNS yönlendirme kapalı");
        return;
    }
    match crate::dns::DnsService::build(cfg) {
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
        None => eprintln!("DNS: tanımlı güvenilir upstream yok"),
    }
}

/// Run the service: under the SCM when started by it, otherwise in the
/// foreground (console/development).
pub fn run() {
    #[cfg(windows)]
    crate::svc::dispatch(serve);
    #[cfg(not(windows))]
    serve();
}

/// The service body: wire up the control plane and the data-plane runtime,
/// then serve the tray/UI over the named pipe (blocks until the pipe stops).
fn serve() {
    let (orch, cfg) = start_up();
    let status = orch.status();
    eprintln!(
        "uf-service hazır: durum={:?}, mod={:?}",
        status.state, status.mode
    );
    // Off the start-up path: the pipe (and so the UI) comes up immediately.
    {
        let cfg = cfg.clone();
        std::thread::spawn(move || dns_health(&cfg));
    }
    let mut orch = orch;
    // Started by the double-click launcher: connect right away.
    if std::env::args().any(|a| a == "--connect") {
        orch.handle(uf_ipc::Request::Connect);
    }

    // The runtime follows the orchestrator: Connect starts the WinDivert
    // engine + port-53 interception and scans for a working strategy;
    // Disconnect stops capture (fail-open). Needs the driver + admin rights.
    #[cfg(windows)]
    {
        use std::sync::{Arc, Mutex};
        let shared = Arc::new(Mutex::new(orch));
        let clients = crate::ipc::Clients::default();
        crate::runtime::Runtime::new(Arc::clone(&shared), clients.clone(), cfg, cache_path())
            .spawn();
        match crate::ipc::serve(uf_ipc::PIPE_NAME, shared, clients) {
            Ok(()) => eprintln!("uf-service pipe sunucusu kapatıldı"),
            Err(e) => eprintln!("uf-service pipe sunucusu durdu: {e}"),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (orch, cfg);
    }
}
