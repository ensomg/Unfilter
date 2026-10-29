//! Live HTTPS reachability probes: the strategy scan's success test and the
//! UI's "test a site" button.
//!
//! A probe resolves the host through the system resolver (which the port-53
//! interceptor answers from the trusted upstreams while connected), opens TCP
//! to port 443, completes a certificate-validated TLS handshake with the real
//! SNI, and reads the first bytes of an HTTP response. The probe's own packets
//! pass through the capture engine, so they exercise the active strategy
//! exactly like browser traffic does. Only a harmless `HEAD /` is sent.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use uf_ipc::BlockKind;

/// Per-stage timeout of one probe (site test).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

/// Per-stage timeout during a strategy scan: a DPI block shows up as a reset
/// or a stall, so waiting longer only slows the scan down.
pub const SCAN_TIMEOUT: Duration = Duration::from_millis(2500);

/// Outcome of probing one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProbeResult {
    /// The name resolved to at least one address.
    pub dns_ok: bool,
    /// A TCP connection to port 443 was established.
    pub tcp_ok: bool,
    /// TLS completed (valid certificate) and an HTTP response started.
    pub tls_ok: bool,
    /// Connect → first response byte, in µs (0 unless `tls_ok`).
    pub latency_us: u32,
}

impl ProbeResult {
    /// Which layer blocked the host, or `None` if it was reachable.
    pub fn block(&self) -> Option<BlockKind> {
        if !self.dns_ok {
            Some(BlockKind::Dns)
        } else if !self.tcp_ok {
            Some(BlockKind::Ip)
        } else if !self.tls_ok {
            Some(BlockKind::Dpi)
        } else {
            None
        }
    }
}

fn tls_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Option<Arc<ClientConfig>>> = OnceLock::new();
    CFG.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .ok()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Some(Arc::new(cfg))
    })
    .clone()
    .expect("ring provider supports the default TLS versions")
}

/// Probe `host` over HTTPS. Never panics on network errors; each failed stage
/// just leaves the later flags false.
pub fn https(host: &str, timeout: Duration) -> ProbeResult {
    let mut r = ProbeResult::default();
    let Ok(addrs) = (host, 443u16).to_socket_addrs() else {
        return r;
    };
    // Prefer IPv4: the interceptor answers both, but v4 paths are the norm.
    let mut addrs: Vec<SocketAddr> = addrs.collect();
    addrs.sort_by_key(|a| a.is_ipv6());
    if addrs.is_empty() {
        return r;
    }
    r.dns_ok = true;

    let start = Instant::now();
    let Some(sock) = addrs
        .iter()
        .take(2)
        .find_map(|a| TcpStream::connect_timeout(a, timeout).ok())
    else {
        return r;
    };
    r.tcp_ok = true;
    if sock.set_read_timeout(Some(timeout)).is_err()
        || sock.set_write_timeout(Some(timeout)).is_err()
    {
        return r;
    }

    let Ok(name) = ServerName::try_from(host.to_string()) else {
        return r;
    };
    let Ok(conn) = ClientConnection::new(tls_config(), name) else {
        return r;
    };
    let mut tls = StreamOwned::new(conn, sock);
    let req = format!(
        "HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Unfilter-probe\r\nConnection: close\r\n\r\n"
    );
    if tls.write_all(req.as_bytes()).is_err() {
        return r;
    }
    let mut head = [0u8; 5];
    if tls.read_exact(&mut head).is_ok() && &head == b"HTTP/" {
        r.tls_ok = true;
        r.latency_us = start.elapsed().as_micros().min(u128::from(u32::MAX)) as u32;
    }
    r
}

/// Result of probing a target set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sweep {
    /// Hosts reached (counted until the sweep stopped).
    pub ok: usize,
    /// Hosts in the set.
    pub total: usize,
    /// Mean connect → first-byte time of the reached hosts, in µs.
    pub latency_us: u32,
}

impl Sweep {
    /// Every host was reached.
    pub fn all_ok(&self) -> bool {
        self.ok == self.total
    }
}

/// Probe `hosts` in parallel, returning as soon as `max_failures` of them
/// failed (a candidate that cannot reach them is out; no need to wait for the
/// slowest timeouts). Stragglers finish on their own detached threads.
pub fn sweep(hosts: &[String], timeout: Duration, max_failures: usize) -> Sweep {
    let (tx, rx) = std::sync::mpsc::channel();
    for h in hosts {
        let (tx, h) = (tx.clone(), h.clone());
        std::thread::spawn(move || {
            let _ = tx.send(https(&h, timeout));
        });
    }
    drop(tx);
    let (mut ok, mut failed, mut sum) = (0usize, 0usize, 0u64);
    for r in rx {
        if r.tls_ok {
            ok += 1;
            sum += u64::from(r.latency_us);
        } else {
            failed += 1;
            if failed >= max_failures.max(1) {
                break;
            }
        }
    }
    Sweep {
        ok,
        total: hosts.len(),
        latency_us: if ok == 0 { 0 } else { (sum / ok as u64) as u32 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_kind_follows_first_failed_stage() {
        let mut r = ProbeResult::default();
        assert_eq!(r.block(), Some(BlockKind::Dns));
        r.dns_ok = true;
        assert_eq!(r.block(), Some(BlockKind::Ip));
        r.tcp_ok = true;
        assert_eq!(r.block(), Some(BlockKind::Dpi));
        r.tls_ok = true;
        assert_eq!(r.block(), None);
    }

    #[test]
    fn unresolvable_host_fails_at_dns() {
        let r = https("unfilter-probe.invalid", Duration::from_millis(500));
        assert!(!r.dns_ok && !r.tcp_ok && !r.tls_ok);
    }

    /// Needs the network: `cargo test -p uf-service -- --ignored live_`.
    #[test]
    #[ignore]
    fn live_probe_reaches_a_public_site() {
        let r = https("www.cloudflare.com", PROBE_TIMEOUT);
        assert_eq!(r.block(), None, "{r:?}");
        assert!(r.latency_us > 0);
    }

    #[test]
    fn tls_config_builds() {
        let _ = tls_config();
    }
}
