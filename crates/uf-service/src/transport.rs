//! The live DoT (DNS-over-TLS, RFC 7858) transport that backs the resolver on
//! the real service. Pure control-plane logic lives in `uf-dns`; this is the
//! socket + TLS glue the ADR-003 stack (rustls + ring, pinned bootstrap IPs)
//! provides, behind the `live-tls` feature so the control plane can be built and
//! tested without the TLS dependency.
//!
//! Each query opens a fresh TLS connection to the provider's pinned IP, writes
//! the 2-byte-length-prefixed DNS message, and reads the length-prefixed reply.
//! The provider domain is used only for certificate validation; the connection
//! goes straight to the pinned IP, so no plaintext bootstrap DNS is ever needed.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_pki_types::ServerName;

use uf_dns::{Transport, TransportError};

/// Connect/read timeout for an upstream query.
const TIMEOUT: Duration = Duration::from_secs(5);
/// A DNS-over-TLS reply we are willing to read (a UDP-style answer is tiny).
const MAX_REPLY: usize = 16 * 1024;

/// A DoT upstream: a pinned IP on port 853 validated against `server_name`.
pub struct DotTransport {
    label: String,
    server_name: ServerName<'static>,
    addr: SocketAddr,
    config: Arc<ClientConfig>,
}

impl DotTransport {
    /// Build a transport for `server_name` reachable at the pinned `ip`:853,
    /// sharing a prebuilt TLS client config (root store + ring provider).
    pub fn new(
        label: impl Into<String>,
        server_name: &str,
        ip: IpAddr,
        config: Arc<ClientConfig>,
    ) -> Result<Self, TransportError> {
        let sni =
            ServerName::try_from(server_name.to_owned()).map_err(|_| TransportError::Protocol)?;
        Ok(DotTransport {
            label: label.into(),
            server_name: sni,
            addr: SocketAddr::new(ip, 853),
            config,
        })
    }

    fn run_query(&self, query: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut sock = TcpStream::connect_timeout(&self.addr, TIMEOUT)?;
        sock.set_read_timeout(Some(TIMEOUT))?;
        sock.set_write_timeout(Some(TIMEOUT))?;
        let mut conn = ClientConnection::new(self.config.clone(), self.server_name.clone())
            .map_err(std::io::Error::other)?;
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);

        // Length-prefixed query (RFC 7858 framing).
        let len = u16::try_from(query.len())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "query too long"))?;
        tls.write_all(&len.to_be_bytes())?;
        tls.write_all(query)?;
        tls.flush()?;

        // Length-prefixed reply.
        let mut lenbuf = [0u8; 2];
        tls.read_exact(&mut lenbuf)?;
        let rlen = u16::from_be_bytes(lenbuf) as usize;
        if rlen == 0 || rlen > MAX_REPLY {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "reply length out of range",
            ));
        }
        let mut reply = vec![0u8; rlen];
        tls.read_exact(&mut reply)?;
        Ok(reply)
    }
}

impl Transport for DotTransport {
    fn name(&self) -> &str {
        &self.label
    }

    fn query(&self, query: &[u8]) -> Result<Vec<u8>, TransportError> {
        self.run_query(query).map_err(|_| TransportError::Network)
    }
}

/// Build a shared rustls client config: the Mozilla root set (webpki-roots) and
/// the ring crypto provider (ADR 003). TLS 1.2+.
pub fn tls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_builds() {
        // Exercises the ring provider + root store wiring without a socket.
        let cfg = tls_config();
        assert!(Arc::strong_count(&cfg) >= 1);
    }

    #[test]
    fn transport_constructs_for_pinned_ip() {
        let cfg = tls_config();
        let t = DotTransport::new("Google", "dns.google", "8.8.8.8".parse().unwrap(), cfg).unwrap();
        assert_eq!(t.name(), "Google");
        assert_eq!(t.addr.port(), 853);
    }

    #[test]
    fn bad_server_name_is_protocol_error() {
        let cfg = tls_config();
        let r = DotTransport::new("x", "", "1.1.1.1".parse().unwrap(), cfg);
        assert_eq!(r.err(), Some(TransportError::Protocol));
    }
}
