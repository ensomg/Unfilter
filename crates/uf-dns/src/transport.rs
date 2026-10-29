//! Live encrypted transports for [`Transport`]: DNS-over-TLS (RFC 7858) and
//! DNS-over-HTTPS (RFC 8484, HTTP/1.1 POST).
//!
//! Both connect straight to a provider's pinned bootstrap IP (no plaintext
//! bootstrap DNS) and validate the certificate against the provider's TLS name
//! with the embedded Mozilla root set (`webpki-roots`). rustls runs on the
//! `ring` provider (ADR 003). Blocking sockets with timeouts: the resolver is
//! driven from the service's DNS worker thread, never the packet hot path.
//!
//! DoT keeps one connection open and reuses it for later queries (pipelined
//! one at a time); a broken connection is re-established once per query.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use crate::resolver::{Transport, TransportError};
use crate::upstream::{Provider, dot_frame};

/// Default connect + read/write timeout for one upstream attempt.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(2500);

/// Largest DNS message accepted from an upstream (TCP/DoH maximum).
const MAX_MESSAGE: usize = 65_535;
/// Largest HTTP response header accepted from a DoH server.
const MAX_HTTP_HEADER: usize = 16 * 1024;

type Tls = StreamOwned<ClientConnection, TcpStream>;

fn roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut store = RootCertStore::empty();
            store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            Arc::new(store)
        })
        .clone()
}

fn client_config(alpn: &[u8]) -> Result<Arc<ClientConfig>, TransportError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| TransportError::Protocol)?
        .with_root_certificates(roots())
        .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    Ok(Arc::new(cfg))
}

/// Open a TLS connection to `provider` on `port`, negotiating `alpn`. Tries each
/// pinned bootstrap IP in order and returns the first that connects; the TLS
/// handshake itself is driven lazily on the first read/write.
fn connect(provider: &Provider, port: u16, alpn: &[u8]) -> Result<Tls, TransportError> {
    let config = client_config(alpn)?;
    let server_name = ServerName::try_from(provider.tls_name)
        .map_err(|_| TransportError::Protocol)?
        .to_owned();
    let mut last = TransportError::Network;
    for &ip in provider.bootstrap {
        match connect_ip(ip, port, config.clone(), server_name.clone()) {
            Ok(tls) => return Ok(tls),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn connect_ip(
    ip: IpAddr,
    port: u16,
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
) -> Result<Tls, TransportError> {
    let addr = SocketAddr::new(ip, port);
    let sock =
        TcpStream::connect_timeout(&addr, DEFAULT_TIMEOUT).map_err(|_| TransportError::Network)?;
    sock.set_read_timeout(Some(DEFAULT_TIMEOUT))
        .map_err(|_| TransportError::Network)?;
    sock.set_write_timeout(Some(DEFAULT_TIMEOUT))
        .map_err(|_| TransportError::Network)?;
    let conn = ClientConnection::new(config, server_name).map_err(|_| TransportError::Protocol)?;
    Ok(StreamOwned::new(conn, sock))
}

/// DNS-over-TLS upstream (RFC 7858). Keeps one connection open and reuses it;
/// a broken connection is re-established once per query.
pub struct Dot {
    provider: Provider,
    conn: Mutex<Option<Tls>>,
}

impl Dot {
    /// A DoT transport for `provider` (connects lazily on the first query).
    pub fn new(provider: Provider) -> Self {
        Dot {
            provider,
            conn: Mutex::new(None),
        }
    }
}

impl Transport for Dot {
    fn name(&self) -> &str {
        self.provider.name
    }

    fn query(&self, query: &[u8]) -> Result<Vec<u8>, TransportError> {
        if query.len() > MAX_MESSAGE {
            return Err(TransportError::Protocol);
        }
        let framed = dot_frame(query);
        // Recover a poisoned lock: a prior panic mid-query only leaves a possibly
        // broken connection, which the re-establish path below already handles.
        let mut guard = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        for attempt in 0..2 {
            if guard.is_none() {
                *guard = Some(connect(&self.provider, self.provider.dot_port, b"dot")?);
            }
            let tls = guard.as_mut().expect("connection was just established");
            match dot_exchange(tls, &framed) {
                Ok(resp) => return Ok(resp),
                Err(e) => {
                    // Drop the broken connection; the next attempt reconnects.
                    *guard = None;
                    if attempt == 1 {
                        return Err(e);
                    }
                }
            }
        }
        unreachable!("the loop returns on success, on the second failure, or on a connect error")
    }
}

/// Send one framed query over an established DoT connection and read the reply:
/// a 2-byte big-endian length, then that many bytes.
fn dot_exchange(tls: &mut Tls, framed: &[u8]) -> Result<Vec<u8>, TransportError> {
    tls.write_all(framed).map_err(|_| TransportError::Network)?;
    tls.flush().map_err(|_| TransportError::Network)?;
    let mut len_buf = [0u8; 2];
    tls.read_exact(&mut len_buf)
        .map_err(|_| TransportError::Network)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(TransportError::Protocol);
    }
    let mut buf = vec![0u8; len];
    tls.read_exact(&mut buf)
        .map_err(|_| TransportError::Network)?;
    Ok(buf)
}

/// DNS-over-HTTPS upstream (RFC 8484, HTTP/1.1 POST). Opens a fresh connection
/// per query (`Connection: close`); the resolver's cache fronts it, so this is
/// not a per-packet cost.
pub struct Doh {
    provider: Provider,
}

impl Doh {
    /// A DoH transport for `provider`.
    pub fn new(provider: Provider) -> Self {
        Doh { provider }
    }
}

impl Transport for Doh {
    fn name(&self) -> &str {
        self.provider.name
    }

    fn query(&self, query: &[u8]) -> Result<Vec<u8>, TransportError> {
        if query.len() > MAX_MESSAGE {
            return Err(TransportError::Protocol);
        }
        let mut tls = connect(&self.provider, 443, b"http/1.1")?;
        let req = build_doh_request(&self.provider, query);
        tls.write_all(&req).map_err(|_| TransportError::Network)?;
        tls.flush().map_err(|_| TransportError::Network)?;
        read_doh_response(&mut tls)
    }
}

/// Build the HTTP/1.1 POST request for a DoH query (RFC 8484).
fn build_doh_request(provider: &Provider, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Accept: application/dns-message\r\n\
         Content-Type: application/dns-message\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        provider.doh_path,
        provider.tls_name,
        body.len()
    );
    let mut out = Vec::with_capacity(head.len() + body.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body);
    out
}

/// Read an HTTP/1.1 DoH response and return the raw DNS message body. Requires a
/// 200 status; the body length comes from `Content-Length` (what every DoH
/// provider sends for `application/dns-message`), else it reads to EOF.
fn read_doh_response(tls: &mut Tls) -> Result<Vec<u8>, TransportError> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        let n = tls.read(&mut chunk).map_err(|_| TransportError::Network)?;
        if n == 0 {
            return Err(TransportError::Protocol); // closed before headers ended
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_HTTP_HEADER {
            return Err(TransportError::Protocol);
        }
    };

    let header = &buf[..header_end];
    if !status_is_200(header) {
        return Err(TransportError::Protocol);
    }
    let content_len = parse_content_length(header);
    let mut body = buf[header_end..].to_vec();

    match content_len {
        Some(cl) => {
            if cl > MAX_MESSAGE {
                return Err(TransportError::Protocol);
            }
            while body.len() < cl {
                let n = tls.read(&mut chunk).map_err(|_| TransportError::Network)?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
            if body.len() < cl {
                return Err(TransportError::Protocol);
            }
            body.truncate(cl);
        }
        None => loop {
            // No Content-Length: read until the server closes (Connection: close).
            let n = tls.read(&mut chunk).map_err(|_| TransportError::Network)?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
            if body.len() > MAX_MESSAGE {
                return Err(TransportError::Protocol);
            }
        },
    }

    if body.is_empty() {
        return Err(TransportError::Protocol);
    }
    Ok(body)
}

/// Whether the response's status line carries a 200 code.
fn status_is_200(header: &[u8]) -> bool {
    let line_end = find_subsequence(header, b"\r\n").unwrap_or(header.len());
    let line = &header[..line_end];
    match line.iter().position(|&b| b == b' ') {
        Some(sp) => line[sp + 1..].starts_with(b"200"),
        None => false,
    }
}

/// Parse the `Content-Length` header value, case-insensitively.
fn parse_content_length(header: &[u8]) -> Option<usize> {
    let lower = header.to_ascii_lowercase();
    let needle = b"content-length:";
    let pos = find_subsequence(&lower, needle)?;
    let after = &header[pos + needle.len()..];
    let line_end = find_subsequence(after, b"\r\n").unwrap_or(after.len());
    std::str::from_utf8(&after[..line_end])
        .ok()?
        .trim()
        .parse::<usize>()
        .ok()
}

/// Index of the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider() -> Provider {
        Provider {
            name: "Test",
            bootstrap: &[],
            tls_name: "dns.example",
            doh_path: "/dns-query",
            dot_port: 853,
        }
    }

    #[test]
    fn doh_request_has_required_headers() {
        let req = build_doh_request(&test_provider(), &[0xAB, 0xCD]);
        let text = String::from_utf8_lossy(&req);
        assert!(text.starts_with("POST /dns-query HTTP/1.1\r\n"));
        assert!(text.contains("Host: dns.example\r\n"));
        assert!(text.contains("Content-Type: application/dns-message\r\n"));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(req.ends_with(&[0xAB, 0xCD]));
    }

    #[test]
    fn parses_200_status() {
        assert!(status_is_200(b"HTTP/1.1 200 OK\r\n"));
        assert!(status_is_200(b"HTTP/2 200\r\n"));
        assert!(!status_is_200(b"HTTP/1.1 404 Not Found\r\n"));
        assert!(!status_is_200(b"HTTP/1.1 500 Internal Server Error\r\n"));
    }

    #[test]
    fn parses_content_length_case_insensitively() {
        let h = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\ncontent-length: 42\r\n\r\n";
        assert_eq!(parse_content_length(h), Some(42));
        assert_eq!(parse_content_length(b"HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    #[test]
    fn finds_subsequence() {
        assert_eq!(find_subsequence(b"ab\r\n\r\ncd", b"\r\n\r\n"), Some(2));
        assert_eq!(find_subsequence(b"abc", b"x"), None);
        assert_eq!(find_subsequence(b"", b"x"), None);
    }
}
