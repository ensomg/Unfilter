//! HTTP `CONNECT` tunnelling: build the request line + headers, parse the status
//! reply. Pure byte codec, table-tested, no sockets — the service drives the
//! [`HttpConnectHandshake`] state machine in v2.
//!
//! Only the handshake is HTTP; once the proxy returns `2xx` the connection is a
//! raw byte tunnel, identical to SOCKS5 after its reply.

use crate::config::{Endpoint, UserPass};
use crate::error::{FallbackError, Result};
use crate::fallback::{Fallback, FallbackKind, Handshake, HandshakeStep};
use crate::target::{Target, TargetAddr};

/// Render a target as the `host:port` authority form a CONNECT request needs.
/// IPv6 literals are bracketed per RFC 3986.
pub fn authority(target: &Target) -> String {
    match &target.addr {
        TargetAddr::Ip(std::net::IpAddr::V6(ip)) => format!("[{ip}]:{}", target.port),
        TargetAddr::Ip(ip) => format!("{ip}:{}", target.port),
        TargetAddr::Domain(name) => format!("{name}:{}", target.port),
    }
}

/// Build a `CONNECT` request for `target`, optionally with Basic proxy auth.
/// Largest proxy reply header we buffer before giving up on the proxy.
const MAX_REPLY_HEADER: usize = 16 * 1024;

/// Whether a value may be placed in a request line or header: no CR/LF (which
/// would let a crafted host or credential inject headers) and no other control
/// bytes.
fn header_safe(s: &str) -> bool {
    !s.bytes().any(|b| b.is_ascii_control())
}

pub fn encode_request(target: &Target, auth: Option<&UserPass>) -> Result<Vec<u8>> {
    if let TargetAddr::Domain(name) = &target.addr {
        if name.is_empty() || name.contains(' ') || !header_safe(name) {
            return Err(FallbackError::Malformed);
        }
    }
    if let Some(a) = auth {
        if !header_safe(&a.username) || !header_safe(&a.password) {
            return Err(FallbackError::Malformed);
        }
    }
    let authority = authority(target);
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(a) = auth {
        let token = base64_encode(format!("{}:{}", a.username, a.password).as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    Ok(req.into_bytes())
}

/// A parsed CONNECT status reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectStatus {
    /// HTTP status code.
    pub code: u16,
    /// Total bytes the headers occupy (up to and including the blank line), so
    /// the caller can split any pipelined tunnel payload that follows.
    pub len: usize,
}

/// Parse a CONNECT response. Needs the full header block (ending `\r\n\r\n`);
/// returns [`Truncated`](FallbackError::Truncated) until then. A `2xx` status is
/// success; anything else is [`Refused`](FallbackError::Refused) with the code.
pub fn parse_response(buf: &[u8]) -> Result<ConnectStatus> {
    let end = match find_header_end(buf) {
        Some(e) => e,
        None if buf.len() > MAX_REPLY_HEADER => return Err(FallbackError::Malformed),
        None => return Err(FallbackError::Truncated),
    };
    // Status line is the first line, terminated by the first CRLF.
    let line_end = find_crlf(buf).ok_or(FallbackError::Malformed)?;
    let line = core::str::from_utf8(&buf[..line_end]).map_err(|_| FallbackError::Malformed)?;
    // "HTTP/1.1 200 Connection established"
    let mut parts = line.splitn(3, ' ');
    let version = parts.next().ok_or(FallbackError::Malformed)?;
    if !version.starts_with("HTTP/") {
        return Err(FallbackError::Malformed);
    }
    let code: u16 = parts
        .next()
        .ok_or(FallbackError::Malformed)?
        .parse()
        .map_err(|_| FallbackError::Malformed)?;
    if (200..300).contains(&code) {
        Ok(ConnectStatus { code, len: end })
    } else {
        Err(FallbackError::Refused(code))
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Standard base64 (RFC 4648) encoder for the Basic auth token. Tiny and
/// self-contained to keep the crate free of extra dependencies.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18 & 0x3F) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6 & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

// --- handshake state machine ------------------------------------------------

/// An HTTP CONNECT handshake driven as a pure state machine (see [`Handshake`]).
pub struct HttpConnectHandshake {
    target: Target,
    auth: Option<UserPass>,
    sent: bool,
    done: bool,
    rx: Vec<u8>,
}

impl HttpConnectHandshake {
    fn new(target: Target, auth: Option<UserPass>) -> Self {
        HttpConnectHandshake {
            target,
            auth,
            sent: false,
            done: false,
            rx: Vec::new(),
        }
    }
}

impl Handshake for HttpConnectHandshake {
    fn pump(&mut self, from_upstream: &[u8]) -> Result<HandshakeStep> {
        if !self.sent {
            self.sent = true;
            return Ok(HandshakeStep::send(encode_request(
                &self.target,
                self.auth.as_ref(),
            )?));
        }
        self.rx.extend_from_slice(from_upstream);
        match parse_response(&self.rx) {
            Ok(status) => {
                let leftover = self.rx.split_off(status.len);
                self.rx = leftover;
                self.done = true;
                Ok(HandshakeStep::established())
            }
            Err(FallbackError::Truncated) => Ok(HandshakeStep::wait()),
            Err(e) => Err(e),
        }
    }

    fn established(&self) -> bool {
        self.done
    }

    fn take_leftover(&mut self) -> Vec<u8> {
        if self.done {
            std::mem::take(&mut self.rx)
        } else {
            Vec::new()
        }
    }
}

/// A configured HTTP CONNECT upstream. Built from [`UpstreamConfig::HttpConnect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpConnectUpstream {
    /// Proxy endpoint the service dials.
    pub endpoint: Endpoint,
    /// Optional Basic-auth credentials.
    pub auth: Option<UserPass>,
}

impl Fallback for HttpConnectUpstream {
    fn kind(&self) -> FallbackKind {
        FallbackKind::HttpConnect
    }

    fn connect(&self, target: &Target) -> Result<Box<dyn Handshake>> {
        Ok(Box::new(HttpConnectHandshake::new(
            target.clone(),
            self.auth.clone(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn base64_matches_known_vectors() {
        // RFC 4648 test vectors.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        // Basic auth token "user:pass".
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn authority_formats_each_address_type() {
        assert_eq!(
            authority(&Target::domain("a.example", 443)),
            "a.example:443"
        );
        assert_eq!(
            authority(&Target::ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80)),
            "1.2.3.4:80"
        );
        assert_eq!(
            authority(&Target::ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443)),
            "[::1]:8443"
        );
    }

    #[test]
    fn request_without_auth() {
        let req = encode_request(&Target::domain("blocked.example", 443), None).unwrap();
        assert_eq!(
            req,
            b"CONNECT blocked.example:443 HTTP/1.1\r\nHost: blocked.example:443\r\n\r\n"
        );
    }

    #[test]
    fn request_with_basic_auth() {
        let auth = UserPass {
            username: "user".into(),
            password: "pass".into(),
        };
        let req = encode_request(&Target::domain("x.example", 443), Some(&auth)).unwrap();
        let text = String::from_utf8(req).unwrap();
        assert!(text.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn response_status_cases() {
        let ok = b"HTTP/1.1 200 Connection established\r\n\r\n";
        let s = parse_response(ok).unwrap();
        assert_eq!(s.code, 200);
        assert_eq!(s.len, ok.len());

        let ok_hdrs = b"HTTP/1.1 200 OK\r\nX-Proxy: foo\r\n\r\n";
        assert_eq!(parse_response(ok_hdrs).unwrap().code, 200);

        // 2xx variants pass.
        assert_eq!(
            parse_response(b"HTTP/1.0 204 No Content\r\n\r\n")
                .unwrap()
                .code,
            204
        );

        // non-2xx is refusal with the code.
        assert_eq!(
            parse_response(b"HTTP/1.1 407 Proxy Auth Required\r\n\r\n"),
            Err(FallbackError::Refused(407))
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 403 Forbidden\r\n\r\n"),
            Err(FallbackError::Refused(403))
        );
    }

    #[test]
    fn response_truncated_until_blank_line() {
        let full = b"HTTP/1.1 200 OK\r\nX-H: 1\r\n\r\n";
        for n in 0..full.len() {
            assert_eq!(
                parse_response(&full[..n]),
                Err(FallbackError::Truncated),
                "len {n}"
            );
        }
        assert!(parse_response(full).is_ok());
    }

    #[test]
    fn response_malformed_status_line() {
        assert_eq!(
            parse_response(b"NOTHTTP 200 OK\r\n\r\n"),
            Err(FallbackError::Malformed)
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 twohundred OK\r\n\r\n"),
            Err(FallbackError::Malformed)
        );
    }

    #[test]
    fn response_reports_trailing_payload() {
        let mut buf = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        buf.extend_from_slice(&[0x16, 0x03, 0x03]); // start of a TLS record
        let s = parse_response(&buf).unwrap();
        assert_eq!(&buf[s.len..], &[0x16, 0x03, 0x03]);
    }

    #[test]
    fn handshake_full_flow() {
        let mut hs = HttpConnectHandshake::new(Target::domain("blocked.example", 443), None);
        let step = hs.pump(&[]).unwrap();
        assert!(step.send.starts_with(b"CONNECT blocked.example:443"));
        assert!(!step.established);
        // reply arrives in two fragments
        assert!(hs.pump(b"HTTP/1.1 200 Conn").unwrap().send.is_empty());
        let step = hs.pump(b"ection established\r\n\r\n").unwrap();
        assert!(step.established);
        assert!(hs.established());
    }

    #[test]
    fn handshake_propagates_refusal() {
        let mut hs = HttpConnectHandshake::new(Target::domain("x.example", 443), None);
        hs.pump(&[]).unwrap();
        assert_eq!(
            hs.pump(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"),
            Err(FallbackError::Refused(502))
        );
    }

    #[test]
    fn upstream_builds_handshake() {
        let u = HttpConnectUpstream {
            endpoint: Endpoint {
                host: "proxy.example".into(),
                port: 8080,
            },
            auth: None,
        };
        assert_eq!(u.kind(), FallbackKind::HttpConnect);
        let mut hs = u.connect(&Target::domain("x.example", 443)).unwrap();
        assert!(hs.pump(&[]).unwrap().send.starts_with(b"CONNECT"));
    }

    #[test]
    fn crlf_in_host_or_credentials_is_rejected() {
        let evil = Target::domain("a.example\r\nX-Evil: 1", 443);
        assert_eq!(encode_request(&evil, None), Err(FallbackError::Malformed));
        let auth = UserPass {
            username: "u\r\nX: y".into(),
            password: "p".into(),
        };
        assert_eq!(
            encode_request(&Target::domain("a.example", 443), Some(&auth)),
            Err(FallbackError::Malformed)
        );
    }

    #[test]
    fn oversized_reply_header_is_rejected() {
        let junk = vec![b'a'; MAX_REPLY_HEADER + 1];
        assert_eq!(parse_response(&junk), Err(FallbackError::Malformed));
    }

    #[test]
    fn leftover_after_200_is_handed_over() {
        let mut hs = HttpConnectHandshake::new(Target::domain("x.example", 443), None);
        hs.pump(&[]).unwrap();
        let reply = b"HTTP/1.1 200 OK\r\n\r\n\x16\x03";
        assert!(hs.pump(reply).unwrap().established);
        assert_eq!(hs.take_leftover(), vec![0x16, 0x03]);
    }
}
