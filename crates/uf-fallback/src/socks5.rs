//! SOCKS5 (RFC 1928) client framing, plus the username/password sub-negotiation
//! (RFC 1929). Everything here is a pure byte codec — no sockets — so the whole
//! protocol is table-tested with no network. The live relay (owning the TCP
//! socket and pumping these bytes) is wired in the service in v2; it only drives
//! the [`Socks5Handshake`] state machine below.

use crate::config::{Endpoint, UserPass};
use crate::error::{FallbackError, Result};
use crate::fallback::{Fallback, FallbackKind, Handshake, HandshakeStep};
use crate::target::{Target, TargetAddr};
use std::net::IpAddr;

/// Protocol version byte.
pub const VERSION: u8 = 0x05;

/// Authentication method numbers (RFC 1928 §3).
pub mod method {
    /// No authentication required.
    pub const NO_AUTH: u8 = 0x00;
    /// Username/password (RFC 1929).
    pub const USERPASS: u8 = 0x02;
    /// Sentinel: server found no acceptable method.
    pub const NO_ACCEPTABLE: u8 = 0xFF;
}

/// CONNECT command.
pub const CMD_CONNECT: u8 = 0x01;
/// Reserved byte, must be zero.
const RSV: u8 = 0x00;

/// Address type tags (RFC 1928 §4).
pub mod atyp {
    /// IPv4 address, 4 bytes.
    pub const IPV4: u8 = 0x01;
    /// Domain name, 1-byte length prefix.
    pub const DOMAIN: u8 = 0x03;
    /// IPv6 address, 16 bytes.
    pub const IPV6: u8 = 0x04;
}

/// RFC 1929 (username/password auth) version byte.
pub const AUTH_VERSION: u8 = 0x01;

// --- encoding ---------------------------------------------------------------

/// Encode the client greeting: version, method count, and the offered methods.
pub fn encode_greeting(methods: &[u8]) -> Result<Vec<u8>> {
    if methods.is_empty() || methods.len() > 255 {
        return Err(FallbackError::Malformed);
    }
    let mut out = Vec::with_capacity(2 + methods.len());
    out.push(VERSION);
    out.push(methods.len() as u8);
    out.extend_from_slice(methods);
    Ok(out)
}

/// Encode an RFC 1929 username/password authentication request.
pub fn encode_userpass(auth: &UserPass) -> Result<Vec<u8>> {
    let (u, p) = (auth.username.as_bytes(), auth.password.as_bytes());
    if u.len() > 255 || p.len() > 255 {
        return Err(FallbackError::FieldTooLong);
    }
    let mut out = Vec::with_capacity(3 + u.len() + p.len());
    out.push(AUTH_VERSION);
    out.push(u.len() as u8);
    out.extend_from_slice(u);
    out.push(p.len() as u8);
    out.extend_from_slice(p);
    Ok(out)
}

/// Encode a CONNECT request for `target`.
pub fn encode_connect(target: &Target) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(22);
    out.push(VERSION);
    out.push(CMD_CONNECT);
    out.push(RSV);
    match &target.addr {
        TargetAddr::Ip(IpAddr::V4(ip)) => {
            out.push(atyp::IPV4);
            out.extend_from_slice(&ip.octets());
        }
        TargetAddr::Ip(IpAddr::V6(ip)) => {
            out.push(atyp::IPV6);
            out.extend_from_slice(&ip.octets());
        }
        TargetAddr::Domain(name) => {
            let bytes = name.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                return Err(FallbackError::FieldTooLong);
            }
            out.push(atyp::DOMAIN);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(out)
}

// --- decoding ---------------------------------------------------------------

/// Parse the server's method-selection reply; returns the chosen method byte.
/// [`Truncated`](FallbackError::Truncated) means "need more bytes", not failure.
pub fn parse_method_reply(buf: &[u8]) -> Result<u8> {
    if buf.len() < 2 {
        return Err(FallbackError::Truncated);
    }
    if buf[0] != VERSION {
        return Err(FallbackError::Malformed);
    }
    if buf[1] == method::NO_ACCEPTABLE {
        return Err(FallbackError::AuthUnsupported);
    }
    Ok(buf[1])
}

/// Parse an RFC 1929 auth reply. `Ok(())` on success (status 0).
pub fn parse_userpass_reply(buf: &[u8]) -> Result<()> {
    if buf.len() < 2 {
        return Err(FallbackError::Truncated);
    }
    // RFC 1929 fixes the reply version at 0x01; some servers echo 0x05. Accept
    // both rather than fail a working proxy.
    if buf[0] != AUTH_VERSION && buf[0] != VERSION {
        return Err(FallbackError::Malformed);
    }
    if buf[1] == 0 {
        Ok(())
    } else {
        Err(FallbackError::AuthFailed)
    }
}

/// A parsed CONNECT reply: the success and the length of the reply so the caller
/// can split any already-pipelined payload that follows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectReply {
    /// The bound address the proxy reports (informational).
    pub bound: TargetAddr,
    /// The bound port.
    pub bound_port: u16,
    /// Total bytes the reply occupies in `buf`.
    pub len: usize,
}

/// Parse a CONNECT reply. Returns the bound address on success, an error whose
/// [`Refused`](FallbackError::Refused) code is the SOCKS reply field otherwise,
/// or [`Truncated`](FallbackError::Truncated) if more bytes are needed.
pub fn parse_connect_reply(buf: &[u8]) -> Result<ConnectReply> {
    if buf.len() < 4 {
        return Err(FallbackError::Truncated);
    }
    if buf[0] != VERSION {
        return Err(FallbackError::Malformed);
    }
    let rep = buf[1];
    // buf[2] is RSV.
    let (bound, addr_len) = match buf[3] {
        atyp::IPV4 => {
            if buf.len() < 4 + 4 {
                return Err(FallbackError::Truncated);
            }
            let o: [u8; 4] = buf[4..8].try_into().unwrap();
            (TargetAddr::Ip(IpAddr::from(o)), 4)
        }
        atyp::IPV6 => {
            if buf.len() < 4 + 16 {
                return Err(FallbackError::Truncated);
            }
            let o: [u8; 16] = buf[4..20].try_into().unwrap();
            (TargetAddr::Ip(IpAddr::from(o)), 16)
        }
        atyp::DOMAIN => {
            let dlen = *buf.get(4).ok_or(FallbackError::Truncated)? as usize;
            if buf.len() < 5 + dlen {
                return Err(FallbackError::Truncated);
            }
            let name = core::str::from_utf8(&buf[5..5 + dlen])
                .map_err(|_| FallbackError::Malformed)?
                .to_owned();
            (TargetAddr::Domain(name), 1 + dlen)
        }
        _ => return Err(FallbackError::Malformed),
    };
    let port_off = 4 + addr_len;
    if buf.len() < port_off + 2 {
        return Err(FallbackError::Truncated);
    }
    // Only report the bound address when the connection actually succeeded.
    if rep != 0 {
        return Err(FallbackError::Refused(rep as u16));
    }
    let bound_port = u16::from_be_bytes([buf[port_off], buf[port_off + 1]]);
    Ok(ConnectReply {
        bound,
        bound_port,
        len: port_off + 2,
    })
}

// --- handshake state machine ------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Greet,
    AwaitMethod,
    AwaitAuth,
    AwaitConnect,
    Done,
}

/// A SOCKS5 CONNECT handshake driven as a pure state machine. The caller owns the
/// socket: it calls [`pump`](Handshake::pump) with any bytes received (empty on
/// the first call) and sends whatever bytes come back, until the step reports the
/// tunnel is established.
pub struct Socks5Handshake {
    target: Target,
    auth: Option<UserPass>,
    state: State,
    rx: Vec<u8>,
}

impl Socks5Handshake {
    fn new(target: Target, auth: Option<UserPass>) -> Self {
        Socks5Handshake {
            target,
            auth,
            state: State::Greet,
            rx: Vec::new(),
        }
    }

    fn offered_methods(&self) -> Vec<u8> {
        if self.auth.is_some() {
            vec![method::NO_AUTH, method::USERPASS]
        } else {
            vec![method::NO_AUTH]
        }
    }
}

impl Handshake for Socks5Handshake {
    fn pump(&mut self, from_upstream: &[u8]) -> Result<HandshakeStep> {
        self.rx.extend_from_slice(from_upstream);
        match self.state {
            State::Greet => {
                let greeting = encode_greeting(&self.offered_methods())?;
                self.state = State::AwaitMethod;
                Ok(HandshakeStep::send(greeting))
            }
            State::AwaitMethod => {
                let chosen = match parse_method_reply(&self.rx) {
                    Ok(m) => m,
                    Err(FallbackError::Truncated) => return Ok(HandshakeStep::wait()),
                    Err(e) => return Err(e),
                };
                self.rx.drain(..2);
                match chosen {
                    method::NO_AUTH => {
                        self.state = State::AwaitConnect;
                        Ok(HandshakeStep::send(encode_connect(&self.target)?))
                    }
                    method::USERPASS => {
                        let auth = self.auth.as_ref().ok_or(FallbackError::AuthUnsupported)?;
                        self.state = State::AwaitAuth;
                        Ok(HandshakeStep::send(encode_userpass(auth)?))
                    }
                    _ => Err(FallbackError::AuthUnsupported),
                }
            }
            State::AwaitAuth => {
                match parse_userpass_reply(&self.rx) {
                    Ok(()) => {}
                    Err(FallbackError::Truncated) => return Ok(HandshakeStep::wait()),
                    Err(e) => return Err(e),
                }
                self.rx.drain(..2);
                self.state = State::AwaitConnect;
                Ok(HandshakeStep::send(encode_connect(&self.target)?))
            }
            State::AwaitConnect => {
                let reply = match parse_connect_reply(&self.rx) {
                    Ok(r) => r,
                    Err(FallbackError::Truncated) => return Ok(HandshakeStep::wait()),
                    Err(e) => return Err(e),
                };
                // Any bytes after the reply are already tunnel payload.
                let leftover = self.rx.split_off(reply.len);
                self.rx = leftover;
                self.state = State::Done;
                Ok(HandshakeStep::established())
            }
            State::Done => Ok(HandshakeStep::established()),
        }
    }

    fn established(&self) -> bool {
        self.state == State::Done
    }

    fn take_leftover(&mut self) -> Vec<u8> {
        if self.state == State::Done {
            std::mem::take(&mut self.rx)
        } else {
            Vec::new()
        }
    }
}

/// A configured SOCKS5 upstream. Built from [`UpstreamConfig::Socks5`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5Upstream {
    /// Proxy endpoint the service dials.
    pub endpoint: Endpoint,
    /// Optional credentials.
    pub auth: Option<UserPass>,
}

impl Fallback for Socks5Upstream {
    fn kind(&self) -> FallbackKind {
        FallbackKind::Socks5
    }

    fn connect(&self, target: &Target) -> Result<Box<dyn Handshake>> {
        Ok(Box::new(Socks5Handshake::new(
            target.clone(),
            self.auth.clone(),
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn up(user: &str, pass: &str) -> UserPass {
        UserPass {
            username: user.into(),
            password: pass.into(),
        }
    }

    #[test]
    fn greeting_encodes_offered_methods() {
        assert_eq!(
            encode_greeting(&[method::NO_AUTH]).unwrap(),
            vec![0x05, 0x01, 0x00]
        );
        assert_eq!(
            encode_greeting(&[method::NO_AUTH, method::USERPASS]).unwrap(),
            vec![0x05, 0x02, 0x00, 0x02]
        );
        assert_eq!(encode_greeting(&[]), Err(FallbackError::Malformed));
    }

    #[test]
    fn connect_request_encodes_each_address_type() {
        // (target, expected prefix bytes after VER/CMD/RSV)
        let v4 = encode_connect(&Target::ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443)).unwrap();
        assert_eq!(v4, vec![0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB]);

        let dom = encode_connect(&Target::domain("a.example", 80)).unwrap();
        let mut want = vec![0x05, 0x01, 0x00, 0x03, 9];
        want.extend_from_slice(b"a.example");
        want.extend_from_slice(&80u16.to_be_bytes());
        assert_eq!(dom, want);

        let v6 = encode_connect(&Target::ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443)).unwrap();
        assert_eq!(v6[3], atyp::IPV6);
        assert_eq!(&v6[v6.len() - 2..], &8443u16.to_be_bytes());
        assert_eq!(v6.len(), 4 + 16 + 2);
    }

    #[test]
    fn connect_request_rejects_overlong_domain() {
        let long = "a".repeat(256);
        assert_eq!(
            encode_connect(&Target::domain(long, 80)),
            Err(FallbackError::FieldTooLong)
        );
    }

    #[test]
    fn userpass_encodes_and_rejects_overlong() {
        assert_eq!(
            encode_userpass(&up("me", "pw")).unwrap(),
            vec![0x01, 2, b'm', b'e', 2, b'p', b'w']
        );
        let long = "x".repeat(256);
        assert_eq!(
            encode_userpass(&up(&long, "pw")),
            Err(FallbackError::FieldTooLong)
        );
    }

    #[test]
    fn method_reply_cases() {
        assert_eq!(parse_method_reply(&[0x05, 0x00]).unwrap(), 0x00);
        assert_eq!(parse_method_reply(&[0x05, 0x02]).unwrap(), 0x02);
        assert_eq!(parse_method_reply(&[0x05]), Err(FallbackError::Truncated));
        assert_eq!(
            parse_method_reply(&[0x04, 0x00]),
            Err(FallbackError::Malformed)
        );
        assert_eq!(
            parse_method_reply(&[0x05, 0xFF]),
            Err(FallbackError::AuthUnsupported)
        );
    }

    #[test]
    fn userpass_reply_cases() {
        assert_eq!(parse_userpass_reply(&[0x01, 0x00]), Ok(()));
        assert_eq!(parse_userpass_reply(&[0x05, 0x00]), Ok(())); // tolerant of echoed 0x05
        assert_eq!(
            parse_userpass_reply(&[0x01, 0x01]),
            Err(FallbackError::AuthFailed)
        );
        assert_eq!(parse_userpass_reply(&[0x01]), Err(FallbackError::Truncated));
        assert_eq!(
            parse_userpass_reply(&[0x02, 0x00]),
            Err(FallbackError::Malformed)
        );
    }

    #[test]
    fn connect_reply_success_and_refusal() {
        // success, IPv4 bound 0.0.0.0:0
        let ok = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        let r = parse_connect_reply(&ok).unwrap();
        assert_eq!(r.len, 10);
        assert_eq!(r.bound, TargetAddr::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));

        // refusal: rep=0x05 (connection refused)
        let refused = [0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        assert_eq!(
            parse_connect_reply(&refused),
            Err(FallbackError::Refused(5))
        );

        // truncated at every prefix of a valid reply
        for n in 0..ok.len() {
            assert_eq!(parse_connect_reply(&ok[..n]), Err(FallbackError::Truncated));
        }

        // bad version / bad atyp
        assert_eq!(
            parse_connect_reply(&[0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
            Err(FallbackError::Malformed)
        );
        assert_eq!(
            parse_connect_reply(&[0x05, 0x00, 0x00, 0x09, 0, 0]),
            Err(FallbackError::Malformed)
        );
    }

    #[test]
    fn connect_reply_reports_trailing_payload_length() {
        // success reply followed by 3 bytes of already-arrived tunnel data
        let mut buf = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let r = parse_connect_reply(&buf).unwrap();
        assert_eq!(r.len, 10);
        assert_eq!(&buf[r.len..], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn handshake_no_auth_full_flow() {
        let mut hs = Socks5Handshake::new(Target::domain("blocked.example", 443), None);
        // first pump: greeting
        let step = hs.pump(&[]).unwrap();
        assert_eq!(step.send, vec![0x05, 0x01, 0x00]);
        assert!(!step.established);
        // server selects no-auth
        let step = hs.pump(&[0x05, 0x00]).unwrap();
        assert_eq!(
            step.send,
            encode_connect(&Target::domain("blocked.example", 443)).unwrap()
        );
        // server success reply
        let step = hs
            .pump(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .unwrap();
        assert!(step.established);
        assert!(hs.established());
    }

    #[test]
    fn handshake_userpass_full_flow() {
        let mut hs = Socks5Handshake::new(
            Target::ip(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
            Some(up("u", "p")),
        );
        let step = hs.pump(&[]).unwrap();
        assert_eq!(step.send, vec![0x05, 0x02, 0x00, 0x02]);
        // server picks userpass
        let step = hs.pump(&[0x05, 0x02]).unwrap();
        assert_eq!(step.send, vec![0x01, 1, b'u', 1, b'p']);
        // auth ok -> connect sent
        let step = hs.pump(&[0x01, 0x00]).unwrap();
        assert_eq!(step.send[0], VERSION);
        assert_eq!(step.send[1], CMD_CONNECT);
        // connect success
        let step = hs
            .pump(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .unwrap();
        assert!(step.established);
    }

    #[test]
    fn handshake_tolerates_fragmented_replies() {
        let mut hs = Socks5Handshake::new(Target::domain("x.example", 443), None);
        assert_eq!(hs.pump(&[]).unwrap().send, vec![0x05, 0x01, 0x00]);
        // method reply split across two reads
        assert!(hs.pump(&[0x05]).unwrap().send.is_empty());
        let step = hs.pump(&[0x00]).unwrap();
        assert!(!step.send.is_empty()); // connect request now
        // connect reply dribbled one byte at a time
        let reply = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for b in &reply[..reply.len() - 1] {
            assert!(!hs.pump(&[*b]).unwrap().established);
        }
        assert!(hs.pump(&[reply[reply.len() - 1]]).unwrap().established);
    }

    #[test]
    fn domain_reply_truncated_at_length_byte_does_not_panic() {
        assert_eq!(
            parse_connect_reply(&[0x05, 0x00, 0x00, atyp::DOMAIN]),
            Err(FallbackError::Truncated)
        );
        let mut ok = vec![0x05, 0x00, 0x00, atyp::DOMAIN, 3];
        ok.extend_from_slice(b"a.b");
        ok.extend_from_slice(&443u16.to_be_bytes());
        for n in 0..ok.len() {
            assert_eq!(parse_connect_reply(&ok[..n]), Err(FallbackError::Truncated));
        }
        assert_eq!(parse_connect_reply(&ok).unwrap().len, ok.len());
    }

    #[test]
    fn handshake_hands_over_trailing_stream_bytes() {
        let mut hs = Socks5Handshake::new(Target::domain("x.example", 443), None);
        hs.pump(&[]).unwrap();
        hs.pump(&[0x05, 0x00]).unwrap();
        let mut reply = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        reply.extend_from_slice(&[0x16, 0x03, 0x03]);
        assert!(hs.pump(&reply).unwrap().established);
        assert_eq!(hs.take_leftover(), vec![0x16, 0x03, 0x03]);
        assert!(hs.take_leftover().is_empty());
    }

    #[test]
    fn handshake_propagates_server_refusal() {
        let mut hs = Socks5Handshake::new(Target::domain("x.example", 443), None);
        hs.pump(&[]).unwrap();
        hs.pump(&[0x05, 0x00]).unwrap();
        assert_eq!(
            hs.pump(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
            Err(FallbackError::Refused(2))
        );
    }

    #[test]
    fn upstream_builds_handshake() {
        let u = Socks5Upstream {
            endpoint: Endpoint {
                host: "127.0.0.1".into(),
                port: 1080,
            },
            auth: None,
        };
        assert_eq!(u.kind(), FallbackKind::Socks5);
        let mut hs = u.connect(&Target::domain("x.example", 443)).unwrap();
        assert_eq!(hs.pump(&[]).unwrap().send, vec![0x05, 0x01, 0x00]);
    }
}
