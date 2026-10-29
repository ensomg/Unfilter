//! Port-53 interception codec: turn a captured outbound DNS query (a raw
//! IPv4/IPv6 + UDP packet) into the inbound reply packet the OS resolver will
//! accept, with the answer taken from the trusted DoH/DoT resolver.
//!
//! Pure byte work, no I/O: the Windows capture loop in [`crate::runtime`] feeds
//! it packets and injects what it returns. Anything it does not understand
//! yields `None`, and the caller re-injects the original query unchanged
//! (fail-open: the system resolver then simply gets the ISP's answer).

use std::net::IpAddr;

use uf_dns::QType;

/// TTL put on synthesized answers. Short, so a strategy/upstream change is
/// picked up quickly; the service's own cache absorbs the repeat queries.
const ANSWER_TTL: u32 = 60;

const QTYPE_SVCB: u16 = 64;
const QTYPE_HTTPS: u16 = 65;

/// A captured DNS query: what was asked, and where its parts sit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Queried name (lower-case, no trailing dot).
    pub name: String,
    /// Queried type.
    pub qtype: QType,
    /// IPv6 packet (else IPv4).
    pub ipv6: bool,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
    /// DNS id + flags (first four header bytes of the query).
    id_flags: [u8; 4],
    /// The question section, copied verbatim into the reply.
    question: Vec<u8>,
}

/// How to answer a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// NOERROR with these addresses (those not matching the query type are
    /// dropped; none left means an empty NOERROR answer).
    Addrs(Vec<IpAddr>),
    /// NXDOMAIN.
    NxDomain,
}

/// What the interceptor should do with a query type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Resolve through the trusted upstreams.
    Resolve,
    /// Answer NOERROR with no records (SVCB/HTTPS: keeps the browser from
    /// using hints from a poisoned ISP answer; it falls back to A/AAAA).
    Empty,
    /// Leave it to the system resolver (re-inject unchanged).
    Pass,
}

impl Query {
    /// What to do with this query.
    pub fn policy(&self) -> Policy {
        match self.qtype {
            QType::A | QType::Aaaa => Policy::Resolve,
            QType::Other(QTYPE_SVCB | QTYPE_HTTPS) => Policy::Empty,
            QType::Other(_) => Policy::Pass,
        }
    }
}

/// Parse a captured IP/UDP packet carrying a standard DNS query. Returns
/// `None` for anything else (responses, multi-question, other opcodes, IPv6
/// extension headers, truncation).
pub fn parse_query(pkt: &[u8]) -> Option<Query> {
    let (ipv6, l4, src_ip, dst_ip) = match pkt.first()? >> 4 {
        4 => {
            let ihl = usize::from(pkt[0] & 0x0F) * 4;
            if ihl < 20 || pkt.len() < ihl + 8 || pkt[9] != 17 {
                return None;
            }
            // Fragmented datagrams are not ours to answer.
            let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
            if frag & 0x3FFF != 0 {
                return None;
            }
            let src: [u8; 4] = pkt[12..16].try_into().ok()?;
            let dst: [u8; 4] = pkt[16..20].try_into().ok()?;
            (false, ihl, IpAddr::from(src), IpAddr::from(dst))
        }
        6 => {
            if pkt.len() < 48 || pkt[6] != 17 {
                return None;
            }
            let src: [u8; 16] = pkt[8..24].try_into().ok()?;
            let dst: [u8; 16] = pkt[24..40].try_into().ok()?;
            (true, 40, IpAddr::from(src), IpAddr::from(dst))
        }
        _ => return None,
    };
    let udp = &pkt[l4..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    let dns = udp.get(8..udp_len.max(8).min(udp.len()))?;
    if dns.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([dns[2], dns[3]]);
    let qdcount = u16::from_be_bytes([dns[4], dns[5]]);
    // QR must be 0 (query), opcode 0 (standard), exactly one question.
    if flags & 0xF800 != 0 || qdcount != 1 {
        return None;
    }
    let msg = uf_dns::message::parse(dns).ok()?;
    if msg.qname.is_empty() {
        return None;
    }
    let qend = question_end(dns)?;
    Some(Query {
        name: msg.qname.trim_end_matches('.').to_string(),
        qtype: msg.qtype,
        ipv6,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        id_flags: [dns[0], dns[1], dns[2], dns[3]],
        question: dns[12..qend].to_vec(),
    })
}

/// End offset of the single question (uncompressed name + type + class).
fn question_end(dns: &[u8]) -> Option<usize> {
    let mut pos = 12;
    loop {
        let len = usize::from(*dns.get(pos)?);
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None; // a query's name is never compressed
        }
        pos += 1 + len;
    }
    let end = pos + 4;
    (end <= dns.len()).then_some(end)
}

/// Build the DNS reply message for `q`.
fn reply_message(q: &Query, answer: &Answer) -> Vec<u8> {
    let addrs: Vec<IpAddr> = match answer {
        Answer::Addrs(a) => a
            .iter()
            .copied()
            .filter(|ip| match q.qtype {
                QType::A => ip.is_ipv4(),
                QType::Aaaa => ip.is_ipv6(),
                QType::Other(_) => false,
            })
            .collect(),
        Answer::NxDomain => Vec::new(),
    };
    let rcode: u16 = if matches!(answer, Answer::NxDomain) {
        3
    } else {
        0
    };
    let rd = u16::from_be_bytes([q.id_flags[2], q.id_flags[3]]) & 0x0100;
    // QR | RD (echoed) | RA | rcode
    let flags = 0x8000 | rd | 0x0080 | rcode;

    let mut m = Vec::with_capacity(12 + q.question.len() + addrs.len() * 28);
    m.extend_from_slice(&q.id_flags[..2]);
    m.extend_from_slice(&flags.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    m.extend_from_slice(&(addrs.len() as u16).to_be_bytes()); // ANCOUNT
    m.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT
    m.extend_from_slice(&q.question);
    for ip in addrs {
        m.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question name
        let (rtype, rdata): (u16, Vec<u8>) = match ip {
            IpAddr::V4(v4) => (1, v4.octets().to_vec()),
            IpAddr::V6(v6) => (28, v6.octets().to_vec()),
        };
        m.extend_from_slice(&rtype.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes()); // class IN
        m.extend_from_slice(&ANSWER_TTL.to_be_bytes());
        m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        m.extend_from_slice(&rdata);
    }
    m
}

/// Build the full inbound IP/UDP reply packet for `q`: addresses and ports
/// swapped, checksums left zero (the capture backend recomputes them).
pub fn build_reply(q: &Query, answer: &Answer) -> Vec<u8> {
    let dns = reply_message(q, answer);
    let udp_len = 8 + dns.len();
    let mut p = Vec::with_capacity(40 + udp_len);
    match (q.dst_ip, q.src_ip) {
        (IpAddr::V4(from), IpAddr::V4(to)) => {
            let total = (20 + udp_len) as u16;
            p.extend_from_slice(&[0x45, 0]);
            p.extend_from_slice(&total.to_be_bytes());
            p.extend_from_slice(&[0, 0, 0x40, 0]); // id 0, DF
            p.extend_from_slice(&[64, 17, 0, 0]); // TTL, UDP, checksum
            p.extend_from_slice(&from.octets());
            p.extend_from_slice(&to.octets());
        }
        (from, to) => {
            let (IpAddr::V6(from), IpAddr::V6(to)) = (from, to) else {
                unreachable!("parse_query keeps both addresses in one family")
            };
            p.extend_from_slice(&[0x60, 0, 0, 0]);
            p.extend_from_slice(&(udp_len as u16).to_be_bytes());
            p.extend_from_slice(&[17, 64]); // next header UDP, hop limit
            p.extend_from_slice(&from.octets());
            p.extend_from_slice(&to.octets());
        }
    }
    p.extend_from_slice(&q.dst_port.to_be_bytes());
    p.extend_from_slice(&q.src_port.to_be_bytes());
    p.extend_from_slice(&(udp_len as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]); // checksum (recomputed on inject)
    p.extend_from_slice(&dns);
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4_query(name: &str, qtype: QType) -> Vec<u8> {
        let dns = uf_dns::message::build_query(0xBEEF, name, qtype).unwrap();
        let udp_len = 8 + dns.len();
        let mut p = vec![0x45, 0];
        p.extend_from_slice(&((20 + udp_len) as u16).to_be_bytes());
        p.extend_from_slice(&[0, 1, 0, 0, 128, 17, 0, 0]);
        p.extend_from_slice(&[192, 168, 1, 10]);
        p.extend_from_slice(&[192, 168, 1, 1]);
        p.extend_from_slice(&50123u16.to_be_bytes());
        p.extend_from_slice(&53u16.to_be_bytes());
        p.extend_from_slice(&(udp_len as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(&dns);
        p
    }

    #[test]
    fn parses_a_query() {
        let q = parse_query(&v4_query("Discord.com", QType::A)).unwrap();
        assert_eq!(q.name, "discord.com");
        assert_eq!(q.qtype, QType::A);
        assert_eq!(q.policy(), Policy::Resolve);
        assert!(!q.ipv6);
    }

    #[test]
    fn reply_swaps_endpoints_and_carries_answers() {
        let q = parse_query(&v4_query("discord.com", QType::A)).unwrap();
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(162, 159, 128, 233)),
            IpAddr::V6(Ipv6Addr::LOCALHOST), // wrong family: dropped
        ];
        let r = build_reply(&q, &Answer::Addrs(addrs));
        assert_eq!(&r[12..16], &[192, 168, 1, 1]);
        assert_eq!(&r[16..20], &[192, 168, 1, 10]);
        assert_eq!(u16::from_be_bytes([r[20], r[21]]), 53);
        assert_eq!(u16::from_be_bytes([r[22], r[23]]), 50123);
        assert_eq!(usize::from(u16::from_be_bytes([r[2], r[3]])), r.len());
        let msg = uf_dns::message::parse(&r[28..]).unwrap();
        assert!(msg.is_response);
        assert_eq!(msg.id, 0xBEEF);
        assert_eq!(msg.qname, "discord.com");
        assert_eq!(
            msg.addresses(),
            vec![IpAddr::V4(Ipv4Addr::new(162, 159, 128, 233))]
        );
    }

    #[test]
    fn nxdomain_and_empty_answers() {
        let q = parse_query(&v4_query("nope.invalid", QType::A)).unwrap();
        let r = build_reply(&q, &Answer::NxDomain);
        let msg = uf_dns::message::parse(&r[28..]).unwrap();
        assert!(msg.is_nxdomain());

        let q = parse_query(&v4_query("x.com", QType::Other(65))).unwrap();
        assert_eq!(q.policy(), Policy::Empty);
        let r = build_reply(&q, &Answer::Addrs(Vec::new()));
        let msg = uf_dns::message::parse(&r[28..]).unwrap();
        assert_eq!(msg.rcode, 0);
        assert!(msg.answers.is_empty());
    }

    #[test]
    fn ignores_responses_and_garbage() {
        let mut p = v4_query("x.com", QType::A);
        p[28 + 2] |= 0x80; // QR=1
        assert!(parse_query(&p).is_none());
        assert!(parse_query(&[0x45, 0, 0]).is_none());
        assert!(parse_query(&[]).is_none());
    }
}
