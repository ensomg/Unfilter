//! Minimal DNS wire-format codec: enough to build a query and read A/AAAA
//! answers (with name compression). Every read is bounds-checked; malformed
//! input is an error, never a panic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A DNS record type we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QType {
    /// IPv4 address (1).
    #[default]
    A,
    /// IPv6 address (28).
    Aaaa,
    /// Any other type, kept as its numeric code.
    Other(u16),
}

impl QType {
    /// Numeric wire code.
    pub fn code(self) -> u16 {
        match self {
            QType::A => 1,
            QType::Aaaa => 28,
            QType::Other(c) => c,
        }
    }

    fn from_code(c: u16) -> QType {
        match c {
            1 => QType::A,
            28 => QType::Aaaa,
            other => QType::Other(other),
        }
    }
}

/// A resource record (only the fields the resolver needs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Record type.
    pub qtype: QType,
    /// TTL in seconds.
    pub ttl: u32,
    /// Parsed address for A/AAAA records.
    pub addr: Option<IpAddr>,
}

/// A parsed DNS message (the parts we use).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsMessage {
    /// Transaction id.
    pub id: u16,
    /// Response code (0 = NOERROR, 3 = NXDOMAIN).
    pub rcode: u8,
    /// Whether the QR bit marks this as a response.
    pub is_response: bool,
    /// Queried name (lower-cased).
    pub qname: String,
    /// Queried type.
    pub qtype: QType,
    /// Answer records.
    pub answers: Vec<Record>,
}

/// Errors from the DNS codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// Input ended before the structure was complete.
    Truncated,
    /// A name had too many compression pointers (loop guard) or was malformed.
    BadName,
    /// A label or name exceeded the protocol limits.
    TooLong,
}

const MAX_NAME: usize = 255;
const MAX_POINTERS: usize = 16;

/// All A/AAAA addresses in the answer section.
impl DnsMessage {
    /// Addresses from A/AAAA answers.
    pub fn addresses(&self) -> Vec<IpAddr> {
        self.answers.iter().filter_map(|r| r.addr).collect()
    }

    /// The smallest TTL across answers, or `None` if there are no answers.
    pub fn min_ttl(&self) -> Option<u32> {
        self.answers.iter().map(|r| r.ttl).min()
    }

    /// Whether this is an NXDOMAIN response.
    pub fn is_nxdomain(&self) -> bool {
        self.is_response && self.rcode == 3
    }
}

/// Build a standard recursive query for `name`/`qtype` with transaction id `id`.
pub fn build_query(id: u16, name: &str, qtype: QType) -> Result<Vec<u8>, DnsError> {
    let mut buf = Vec::with_capacity(32 + name.len());
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD = 1
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR counts
    write_name(&mut buf, name)?;
    buf.extend_from_slice(&qtype.code().to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    Ok(buf)
}

fn write_name(buf: &mut Vec<u8>, name: &str) -> Result<(), DnsError> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.len() > MAX_NAME {
        return Err(DnsError::TooLong);
    }
    if !trimmed.is_empty() {
        for label in trimmed.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(DnsError::BadName);
            }
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
    }
    buf.push(0); // root label
    Ok(())
}

/// Parse a DNS message, reading the question and A/AAAA answers.
pub fn parse(buf: &[u8]) -> Result<DnsMessage, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::Truncated);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);

    let mut pos = 12;
    // A response may legally carry no question (e.g. some FORMERR replies).
    let (qname, qtype) = if qdcount == 0 {
        (String::new(), QType::default())
    } else {
        let (qname, _) = read_name(buf, &mut pos)?;
        let qtype = QType::from_code(read_u16(buf, &mut pos)?);
        let _qclass = read_u16(buf, &mut pos)?;
        (qname, qtype)
    };

    // Skip any extra questions (should be 1, but be defensive).
    for _ in 1..qdcount {
        let _ = read_name(buf, &mut pos)?;
        read_u16(buf, &mut pos)?;
        read_u16(buf, &mut pos)?;
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        let _ = read_name(buf, &mut pos)?;
        let rtype = QType::from_code(read_u16(buf, &mut pos)?);
        let _class = read_u16(buf, &mut pos)?;
        let ttl = read_u32(buf, &mut pos)?;
        let rdlen = read_u16(buf, &mut pos)? as usize;
        let rdata = buf.get(pos..pos + rdlen).ok_or(DnsError::Truncated)?;
        pos += rdlen;

        let addr = match rtype {
            QType::A if rdlen == 4 => Some(IpAddr::V4(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            QType::Aaaa if rdlen == 16 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                Some(IpAddr::V6(Ipv6Addr::from(o)))
            }
            _ => None,
        };
        answers.push(Record {
            qtype: rtype,
            ttl,
            addr,
        });
    }

    Ok(DnsMessage {
        id,
        rcode: (flags & 0x000F) as u8,
        is_response: (flags & 0x8000) != 0,
        qname,
        qtype,
        answers,
    })
}

fn read_u16(buf: &[u8], pos: &mut usize) -> Result<u16, DnsError> {
    let b = buf.get(*pos..*pos + 2).ok_or(DnsError::Truncated)?;
    *pos += 2;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32, DnsError> {
    let b = buf.get(*pos..*pos + 4).ok_or(DnsError::Truncated)?;
    *pos += 4;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a (possibly compressed) domain name, lower-cased. `pos` is advanced past
/// the name in the record stream (following pointers does not move `pos`).
fn read_name(buf: &[u8], pos: &mut usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut cursor = *pos;
    let mut jumped = false;
    let mut pointers = 0usize;
    let start = *pos;

    loop {
        let len = *buf.get(cursor).ok_or(DnsError::Truncated)? as usize;
        if len & 0xC0 == 0xC0 {
            // Compression pointer: two bytes.
            let b2 = *buf.get(cursor + 1).ok_or(DnsError::Truncated)? as usize;
            let target = ((len & 0x3F) << 8) | b2;
            if !jumped {
                *pos = cursor + 2;
            }
            pointers += 1;
            if pointers > MAX_POINTERS {
                return Err(DnsError::BadName);
            }
            cursor = target;
            jumped = true;
            continue;
        }
        if len == 0 {
            if !jumped {
                *pos = cursor + 1;
            }
            break;
        }
        cursor += 1;
        let label = buf.get(cursor..cursor + len).ok_or(DnsError::Truncated)?;
        if !name.is_empty() {
            name.push('.');
        }
        for &b in label {
            name.push((b as char).to_ascii_lowercase());
        }
        cursor += len;
        if name.len() > MAX_NAME {
            return Err(DnsError::TooLong);
        }
    }
    Ok((name, start))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrips_through_parse() {
        let q = build_query(0x1234, "example.com", QType::A).unwrap();
        let m = parse(&q).unwrap();
        assert_eq!(m.id, 0x1234);
        assert!(!m.is_response);
        assert_eq!(m.qname, "example.com");
        assert_eq!(m.qtype, QType::A);
    }

    #[test]
    fn parses_a_answer_with_compression() {
        // Header: id=1, flags=0x8180 (response, RD, RA), qd=1, an=1.
        let mut m = vec![0x00, 0x01, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        // Question: example.com A IN
        write_name(&mut m, "example.com").unwrap();
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        // Answer: name = pointer to offset 12, A IN ttl=300 rdlen=4 1.2.3.4
        m.extend_from_slice(&[0xC0, 0x0C]);
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&300u32.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&[1, 2, 3, 4]);

        let parsed = parse(&m).unwrap();
        assert!(parsed.is_response);
        assert_eq!(parsed.qname, "example.com");
        assert_eq!(
            parsed.addresses(),
            vec!["1.2.3.4".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(parsed.min_ttl(), Some(300));
    }

    #[test]
    fn nxdomain_detected() {
        let mut m = vec![0x00, 0x02, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0];
        write_name(&mut m, "nope.example").unwrap();
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        let parsed = parse(&m).unwrap();
        assert!(parsed.is_nxdomain());
    }

    #[test]
    fn response_without_question_parses() {
        let m = vec![0x00, 0x07, 0x81, 0x81, 0, 0, 0, 0, 0, 0, 0, 0];
        let parsed = parse(&m).unwrap();
        assert_eq!(parsed.id, 7);
        assert_eq!(parsed.rcode, 1);
        assert!(parsed.qname.is_empty());
    }

    #[test]
    fn compression_loop_is_rejected() {
        // A pointer at offset 12 that points to itself.
        let m = vec![0x00, 0x01, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C];
        assert_eq!(parse(&m), Err(DnsError::BadName));
    }

    #[test]
    fn truncated_never_panics() {
        let full = build_query(1, "a.example.com", QType::Aaaa).unwrap();
        for n in 0..full.len() {
            let _ = parse(&full[..n]);
        }
    }
}
