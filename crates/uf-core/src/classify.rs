//! Classification results: what the engine learns about a flow from its first
//! L7 payload. All string-like fields borrow into the packet buffer; nothing is
//! copied or allocated during classification.

/// Application-layer protocol detected on a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L7Proto {
    /// TLS over TCP (a ClientHello was seen).
    Tls,
    /// Plain HTTP/1.x over TCP.
    Http,
    /// QUIC over UDP (an Initial was seen).
    Quic,
    /// DNS over UDP/TCP port 53.
    Dns,
    /// Not yet determined or not one of the above.
    Unknown,
}

/// Coarse category of a destination, used together with the prober's verdict to
/// decide whether a flow is worth acting on. Unblocked traffic is never touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetCategory {
    /// Social media.
    Social,
    /// Video / streaming.
    Video,
    /// Messaging (incl. Discord).
    Messaging,
    /// News.
    News,
    /// Everything else / uncategorised.
    Other,
}

/// What classification extracted from a flow's opening payload.
///
/// Lifetime `'p` ties every borrowed field to the packet buffer it was parsed
/// from, so the classifier allocates nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct Classification<'p> {
    /// Detected application protocol.
    pub proto: Option<L7Proto>,
    /// Server Name Indication from a TLS ClientHello, if present and not
    /// encrypted. `None` when ECH hides it.
    pub sni: Option<&'p str>,
    /// ALPN protocol list, raw (each entry is one advertised protocol).
    pub alpn: Option<&'p [u8]>,
    /// Whether the ClientHello carried an Encrypted Client Hello extension. When
    /// true, SNI-based strategy selection is impossible and the engine falls
    /// back to flow/IP-based handling.
    pub has_ech: bool,
    /// Host header from an HTTP/1.x request line.
    pub http_host: Option<&'p str>,
    /// SNI recovered from a decrypted QUIC Initial.
    pub quic_sni: Option<&'p str>,
}

impl<'p> Classification<'p> {
    /// The best available server name across TLS SNI, QUIC SNI and HTTP Host.
    pub fn server_name(&self) -> Option<&'p str> {
        self.sni.or(self.quic_sni).or(self.http_host)
    }

    /// Whether anything identifying the destination was recovered.
    pub fn is_identified(&self) -> bool {
        self.server_name().is_some()
    }
}

impl L7Proto {
    /// Detect the application protocol from the first bytes of a flow's payload
    /// and its destination port. This is a cheap pre-filter; full parsing (SNI
    /// extraction, QUIC decryption) happens in phase 1 parser modules.
    pub fn sniff(payload: &[u8], dst_port: u16) -> L7Proto {
        match payload.first() {
            // TLS handshake record (0x16), ClientHello is handshake type 0x01.
            Some(0x16) if payload.get(5) == Some(&0x01) => L7Proto::Tls,
            _ if dst_port == 53 => L7Proto::Dns,
            // QUIC long header: high bit set, fixed bit set.
            Some(b) if dst_port == 443 && (b & 0xC0) == 0xC0 => L7Proto::Quic,
            _ if Self::looks_like_http(payload) => L7Proto::Http,
            _ => L7Proto::Unknown,
        }
    }

    fn looks_like_http(payload: &[u8]) -> bool {
        const METHODS: [&[u8]; 6] = [b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"CONN"];
        METHODS.iter().any(|m| payload.starts_with(m))
    }
}

/// Classify a flow's opening payload: sniff the protocol, then run the matching
/// parser to recover the server name. Allocation-free; every field borrows into
/// `payload`. A parse failure degrades gracefully to a partly-filled result
/// (the engine then passes the flow through).
pub fn classify(payload: &[u8], dst_port: u16) -> Classification<'_> {
    let proto = L7Proto::sniff(payload, dst_port);
    let mut out = Classification {
        proto: Some(proto),
        ..Classification::default()
    };
    match proto {
        L7Proto::Tls => {
            let _ = crate::parse::tls::parse_client_hello(payload, &mut out);
        }
        L7Proto::Http => {
            let _ = crate::parse::http::parse_request(payload, &mut out);
        }
        // QUIC Initial decryption and DNS live in uf-quic / uf-dns.
        _ => {}
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_tls_sni() {
        // "GET "-free TLS record is built by the tls parser tests; here just
        // check the dispatch picks TLS and fills nothing on a stub.
        let payload = [0x16u8, 0x03, 0x03, 0x00, 0x00, 0x01];
        let c = classify(&payload, 443);
        assert_eq!(c.proto, Some(L7Proto::Tls));
    }

    #[test]
    fn classify_http_host() {
        let req = b"GET / HTTP/1.1\r\nHost: site.example\r\n\r\n";
        let c = classify(req, 80);
        assert_eq!(c.proto, Some(L7Proto::Http));
        assert_eq!(c.http_host, Some("site.example"));
    }

    #[test]
    fn classify_dns_by_port() {
        let c = classify(&[0x00, 0x01], 53);
        assert_eq!(c.proto, Some(L7Proto::Dns));
    }
}
