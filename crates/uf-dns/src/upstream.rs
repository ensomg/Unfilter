//! Embedded DoH/DoT providers with bootstrap IP addresses, so no plaintext
//! bootstrap DNS is ever needed (master prompt §5.2). The provider's own domain
//! is used only for TLS certificate validation; connections go straight to the
//! pinned IPs.

use std::net::IpAddr;

/// One upstream resolver provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provider {
    /// Display name (shown in the UI's DNS provider picker).
    pub name: &'static str,
    /// Pinned IPs to connect to (IPv4 first, then IPv6).
    pub bootstrap: &'static [IpAddr],
    /// TLS server name for certificate validation and the DoH `Host`.
    pub tls_name: &'static str,
    /// DoH endpoint path (POST target).
    pub doh_path: &'static str,
    /// DoT port (always 853).
    pub dot_port: u16,
}

use std::net::{Ipv4Addr, Ipv6Addr};

const fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

const CLOUDFLARE_IPS: &[IpAddr] = &[
    v4(1, 1, 1, 1),
    v4(1, 0, 0, 1),
    IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
];
const GOOGLE_IPS: &[IpAddr] = &[v4(8, 8, 8, 8), v4(8, 8, 4, 4)];
const QUAD9_IPS: &[IpAddr] = &[v4(9, 9, 9, 9), v4(149, 112, 112, 112)];
const ADGUARD_IPS: &[IpAddr] = &[v4(94, 140, 14, 14), v4(94, 140, 15, 15)];

/// The built-in providers, tried in order; the resolver reorders by measured
/// latency at runtime.
pub const PROVIDERS: &[Provider] = &[
    Provider {
        name: "Cloudflare",
        bootstrap: CLOUDFLARE_IPS,
        tls_name: "cloudflare-dns.com",
        doh_path: "/dns-query",
        dot_port: 853,
    },
    Provider {
        name: "Google",
        bootstrap: GOOGLE_IPS,
        tls_name: "dns.google",
        doh_path: "/dns-query",
        dot_port: 853,
    },
    Provider {
        name: "Quad9",
        bootstrap: QUAD9_IPS,
        tls_name: "dns.quad9.net",
        doh_path: "/dns-query",
        dot_port: 853,
    },
    Provider {
        name: "AdGuard",
        bootstrap: ADGUARD_IPS,
        tls_name: "dns.adguard-dns.com",
        doh_path: "/dns-query",
        dot_port: 853,
    },
];

/// Frame a DNS message for DoT: a 2-byte big-endian length prefix then the
/// message (RFC 7858).
pub fn dot_frame(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 2);
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

/// Build the HTTP/2 request bytes a DoH POST needs, as (`:path`, body). The body
/// is the raw DNS message; the caller sets `content-type: application/dns-message`
/// (RFC 8484).
pub fn doh_request<'a>(provider: &Provider, msg: &'a [u8]) -> (&'static str, &'a [u8]) {
    (provider.doh_path, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers_have_bootstrap_ips() {
        assert!(!PROVIDERS.is_empty());
        for p in PROVIDERS {
            assert!(!p.bootstrap.is_empty(), "{} has no bootstrap IP", p.name);
            assert!(!p.tls_name.is_empty());
            assert_eq!(p.dot_port, 853);
        }
    }

    #[test]
    fn dot_frame_prefixes_length() {
        let framed = dot_frame(&[0xAA, 0xBB, 0xCC]);
        assert_eq!(framed, vec![0x00, 0x03, 0xAA, 0xBB, 0xCC]);
    }
}
