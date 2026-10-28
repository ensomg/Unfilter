//! Bounds-checked read/write helpers for the IPv4/IPv6 + TCP headers the desync
//! applier works on.
//!
//! The capture backend hands us whole IP packets (WinDivert NETWORK layer), so
//! a strategy that splits or fakes a segment must read the original headers and
//! build new packets with adjusted sequence numbers, lengths, flags and TTL.
//! Everything here is pure and allocation-light: a [`TcpView`] borrows a byte
//! slice and exposes checked getters/setters; it never panics on a malformed or
//! truncated packet (it returns [`None`]/[`Err`] instead).
//!
//! Checksums are deliberately *not* computed here. A rewritten packet is handed
//! to the backend with its checksum fields left stale and
//! [`PacketMeta::checksums_valid`](crate::io::PacketMeta) cleared, so the
//! backend recomputes them before injection. The one exception is a
//! deliberately corrupt checksum (the `badsum` fooling technique), which the
//! applier writes explicitly and marks valid so the backend leaves it alone.

use crate::error::{Error, Result};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP protocol number for TCP.
pub const PROTO_TCP: u8 = 6;
/// IP protocol number for UDP.
pub const PROTO_UDP: u8 = 17;

/// TCP control flags (the ones the applier reads or sets).
pub mod tcp_flags {
    /// FIN.
    pub const FIN: u8 = 0x01;
    /// SYN.
    pub const SYN: u8 = 0x02;
    /// RST.
    pub const RST: u8 = 0x04;
    /// PSH.
    pub const PSH: u8 = 0x08;
    /// ACK.
    pub const ACK: u8 = 0x10;
    /// URG.
    pub const URG: u8 = 0x20;
}

/// Which IP version a packet is, and where its L4 header begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    /// IPv4.
    V4,
    /// IPv6 (no extension-header chain; a packet with extension headers before
    /// TCP is treated as not-TCP and passed through).
    V6,
}

/// The parsed shape of an IP packet carrying TCP: where each region sits inside
/// the original byte buffer. Offsets are validated against the buffer length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpLayout {
    /// IPv4 or IPv6.
    pub version: IpVersion,
    /// Length of the IP header in bytes (20 for IPv6, 20–60 for IPv4).
    pub ip_header_len: usize,
    /// Length of the TCP header in bytes (20–60).
    pub tcp_header_len: usize,
    /// Offset of the TCP payload within the packet.
    pub payload_off: usize,
    /// Length of the TCP payload (the application bytes).
    pub payload_len: usize,
}

impl TcpLayout {
    /// Offset of the TCP header within the packet.
    pub fn tcp_off(&self) -> usize {
        self.ip_header_len
    }
}

/// Parse an IP packet and locate its TCP header and payload. Returns
/// [`Error::Malformed`] if the packet is not IPv4/IPv6 TCP, or
/// [`Error::Truncated`] if a declared length runs past the buffer.
pub fn parse_tcp(pkt: &[u8]) -> Result<TcpLayout> {
    let first = *pkt.first().ok_or(Error::Truncated)?;
    let version = first >> 4;
    let (ip_header_len, proto, total_len) = match version {
        4 => {
            if pkt.len() < 20 {
                return Err(Error::Truncated);
            }
            let ihl = (first & 0x0F) as usize * 4;
            if ihl < 20 {
                return Err(Error::Malformed);
            }
            let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
            (ihl, pkt[9], total)
        }
        6 => {
            if pkt.len() < 40 {
                return Err(Error::Truncated);
            }
            // Only a bare TCP next-header is handled; an extension-header chain
            // means "not simple TCP", so the caller passes it through.
            let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
            (40, pkt[6], 40 + payload_len)
        }
        _ => return Err(Error::Malformed),
    };
    if proto != PROTO_TCP {
        return Err(Error::Malformed);
    }
    // The declared total length must fit; a shorter capture is truncated.
    let total_len = total_len.max(ip_header_len);
    if pkt.len() < total_len || total_len < ip_header_len + 20 {
        return Err(Error::Truncated);
    }
    let tcp = pkt.get(ip_header_len..).ok_or(Error::Truncated)?;
    let data_off = (tcp[12] >> 4) as usize * 4;
    if !(20..=60).contains(&data_off) {
        return Err(Error::Malformed);
    }
    let payload_off = ip_header_len + data_off;
    if payload_off > total_len {
        return Err(Error::Truncated);
    }
    Ok(TcpLayout {
        version: if version == 4 {
            IpVersion::V4
        } else {
            IpVersion::V6
        },
        ip_header_len,
        tcp_header_len: data_off,
        payload_off,
        payload_len: total_len - payload_off,
    })
}

/// The source and destination endpoints of a TCP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoints {
    /// Source IP.
    pub src_ip: IpAddr,
    /// Destination IP.
    pub dst_ip: IpAddr,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
}

/// Extract the 5-tuple endpoints of a TCP packet (addresses from the IP header,
/// ports from the TCP header). Returns [`None`] if the packet is not IPv4/IPv6
/// TCP or is truncated, so the caller passes such packets through.
pub fn tcp_endpoints(pkt: &[u8]) -> Option<Endpoints> {
    let l = parse_tcp(pkt).ok()?;
    let tcp = l.tcp_off();
    let src_port = u16::from_be_bytes([*pkt.get(tcp)?, *pkt.get(tcp + 1)?]);
    let dst_port = u16::from_be_bytes([*pkt.get(tcp + 2)?, *pkt.get(tcp + 3)?]);
    let (src_ip, dst_ip) = match l.version {
        IpVersion::V4 => (
            IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])),
            IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])),
        ),
        IpVersion::V6 => {
            let s: [u8; 16] = pkt.get(8..24)?.try_into().ok()?;
            let d: [u8; 16] = pkt.get(24..40)?.try_into().ok()?;
            (IpAddr::V6(Ipv6Addr::from(s)), IpAddr::V6(Ipv6Addr::from(d)))
        }
    };
    Some(Endpoints {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
    })
}

/// A read/write view over an owned IP+TCP packet buffer. Getters and setters are
/// all bounds-checked against the layout computed at construction.
#[derive(Debug, Clone)]
pub struct TcpPacket {
    buf: Vec<u8>,
    layout: TcpLayout,
}

impl TcpPacket {
    /// Build a view by parsing `bytes`. The bytes are copied so the packet can
    /// be mutated independently of the capture buffer.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let layout = parse_tcp(bytes)?;
        // Trim any trailing bytes past the IP total length (padding).
        let end = layout.payload_off + layout.payload_len;
        Ok(TcpPacket {
            buf: bytes[..end].to_vec(),
            layout,
        })
    }

    /// The packet's layout.
    pub fn layout(&self) -> TcpLayout {
        self.layout
    }

    /// The whole packet as bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }

    /// The TCP payload (application bytes).
    pub fn payload(&self) -> &[u8] {
        &self.buf[self.layout.payload_off..]
    }

    fn tcp(&self) -> &[u8] {
        &self.buf[self.layout.tcp_off()..]
    }

    fn tcp_mut(&mut self) -> &mut [u8] {
        let off = self.layout.tcp_off();
        &mut self.buf[off..]
    }

    /// The 32-bit sequence number.
    pub fn seq(&self) -> u32 {
        let t = self.tcp();
        u32::from_be_bytes([t[4], t[5], t[6], t[7]])
    }

    /// Set the sequence number.
    pub fn set_seq(&mut self, seq: u32) {
        self.tcp_mut()[4..8].copy_from_slice(&seq.to_be_bytes());
    }

    /// The TCP flags byte (CWR/ECE are in the adjacent byte, not covered here).
    pub fn flags(&self) -> u8 {
        self.tcp()[13]
    }

    /// Set the low TCP flags byte.
    pub fn set_flags(&mut self, flags: u8) {
        self.tcp_mut()[13] = flags;
    }

    /// The advertised receive window.
    pub fn window(&self) -> u16 {
        let t = self.tcp();
        u16::from_be_bytes([t[14], t[15]])
    }

    /// Set the advertised receive window.
    pub fn set_window(&mut self, window: u16) {
        self.tcp_mut()[14..16].copy_from_slice(&window.to_be_bytes());
    }

    /// Set the urgent pointer and the URG flag together.
    pub fn set_urgent(&mut self, ptr: u16) {
        let flags = self.flags() | tcp_flags::URG;
        self.set_flags(flags);
        self.tcp_mut()[18..20].copy_from_slice(&ptr.to_be_bytes());
    }

    /// The IPv4 TTL / IPv6 hop limit.
    pub fn ttl(&self) -> u8 {
        match self.layout.version {
            IpVersion::V4 => self.buf[8],
            IpVersion::V6 => self.buf[7],
        }
    }

    /// Set the IPv4 TTL / IPv6 hop limit.
    pub fn set_ttl(&mut self, ttl: u8) {
        match self.layout.version {
            IpVersion::V4 => self.buf[8] = ttl,
            IpVersion::V6 => self.buf[7] = ttl,
        }
    }

    /// Replace the TCP payload, fixing the IP length fields to match. The TCP
    /// and IP checksums are zeroed; the caller must have the backend recompute
    /// them (or set a deliberate value for `badsum`).
    pub fn set_payload(&mut self, data: &[u8]) {
        self.buf.truncate(self.layout.payload_off);
        self.buf.extend_from_slice(data);
        self.layout.payload_len = data.len();
        self.fix_lengths();
        self.zero_checksums();
    }

    /// Corrupt the TCP checksum deliberately (the `badsum` fooling technique:
    /// the real server drops the segment, a checksum-blind DPI box still acts on
    /// it). After this the packet must be injected with checksums marked valid
    /// so the backend does not repair it.
    pub fn corrupt_tcp_checksum(&mut self) {
        let off = self.layout.tcp_off() + 16;
        let cur = u16::from_be_bytes([self.buf[off], self.buf[off + 1]]);
        self.buf[off..off + 2].copy_from_slice(&cur.wrapping_add(0x1111).to_be_bytes());
    }

    fn fix_lengths(&mut self) {
        match self.layout.version {
            IpVersion::V4 => {
                let total = self.buf.len() as u16;
                self.buf[2..4].copy_from_slice(&total.to_be_bytes());
            }
            IpVersion::V6 => {
                let payload = (self.buf.len() - 40) as u16;
                self.buf[4..6].copy_from_slice(&payload.to_be_bytes());
            }
        }
    }

    fn zero_checksums(&mut self) {
        if self.layout.version == IpVersion::V4 {
            self.buf[10..12].copy_from_slice(&[0, 0]);
        }
        let off = self.layout.tcp_off() + 16;
        self.buf[off..off + 2].copy_from_slice(&[0, 0]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal IPv4 TCP packet with the given payload (20-byte headers).
    fn v4(seq: u32, payload: &[u8]) -> Vec<u8> {
        let total = 40 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45; // v4, ihl 5
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64; // ttl
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&[192, 168, 1, 2]);
        p[16..20].copy_from_slice(&[93, 184, 216, 34]);
        p[20..24].copy_from_slice(&[0xC0, 0x00, 0x01, 0xBB]); // ports
        p[24..28].copy_from_slice(&seq.to_be_bytes());
        p[32] = 0x50; // data offset 5
        p[33] = tcp_flags::PSH | tcp_flags::ACK;
        p[34..36].copy_from_slice(&64240u16.to_be_bytes()); // window
        p[40..].copy_from_slice(payload);
        p
    }

    fn v6(seq: u32, payload: &[u8]) -> Vec<u8> {
        // 40-byte IPv6 header + 20-byte TCP header + payload.
        let mut p = vec![0u8; 60 + payload.len()];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        p[6] = PROTO_TCP;
        p[7] = 64; // hop limit
        p[20] = 0x20; // part of src addr, arbitrary
        let tcp = 40;
        p[tcp + 12] = 0x50;
        p[tcp + 13] = tcp_flags::PSH | tcp_flags::ACK;
        p[tcp + 4..tcp + 8].copy_from_slice(&seq.to_be_bytes());
        p[60..].copy_from_slice(payload);
        p
    }

    #[test]
    fn parses_v4_layout() {
        let pkt = v4(1000, b"hello");
        let l = parse_tcp(&pkt).unwrap();
        assert_eq!(l.version, IpVersion::V4);
        assert_eq!(l.ip_header_len, 20);
        assert_eq!(l.tcp_header_len, 20);
        assert_eq!(l.payload_off, 40);
        assert_eq!(l.payload_len, 5);
    }

    #[test]
    fn parses_v6_layout() {
        let pkt = v6(1, b"abcd");
        let l = parse_tcp(&pkt).unwrap();
        assert_eq!(l.version, IpVersion::V6);
        assert_eq!(l.payload_off, 60);
        assert_eq!(l.payload_len, 4);
    }

    #[test]
    fn getters_and_setters_roundtrip() {
        let mut p = TcpPacket::parse(&v4(5000, b"payload")).unwrap();
        assert_eq!(p.seq(), 5000);
        assert_eq!(p.payload(), b"payload");
        assert_eq!(p.ttl(), 64);
        assert_eq!(p.window(), 64240);
        p.set_seq(5003);
        p.set_ttl(4);
        p.set_window(16);
        assert_eq!(p.seq(), 5003);
        assert_eq!(p.ttl(), 4);
        assert_eq!(p.window(), 16);
    }

    #[test]
    fn set_payload_fixes_total_length() {
        let mut p = TcpPacket::parse(&v4(1, b"hello world")).unwrap();
        p.set_payload(b"hi");
        assert_eq!(p.payload(), b"hi");
        assert_eq!(p.bytes().len(), 42);
        assert_eq!(u16::from_be_bytes([p.bytes()[2], p.bytes()[3]]), 42);
        // IPv4 checksum zeroed for the backend to recompute.
        assert_eq!(&p.bytes()[10..12], &[0, 0]);
    }

    #[test]
    fn set_payload_fixes_v6_length() {
        let mut p = TcpPacket::parse(&v6(1, b"abcd")).unwrap();
        p.set_payload(b"xyz");
        assert_eq!(p.bytes().len(), 63);
        assert_eq!(u16::from_be_bytes([p.bytes()[4], p.bytes()[5]]), 23);
    }

    #[test]
    fn non_tcp_is_malformed() {
        let mut p = v4(1, b"x");
        p[9] = PROTO_UDP;
        assert_eq!(parse_tcp(&p), Err(Error::Malformed));
    }

    #[test]
    fn truncated_never_panics() {
        let full = v4(1, b"some payload bytes");
        for n in 0..full.len() {
            let _ = TcpPacket::parse(&full[..n]);
        }
    }

    #[test]
    fn urgent_sets_flag_and_pointer() {
        let mut p = TcpPacket::parse(&v4(1, b"data")).unwrap();
        p.set_urgent(3);
        assert_ne!(p.flags() & tcp_flags::URG, 0);
    }
}
