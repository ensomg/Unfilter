//! Windows implementation of [`uf_probe::FingerprintSource`].
//!
//! It identifies the network by its default gateway's MAC address, resolved
//! with `SendARP` against the gateway IP that `GetAdaptersAddresses` reports.
//! The gateway MAC is stable per physical network and distinguishes one
//! Wi-Fi/ISP from another, while never leaving this process in raw form — only
//! the hash is persisted (master prompt §5.5). ASN and SSID are left `None`
//! here; the hash stays stable without them.
//!
//! All FFI is confined to this module; every `unsafe` block carries a SAFETY
//! note. On any failure the source returns empty inputs, which hash to a stable
//! "unknown network" key rather than erroring.

#![allow(unsafe_code)]

use uf_probe::{FingerprintSource, NetworkInputs};
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    IP_ADAPTER_ADDRESSES_LH, SendARP,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::AF_INET;

/// The gathered network fingerprint inputs.
pub struct WindowsSource;

impl FingerprintSource for WindowsSource {
    fn gather(&self) -> NetworkInputs {
        NetworkInputs {
            gateway_mac: gateway_mac(),
            asn: None,
            ssid: None,
        }
    }
}

/// Read the first up adapter's IPv4 default gateway and resolve its MAC.
fn gateway_mac() -> Option<[u8; 6]> {
    let buf = adapters_buffer()?;
    // SAFETY: `buf` holds a valid adapter list written by GetAdaptersAddresses,
    // 8-byte aligned (backed by a Vec<u64>); we walk the `Next` chain while the
    // pointer is non-null and only read fields the API guarantees are set.
    unsafe {
        let mut adapter = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !adapter.is_null() {
            let a = &*adapter;
            if a.OperStatus == IfOperStatusUp {
                let mut gw = a.FirstGatewayAddress;
                while !gw.is_null() {
                    let sa = (*gw).Address;
                    if let Some(ip) = sockaddr_v4(sa.lpSockaddr.cast()) {
                        if let Some(mac) = send_arp(ip) {
                            return Some(mac);
                        }
                    }
                    gw = (*gw).Next;
                }
            }
            adapter = a.Next;
        }
    }
    None
}

/// Call GetAdaptersAddresses into a correctly aligned buffer.
fn adapters_buffer() -> Option<Vec<u64>> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 0;
    // First call: ask for the required size.
    // SAFETY: a null buffer with a zero size is the documented way to query the
    // needed size; `size` is a valid out-pointer.
    let rc = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            flags,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if rc != ERROR_BUFFER_OVERFLOW || size == 0 {
        return None;
    }
    // Back the buffer with u64 so it is 8-byte aligned for IP_ADAPTER_ADDRESSES.
    let words = (size as usize).div_ceil(8);
    let mut buf = vec![0u64; words];
    // SAFETY: `buf` is `words * 8 >= size` bytes, 8-aligned; `size` matches it.
    let rc = unsafe {
        GetAdaptersAddresses(
            AF_INET as u32,
            flags,
            std::ptr::null(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if rc == NO_ERROR { Some(buf) } else { None }
}

/// Read an IPv4 address from a `SOCKADDR` pointer (family + 4 address bytes at
/// offset 4), if it is `AF_INET`.
fn sockaddr_v4(sa: *const u8) -> Option<[u8; 4]> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: a non-null SOCKADDR from the adapter list is at least 16 bytes;
    // we read the 2-byte family and, for AF_INET, the 4 address bytes at the
    // fixed SOCKADDR_IN offset 4.
    unsafe {
        let family = u16::from_ne_bytes([*sa, *sa.add(1)]);
        if family != AF_INET {
            return None;
        }
        Some([*sa.add(4), *sa.add(5), *sa.add(6), *sa.add(7)])
    }
}

/// Resolve an IPv4 address to its MAC via SendARP.
fn send_arp(ip: [u8; 4]) -> Option<[u8; 6]> {
    // SendARP wants the destination IP as a u32 in network byte order, i.e. the
    // address bytes loaded little-endian on Windows.
    let dest = u32::from_le_bytes(ip);
    let mut mac = [0u8; 8];
    let mut len: u32 = 8;
    // SAFETY: `mac` is an 8-byte out buffer and `len` its length; SendARP writes
    // at most `len` bytes and updates it.
    let rc = unsafe { SendARP(dest, 0, mac.as_mut_ptr().cast(), &mut len) };
    if rc == NO_ERROR && len >= 6 {
        Some([mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]])
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gather_is_stable_within_a_run() {
        // We cannot assert a specific MAC in CI, but gathering twice must agree
        // and must never panic.
        let a = WindowsSource.gather();
        let b = WindowsSource.gather();
        assert_eq!(a.gateway_mac, b.gateway_mac);
    }

    #[test]
    fn sockaddr_v4_reads_family_and_bytes() {
        let mut sa = [0u8; 16];
        sa[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
        sa[4..8].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(sockaddr_v4(sa.as_ptr()), Some([10, 0, 0, 1]));
        // Non-AF_INET family -> None.
        sa[0] = 23; // AF_INET6 low byte
        assert_eq!(sockaddr_v4(sa.as_ptr()), None);
        assert_eq!(sockaddr_v4(std::ptr::null()), None);
    }
}
