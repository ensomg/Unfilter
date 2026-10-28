//! Raw FFI to WinDivert 2.2, loaded dynamically (ADR 002).
//!
//! The DLL is loaded with `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` so only a copy
//! shipped next to our executable is used — never one planted elsewhere on the
//! search path (DLL hijack prevention). Every symbol is resolved explicitly;
//! all `unsafe` is confined to this module.

use core::ffi::{c_char, c_void};
use std::ffi::CString;

use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LoadLibraryExW,
};

/// Opaque WinDivert handle (a Win32 `HANDLE`).
pub type Handle = *mut c_void;

/// WinDivert `WINDIVERT_LAYER_NETWORK`.
pub const LAYER_NETWORK: i32 = 0;

/// `WINDIVERT_SHUTDOWN_BOTH`.
pub const SHUTDOWN_BOTH: u32 = 3;

/// `ERROR_NO_DATA` — returned by `WinDivertRecv` after shutdown.
pub const ERROR_NO_DATA: u32 = 232;
/// `ERROR_INSUFFICIENT_BUFFER` — packet larger than the supplied buffer.
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// `WINDIVERT_ADDRESS`, 80 bytes (WinDivert 2.2). The bit-field word and the
/// per-layer union are kept as raw fields and decoded by accessor helpers so the
/// Rust layout cannot drift from the C ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    /// Capture timestamp (performance-counter ticks).
    pub timestamp: i64,
    /// Packed bit-field: Layer:8, Event:8, flags:8, Reserved1:8.
    pub flags: u32,
    /// Reserved2.
    pub reserved2: u32,
    /// Per-layer union; for NETWORK this is `{ u32 IfIdx; u32 SubIfIdx; }`.
    pub union_data: [u8; 64],
}

// Bit offsets inside `flags` (MSVC allocates bit-fields from the LSB).
const BIT_OUTBOUND: u32 = 17;
const BIT_LOOPBACK: u32 = 18;
const BIT_IMPOSTOR: u32 = 19;
const BIT_IPV6: u32 = 20;
const BIT_IPCHECKSUM: u32 = 21;
const BIT_TCPCHECKSUM: u32 = 22;
const BIT_UDPCHECKSUM: u32 = 23;

impl Address {
    /// A zeroed NETWORK-layer address.
    pub fn zeroed() -> Self {
        Address {
            timestamp: 0,
            flags: 0, // Layer bits 0..8 == 0 == NETWORK
            reserved2: 0,
            union_data: [0u8; 64],
        }
    }

    fn get_bit(&self, bit: u32) -> bool {
        (self.flags >> bit) & 1 == 1
    }

    fn set_bit(&mut self, bit: u32, on: bool) {
        if on {
            self.flags |= 1 << bit;
        } else {
            self.flags &= !(1 << bit);
        }
    }

    /// Outbound direction flag.
    pub fn outbound(&self) -> bool {
        self.get_bit(BIT_OUTBOUND)
    }
    /// Loopback flag.
    pub fn loopback(&self) -> bool {
        self.get_bit(BIT_LOOPBACK)
    }
    /// Impostor flag (packet injected by software).
    pub fn impostor(&self) -> bool {
        self.get_bit(BIT_IMPOSTOR)
    }
    /// IPv6 flag.
    pub fn ipv6(&self) -> bool {
        self.get_bit(BIT_IPV6)
    }

    /// Set direction/loopback/impostor/ipv6 flags at once.
    pub fn set_flags(&mut self, outbound: bool, loopback: bool, impostor: bool, ipv6: bool) {
        self.set_bit(BIT_OUTBOUND, outbound);
        self.set_bit(BIT_LOOPBACK, loopback);
        self.set_bit(BIT_IMPOSTOR, impostor);
        self.set_bit(BIT_IPV6, ipv6);
    }

    /// Mark all three checksums as already valid (so WinDivert does not touch
    /// them on send), or clear them (so it recomputes).
    pub fn set_checksums_valid(&mut self, valid: bool) {
        self.set_bit(BIT_IPCHECKSUM, valid);
        self.set_bit(BIT_TCPCHECKSUM, valid);
        self.set_bit(BIT_UDPCHECKSUM, valid);
    }

    /// Network-layer interface index.
    pub fn if_idx(&self) -> u32 {
        u32::from_ne_bytes([
            self.union_data[0],
            self.union_data[1],
            self.union_data[2],
            self.union_data[3],
        ])
    }

    /// Network-layer sub-interface index.
    pub fn sub_if_idx(&self) -> u32 {
        u32::from_ne_bytes([
            self.union_data[4],
            self.union_data[5],
            self.union_data[6],
            self.union_data[7],
        ])
    }

    /// Set the network-layer interface indices.
    pub fn set_network(&mut self, if_idx: u32, sub_if_idx: u32) {
        self.union_data[0..4].copy_from_slice(&if_idx.to_ne_bytes());
        self.union_data[4..8].copy_from_slice(&sub_if_idx.to_ne_bytes());
    }
}

// The whole design depends on this matching the C ABI exactly.
const _: () = assert!(core::mem::size_of::<Address>() == 80);

type FnOpen = unsafe extern "system" fn(*const c_char, i32, i16, u64) -> Handle;
type FnRecv = unsafe extern "system" fn(Handle, *mut u8, u32, *mut u32, *mut Address) -> i32;
type FnSend = unsafe extern "system" fn(Handle, *const u8, u32, *mut u32, *const Address) -> i32;
type FnShutdown = unsafe extern "system" fn(Handle, u32) -> i32;
type FnClose = unsafe extern "system" fn(Handle) -> i32;

/// Resolved WinDivert entry points plus the module they came from.
pub struct Api {
    module: HMODULE,
    open: FnOpen,
    recv: FnRecv,
    send: FnSend,
    shutdown: FnShutdown,
    close: FnClose,
}

/// Why loading WinDivert failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// `LoadLibraryEx` failed; carries the OS error code.
    LibraryNotFound(u32),
    /// A required export was missing.
    SymbolMissing(&'static str),
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl Api {
    /// Load `WinDivert.dll` from the application directory and resolve all
    /// entry points.
    pub fn load() -> Result<Api, LoadError> {
        let name = wide("WinDivert.dll");
        // SAFETY: `name` is a valid NUL-terminated UTF-16 string that outlives
        // the call; the flag restricts the search to the application directory.
        let module = unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
            )
        };
        if module.is_null() {
            // SAFETY: querying the thread's last-error is always sound.
            return Err(LoadError::LibraryNotFound(unsafe { GetLastError() }));
        }

        // SAFETY: `module` is a live library handle; each name is a valid
        // NUL-terminated C string. `GetProcAddress` returns `None`/null for a
        // missing export, which `resolve` turns into an error. The transmute
        // matches each documented WinDivert 2.2 signature.
        let api = unsafe {
            Api {
                module,
                open: core::mem::transmute::<*const c_void, FnOpen>(resolve(
                    module,
                    c"WinDivertOpen",
                )?),
                recv: core::mem::transmute::<*const c_void, FnRecv>(resolve(
                    module,
                    c"WinDivertRecv",
                )?),
                send: core::mem::transmute::<*const c_void, FnSend>(resolve(
                    module,
                    c"WinDivertSend",
                )?),
                shutdown: core::mem::transmute::<*const c_void, FnShutdown>(resolve(
                    module,
                    c"WinDivertShutdown",
                )?),
                close: core::mem::transmute::<*const c_void, FnClose>(resolve(
                    module,
                    c"WinDivertClose",
                )?),
            }
        };
        Ok(api)
    }

    /// Open a handle on the NETWORK layer with the given filter string.
    ///
    /// Returns the OS error code on failure (e.g. 5 = access denied when not
    /// elevated, 2 = driver files missing).
    ///
    /// # Safety
    /// Requires a correctly installed, signed WinDivert driver and
    /// administrator privileges. The handle must later be closed with
    /// [`close`](Api::close).
    pub unsafe fn open(&self, filter: &str, priority: i16, flags: u64) -> Result<Handle, u32> {
        let c = CString::new(filter).map_err(|_| 87u32 /* ERROR_INVALID_PARAMETER */)?;
        // SAFETY: `c` is a valid NUL-terminated C string living across the call;
        // the function pointer was resolved from WinDivert and matches `FnOpen`.
        let h = unsafe { (self.open)(c.as_ptr(), LAYER_NETWORK, priority, flags) };
        if h == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            // SAFETY: last-error query is always sound.
            Err(unsafe { GetLastError() })
        } else {
            Ok(h)
        }
    }

    /// Receive one packet into `buf`, returning its length and address, or the
    /// OS error code. `ERROR_NO_DATA` means the handle was shut down.
    ///
    /// # Safety
    /// `handle` must be an open WinDivert handle from [`open`](Api::open).
    pub unsafe fn recv(&self, handle: Handle, buf: &mut [u8]) -> Result<(u32, Address), u32> {
        let mut addr = Address::zeroed();
        let mut recv_len: u32 = 0;
        // SAFETY: `buf` is a valid writable region of `buf.len()` bytes; `addr`
        // and `recv_len` are valid out-pointers; `handle` is an open handle.
        let ok = unsafe {
            (self.recv)(
                handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut recv_len,
                &mut addr,
            )
        };
        if ok == 0 {
            // SAFETY: last-error query is always sound.
            Err(unsafe { GetLastError() })
        } else {
            Ok((recv_len, addr))
        }
    }

    /// Inject one packet described by `addr`.
    ///
    /// # Safety
    /// `handle` must be an open WinDivert handle; `pkt` must be a valid IP
    /// packet consistent with `addr`.
    pub unsafe fn send(&self, handle: Handle, pkt: &[u8], addr: &Address) -> Result<u32, u32> {
        let mut sent: u32 = 0;
        // SAFETY: `pkt` is a readable region of `pkt.len()` bytes; `addr` is a
        // valid address; `sent` is a valid out-pointer; `handle` is open.
        let ok = unsafe { (self.send)(handle, pkt.as_ptr(), pkt.len() as u32, &mut sent, addr) };
        if ok == 0 {
            // SAFETY: last-error query is always sound.
            Err(unsafe { GetLastError() })
        } else {
            Ok(sent)
        }
    }

    /// Shut down both directions of a handle (unblocks a pending `recv`).
    ///
    /// # Safety
    /// `handle` must be an open WinDivert handle.
    pub unsafe fn shutdown(&self, handle: Handle) {
        // SAFETY: `handle` is an open handle; the call only transitions it to
        // the shutdown state and cannot violate memory safety.
        unsafe { (self.shutdown)(handle, SHUTDOWN_BOTH) };
    }

    /// Close a handle.
    ///
    /// # Safety
    /// `handle` must be an open WinDivert handle not used after this call.
    pub unsafe fn close(&self, handle: Handle) {
        // SAFETY: `handle` is an open handle no longer used afterwards.
        unsafe { (self.close)(handle) };
    }

    /// A `Send`-able token that can shut this handle down from another thread
    /// (the fail-open watchdog). Stores the handle as an integer and the
    /// resolved shutdown entry point, both of which are safe to move.
    pub fn token(&self, handle: Handle) -> ShutdownToken {
        ShutdownToken {
            handle: handle as usize,
            shutdown: self.shutdown,
        }
    }
}

/// A cross-thread shutdown signal for a WinDivert handle. Copyable and `Send`
/// (it holds a plain integer and a function pointer), so the watchdog thread can
/// own one and unblock a pending `recv` to guarantee fail-open.
#[derive(Clone, Copy)]
pub struct ShutdownToken {
    handle: usize,
    shutdown: FnShutdown,
}

impl ShutdownToken {
    /// Shut the handle down, unblocking any in-flight `recv`.
    pub fn trigger(&self) {
        // SAFETY: `handle` is the integer form of a WinDivert handle that was
        // open when this token was created; `shutdown` is the resolved entry
        // point. Shutting a (possibly already closed) handle down is sound.
        unsafe {
            (self.shutdown)(self.handle as Handle, SHUTDOWN_BOTH);
        }
    }
}

impl Drop for Api {
    fn drop(&mut self) {
        // SAFETY: `module` was returned by `LoadLibraryExW` and is freed exactly
        // once here. No resolved pointer is used after this.
        unsafe {
            FreeLibrary(self.module);
        }
    }
}

fn resolve(module: HMODULE, name: &core::ffi::CStr) -> Result<*const c_void, LoadError> {
    // SAFETY: `module` is a live library handle and `name` is a valid C string.
    let proc = unsafe { GetProcAddress(module, name.as_ptr() as *const u8) };
    match proc {
        Some(p) => Ok(p as *const c_void),
        None => Err(LoadError::SymbolMissing(leaked(name))),
    }
}

// Map the few names we resolve to 'static strings for error reporting.
fn leaked(name: &core::ffi::CStr) -> &'static str {
    match name.to_bytes() {
        b"WinDivertOpen" => "WinDivertOpen",
        b"WinDivertRecv" => "WinDivertRecv",
        b"WinDivertSend" => "WinDivertSend",
        b"WinDivertShutdown" => "WinDivertShutdown",
        b"WinDivertClose" => "WinDivertClose",
        _ => "WinDivert<unknown>",
    }
}
