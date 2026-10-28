//! Raw FFI to WinDivert 2.2, loaded dynamically (ADR 002).
//!
//! The DLL is loaded with `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` so only a copy
//! shipped next to our executable is used — never one planted elsewhere on the
//! search path (DLL hijack prevention). Every symbol is resolved explicitly;
//! all `unsafe` is confined to this module.

use core::ffi::{c_char, c_void};
use std::ffi::CString;
use std::sync::{Arc, Mutex};

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
/// `ERROR_INVALID_HANDLE` — the handle was closed underneath a `recv`.
pub const ERROR_INVALID_HANDLE: u32 = 6;
/// `ERROR_OPERATION_ABORTED` — a pending `recv` was cancelled.
pub const ERROR_OPERATION_ABORTED: u32 = 995;

/// `WINDIVERT_MTU_MAX`: the largest packet WinDivert can hand us (IPv6 header
/// plus a 64 KiB payload). Outbound segments can be this large when the NIC
/// does large-send offload, so the receive buffer must be this big or such a
/// packet is lost inside the driver.
pub const MTU_MAX: usize = 40 + 0xFFFF;

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

    /// The captured IPv4 header checksum is valid (always clear for IPv6).
    pub fn ip_checksum(&self) -> bool {
        self.get_bit(BIT_IPCHECKSUM)
    }

    /// The captured TCP checksum is valid.
    pub fn tcp_checksum(&self) -> bool {
        self.get_bit(BIT_TCPCHECKSUM)
    }

    /// The captured UDP checksum is valid.
    pub fn udp_checksum(&self) -> bool {
        self.get_bit(BIT_UDPCHECKSUM)
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
type FnCalcChecksums = unsafe extern "system" fn(*mut c_void, u32, *mut Address, u64) -> i32;

/// The loaded `WinDivert.dll`. Freed when the last [`Api`] or
/// [`ShutdownToken`] referring to it is dropped, so no resolved entry point can
/// outlive the code it points into.
struct Module(HMODULE);

// SAFETY: an `HMODULE` is a process-wide value, and `FreeLibrary` may be called
// from any thread.
unsafe impl Send for Module {}
// SAFETY: as above; the module is never mutated through a shared reference.
unsafe impl Sync for Module {}

impl Drop for Module {
    fn drop(&mut self) {
        // SAFETY: the module came from `LoadLibraryExW` and is freed exactly
        // once, here, after every holder of a resolved pointer is gone.
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

/// Resolved WinDivert entry points plus the module they came from.
pub struct Api {
    module: Arc<Module>,
    open: FnOpen,
    recv: FnRecv,
    send: FnSend,
    shutdown: FnShutdown,
    close: FnClose,
    calc_checksums: FnCalcChecksums,
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
        // Owned from here on: a missing symbol below frees the library instead
        // of leaking it.
        let module = Arc::new(Module(module));
        let raw = module.0;

        // SAFETY: `module` is a live library handle; each name is a valid
        // NUL-terminated C string. `GetProcAddress` returns `None`/null for a
        // missing export, which `resolve` turns into an error. The transmute
        // matches each documented WinDivert 2.2 signature.
        let api = unsafe {
            Api {
                open: core::mem::transmute::<*const c_void, FnOpen>(resolve(
                    raw,
                    c"WinDivertOpen",
                )?),
                recv: core::mem::transmute::<*const c_void, FnRecv>(resolve(
                    raw,
                    c"WinDivertRecv",
                )?),
                send: core::mem::transmute::<*const c_void, FnSend>(resolve(
                    raw,
                    c"WinDivertSend",
                )?),
                shutdown: core::mem::transmute::<*const c_void, FnShutdown>(resolve(
                    raw,
                    c"WinDivertShutdown",
                )?),
                close: core::mem::transmute::<*const c_void, FnClose>(resolve(
                    raw,
                    c"WinDivertClose",
                )?),
                calc_checksums: core::mem::transmute::<*const c_void, FnCalcChecksums>(resolve(
                    raw,
                    c"WinDivertHelperCalcChecksums",
                )?),
                module,
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

    /// Recompute the IP/TCP/UDP checksums of `pkt` in place and mark them
    /// valid in `addr`. Returns `false` if the packet could not be parsed.
    pub fn calc_checksums(&self, pkt: &mut [u8], addr: &mut Address) -> bool {
        // SAFETY: `pkt` is a writable region of `pkt.len()` bytes and `addr` a
        // valid address; the helper only reads and writes inside them.
        let ok =
            unsafe { (self.calc_checksums)(pkt.as_mut_ptr().cast(), pkt.len() as u32, addr, 0) };
        ok != 0
    }

    /// Take ownership of an open handle's lifetime. The returned token is the
    /// only way the handle is ever closed, and it can be cloned to a watchdog
    /// thread to shut the handle down from there (fail-open).
    ///
    /// # Safety
    /// `handle` must be an open WinDivert handle from [`open`](Api::open) that
    /// is closed through nothing but the returned token.
    pub unsafe fn token(&self, handle: Handle) -> ShutdownToken {
        ShutdownToken {
            inner: Arc::new(TokenState {
                handle: handle as usize,
                shutdown: self.shutdown,
                close: self.close,
                closed: Mutex::new(false),
                _module: Arc::clone(&self.module),
            }),
        }
    }
}

struct TokenState {
    handle: usize,
    shutdown: FnShutdown,
    close: FnClose,
    /// Set once the handle is closed. Held while shutting down or closing, so
    /// a watchdog can never touch a handle value the OS may have reused.
    closed: Mutex<bool>,
    /// Keeps `WinDivert.dll` loaded for as long as any token can call into it.
    _module: Arc<Module>,
}

/// A cross-thread shutdown signal for a WinDivert handle. `Clone + Send`, so
/// the watchdog thread can own one and unblock a pending `recv` to guarantee
/// fail-open. Safe to trigger at any time, including after the backend was
/// dropped: it then does nothing.
#[derive(Clone)]
pub struct ShutdownToken {
    inner: Arc<TokenState>,
}

impl ShutdownToken {
    /// Shut the handle down, unblocking any in-flight `recv`. A no-op once the
    /// handle has been closed.
    pub fn trigger(&self) {
        let closed = self.inner.closed.lock().unwrap_or_else(|e| e.into_inner());
        if !*closed {
            // SAFETY: the handle is still open (checked under the lock, which
            // `close` also takes) and the DLL is kept loaded by `_module`.
            unsafe {
                (self.inner.shutdown)(self.inner.handle as Handle, SHUTDOWN_BOTH);
            }
        }
    }

    /// Shut down and close the handle. Idempotent; called from the backend's
    /// `Drop`.
    pub(super) fn close(&self) {
        let mut closed = self.inner.closed.lock().unwrap_or_else(|e| e.into_inner());
        if !*closed {
            *closed = true;
            // SAFETY: the handle is open and, with `closed` now set under the
            // lock, no token will use it again. Shutting down then closing
            // removes the driver filter (fail-open).
            unsafe {
                (self.inner.shutdown)(self.inner.handle as Handle, SHUTDOWN_BOTH);
                (self.inner.close)(self.inner.handle as Handle);
            }
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
        b"WinDivertHelperCalcChecksums" => "WinDivertHelperCalcChecksums",
        _ => "WinDivert<unknown>",
    }
}
