//! Transport for the protocol: line framing, handshake and (on Windows) the
//! ACL'd named pipe from ADR 005.
//!
//! The module has three layers:
//!
//! 1. **Framing** — [`FrameReader`] / [`write_frame`]: newline-delimited UTF-8
//!    JSON over any [`std::io::Read`] / [`std::io::Write`], at most
//!    [`MAX_FRAME_LEN`] bytes per frame (newline included). Transport-agnostic
//!    and unit-tested on in-memory streams.
//! 2. **Handshake** — [`client_handshake`] / [`server_handshake`]: the first
//!    message on every connection is `Hello { protocol: PROTOCOL_VERSION }`.
//! 3. **Windows pipe** (`cfg(windows)`) — [`PipeServer`] (service side),
//!    [`PipeClient`] (UI/tray side), the shared [`PipeStream`], and
//!    [`ServiceLink`], a self-reconnecting client used by the UI and the tray.
//!
//! All pipe handles are opened for overlapped I/O, so one client connection
//! can be read on one thread and written on another at the same time
//! ([`PipeStream::try_clone`]); synchronous pipe handles would serialise the
//! two and deadlock.
//!
//! # Service-side usage
//!
//! ```no_run
//! # #[cfg(windows)] fn main() -> std::io::Result<()> {
//! use uf_ipc::pipe::{FrameReader, PipeServer, server_handshake, write_frame};
//! use uf_ipc::{ClientMessage, PIPE_NAME, ServerMessage};
//!
//! let mut server = PipeServer::bind(PIPE_NAME)?;
//! let stop = server.shutdown_handle(); // call `stop.shutdown()` from another thread
//! # drop(stop);
//! while let Some(stream) = server.accept()? {
//!     std::thread::spawn(move || {
//!         let mut writer = stream.try_clone().expect("duplicate pipe handle");
//!         let mut reader = FrameReader::new(stream);
//!         if server_handshake(&mut reader, &mut writer).is_err() {
//!             return;
//!         }
//!         // `writer` may now move to an event-push thread while this one reads.
//!         while let Ok(Some(msg)) = reader.read_message::<ClientMessage>() {
//!             # let _ = msg;
//!             // validate + handle `msg`, reply with write_frame(&mut writer, &ServerMessage::…)
//!         }
//!     });
//! }
//! # Ok(()) }
//! # #[cfg(not(windows))] fn main() {}
//! ```
//!
//! # Client-side usage
//!
//! ```no_run
//! # #[cfg(windows)] fn main() {
//! use uf_ipc::pipe::{LinkEvent, ServiceLink};
//! use uf_ipc::{PIPE_NAME, Request};
//!
//! let link = ServiceLink::spawn(PIPE_NAME, |ev: LinkEvent| println!("{ev:?}"));
//! let _ = link.send(Request::Connect); // Err(NotConnected) while the service is down
//! # }
//! # #[cfg(not(windows))] fn main() {}
//! ```

use std::fmt;
use std::io::{self, Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{ClientMessage, PROTOCOL_VERSION, ProtocolError, ResponsePayload, ServerMessage};

/// Maximum size of one frame in bytes, including the trailing `\n` (ADR 005).
pub const MAX_FRAME_LEN: usize = 64 * 1024;

/// Errors produced while reading or writing frames.
#[derive(Debug)]
pub enum FrameError {
    /// The underlying stream failed.
    Io(io::Error),
    /// A frame exceeded [`MAX_FRAME_LEN`]. The stream is out of sync: close it.
    TooLarge,
    /// The stream ended in the middle of a frame.
    UnexpectedEof,
    /// The frame was not valid UTF-8 (the frame was consumed; the stream is usable).
    InvalidUtf8,
    /// The frame was not valid JSON for the expected type (the frame was
    /// consumed; the stream is usable).
    Json(serde_json::Error),
}

impl FrameError {
    /// Whether the connection must be closed after this error. Malformed frames
    /// (`InvalidUtf8`, `Json`) are recoverable: the service answers
    /// `BadRequest` and keeps reading.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Self::Io(_) | Self::TooLarge | Self::UnexpectedEof)
    }
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "pipe I/O error: {e}"),
            Self::TooLarge => write!(f, "frame larger than {MAX_FRAME_LEN} bytes"),
            Self::UnexpectedEof => write!(f, "stream ended inside a frame"),
            Self::InvalidUtf8 => write!(f, "frame is not valid UTF-8"),
            Self::Json(e) => write!(f, "malformed JSON frame: {e}"),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Reads newline-delimited frames from a byte stream, enforcing
/// [`MAX_FRAME_LEN`]. Blank lines are skipped and a trailing `\r` is ignored.
#[derive(Debug)]
pub struct FrameReader<R> {
    inner: R,
    buf: Vec<u8>,
    /// Bytes of `buf` already known not to contain `\n`.
    scanned: usize,
    poisoned: bool,
}

impl<R: Read> FrameReader<R> {
    /// Wraps a reader.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            scanned: 0,
            poisoned: false,
        }
    }

    /// Returns the next frame without its newline, or `Ok(None)` on a clean
    /// end of stream (between frames).
    pub fn read_line(&mut self) -> Result<Option<String>, FrameError> {
        if self.poisoned {
            return Err(FrameError::TooLarge);
        }
        loop {
            if let Some(i) = self.buf[self.scanned..].iter().position(|&b| b == b'\n') {
                let end = self.scanned + i;
                self.scanned = 0;
                if end + 1 > MAX_FRAME_LEN {
                    self.poisoned = true;
                    return Err(FrameError::TooLarge);
                }
                let mut line: Vec<u8> = self.buf.drain(..=end).collect();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.is_empty() {
                    continue;
                }
                return String::from_utf8(line)
                    .map(Some)
                    .map_err(|_| FrameError::InvalidUtf8);
            }
            self.scanned = self.buf.len();
            if self.buf.len() >= MAX_FRAME_LEN {
                self.poisoned = true;
                return Err(FrameError::TooLarge);
            }
            let old = self.buf.len();
            let want = (MAX_FRAME_LEN - old).min(8 * 1024);
            self.buf.resize(old + want, 0);
            let n = loop {
                match self.inner.read(&mut self.buf[old..]) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        self.buf.truncate(old);
                        return Err(FrameError::Io(e));
                    }
                }
            };
            self.buf.truncate(old + n);
            if n == 0 {
                return if self.buf.iter().all(|b| b.is_ascii_whitespace()) {
                    self.buf.clear();
                    Ok(None)
                } else {
                    Err(FrameError::UnexpectedEof)
                };
            }
        }
    }

    /// Reads and decodes the next frame as `T`. `Ok(None)` on clean end of stream.
    pub fn read_message<T: DeserializeOwned>(&mut self) -> Result<Option<T>, FrameError> {
        match self.read_line()? {
            Some(line) => serde_json::from_str(&line)
                .map(Some)
                .map_err(FrameError::Json),
            None => Ok(None),
        }
    }

    /// Shared access to the wrapped reader.
    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    /// Mutable access to the wrapped reader.
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    /// Unwraps the reader. Buffered, not yet returned bytes are lost.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Encodes `msg` as one frame and writes it with a single `write_all` (one
/// pipe message in message mode), then flushes.
pub fn write_frame<W: Write + ?Sized, T: Serialize>(w: &mut W, msg: &T) -> Result<(), FrameError> {
    let line = crate::encode(msg).map_err(FrameError::Json)?;
    if line.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge);
    }
    w.write_all(line.as_bytes())?;
    w.flush()?;
    Ok(())
}

/// Why the opening handshake failed.
#[derive(Debug)]
pub enum HandshakeError {
    /// Transport / framing failure.
    Frame(FrameError),
    /// The peer closed the connection before completing the handshake.
    Closed,
    /// The peers speak different protocol versions.
    VersionMismatch {
        /// Our [`PROTOCOL_VERSION`].
        ours: u32,
        /// The peer's version.
        theirs: u32,
    },
    /// The peer's first message was not a `Hello`.
    Unexpected,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(e) => write!(f, "handshake failed: {e}"),
            Self::Closed => write!(f, "peer closed the connection during the handshake"),
            Self::VersionMismatch { ours, theirs } => {
                write!(f, "protocol version mismatch: ours {ours}, peer {theirs}")
            }
            Self::Unexpected => write!(f, "first message was not Hello"),
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<FrameError> for HandshakeError {
    fn from(e: FrameError) -> Self {
        Self::Frame(e)
    }
}

/// Client side of the handshake: sends `Hello`, expects the service's `Hello`
/// with the same [`PROTOCOL_VERSION`].
pub fn client_handshake<R: Read, W: Write + ?Sized>(
    reader: &mut FrameReader<R>,
    writer: &mut W,
) -> Result<(), HandshakeError> {
    write_frame(
        writer,
        &ClientMessage::Hello {
            protocol: PROTOCOL_VERSION,
        },
    )?;
    match reader.read_message::<ServerMessage>()? {
        None => Err(HandshakeError::Closed),
        Some(ServerMessage::Hello { protocol }) if protocol == PROTOCOL_VERSION => Ok(()),
        Some(ServerMessage::Hello { protocol }) => Err(HandshakeError::VersionMismatch {
            ours: PROTOCOL_VERSION,
            theirs: protocol,
        }),
        Some(ServerMessage::Response {
            payload:
                ResponsePayload::Error {
                    error: ProtocolError::VersionMismatch { expected },
                },
            ..
        }) => Err(HandshakeError::VersionMismatch {
            ours: PROTOCOL_VERSION,
            theirs: expected,
        }),
        Some(_) => Err(HandshakeError::Unexpected),
    }
}

/// Service side of the handshake: reads the client's first message. On a
/// matching `Hello` replies with `Hello`; otherwise replies with
/// `Error::VersionMismatch` / `Error::BadRequest` (id 0, or the offending
/// request's id) and returns an error — the caller then closes the pipe.
///
/// This blocks until the client speaks; the service should bound it with a
/// timer that calls [`PipeStream::cancel`] (Windows) so an idle client cannot
/// hold an instance forever.
pub fn server_handshake<R: Read, W: Write + ?Sized>(
    reader: &mut FrameReader<R>,
    writer: &mut W,
) -> Result<(), HandshakeError> {
    let first = match reader.read_message::<ClientMessage>() {
        Ok(Some(m)) => m,
        Ok(None) => return Err(HandshakeError::Closed),
        Err(e) if !e.is_fatal() => {
            reply_error(writer, 0, ProtocolError::BadRequest);
            return Err(HandshakeError::Frame(e));
        }
        Err(e) => return Err(HandshakeError::Frame(e)),
    };
    match first {
        ClientMessage::Hello { protocol } if protocol == PROTOCOL_VERSION => {
            write_frame(
                writer,
                &ServerMessage::Hello {
                    protocol: PROTOCOL_VERSION,
                },
            )?;
            Ok(())
        }
        ClientMessage::Hello { protocol } => {
            reply_error(
                writer,
                0,
                ProtocolError::VersionMismatch {
                    expected: PROTOCOL_VERSION,
                },
            );
            Err(HandshakeError::VersionMismatch {
                ours: PROTOCOL_VERSION,
                theirs: protocol,
            })
        }
        ClientMessage::Request { id, .. } => {
            reply_error(writer, id, ProtocolError::BadRequest);
            Err(HandshakeError::Unexpected)
        }
    }
}

fn reply_error<W: Write + ?Sized>(writer: &mut W, id: u64, error: ProtocolError) {
    // Best effort: the connection is about to be closed anyway.
    let _ = write_frame(
        writer,
        &ServerMessage::Response {
            id,
            payload: ResponsePayload::Error { error },
        },
    );
}

#[cfg(windows)]
pub use win::{
    Canceller, LinkEvent, NotConnected, OfflineReason, PipeClient, PipeServer, PipeStream,
    SDDL_ADR005, ServiceLink, ShutdownHandle,
};

#[cfg(windows)]
#[allow(unsafe_code)]
mod win {
    //! Win32 named-pipe FFI. Every `unsafe` block is a direct Win32 call with
    //! arguments that are valid for the duration of the call.

    use std::io::{self, Read, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::ptr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc::{self, RecvTimeoutError, Sender};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND,
        ERROR_IO_PENDING, ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY,
        ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, GetLastError, HANDLE, HLOCAL,
        INVALID_HANDLE_VALUE, LocalFree, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, SetNamedPipeHandleState,
        WaitNamedPipeW,
    };
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, INFINITE, SetEvent, WaitForMultipleObjects,
        WaitForSingleObject,
    };

    use super::{FrameReader, HandshakeError, client_handshake, write_frame};
    use crate::{ClientMessage, Request, ServerMessage};

    /// ADR 005 DACL: protected (no inheritance); SYSTEM full control;
    /// interactive users read + write **without** `FILE_CREATE_PIPE_INSTANCE`
    /// (0x4), so a user process cannot create a rogue instance of the pipe.
    /// `0x12019b` = `FILE_GENERIC_READ | FILE_GENERIC_WRITE & !FILE_APPEND_DATA`.
    pub const SDDL_ADR005: &str = "D:P(A;;GA;;;SY)(A;;0x12019b;;;IU)";

    /// Access mask clients request; must be a subset of the IU grant above.
    const CLIENT_ACCESS: u32 = 0x0012_019b;

    /// Kernel buffer size per direction; equals the frame cap.
    const PIPE_BUFFER: u32 = super::MAX_FRAME_LEN as u32;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn last_error() -> u32 {
        // SAFETY: GetLastError has no preconditions.
        unsafe { GetLastError() }
    }

    fn os_error(code: u32) -> io::Error {
        io::Error::from_raw_os_error(code as i32)
    }

    fn cancelled() -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionAborted, "pipe operation cancelled")
    }

    /// Creates an unnamed manual-reset event.
    fn new_event() -> io::Result<OwnedHandle> {
        // SAFETY: null security attributes and name are allowed.
        let h = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `h` is a fresh, valid handle that we exclusively own.
        Ok(unsafe { OwnedHandle::from_raw_handle(h) })
    }

    fn raw(h: &OwnedHandle) -> HANDLE {
        h.as_raw_handle()
    }

    fn is_signaled(event: &OwnedHandle) -> bool {
        // SAFETY: valid event handle, zero timeout.
        unsafe { WaitForSingleObject(raw(event), 0) == WAIT_OBJECT_0 }
    }

    /// Runs one overlapped operation to completion (or cancellation).
    ///
    /// `start` issues the call with the provided `OVERLAPPED`; it returns the
    /// Win32 BOOL. This function never returns while the operation is still
    /// pending, so the stack-allocated `OVERLAPPED` outlives it.
    /// `ERROR_MORE_DATA` (partial message read) counts as success.
    fn overlapped_io(
        handle: HANDLE,
        event: &OwnedHandle,
        cancel: &OwnedHandle,
        start: impl FnOnce(*mut OVERLAPPED) -> i32,
    ) -> io::Result<u32> {
        if is_signaled(cancel) {
            return Err(cancelled());
        }
        // SAFETY: OVERLAPPED is a plain C struct; all-zero is its documented initial state.
        let mut ov: OVERLAPPED = unsafe { std::mem::zeroed() };
        ov.hEvent = raw(event);
        let ok = start(&mut ov);
        if ok == 0 {
            let err = last_error();
            if err != ERROR_IO_PENDING {
                return Err(os_error(err));
            }
            let handles = [raw(event), raw(cancel)];
            // SAFETY: two valid event handles; INFINITE wait.
            let w = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
            if w == WAIT_OBJECT_0 + 1 {
                // SAFETY: `ov` belongs to an operation issued on `handle`.
                unsafe { CancelIoEx(handle, &ov) };
            }
        }
        let mut n = 0u32;
        // SAFETY: `ov` was used for an operation on `handle`; bWait=TRUE blocks until it
        // has fully completed (or been aborted), after which `ov` may be dropped.
        let ok = unsafe { GetOverlappedResult(handle, &ov, &mut n, 1) };
        if ok != 0 {
            return Ok(n);
        }
        match last_error() {
            ERROR_MORE_DATA => Ok(n),
            ERROR_OPERATION_ABORTED => Err(cancelled()),
            err => Err(os_error(err)),
        }
    }

    /// Cancels the blocking operations of a [`PipeStream`] and all of its clones.
    #[derive(Clone, Debug)]
    pub struct Canceller(Arc<OwnedHandle>);

    impl Canceller {
        /// Aborts pending and future reads/writes with `ConnectionAborted`.
        pub fn cancel(&self) {
            // SAFETY: valid event handle.
            unsafe { SetEvent(raw(&self.0)) };
        }
    }

    /// One end of a connected pipe. Implements [`Read`] / [`Write`]; reading
    /// returns `Ok(0)` once the peer has closed its end.
    #[derive(Debug)]
    pub struct PipeStream {
        handle: OwnedHandle,
        event: OwnedHandle,
        cancel: Arc<OwnedHandle>,
    }

    impl PipeStream {
        fn from_handle(handle: OwnedHandle) -> io::Result<Self> {
            Ok(Self {
                handle,
                event: new_event()?,
                cancel: Arc::new(new_event()?),
            })
        }

        /// Duplicates the pipe handle so reads and writes can run on different
        /// threads concurrently. Clones share one [`Canceller`].
        pub fn try_clone(&self) -> io::Result<Self> {
            let mut dup: HANDLE = ptr::null_mut();
            // SAFETY: duplicating our own valid handle into our own process.
            let ok = unsafe {
                let me = GetCurrentProcess();
                DuplicateHandle(
                    me,
                    raw(&self.handle),
                    me,
                    &mut dup,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                // SAFETY: `dup` is a fresh handle owned by us.
                handle: unsafe { OwnedHandle::from_raw_handle(dup) },
                event: new_event()?,
                cancel: Arc::clone(&self.cancel),
            })
        }

        /// A handle that aborts blocking I/O on this stream (and its clones)
        /// from any thread.
        pub fn canceller(&self) -> Canceller {
            Canceller(Arc::clone(&self.cancel))
        }

        /// Aborts pending and future I/O on this stream and its clones.
        pub fn cancel(&self) {
            self.canceller().cancel();
        }
    }

    impl Read for PipeStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = buf.len().min(u32::MAX as usize) as u32;
            let h = raw(&self.handle);
            let r = overlapped_io(h, &self.event, &self.cancel, |ov| {
                // SAFETY: `buf` is valid for `len` bytes and outlives the operation
                // (overlapped_io waits for completion).
                unsafe { ReadFile(h, buf.as_mut_ptr(), len, ptr::null_mut(), ov) }
            });
            match r {
                Ok(n) => Ok(n as usize),
                Err(e)
                    if matches!(
                        e.raw_os_error().map(|c| c as u32),
                        Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA)
                    ) =>
                {
                    Ok(0)
                }
                Err(e) => Err(e),
            }
        }
    }

    impl Write for PipeStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let len = buf.len().min(u32::MAX as usize) as u32;
            let h = raw(&self.handle);
            let n = overlapped_io(h, &self.event, &self.cancel, |ov| {
                // SAFETY: `buf` is valid for `len` bytes and outlives the operation.
                unsafe { WriteFile(h, buf.as_ptr(), len, ptr::null_mut(), ov) }
            })?;
            Ok(n as usize)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Owned security descriptor from `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
    struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

    // SAFETY: the descriptor is immutable after creation and only read by CreateNamedPipeW.
    unsafe impl Send for SecurityDescriptor {}
    // SAFETY: as above; shared read-only access is fine.
    unsafe impl Sync for SecurityDescriptor {}

    impl SecurityDescriptor {
        fn from_sddl(sddl: &str) -> io::Result<Self> {
            let w = wide(sddl);
            let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
            // SAFETY: `w` is NUL-terminated; `sd` receives a LocalAlloc'd descriptor.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    w.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(sd))
        }
    }

    impl Drop for SecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }

    /// Wakes a blocked [`PipeServer::accept`] from another thread.
    #[derive(Clone, Debug)]
    pub struct ShutdownHandle(Arc<OwnedHandle>);

    impl ShutdownHandle {
        /// Makes the current and every future `accept` return `Ok(None)`.
        pub fn shutdown(&self) {
            // SAFETY: valid event handle.
            unsafe { SetEvent(raw(&self.0)) };
        }
    }

    /// Service side: owns the pipe name and hands out one [`PipeStream`] per client.
    ///
    /// One listening instance is always kept open, so the name stays owned
    /// by the service between accepts (no squatting window) and clients see
    /// `ERROR_PIPE_BUSY` rather than "not found" while a slot is being created.
    pub struct PipeServer {
        name: Vec<u16>,
        sd: SecurityDescriptor,
        next: Option<OwnedHandle>,
        event: OwnedHandle,
        shutdown: Arc<OwnedHandle>,
    }

    impl std::fmt::Debug for PipeServer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PipeServer")
                .field("name", &String::from_utf16_lossy(&self.name))
                .finish_non_exhaustive()
        }
    }

    impl PipeServer {
        /// Creates the first instance with the ADR 005 DACL ([`SDDL_ADR005`]).
        /// Fails if any process already owns a pipe with this name.
        pub fn bind(name: &str) -> io::Result<Self> {
            Self::bind_with_sddl(name, SDDL_ADR005)
        }

        /// Like [`bind`](Self::bind) with a custom SDDL DACL (tests run unelevated
        /// and use e.g. `"D:P(A;;GA;;;OW)"`). The creator must keep
        /// `FILE_CREATE_PIPE_INSTANCE` or later instances cannot be created.
        pub fn bind_with_sddl(name: &str, sddl: &str) -> io::Result<Self> {
            let mut server = Self {
                name: wide(name),
                sd: SecurityDescriptor::from_sddl(sddl)?,
                next: None,
                event: new_event()?,
                shutdown: Arc::new(new_event()?),
            };
            server.next = Some(server.create_instance(true)?);
            Ok(server)
        }

        fn create_instance(&self, first: bool) -> io::Result<OwnedHandle> {
            let sa = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: self.sd.0,
                bInheritHandle: 0,
            };
            let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
            if first {
                open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
            }
            // SAFETY: `name` is NUL-terminated and `sa` (with its descriptor) outlives the call.
            let h = unsafe {
                CreateNamedPipeW(
                    self.name.as_ptr(),
                    open_mode,
                    PIPE_TYPE_MESSAGE
                        | PIPE_READMODE_MESSAGE
                        | PIPE_WAIT
                        | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    PIPE_BUFFER,
                    PIPE_BUFFER,
                    0,
                    &sa,
                )
            };
            if h == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fresh, valid handle owned by us.
            Ok(unsafe { OwnedHandle::from_raw_handle(h) })
        }

        /// A handle to stop the accept loop from another thread.
        pub fn shutdown_handle(&self) -> ShutdownHandle {
            ShutdownHandle(Arc::clone(&self.shutdown))
        }

        /// Blocks until a client connects. Returns `Ok(None)` after
        /// [`ShutdownHandle::shutdown`]. The returned stream is exclusively that
        /// client's; drop it to close the connection.
        pub fn accept(&mut self) -> io::Result<Option<PipeStream>> {
            let instance = match self.next.take() {
                Some(h) => h,
                None => self.create_instance(false)?,
            };
            let h = raw(&instance);
            let r = overlapped_io(h, &self.event, &self.shutdown, |ov| {
                // SAFETY: valid pipe instance; `ov` outlives the operation.
                unsafe { ConnectNamedPipe(h, ov) }
            });
            match r {
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32) => {}
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                    self.next = Some(instance);
                    return Ok(None);
                }
                Err(e) => return Err(e),
            }
            // Keep the name owned while this client is served. If that fails,
            // the next accept retries.
            self.next = self.create_instance(false).ok();
            PipeStream::from_handle(instance).map(Some)
        }
    }

    /// Client side connector.
    #[derive(Debug, Clone, Copy)]
    pub struct PipeClient;

    impl PipeClient {
        /// Connects to `name`, retrying while the pipe does not exist yet
        /// (service starting) or all instances are busy, until `timeout`.
        /// Times out with `ErrorKind::TimedOut`; a missing service with
        /// `ErrorKind::NotFound`.
        ///
        /// The handle is opened with `SECURITY_IDENTIFICATION`, so a rogue
        /// server could at most identify — never impersonate — the user.
        pub fn connect(name: &str, timeout: Duration) -> io::Result<PipeStream> {
            let w = wide(name);
            let deadline = Instant::now() + timeout;
            loop {
                // SAFETY: `w` is NUL-terminated; no security attributes or template.
                let h = unsafe {
                    CreateFileW(
                        w.as_ptr(),
                        CLIENT_ACCESS,
                        0,
                        ptr::null(),
                        OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                        ptr::null_mut(),
                    )
                };
                if h != INVALID_HANDLE_VALUE {
                    // SAFETY: fresh, valid handle owned by us.
                    let handle = unsafe { OwnedHandle::from_raw_handle(h) };
                    let mode = PIPE_READMODE_MESSAGE;
                    // SAFETY: valid pipe handle; only the mode pointer is non-null.
                    let ok = unsafe {
                        SetNamedPipeHandleState(raw(&handle), &mode, ptr::null(), ptr::null())
                    };
                    if ok == 0 {
                        return Err(io::Error::last_os_error());
                    }
                    return PipeStream::from_handle(handle);
                }
                let err = last_error();
                let now = Instant::now();
                if now >= deadline {
                    return Err(match err {
                        ERROR_FILE_NOT_FOUND => os_error(err),
                        ERROR_PIPE_BUSY => {
                            io::Error::new(io::ErrorKind::TimedOut, "all pipe instances busy")
                        }
                        _ => os_error(err),
                    });
                }
                let left = (deadline - now).as_millis().clamp(1, u32::MAX as u128 - 1) as u32;
                match err {
                    ERROR_PIPE_BUSY => {
                        // SAFETY: `w` is NUL-terminated.
                        unsafe { WaitNamedPipeW(w.as_ptr(), left) };
                    }
                    ERROR_FILE_NOT_FOUND => {
                        std::thread::sleep(Duration::from_millis(u64::from(left.min(50))));
                    }
                    _ => return Err(os_error(err)),
                }
            }
        }
    }

    /// Why a [`ServiceLink`] is offline.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum OfflineReason {
        /// The pipe does not exist / cannot be opened (service not running).
        NotRunning,
        /// An established connection was lost.
        Lost,
        /// The service speaks another protocol version.
        VersionMismatch {
            /// The service's version.
            service: u32,
        },
        /// The handshake failed for another reason.
        Handshake,
    }

    /// Notifications from a [`ServiceLink`], delivered on its worker threads.
    #[derive(Debug, Clone)]
    pub enum LinkEvent {
        /// Handshake done; a `GetStatus` request has already been sent.
        Connected,
        /// A message from the service (response or pushed event).
        Message(ServerMessage),
        /// Not connected; the link keeps retrying with backoff.
        Offline(OfflineReason),
    }

    /// Returned by [`ServiceLink::send`] while the service is unreachable.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NotConnected;

    impl std::fmt::Display for NotConnected {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("service not connected")
        }
    }

    impl std::error::Error for NotConnected {}

    enum Cmd {
        Send(u64, Request),
        ReaderDone,
        Retry,
        Shutdown,
    }

    /// Initial reconnect delay.
    pub(super) const BACKOFF_MIN: Duration = Duration::from_millis(250);
    /// Reconnect delay cap.
    pub(super) const BACKOFF_MAX: Duration = Duration::from_secs(5);
    const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

    /// Next reconnect delay (doubling, capped).
    pub(super) fn next_backoff(cur: Duration) -> Duration {
        (cur * 2).min(BACKOFF_MAX)
    }

    /// A self-reconnecting client connection to the service.
    ///
    /// Runs a manager thread (connect → handshake → write requests) and, while
    /// connected, a reader thread that forwards every [`ServerMessage`] to the
    /// callback. No timers run while connected; while offline the manager
    /// sleeps with exponential backoff (250 ms … 5 s).
    pub struct ServiceLink {
        tx: Sender<Cmd>,
        connected: Arc<AtomicBool>,
        next_id: Arc<AtomicU64>,
    }

    impl std::fmt::Debug for ServiceLink {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ServiceLink")
                .field("connected", &self.is_connected())
                .finish_non_exhaustive()
        }
    }

    impl ServiceLink {
        /// Starts the link. `on_event` runs on the link's threads; marshal to the
        /// UI thread yourself.
        pub fn spawn(name: &str, on_event: impl Fn(LinkEvent) + Send + Sync + 'static) -> Self {
            let (tx, rx) = mpsc::channel::<Cmd>();
            let connected = Arc::new(AtomicBool::new(false));
            let next_id = Arc::new(AtomicU64::new(1));
            let cb: Arc<dyn Fn(LinkEvent) + Send + Sync> = Arc::new(on_event);
            let name = name.to_owned();
            let (tx2, conn2, ids2) = (tx.clone(), Arc::clone(&connected), Arc::clone(&next_id));
            std::thread::Builder::new()
                .name("uf-ipc-link".into())
                .spawn(move || manager(&name, &rx, &tx2, &conn2, &ids2, &cb))
                .expect("spawn ipc link thread");
            Self {
                tx,
                connected,
                next_id,
            }
        }

        /// Whether the handshake has completed and the connection is up.
        pub fn is_connected(&self) -> bool {
            self.connected.load(Ordering::Acquire)
        }

        /// Queues a request; returns its correlation id.
        pub fn send(&self, request: Request) -> Result<u64, NotConnected> {
            if !self.is_connected() {
                return Err(NotConnected);
            }
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            self.tx
                .send(Cmd::Send(id, request))
                .map_err(|_| NotConnected)?;
            Ok(id)
        }

        /// Skips the current backoff wait and tries to connect now.
        pub fn retry_now(&self) {
            let _ = self.tx.send(Cmd::Retry);
        }
    }

    impl Drop for ServiceLink {
        fn drop(&mut self) {
            let _ = self.tx.send(Cmd::Shutdown);
        }
    }

    fn connect_once(name: &str) -> Result<(PipeStream, PipeStream), OfflineReason> {
        let stream =
            PipeClient::connect(name, CONNECT_TIMEOUT).map_err(|_| OfflineReason::NotRunning)?;
        let mut writer = stream.try_clone().map_err(|_| OfflineReason::Handshake)?;
        let mut reader = FrameReader::new(stream);
        match client_handshake(&mut reader, &mut writer) {
            Ok(()) => {}
            Err(HandshakeError::VersionMismatch { theirs, .. }) => {
                return Err(OfflineReason::VersionMismatch { service: theirs });
            }
            Err(_) => return Err(OfflineReason::Handshake),
        }
        // The handshake consumed exactly one frame and the service sends nothing
        // before it sees a request, so no buffered bytes are lost here.
        Ok((reader.into_inner(), writer))
    }

    fn manager(
        name: &str,
        rx: &mpsc::Receiver<Cmd>,
        tx: &Sender<Cmd>,
        connected: &AtomicBool,
        next_id: &AtomicU64,
        cb: &Arc<dyn Fn(LinkEvent) + Send + Sync>,
    ) {
        let mut backoff = BACKOFF_MIN;
        let mut last_offline: Option<OfflineReason> = None;
        loop {
            match connect_once(name) {
                Ok((reader, mut writer)) => {
                    backoff = BACKOFF_MIN;
                    let canceller = writer.canceller();
                    let id = next_id.fetch_add(1, Ordering::Relaxed);
                    let hello_ok = write_frame(
                        &mut writer,
                        &ClientMessage::Request {
                            id,
                            request: Request::GetStatus,
                        },
                    )
                    .is_ok();
                    let (tx_r, cb_r) = (tx.clone(), Arc::clone(cb));
                    let spawned = std::thread::Builder::new()
                        .name("uf-ipc-reader".into())
                        .spawn(move || {
                            let mut fr = FrameReader::new(reader);
                            loop {
                                match fr.read_message::<ServerMessage>() {
                                    Ok(Some(m)) => cb_r(LinkEvent::Message(m)),
                                    Ok(None) => break,
                                    Err(e) if !e.is_fatal() => continue,
                                    Err(_) => break,
                                }
                            }
                            let _ = tx_r.send(Cmd::ReaderDone);
                        });
                    if spawned.is_ok() && hello_ok {
                        connected.store(true, Ordering::Release);
                        cb(LinkEvent::Connected);
                    } else {
                        canceller.cancel();
                    }
                    // Without a reader thread nobody would send ReaderDone.
                    let shutdown = spawned.is_ok()
                        && loop {
                            match rx.recv() {
                                Ok(Cmd::Send(id, request)) => {
                                    let msg = ClientMessage::Request { id, request };
                                    if write_frame(&mut writer, &msg).is_err() {
                                        canceller.cancel();
                                    }
                                }
                                Ok(Cmd::ReaderDone) => break false,
                                Ok(Cmd::Retry) => {}
                                Ok(Cmd::Shutdown) | Err(_) => break true,
                            }
                        };
                    connected.store(false, Ordering::Release);
                    canceller.cancel();
                    if shutdown {
                        return;
                    }
                    last_offline = Some(OfflineReason::Lost);
                    cb(LinkEvent::Offline(OfflineReason::Lost));
                }
                Err(reason) => {
                    if last_offline != Some(reason) {
                        last_offline = Some(reason);
                        cb(LinkEvent::Offline(reason));
                    }
                }
            }
            match rx.recv_timeout(backoff) {
                Ok(Cmd::Shutdown) | Err(RecvTimeoutError::Disconnected) => return,
                Ok(Cmd::Retry) => backoff = BACKOFF_MIN,
                Ok(Cmd::Send(..) | Cmd::ReaderDone) | Err(RecvTimeoutError::Timeout) => {
                    backoff = next_backoff(backoff);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Event, Request, Status};
    use std::io::Cursor;

    /// A reader that returns at most `chunk` bytes per call.
    struct Trickle<'a> {
        data: &'a [u8],
        chunk: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.chunk.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    #[test]
    fn reads_multiple_frames_and_eof() {
        let data =
            b"{\"type\":\"hello\",\"protocol\":1}\n\n{\"type\":\"hello\",\"protocol\":2}\r\n";
        let mut r = FrameReader::new(Cursor::new(&data[..]));
        let a: ClientMessage = r.read_message().unwrap().unwrap();
        let b: ClientMessage = r.read_message().unwrap().unwrap();
        assert_eq!(a, ClientMessage::Hello { protocol: 1 });
        assert_eq!(b, ClientMessage::Hello { protocol: 2 });
        assert!(r.read_line().unwrap().is_none());
        assert!(r.read_line().unwrap().is_none());
    }

    #[test]
    fn frames_split_across_reads() {
        let mut out = Vec::new();
        for i in 0..20 {
            write_frame(
                &mut out,
                &ClientMessage::Request {
                    id: i,
                    request: Request::TestSite {
                        host: format!("host{i}.example"),
                    },
                },
            )
            .unwrap();
        }
        let mut r = FrameReader::new(Trickle {
            data: &out,
            chunk: 7,
        });
        for i in 0..20 {
            match r.read_message::<ClientMessage>().unwrap().unwrap() {
                ClientMessage::Request { id, .. } => assert_eq!(id, i),
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(r.read_line().unwrap().is_none());
    }

    #[test]
    fn exactly_max_frame_is_accepted() {
        let mut data = vec![b'a'; MAX_FRAME_LEN - 1];
        data.push(b'\n');
        let mut r = FrameReader::new(Cursor::new(data));
        assert_eq!(r.read_line().unwrap().unwrap().len(), MAX_FRAME_LEN - 1);
    }

    #[test]
    fn oversized_frame_is_rejected_and_poisons() {
        let mut data = vec![b'a'; MAX_FRAME_LEN];
        data.push(b'\n');
        data.extend_from_slice(b"{}\n");
        let mut r = FrameReader::new(Cursor::new(data));
        let e = r.read_line().unwrap_err();
        assert!(matches!(e, FrameError::TooLarge) && e.is_fatal());
        assert!(matches!(r.read_line(), Err(FrameError::TooLarge)));
    }

    #[test]
    fn endless_frame_without_newline_is_rejected() {
        let data = vec![b'x'; MAX_FRAME_LEN * 3];
        let mut r = FrameReader::new(Cursor::new(data));
        assert!(matches!(r.read_line(), Err(FrameError::TooLarge)));
    }

    #[test]
    fn truncated_frame_is_unexpected_eof() {
        let mut r = FrameReader::new(Cursor::new(&b"{\"type\":"[..]));
        assert!(matches!(r.read_line(), Err(FrameError::UnexpectedEof)));
    }

    #[test]
    fn malformed_json_is_recoverable() {
        let data = b"not json\n\xff\xfe\n{\"type\":\"hello\",\"protocol\":1}\n";
        let mut r = FrameReader::new(Cursor::new(&data[..]));
        let e = r.read_message::<ClientMessage>().unwrap_err();
        assert!(matches!(e, FrameError::Json(_)) && !e.is_fatal());
        let e = r.read_message::<ClientMessage>().unwrap_err();
        assert!(matches!(e, FrameError::InvalidUtf8) && !e.is_fatal());
        assert!(r.read_message::<ClientMessage>().unwrap().is_some());
    }

    #[test]
    fn write_frame_rejects_oversized_message() {
        let msg = ServerMessage::Event {
            event: Event::Log {
                time: "00:00:00".into(),
                host: "h".repeat(MAX_FRAME_LEN),
                method: String::new(),
                outcome: String::new(),
            },
        };
        let mut out = Vec::new();
        assert!(matches!(
            write_frame(&mut out, &msg),
            Err(FrameError::TooLarge)
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn write_frame_is_one_line() {
        let msg = ServerMessage::Event {
            event: Event::Status {
                status: Status {
                    state: crate::ConnState::Ready,
                    strategy: Some("a\nb".into()),
                    added_latency_us: 0,
                    mode: crate::Mode::Normal,
                },
            },
        };
        let mut out = Vec::new();
        write_frame(&mut out, &msg).unwrap();
        assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1);
        assert_eq!(out.last(), Some(&b'\n'));
    }

    fn server_reply_to(client_bytes: &[u8]) -> (Result<(), HandshakeError>, Vec<u8>) {
        let mut reader = FrameReader::new(Cursor::new(client_bytes.to_vec()));
        let mut out = Vec::new();
        let r = server_handshake(&mut reader, &mut out);
        (r, out)
    }

    #[test]
    fn handshake_happy_path() {
        // Client writes Hello into a buffer...
        let mut client_out = Vec::new();
        let server_hello = crate::encode(&ServerMessage::Hello {
            protocol: PROTOCOL_VERSION,
        })
        .unwrap();
        let mut client_in = FrameReader::new(Cursor::new(server_hello.into_bytes()));
        client_handshake(&mut client_in, &mut client_out).unwrap();
        // ...which the server accepts and answers with Hello.
        let (r, out) = server_reply_to(&client_out);
        r.unwrap();
        let mut back = FrameReader::new(Cursor::new(out));
        assert_eq!(
            back.read_message::<ServerMessage>().unwrap().unwrap(),
            ServerMessage::Hello {
                protocol: PROTOCOL_VERSION
            }
        );
    }

    #[test]
    fn server_rejects_wrong_version() {
        let bad = crate::encode(&ClientMessage::Hello {
            protocol: PROTOCOL_VERSION + 1,
        })
        .unwrap();
        let (r, out) = server_reply_to(bad.as_bytes());
        assert!(matches!(r, Err(HandshakeError::VersionMismatch { .. })));
        // The client side interprets that reply as a version mismatch.
        let mut client_in = FrameReader::new(Cursor::new(out));
        let mut sink = Vec::new();
        match client_handshake(&mut client_in, &mut sink) {
            Err(HandshakeError::VersionMismatch { ours, theirs }) => {
                assert_eq!((ours, theirs), (PROTOCOL_VERSION, PROTOCOL_VERSION));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn server_rejects_request_before_hello() {
        let req = crate::encode(&ClientMessage::Request {
            id: 7,
            request: Request::Connect,
        })
        .unwrap();
        let (r, out) = server_reply_to(req.as_bytes());
        assert!(matches!(r, Err(HandshakeError::Unexpected)));
        let mut back = FrameReader::new(Cursor::new(out));
        assert_eq!(
            back.read_message::<ServerMessage>().unwrap().unwrap(),
            ServerMessage::Response {
                id: 7,
                payload: ResponsePayload::Error {
                    error: ProtocolError::BadRequest
                }
            }
        );
    }

    #[test]
    fn server_handshake_on_closed_stream() {
        let (r, out) = server_reply_to(b"");
        assert!(matches!(r, Err(HandshakeError::Closed)));
        assert!(out.is_empty());
    }

    #[test]
    fn client_detects_newer_service_hello() {
        let hello = crate::encode(&ServerMessage::Hello { protocol: 99 }).unwrap();
        let mut client_in = FrameReader::new(Cursor::new(hello.into_bytes()));
        let mut sink = Vec::new();
        assert!(matches!(
            client_handshake(&mut client_in, &mut sink),
            Err(HandshakeError::VersionMismatch { theirs: 99, .. })
        ));
    }

    #[cfg(windows)]
    mod windows_pipe {
        use super::super::win::{BACKOFF_MAX, BACKOFF_MIN, next_backoff};
        use super::super::*;
        use crate::{Event, Request, ServerMessage};
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::mpsc;
        use std::time::Duration;

        /// Unelevated tests cannot use the SYSTEM-only DACL; owner-only is enough.
        const TEST_SDDL: &str = "D:P(A;;GA;;;OW)";

        fn unique_name() -> String {
            static N: AtomicU32 = AtomicU32::new(0);
            format!(
                r"\\.\pipe\unfilter-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            )
        }

        #[test]
        fn adr005_sddl_parses() {
            // Binding with the production DACL works for the first instance even
            // unelevated (the creator's handle needs no DACL grant).
            let name = unique_name();
            let server = PipeServer::bind(&name).unwrap();
            drop(server);
        }

        #[test]
        fn second_bind_on_same_name_fails() {
            let name = unique_name();
            let _a = PipeServer::bind_with_sddl(&name, TEST_SDDL).unwrap();
            assert!(PipeServer::bind_with_sddl(&name, TEST_SDDL).is_err());
        }

        #[test]
        fn connect_to_missing_pipe_times_out_as_not_found() {
            let e = PipeClient::connect(&unique_name(), Duration::from_millis(120)).unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
        }

        #[test]
        fn shutdown_unblocks_accept() {
            let name = unique_name();
            let mut server = PipeServer::bind_with_sddl(&name, TEST_SDDL).unwrap();
            let stop = server.shutdown_handle();
            let t = std::thread::spawn(move || server.accept().unwrap().is_none());
            std::thread::sleep(Duration::from_millis(50));
            stop.shutdown();
            assert!(t.join().unwrap());
        }

        #[test]
        fn handshake_and_full_duplex_over_real_pipe() {
            let name = unique_name();
            let mut server = PipeServer::bind_with_sddl(&name, TEST_SDDL).unwrap();
            let srv = std::thread::spawn(move || {
                let mut clients = Vec::new();
                for _ in 0..2 {
                    let stream = server.accept().unwrap().unwrap();
                    clients.push(std::thread::spawn(move || {
                        let mut writer = stream.try_clone().unwrap();
                        let mut reader = FrameReader::new(stream);
                        server_handshake(&mut reader, &mut writer).unwrap();
                        // Pusher thread writes while this thread blocks in read.
                        let pusher = std::thread::spawn(move || {
                            for i in 0..50 {
                                let ev = ServerMessage::Event {
                                    event: Event::Log {
                                        time: format!("{i}"),
                                        host: "h".into(),
                                        method: "m".into(),
                                        outcome: "OK".into(),
                                    },
                                };
                                write_frame(&mut writer, &ev).unwrap();
                            }
                        });
                        let mut got = 0;
                        while let Ok(Some(_)) = reader.read_message::<ClientMessage>() {
                            got += 1;
                        }
                        pusher.join().unwrap();
                        got
                    }));
                }
                clients
                    .into_iter()
                    .map(|c| c.join().unwrap())
                    .collect::<Vec<_>>()
            });

            for _ in 0..2 {
                let stream = PipeClient::connect(&name, Duration::from_secs(2)).unwrap();
                let mut writer = stream.try_clone().unwrap();
                let mut reader = FrameReader::new(stream);
                client_handshake(&mut reader, &mut writer).unwrap();
                let w = std::thread::spawn(move || {
                    for id in 0..30 {
                        let m = ClientMessage::Request {
                            id,
                            request: Request::GetStatus,
                        };
                        write_frame(&mut writer, &m).unwrap();
                    }
                    // dropping `writer` keeps the reader clone open
                });
                for _ in 0..50 {
                    assert!(matches!(
                        reader.read_message::<ServerMessage>().unwrap().unwrap(),
                        ServerMessage::Event { .. }
                    ));
                }
                w.join().unwrap();
                drop(reader); // closes the last client handle -> server sees EOF
            }
            assert_eq!(srv.join().unwrap(), vec![30, 30]);
        }

        #[test]
        fn cancel_unblocks_read() {
            let name = unique_name();
            let mut server = PipeServer::bind_with_sddl(&name, TEST_SDDL).unwrap();
            let srv = std::thread::spawn(move || server.accept().unwrap().unwrap());
            let mut client = PipeClient::connect(&name, Duration::from_secs(2)).unwrap();
            let _server_end = srv.join().unwrap();
            let canceller = client.canceller();
            let t = std::thread::spawn(move || {
                let mut buf = [0u8; 16];
                client.read(&mut buf).unwrap_err().kind()
            });
            std::thread::sleep(Duration::from_millis(50));
            canceller.cancel();
            assert_eq!(t.join().unwrap(), std::io::ErrorKind::ConnectionAborted);
        }

        #[test]
        fn service_link_connects_sends_and_reconnects() {
            let name = unique_name();
            let (ev_tx, ev_rx) = mpsc::channel();
            let link = ServiceLink::spawn(&name, move |e| {
                let _ = ev_tx.send(e);
            });
            let wait = |pred: &dyn Fn(&LinkEvent) -> bool| loop {
                let e = ev_rx.recv_timeout(Duration::from_secs(10)).expect("event");
                if pred(&e) {
                    return e;
                }
            };
            wait(&|e| matches!(e, LinkEvent::Offline(OfflineReason::NotRunning)));
            assert_eq!(link.send(Request::Connect), Err(NotConnected));

            let mut server = PipeServer::bind_with_sddl(&name, TEST_SDDL).unwrap();
            link.retry_now();
            let stream = server.accept().unwrap().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = FrameReader::new(stream);
            server_handshake(&mut reader, &mut writer).unwrap();
            wait(&|e| matches!(e, LinkEvent::Connected));
            // The link sends GetStatus on its own after the handshake.
            match reader.read_message::<ClientMessage>().unwrap().unwrap() {
                ClientMessage::Request { request, .. } => assert_eq!(request, Request::GetStatus),
                other => panic!("unexpected {other:?}"),
            }
            let id = link.send(Request::Repair).unwrap();
            match reader.read_message::<ClientMessage>().unwrap().unwrap() {
                ClientMessage::Request { id: got, request } => {
                    assert_eq!((got, request), (id, Request::Repair));
                }
                other => panic!("unexpected {other:?}"),
            }
            write_frame(
                &mut writer,
                &ServerMessage::Response {
                    id,
                    payload: crate::ResponsePayload::Ok,
                },
            )
            .unwrap();
            wait(&|e| matches!(e, LinkEvent::Message(ServerMessage::Response { .. })));
            drop(writer);
            drop(reader);
            wait(&|e| matches!(e, LinkEvent::Offline(OfflineReason::Lost)));
            assert!(!link.is_connected());
        }

        #[test]
        fn backoff_doubles_and_caps() {
            let mut b = BACKOFF_MIN;
            let mut seen = vec![b];
            for _ in 0..10 {
                b = next_backoff(b);
                seen.push(b);
            }
            assert_eq!(seen[1], BACKOFF_MIN * 2);
            assert!(seen.windows(2).all(|w| w[1] >= w[0]));
            assert_eq!(*seen.last().unwrap(), BACKOFF_MAX);
        }
    }
}
