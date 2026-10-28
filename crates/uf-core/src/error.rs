//! Core error type. Deliberately small and `#[non_exhaustive]` so adapters can
//! match on the cases that matter and fall back to pass-through otherwise.

use core::fmt;

/// Result alias used throughout `uf-core`.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced inside the core engine and its parsers.
///
/// None of these are fatal to the user's connectivity: the engine's contract is
/// that any error on a packet means "re-inject it unchanged" (fail-open).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input was too short to contain the structure being parsed.
    Truncated,
    /// A length or offset field pointed outside the buffer.
    OutOfBounds,
    /// The bytes did not match the expected protocol framing.
    Malformed,
    /// A capacity limit was reached (buffer pool empty, emitter full, flow
    /// table full). The caller falls back to pass-through.
    Capacity,
    /// The platform I/O backend reported it has shut down; stop the loop.
    Shutdown,
    /// A platform I/O call failed transiently. Carries the OS error code. The
    /// engine treats this as fail-open (count and continue), not fatal.
    Io(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::Truncated => "input truncated",
            Error::OutOfBounds => "length field out of bounds",
            Error::Malformed => "malformed protocol framing",
            Error::Capacity => "capacity limit reached",
            Error::Shutdown => "io backend shut down",
            Error::Io(code) => return write!(f, "io backend error (os code {code})"),
        };
        f.write_str(s)
    }
}

impl std::error::Error for Error {}
