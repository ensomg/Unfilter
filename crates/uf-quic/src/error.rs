//! Error type for QUIC Initial parsing and decryption. Like the rest of the
//! project, every case is non-fatal: the caller falls back to treating the flow
//! as opaque QUIC (SNI unknown) and lets the engine's flow/IP handling decide.

use core::fmt;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Why an Initial packet could not be read or decrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ended before the structure was complete.
    Truncated,
    /// A length or offset pointed outside the datagram.
    OutOfBounds,
    /// The bytes did not match the QUIC framing.
    Malformed,
    /// Not a long-header Initial packet (e.g. a short header or 0-RTT).
    NotInitial,
    /// A QUIC version this crate does not have Initial keys for.
    UnsupportedVersion,
    /// Decryption failed (wrong keys, corrupt packet, or an unexpected frame).
    Crypto,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::Truncated => "quic input truncated",
            Error::OutOfBounds => "quic length out of bounds",
            Error::Malformed => "malformed quic framing",
            Error::NotInitial => "not a quic initial packet",
            Error::UnsupportedVersion => "unsupported quic version",
            Error::Crypto => "quic initial decryption failed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Error {}
