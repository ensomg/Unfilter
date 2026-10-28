//! Fallback error type. Small and `#[non_exhaustive]` so the service can match
//! the cases it cares about and treat the rest as "fallback unavailable, give up
//! on this target" without ever affecting the default traffic path.

use core::fmt;

/// Result alias for the fallback handshakes and builders.
pub type Result<T> = core::result::Result<T, FallbackError>;

/// Why establishing a tunnel through a fallback upstream failed.
///
/// None of these touch the default path: a fallback is only ever consulted for a
/// target the prober marked [`IpBlocked`](crate::target::TargetVerdict::IpBlocked),
/// and a failure here just means that one target stays unreachable (fail-closed
/// for that target only, never for the rest of the user's traffic).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FallbackError {
    /// The upstream's reply was shorter than the framing requires. For a
    /// byte-at-a-time transport this is not terminal: pump more bytes in.
    Truncated,
    /// The upstream's reply did not match the protocol framing.
    Malformed,
    /// The upstream offered no acceptable authentication method, or demanded one
    /// the configured upstream cannot satisfy.
    AuthUnsupported,
    /// Authentication was attempted and rejected by the upstream.
    AuthFailed,
    /// The upstream refused the CONNECT. Carries the protocol-specific code
    /// (SOCKS5 reply field, or HTTP status code) for logging.
    Refused(u16),
    /// A variable-length field (hostname, username, password) exceeded the
    /// protocol limit and cannot be encoded.
    FieldTooLong,
    /// This upstream cannot serve the target in this build. Returned by the
    /// WireGuard upstream in v1 (interface only) and when a feature is disabled.
    /// Explicitly *not* a panic: the caller falls back to the next upstream or
    /// leaves the target direct.
    NotAvailable,
}

impl fmt::Display for FallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            FallbackError::Truncated => "reply truncated (need more bytes)",
            FallbackError::Malformed => "malformed upstream reply",
            FallbackError::AuthUnsupported => "no acceptable authentication method",
            FallbackError::AuthFailed => "upstream rejected authentication",
            FallbackError::Refused(code) => {
                return write!(f, "upstream refused connect (code {code})");
            }
            FallbackError::FieldTooLong => "address or credential field too long to encode",
            FallbackError::NotAvailable => "fallback upstream not available in this build",
        };
        f.write_str(s)
    }
}

impl std::error::Error for FallbackError {}
