//! Versioned JSON-RPC-style protocol shared by the service, tray and UI.
//!
//! Framing (see ADR 005): newline-delimited UTF-8 JSON over an ACL'd named pipe.
//! The first message each side sends is [`ClientMessage::Hello`] /
//! [`ServerMessage::Hello`] carrying [`PROTOCOL_VERSION`]; on mismatch the
//! service replies with an error and closes the pipe. The UI never runs
//! elevated, so every request is treated as untrusted input by the service.

use serde::{Deserialize, Serialize};

pub mod pipe;

/// Protocol version. Bump on any breaking change to the message shapes below.
pub const PROTOCOL_VERSION: u32 = 1;

/// Named pipe the service listens on.
pub const PIPE_NAME: &str = r"\\.\pipe\unfilter";

/// Connection state the UI shows (mirrors the status ring: idle/scanning/up).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnState {
    /// Engine installed but not bypassing (HAZIR).
    Ready,
    /// Prober is searching for a working strategy (TARANIYOR).
    Scanning,
    /// A working strategy is active (BAĞLI).
    Connected,
    /// Something is wrong (driver/service problem).
    Fault,
}

/// Operating mode toggle on the main screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Normal.
    Normal,
    /// Game mode: prioritises Discord / game UDP latency.
    Game,
}

/// A request from the UI/tray to the service. Each is wrapped in
/// [`ClientMessage`] with a correlation `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Request {
    /// Start bypassing (BAĞLAN).
    Connect,
    /// Stop bypassing (BAĞLANTIYI KES).
    Disconnect,
    /// Re-run the strategy prober.
    Rescan,
    /// Switch operating mode.
    SetMode {
        /// Desired mode.
        mode: Mode,
    },
    /// Check and repair driver/service/network settings (Onar button).
    Repair,
    /// Test a single site and report DNS/TCP/TLS/method steps (Loglar panel).
    TestSite {
        /// Host to test.
        host: String,
    },
    /// Ask for the current status snapshot.
    GetStatus,
}

/// A message from a client to the service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Opening handshake; must be the first message.
    Hello {
        /// The client's protocol version.
        protocol: u32,
    },
    /// A correlated request.
    Request {
        /// Correlation id echoed in the matching [`ServerMessage::Response`].
        id: u64,
        /// The request itself.
        #[serde(flatten)]
        request: Request,
    },
}

/// The status snapshot the UI renders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// Connection state.
    pub state: ConnState,
    /// Active strategy name, if connected.
    pub strategy: Option<String>,
    /// Added latency in microseconds (from the engine histogram).
    pub added_latency_us: u32,
    /// Current mode.
    pub mode: Mode,
}

/// Result of a [`Request::TestSite`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteTest {
    /// Host tested.
    pub host: String,
    /// DNS resolution succeeded.
    pub dns_ok: bool,
    /// TCP connect succeeded.
    pub tcp_ok: bool,
    /// TLS handshake with correct SNI succeeded.
    pub tls_ok: bool,
    /// Detected block type, if blocked.
    pub block: Option<BlockKind>,
    /// Strategy that made it work, if any.
    pub via: Option<String>,
}

/// How a site is being blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockKind {
    /// DNS poisoning / hijack.
    Dns,
    /// DPI on the TLS/HTTP handshake.
    Dpi,
    /// IP-level block (no DPI strategy helps; fallback territory).
    Ip,
}

/// Protocol errors the service can return.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProtocolError {
    /// Client and service disagree on [`PROTOCOL_VERSION`].
    VersionMismatch {
        /// The version the service speaks.
        expected: u32,
    },
    /// The request was malformed or not understood.
    BadRequest,
    /// The service is not ready to serve this request yet.
    NotReady,
}

/// A message from the service to a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Opening handshake reply.
    Hello {
        /// The service's protocol version.
        protocol: u32,
    },
    /// Response to a correlated request.
    Response {
        /// Correlation id from the [`ClientMessage::Request`].
        id: u64,
        /// The payload.
        #[serde(flatten)]
        payload: ResponsePayload,
    },
    /// An unsolicited push (status change, log line); has no id.
    Event {
        /// The event.
        #[serde(flatten)]
        event: Event,
    },
}

/// The body of a [`ServerMessage::Response`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ResponsePayload {
    /// Current status (reply to `GetStatus`/`Connect`/`Disconnect`/`SetMode`).
    Status {
        /// Snapshot.
        status: Status,
    },
    /// Site test result.
    SiteTest {
        /// Result.
        test: SiteTest,
    },
    /// A simple acknowledgement.
    Ok,
    /// An error.
    Error {
        /// The error.
        error: ProtocolError,
    },
}

/// Unsolicited events pushed to clients.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Event {
    /// Status changed.
    Status {
        /// New snapshot.
        status: Status,
    },
    /// A log line for the live log view (time formatted by the service).
    Log {
        /// `HH:MM:SS`.
        time: String,
        /// Host the line is about.
        host: String,
        /// Method / strategy used.
        method: String,
        /// Short outcome, e.g. "OK" or "fallback".
        outcome: String,
    },
}

/// Serialise a message to one newline-terminated JSON frame.
pub fn encode<T: Serialize>(msg: &T) -> serde_json::Result<String> {
    let mut s = serde_json::to_string(msg)?;
    s.push('\n');
    Ok(s)
}

/// Parse one JSON frame (without the trailing newline).
pub fn decode<T: for<'de> Deserialize<'de>>(line: &str) -> serde_json::Result<T> {
    serde_json::from_str(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_roundtrips() {
        let msg = ClientMessage::Hello {
            protocol: PROTOCOL_VERSION,
        };
        let line = encode(&msg).unwrap();
        assert!(line.ends_with('\n'));
        let back: ClientMessage = decode(line.trim_end()).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn request_roundtrips() {
        let msg = ClientMessage::Request {
            id: 42,
            request: Request::TestSite {
                host: "example.com".into(),
            },
        };
        let line = encode(&msg).unwrap();
        let back: ClientMessage = decode(line.trim_end()).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn status_event_roundtrips() {
        let msg = ServerMessage::Event {
            event: Event::Status {
                status: Status {
                    state: ConnState::Connected,
                    strategy: Some("split+fake_badsum".into()),
                    added_latency_us: 350,
                    mode: Mode::Game,
                },
            },
        };
        let line = encode(&msg).unwrap();
        let back: ServerMessage = decode(line.trim_end()).unwrap();
        assert_eq!(msg, back);
    }
}
