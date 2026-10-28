//! HTTP/1.x request parser: recovers the `Host` header from a plain-text
//! request. Only the request line and headers are scanned, up to the blank
//! line; the body is ignored.

use crate::classify::Classification;
use crate::error::{Error, Result};

/// Scan an HTTP/1.x request and set `out.http_host` to the `Host` header value
/// (trimmed), if present. Returns [`Error::Malformed`] if the input does not
/// start with a request line.
pub fn parse_request<'p>(payload: &'p [u8], out: &mut Classification<'p>) -> Result<()> {
    // Must begin with a METHOD and have a request line terminator.
    let line_end = find(payload, b"\r\n").ok_or(Error::Truncated)?;
    let request_line = &payload[..line_end];
    if !is_request_line(request_line) {
        return Err(Error::Malformed);
    }

    let mut rest = &payload[line_end + 2..];
    while let Some(end) = find(rest, b"\r\n") {
        if end == 0 {
            break; // blank line: end of headers
        }
        let line = &rest[..end];
        if let Some(value) = header_value(line, b"host") {
            out.http_host = core::str::from_utf8(value).ok();
            break;
        }
        rest = &rest[end + 2..];
    }
    Ok(())
}

fn is_request_line(line: &[u8]) -> bool {
    const METHODS: [&[u8]; 7] = [
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"CONNECT ",
    ];
    METHODS.iter().any(|m| line.starts_with(m))
}

/// If `line` is `Name: value` with a case-insensitive match on `name`, return
/// the trimmed value bytes.
fn header_value<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let colon = line.iter().position(|&b| b == b':')?;
    let (key, val) = line.split_at(colon);
    if key.len() != name.len() {
        return None;
    }
    if !key.iter().zip(name).all(|(a, b)| a.eq_ignore_ascii_case(b)) {
        return None;
    }
    Some(trim(&val[1..]))
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_host() {
        let req = b"GET /path HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let mut out = Classification::default();
        parse_request(req, &mut out).unwrap();
        assert_eq!(out.http_host, Some("example.com"));
    }

    #[test]
    fn host_is_case_insensitive_and_trimmed() {
        let req = b"POST / HTTP/1.1\r\nhOsT:   blocked.example  \r\n\r\n";
        let mut out = Classification::default();
        parse_request(req, &mut out).unwrap();
        assert_eq!(out.http_host, Some("blocked.example"));
    }

    #[test]
    fn non_request_rejected() {
        let mut out = Classification::default();
        assert_eq!(
            parse_request(b"HTTP/1.1 200 OK\r\n\r\n", &mut out),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn missing_host_is_ok_none() {
        let req = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        let mut out = Classification::default();
        parse_request(req, &mut out).unwrap();
        assert_eq!(out.http_host, None);
    }
}
