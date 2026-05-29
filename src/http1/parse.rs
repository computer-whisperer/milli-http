//! Zero-copy HTTP/1.1 parser.
//!
//! All parsers work on `&[u8]` and return byte-slice references or offsets.

use crate::error::Error;

/// Find the end of the header section (`\r\n\r\n`).
/// Returns the offset *past* the `\r\n\r\n` sequence, or `None` if not found.
pub fn find_end_of_headers(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    for i in 0..buf.len() - 3 {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n' {
            return Some(i + 4);
        }
    }
    None
}

/// Parse a request line: `METHOD SP PATH SP HTTP/1.x CRLF`.
///
/// Returns `(method, path, consumed)` where consumed includes the trailing CRLF.
pub fn parse_request_line(buf: &[u8]) -> Result<(&[u8], &[u8], usize), Error> {
    let line_end = find_crlf(buf).ok_or(Error::WouldBlock)?;
    let line = &buf[..line_end];

    // METHOD SP
    let sp1 = memchr(b' ', line).ok_or(Error::InvalidState)?;
    let method = &line[..sp1];
    if method.is_empty() {
        return Err(Error::InvalidState);
    }

    // PATH SP
    let rest = &line[sp1 + 1..];
    let sp2 = memchr(b' ', rest).ok_or(Error::InvalidState)?;
    let path = &rest[..sp2];
    if path.is_empty() {
        return Err(Error::InvalidState);
    }

    // HTTP/1.x
    let version = &rest[sp2 + 1..];
    if !version.starts_with(b"HTTP/1.") {
        return Err(Error::InvalidState);
    }

    Ok((method, path, line_end + 2)) // +2 for CRLF
}

/// Parse a status line: `HTTP/1.x SP STATUS SP REASON CRLF`.
///
/// Returns `(status_code, reason, consumed)`.
pub fn parse_status_line(buf: &[u8]) -> Result<(u16, &[u8], usize), Error> {
    let line_end = find_crlf(buf).ok_or(Error::WouldBlock)?;
    let line = &buf[..line_end];

    // HTTP/1.x SP
    if !line.starts_with(b"HTTP/1.") {
        return Err(Error::InvalidState);
    }
    let sp1 = memchr(b' ', line).ok_or(Error::InvalidState)?;

    // STATUS SP
    let rest = &line[sp1 + 1..];
    if rest.len() < 3 {
        return Err(Error::InvalidState);
    }
    let status_bytes = &rest[..3];
    let status = parse_decimal_u16(status_bytes).ok_or(Error::InvalidState)?;
    if status < 100 {
        return Err(Error::InvalidState);
    }

    // REASON (may be empty, or preceded by SP)
    let reason = if rest.len() > 3 && rest[3] == b' ' {
        &rest[4..]
    } else {
        b""
    };

    Ok((status, reason, line_end + 2))
}

/// Parse a single header line: `Name: Value CRLF`.
///
/// Returns `(name, value, consumed)`. An empty line (just CRLF) returns consumed=2
/// with empty name and value to signal end of headers.
pub fn parse_header_line(buf: &[u8]) -> Result<(&[u8], &[u8], usize), Error> {
    // Check for empty line (end of headers)
    if buf.len() >= 2 && buf[0] == b'\r' && buf[1] == b'\n' {
        return Ok((b"", b"", 2));
    }

    let line_end = find_crlf(buf).ok_or(Error::WouldBlock)?;
    let line = &buf[..line_end];

    let colon = memchr(b':', line).ok_or(Error::InvalidState)?;
    let name = &line[..colon];
    if name.is_empty() {
        return Err(Error::InvalidState);
    }
    // RFC 9112 §5.1: no whitespace is allowed between the field name and the
    // colon. Field names are tokens and never contain SP/HTAB; accepting
    // "Name : value" creates a request-smuggling differential with intermediaries
    // that trim it.
    if name.iter().any(|&b| b == b' ' || b == b'\t') {
        return Err(Error::InvalidState);
    }

    // Skip optional whitespace after colon
    let value_start = colon + 1;
    let value = trim_ows(&line[value_start..]);

    // RFC 9110 §5.5: field values must not contain control characters other
    // than HTAB — in particular bare CR/LF/NUL, which enable header injection
    // and response splitting when the parsed value is forwarded.
    if value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(Error::InvalidState);
    }

    Ok((name, value, line_end + 2))
}

/// Parse a chunk size line for Transfer-Encoding: chunked.
///
/// Format: `HEX_SIZE [; ext] CRLF`
/// Returns `(chunk_size, consumed)`.
pub fn parse_chunk_size(buf: &[u8]) -> Result<(usize, usize), Error> {
    let line_end = find_crlf(buf).ok_or(Error::WouldBlock)?;
    let line = &buf[..line_end];

    // Find end of hex digits (stop at ';' for chunk extensions)
    let hex_end = line
        .iter()
        .position(|&b| b == b';' || b == b' ')
        .unwrap_or(line.len());

    let hex_str = &line[..hex_end];
    if hex_str.is_empty() {
        return Err(Error::InvalidState);
    }

    let size = parse_hex(hex_str).ok_or(Error::InvalidState)?;
    Ok((size, line_end + 2))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find `\r\n` in buffer. Returns offset of `\r`.
fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Find first occurrence of byte in slice.
fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|&b| b == needle)
}

/// Trim optional whitespace (OWS: SP / HTAB) from both ends.
fn trim_ows(buf: &[u8]) -> &[u8] {
    let start = buf
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(buf.len());
    let end = buf
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map(|i| i + 1)
        .unwrap_or(start);
    &buf[start..end]
}

/// Parse ASCII decimal digits into u16.
fn parse_decimal_u16(buf: &[u8]) -> Option<u16> {
    let mut n: u16 = 0;
    for &b in buf {
        let d = b.wrapping_sub(b'0');
        if d > 9 {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(d as u16)?;
    }
    Some(n)
}

/// Parse hex digits into usize.
fn parse_hex(buf: &[u8]) -> Option<usize> {
    if buf.is_empty() {
        return None;
    }
    let mut n: usize = 0;
    for &b in buf {
        let d = match b {
            b'0'..=b'9' => (b - b'0') as usize,
            b'a'..=b'f' => (b - b'a' + 10) as usize,
            b'A'..=b'F' => (b - b'A' + 10) as usize,
            _ => return None,
        };
        n = n.checked_mul(16)?.checked_add(d)?;
    }
    Some(n)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_end_of_headers_basic() {
        let buf = b"Host: example.com\r\n\r\n";
        assert_eq!(find_end_of_headers(buf), Some(21));
    }

    #[test]
    fn header_line_accepts_normal() {
        let (name, value, _) = parse_header_line(b"Host: example.com\r\n").unwrap();
        assert_eq!(name, b"Host");
        assert_eq!(value, b"example.com");
    }

    #[test]
    fn header_line_rejects_whitespace_before_colon() {
        // RFC 9112 §5.1 request-smuggling differential.
        assert!(parse_header_line(b"Content-Length : 5\r\n").is_err());
        assert!(parse_header_line(b"Content-Length\t: 5\r\n").is_err());
    }

    #[test]
    fn header_line_rejects_control_chars_in_value() {
        // RFC 9110 §5.5: bare CR / LF / NUL in a value -> header injection.
        assert!(parse_header_line(b"X: a\rb\r\n").is_err()); // bare CR
        assert!(parse_header_line(b"X: a\nb\r\n").is_err()); // bare LF
        assert!(parse_header_line(b"X: a\x00b\r\n").is_err()); // NUL
        // HTAB inside a value remains allowed.
        assert!(parse_header_line(b"X: a\tb\r\n").is_ok());
    }

    #[test]
    fn find_end_of_headers_not_found() {
        let buf = b"Host: example.com\r\n";
        assert_eq!(find_end_of_headers(buf), None);
    }

    #[test]
    fn find_end_of_headers_empty() {
        let buf = b"\r\n\r\n";
        assert_eq!(find_end_of_headers(buf), Some(4));
    }

    #[test]
    fn parse_request_line_get() {
        let buf = b"GET / HTTP/1.1\r\n";
        let (method, path, consumed) = parse_request_line(buf).unwrap();
        assert_eq!(method, b"GET");
        assert_eq!(path, b"/");
        assert_eq!(consumed, 16);
    }

    #[test]
    fn parse_request_line_post() {
        let buf = b"POST /api/data HTTP/1.1\r\n";
        let (method, path, consumed) = parse_request_line(buf).unwrap();
        assert_eq!(method, b"POST");
        assert_eq!(path, b"/api/data");
        assert_eq!(consumed, 25);
    }

    #[test]
    fn parse_request_line_incomplete() {
        let buf = b"GET / HTTP/1.1";
        assert_eq!(parse_request_line(buf), Err(Error::WouldBlock));
    }

    #[test]
    fn parse_request_line_bad_version() {
        let buf = b"GET / HTTP/2.0\r\n";
        assert_eq!(parse_request_line(buf), Err(Error::InvalidState));
    }

    #[test]
    fn parse_status_line_200() {
        let buf = b"HTTP/1.1 200 OK\r\n";
        let (status, reason, consumed) = parse_status_line(buf).unwrap();
        assert_eq!(status, 200);
        assert_eq!(reason, b"OK");
        assert_eq!(consumed, 17);
    }

    #[test]
    fn parse_status_line_404() {
        let buf = b"HTTP/1.1 404 Not Found\r\n";
        let (status, reason, consumed) = parse_status_line(buf).unwrap();
        assert_eq!(status, 404);
        assert_eq!(reason, b"Not Found");
        assert_eq!(consumed, 24);
    }

    #[test]
    fn parse_status_line_no_reason() {
        let buf = b"HTTP/1.1 200\r\n";
        let (status, reason, consumed) = parse_status_line(buf).unwrap();
        assert_eq!(status, 200);
        assert_eq!(reason, b"");
        assert_eq!(consumed, 14);
    }

    #[test]
    fn parse_header_line_basic() {
        let buf = b"Host: example.com\r\n";
        let (name, value, consumed) = parse_header_line(buf).unwrap();
        assert_eq!(name, b"Host");
        assert_eq!(value, b"example.com");
        assert_eq!(consumed, 19);
    }

    #[test]
    fn parse_header_line_trimmed() {
        let buf = b"Content-Type:  text/html \r\n";
        let (name, value, consumed) = parse_header_line(buf).unwrap();
        assert_eq!(name, b"Content-Type");
        assert_eq!(value, b"text/html");
        assert_eq!(consumed, 27);
    }

    #[test]
    fn parse_header_line_end_of_headers() {
        let buf = b"\r\nBody here";
        let (name, value, consumed) = parse_header_line(buf).unwrap();
        assert_eq!(name, b"");
        assert_eq!(value, b"");
        assert_eq!(consumed, 2);
    }

    #[test]
    fn parse_chunk_size_basic() {
        let buf = b"1a\r\n";
        let (size, consumed) = parse_chunk_size(buf).unwrap();
        assert_eq!(size, 0x1a);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn parse_chunk_size_zero() {
        let buf = b"0\r\n";
        let (size, consumed) = parse_chunk_size(buf).unwrap();
        assert_eq!(size, 0);
        assert_eq!(consumed, 3);
    }

    #[test]
    fn parse_chunk_size_with_extension() {
        let buf = b"ff;name=value\r\n";
        let (size, consumed) = parse_chunk_size(buf).unwrap();
        assert_eq!(size, 0xff);
        assert_eq!(consumed, 15);
    }

    #[test]
    fn parse_chunk_size_uppercase() {
        let buf = b"FF\r\n";
        let (size, consumed) = parse_chunk_size(buf).unwrap();
        assert_eq!(size, 0xff);
        assert_eq!(consumed, 4);
    }

    #[test]
    fn parse_hex_roundtrip() {
        assert_eq!(parse_hex(b"0"), Some(0));
        assert_eq!(parse_hex(b"a"), Some(10));
        assert_eq!(parse_hex(b"10"), Some(16));
        assert_eq!(parse_hex(b"ff"), Some(255));
        assert_eq!(parse_hex(b"100"), Some(256));
        assert_eq!(parse_hex(b""), None);
        assert_eq!(parse_hex(b"xyz"), None);
    }

    #[test]
    fn trim_ows_cases() {
        assert_eq!(trim_ows(b"  hello  "), b"hello");
        assert_eq!(trim_ows(b"\thello\t"), b"hello");
        assert_eq!(trim_ows(b"hello"), b"hello");
        assert_eq!(trim_ows(b"   "), b"");
        assert_eq!(trim_ows(b""), b"");
    }
}
