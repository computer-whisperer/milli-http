//! Zero-copy HTTP/1.1 parser.
//!
//! All parsers work on `&[u8]` and return byte-slice references or offsets.
//!
//! The parsers avoid slice indexing: every delimiter search goes through an
//! `Option`-returning split, so no bounds-check panic path survives in the
//! generated code. Current stable rustc proves the indices in bounds on its
//! own, but rustc 1.88 (the MSRV) at `opt-level = "z"` does not, and callers
//! that forbid panics in release builds (link-time checks such as `no-panic`)
//! need the parser to be free of them.

use crate::error::Error;

/// Find the end of the header section (`\r\n\r\n`).
/// Returns the offset *past* the `\r\n\r\n` sequence, or `None` if not found.
pub fn find_end_of_headers(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Parse a request line: `METHOD SP PATH SP HTTP/1.x CRLF`.
///
/// Returns `(method, path, consumed)` where consumed includes the trailing CRLF.
pub fn parse_request_line(buf: &[u8]) -> Result<(&[u8], &[u8], usize), Error> {
    let (line, consumed) = split_line(buf).ok_or(Error::WouldBlock)?;

    let (method, rest) = split_once(line, b' ').ok_or(Error::InvalidState)?;
    let (path, version) = split_once(rest, b' ').ok_or(Error::InvalidState)?;
    if method.is_empty() || path.is_empty() || !version.starts_with(b"HTTP/1.") {
        return Err(Error::InvalidState);
    }

    Ok((method, path, consumed))
}

/// Parse a status line: `HTTP/1.x SP STATUS SP REASON CRLF`.
///
/// Returns `(status_code, reason, consumed)`.
pub fn parse_status_line(buf: &[u8]) -> Result<(u16, &[u8], usize), Error> {
    let (line, consumed) = split_line(buf).ok_or(Error::WouldBlock)?;

    if !line.starts_with(b"HTTP/1.") {
        return Err(Error::InvalidState);
    }
    let (_version, rest) = split_once(line, b' ').ok_or(Error::InvalidState)?;

    // Three-digit STATUS, then an optional SP REASON.
    let (status_bytes, rest) = rest.split_at_checked(3).ok_or(Error::InvalidState)?;
    let status = parse_decimal_u16(status_bytes).ok_or(Error::InvalidState)?;
    if status < 100 {
        return Err(Error::InvalidState);
    }
    let reason = rest.strip_prefix(b" ").unwrap_or(b"");

    Ok((status, reason, consumed))
}

/// Parse a single header line: `Name: Value CRLF`.
///
/// Returns `(name, value, consumed)`. An empty line (just CRLF) returns consumed=2
/// with empty name and value to signal end of headers.
pub fn parse_header_line(buf: &[u8]) -> Result<(&[u8], &[u8], usize), Error> {
    // Empty line: end of headers.
    if buf.starts_with(b"\r\n") {
        return Ok((b"", b"", 2));
    }

    let (line, consumed) = split_line(buf).ok_or(Error::WouldBlock)?;
    let (name, value) = split_once(line, b':').ok_or(Error::InvalidState)?;
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

    let value = trim_ows(value);

    // RFC 9110 §5.5: field values must not contain control characters other
    // than HTAB — in particular bare CR/LF/NUL, which enable header injection
    // and response splitting when the parsed value is forwarded.
    if value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(Error::InvalidState);
    }

    Ok((name, value, consumed))
}

/// Parse a chunk size line for Transfer-Encoding: chunked.
///
/// Format: `HEX_SIZE [; ext] CRLF`
/// Returns `(chunk_size, consumed)`.
pub fn parse_chunk_size(buf: &[u8]) -> Result<(usize, usize), Error> {
    let (line, consumed) = split_line(buf).ok_or(Error::WouldBlock)?;

    // Hex digits end at ';' (chunk extension) or SP; `parse_hex` rejects an
    // empty run.
    let hex_str = line
        .split(|&b| b == b';' || b == b' ')
        .next()
        .unwrap_or(b"");
    let size = parse_hex(hex_str).ok_or(Error::InvalidState)?;

    Ok((size, consumed))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Split the first CRLF-terminated line off `buf`.
///
/// Returns `(line, consumed)` where consumed includes the CRLF, or `None` if
/// no CRLF has arrived yet.
fn split_line(buf: &[u8]) -> Option<(&[u8], usize)> {
    let end = buf.windows(2).position(|w| w == b"\r\n")?;
    Some((buf.get(..end)?, end + 2))
}

/// Split `buf` at the first `delim`, dropping the delimiter.
///
/// Returns `(before, after)`, or `None` if `delim` does not occur.
fn split_once(buf: &[u8], delim: u8) -> Option<(&[u8], &[u8])> {
    let at = buf.iter().position(|&b| b == delim)?;
    let (before, rest) = buf.split_at_checked(at)?;
    let (_delim, after) = rest.split_first()?;
    Some((before, after))
}

/// Trim optional whitespace (OWS: SP / HTAB) from both ends.
fn trim_ows(mut buf: &[u8]) -> &[u8] {
    let ows = |b: u8| b == b' ' || b == b'\t';
    while let Some((&b, rest)) = buf.split_first()
        && ows(b)
    {
        buf = rest;
    }
    while let Some((&b, rest)) = buf.split_last()
        && ows(b)
    {
        buf = rest;
    }
    buf
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

    #[test]
    fn find_end_of_headers_shorter_than_terminator() {
        assert_eq!(find_end_of_headers(b""), None);
        assert_eq!(find_end_of_headers(b"\r\n\r"), None);
    }

    #[test]
    fn parse_request_line_missing_parts() {
        assert_eq!(parse_request_line(b"GET\r\n"), Err(Error::InvalidState));
        assert_eq!(parse_request_line(b"GET /\r\n"), Err(Error::InvalidState));
        assert_eq!(
            parse_request_line(b" / HTTP/1.1\r\n"),
            Err(Error::InvalidState)
        );
        assert_eq!(
            parse_request_line(b"GET  HTTP/1.1\r\n"),
            Err(Error::InvalidState)
        );
    }

    #[test]
    fn parse_status_line_short_or_bad_status() {
        assert_eq!(parse_status_line(b"HTTP/1.1\r\n"), Err(Error::InvalidState));
        assert_eq!(
            parse_status_line(b"HTTP/1.1 20\r\n"),
            Err(Error::InvalidState)
        );
        assert_eq!(
            parse_status_line(b"HTTP/1.1 abc\r\n"),
            Err(Error::InvalidState)
        );
        assert_eq!(
            parse_status_line(b"HTTP/1.1 099 Low\r\n"),
            Err(Error::InvalidState)
        );
    }

    #[test]
    fn parse_header_line_missing_name_or_colon() {
        assert_eq!(
            parse_header_line(b"Host example.com\r\n"),
            Err(Error::InvalidState)
        );
        assert_eq!(parse_header_line(b": value\r\n"), Err(Error::InvalidState));
    }

    #[test]
    fn parse_chunk_size_empty_or_bad_hex() {
        assert_eq!(parse_chunk_size(b";ext\r\n"), Err(Error::InvalidState));
        assert_eq!(parse_chunk_size(b"\r\n"), Err(Error::InvalidState));
        assert_eq!(parse_chunk_size(b"zz\r\n"), Err(Error::InvalidState));
        assert_eq!(parse_chunk_size(b"1a"), Err(Error::WouldBlock));
    }
}
