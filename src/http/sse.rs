//! Server-Sent Events (SSE) frame formatting.
//!
//! SSE is a plain-text framing for server→client push over an ordinary HTTP
//! response (RFC-less; specified in WHATWG HTML "server-sent events"). A
//! stream is a `200` response with `content-type: text/event-stream`, no
//! content-length, and `end_stream = false`, whose body is a sequence of
//! frames pushed as application events occur — which every protocol path here
//! supports (see the `*_streaming_response` integration tests): HTTP/1.1
//! delimits the stream by connection close, HTTP/2 by END_STREAM, HTTP/3 by
//! stream FIN.
//!
//! This module only formats frames; subscription tracking and delivery policy
//! (e.g. coalescing on backpressure) are application concerns.

use crate::error::Error;

/// Format a single SSE frame into `out`, returning the number of bytes
/// written.
///
/// `event` becomes an `event: <name>` field (browsers dispatch it to
/// `addEventListener(name)`); `None` sends a plain `message` event. `data`
/// may contain newlines — each line is emitted as its own `data:` field, and
/// the client reassembles them with `\n` per the SSE spec, so arbitrary text
/// round-trips. A trailing blank line terminates the frame.
///
/// Returns [`Error::BufferTooSmall`] if the frame does not fit; nothing
/// partial should be sent in that case.
pub fn format_event(event: Option<&str>, data: &str, out: &mut [u8]) -> Result<usize, Error> {
    let mut off = 0;
    if let Some(name) = event {
        put(out, &mut off, b"event: ")?;
        put(out, &mut off, name.as_bytes())?;
        put(out, &mut off, b"\n")?;
    }
    for line in data.split('\n') {
        put(out, &mut off, b"data: ")?;
        put(out, &mut off, line.as_bytes())?;
        put(out, &mut off, b"\n")?;
    }
    put(out, &mut off, b"\n")?;
    Ok(off)
}

/// Format a `retry: <ms>` frame, instructing the client how long to wait
/// before reconnecting after the stream drops.
pub fn format_retry(retry_ms: u32, out: &mut [u8]) -> Result<usize, Error> {
    let mut off = 0;
    put(out, &mut off, b"retry: ")?;
    let mut digits = [0u8; 10];
    let mut n = retry_ms;
    let mut pos = digits.len();
    loop {
        pos -= 1;
        digits[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    put(out, &mut off, &digits[pos..])?;
    put(out, &mut off, b"\n\n")?;
    Ok(off)
}

fn put(out: &mut [u8], off: &mut usize, bytes: &[u8]) -> Result<(), Error> {
    let end = *off + bytes.len();
    if end > out.len() {
        return Err(Error::BufferTooSmall { needed: end });
    }
    out[*off..end].copy_from_slice(bytes);
    *off = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_event() {
        let mut buf = [0u8; 64];
        let n = format_event(Some("volume"), "0.5", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"event: volume\ndata: 0.5\n\n");
    }

    #[test]
    fn unnamed_event() {
        let mut buf = [0u8; 64];
        let n = format_event(None, "hello", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"data: hello\n\n");
    }

    #[test]
    fn multiline_data_splits_into_data_fields() {
        let mut buf = [0u8; 64];
        let n = format_event(None, "a\nb", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"data: a\ndata: b\n\n");
    }

    #[test]
    fn empty_data_still_emits_field() {
        let mut buf = [0u8; 64];
        let n = format_event(Some("ping"), "", &mut buf).unwrap();
        assert_eq!(&buf[..n], b"event: ping\ndata: \n\n");
    }

    #[test]
    fn buffer_too_small_is_clean_error() {
        let mut buf = [0u8; 8];
        assert!(matches!(
            format_event(Some("volume"), "0.5", &mut buf),
            Err(Error::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn retry_frame() {
        let mut buf = [0u8; 32];
        let n = format_retry(3000, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"retry: 3000\n\n");
        let n = format_retry(0, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"retry: 0\n\n");
    }
}
