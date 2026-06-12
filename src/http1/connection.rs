//! HTTP/1.1 connection state machine.
//!
//! Pure codec following the milli-http pattern:
//! `feed_data()` → `poll_output()` → `poll_event()`
//!
//! # Buffer lifecycle
//!
//! The connection will not begin parsing the next request/response until the
//! application has consumed the current headers (via `recv_headers`) and body
//! data (via `recv_body`). This prevents data from one message leaking into
//! the next on keep-alive connections.
//!
//! # I/O buffers
//!
//! I/O buffers are **not** owned by this struct; callers provide them via
//! [`Http1Io`] on every method that touches network data.

use super::io::Http1Io;
use super::parse;
use crate::buf::Buf;
use crate::error::Error;

/// Events produced by the HTTP/1.1 connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http1Event {
    /// Connection ready. Emitted as the first event for API consistency with H2/H3.
    Connected,
    /// Headers received (request headers on server-side, response headers on client-side).
    /// The `u64` is a pseudo-stream-id for API consistency with H2/H3.
    Headers(u64),
    /// Body data available.
    Data(u64),
    /// Request/response complete.
    Finished(u64),
    /// A timeout fired (idle or header timeout).
    Timeout,
}

/// Connection role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Parse state for incoming messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    /// Waiting for a request line (server) or status line (client).
    Idle,
    /// Reading body with known Content-Length.
    BodyContentLength { remaining: usize },
    /// Reading chunked transfer encoding.
    BodyChunked,
    /// Reading body until connection close (response only).
    BodyUntilClose,
    /// Current message is done; waiting for app to drain buffers before
    /// accepting the next message (keep-alive).
    Done,
}

/// Chunk decoding sub-state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkState {
    /// Expecting a chunk-size line.
    Size,
    /// Reading chunk data bytes.
    Data { remaining: usize },
    /// Expecting CRLF after chunk data.
    DataTrailer,
    /// Final chunk received; expecting optional trailers + final CRLF.
    Trailers,
}

/// HTTP/1.1 connection state machine.
///
/// I/O buffers are **not** owned by this struct; callers provide them via
/// [`Http1Io`] on every method that touches network data.
///
/// Generic parameters:
/// - `HDRBUF`: header storage buffer size
/// - `DATABUF`: body data buffer size
pub struct Http1Connection<const HDRBUF: usize = 2048, const DATABUF: usize = 4096> {
    role: Role,
    state: ParseState,
    send_offset: usize,
    /// Parsed headers stored as `name\0value\0` pairs.
    header_buf: Buf<HDRBUF>,
    headers_available: bool,
    /// Buffered body data for the application to read.
    data_buf: Buf<DATABUF>,
    events: heapless::Deque<Http1Event, 32>,
    /// Pseudo-stream-id (increments per request).
    current_stream_id: u64,
    /// Chunked decoding sub-state.
    chunk_state: ChunkState,
    /// Whether the current message uses keep-alive.
    keep_alive: bool,
    /// Whether end-of-stream has been signalled for the current message.
    body_finished: bool,
    /// Whether the Connected event has been emitted.
    connected_emitted: bool,
    // Timeout support
    timeout_config: crate::http::TimeoutConfig,
    last_activity: u64,
    connection_start: u64,
    headers_phase_complete: bool,
    closed: bool,
}

impl<const HDRBUF: usize, const DATABUF: usize> Http1Connection<HDRBUF, DATABUF> {
    /// Create a new client-side HTTP/1.1 connection.
    pub fn new_client() -> Self {
        Self::new(Role::Client)
    }

    /// Create a new server-side HTTP/1.1 connection.
    pub fn new_server() -> Self {
        Self::new(Role::Server)
    }

    fn new(role: Role) -> Self {
        Self {
            role,
            state: ParseState::Idle,
            send_offset: 0,
            header_buf: Buf::new(),
            headers_available: false,
            data_buf: Buf::new(),
            events: heapless::Deque::new(),
            current_stream_id: 0,
            chunk_state: ChunkState::Size,
            keep_alive: true,
            body_finished: false,
            connected_emitted: false,
            timeout_config: crate::http::TimeoutConfig::default(),
            last_activity: 0,
            connection_start: 0,
            headers_phase_complete: false,
            closed: false,
        }
    }

    /// Feed received TCP data into the connection.
    pub fn feed_data<const BUF: usize>(
        &mut self,
        io: &mut Http1Io<'_, BUF>,
        data: &[u8],
    ) -> Result<(), Error> {
        if io.recv_buf.len() + data.len() > BUF {
            return Err(Error::BufferTooSmall {
                needed: io.recv_buf.len() + data.len(),
            });
        }
        let _ = io.recv_buf.extend_from_slice(data);
        self.process_recv(io)
    }

    /// Pull the next chunk of outgoing data.
    pub fn poll_output<'a, const BUF: usize>(
        &mut self,
        io: &mut Http1Io<'_, BUF>,
        buf: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        if self.send_offset >= io.send_buf.len() {
            return None;
        }
        let avail = io.send_buf.len() - self.send_offset;
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&io.send_buf[self.send_offset..self.send_offset + n]);
        self.send_offset += n;
        if self.send_offset >= io.send_buf.len() {
            io.send_buf.clear();
            self.send_offset = 0;
        }
        Some(&buf[..n])
    }

    /// Poll for the next event.
    pub fn poll_event(&mut self) -> Option<Http1Event> {
        if !self.connected_emitted {
            self.connected_emitted = true;
            return Some(Http1Event::Connected);
        }
        self.events.pop_front()
    }

    // ------------------------------------------------------------------
    // Application API
    // ------------------------------------------------------------------

    /// Send headers (request line + headers for client, status line + headers for server).
    ///
    /// Headers should include pseudo-headers (`:method`, `:path`, `:status`) which
    /// will be used to construct the request/status line.
    pub fn send_headers<const BUF: usize>(
        &mut self,
        io: &mut Http1Io<'_, BUF>,
        stream_id: u64,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error> {
        self.check_stream_id(stream_id)?;
        match self.role {
            Role::Client => self.encode_request(io, headers, end_stream),
            Role::Server => self.encode_response(io, headers, end_stream),
        }
    }

    /// Send body data.
    pub fn send_data<const BUF: usize>(
        &mut self,
        io: &mut Http1Io<'_, BUF>,
        stream_id: u64,
        data: &[u8],
        _end_stream: bool,
    ) -> Result<usize, Error> {
        self.check_stream_id(stream_id)?;
        io.queue_send(data)?;
        Ok(data.len())
    }

    /// Read received headers via callback.
    ///
    /// Iterates stored headers as `name\0value\0` pairs, calling `emit(name, value)`.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        mut emit: F,
    ) -> Result<(), Error> {
        self.check_stream_id(stream_id)?;
        if !self.headers_available {
            return Err(Error::WouldBlock);
        }

        let buf = &self.header_buf;
        let mut pos = 0;
        while pos < buf.len() {
            // Find name end (first \0)
            let name_end = buf[pos..]
                .iter()
                .position(|&b| b == 0)
                .map(|i| pos + i)
                .unwrap_or(buf.len());
            if name_end >= buf.len() {
                break;
            }
            let name = &buf[pos..name_end];

            // Find value end (second \0)
            let value_start = name_end + 1;
            let value_end = buf[value_start..]
                .iter()
                .position(|&b| b == 0)
                .map(|i| value_start + i)
                .unwrap_or(buf.len());
            let value = &buf[value_start..value_end];

            emit(name, value);
            pos = value_end + 1;
        }

        self.header_buf.clear();
        self.headers_available = false;
        Ok(())
    }

    /// Read received body data.
    pub fn recv_body(&mut self, stream_id: u64, buf: &mut [u8]) -> Result<(usize, bool), Error> {
        self.check_stream_id(stream_id)?;
        if self.data_buf.is_empty() {
            if self.body_finished {
                return Ok((0, true));
            }
            return Err(Error::WouldBlock);
        }

        let copy_len = self.data_buf.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&self.data_buf[..copy_len]);

        // Shift remaining data
        self.data_buf.copy_within(copy_len.., 0);
        self.data_buf.truncate(self.data_buf.len() - copy_len);

        let fin = self.data_buf.is_empty() && self.body_finished;
        Ok((copy_len, fin))
    }

    /// Open a new stream (client-side: encode request).
    pub fn open_stream<const BUF: usize>(
        &mut self,
        io: &mut Http1Io<'_, BUF>,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<u64, Error> {
        self.current_stream_id += 1;
        let sid = self.current_stream_id;
        self.send_headers(io, sid, headers, end_stream)?;
        Ok(sid)
    }

    // ------------------------------------------------------------------
    // Timeout + connection state API
    // ------------------------------------------------------------------

    /// Configure timeouts. `now` is the current timestamp in microseconds.
    pub fn set_timeouts(&mut self, config: crate::http::TimeoutConfig, now: u64) {
        self.timeout_config = config;
        self.last_activity = now;
        self.connection_start = now;
    }

    /// Return the earliest deadline (in µs) at which `handle_timeout` should be called,
    /// or `None` if no timeouts are configured.
    pub fn next_timeout(&self) -> Option<u64> {
        if self.closed {
            return None;
        }
        let mut earliest: Option<u64> = None;

        if !self.headers_phase_complete {
            if let Some(hdr_us) = self.timeout_config.header_timeout_us {
                let deadline = self.connection_start.saturating_add(hdr_us);
                earliest = Some(earliest.map_or(deadline, |e: u64| e.min(deadline)));
            }
        }

        if let Some(idle_us) = self.timeout_config.idle_timeout_us {
            let deadline = self.last_activity.saturating_add(idle_us);
            earliest = Some(earliest.map_or(deadline, |e: u64| e.min(deadline)));
        }

        earliest
    }

    /// Check timeouts. If a timeout fires, sets `closed = true` and emits
    /// `Http1Event::Timeout`.
    pub fn handle_timeout(&mut self, now: u64) {
        if self.closed {
            return;
        }

        // Header timeout: fires if headers phase not complete
        if !self.headers_phase_complete {
            if let Some(hdr_us) = self.timeout_config.header_timeout_us {
                if now >= self.connection_start.saturating_add(hdr_us) {
                    self.closed = true;
                    let _ = self.events.push_back(Http1Event::Timeout);
                    return;
                }
            }
        }

        // Idle timeout
        if let Some(idle_us) = self.timeout_config.idle_timeout_us {
            if now >= self.last_activity.saturating_add(idle_us) {
                self.closed = true;
                let _ = self.events.push_back(Http1Event::Timeout);
            }
        }
    }

    /// Feed data with timestamp tracking. Updates `last_activity` then calls `feed_data`.
    pub fn feed_data_timed<const BUF: usize>(
        &mut self,
        io: &mut Http1Io<'_, BUF>,
        data: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        // Only non-empty feeds count as activity (matches H2Connection):
        // empty re-drive feeds must not refresh the idle clock.
        if !data.is_empty() {
            self.last_activity = now;
        }
        self.feed_data(io, data)
    }

    /// Whether the connection has been closed (by timeout or other means).
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Whether the connection is usable (not closed).
    pub fn is_established(&self) -> bool {
        !self.closed
    }

    // ------------------------------------------------------------------
    // Internal: validation
    // ------------------------------------------------------------------

    /// Validate that the stream_id matches the current active stream.
    fn check_stream_id(&self, stream_id: u64) -> Result<(), Error> {
        if stream_id != self.current_stream_id {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal: encoding
    // ------------------------------------------------------------------

    fn encode_request<const BUF: usize>(
        &mut self,
        io: &mut Http1Io<'_, BUF>,
        headers: &[(&[u8], &[u8])],
        _end_stream: bool,
    ) -> Result<(), Error> {
        let mut method: &[u8] = b"GET";
        let mut path: &[u8] = b"/";
        let mut host: &[u8] = b"";

        // Collect pseudo-headers and regular headers
        for &(name, value) in headers {
            match name {
                b":method" => method = value,
                b":path" => path = value,
                b":authority" => host = value,
                _ => {}
            }
        }

        // Request line: METHOD PATH HTTP/1.1\r\n
        io.queue_send(method)?;
        io.queue_send(b" ")?;
        io.queue_send(path)?;
        io.queue_send(b" HTTP/1.1\r\n")?;

        // Host header
        if !host.is_empty() {
            io.queue_send(b"Host: ")?;
            io.queue_send(host)?;
            io.queue_send(b"\r\n")?;
        }

        // Regular headers
        for &(name, value) in headers {
            if name.starts_with(b":") {
                continue; // Skip pseudo-headers
            }
            io.queue_send(name)?;
            io.queue_send(b": ")?;
            io.queue_send(value)?;
            io.queue_send(b"\r\n")?;
        }

        // End of headers
        io.queue_send(b"\r\n")?;

        Ok(())
    }

    fn encode_response<const BUF: usize>(
        &mut self,
        io: &mut Http1Io<'_, BUF>,
        headers: &[(&[u8], &[u8])],
        _end_stream: bool,
    ) -> Result<(), Error> {
        let mut status: &[u8] = b"200";

        for &(name, value) in headers {
            if name == b":status" {
                status = value;
            }
        }

        let reason = status_reason(status);

        // Status line: HTTP/1.1 STATUS REASON\r\n
        io.queue_send(b"HTTP/1.1 ")?;
        io.queue_send(status)?;
        io.queue_send(b" ")?;
        io.queue_send(reason)?;
        io.queue_send(b"\r\n")?;

        // Regular headers
        for &(name, value) in headers {
            if name.starts_with(b":") {
                continue;
            }
            io.queue_send(name)?;
            io.queue_send(b": ")?;
            io.queue_send(value)?;
            io.queue_send(b"\r\n")?;
        }

        // End of headers
        io.queue_send(b"\r\n")?;

        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal: receive processing
    // ------------------------------------------------------------------

    fn process_recv<const BUF: usize>(&mut self, io: &mut Http1Io<'_, BUF>) -> Result<(), Error> {
        loop {
            match self.state {
                ParseState::Idle => {
                    if !self.try_parse_start_line(io)? {
                        return Ok(());
                    }
                }
                ParseState::BodyContentLength { remaining } => {
                    if !self.process_content_length_body(io, remaining)? {
                        return Ok(());
                    }
                }
                ParseState::BodyChunked => {
                    if !self.process_chunked_body(io)? {
                        return Ok(());
                    }
                }
                ParseState::BodyUntilClose => {
                    self.process_until_close_body(io);
                    return Ok(());
                }
                ParseState::Done => {
                    // Only transition to Idle once the app has consumed headers
                    // and body data. This prevents data from one message leaking
                    // into the next on keep-alive connections.
                    if self.headers_available || !self.data_buf.is_empty() {
                        return Ok(());
                    }
                    self.body_finished = false;
                    self.chunk_state = ChunkState::Size;
                    // Reset header phase for the next keep-alive request
                    self.headers_phase_complete = false;
                    self.connection_start = self.last_activity;
                    self.state = ParseState::Idle;
                }
            }
        }
    }

    /// Try to parse a request line (server) or status line (client) + headers.
    /// Returns true if we transitioned out of Idle.
    ///
    /// Now that `recv_buf` is external (on `io`), we can parse directly from
    /// `io.recv_buf` while writing to `self.header_buf` — no stack copy needed.
    fn try_parse_start_line<const BUF: usize>(
        &mut self,
        io: &mut Http1Io<'_, BUF>,
    ) -> Result<bool, Error> {
        // Need at least the full headers block
        let end = match parse::find_end_of_headers(&io.recv_buf) {
            Some(e) => e,
            None => return Ok(false),
        };

        self.header_buf.clear();
        self.headers_available = false;

        let mut offset = 0;

        if self.role == Role::Server {
            let (method, path, consumed) = parse::parse_request_line(&io.recv_buf[offset..end])?;
            self.store_header(method, path)?;
            offset += consumed;
        } else {
            let (status, _reason, consumed) = parse::parse_status_line(&io.recv_buf[offset..end])?;
            let status_bytes = crate::http::StatusCode(status).to_bytes();
            self.store_header_kv(b":status", &status_bytes)?;
            offset += consumed;
        }

        // Parse headers
        let mut content_length: Option<usize> = None;
        let mut chunked = false;
        let mut connection_close = false;

        loop {
            let (name, value, consumed) = parse::parse_header_line(&io.recv_buf[offset..end])?;
            offset += consumed;

            if name.is_empty() {
                break; // End of headers
            }

            // Reject null bytes in header names and values (RFC 9110 forbids them,
            // and they would corrupt our \0-separated header_buf storage).
            if name.contains(&0) || value.contains(&0) {
                return Err(Error::InvalidState);
            }

            // Check for transfer-encoding and content-length (case-insensitive)
            if eq_ignore_case(name, b"content-length") {
                content_length = parse_usize_ascii(value);
            } else if eq_ignore_case(name, b"transfer-encoding") {
                if contains_ignore_case(value, b"chunked") {
                    chunked = true;
                }
            } else if eq_ignore_case(name, b"connection") && contains_ignore_case(value, b"close") {
                connection_close = true;
            }

            self.store_header_kv(name, value)?;
        }

        // RFC 9112 §6.1: reject messages with both Content-Length and
        // Transfer-Encoding to prevent request smuggling.
        if chunked && content_length.is_some() {
            return Err(Error::InvalidState);
        }

        // Consume parsed bytes from recv_buf
        io.drain_recv(end);

        self.headers_available = true;
        self.keep_alive = !connection_close;

        // Determine body framing
        if chunked {
            self.state = ParseState::BodyChunked;
            self.chunk_state = ChunkState::Size;
        } else if let Some(len) = content_length {
            if len == 0 {
                self.state = ParseState::Done;
                self.body_finished = true;
            } else {
                self.state = ParseState::BodyContentLength { remaining: len };
            }
        } else if self.role == Role::Server {
            // Requests without Content-Length or Transfer-Encoding have no body
            self.state = ParseState::Done;
            self.body_finished = true;
        } else {
            // Responses without either might read until close
            self.state = ParseState::BodyUntilClose;
        }

        // Emit events
        self.headers_phase_complete = true;
        if self.role == Role::Server {
            self.current_stream_id += 1;
            let sid = self.current_stream_id;
            let _ = self.events.push_back(Http1Event::Headers(sid));
        } else {
            let sid = self.current_stream_id;
            let _ = self.events.push_back(Http1Event::Headers(sid));
        }

        if self.body_finished {
            let sid = self.current_stream_id;
            let _ = self.events.push_back(Http1Event::Finished(sid));
        }

        Ok(true)
    }

    fn process_content_length_body<const BUF: usize>(
        &mut self,
        io: &mut Http1Io<'_, BUF>,
        remaining: usize,
    ) -> Result<bool, Error> {
        if io.recv_buf.is_empty() {
            return Ok(false);
        }

        let to_consume = io.recv_buf.len().min(remaining);
        let can_store = (DATABUF - self.data_buf.len()).min(to_consume);

        if can_store > 0 {
            let _ = self.data_buf.extend_from_slice(&io.recv_buf[..can_store]);
            io.drain_recv(can_store);
            let new_remaining = remaining - can_store;

            let sid = self.current_stream_id;
            let _ = self.events.push_back(Http1Event::Data(sid));

            if new_remaining == 0 {
                self.body_finished = true;
                self.state = ParseState::Done;
                let _ = self.events.push_back(Http1Event::Finished(sid));
            } else {
                self.state = ParseState::BodyContentLength {
                    remaining: new_remaining,
                };
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn process_chunked_body<const BUF: usize>(
        &mut self,
        io: &mut Http1Io<'_, BUF>,
    ) -> Result<bool, Error> {
        match self.chunk_state {
            ChunkState::Size => {
                let result = parse::parse_chunk_size(&io.recv_buf);
                match result {
                    Ok((size, consumed)) => {
                        io.drain_recv(consumed);
                        if size == 0 {
                            self.chunk_state = ChunkState::Trailers;
                        } else {
                            self.chunk_state = ChunkState::Data { remaining: size };
                        }
                        Ok(true)
                    }
                    Err(Error::WouldBlock) => Ok(false),
                    Err(e) => Err(e),
                }
            }
            ChunkState::Data { remaining } => {
                if io.recv_buf.is_empty() {
                    return Ok(false);
                }
                let to_consume = io.recv_buf.len().min(remaining);
                let can_store = (DATABUF - self.data_buf.len()).min(to_consume);

                if can_store > 0 {
                    let _ = self.data_buf.extend_from_slice(&io.recv_buf[..can_store]);
                    io.drain_recv(can_store);
                    let new_remaining = remaining - can_store;

                    let sid = self.current_stream_id;
                    let _ = self.events.push_back(Http1Event::Data(sid));

                    if new_remaining == 0 {
                        self.chunk_state = ChunkState::DataTrailer;
                    } else {
                        self.chunk_state = ChunkState::Data {
                            remaining: new_remaining,
                        };
                    }
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            ChunkState::DataTrailer => {
                // Expecting CRLF after chunk data
                if io.recv_buf.len() < 2 {
                    return Ok(false);
                }
                if io.recv_buf[0] == b'\r' && io.recv_buf[1] == b'\n' {
                    io.drain_recv(2);
                    self.chunk_state = ChunkState::Size;
                    Ok(true)
                } else {
                    Err(Error::InvalidState)
                }
            }
            ChunkState::Trailers => {
                // After last chunk (size=0), expect CRLF (no trailers supported)
                if io.recv_buf.len() < 2 {
                    return Ok(false);
                }
                if io.recv_buf[0] == b'\r' && io.recv_buf[1] == b'\n' {
                    io.drain_recv(2);
                    self.body_finished = true;
                    self.state = ParseState::Done;
                    let sid = self.current_stream_id;
                    let _ = self.events.push_back(Http1Event::Finished(sid));
                    Ok(true)
                } else {
                    // Skip trailer headers
                    let (_, _, consumed) = parse::parse_header_line(&io.recv_buf)?;
                    io.drain_recv(consumed);
                    Ok(true)
                }
            }
        }
    }

    fn process_until_close_body<const BUF: usize>(&mut self, io: &mut Http1Io<'_, BUF>) {
        if !io.recv_buf.is_empty() {
            let n = io.recv_buf.len().min(DATABUF - self.data_buf.len());
            if n > 0 {
                let _ = self.data_buf.extend_from_slice(&io.recv_buf[..n]);
                io.drain_recv(n);
                let sid = self.current_stream_id;
                let _ = self.events.push_back(Http1Event::Data(sid));
            }
        }
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Store a request-line pair (:method + :path) into header_buf.
    fn store_header(&mut self, method: &[u8], path: &[u8]) -> Result<(), Error> {
        self.store_header_kv(b":method", method)?;
        self.store_header_kv(b":path", path)?;
        Ok(())
    }

    fn store_header_kv(&mut self, name: &[u8], value: &[u8]) -> Result<(), Error> {
        let needed = name.len() + 1 + value.len() + 1; // name\0value\0
        if self.header_buf.len() + needed > HDRBUF {
            return Err(Error::BufferTooSmall { needed });
        }
        let _ = self.header_buf.extend_from_slice(name);
        let _ = self.header_buf.push(0);
        let _ = self.header_buf.extend_from_slice(value);
        let _ = self.header_buf.push(0);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Case-insensitive comparison of ASCII bytes.
fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .all(|(&x, &y)| x.eq_ignore_ascii_case(&y))
}

/// Check if `haystack` contains `needle` (case-insensitive, for header values).
fn contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    for i in 0..=(haystack.len() - needle.len()) {
        if eq_ignore_case(&haystack[i..i + needle.len()], needle) {
            return true;
        }
    }
    false
}

/// Parse ASCII decimal bytes to usize.
fn parse_usize_ascii(buf: &[u8]) -> Option<usize> {
    let mut n: usize = 0;
    if buf.is_empty() {
        return None;
    }
    for &b in buf {
        let d = b.wrapping_sub(b'0');
        if d > 9 {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(d as usize)?;
    }
    Some(n)
}

/// Map status code to reason phrase.
fn status_reason(status: &[u8]) -> &'static [u8] {
    match status {
        b"100" => b"Continue",
        b"101" => b"Switching Protocols",
        b"200" => b"OK",
        b"201" => b"Created",
        b"204" => b"No Content",
        b"301" => b"Moved Permanently",
        b"302" => b"Found",
        b"304" => b"Not Modified",
        b"307" => b"Temporary Redirect",
        b"308" => b"Permanent Redirect",
        b"400" => b"Bad Request",
        b"401" => b"Unauthorized",
        b"403" => b"Forbidden",
        b"404" => b"Not Found",
        b"405" => b"Method Not Allowed",
        b"408" => b"Request Timeout",
        b"413" => b"Payload Too Large",
        b"429" => b"Too Many Requests",
        b"500" => b"Internal Server Error",
        b"502" => b"Bad Gateway",
        b"503" => b"Service Unavailable",
        _ => b"",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::io::Http1IoBufs;
    use super::*;

    #[test]
    fn server_parses_get_request() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        conn.feed_data(
            &mut io.as_io(),
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        let event = conn.poll_event().unwrap();
        assert_eq!(event, Http1Event::Headers(1));

        let event2 = conn.poll_event().unwrap();
        assert_eq!(event2, Http1Event::Finished(1));

        let mut method = heapless::Vec::<u8, 16>::new();
        let mut path = heapless::Vec::<u8, 64>::new();
        let mut host = heapless::Vec::<u8, 64>::new();
        conn.recv_headers(1, |name, value| match name {
            b":method" => {
                let _ = method.extend_from_slice(value);
            }
            b":path" => {
                let _ = path.extend_from_slice(value);
            }
            b"Host" => {
                let _ = host.extend_from_slice(value);
            }
            _ => {}
        })
        .unwrap();
        assert_eq!(method.as_slice(), b"GET");
        assert_eq!(path.as_slice(), b"/");
        assert_eq!(host.as_slice(), b"example.com");
    }

    #[test]
    fn server_parses_post_with_body() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        conn.feed_data(
            &mut io.as_io(),
            b"POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Data(1));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Finished(1));

        let mut buf = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert!(fin);
    }

    #[test]
    fn server_parses_chunked_body() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        conn.feed_data(
            &mut io.as_io(),
            b"POST /data HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n\
              5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        )
        .unwrap();

        let mut events = heapless::Vec::<Http1Event, 16>::new();
        while let Some(ev) = conn.poll_event() {
            let _ = events.push(ev);
        }
        assert!(events.contains(&Http1Event::Headers(1)));
        assert!(events.contains(&Http1Event::Finished(1)));

        let mut buf = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello world");
        assert!(fin);
    }

    #[test]
    fn client_parses_response() {
        let mut conn = Http1Connection::<1024, 1024>::new_client();
        let mut io = Http1IoBufs::<4096>::new();
        conn.current_stream_id = 1;
        conn.feed_data(
            &mut io.as_io(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));

        let mut status = heapless::Vec::<u8, 16>::new();
        conn.recv_headers(1, |name, value| {
            if name == b":status" {
                let _ = status.extend_from_slice(value);
            }
        })
        .unwrap();
        assert_eq!(status.as_slice(), b"200");

        assert_eq!(conn.poll_event().unwrap(), Http1Event::Data(1));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Finished(1));

        let mut buf = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert!(fin);
    }

    #[test]
    fn server_sends_response() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        conn.current_stream_id = 1;

        conn.send_headers(
            &mut io.as_io(),
            1,
            &[
                (b":status", b"200"),
                (b"content-type", b"text/plain"),
                (b"content-length", b"5"),
            ],
            false,
        )
        .unwrap();

        conn.send_data(&mut io.as_io(), 1, b"hello", true).unwrap();

        let mut out = [0u8; 4096];
        let data = conn.poll_output(&mut io.as_io(), &mut out).unwrap();

        let expected =
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello";
        assert_eq!(data, expected);
    }

    #[test]
    fn client_sends_request() {
        let mut conn = Http1Connection::<1024, 1024>::new_client();
        let mut io = Http1IoBufs::<4096>::new();

        let sid = conn
            .open_stream(
                &mut io.as_io(),
                &[
                    (b":method", b"GET"),
                    (b":path", b"/index.html"),
                    (b":authority", b"example.com"),
                ],
                true,
            )
            .unwrap();
        assert_eq!(sid, 1);

        let mut out = [0u8; 4096];
        let data = conn.poll_output(&mut io.as_io(), &mut out).unwrap();

        let expected = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(data, expected);
    }

    #[test]
    fn incremental_feed() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();

        conn.feed_data(&mut io.as_io(), b"GET / HTTP/1.1\r\n")
            .unwrap();
        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert!(conn.poll_event().is_none());

        conn.feed_data(&mut io.as_io(), b"Host: example.com\r\n")
            .unwrap();
        assert!(conn.poll_event().is_none());

        conn.feed_data(&mut io.as_io(), b"\r\n").unwrap();
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));
    }

    #[test]
    fn keep_alive_multiple_requests() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();

        conn.feed_data(
            &mut io.as_io(),
            b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();
        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));
        while conn.poll_event().is_some() {}
        conn.recv_headers(1, |_, _| {}).unwrap();

        conn.feed_data(
            &mut io.as_io(),
            b"GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(2));
    }

    #[test]
    fn keep_alive_post_then_get() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();

        conn.feed_data(
            &mut io.as_io(),
            b"POST /a HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\nabc",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));
        while conn.poll_event().is_some() {}
        conn.recv_headers(1, |_, _| {}).unwrap();
        let mut buf = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"abc");
        assert!(fin);

        conn.feed_data(
            &mut io.as_io(),
            b"GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(2));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Finished(2));
    }

    #[test]
    fn keep_alive_blocks_until_headers_consumed() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();

        conn.feed_data(
            &mut io.as_io(),
            b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n\
              GET /b HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Finished(1));
        assert!(conn.poll_event().is_none());

        conn.recv_headers(1, |_, _| {}).unwrap();
        conn.feed_data(&mut io.as_io(), b"").unwrap();
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(2));
    }

    #[test]
    fn stream_id_validation() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        conn.feed_data(
            &mut io.as_io(),
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();
        while conn.poll_event().is_some() {}

        assert_eq!(conn.recv_headers(99, |_, _| {}), Err(Error::InvalidState));
        assert!(conn.recv_headers(1, |_, _| {}).is_ok());
    }

    #[test]
    fn reject_content_length_and_transfer_encoding() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        let result = conn.feed_data(
            &mut io.as_io(),
            b"POST /data HTTP/1.1\r\nHost: example.com\r\n\
              Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        assert_eq!(result, Err(Error::InvalidState));
    }

    #[test]
    fn reject_null_byte_in_header_value() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        let data = b"GET / HTTP/1.1\r\nHost: exam\x00ple.com\r\n\r\n".to_vec();
        let result = conn.feed_data(&mut io.as_io(), &data);
        assert_eq!(result, Err(Error::InvalidState));
    }

    #[test]
    fn content_length_zero() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        conn.feed_data(
            &mut io.as_io(),
            b"POST /data HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Finished(1));
        assert!(conn.poll_event().is_none());
    }

    #[test]
    fn feed_data_buffer_overflow() {
        let mut conn = Http1Connection::<64, 64>::new_server();
        let mut io = Http1IoBufs::<64>::new();
        let big = [b'X'; 100];
        let result = conn.feed_data(&mut io.as_io(), &big);
        assert_eq!(result, Err(Error::BufferTooSmall { needed: 100 }));
    }

    #[test]
    fn header_buf_overflow() {
        let mut conn = Http1Connection::<32, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        let result = conn.feed_data(
            &mut io.as_io(),
            b"GET /very-long-path-that-will-overflow HTTP/1.1\r\n\
              Host: example.com\r\n\r\n",
        );
        assert_eq!(result, Err(Error::BufferTooSmall { needed: 41 }));
    }

    #[test]
    fn data_buf_backpressure() {
        let mut conn = Http1Connection::<1024, 8>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        conn.feed_data(
            &mut io.as_io(),
            b"POST /data HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n\r\nhello world!",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Data(1));
        assert!(conn.poll_event().is_none());

        let mut buf = [0u8; 16];
        let (n, fin) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(n, 8);
        assert!(!fin);

        conn.feed_data(&mut io.as_io(), b"").unwrap();
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Data(1));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Finished(1));

        let (n2, fin2) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(n2, 4);
        assert!(fin2);
    }

    #[test]
    fn client_body_until_close() {
        let mut conn = Http1Connection::<1024, 1024>::new_client();
        let mut io = Http1IoBufs::<4096>::new();
        conn.current_stream_id = 1;

        conn.feed_data(&mut io.as_io(), b"HTTP/1.1 200 OK\r\n\r\nhello")
            .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Data(1));

        conn.feed_data(&mut io.as_io(), b" world").unwrap();
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Data(1));

        let mut buf = [0u8; 64];
        let (n, _fin) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello world");
    }

    #[test]
    fn incremental_chunked_body() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();

        conn.feed_data(
            &mut io.as_io(),
            b"POST /data HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .unwrap();
        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));

        conn.feed_data(&mut io.as_io(), b"5\r\nhel").unwrap();
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Data(1));

        conn.feed_data(&mut io.as_io(), b"lo\r\n0\r\n\r\n").unwrap();

        let mut events = heapless::Vec::<Http1Event, 8>::new();
        while let Some(ev) = conn.poll_event() {
            let _ = events.push(ev);
        }
        assert!(events.contains(&Http1Event::Finished(1)));

        let mut buf = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
        assert!(fin);
    }

    #[test]
    fn malformed_request_no_spaces() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        let result = conn.feed_data(&mut io.as_io(), b"GET\r\n\r\n");
        assert_eq!(result, Err(Error::InvalidState));
    }

    #[test]
    fn malformed_header_no_colon() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        let result = conn.feed_data(&mut io.as_io(), b"GET / HTTP/1.1\r\nBadHeader\r\n\r\n");
        assert_eq!(result, Err(Error::InvalidState));
    }

    #[test]
    fn client_server_e2e() {
        let mut client = Http1Connection::<1024, 1024>::new_client();
        let mut cio = Http1IoBufs::<4096>::new();
        let mut server = Http1Connection::<1024, 1024>::new_server();
        let mut sio = Http1IoBufs::<4096>::new();

        let stream_id = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"GET"),
                    (b":path", b"/"),
                    (b":authority", b"localhost"),
                ],
                true,
            )
            .unwrap();

        let mut buf = [0u8; 4096];
        while let Some(data) = client.poll_output(&mut cio.as_io(), &mut buf) {
            let copy: heapless::Vec<u8, 4096> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(data);
                v
            };
            server.feed_data(&mut sio.as_io(), &copy).unwrap();
        }

        assert!(matches!(server.poll_event(), Some(Http1Event::Connected)));
        let ev = server.poll_event().unwrap();
        assert!(matches!(ev, Http1Event::Headers(_)));
        while server.poll_event().is_some() {}

        let mut got_method = false;
        server
            .recv_headers(1, |name, value| {
                if name == b":method" && value == b"GET" {
                    got_method = true;
                }
            })
            .unwrap();
        assert!(got_method);

        server
            .send_headers(
                &mut sio.as_io(),
                1,
                &[
                    (b":status", b"200"),
                    (b"content-type", b"text/plain"),
                    (b"content-length", b"12"),
                ],
                false,
            )
            .unwrap();
        server
            .send_data(&mut sio.as_io(), 1, b"Hello World!", true)
            .unwrap();

        let mut buf2 = [0u8; 4096];
        while let Some(data) = server.poll_output(&mut sio.as_io(), &mut buf2) {
            let copy: heapless::Vec<u8, 4096> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(data);
                v
            };
            client.feed_data(&mut cio.as_io(), &copy).unwrap();
        }

        let mut got_headers = false;
        let mut got_data = false;
        let mut got_finished = false;
        while let Some(ev) = client.poll_event() {
            match ev {
                Http1Event::Headers(sid) if sid == stream_id => got_headers = true,
                Http1Event::Data(sid) if sid == stream_id => got_data = true,
                Http1Event::Finished(sid) if sid == stream_id => got_finished = true,
                _ => {}
            }
        }
        assert!(got_headers);
        assert!(got_data);
        assert!(got_finished);

        let mut status = heapless::Vec::<u8, 16>::new();
        client
            .recv_headers(stream_id, |name, value| {
                if name == b":status" {
                    let _ = status.extend_from_slice(value);
                }
            })
            .unwrap();
        assert_eq!(status.as_slice(), b"200");

        let mut body = [0u8; 64];
        let (n, fin) = client.recv_body(stream_id, &mut body).unwrap();
        assert_eq!(&body[..n], b"Hello World!");
        assert!(fin);
    }

    #[test]
    fn eq_ignore_case_works() {
        assert!(eq_ignore_case(b"content-length", b"Content-Length"));
        assert!(eq_ignore_case(b"HOST", b"host"));
        assert!(!eq_ignore_case(b"foo", b"bar"));
        assert!(!eq_ignore_case(b"foo", b"fooo"));
    }

    #[test]
    fn contains_ignore_case_works() {
        assert!(contains_ignore_case(b"chunked", b"chunked"));
        assert!(contains_ignore_case(b"Chunked", b"chunked"));
        assert!(contains_ignore_case(b"gzip, chunked", b"chunked"));
        assert!(!contains_ignore_case(b"gzip", b"chunked"));
    }

    #[test]
    fn parse_usize_ascii_works() {
        assert_eq!(parse_usize_ascii(b"0"), Some(0));
        assert_eq!(parse_usize_ascii(b"123"), Some(123));
        assert_eq!(parse_usize_ascii(b"65535"), Some(65535));
        assert_eq!(parse_usize_ascii(b"abc"), None);
        assert_eq!(parse_usize_ascii(b""), None);
    }

    #[test]
    fn status_reason_lookup() {
        assert_eq!(status_reason(b"200"), b"OK");
        assert_eq!(status_reason(b"404"), b"Not Found");
        assert_eq!(status_reason(b"500"), b"Internal Server Error");
        assert_eq!(status_reason(b"999"), b"");
    }

    // ====== Wire-Format Compatibility Tests ======

    #[test]
    fn wire_curl_get_request() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        conn.feed_data(
            &mut io.as_io(),
            b"GET /index.html HTTP/1.1\r\n\
              Host: example.com\r\n\
              User-Agent: curl/8.0\r\n\
              Accept: */*\r\n\
              \r\n",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Finished(1));

        let mut method = heapless::Vec::<u8, 16>::new();
        let mut path = heapless::Vec::<u8, 64>::new();
        let mut host = heapless::Vec::<u8, 64>::new();
        let mut ua = heapless::Vec::<u8, 64>::new();
        let mut accept = heapless::Vec::<u8, 16>::new();
        conn.recv_headers(1, |name, value| match name {
            b":method" => {
                let _ = method.extend_from_slice(value);
            }
            b":path" => {
                let _ = path.extend_from_slice(value);
            }
            b"Host" => {
                let _ = host.extend_from_slice(value);
            }
            b"User-Agent" => {
                let _ = ua.extend_from_slice(value);
            }
            b"Accept" => {
                let _ = accept.extend_from_slice(value);
            }
            _ => {}
        })
        .unwrap();
        assert_eq!(method.as_slice(), b"GET");
        assert_eq!(path.as_slice(), b"/index.html");
        assert_eq!(host.as_slice(), b"example.com");
        assert_eq!(ua.as_slice(), b"curl/8.0");
        assert_eq!(accept.as_slice(), b"*/*");
    }

    #[test]
    fn wire_nginx_200_response() {
        let mut conn = Http1Connection::<1024, 1024>::new_client();
        let mut io = Http1IoBufs::<4096>::new();
        conn.current_stream_id = 1;
        conn.feed_data(
            &mut io.as_io(),
            b"HTTP/1.1 200 OK\r\n\
              Server: nginx/1.24\r\n\
              Content-Type: text/html\r\n\
              Content-Length: 13\r\n\
              \r\n\
              <html></html>",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));

        let mut status = heapless::Vec::<u8, 16>::new();
        let mut server = heapless::Vec::<u8, 32>::new();
        let mut ctype = heapless::Vec::<u8, 32>::new();
        conn.recv_headers(1, |name, value| match name {
            b":status" => {
                let _ = status.extend_from_slice(value);
            }
            b"Server" => {
                let _ = server.extend_from_slice(value);
            }
            b"Content-Type" => {
                let _ = ctype.extend_from_slice(value);
            }
            _ => {}
        })
        .unwrap();
        assert_eq!(status.as_slice(), b"200");
        assert_eq!(server.as_slice(), b"nginx/1.24");
        assert_eq!(ctype.as_slice(), b"text/html");

        while conn.poll_event().is_some() {}

        let mut body = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut body).unwrap();
        assert_eq!(&body[..n], b"<html></html>");
        assert!(fin);
    }

    #[test]
    fn wire_nginx_301_redirect() {
        let mut conn = Http1Connection::<1024, 1024>::new_client();
        let mut io = Http1IoBufs::<4096>::new();
        conn.current_stream_id = 1;
        conn.feed_data(
            &mut io.as_io(),
            b"HTTP/1.1 301 Moved Permanently\r\n\
              Location: https://example.com/\r\n\
              Content-Length: 0\r\n\
              \r\n",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));

        let mut status = heapless::Vec::<u8, 16>::new();
        let mut location = heapless::Vec::<u8, 64>::new();
        conn.recv_headers(1, |name, value| match name {
            b":status" => {
                let _ = status.extend_from_slice(value);
            }
            b"Location" => {
                let _ = location.extend_from_slice(value);
            }
            _ => {}
        })
        .unwrap();
        assert_eq!(status.as_slice(), b"301");
        assert_eq!(location.as_slice(), b"https://example.com/");
    }

    #[test]
    fn wire_chunked_response() {
        let mut conn = Http1Connection::<1024, 1024>::new_client();
        let mut io = Http1IoBufs::<4096>::new();
        conn.current_stream_id = 1;
        conn.feed_data(
            &mut io.as_io(),
            b"HTTP/1.1 200 OK\r\n\
              Transfer-Encoding: chunked\r\n\
              \r\n\
              5\r\nhello\r\n0\r\n\r\n",
        )
        .unwrap();

        let mut events = heapless::Vec::<Http1Event, 16>::new();
        while let Some(ev) = conn.poll_event() {
            let _ = events.push(ev);
        }
        assert!(events.contains(&Http1Event::Headers(1)));
        assert!(events.contains(&Http1Event::Finished(1)));

        conn.recv_headers(1, |_, _| {}).unwrap();

        let mut body = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut body).unwrap();
        assert_eq!(&body[..n], b"hello");
        assert!(fin);
    }

    #[test]
    fn wire_connection_close() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        conn.feed_data(
            &mut io.as_io(),
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));

        let mut connection_hdr = heapless::Vec::<u8, 16>::new();
        conn.recv_headers(1, |name, value| {
            if name == b"Connection" {
                let _ = connection_hdr.extend_from_slice(value);
            }
        })
        .unwrap();
        assert_eq!(connection_hdr.as_slice(), b"close");
    }

    #[test]
    fn wire_post_json() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        conn.feed_data(
            &mut io.as_io(),
            b"POST /api HTTP/1.1\r\n\
              Host: api.example.com\r\n\
              Content-Type: application/json\r\n\
              Content-Length: 27\r\n\
              \r\n\
              {\"key\":\"value\",\"count\":42}\n",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));

        let mut method = heapless::Vec::<u8, 16>::new();
        let mut path = heapless::Vec::<u8, 64>::new();
        let mut ctype = heapless::Vec::<u8, 64>::new();
        conn.recv_headers(1, |name, value| match name {
            b":method" => {
                let _ = method.extend_from_slice(value);
            }
            b":path" => {
                let _ = path.extend_from_slice(value);
            }
            b"Content-Type" => {
                let _ = ctype.extend_from_slice(value);
            }
            _ => {}
        })
        .unwrap();
        assert_eq!(method.as_slice(), b"POST");
        assert_eq!(path.as_slice(), b"/api");
        assert_eq!(ctype.as_slice(), b"application/json");

        while conn.poll_event().is_some() {}

        let mut body = [0u8; 64];
        let (n, fin) = conn.recv_body(1, &mut body).unwrap();
        assert_eq!(&body[..n], b"{\"key\":\"value\",\"count\":42}\n");
        assert!(fin);
    }

    #[test]
    fn wire_case_insensitive_headers() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        conn.feed_data(
            &mut io.as_io(),
            b"GET / HTTP/1.1\r\nHOST: example.com\r\nContent-Length: 0\r\n\r\n",
        )
        .unwrap();

        assert_eq!(conn.poll_event(), Some(Http1Event::Connected));
        assert_eq!(conn.poll_event().unwrap(), Http1Event::Headers(1));

        let mut host = heapless::Vec::<u8, 64>::new();
        conn.recv_headers(1, |name, value| {
            if eq_ignore_case(name, b"host") {
                let _ = host.extend_from_slice(value);
            }
        })
        .unwrap();
        assert_eq!(host.as_slice(), b"example.com");
    }

    #[test]
    fn wire_server_response_encoding() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        conn.current_stream_id = 1;

        conn.send_headers(
            &mut io.as_io(),
            1,
            &[
                (b":status", b"200"),
                (b"Server", b"milli-http"),
                (b"Content-Length", b"2"),
            ],
            false,
        )
        .unwrap();
        conn.send_data(&mut io.as_io(), 1, b"OK", true).unwrap();

        let mut out = [0u8; 4096];
        let data = conn.poll_output(&mut io.as_io(), &mut out).unwrap();
        assert_eq!(
            data,
            b"HTTP/1.1 200 OK\r\nServer: milli-http\r\nContent-Length: 2\r\n\r\nOK"
        );
    }

    // ====== Timeout + Connection State Tests ======

    #[test]
    fn idle_timeout_between_keepalive() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        let config = crate::http::TimeoutConfig {
            idle_timeout_us: Some(1_000_000),
            header_timeout_us: None,
        };
        conn.set_timeouts(config, 0);

        conn.feed_data_timed(
            &mut io.as_io(),
            b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n",
            100_000,
        )
        .unwrap();

        while conn.poll_event().is_some() {}
        conn.recv_headers(1, |_, _| {}).unwrap();

        conn.feed_data_timed(&mut io.as_io(), b"", 200_000).unwrap();

        conn.handle_timeout(2_200_000);
        assert!(conn.is_closed());

        let mut got_timeout = false;
        while let Some(ev) = conn.poll_event() {
            if ev == Http1Event::Timeout {
                got_timeout = true;
            }
        }
        assert!(got_timeout);
    }

    #[test]
    fn header_timeout_on_slow_headers() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        let config = crate::http::TimeoutConfig {
            idle_timeout_us: None,
            header_timeout_us: Some(500_000),
        };
        conn.set_timeouts(config, 0);

        conn.feed_data_timed(&mut io.as_io(), b"GET / HTTP/1.1\r\n", 100_000)
            .unwrap();

        conn.handle_timeout(600_000);
        assert!(conn.is_closed());

        let mut got_timeout = false;
        while let Some(ev) = conn.poll_event() {
            if ev == Http1Event::Timeout {
                got_timeout = true;
            }
        }
        assert!(got_timeout);
    }

    #[test]
    fn header_timeout_resets_on_keepalive() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        let mut io = Http1IoBufs::<4096>::new();
        let config = crate::http::TimeoutConfig {
            idle_timeout_us: None,
            header_timeout_us: Some(500_000),
        };
        conn.set_timeouts(config, 0);

        conn.feed_data_timed(
            &mut io.as_io(),
            b"GET /a HTTP/1.1\r\nHost: example.com\r\n\r\n",
            100_000,
        )
        .unwrap();

        while conn.poll_event().is_some() {}
        conn.recv_headers(1, |_, _| {}).unwrap();

        // First bytes of the next request arrive at t=200ms — this is what
        // triggers the keep-alive transition and anchors the next header
        // deadline. (Empty feeds deliberately do not count as activity, so
        // they can no longer stand in for the clock here.)
        conn.feed_data_timed(&mut io.as_io(), b"GET /b HT", 200_000)
            .unwrap();

        conn.handle_timeout(600_000);
        assert!(!conn.is_closed());

        conn.handle_timeout(800_000);
        assert!(conn.is_closed());
    }

    #[test]
    fn is_closed_and_is_established() {
        let mut conn = Http1Connection::<1024, 1024>::new_server();
        assert!(conn.is_established());
        assert!(!conn.is_closed());

        let config = crate::http::TimeoutConfig {
            idle_timeout_us: Some(100),
            header_timeout_us: None,
        };
        conn.set_timeouts(config, 0);
        conn.handle_timeout(1000);

        assert!(conn.is_closed());
        assert!(!conn.is_established());
    }
}
