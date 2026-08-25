//! HTTP/2 connection state machine (RFC 9113).
//!
//! Pure codec following the milli-http pattern:
//! `feed_data()` → `poll_output()` → `poll_event()`

use super::flow_control::{
    DEFAULT_CONNECTION_WINDOW_SIZE, DEFAULT_INITIAL_WINDOW_SIZE, FlowController,
};
use super::frame::{self, *};
use super::io::H2Io;
use super::stream::{H2Stream, H2StreamState};
use crate::buf::BufExt;
use crate::error::Error;
use crate::hpack::codec::{HpackDecoder, HpackEncoder};

/// HTTP/2 connection preface (RFC 9113 §3.4).
pub const CONNECTION_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Events produced by the HTTP/2 connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H2Event {
    /// Connection settings exchanged, ready for requests.
    Connected,
    /// Headers received on a stream.
    Headers(u64),
    /// Body data available on a stream.
    Data(u64),
    /// Stream reset by peer.
    StreamReset(u64, u32),
    /// Peer sent GOAWAY.
    GoAway(u64, u32),
    /// Stream finished (END_STREAM received).
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

/// HTTP/2 connection settings.
#[derive(Debug, Clone)]
pub struct H2Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
}

impl Default for H2Settings {
    fn default() -> Self {
        Self {
            header_table_size: 0, // We don't use dynamic table
            enable_push: false,
            max_concurrent_streams: 128,
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE as u32,
            max_frame_size: 16384,
            max_header_list_size: 8192,
        }
    }
}

impl H2Settings {
    /// Encode settings as SETTINGS frame payload (6 bytes per param).
    pub fn encode_params(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let mut off = 0;
        off += frame::encode_setting(
            SETTINGS_HEADER_TABLE_SIZE,
            self.header_table_size,
            &mut buf[off..],
        )?;
        if !self.enable_push {
            off += frame::encode_setting(SETTINGS_ENABLE_PUSH, 0, &mut buf[off..])?;
        }
        off += frame::encode_setting(
            SETTINGS_MAX_CONCURRENT_STREAMS,
            self.max_concurrent_streams,
            &mut buf[off..],
        )?;
        off += frame::encode_setting(
            SETTINGS_INITIAL_WINDOW_SIZE,
            self.initial_window_size,
            &mut buf[off..],
        )?;
        off += frame::encode_setting(
            SETTINGS_MAX_FRAME_SIZE,
            self.max_frame_size,
            &mut buf[off..],
        )?;
        off += frame::encode_setting(
            SETTINGS_MAX_HEADER_LIST_SIZE,
            self.max_header_list_size,
            &mut buf[off..],
        )?;
        Ok(off)
    }

    /// Apply a settings parameter with RFC 9113 §6.5.2 validation.
    pub fn apply(&mut self, id: u16, value: u32) -> Result<(), Error> {
        match id {
            SETTINGS_HEADER_TABLE_SIZE => self.header_table_size = value,
            SETTINGS_ENABLE_PUSH => {
                if value > 1 {
                    return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                }
                self.enable_push = value != 0;
            }
            SETTINGS_MAX_CONCURRENT_STREAMS => self.max_concurrent_streams = value,
            SETTINGS_INITIAL_WINDOW_SIZE => {
                if value > 0x7fff_ffff {
                    return Err(Error::Http2(crate::error::H2Error::FlowControlError));
                }
                self.initial_window_size = value;
            }
            SETTINGS_MAX_FRAME_SIZE => {
                if !(16384..=16_777_215).contains(&value) {
                    return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                }
                self.max_frame_size = value;
            }
            SETTINGS_MAX_HEADER_LIST_SIZE => self.max_header_list_size = value,
            _ => {} // Unknown settings are ignored (RFC 9113 §6.5.2)
        }
        Ok(())
    }
}

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum H2ConnState {
    /// Waiting for connection preface (client: send preface, server: expect preface).
    WaitingPreface,
    /// Waiting for initial SETTINGS from peer.
    WaitingSettings,
    /// Connection is active.
    Active,
    /// GOAWAY sent or received.
    Closing,
    /// Connection closed.
    Closed,
}

/// HTTP/2 connection state machine.
///
/// I/O buffers are **not** owned by this struct; callers provide them via
/// [`H2Io`] on every method that touches network data.
///
/// Generic parameters:
/// - `MAX_STREAMS`: maximum number of concurrent streams tracked
/// - `HDRBUF`: per-stream header buffer size
/// - `DATABUF`: per-stream data buffer size
pub struct H2Connection<
    const MAX_STREAMS: usize = 8,
    const HDRBUF: usize = 2048,
    const DATABUF: usize = 4096,
> {
    role: Role,
    state: H2ConnState,
    local_settings: H2Settings,
    peer_settings: H2Settings,
    #[cfg(not(feature = "alloc"))]
    streams: heapless::Vec<H2Stream<HDRBUF, DATABUF>, MAX_STREAMS>,
    #[cfg(feature = "alloc")]
    streams: alloc::vec::Vec<H2Stream<HDRBUF, DATABUF>>,
    encoder: HpackEncoder,
    decoder: HpackDecoder,
    send_offset: usize,
    // Flow control
    conn_send_fc: FlowController,
    conn_recv_fc: FlowController,
    /// Connection-level receive-window credit not yet sent because the send
    /// buffer was full (see `H2Stream::pending_recv_credit`). Retried from
    /// `generate_output`.
    pending_conn_credit: u32,
    // Event queue
    #[cfg(not(feature = "alloc"))]
    events: heapless::Deque<H2Event, 32>,
    #[cfg(feature = "alloc")]
    events: alloc::collections::VecDeque<H2Event>,
    // Connection state
    next_stream_id: u64,
    last_peer_stream_id: u64,
    continuation_stream_id: Option<u64>,
    settings_sent: bool,
    settings_ack_received: bool,
    peer_settings_received: bool,
    preface_sent: bool,
    preface_validated: bool,
    preface_bytes_seen: usize,
    goaway_sent: bool,
    // Timeout support
    timeout_config: crate::http::TimeoutConfig,
    last_activity: u64,
    connection_start: u64,
    headers_phase_complete: bool,
    /// A DATA frame whose payload has not fully arrived. Its 9-byte header (and
    /// pad-length byte, if PADDED) have already been drained; the remaining
    /// payload is streamed into the stream's `data_buf` as records arrive. See
    /// [`pump_partial_data`](Self::pump_partial_data). This decouples the
    /// receive buffer size from the h2 frame size: a max-size DATA frame is
    /// 16393 bytes but a TLS record holds at most 16384, so every full-size
    /// frame straddles a record boundary. Buffering the whole frame before
    /// processing it would require `recv_buf` to hold the leftover plus the
    /// next record at once (~32 KB), overflowing the shared TLS app buffer.
    partial_data: Option<PartialData>,
}

/// In-progress receive of a DATA frame's payload (see
/// [`H2Connection::partial_data`]).
#[derive(Clone, Copy)]
struct PartialData {
    stream_id: u64,
    /// END_STREAM flag — apply once the whole payload (and padding) is consumed.
    end_stream: bool,
    /// Payload bytes still to deliver into the stream's `data_buf`.
    data_remaining: usize,
    /// Trailing padding bytes still to discard after the payload.
    pad_remaining: usize,
    /// Whether a matching stream exists. If not, payload bytes are still drained
    /// off `recv_buf` to stay frame-aligned, but discarded (matching the prior
    /// lenient handling of DATA on an unknown stream).
    deliver: bool,
}

impl<const MAX_STREAMS: usize, const HDRBUF: usize, const DATABUF: usize>
    H2Connection<MAX_STREAMS, HDRBUF, DATABUF>
{
    /// Create a new client-side connection.
    pub fn new_client() -> Self {
        Self::new(Role::Client)
    }

    /// Create a new server-side connection.
    pub fn new_server() -> Self {
        Self::new(Role::Server)
    }

    fn new(role: Role) -> Self {
        let next_stream_id = match role {
            Role::Client => 1,
            Role::Server => 2,
        };
        // Advertise a receive window equal to our per-stream body buffer
        // (`DATABUF`) instead of the RFC default of 65535. `recv_body` credits
        // WINDOW_UPDATE on consumption (see that fn), so capping the initial
        // window at the buffer size means a peer can never have more DATA in
        // flight than `data_buf` can hold — the overflow path below would
        // otherwise silently drop body bytes and corrupt large request bodies.
        //
        // Likewise advertise the *real* stream capacity (RFC 9113 §6.5.2).
        // The default of 128 promised concurrency the `MAX_STREAMS`-bounded
        // stream table cannot deliver: a compliant client (e.g. hyper
        // multiplexing a request batch) legitimately opened a 9th stream,
        // `ensure_stream` silently refused it, and the Headers event for the
        // never-created stream made the server route a request with no
        // readable headers. Advertising the true limit makes the peer queue
        // excess streams client-side instead.
        let local_settings = H2Settings {
            initial_window_size: DATABUF as u32,
            max_concurrent_streams: MAX_STREAMS as u32,
            ..H2Settings::default()
        };
        Self {
            role,
            state: H2ConnState::WaitingPreface,
            local_settings,
            peer_settings: H2Settings::default(),
            #[cfg(not(feature = "alloc"))]
            streams: heapless::Vec::new(),
            #[cfg(feature = "alloc")]
            streams: alloc::vec::Vec::new(),
            encoder: HpackEncoder::new(),
            decoder: HpackDecoder::new(),
            send_offset: 0,
            conn_send_fc: FlowController::new(DEFAULT_CONNECTION_WINDOW_SIZE),
            conn_recv_fc: FlowController::new(DEFAULT_CONNECTION_WINDOW_SIZE),
            pending_conn_credit: 0,
            #[cfg(not(feature = "alloc"))]
            events: heapless::Deque::new(),
            #[cfg(feature = "alloc")]
            events: alloc::collections::VecDeque::new(),
            next_stream_id,
            last_peer_stream_id: 0,
            continuation_stream_id: None,
            settings_sent: false,
            settings_ack_received: false,
            peer_settings_received: false,
            preface_sent: false,
            preface_validated: false,
            preface_bytes_seen: 0,
            goaway_sent: false,
            timeout_config: crate::http::TimeoutConfig::default(),
            last_activity: 0,
            connection_start: 0,
            headers_phase_complete: false,
            partial_data: None,
        }
    }

    /// Feed received TCP data into the connection.
    pub fn feed_data<const BUF: usize>(
        &mut self,
        io: &mut H2Io<'_, BUF>,
        data: &[u8],
    ) -> Result<(), Error> {
        self.generate_output(io);

        if io.recv_buf.len() + data.len() > BUF {
            return Err(Error::BufferTooSmall {
                needed: io.recv_buf.len() + data.len(),
            });
        }
        io.recv_buf.buf_try_reserve(data.len())?;
        let _ = io.recv_buf.extend_from_slice(data);

        self.process_recv(io)
    }

    /// Pull the next chunk of outgoing data.
    pub fn poll_output<'a, const BUF: usize>(
        &mut self,
        io: &mut H2Io<'_, BUF>,
        buf: &'a mut [u8],
    ) -> Option<&'a [u8]> {
        self.generate_output(io);

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
    pub fn poll_event(&mut self) -> Option<H2Event> {
        self.events.pop_front()
    }

    /// Push an event into the queue. When the queue is full (consumer is
    /// lagging) the oldest event is dropped to make room, so the most recent
    /// events are never silently lost. (heapless `push_back` on a full deque
    /// silently drops the NEW event — the opposite policy — so the no-alloc
    /// path must evict explicitly too.)
    fn push_event(&mut self, event: H2Event) {
        #[cfg(feature = "alloc")]
        if self.events.len() >= 64 {
            let _ = self.events.pop_front();
        }
        #[cfg(not(feature = "alloc"))]
        if self.events.is_full() {
            let _ = self.events.pop_front();
        }
        let _ = self.events.push_back(event);
    }

    // ------------------------------------------------------------------
    // Application API
    // ------------------------------------------------------------------

    /// Send headers on a new or existing stream.
    pub fn send_headers<const BUF: usize>(
        &mut self,
        io: &mut H2Io<'_, BUF>,
        stream_id: u64,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error> {
        // Track the stream before encoding anything: silently emitting
        // HEADERS for a stream the table cannot hold would desync stream
        // state from the wire (and, server-side, resurrect IDs the peer has
        // already finished with).
        if !self.ensure_stream(stream_id) {
            return Err(Error::InvalidState);
        }
        let hdr_start = io.send_buf.len();
        if hdr_start + 9 > BUF {
            return Err(Error::BufferTooSmall {
                needed: hdr_start + 9,
            });
        }
        // The zero-fill below grows send_buf to its full BUF bound for the
        // HPACK scratch region, so reserve the whole remainder fallibly.
        io.send_buf.buf_try_reserve(BUF - hdr_start)?;
        for _ in 0..9 {
            let _ = io.send_buf.push(0);
        }

        let encode_start = io.send_buf.len();
        let max_hpack = BUF - encode_start;
        while io.send_buf.len() < BUF {
            let _ = io.send_buf.push(0);
        }
        let hpack_len = self.encoder.encode(
            headers,
            &mut io.send_buf[encode_start..encode_start + max_hpack],
        )?;
        io.send_buf.truncate(encode_start + hpack_len);

        let mut flags = 0u8;
        if end_stream {
            flags |= FLAG_END_STREAM;
        }
        flags |= FLAG_END_HEADERS;
        let hdr = frame::H2FrameHeader {
            length: hpack_len as u32,
            frame_type: FRAME_HEADERS,
            flags,
            stream_id,
        };
        frame::encode_frame_header(&hdr, &mut io.send_buf[hdr_start..hdr_start + 9])?;

        if let Some(stream) = self.get_stream_mut(stream_id) {
            if stream.state == H2StreamState::Idle {
                stream.open();
            }
            if end_stream {
                stream.send_end_stream();
            }
        }

        Ok(())
    }

    /// Open a new stream and send headers. Returns the stream ID.
    pub fn open_stream<const BUF: usize>(
        &mut self,
        io: &mut H2Io<'_, BUF>,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<u64, Error> {
        if self.next_stream_id > 0x7fff_ffff {
            return Err(Error::StreamLimitExhausted);
        }
        let stream_id = self.next_stream_id;
        self.next_stream_id += 2;
        self.send_headers(io, stream_id, headers, end_stream)?;
        Ok(stream_id)
    }

    /// Bytes [`send_data`](Self::send_data) would accept on `stream_id`
    /// right now without truncating — the smaller of the connection window,
    /// the stream window, and the peer's max frame size. `None` when the
    /// stream is unknown or not in a sendable state (`send_data` would
    /// answer `InvalidState`/`WouldBlock` forever); `Some(0)` is a closed
    /// window, i.e. backpressure. Send-buffer space is not counted:
    /// `send_data` reports that as `BufferTooSmall` without writing
    /// anything. Lets a sender of self-delimiting records refuse a partial
    /// write instead of tearing a record the receiver cannot resync on.
    pub fn send_capacity(&self, stream_id: u64) -> Option<usize> {
        let stream = self.get_stream(stream_id)?;
        if !stream.can_send() {
            return None;
        }
        let by_conn = self.conn_send_fc.window().max(0) as usize;
        let by_stream = stream.send_window.max(0) as usize;
        Some(
            by_conn
                .min(by_stream)
                .min(self.peer_settings.max_frame_size as usize),
        )
    }

    /// Send data on a stream.
    pub fn send_data<const BUF: usize>(
        &mut self,
        io: &mut H2Io<'_, BUF>,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        if let Some(stream) = self.get_stream(stream_id)
            && !stream.can_send()
        {
            return Err(Error::InvalidState);
        }
        let max_by_conn = self.conn_send_fc.window().max(0) as usize;
        let max_by_stream = self
            .get_stream(stream_id)
            .map(|s| s.send_window.max(0) as usize)
            .unwrap_or(0);
        let max_frame = self.peer_settings.max_frame_size as usize;
        let can_send = data
            .len()
            .min(max_by_conn)
            .min(max_by_stream)
            .min(max_frame);

        if can_send == 0 && !data.is_empty() {
            return Err(Error::WouldBlock);
        }

        let to_send = if data.is_empty() {
            data
        } else {
            &data[..can_send]
        };
        let actual_end = end_stream && (to_send.len() == data.len());

        let total_needed = 9 + to_send.len();
        if io.send_buf.len() + total_needed > BUF {
            return Err(Error::BufferTooSmall {
                needed: io.send_buf.len() + total_needed,
            });
        }
        io.send_buf.buf_try_reserve(total_needed)?;
        let flags = if actual_end { FLAG_END_STREAM } else { 0 };
        let hdr = frame::H2FrameHeader {
            length: to_send.len() as u32,
            frame_type: FRAME_DATA,
            flags,
            stream_id,
        };
        let hdr_start = io.send_buf.len();
        for _ in 0..9 {
            let _ = io.send_buf.push(0);
        }
        frame::encode_frame_header(&hdr, &mut io.send_buf[hdr_start..hdr_start + 9])?;
        let _ = io.send_buf.extend_from_slice(to_send);

        if !to_send.is_empty() {
            self.conn_send_fc.consume(to_send.len() as u32)?;
            if let Some(stream) = self.get_stream_mut(stream_id) {
                stream.send_window -= to_send.len() as i32;
            }
        }

        if actual_end && let Some(stream) = self.get_stream_mut(stream_id) {
            stream.send_end_stream();
        }

        Ok(to_send.len())
    }

    /// Read received headers for a stream.
    pub fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        emit: F,
    ) -> Result<(), Error> {
        // Field-level borrows: the decoder (mutable — dynamic table inserts)
        // and the stream's header block (immutable) are disjoint.
        let stream = self
            .streams
            .iter()
            .find(|s| s.id == stream_id)
            .ok_or(Error::InvalidState)?;
        if !stream.headers_received {
            return Err(Error::WouldBlock);
        }
        self.decoder.decode(&stream.headers_data, emit)?;
        // Clear after decode to prevent double-reading
        if let Some(stream) = self.get_stream_mut(stream_id) {
            stream.headers_data.clear();
            stream.headers_received = false;
        }
        Ok(())
    }

    /// Whether a DATA frame's payload is still being received incrementally
    /// (see [`partial_data`](Self::partial_data)). Combined with a non-empty
    /// receive buffer at the transport layer, this signals that the peer is
    /// sending faster than the body is being consumed and the runner should
    /// apply backpressure rather than read more.
    pub fn has_partial_data(&self) -> bool {
        self.partial_data.is_some()
    }

    /// Read received body data for a stream.
    pub fn recv_body<const BUF: usize>(
        &mut self,
        io: &mut H2Io<'_, BUF>,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        let stream = self.get_stream_mut(stream_id).ok_or(Error::InvalidState)?;

        if stream.data_buf.is_empty() {
            if stream.fin_received {
                // The body is fully drained. Clear `data_available` so the
                // Closed-stream retain in `process_recv` can reap this slot —
                // a body terminated by an empty END_STREAM DATA frame (the
                // normal curl/nghttp2 streaming-upload ending) sets
                // `data_available` on completion but leaves nothing for the
                // copy path below to clear, so without this the slot leaked
                // and `MAX_STREAMS` requests wedged a persistent connection.
                stream.data_available = false;
                return Ok((0, true));
            }
            return Err(Error::WouldBlock);
        }

        let copy_len = stream.data_buf.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&stream.data_buf[..copy_len]);

        stream.data_buf.copy_within(copy_len.., 0);
        stream.data_buf.truncate(stream.data_buf.len() - copy_len);

        let fin = stream.data_buf.is_empty() && stream.fin_received;
        stream.data_available = !stream.data_buf.is_empty();

        if copy_len > 0 {
            self.send_window_update(io, 0, copy_len as u32);
            self.send_window_update(io, stream_id, copy_len as u32);
        }

        Ok((copy_len, fin))
    }

    /// Stop receiving a stream's body: the application will not (or no
    /// longer) read it. Role-symmetric — it discards inbound data and queues
    /// RST_STREAM regardless of which side opened the stream:
    ///
    /// - **Server**: reject a request without consuming its body (e.g. a 413
    ///   on an upload) — otherwise the unread body fills `data_buf`, the pump
    ///   stalls, and the connection wedges behind the runner's receive
    ///   backpressure with nothing left to unwedge it.
    /// - **Client**: cancel a response stream (e.g. abandon a long-lived
    ///   subscription) without tearing down the shared connection; other
    ///   streams are unaffected. A late response, trailers, or in-flight DATA
    ///   arriving behind our RST_STREAM are ignored per RFC 9113 §5.1 (see
    ///   the closed-stream leniency in `process_recv`), with DATA bytes still
    ///   credited back to the connection window.
    ///
    /// Effects:
    /// - An in-flight DATA frame on this stream switches the pump to discard
    ///   mode: the remaining payload is drained off `recv_buf` and the
    ///   connection window credited, so frames behind it become parseable
    ///   again and `recv_blocked` clears.
    /// - Buffered-but-unread body bytes are dropped and credited back to the
    ///   connection window (RFC 9113 §6.9.1).
    /// - Unless the peer already finished the stream (END_STREAM received —
    ///   nothing more is coming), RST_STREAM with `error_code` is sent so the
    ///   peer stops transmitting. Use `0` (NO_ERROR) when rejecting after a
    ///   complete response (RFC 9113 §8.1), `0x8` (CANCEL) otherwise. A full
    ///   send buffer defers the frame (`H2Stream::pending_rst`), retried from
    ///   `generate_output` — never silently dropped.
    ///
    /// The stream transitions to Closed; its slot is reaped once any pending
    /// RST has gone out. Returns `InvalidState` if the stream doesn't exist.
    pub fn discard_body<const BUF: usize>(
        &mut self,
        io: &mut H2Io<'_, BUF>,
        stream_id: u64,
        error_code: u32,
    ) -> Result<(), Error> {
        if !self.streams.iter().any(|s| s.id == stream_id) {
            return Err(Error::InvalidState);
        }

        // Abandon any in-flight DATA frame: the pump drains the remaining
        // payload off recv_buf (crediting the connection window) instead of
        // waiting forever for data_buf space that will never come.
        if let Some(pd) = self.partial_data.as_mut()
            && pd.stream_id == stream_id
        {
            pd.deliver = false;
        }

        let (buffered, send_rst) = {
            let stream = self
                .streams
                .iter_mut()
                .find(|s| s.id == stream_id)
                .expect("checked above");
            let buffered = stream.data_buf.len() as u32;
            stream.data_buf.clear();
            stream.data_available = false;
            // Drop unread headers too: the application has abandoned the
            // whole stream, and the Closed-stream retain deliberately keeps
            // slots with unread headers alive (a normally-completed response
            // must survive until read). Without this, a client canceling
            // before reading the response headers leaked the slot forever —
            // MAX_STREAMS cancels wedged the connection with InvalidState on
            // every subsequent open_stream.
            stream.headers_data.clear();
            stream.headers_received = false;
            // No RST needed if the peer already half-closed: nothing more is
            // coming, the discard is purely local.
            let send_rst = !stream.fin_received;
            if send_rst {
                stream.pending_rst = Some(error_code);
            }
            stream.reset();
            (buffered, send_rst)
        };
        if buffered > 0 {
            self.send_window_update(io, 0, buffered);
        }
        if send_rst {
            // Try to get the RST out now; a full send buffer leaves it
            // pending for generate_output to retry.
            self.flush_window_updates(io);
        }
        Ok(())
    }

    /// Send a GOAWAY frame.
    pub fn send_goaway<const BUF: usize>(
        &mut self,
        io: &mut H2Io<'_, BUF>,
        error_code: u32,
    ) -> Result<(), Error> {
        let frame = H2Frame::GoAway {
            last_stream_id: self.last_peer_stream_id,
            error_code,
            debug: &[],
        };
        let mut buf = [0u8; 32];
        let n = frame::encode_frame(&frame, &mut buf)?;
        io.queue_send(&buf[..n])?;
        self.goaway_sent = true;
        self.state = H2ConnState::Closing;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internal: output generation
    // ------------------------------------------------------------------

    /// Generate pending protocol frames (SETTINGS, WINDOW_UPDATE, etc.) into the I/O send buffer.
    ///
    /// This is automatically called by [`poll_output`](Self::poll_output). Exposed publicly for
    /// composed stacks (e.g. H2-over-TLS) where the send buffer feeds into
    /// another layer rather than directly to the network.
    pub fn generate_output<const BUF: usize>(&mut self, io: &mut H2Io<'_, BUF>) {
        if !self.preface_sent {
            if self.role == Role::Client {
                let _ = io.queue_send(CONNECTION_PREFACE);
            }
            let _ = self.send_initial_settings(io);
            self.preface_sent = true;
        }
        // Retry WINDOW_UPDATE credit that a previously-full send buffer deferred.
        self.flush_window_updates(io);
    }

    fn send_initial_settings<const BUF: usize>(
        &mut self,
        io: &mut H2Io<'_, BUF>,
    ) -> Result<(), Error> {
        let mut params = [0u8; 64];
        let params_len = self.local_settings.encode_params(&mut params)?;
        let frame = H2Frame::Settings {
            ack: false,
            params: &params[..params_len],
        };
        let mut buf = [0u8; 128];
        let n = frame::encode_frame(&frame, &mut buf)?;
        io.queue_send(&buf[..n])?;
        self.settings_sent = true;
        Ok(())
    }

    fn send_settings_ack<const BUF: usize>(&mut self, io: &mut H2Io<'_, BUF>) -> Result<(), Error> {
        let frame = H2Frame::Settings {
            ack: true,
            params: &[],
        };
        let mut buf = [0u8; 16];
        let n = frame::encode_frame(&frame, &mut buf)?;
        io.queue_send(&buf[..n])
    }

    fn send_ping_ack<const BUF: usize>(
        &mut self,
        io: &mut H2Io<'_, BUF>,
        data: [u8; 8],
    ) -> Result<(), Error> {
        let frame = H2Frame::Ping { data, ack: true };
        let mut buf = [0u8; 32];
        let n = frame::encode_frame(&frame, &mut buf)?;
        io.queue_send(&buf[..n])
    }

    /// Record receive-window credit for a stream (or the connection, id 0) and
    /// try to emit the WINDOW_UPDATE. The credit is accumulated into a pending
    /// counter and only applied to the advertised window once the frame is
    /// actually queued — if the send buffer is full the frame is deferred and
    /// retried from `flush_window_updates`/`generate_output`, never dropped.
    ///
    /// Previously this queued the frame with the result ignored while crediting
    /// the window unconditionally: a full send buffer silently dropped the
    /// WINDOW_UPDATE but still advanced `recv_window`, desyncing the peer's view
    /// from ours and stalling the upload forever (the peer waits for credit it
    /// never receives, so no further DATA arrives to drive a retry).
    fn send_window_update<const BUF: usize>(
        &mut self,
        io: &mut H2Io<'_, BUF>,
        stream_id: u64,
        increment: u32,
    ) {
        if increment == 0 {
            return;
        }
        if stream_id == 0 {
            self.pending_conn_credit = self.pending_conn_credit.saturating_add(increment);
        } else if let Some(stream) = self.get_stream_mut(stream_id) {
            stream.pending_recv_credit = stream.pending_recv_credit.saturating_add(increment);
        }
        self.flush_window_updates(io);
    }

    /// Emit any deferred per-stream control frames — WINDOW_UPDATE credit
    /// (connection + per-stream) and RST_STREAM queued by [`discard_body`]
    /// — that fit in the send buffer, applying the effect (window advance,
    /// pending-RST clear) only on a successful queue. Pending credit
    /// coalesces, so a backlog drains as one larger increment once buffer
    /// space frees. Called from `generate_output`, so it retries on every
    /// `poll_output` cycle.
    ///
    /// [`discard_body`]: Self::discard_body
    fn flush_window_updates<const BUF: usize>(&mut self, io: &mut H2Io<'_, BUF>) {
        let mut buf = [0u8; 16];
        if self.pending_conn_credit > 0 {
            let inc = self.pending_conn_credit;
            let frame = H2Frame::WindowUpdate {
                stream_id: 0,
                increment: inc,
            };
            if let Ok(n) = frame::encode_frame(&frame, &mut buf)
                && io.queue_send(&buf[..n]).is_ok()
            {
                let _ = self.conn_recv_fc.replenish(inc);
                self.pending_conn_credit = 0;
            }
        }
        for stream in self.streams.iter_mut() {
            if stream.pending_recv_credit > 0 {
                let inc = stream.pending_recv_credit;
                let frame = H2Frame::WindowUpdate {
                    stream_id: stream.id,
                    increment: inc,
                };
                if let Ok(n) = frame::encode_frame(&frame, &mut buf)
                    && io.queue_send(&buf[..n]).is_ok()
                {
                    let new_window = stream.recv_window as i64 + inc as i64;
                    stream.recv_window = new_window.min(0x7fff_ffff) as i32;
                    stream.pending_recv_credit = 0;
                }
            }
            if let Some(error_code) = stream.pending_rst {
                let frame = H2Frame::RstStream {
                    stream_id: stream.id,
                    error_code,
                };
                if let Ok(n) = frame::encode_frame(&frame, &mut buf)
                    && io.queue_send(&buf[..n]).is_ok()
                {
                    stream.pending_rst = None;
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Internal: receive processing
    // ------------------------------------------------------------------

    /// Stream as much of the in-progress DATA frame's payload (then its
    /// padding) as `recv_buf` currently holds and the stream's `data_buf` can
    /// accept. Clears `partial_data` once the whole frame is consumed; otherwise
    /// leaves it for the next call — either because `recv_buf` ran dry (need
    /// more network bytes) or because `data_buf` is full (backpressure until the
    /// consumer drains via `recv_body`). Never errors: the connection-level
    /// receive window was already committed when the frame header was parsed,
    /// and buffer pressure is handled by leaving bytes unconsumed in `recv_buf`.
    fn pump_partial_data<const BUF: usize>(&mut self, io: &mut H2Io<'_, BUF>) {
        let Some(mut pd) = self.partial_data.take() else {
            return;
        };

        // 1. Deliver payload into the stream's data_buf (or discard if the
        //    stream is gone), bounded by available bytes and buffer space.
        while pd.data_remaining > 0 {
            let avail = io.recv_buf.len();
            if avail == 0 {
                break; // need more bytes from the network
            }
            if pd.deliver {
                let n = {
                    let Some(stream) = self.streams.iter_mut().find(|s| s.id == pd.stream_id)
                    else {
                        // Stream vanished mid-frame (e.g. reset): discard the rest.
                        pd.deliver = false;
                        continue;
                    };
                    let free = stream.data_buf.capacity() - stream.data_buf.len();
                    if free == 0 {
                        break; // data_buf full → backpressure until recv_body drains
                    }
                    let n = pd.data_remaining.min(avail).min(free);
                    if stream.data_buf.buf_try_reserve(n).is_err() {
                        break; // allocator pressure → backpressure, as for full
                    }
                    // n <= free, so this never overflows the buffer.
                    let _ = stream.data_buf.extend_from_slice(&io.recv_buf[..n]);
                    stream.data_available = true;
                    stream.recv_window -= n as i32;
                    n
                };
                io.drain_recv(n);
                pd.data_remaining -= n;
                self.push_event(H2Event::Data(pd.stream_id));
            } else {
                // Stream gone (unknown or reset mid-frame): drain the bytes off
                // recv_buf to stay frame-aligned, discard them, and credit the
                // connection window so it doesn't leak (RFC 9113 §6.9.1 — a
                // reset stream's bytes still count against the connection).
                let n = pd.data_remaining.min(avail);
                io.drain_recv(n);
                pd.data_remaining -= n;
                if n > 0 {
                    self.send_window_update(io, 0, n as u32);
                }
            }
        }

        // 2. Discard trailing padding once all payload has been delivered.
        if pd.data_remaining == 0 && pd.pad_remaining > 0 {
            let n = pd.pad_remaining.min(io.recv_buf.len());
            io.drain_recv(n);
            pd.pad_remaining -= n;
        }

        // 3. Frame fully consumed → apply END_STREAM and signal completion.
        if pd.data_remaining == 0 && pd.pad_remaining == 0 {
            if pd.deliver {
                if let Some(stream) = self.streams.iter_mut().find(|s| s.id == pd.stream_id) {
                    // Mark the stream readable so `process_recv`'s retain keeps
                    // it alive for the application even when this DATA frame
                    // carried no bytes (e.g. a 0-length END_STREAM frame closing
                    // the stream): the app still needs to read the response
                    // headers/status. A non-empty frame already set this while
                    // delivering payload.
                    stream.data_available = true;
                    if pd.end_stream {
                        stream.recv_end_stream();
                    }
                }
                if pd.end_stream {
                    self.push_event(H2Event::Finished(pd.stream_id));
                }
            }
            // A discarded (reset/unknown-stream) frame signals nothing.
            // partial_data remains None (taken at the top).
        } else {
            self.partial_data = Some(pd);
        }
    }

    fn process_recv<const BUF: usize>(&mut self, io: &mut H2Io<'_, BUF>) -> Result<(), Error> {
        if self.role == Role::Server && !self.preface_validated {
            self.validate_client_preface(io)?;
            if !self.preface_validated {
                return Ok(());
            }
        }

        loop {
            // Resume an in-progress DATA frame whose payload spans receive
            // buffers / TLS records before parsing the next frame header.
            if self.partial_data.is_some() {
                self.pump_partial_data(io);
                if self.partial_data.is_some() {
                    // Couldn't finish: either recv_buf is drained (need more
                    // bytes) or the stream's data_buf is full (backpressure
                    // until the consumer drains via recv_body). Stop this round.
                    break;
                }
                continue;
            }

            if io.recv_buf.len() < 9 {
                break;
            }

            let payload_len = ((io.recv_buf[0] as usize) << 16)
                | ((io.recv_buf[1] as usize) << 8)
                | (io.recv_buf[2] as usize);
            let total = 9 + payload_len;

            // RFC 9113 §4.2: reject frames exceeding our advertised MAX_FRAME_SIZE
            if payload_len > self.local_settings.max_frame_size as usize {
                return Err(Error::Http2(crate::error::H2Error::FrameSizeError));
            }

            let frame_type = io.recv_buf[3];
            let flags = io.recv_buf[4];
            let stream_id = u32::from_be_bytes([
                io.recv_buf[5] & 0x7f,
                io.recv_buf[6],
                io.recv_buf[7],
                io.recv_buf[8],
            ]) as u64;

            if let Some(expected_sid) = self.continuation_stream_id {
                if frame_type != FRAME_CONTINUATION || stream_id != expected_sid {
                    return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                }
            }

            // DATA frames are consumed incrementally: only the 9-byte header
            // (plus the pad-length byte, if PADDED) needs to be present now. The
            // payload is streamed into the stream's data_buf as it arrives (see
            // pump_partial_data), so a record-straddling max-size frame never
            // requires the whole frame to sit in recv_buf at once. The
            // flow-control bound is the data_buf capacity, applied as
            // backpressure, not a hard window check — this also tolerates the
            // legal pre-SETTINGS-ack burst a peer may send under the RFC-default
            // window (RFC 9113 §6.9.2).
            if frame_type == FRAME_DATA {
                if stream_id == 0 {
                    return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                }
                let padded = flags & FLAG_PADDED != 0;
                let header_len = if padded { 10 } else { 9 };
                if io.recv_buf.len() < header_len {
                    break; // need the pad-length byte before the frame can be sized
                }
                let (data_total, pad_total) = if padded {
                    if payload_len == 0 {
                        return Err(Error::BufferTooSmall { needed: 1 });
                    }
                    // payload = 1 (pad-length byte) + data + pad_len (padding)
                    let pad_len = io.recv_buf[9] as usize;
                    if pad_len >= payload_len {
                        return Err(Error::InvalidState);
                    }
                    (payload_len - 1 - pad_len, pad_len)
                } else {
                    (payload_len, 0)
                };

                // A Closed slot no longer receives — its frames are handled
                // like unknown-stream frames (drained + connection window
                // credited) per RFC 9113 §5.1. The slot lingers between a
                // local reset (`discard_body`) and the end-of-batch reap;
                // without this gate, DATA landing in that window was
                // delivered into the canceled stream's `data_buf` with no
                // credit returned, and `data_available` kept the slot alive
                // forever — a slot + connection-window leak per cancel.
                let live = self
                    .streams
                    .iter()
                    .find(|s| s.id == stream_id && s.state != H2StreamState::Closed);

                // RFC 9113 §6.9.1: once the peer has acknowledged our SETTINGS
                // it must honor the receive window we advertised; exceeding it
                // is a FLOW_CONTROL_ERROR. Before the ack the peer is entitled to
                // the RFC-default window (§6.9.2) and may legally send more than
                // we advertised — that burst is absorbed by data_buf
                // backpressure (see pump_partial_data), not rejected. Frames on
                // a closed stream are exempt (§5.1 — sent before our RST
                // arrived, against a window we no longer track).
                if self.settings_ack_received
                    && let Some(stream) = live
                    && (data_total as i32) > stream.recv_window
                {
                    return Err(Error::Http2(crate::error::H2Error::FlowControlError));
                }

                // Commit the frame's data length against the connection-level
                // receive window up front; recv_body replenishes it on drain.
                self.conn_recv_fc.consume(data_total as u32)?;
                let deliver = live.is_some();

                io.drain_recv(header_len);
                self.partial_data = Some(PartialData {
                    stream_id,
                    end_stream: flags & FLAG_END_STREAM != 0,
                    data_remaining: data_total,
                    pad_remaining: pad_total,
                    deliver,
                });
                continue;
            }

            // All other frame types are bounded by MAX_FRAME_SIZE and processed
            // whole. A frame that cannot fit the receive buffer can never be
            // assembled — fail fast rather than waiting forever.
            if total > BUF {
                return Err(Error::Http2(crate::error::H2Error::FrameSizeError));
            }
            if io.recv_buf.len() < total {
                break;
            }

            let ps = 9;
            let pe = total;

            match frame_type {
                FRAME_HEADERS => {
                    if stream_id == 0 {
                        return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                    }
                    let end_stream = flags & FLAG_END_STREAM != 0;
                    let end_headers = flags & FLAG_END_HEADERS != 0;
                    let (data_start, data_end) = if flags & FLAG_PADDED != 0 {
                        if payload_len == 0 {
                            return Err(Error::BufferTooSmall { needed: 1 });
                        }
                        let pad_len = io.recv_buf[ps] as usize;
                        if pad_len >= payload_len {
                            return Err(Error::InvalidState);
                        }
                        (ps + 1, pe - pad_len)
                    } else {
                        (ps, pe)
                    };
                    let frag_start = if flags & FLAG_PRIORITY != 0 {
                        if data_end - data_start < 5 {
                            return Err(Error::BufferTooSmall { needed: 5 });
                        }
                        data_start + 5
                    } else {
                        data_start
                    };

                    // RFC 9113 §5.1.1: a stream newly opened by HEADERS must use
                    // the initiator's ID space — client-initiated streams are
                    // odd, server-initiated even. A server must only see new odd
                    // streams from a client; a client must not have the peer open
                    // a new stream via HEADERS (server push uses PUSH_PROMISE and
                    // is disabled). Existing streams (e.g. a response on a stream
                    // we opened) are unaffected.
                    // RFC 9113 §5.1: frames on a closed stream must be
                    // ignored — a late response or trailers can legitimately
                    // be in flight behind our RST_STREAM, and treating them
                    // as the peer opening a new stream (below) tears down
                    // the whole connection. Two shapes of "closed":
                    // - a still-present slot in Closed state (a local
                    //   `discard_body` whose reap hasn't run yet, or a
                    //   completed exchange retained for the application) —
                    //   delivering here would clobber retained response
                    //   headers and re-pin the slot;
                    // - no slot at all, but the ID is in our own monotonic
                    //   ID space below `next_stream_id` — a stream we opened
                    //   that has been reaped.
                    // The dropped block still passes through the HPACK
                    // decoder (output discarded): skipping it would desync a
                    // dynamic-table-inserting peer's table for every
                    // subsequent header block on the connection. A
                    // !END_HEADERS block cannot be decoded fragment-wise, so
                    // it is a connection error (COMPRESSION_ERROR, §4.3): we
                    // can no longer maintain HPACK state, and a clean
                    // teardown beats silently wrong header values on other
                    // streams. (In practice multi-frame trailers on a
                    // canceled stream do not occur with in-tree peers.)
                    let is_new = !self.streams.iter().any(|s| s.id == stream_id);
                    let closed = self
                        .streams
                        .iter()
                        .any(|s| s.id == stream_id && s.state == H2StreamState::Closed)
                        || (is_new
                            && stream_id < self.next_stream_id
                            && match self.role {
                                Role::Client => stream_id % 2 == 1,
                                Role::Server => stream_id.is_multiple_of(2),
                            });
                    if closed {
                        if !end_headers {
                            return Err(Error::Http2(crate::error::H2Error::CompressionError));
                        }
                        self.decoder
                            .decode(&io.recv_buf[frag_start..data_end], |_, _| {})?;
                        io.drain_recv(total);
                        continue;
                    }
                    if is_new {
                        let ok = match self.role {
                            Role::Server => stream_id % 2 == 1,
                            Role::Client => false,
                        };
                        if !ok {
                            return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                        }
                    }

                    self.last_peer_stream_id = self.last_peer_stream_id.max(stream_id);
                    // RFC 9113 §5.1.2: a peer opening more streams than our
                    // advertised SETTINGS_MAX_CONCURRENT_STREAMS is a
                    // protocol violation; treat it as a connection error.
                    // Never fall through with the stream missing — pushing
                    // Headers/Finished events for a stream that was never
                    // created hands the application a request whose headers
                    // cannot be read (this produced bogus 405s).
                    if !self.ensure_stream(stream_id) {
                        return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                    }
                    if let Some(stream) = self.streams.iter_mut().find(|s| s.id == stream_id) {
                        if stream.state == H2StreamState::Idle {
                            stream.open();
                        }
                        stream.headers_data.clear();
                        // RFC 9113 §6.5.2 / §6.10 (CVE-2024-27316): bound the header
                        // block. The accumulation buffer (HDRBUF) caps the field
                        // section we will accept; if it overflows, reject the whole
                        // connection rather than silently truncating an
                        // attacker-controlled header set or accepting an unbounded
                        // CONTINUATION flood. Allocator exhaustion gets the same
                        // treatment — reject the connection, don't panic or truncate.
                        if stream
                            .headers_data
                            .buf_try_reserve(data_end - frag_start)
                            .is_err()
                            || stream
                                .headers_data
                                .extend_from_slice(&io.recv_buf[frag_start..data_end])
                                .is_err()
                        {
                            return Err(Error::Http2(crate::error::H2Error::EnhanceYourCalm));
                        }
                        if end_headers {
                            stream.headers_received = true;
                        }
                        if end_stream {
                            stream.recv_end_stream();
                        }
                    }
                    if !end_headers {
                        self.continuation_stream_id = Some(stream_id);
                    } else {
                        self.push_event(H2Event::Headers(stream_id));
                    }
                    if end_stream {
                        self.push_event(H2Event::Finished(stream_id));
                    }
                }
                FRAME_SETTINGS => {
                    if stream_id != 0 {
                        return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                    }
                    let ack = flags & FLAG_ACK != 0;
                    if ack {
                        if payload_len != 0 {
                            return Err(Error::Http2(crate::error::H2Error::FrameSizeError));
                        }
                        self.settings_ack_received = true;
                        if self.peer_settings_received && self.state == H2ConnState::WaitingSettings
                        {
                            self.state = H2ConnState::Active;
                            self.headers_phase_complete = true;
                            self.push_event(H2Event::Connected);
                        }
                    } else {
                        let old_initial = self.peer_settings.initial_window_size as i32;
                        frame::decode_settings_params(&io.recv_buf[ps..pe], |id, value| {
                            self.peer_settings.apply(id, value)
                        })?;
                        self.peer_settings_received = true;
                        self.send_settings_ack(io)?;
                        match self.state {
                            H2ConnState::WaitingPreface | H2ConnState::WaitingSettings => {
                                self.state = H2ConnState::Active;
                                self.headers_phase_complete = true;
                                self.push_event(H2Event::Connected);
                            }
                            _ => {}
                        }
                        let new_initial = self.peer_settings.initial_window_size as i32;
                        let delta = new_initial - old_initial;
                        if delta != 0 {
                            for stream in self.streams.iter_mut() {
                                // RFC 9113 §6.9.2: a window pushed above 2^31-1 by an
                                // INITIAL_WINDOW_SIZE change is a FLOW_CONTROL_ERROR,
                                // not an overflow panic / silent wrap.
                                stream.send_window = stream
                                    .send_window
                                    .checked_add(delta)
                                    .ok_or(Error::Http2(crate::error::H2Error::FlowControlError))?;
                            }
                        }
                    }
                }
                FRAME_WINDOW_UPDATE => {
                    if payload_len != 4 {
                        return Err(Error::InvalidState);
                    }
                    let increment = u32::from_be_bytes([
                        io.recv_buf[ps] & 0x7f,
                        io.recv_buf[ps + 1],
                        io.recv_buf[ps + 2],
                        io.recv_buf[ps + 3],
                    ]);
                    if increment == 0 {
                        return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                    }
                    if stream_id == 0 {
                        self.conn_send_fc.replenish(increment)?;
                    } else if let Some(stream) = self.get_stream_mut(stream_id) {
                        let new_window = stream.send_window as i64 + increment as i64;
                        if new_window > 0x7fff_ffff {
                            return Err(Error::Http2(crate::error::H2Error::FlowControlError));
                        }
                        stream.send_window = new_window as i32;
                    }
                }
                FRAME_PING => {
                    if stream_id != 0 {
                        return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                    }
                    if payload_len != 8 {
                        return Err(Error::Http2(crate::error::H2Error::FrameSizeError));
                    }
                    if flags & FLAG_ACK == 0 {
                        let mut data = [0u8; 8];
                        data.copy_from_slice(&io.recv_buf[ps..ps + 8]);
                        self.send_ping_ack(io, data)?;
                    }
                }
                FRAME_GOAWAY => {
                    if stream_id != 0 {
                        return Err(Error::InvalidState);
                    }
                    if payload_len < 8 {
                        return Err(Error::BufferTooSmall { needed: 8 });
                    }
                    let last_stream_id = u32::from_be_bytes([
                        io.recv_buf[ps] & 0x7f,
                        io.recv_buf[ps + 1],
                        io.recv_buf[ps + 2],
                        io.recv_buf[ps + 3],
                    ]) as u64;
                    let error_code = u32::from_be_bytes([
                        io.recv_buf[ps + 4],
                        io.recv_buf[ps + 5],
                        io.recv_buf[ps + 6],
                        io.recv_buf[ps + 7],
                    ]);
                    self.state = H2ConnState::Closing;
                    self.push_event(H2Event::GoAway(last_stream_id, error_code));
                }
                FRAME_RST_STREAM => {
                    if stream_id == 0 {
                        return Err(Error::InvalidState);
                    }
                    if payload_len != 4 {
                        return Err(Error::InvalidState);
                    }
                    let error_code = u32::from_be_bytes([
                        io.recv_buf[ps],
                        io.recv_buf[ps + 1],
                        io.recv_buf[ps + 2],
                        io.recv_buf[ps + 3],
                    ]);
                    // Defense in depth: if a DATA frame were mid-flight on this
                    // stream, switch the pump to discard mode (drain the payload
                    // off recv_buf, crediting the connection window). NOTE: with
                    // the current loop structure this cannot fire — process_recv
                    // never parses frames while partial_data is Some, so an RST
                    // behind a stalled pump is not reached until the app drains
                    // the body. An application that never drains therefore still
                    // wedges the connection; the recovery path for that (a body
                    // cancel/discard API or manager-wired timeouts) is an open
                    // follow-up.
                    if let Some(pd) = self.partial_data.as_mut() {
                        if pd.stream_id == stream_id {
                            pd.deliver = false;
                        }
                    }
                    // Drop any buffered-but-undrained body and credit the
                    // connection window for it (RFC 9113 §6.9.1), then reset.
                    let buffered = {
                        if let Some(stream) = self.get_stream_mut(stream_id) {
                            let b = stream.data_buf.len() as u32;
                            stream.data_buf.clear();
                            stream.data_available = false;
                            stream.reset();
                            b
                        } else {
                            0
                        }
                    };
                    if buffered > 0 {
                        self.send_window_update(io, 0, buffered);
                    }
                    self.push_event(H2Event::StreamReset(stream_id, error_code));
                }
                FRAME_PRIORITY => {}
                FRAME_CONTINUATION => {
                    if stream_id == 0 {
                        return Err(Error::Http2(crate::error::H2Error::ProtocolError));
                    }
                    let end_headers = flags & FLAG_END_HEADERS != 0;
                    if end_headers {
                        // Clear the contiguity latch even when the slot is
                        // gone (a stream reaped between its HEADERS and this
                        // CONTINUATION): leaving it set turns the next
                        // unrelated frame into a guaranteed ProtocolError
                        // connection kill.
                        self.continuation_stream_id = None;
                    }
                    if let Some(stream) = self.streams.iter_mut().find(|s| s.id == stream_id) {
                        // Bound the accumulated header block (see FRAME_HEADERS): an
                        // overflow here means a CONTINUATION flood or oversized field
                        // section — terminate rather than silently truncate. Allocator
                        // exhaustion terminates the same way.
                        if stream.headers_data.buf_try_reserve(pe - ps).is_err()
                            || stream
                                .headers_data
                                .extend_from_slice(&io.recv_buf[ps..pe])
                                .is_err()
                        {
                            return Err(Error::Http2(crate::error::H2Error::EnhanceYourCalm));
                        }
                        if end_headers {
                            stream.headers_received = true;
                            self.push_event(H2Event::Headers(stream_id));
                        }
                    }
                }
                FRAME_PUSH_PROMISE => {}
                _ => {}
            }

            io.drain_recv(total);
        }

        self.streams.retain(|s| {
            // Keep Closed streams that still have something for the
            // application: undelivered body data, unread headers (a complete
            // response followed by RST_STREAM NO_ERROR — RFC 9113 §8.1's
            // reject-without-reading pattern — closes the stream in the same
            // feed that delivered the headers; the response must survive
            // until read), or a deferred RST_STREAM (discard_body under a
            // full send buffer) that must go out before the slot is reused.
            s.state != H2StreamState::Closed
                || s.data_available
                || s.headers_received
                || s.pending_rst.is_some()
        });

        Ok(())
    }

    fn validate_client_preface<const BUF: usize>(
        &mut self,
        io: &mut H2Io<'_, BUF>,
    ) -> Result<(), Error> {
        let expected = CONNECTION_PREFACE;
        let remaining_preface = &expected[self.preface_bytes_seen..];
        let check_len = remaining_preface.len().min(io.recv_buf.len());

        for i in 0..check_len {
            if io.recv_buf[i] != remaining_preface[i] {
                return Err(Error::InvalidState);
            }
        }

        self.preface_bytes_seen += check_len;
        if check_len > 0 {
            io.drain_recv(check_len);
        }

        if self.preface_bytes_seen >= expected.len() {
            self.preface_validated = true;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Stream management
    // ------------------------------------------------------------------

    /// Ensure a stream exists, creating it if there is capacity. Returns
    /// `false` if the stream does not exist and cannot be created
    /// (`MAX_STREAMS` live streams even after reclaiming closed ones).
    fn ensure_stream(&mut self, stream_id: u64) -> bool {
        if self.streams.iter().any(|s| s.id == stream_id) {
            return true;
        }
        if self.streams.len() >= MAX_STREAMS {
            // `process_recv` only sweeps closed streams after the whole
            // batch, so a burst that opens, completes, and is followed by
            // more HEADERS still holds slots here. Closed streams do not
            // count toward the peer's advertised concurrency (RFC 9113
            // §5.1.2) and must not hold capacity against new ones — reclaim
            // them before refusing. Same predicate as the post-batch sweep:
            // closed streams still carrying something for the application
            // (undelivered body, unread headers, a deferred RST) survive.
            self.streams.retain(|s| {
                s.state != H2StreamState::Closed
                    || s.data_available
                    || s.headers_received
                    || s.pending_rst.is_some()
            });
        }
        if self.streams.len() >= MAX_STREAMS {
            return false;
        }
        let initial_send = self.peer_settings.initial_window_size as i32;
        let initial_recv = self.local_settings.initial_window_size as i32;
        let _ = self
            .streams
            .push(H2Stream::new(stream_id, initial_send, initial_recv));
        true
    }

    fn get_stream(&self, stream_id: u64) -> Option<&H2Stream<HDRBUF, DATABUF>> {
        self.streams.iter().find(|s| s.id == stream_id)
    }

    fn get_stream_mut(&mut self, stream_id: u64) -> Option<&mut H2Stream<HDRBUF, DATABUF>> {
        self.streams.iter_mut().find(|s| s.id == stream_id)
    }

    /// Whether the connection is in Active state.
    pub fn is_active(&self) -> bool {
        self.state == H2ConnState::Active
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
        if self.state == H2ConnState::Closed {
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

    /// Check timeouts. If a timeout fires, queues a GOAWAY frame, transitions
    /// to Closed, and emits `H2Event::Timeout`.
    pub fn handle_timeout<const BUF: usize>(&mut self, io: &mut H2Io<'_, BUF>, now: u64) {
        if self.state == H2ConnState::Closed {
            return;
        }

        if !self.headers_phase_complete {
            if let Some(hdr_us) = self.timeout_config.header_timeout_us {
                if now >= self.connection_start.saturating_add(hdr_us) {
                    let _ = self.send_goaway(io, 0);
                    self.state = H2ConnState::Closed;
                    self.push_event(H2Event::Timeout);
                    return;
                }
            }
        }

        // Idle timeout
        if let Some(idle_us) = self.timeout_config.idle_timeout_us {
            if now >= self.last_activity.saturating_add(idle_us) {
                let _ = self.send_goaway(io, 0);
                self.state = H2ConnState::Closed;
                self.push_event(H2Event::Timeout);
            }
        }
    }

    /// Feed data with timestamp tracking. Updates `last_activity` then calls
    /// `feed_data`.
    ///
    /// Only non-empty feeds count as activity: the runner re-drives a
    /// backpressured connection with empty feeds every poll cycle, and a
    /// wedged connection (body never drained) must not refresh its own idle
    /// clock through those — the idle timeout is exactly the backstop that
    /// reaps it.
    pub fn feed_data_timed<const BUF: usize>(
        &mut self,
        io: &mut H2Io<'_, BUF>,
        data: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        if !data.is_empty() {
            self.last_activity = now;
        }
        self.feed_data(io, data)
    }

    /// Record peer receive activity at `now` (µs), refreshing the idle clock.
    ///
    /// For the TLS compositions (`h2_tls`, `https1`): decrypted plaintext
    /// reaches this layer through the shared `recv_buf`, so their
    /// `feed_data_timed` calls always pass an empty `data` slice and the
    /// non-empty guard in [`Self::feed_data_timed`] never fires. The wrapper
    /// calls this instead whenever it fed non-empty ciphertext that the TLS
    /// layer accepted — the RFC 9000 §10.1 receive rule (restart the idle
    /// timer on a packet received and processed successfully). Empty runner
    /// re-drives still don't refresh, so a wedged connection (body never
    /// drained → reads backpressured) is still reaped by the idle timeout.
    ///
    /// Without this, `last_activity` froze at accept and the idle timeout
    /// acted as an absolute connection lifetime: every h2-over-TLS transfer
    /// longer than the timeout died mid-flight at exactly `accept + idle`
    /// (KalogonTech/Raven-Firmware#80 — 95 s OTA uploads GOAWAY'd at 60 s).
    pub fn note_recv_activity(&mut self, now: u64) {
        self.last_activity = now;
    }

    /// Whether the connection has been closed (GOAWAY sent/received, or timeout).
    pub fn is_closed(&self) -> bool {
        matches!(self.state, H2ConnState::Closed | H2ConnState::Closing)
    }

    /// Whether the SETTINGS exchange is complete and the connection is usable.
    pub fn is_established(&self) -> bool {
        self.state == H2ConnState::Active
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::io::H2IoBufs;
    use super::*;

    #[test]
    fn client_generates_preface() {
        let mut conn = H2Connection::<16>::new_client();
        let mut io = H2IoBufs::<4096>::new();
        let mut buf = [0u8; 4096];
        let output = conn.poll_output(&mut io.as_io(), &mut buf);
        assert!(output.is_some());
        let data = output.unwrap();
        assert!(data.starts_with(CONNECTION_PREFACE));
        let after_preface = &data[CONNECTION_PREFACE.len()..];
        assert!(after_preface.len() >= 9);
        assert_eq!(after_preface[3], FRAME_SETTINGS);
    }

    #[test]
    fn server_generates_settings_only() {
        let mut conn = H2Connection::<16>::new_server();
        let mut io = H2IoBufs::<4096>::new();
        let mut buf = [0u8; 4096];
        let output = conn.poll_output(&mut io.as_io(), &mut buf);
        assert!(output.is_some());
        let data = output.unwrap();
        assert_eq!(data[3], FRAME_SETTINGS);
    }

    #[test]
    fn client_server_handshake() {
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<8192>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<8192>::new();

        // Client → Server
        let mut buf = [0u8; 4096];
        let data = client.poll_output(&mut cio.as_io(), &mut buf).unwrap();
        let client_data: heapless::Vec<u8, 4096> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(data);
            v
        };
        server.feed_data(&mut sio.as_io(), &client_data).unwrap();

        // Server → Client
        let mut buf2 = [0u8; 4096];
        let data = server.poll_output(&mut sio.as_io(), &mut buf2).unwrap();
        let server_data: heapless::Vec<u8, 4096> = {
            let mut v = heapless::Vec::new();
            let _ = v.extend_from_slice(data);
            v
        };
        client.feed_data(&mut cio.as_io(), &server_data).unwrap();

        // Client should get Connected event
        let mut client_connected = false;
        while let Some(ev) = client.poll_event() {
            if ev == H2Event::Connected {
                client_connected = true;
            }
        }
        assert!(client_connected);

        // Client sends SETTINGS ACK back
        let mut buf3 = [0u8; 4096];
        if let Some(data) = client.poll_output(&mut cio.as_io(), &mut buf3) {
            let ack_data: heapless::Vec<u8, 4096> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(data);
                v
            };
            server.feed_data(&mut sio.as_io(), &ack_data).unwrap();
        }

        // Server should get Connected event
        let mut server_connected = false;
        while let Some(ev) = server.poll_event() {
            if ev == H2Event::Connected {
                server_connected = true;
            }
        }
        assert!(server_connected);
    }

    #[test]
    fn full_request_response() {
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<16384>::new();

        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        // Client sends request
        let stream_id = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"GET"),
                    (b":path", b"/"),
                    (b":scheme", b"https"),
                    (b":authority", b"example.com"),
                ],
                true,
            )
            .unwrap();
        assert_eq!(stream_id, 1);

        exchange(&mut client, &mut cio, &mut server, &mut sio);

        // Server should see Headers
        let mut got_headers = false;
        let mut header_stream = 0u64;
        while let Some(ev) = server.poll_event() {
            if let H2Event::Headers(sid) = ev {
                got_headers = true;
                header_stream = sid;
            }
        }
        assert!(got_headers);

        // Server reads headers
        let mut method = heapless::Vec::<u8, 64>::new();
        server
            .recv_headers(header_stream, |name, value| {
                if name == b":method" {
                    let _ = method.extend_from_slice(value);
                }
            })
            .unwrap();
        assert_eq!(method.as_slice(), b"GET");

        // Server sends response
        server
            .send_headers(
                &mut sio.as_io(),
                header_stream,
                &[(b":status", b"200"), (b"content-type", b"text/plain")],
                false,
            )
            .unwrap();
        server
            .send_data(&mut sio.as_io(), header_stream, b"Hello!", true)
            .unwrap();

        exchange(&mut server, &mut sio, &mut client, &mut cio);

        // Client should see response
        let mut got_resp = false;
        let mut got_data = false;
        while let Some(ev) = client.poll_event() {
            match ev {
                H2Event::Headers(sid) if sid == stream_id => got_resp = true,
                H2Event::Data(sid) if sid == stream_id => got_data = true,
                _ => {}
            }
        }
        assert!(got_resp);
        assert!(got_data);

        // Client reads response body
        let mut body = [0u8; 256];
        let (n, fin) = client
            .recv_body(&mut cio.as_io(), stream_id, &mut body)
            .unwrap();
        assert_eq!(&body[..n], b"Hello!");
        assert!(fin);
    }

    #[test]
    fn ping_pong() {
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<8192>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<8192>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        // Client sends PING by injecting raw frame into send_buf
        let ping_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let frame = H2Frame::Ping {
            data: ping_data,
            ack: false,
        };
        let mut buf = [0u8; 32];
        let n = frame::encode_frame(&frame, &mut buf).unwrap();
        cio.as_io().queue_send(&buf[..n]).unwrap();

        exchange(&mut client, &mut cio, &mut server, &mut sio);

        // Server should have sent PING ACK
        let mut buf2 = [0u8; 4096];
        if let Some(data) = server.poll_output(&mut sio.as_io(), &mut buf2) {
            let copy: heapless::Vec<u8, 4096> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(data);
                v
            };
            client.feed_data(&mut cio.as_io(), &copy).unwrap();
        }
    }

    #[test]
    fn goaway() {
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<8192>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<8192>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        server.send_goaway(&mut sio.as_io(), 0).unwrap();
        exchange(&mut server, &mut sio, &mut client, &mut cio);

        let mut got_goaway = false;
        while let Some(ev) = client.poll_event() {
            if let H2Event::GoAway(_, _) = ev {
                got_goaway = true;
            }
        }
        assert!(got_goaway);
    }

    // Test helpers

    fn run_handshake<const M: usize, const BUF: usize, const H: usize, const D: usize>(
        client: &mut H2Connection<M, H, D>,
        cio: &mut H2IoBufs<BUF>,
        server: &mut H2Connection<M, H, D>,
        sio: &mut H2IoBufs<BUF>,
    ) {
        for _ in 0..5 {
            exchange(client, cio, server, sio);
            exchange(server, sio, client, cio);
        }
    }

    fn exchange<const M: usize, const BUF: usize, const H: usize, const D: usize>(
        sender: &mut H2Connection<M, H, D>,
        sender_io: &mut H2IoBufs<BUF>,
        receiver: &mut H2Connection<M, H, D>,
        receiver_io: &mut H2IoBufs<BUF>,
    ) {
        let mut buf = [0u8; 8192];
        while let Some(data) = sender.poll_output(&mut sender_io.as_io(), &mut buf) {
            let copy: heapless::Vec<u8, 8192> = {
                let mut v = heapless::Vec::new();
                let _ = v.extend_from_slice(data);
                v
            };
            let _ = receiver.feed_data(&mut receiver_io.as_io(), &copy);
        }
    }

    // ====== Stream-capacity tests ======

    /// The server's initial SETTINGS must advertise the real `MAX_STREAMS`
    /// (RFC 9113 §6.5.2). Advertising the old default of 128 over a smaller
    /// stream table let compliant clients open streams the table refused.
    #[test]
    fn server_advertises_true_stream_capacity() {
        let mut server = H2Connection::<4>::new_server();
        let mut io = H2IoBufs::<4096>::new();
        let mut buf = [0u8; 4096];
        let data = server.poll_output(&mut io.as_io(), &mut buf).unwrap();
        // First frame is SETTINGS; walk its parameters.
        assert_eq!(data[3], FRAME_SETTINGS);
        let len = u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize;
        let mut advertised = None;
        frame::decode_settings_params(&data[9..9 + len], |id, value| {
            if id == SETTINGS_MAX_CONCURRENT_STREAMS {
                advertised = Some(value);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(advertised, Some(4));
    }

    /// Regression for the field 405s: a burst of requests that open, complete,
    /// and close — with no further inbound data to trigger the post-batch
    /// sweep — must not hold stream-table capacity against the next request.
    /// Before the fix, the (MAX_STREAMS+1)-th stream was silently refused but
    /// its Headers event still fired, so the application routed a request
    /// whose headers were unreadable.
    #[test]
    fn closed_streams_are_reclaimed_for_new_ones_within_capacity() {
        let mut client = H2Connection::<4>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<4>::new_server();
        let mut sio = H2IoBufs::<16384>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);
        while client.poll_event().is_some() {}
        while server.poll_event().is_some() {}

        let req: &[(&[u8], &[u8])] = &[
            (b":method", b"GET"),
            (b":path", b"/"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
        ];

        // Burst 1: fill the stream table, respond to everything (streams
        // close server-side, but nothing arrives afterwards to sweep them).
        let mut burst = heapless::Vec::<u64, 4>::new();
        for _ in 0..4 {
            burst
                .push(client.open_stream(&mut cio.as_io(), req, true).unwrap())
                .unwrap();
        }
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        while let Some(ev) = server.poll_event() {
            if let H2Event::Headers(sid) = ev {
                server.recv_headers(sid, |_, _| {}).unwrap();
                server
                    .send_headers(&mut sio.as_io(), sid, &[(b":status", b"200")], true)
                    .unwrap();
            }
        }
        exchange(&mut server, &mut sio, &mut client, &mut cio);
        // Consume the responses client-side: a closed stream with unread
        // headers is deliberately NOT reclaimable (the application hasn't
        // seen its response yet), so the client must read them for its own
        // slots to free.
        while let Some(ev) = client.poll_event() {
            if let H2Event::Headers(sid) = ev {
                client.recv_headers(sid, |_, _| {}).unwrap();
            }
        }

        // Burst 2: one more request. All four table slots hold closed
        // streams; the new one must displace them, and its headers must be
        // readable when the Headers event is consumed.
        let sid = client.open_stream(&mut cio.as_io(), req, true).unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        let mut got = false;
        while let Some(ev) = server.poll_event() {
            if let H2Event::Headers(s) = ev {
                assert_eq!(s, sid);
                let mut method = heapless::Vec::<u8, 16>::new();
                server
                    .recv_headers(s, |name, value| {
                        if name == b":method" {
                            let _ = method.extend_from_slice(value);
                        }
                    })
                    .expect("headers must be readable for an accepted stream");
                assert_eq!(method.as_slice(), b"GET");
                got = true;
            }
        }
        assert!(got, "server never saw the post-burst request");
    }

    /// A peer that exceeds the advertised SETTINGS_MAX_CONCURRENT_STREAMS with
    /// genuinely live (unanswered) streams is a protocol violation — the
    /// connection errors instead of emitting events for a stream that was
    /// never created (RFC 9113 §5.1.2).
    #[test]
    fn exceeding_advertised_stream_limit_is_a_connection_error() {
        // Client table is larger than the server's so the client *can*
        // violate the server's limit; the generic-bound helpers require equal
        // shapes, so the exchange is hand-rolled.
        let mut client = H2Connection::<8>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<2>::new_server();
        let mut sio = H2IoBufs::<16384>::new();

        let mut buf = [0u8; 8192];
        for _ in 0..5 {
            while let Some(data) = client.poll_output(&mut cio.as_io(), &mut buf) {
                let mut v = heapless::Vec::<u8, 8192>::new();
                v.extend_from_slice(data).unwrap();
                server.feed_data(&mut sio.as_io(), &v).unwrap();
            }
            while let Some(data) = server.poll_output(&mut sio.as_io(), &mut buf) {
                let mut v = heapless::Vec::<u8, 8192>::new();
                v.extend_from_slice(data).unwrap();
                client.feed_data(&mut cio.as_io(), &v).unwrap();
            }
        }

        let req: &[(&[u8], &[u8])] = &[
            (b":method", b"GET"),
            (b":path", b"/"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
        ];
        // Three concurrent (unanswered) requests against an advertised limit
        // of two.
        for _ in 0..3 {
            client.open_stream(&mut cio.as_io(), req, true).unwrap();
        }
        let mut result = Ok(());
        while let Some(data) = client.poll_output(&mut cio.as_io(), &mut buf) {
            let mut v = heapless::Vec::<u8, 8192>::new();
            v.extend_from_slice(data).unwrap();
            result = server.feed_data(&mut sio.as_io(), &v);
            if result.is_err() {
                break;
            }
        }
        assert!(
            matches!(
                result,
                Err(Error::Http2(crate::error::H2Error::ProtocolError))
            ),
            "expected connection-level protocol error, got {result:?}"
        );
    }

    // ====== Timeout + Connection State Tests ======

    #[test]
    fn idle_timeout_fires() {
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<8192>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<8192>::new();

        let config = crate::http::TimeoutConfig {
            idle_timeout_us: Some(1_000_000),
            header_timeout_us: None,
        };
        server.set_timeouts(config, 0);
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        server.handle_timeout(&mut sio.as_io(), 2_000_000);

        let mut got_timeout = false;
        while let Some(ev) = server.poll_event() {
            if ev == H2Event::Timeout {
                got_timeout = true;
            }
        }
        assert!(got_timeout);
        assert!(server.is_closed());
    }

    #[test]
    fn header_timeout_fires_during_preface() {
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<8192>::new();

        let config = crate::http::TimeoutConfig {
            idle_timeout_us: None,
            header_timeout_us: Some(500_000),
        };
        server.set_timeouts(config, 0);

        server.handle_timeout(&mut sio.as_io(), 600_000);

        let mut got_timeout = false;
        while let Some(ev) = server.poll_event() {
            if ev == H2Event::Timeout {
                got_timeout = true;
            }
        }
        assert!(got_timeout);
        assert!(server.is_closed());
    }

    #[test]
    fn activity_resets_idle_timer() {
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<8192>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<8192>::new();

        let config = crate::http::TimeoutConfig {
            idle_timeout_us: Some(1_000_000),
            header_timeout_us: None,
        };
        server.set_timeouts(config, 0);
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        // Activity at t=800ms. Must be real bytes: empty feeds (the runner's
        // backpressure re-drives) deliberately do not count as activity.
        let ping = [0u8, 0, 8, 0x6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        server
            .feed_data_timed(&mut sio.as_io(), &ping, 800_000)
            .unwrap();

        // Check at t=1.5s — should NOT timeout
        server.handle_timeout(&mut sio.as_io(), 1_500_000);
        assert!(!server.is_closed());

        // Check at t=2s — SHOULD timeout
        server.handle_timeout(&mut sio.as_io(), 2_000_000);
        assert!(server.is_closed());
    }

    #[test]
    fn is_closed_and_is_established() {
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<8192>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<8192>::new();

        assert!(!server.is_established());
        assert!(!server.is_closed());

        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        assert!(server.is_established());
        assert!(!server.is_closed());

        server.send_goaway(&mut sio.as_io(), 0).unwrap();
        assert!(!server.is_established());
        assert!(server.is_closed());
    }

    #[test]
    fn next_timeout_returns_correct_deadline() {
        let mut server = H2Connection::<16>::new_server();

        assert_eq!(server.next_timeout(), None);

        let config = crate::http::TimeoutConfig {
            idle_timeout_us: Some(1_000_000),
            header_timeout_us: Some(500_000),
        };
        server.set_timeouts(config, 100_000);

        assert_eq!(server.next_timeout(), Some(600_000));
    }

    // ====== Item 1: Timeout Integration Tests ======

    #[test]
    fn timeout_idle_after_request_response() {
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<32768>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<32768>::new();

        let config = crate::http::TimeoutConfig {
            idle_timeout_us: Some(1_000_000),
            header_timeout_us: None,
        };
        server.set_timeouts(config, 0);

        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let stream_id = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"GET"),
                    (b":path", b"/"),
                    (b":scheme", b"https"),
                    (b":authority", b"example.com"),
                ],
                true,
            )
            .unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);

        while let Some(_) = server.poll_event() {}

        server
            .send_headers(&mut sio.as_io(), stream_id, &[(b":status", b"200")], true)
            .unwrap();
        exchange(&mut server, &mut sio, &mut client, &mut cio);

        while let Some(_) = client.poll_event() {}

        server.handle_timeout(&mut sio.as_io(), 2_000_000);

        let mut got_timeout = false;
        while let Some(ev) = server.poll_event() {
            if ev == H2Event::Timeout {
                got_timeout = true;
            }
        }
        assert!(got_timeout, "server should emit Timeout after idle");
        assert!(server.is_closed());
    }

    #[test]
    fn timeout_client_header_timeout() {
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<8192>::new();

        let config = crate::http::TimeoutConfig {
            idle_timeout_us: None,
            header_timeout_us: Some(500_000),
        };
        client.set_timeouts(config, 0);

        client.handle_timeout(&mut cio.as_io(), 600_000);

        let mut got_timeout = false;
        while let Some(ev) = client.poll_event() {
            if ev == H2Event::Timeout {
                got_timeout = true;
            }
        }
        assert!(got_timeout, "client should emit Timeout for header timeout");
        assert!(client.is_closed());
    }

    // ====== Item 2: Flow Control Tests ======

    #[test]
    fn send_data_blocked_by_flow_control() {
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<32768>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<32768>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let stream_id = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"POST"),
                    (b":path", b"/"),
                    (b":scheme", b"https"),
                    (b":authority", b"example.com"),
                ],
                false,
            )
            .unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        while let Some(_) = server.poll_event() {}

        // The client's stream send window equals the server's advertised
        // SETTINGS_INITIAL_WINDOW_SIZE, which is now DATABUF (see
        // H2Connection::new), not the RFC default of 65535.
        const WINDOW: usize = 4096;
        let chunk = [0u8; 16384];
        let mut total_sent = 0usize;
        while total_sent < WINDOW {
            let remaining = WINDOW - total_sent;
            let to_send = remaining.min(16384);
            let n = client
                .send_data(&mut cio.as_io(), stream_id, &chunk[..to_send], false)
                .unwrap();
            total_sent += n;
            exchange(&mut client, &mut cio, &mut server, &mut sio);
        }
        assert_eq!(total_sent, WINDOW);

        let result = client.send_data(&mut cio.as_io(), stream_id, &[0u8; 1], false);
        assert_eq!(result, Err(Error::WouldBlock));
    }

    #[test]
    fn send_capacity_tracks_windows_and_stream_state() {
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<32768>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<32768>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let stream_id = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"POST"),
                    (b":path", b"/"),
                    (b":scheme", b"https"),
                    (b":authority", b"example.com"),
                ],
                false,
            )
            .unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        while let Some(_) = server.poll_event() {}

        // Fresh stream: bounded by the server's advertised stream window
        // (DATABUF = 4096), below the connection window and max frame size.
        assert_eq!(client.send_capacity(stream_id), Some(4096));
        // A stream that was never opened cannot send at all.
        assert_eq!(client.send_capacity(stream_id + 2), None);

        let chunk = [0u8; 4096];
        assert_eq!(
            client
                .send_data(&mut cio.as_io(), stream_id, &chunk[..4000], false)
                .unwrap(),
            4000
        );
        assert_eq!(client.send_capacity(stream_id), Some(96));

        // Exhausted window: capacity is a closed window (Some(0)), which is
        // exactly what send_data would refuse with WouldBlock.
        assert_eq!(
            client
                .send_data(&mut cio.as_io(), stream_id, &chunk[..96], false)
                .unwrap(),
            96
        );
        assert_eq!(client.send_capacity(stream_id), Some(0));
        assert_eq!(
            client.send_data(&mut cio.as_io(), stream_id, &[0u8; 1], false),
            Err(Error::WouldBlock)
        );

        // Ending our side leaves the stream unsendable: None, not Some(0).
        client
            .send_data(&mut cio.as_io(), stream_id, &[], true)
            .unwrap();
        assert_eq!(client.send_capacity(stream_id), None);
    }

    #[test]
    fn send_data_resumes_after_window_update() {
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<32768>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<32768>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let stream_id = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"POST"),
                    (b":path", b"/"),
                    (b":scheme", b"https"),
                    (b":authority", b"example.com"),
                ],
                false,
            )
            .unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        while let Some(_) = server.poll_event() {}

        // Stream send window = server's advertised window = DATABUF (see
        // H2Connection::new), not the RFC default of 65535.
        const WINDOW: usize = 4096;
        let chunk = [0u8; 16384];
        let mut total_sent = 0usize;
        while total_sent < WINDOW {
            let remaining = WINDOW - total_sent;
            let to_send = remaining.min(16384);
            let n = client
                .send_data(&mut cio.as_io(), stream_id, &chunk[..to_send], false)
                .unwrap();
            total_sent += n;
            exchange(&mut client, &mut cio, &mut server, &mut sio);
        }
        assert_eq!(
            client.send_data(&mut cio.as_io(), stream_id, &[0u8; 1], false),
            Err(Error::WouldBlock)
        );

        // Inject WINDOW_UPDATE frames
        let wu_stream = H2Frame::WindowUpdate {
            stream_id,
            increment: 1024,
        };
        let wu_conn = H2Frame::WindowUpdate {
            stream_id: 0,
            increment: 1024,
        };
        let mut buf = [0u8; 16];

        let n = frame::encode_frame(&wu_stream, &mut buf).unwrap();
        client.feed_data(&mut cio.as_io(), &buf[..n]).unwrap();

        let n = frame::encode_frame(&wu_conn, &mut buf).unwrap();
        client.feed_data(&mut cio.as_io(), &buf[..n]).unwrap();

        let result = client.send_data(&mut cio.as_io(), stream_id, &[0u8; 1024], true);
        assert_eq!(result, Ok(1024));
    }

    #[test]
    fn large_body_paced_by_flow_control_no_drops() {
        // A request body several times larger than the per-stream receive
        // window must arrive intact. The server advertises a window equal to
        // its per-stream `data_buf` (see H2Connection::new) and credits
        // WINDOW_UPDATE only as it drains via `recv_body`, so the client is
        // paced to the server's consumption rate and never overruns the
        // buffer. Before the window/DATABUF fix, the client would send up to
        // the 65535 default and the server silently dropped everything past
        // 4 KB.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<16384>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let stream_id = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"POST"),
                    (b":path", b"/system/update"),
                    (b":scheme", b"https"),
                    (b":authority", b"example.com"),
                ],
                false,
            )
            .unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        while server.poll_event().is_some() {}

        // Position-dependent payload spanning multiple windows so a drop or
        // reorder is caught by the content comparison.
        const TOTAL: usize = 4096 * 3 + 1234;
        let payload: alloc::vec::Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();

        let mut sent = 0usize;
        let mut closed = false;
        let mut finished = false;
        let mut received: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let mut drain = [0u8; 1024];

        // Pump: client sends as the window allows; server drains (crediting
        // WINDOW_UPDATE); credits flow back via exchange. The iteration bound
        // guards against a regression where the window never reopens (deadlock).
        for _ in 0..2000 {
            if sent < TOTAL {
                match client.send_data(&mut cio.as_io(), stream_id, &payload[sent..], false) {
                    Ok(n) => sent += n,
                    Err(Error::WouldBlock) => {}
                    Err(e) => panic!("send_data failed: {:?}", e),
                }
            } else if !closed {
                client
                    .send_data(&mut cio.as_io(), stream_id, &[], true)
                    .unwrap();
                closed = true;
            }

            exchange(&mut client, &mut cio, &mut server, &mut sio);
            while server.poll_event().is_some() {}

            loop {
                match server.recv_body(&mut sio.as_io(), stream_id, &mut drain) {
                    Ok((0, true)) => {
                        finished = true;
                        break;
                    }
                    Ok((0, false)) => break,
                    Ok((n, fin)) => {
                        received.extend_from_slice(&drain[..n]);
                        if fin {
                            finished = true;
                            break;
                        }
                    }
                    Err(Error::WouldBlock) => break,
                    Err(e) => panic!("recv_body failed: {:?}", e),
                }
            }

            // Deliver WINDOW_UPDATE credits (and anything else) back to client.
            exchange(&mut server, &mut sio, &mut client, &mut cio);

            if finished && closed {
                break;
            }
        }

        assert!(finished, "server never observed end of stream");
        assert_eq!(sent, TOTAL, "client did not send the whole body");
        assert_eq!(
            received.len(),
            TOTAL,
            "received byte count != sent (data dropped under flow control)"
        );
        assert_eq!(received, payload, "received body content mismatch");
    }

    #[test]
    fn window_update_deferred_when_send_buffer_full_not_dropped() {
        // Regression: with a full send buffer, recv_body must DEFER the
        // WINDOW_UPDATE (leaving the advertised recv_window unchanged) rather
        // than drop the frame while crediting the window anyway. The old code
        // ignored the queue_send result but still advanced recv_window, so a
        // full buffer desynced our window from the peer's view and stalled the
        // upload forever (peer waits for credit it never receives -> no more
        // DATA -> nothing drives a retry). The deferred credit must flush from
        // generate_output once the buffer drains.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<16384>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let stream_id = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"POST"),
                    (b":path", b"/system/update"),
                    (b":scheme", b"https"),
                    (b":authority", b"example.com"),
                ],
                false,
            )
            .unwrap();
        let chunk = [0xABu8; 1000];
        client
            .send_data(&mut cio.as_io(), stream_id, &chunk, false)
            .unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        while server.poll_event().is_some() {}

        let recv_window_before = server
            .streams
            .iter()
            .find(|s| s.id == stream_id)
            .unwrap()
            .recv_window;

        // Fill the server's send buffer so the WINDOW_UPDATE cannot be queued.
        let filler = [0u8; 16384];
        let used = sio.send_buf.len();
        sio.send_buf
            .extend_from_slice(&filler[..16384 - used])
            .unwrap();

        // Drain the body. The credit wants to go out but the buffer is full.
        let mut buf = [0u8; 2048];
        let (n, _fin) = server
            .recv_body(&mut sio.as_io(), stream_id, &mut buf)
            .unwrap();
        assert_eq!(n, 1000);

        // Credit deferred, advertised window unchanged, nothing silently dropped.
        let stream = server.streams.iter().find(|s| s.id == stream_id).unwrap();
        assert_eq!(
            stream.recv_window, recv_window_before,
            "recv_window must not advance while the WINDOW_UPDATE is deferred"
        );
        assert!(
            stream.pending_recv_credit >= 1000,
            "stream credit should be pending"
        );
        assert!(
            server.pending_conn_credit >= 1000,
            "conn credit should be pending"
        );

        // Drain the buffer; generate_output should now emit the deferred credit.
        sio.send_buf.clear();
        server.generate_output(&mut sio.as_io());

        let stream = server.streams.iter().find(|s| s.id == stream_id).unwrap();
        assert_eq!(
            stream.pending_recv_credit, 0,
            "pending stream credit flushed"
        );
        assert_eq!(server.pending_conn_credit, 0, "pending conn credit flushed");
        assert_eq!(
            stream.recv_window,
            recv_window_before + 1000,
            "window advances only after the WINDOW_UPDATE is actually sent"
        );
        assert!(
            !sio.send_buf.is_empty(),
            "WINDOW_UPDATE emitted after buffer drained"
        );
    }

    #[test]
    fn server_accepts_eager_max_size_data_frame() {
        // A client may legally send a full SETTINGS_MAX_FRAME_SIZE (16384) DATA
        // frame on a freshly opened stream before it has processed our SETTINGS
        // — RFC 9113 §6.9.2 lets it assume the 65535 default stream window. The
        // server advertises stream window = DATABUF (H2Connection::new), so
        // DATABUF must be >= 16384 to accept that eager in-flight data instead
        // of rejecting it with FLOW_CONTROL_ERROR. A 4096 DATABUF reproduced the
        // observed h2-firmware-upload death on hardware (curl/nghttp2 sends a
        // ~16 KB DATA frame up front). Model the production server's buffer
        // sizing: DATABUF = 16384 (matches H2TlsServer's default).
        let mut client = H2Connection::<16, 2048, 16384>::new_client();
        let mut cio = H2IoBufs::<32768>::new();
        let mut server = H2Connection::<16, 2048, 16384>::new_server();
        let mut sio = H2IoBufs::<32768>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let sid = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"POST"),
                    (b":path", b"/system/update"),
                    (b":scheme", b"https"),
                    (b":authority", b"x"),
                ],
                false,
            )
            .unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        while server.poll_event().is_some() {}

        // Hand-craft a raw 16384-byte DATA frame on the stream (bypasses the
        // client's own send-window check, modelling the pre-SETTINGS race).
        const PAYLOAD: usize = 16384;
        let mut frame: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(9 + PAYLOAD);
        frame.push((PAYLOAD >> 16) as u8);
        frame.push((PAYLOAD >> 8) as u8);
        frame.push(PAYLOAD as u8);
        frame.push(0); // type = DATA
        frame.push(0); // flags
        frame.extend_from_slice(&(sid as u32).to_be_bytes());
        frame.extend_from_slice(&[0xAAu8; PAYLOAD]);

        let result = server.feed_data(&mut sio.as_io(), &frame);
        assert_eq!(
            result,
            Ok(()),
            "server accepts a max-size (16384) DATA frame within its advertised window"
        );

        // The full payload is buffered and drainable via recv_body. The frame
        // carried no END_STREAM, so recv_body yields WouldBlock once drained.
        let mut sink = alloc::vec::Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match server.recv_body(&mut sio.as_io(), sid, &mut chunk) {
                Ok((0, _)) => break,
                Ok((n, _)) => sink.extend_from_slice(&chunk[..n]),
                Err(Error::WouldBlock) => break,
                Err(e) => panic!("recv_body failed: {e:?}"),
            }
        }
        assert_eq!(sink.len(), PAYLOAD, "all 16384 body bytes delivered");
        assert!(sink.iter().all(|&b| b == 0xAA), "body bytes intact");
    }

    #[test]
    fn incremental_data_backpressures_small_databuf_and_delivers_all() {
        // With a small DATABUF (4096) the pump must stream a max-size (16384)
        // DATA frame into data_buf incrementally: fill to capacity, stop
        // (leaving the rest parked in recv_buf), and resume once the consumer
        // drains via recv_body. This is the runner's TCP-backpressure path —
        // here we model it by re-driving with feed_data(&[]) after each drain.
        // data_buf must never exceed DATABUF, and the whole body must arrive.
        const DATABUF: usize = 4096;
        let mut client = H2Connection::<16, 2048, DATABUF>::new_client();
        let mut cio = H2IoBufs::<40960>::new();
        let mut server = H2Connection::<16, 2048, DATABUF>::new_server();
        let mut sio = H2IoBufs::<40960>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let sid = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"POST"),
                    (b":path", b"/system/update"),
                    (b":scheme", b"https"),
                    (b":authority", b"x"),
                ],
                false,
            )
            .unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        while server.poll_event().is_some() {}

        // Model the pre-SETTINGS-ack state: a peer that has not yet processed
        // our SETTINGS may use the RFC-default 65535 window and burst a
        // full-size (16384) DATA frame that exceeds our advertised DATABUF
        // window (RFC 9113 §6.9.2). Our stream-window enforcement is gated on
        // settings_ack_received, so clear it to exercise that legal burst — the
        // backpressure path, not a FLOW_CONTROL_ERROR.
        server.settings_ack_received = false;

        // Hand-craft one max-size (16384) DATA frame and feed it whole, as a
        // 16 KB TLS record would deliver it.
        const PAYLOAD: usize = 16384;
        let mut frame: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(9 + PAYLOAD);
        frame.push((PAYLOAD >> 16) as u8);
        frame.push((PAYLOAD >> 8) as u8);
        frame.push(PAYLOAD as u8);
        frame.push(0); // DATA
        frame.push(0); // flags
        frame.extend_from_slice(&(sid as u32).to_be_bytes());
        frame.extend_from_slice(&[0x5Au8; PAYLOAD]);
        server.feed_data(&mut sio.as_io(), &frame).unwrap();

        // Drain + re-drive until the frame is fully consumed. data_buf is
        // bounded by DATABUF the entire time (backpressure), and recv_buf holds
        // the parked remainder.
        let mut total = 0usize;
        let mut chunk = [0u8; 1024];
        for _ in 0..1000 {
            let max_seen = server
                .streams
                .iter()
                .find(|s| s.id == sid)
                .unwrap()
                .data_buf
                .len();
            assert!(
                max_seen <= DATABUF,
                "data_buf {max_seen} exceeded DATABUF {DATABUF} — backpressure failed"
            );
            // Fully drain whatever is buffered.
            loop {
                match server.recv_body(&mut sio.as_io(), sid, &mut chunk) {
                    Ok((0, _)) => break,
                    Ok((n, _)) => total += n,
                    Err(Error::WouldBlock) => break,
                    Err(e) => panic!("recv_body: {e:?}"),
                }
            }
            if !server.has_partial_data() {
                break;
            }
            // Re-drive the pump (models the runner's empty feed after a drain).
            server.feed_data(&mut sio.as_io(), &[]).unwrap();
        }
        assert_eq!(
            total, PAYLOAD,
            "entire body delivered across backpressured pumps"
        );
        assert!(!server.has_partial_data(), "frame fully consumed");
    }

    #[test]
    fn stream_slot_reaped_after_empty_end_stream_data_frame() {
        // Regression: a body terminated by an empty END_STREAM DATA frame (the
        // standard curl/nghttp2/browser streaming-upload ending) sets
        // `data_available` on pump completion, but recv_body's empty-buffer
        // early return never cleared it — so the Closed-stream retain kept the
        // slot forever and MAX_STREAMS requests wedged a persistent connection.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<16384>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let stream_id = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"POST"),
                    (b":path", b"/upload"),
                    (b":scheme", b"https"),
                    (b":authority", b"example.com"),
                ],
                false,
            )
            .unwrap();
        // Deliver the body and drain it FULLY before the fin frame arrives:
        // the copy path clears `data_available`, so the empty END_STREAM frame
        // below re-sets it with nothing left for the copy path to clear — the
        // (0, true) early return is then the only place it can be cleared.
        client
            .send_data(&mut cio.as_io(), stream_id, b"body bytes", false)
            .unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        while server.poll_event().is_some() {}
        // Consume the request headers (any real app does) so the
        // Closed-stream retain can reap the slot afterwards.
        server.recv_headers(stream_id, |_, _| {}).unwrap();
        let mut buf = [0u8; 64];
        loop {
            match server.recv_body(&mut sio.as_io(), stream_id, &mut buf) {
                Ok((0, _)) | Err(Error::WouldBlock) => break,
                Ok((_, _)) => {}
                Err(e) => panic!("recv_body: {e:?}"),
            }
        }

        // Now the empty DATA frame carrying only END_STREAM.
        client
            .send_data(&mut cio.as_io(), stream_id, &[], true)
            .unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        while server.poll_event().is_some() {}

        // End of stream surfaces via the empty-buffer early return.
        let got = server.recv_body(&mut sio.as_io(), stream_id, &mut buf);
        assert_eq!(got, Ok((0, true)), "server should observe end of stream");

        // Respond and close our side -> stream state Closed.
        server
            .send_headers(&mut sio.as_io(), stream_id, &[(b":status", b"200")], true)
            .unwrap();
        exchange(&mut server, &mut sio, &mut client, &mut cio);

        // Any subsequent receive processing runs the Closed-stream retain.
        server.feed_data(&mut sio.as_io(), &[]).unwrap();
        assert!(
            server.streams.is_empty(),
            "drained Closed stream must be reaped, not leak its slot"
        );
    }

    // ====== discard_body ======

    /// Parse a raw h2 byte stream into (frame_type, stream_id, payload) tuples.
    fn parse_frames(raw: &[u8]) -> alloc::vec::Vec<(u8, u32, alloc::vec::Vec<u8>)> {
        let mut frames = alloc::vec::Vec::new();
        let mut off = 0;
        while off + 9 <= raw.len() {
            let len = ((raw[off] as usize) << 16)
                | ((raw[off + 1] as usize) << 8)
                | raw[off + 2] as usize;
            let ty = raw[off + 3];
            let sid = u32::from_be_bytes([raw[off + 5], raw[off + 6], raw[off + 7], raw[off + 8]])
                & 0x7fff_ffff;
            let ps = off + 9;
            frames.push((ty, sid, raw[ps..ps + len].to_vec()));
            off = ps + len;
        }
        assert_eq!(off, raw.len(), "trailing partial frame in stream");
        frames
    }

    #[test]
    fn discard_body_unwedges_stalled_pump_and_sends_rst() {
        // A stalled pump (data_buf full, app refuses to drain) wedges the
        // connection: frames behind the parked payload are unreachable and
        // the runner's backpressure gating stops socket reads. discard_body
        // is the escape hatch: the pump flips to discard mode, the remaining
        // payload drains off recv_buf (crediting the connection window), and
        // RST_STREAM tells the peer to stop sending.
        const DATABUF: usize = 4096;
        let mut client = H2Connection::<16, 2048, DATABUF>::new_client();
        let mut cio = H2IoBufs::<40960>::new();
        let mut server = H2Connection::<16, 2048, DATABUF>::new_server();
        let mut sio = H2IoBufs::<40960>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let sid = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"POST"),
                    (b":path", b"/system/update"),
                    (b":scheme", b"https"),
                    (b":authority", b"x"),
                ],
                false,
            )
            .unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        while server.poll_event().is_some() {}
        // Consume the request headers (any real app does) so the
        // Closed-stream retain can reap the slot afterwards.
        server.recv_headers(sid, |_, _| {}).unwrap();

        // Pre-SETTINGS-ack burst: a full 16384-byte DATA frame (legal under
        // the RFC-default window, RFC 9113 \u{a7}6.9.2).
        server.settings_ack_received = false;
        const PAYLOAD: usize = 16384;
        let mut frame: alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity(9 + PAYLOAD);
        frame.push((PAYLOAD >> 16) as u8);
        frame.push((PAYLOAD >> 8) as u8);
        frame.push(PAYLOAD as u8);
        frame.push(0); // DATA
        frame.push(0); // flags
        frame.extend_from_slice(&(sid as u32).to_be_bytes());
        frame.extend_from_slice(&[0x5Au8; PAYLOAD]);
        server.feed_data(&mut sio.as_io(), &frame).unwrap();

        // The pump is stalled: data_buf holds DATABUF bytes, the rest is
        // parked in recv_buf. The app never drains.
        assert!(server.has_partial_data(), "pump should be stalled");

        // App decides not to read the body.
        server.discard_body(&mut sio.as_io(), sid, 0x8).unwrap();

        // Runner-style empty re-drive: the discard pump must consume the
        // entire remaining payload without needing data_buf space.
        server.feed_data(&mut sio.as_io(), &[]).unwrap();
        assert!(!server.has_partial_data(), "discard pump must finish");
        assert!(
            server.streams.is_empty(),
            "discarded stream slot must be reaped"
        );

        // Wire contract: RST_STREAM(CANCEL) went out, and the connection
        // window was fully re-credited (16384 across WINDOW_UPDATEs on
        // stream 0) so the next request's body has room.
        let mut out = alloc::vec::Vec::new();
        let mut buf = [0u8; 8192];
        while let Some(d) = server.poll_output(&mut sio.as_io(), &mut buf) {
            out.extend_from_slice(d);
        }
        let frames = parse_frames(&out);
        let rst: alloc::vec::Vec<_> = frames
            .iter()
            .filter(|(ty, _, _)| *ty == FRAME_RST_STREAM)
            .collect();
        assert_eq!(rst.len(), 1, "exactly one RST_STREAM");
        assert_eq!(rst[0].1 as u64, sid, "RST on the discarded stream");
        assert_eq!(
            u32::from_be_bytes([rst[0].2[0], rst[0].2[1], rst[0].2[2], rst[0].2[3]]),
            0x8,
            "CANCEL error code"
        );
        let conn_credit: usize = frames
            .iter()
            .filter(|(ty, sid, _)| *ty == FRAME_WINDOW_UPDATE && *sid == 0)
            .map(|(_, _, p)| u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize)
            .sum();
        assert_eq!(
            conn_credit, PAYLOAD,
            "entire discarded payload re-credited to the connection window"
        );
    }

    #[test]
    fn discard_body_rst_deferred_when_send_buffer_full() {
        // discard_body with a full send buffer must defer the RST_STREAM
        // (H2Stream::pending_rst) and keep the stream slot alive until the
        // frame actually goes out via generate_output — a silently dropped
        // RST would leave the peer uploading into a dead stream forever.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<16384>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let sid = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"POST"),
                    (b":path", b"/upload"),
                    (b":scheme", b"https"),
                    (b":authority", b"x"),
                ],
                false,
            )
            .unwrap();
        client
            .send_data(&mut cio.as_io(), sid, &[0xAB; 100], false)
            .unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        while server.poll_event().is_some() {}
        // Consume the request headers (any real app does) so the
        // Closed-stream retain can reap the slot afterwards.
        server.recv_headers(sid, |_, _| {}).unwrap();

        // Fill the server's send buffer so nothing can be queued.
        let used = sio.send_buf.len();
        let filler = alloc::vec![0u8; 16384 - used];
        sio.send_buf.extend_from_slice(&filler).unwrap();

        server.discard_body(&mut sio.as_io(), sid, 0x8).unwrap();
        let stream = server.streams.iter().find(|s| s.id == sid).unwrap();
        assert_eq!(stream.pending_rst, Some(0x8), "RST deferred, not dropped");

        // Retain must keep the slot while the RST is pending.
        server.feed_data(&mut sio.as_io(), &[]).unwrap();
        assert!(
            server.streams.iter().any(|s| s.id == sid),
            "slot retained until the deferred RST is sent"
        );

        // Drain the buffer; generate_output flushes the RST; slot reaped.
        sio.send_buf.clear();
        server.generate_output(&mut sio.as_io());
        let out: alloc::vec::Vec<u8> = sio.send_buf.as_slice().to_vec();
        let frames = parse_frames(&out);
        assert!(
            frames
                .iter()
                .any(|(ty, fsid, _)| *ty == FRAME_RST_STREAM && *fsid as u64 == sid),
            "deferred RST_STREAM emitted after buffer drained"
        );
        server.feed_data(&mut sio.as_io(), &[]).unwrap();
        assert!(server.streams.is_empty(), "slot reaped after RST sent");
    }

    #[test]
    fn discard_body_after_fin_sends_no_rst() {
        // If the peer already half-closed (END_STREAM received), nothing more
        // is coming: discard is purely local bookkeeping and an RST_STREAM
        // would be noise. The slot must still be reaped.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<16384>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let sid = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"POST"),
                    (b":path", b"/upload"),
                    (b":scheme", b"https"),
                    (b":authority", b"x"),
                ],
                false,
            )
            .unwrap();
        client
            .send_data(&mut cio.as_io(), sid, b"unread body", true)
            .unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        while server.poll_event().is_some() {}
        // Consume the request headers (any real app does) so the
        // Closed-stream retain can reap the slot afterwards.
        server.recv_headers(sid, |_, _| {}).unwrap();

        server.discard_body(&mut sio.as_io(), sid, 0x8).unwrap();
        server.feed_data(&mut sio.as_io(), &[]).unwrap();
        assert!(server.streams.is_empty(), "slot reaped");

        let mut out = alloc::vec::Vec::new();
        let mut buf = [0u8; 8192];
        while let Some(d) = server.poll_output(&mut sio.as_io(), &mut buf) {
            out.extend_from_slice(d);
        }
        assert!(
            !parse_frames(&out)
                .iter()
                .any(|(ty, _, _)| *ty == FRAME_RST_STREAM),
            "no RST after the peer already finished the stream"
        );
    }

    /// Open a client request and deliver a server response HEADERS
    /// (`:status: 200`, end_stream=false) for it, leaving the stream open
    /// for body DATA. Returns the stream id.
    fn open_streaming_response<const M: usize, const BUF: usize>(
        client: &mut H2Connection<M>,
        cio: &mut H2IoBufs<BUF>,
        server: &mut H2Connection<M>,
        sio: &mut H2IoBufs<BUF>,
    ) -> u64 {
        let sid = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"POST"),
                    (b":path", b"/telemetry/live"),
                    (b":scheme", b"https"),
                    (b":authority", b"x"),
                ],
                true,
            )
            .unwrap();
        exchange(client, cio, server, sio);
        while server.poll_event().is_some() {}
        server.recv_headers(sid, |_, _| {}).unwrap();
        server
            .send_headers(&mut sio.as_io(), sid, &[(b":status", b"200")], false)
            .unwrap();
        exchange(server, sio, client, cio);
        while client.poll_event().is_some() {}
        sid
    }

    #[test]
    fn client_discard_body_cancels_response_stream() {
        // The client-side use: abandon a long-lived response stream (e.g. a
        // telemetry subscription) without tearing down the shared
        // connection. RST_STREAM(CANCEL) goes out, buffered + late-arriving
        // body bytes are credited back to the connection window, the slot is
        // reaped, and a subsequent request on the same connection works.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<16384>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);
        let sid = open_streaming_response(&mut client, &mut cio, &mut server, &mut sio);

        // Some body arrives and sits unread client-side.
        server
            .send_data(&mut sio.as_io(), sid, &[0x11; 300], false)
            .unwrap();
        exchange(&mut server, &mut sio, &mut client, &mut cio);
        while client.poll_event().is_some() {}
        client.recv_headers(sid, |_, _| {}).unwrap();

        // Cancel. The RST is queued client-side but NOT yet delivered — the
        // server keeps streaming into the closing window.
        client.discard_body(&mut cio.as_io(), sid, 0x8).unwrap();
        client.feed_data(&mut cio.as_io(), &[]).unwrap();
        assert!(client.streams.is_empty(), "canceled slot reaped");
        server
            .send_data(&mut sio.as_io(), sid, &[0x22; 200], false)
            .unwrap();
        exchange(&mut server, &mut sio, &mut client, &mut cio);
        assert!(
            client.poll_event().is_none(),
            "in-flight DATA behind the cancel must be silent"
        );
        assert!(client.is_active(), "connection survives the late DATA");

        // Wire contract: one RST_STREAM(CANCEL) on the canceled stream, and
        // every body byte (300 buffered at cancel + 200 in flight behind it)
        // credited back to the connection window.
        let mut out = alloc::vec::Vec::new();
        let mut buf = [0u8; 8192];
        while let Some(d) = client.poll_output(&mut cio.as_io(), &mut buf) {
            out.extend_from_slice(d);
        }
        let frames = parse_frames(&out);
        let rst: alloc::vec::Vec<_> = frames
            .iter()
            .filter(|(ty, _, _)| *ty == FRAME_RST_STREAM)
            .collect();
        assert_eq!(rst.len(), 1, "exactly one RST_STREAM");
        assert_eq!(rst[0].1 as u64, sid);
        assert_eq!(
            u32::from_be_bytes([rst[0].2[0], rst[0].2[1], rst[0].2[2], rst[0].2[3]]),
            0x8,
            "CANCEL error code"
        );
        let conn_credit: usize = frames
            .iter()
            .filter(|(ty, fsid, _)| *ty == FRAME_WINDOW_UPDATE && *fsid == 0)
            .map(|(_, _, p)| u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize)
            .sum();
        assert_eq!(conn_credit, 500, "all discarded body bytes re-credited");

        // The server processes the RST and the connection keeps working: a
        // fresh request round-trips.
        server.feed_data(&mut sio.as_io(), &out).unwrap();
        while server.poll_event().is_some() {}
        let sid2 = open_streaming_response(&mut client, &mut cio, &mut server, &mut sio);
        assert_ne!(sid, sid2);
        client.recv_headers(sid2, |_, _| {}).unwrap();
    }

    #[test]
    fn client_cancel_before_reading_headers_does_not_leak_slots() {
        // Canceling a stream whose response headers were never read must
        // still free the slot: the Closed-stream retain deliberately keeps
        // unread-headers slots alive (a completed response must survive
        // until read), but discard_body is an explicit declaration of
        // disinterest. Before the headers-clear in discard_body, MAX_STREAMS
        // cancels wedged the client with InvalidState on every open_stream.
        let mut client = H2Connection::<2>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<2>::new_server();
        let mut sio = H2IoBufs::<16384>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        for _ in 0..4 {
            let sid = open_streaming_response(&mut client, &mut cio, &mut server, &mut sio);
            // Cancel WITHOUT reading the response headers.
            client.discard_body(&mut cio.as_io(), sid, 0x8).unwrap();
            client.feed_data(&mut cio.as_io(), &[]).unwrap();
            assert!(client.streams.is_empty(), "canceled slot reaped");
            // Deliver the RST so the server-side slot closes too.
            exchange(&mut client, &mut cio, &mut server, &mut sio);
            while server.poll_event().is_some() {}
        }
    }

    #[test]
    fn late_headers_on_canceled_stream_ignored_and_hpack_stays_synced() {
        // Trailers (or a late response) already in flight when the client's
        // RST_STREAM lands must be ignored (RFC 9113 §5.1) — before the
        // closed-stream leniency, HEADERS on the reaped stream id was
        // treated as the peer opening a new stream: a connection-fatal
        // ProtocolError that defeated the whole point of per-stream cancel.
        // The dropped block must still pass through the HPACK decoder: this
        // one inserts a dynamic-table entry that a later response references
        // by index.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<16384>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);
        let sid = open_streaming_response(&mut client, &mut cio, &mut server, &mut sio);
        client.recv_headers(sid, |_, _| {}).unwrap();

        client.discard_body(&mut cio.as_io(), sid, 0x8).unwrap();
        client.feed_data(&mut cio.as_io(), &[]).unwrap();
        assert!(client.streams.is_empty(), "canceled slot reaped");

        // Late trailers on the canceled stream, hand-crafted because our own
        // encoder is static-only: a Literal with Incremental Indexing
        // (RFC 7541 §6.2.1) inserting x-token: hello at dynamic index 62.
        let mut block: alloc::vec::Vec<u8> = alloc::vec![0x40];
        block.push(7);
        block.extend_from_slice(b"x-token");
        block.push(5);
        block.extend_from_slice(b"hello");
        let mut frame: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        frame.extend_from_slice(&[0, 0, block.len() as u8]);
        frame.push(FRAME_HEADERS);
        frame.push(FLAG_END_HEADERS | FLAG_END_STREAM);
        frame.extend_from_slice(&(sid as u32).to_be_bytes());
        frame.extend_from_slice(&block);
        client
            .feed_data(&mut cio.as_io(), &frame)
            .expect("late HEADERS on a canceled stream must not error");
        assert!(
            client.poll_event().is_none(),
            "ignored block must emit no events"
        );
        assert!(client.is_active());

        // A new request whose response references the inserted entry by
        // index (0xBE = dynamic 62) proves the dropped block was decoded
        // into the table, not skipped.
        let sid2 = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"GET"),
                    (b":path", b"/"),
                    (b":scheme", b"https"),
                    (b":authority", b"x"),
                ],
                true,
            )
            .unwrap();
        let block2: &[u8] = &[0x88, 0xBE]; // :status: 200 (static 8), dynamic 62
        let mut frame2: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        frame2.extend_from_slice(&[0, 0, block2.len() as u8]);
        frame2.push(FRAME_HEADERS);
        frame2.push(FLAG_END_HEADERS | FLAG_END_STREAM);
        frame2.extend_from_slice(&(sid2 as u32).to_be_bytes());
        frame2.extend_from_slice(block2);
        client.feed_data(&mut cio.as_io(), &frame2).unwrap();
        let mut token = alloc::vec::Vec::new();
        client
            .recv_headers(sid2, |name, value| {
                if name == b"x-token" {
                    token.extend_from_slice(value);
                }
            })
            .unwrap();
        assert_eq!(
            token, b"hello",
            "dynamic entry from the dropped block must resolve"
        );
    }

    #[test]
    fn frames_in_the_cancel_to_reap_window_are_ignored() {
        // The reap runs at the END of a process_recv batch, so a canceled
        // slot is still present when the next feed's frames parse. Frames in
        // that window must get closed-stream treatment (RFC 9113 §5.1):
        // before the state gate on `deliver`, late DATA was delivered into
        // the canceled stream's data_buf with no window credit returned and
        // `data_available` re-pinned the slot — a slot + connection-window
        // leak per cancel, with no empty re-drive to save it.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<16384>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);
        let sid = open_streaming_response(&mut client, &mut cio, &mut server, &mut sio);
        client.recv_headers(sid, |_, _| {}).unwrap();

        client.discard_body(&mut cio.as_io(), sid, 0x8).unwrap();
        // NO empty re-drive: the very next feed carries late DATA while the
        // Closed slot is still present.
        server
            .send_data(&mut sio.as_io(), sid, &[0x33; 256], false)
            .unwrap();
        exchange(&mut server, &mut sio, &mut client, &mut cio);
        assert!(
            client.poll_event().is_none(),
            "no events for the canceled stream"
        );
        assert!(
            client.streams.is_empty(),
            "slot reaped by the same feed's sweep"
        );

        // Every discarded byte came back as connection credit.
        let mut out = alloc::vec::Vec::new();
        let mut buf = [0u8; 8192];
        while let Some(d) = client.poll_output(&mut cio.as_io(), &mut buf) {
            out.extend_from_slice(d);
        }
        let conn_credit: usize = parse_frames(&out)
            .iter()
            .filter(|(ty, fsid, _)| *ty == FRAME_WINDOW_UPDATE && *fsid == 0)
            .map(|(_, _, p)| u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize)
            .sum();
        assert_eq!(
            conn_credit, 256,
            "in-window DATA credited to the connection"
        );
    }

    #[test]
    fn trailers_in_the_cancel_to_reap_window_are_ignored() {
        // Same window as above, HEADERS shape: trailers landing on the
        // still-present Closed slot must not fire events, clobber retained
        // state, or re-pin the slot via headers_received.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<16384>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);
        let sid = open_streaming_response(&mut client, &mut cio, &mut server, &mut sio);
        client.recv_headers(sid, |_, _| {}).unwrap();

        client.discard_body(&mut cio.as_io(), sid, 0x8).unwrap();
        let block: &[u8] = &[0x88]; // :status: 200 (static)
        let mut frame: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        frame.extend_from_slice(&[0, 0, block.len() as u8]);
        frame.push(FRAME_HEADERS);
        frame.push(FLAG_END_HEADERS | FLAG_END_STREAM);
        frame.extend_from_slice(&(sid as u32).to_be_bytes());
        frame.extend_from_slice(block);
        client
            .feed_data(&mut cio.as_io(), &frame)
            .expect("trailers on a canceled slot must not error");
        assert!(client.poll_event().is_none(), "ignored block, no events");
        assert!(client.streams.is_empty(), "slot reaped, not re-pinned");

        // The connection keeps working end to end.
        let sid2 = open_streaming_response(&mut client, &mut cio, &mut server, &mut sio);
        client.recv_headers(sid2, |_, _| {}).unwrap();
    }

    #[test]
    fn multiframe_trailers_on_canceled_stream_are_a_connection_error() {
        // A !END_HEADERS block on a closed stream cannot be decoded
        // fragment-wise, so ignoring it would silently desync the HPACK
        // dynamic table for every other stream — the honest outcome is a
        // COMPRESSION_ERROR connection teardown.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<16384>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);
        let sid = open_streaming_response(&mut client, &mut cio, &mut server, &mut sio);
        client.recv_headers(sid, |_, _| {}).unwrap();
        client.discard_body(&mut cio.as_io(), sid, 0x8).unwrap();
        client.feed_data(&mut cio.as_io(), &[]).unwrap();
        assert!(client.streams.is_empty());

        let block: &[u8] = &[0x88];
        let mut frame: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        frame.extend_from_slice(&[0, 0, block.len() as u8]);
        frame.push(FRAME_HEADERS);
        frame.push(FLAG_END_STREAM); // no END_HEADERS
        frame.extend_from_slice(&(sid as u32).to_be_bytes());
        frame.extend_from_slice(block);
        assert!(matches!(
            client.feed_data(&mut cio.as_io(), &frame),
            Err(Error::Http2(crate::error::H2Error::CompressionError))
        ));
    }

    #[test]
    fn continuation_for_reaped_stream_clears_the_latch() {
        // Pre-existing wedge: HEADERS(!END_HEADERS + END_STREAM) closes the
        // stream, the end-of-feed sweep reaps the slot, and the CONTINUATION
        // arriving in the next feed used to leave `continuation_stream_id`
        // latched (the clear lived inside the slot lookup) — turning the
        // next unrelated frame into a guaranteed ProtocolError.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<16384>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);
        let sid = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"GET"),
                    (b":path", b"/"),
                    (b":scheme", b"https"),
                    (b":authority", b"x"),
                ],
                true,
            )
            .unwrap();

        // Feed 1: HEADERS fragment, END_STREAM but not END_HEADERS — the
        // stream goes Closed (fin both ways) and the sweep reaps it.
        let frag: &[u8] = &[0x88];
        let mut h: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        h.extend_from_slice(&[0, 0, frag.len() as u8]);
        h.push(FRAME_HEADERS);
        h.push(FLAG_END_STREAM);
        h.extend_from_slice(&(sid as u32).to_be_bytes());
        h.extend_from_slice(frag);
        client.feed_data(&mut cio.as_io(), &h).unwrap();
        assert!(client.streams.is_empty(), "slot reaped with block open");

        // Feed 2: the CONTINUATION completing the block — slot gone, but the
        // latch must clear.
        let mut c: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        c.extend_from_slice(&[0, 0, frag.len() as u8]);
        c.push(FRAME_CONTINUATION);
        c.push(FLAG_END_HEADERS);
        c.extend_from_slice(&(sid as u32).to_be_bytes());
        c.extend_from_slice(frag);
        client.feed_data(&mut cio.as_io(), &c).unwrap();

        // Feed 3: an unrelated frame must not hit a stale latch.
        let ping: &[u8] = &[0, 0, 8, FRAME_PING, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        client
            .feed_data(&mut cio.as_io(), ping)
            .expect("stale continuation latch must not kill the connection");
    }

    #[test]
    fn empty_feed_does_not_refresh_idle_clock() {
        // The runner re-drives backpressured connections with empty feeds
        // every poll cycle. Those must not count as activity, or a wedged
        // connection refreshes its own idle clock forever and the timeout
        // backstop never fires.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<16384>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<16384>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);
        while server.poll_event().is_some() {}

        let config = crate::http::TimeoutConfig {
            idle_timeout_us: Some(1_000_000),
            header_timeout_us: None,
        };
        server.set_timeouts(config, 0);

        // Empty re-drives right up to the deadline must not push it out.
        for now in [400_000u64, 800_000, 999_000] {
            server.feed_data_timed(&mut sio.as_io(), &[], now).unwrap();
        }
        server.handle_timeout(&mut sio.as_io(), 1_000_000);
        let mut timed_out = false;
        while let Some(ev) = server.poll_event() {
            if ev == H2Event::Timeout {
                timed_out = true;
            }
        }
        assert!(timed_out, "idle timeout fires despite empty re-drives");

        // Control: a non-empty feed (a PING) does refresh the clock.
        let mut server2 = H2Connection::<16>::new_server();
        let mut sio2 = H2IoBufs::<16384>::new();
        let mut client2 = H2Connection::<16>::new_client();
        let mut cio2 = H2IoBufs::<16384>::new();
        run_handshake(&mut client2, &mut cio2, &mut server2, &mut sio2);
        while server2.poll_event().is_some() {}
        server2.set_timeouts(config, 0);

        // PING frame: len 8, type 0x6, flags 0, sid 0, 8 opaque bytes.
        let ping = [0u8, 0, 8, 0x6, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        server2
            .feed_data_timed(&mut sio2.as_io(), &ping, 900_000)
            .unwrap();
        server2.handle_timeout(&mut sio2.as_io(), 1_000_000);
        let mut timed_out2 = false;
        while let Some(ev) = server2.poll_event() {
            if ev == H2Event::Timeout {
                timed_out2 = true;
            }
        }
        assert!(!timed_out2, "real data refreshes the idle clock");
    }

    // ====== Item 3: RST_STREAM Reception ======

    #[test]
    fn rst_stream_emits_event() {
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<8192>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<8192>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let stream_id = client
            .open_stream(
                &mut cio.as_io(),
                &[
                    (b":method", b"GET"),
                    (b":path", b"/"),
                    (b":scheme", b"https"),
                    (b":authority", b"example.com"),
                ],
                true,
            )
            .unwrap();
        exchange(&mut client, &mut cio, &mut server, &mut sio);
        while let Some(_) = client.poll_event() {}

        let rst = H2Frame::RstStream {
            stream_id,
            error_code: 0x8,
        };
        let mut buf = [0u8; 32];
        let n = frame::encode_frame(&rst, &mut buf).unwrap();
        client.feed_data(&mut cio.as_io(), &buf[..n]).unwrap();

        let mut got_reset = false;
        while let Some(ev) = client.poll_event() {
            if ev == H2Event::StreamReset(stream_id, 0x8) {
                got_reset = true;
            }
        }
        assert!(
            got_reset,
            "client should emit StreamReset(stream_id, CANCEL)"
        );
    }

    #[test]
    fn continuation_flood_rejected() {
        // RFC 9113 §6.5.2 / §6.10 (CVE-2024-27316): a HEADERS frame without
        // END_HEADERS followed by CONTINUATION frames whose accumulated field
        // section exceeds what we will buffer (HDRBUF) must terminate the
        // connection rather than silently truncate or loop unboundedly.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<32768>::new();
        let mut server = H2Connection::<16>::new_server(); // HDRBUF = 2048
        let mut sio = H2IoBufs::<32768>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        fn raw_frame(
            ty: u8,
            flags: u8,
            stream_id: u32,
            payload_len: usize,
            out: &mut [u8],
        ) -> usize {
            out[0] = (payload_len >> 16) as u8;
            out[1] = (payload_len >> 8) as u8;
            out[2] = payload_len as u8;
            out[3] = ty;
            out[4] = flags;
            out[5..9].copy_from_slice(&stream_id.to_be_bytes());
            for b in &mut out[9..9 + payload_len] {
                *b = 0;
            }
            9 + payload_len
        }

        let mut buf = [0u8; 2048];

        // HEADERS (no END_HEADERS): 1500 bytes — fits within HDRBUF.
        let n = raw_frame(FRAME_HEADERS, 0, 1, 1500, &mut buf);
        server.feed_data(&mut sio.as_io(), &buf[..n]).unwrap();

        // CONTINUATION pushes the accumulated block past HDRBUF (2048).
        let n = raw_frame(FRAME_CONTINUATION, 0, 1, 1500, &mut buf);
        let res = server.feed_data(&mut sio.as_io(), &buf[..n]);
        assert!(
            matches!(
                res,
                Err(Error::Http2(crate::error::H2Error::EnhanceYourCalm))
            ),
            "oversized CONTINUATION accumulation must terminate the connection, got {:?}",
            res
        );
    }

    #[test]
    fn settings_initial_window_overflow_is_flow_control_error() {
        // RFC 9113 §6.9.2: a SETTINGS_INITIAL_WINDOW_SIZE change that pushes a
        // stream's flow-control window above 2^31-1 MUST be a FLOW_CONTROL_ERROR,
        // not a panic (debug) or silent wrap to negative (release).
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<32768>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<32768>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        fn raw_frame(ty: u8, flags: u8, stream_id: u32, payload: &[u8], out: &mut [u8]) -> usize {
            let n = payload.len();
            out[0] = (n >> 16) as u8;
            out[1] = (n >> 8) as u8;
            out[2] = n as u8;
            out[3] = ty;
            out[4] = flags;
            out[5..9].copy_from_slice(&stream_id.to_be_bytes());
            out[9..9 + n].copy_from_slice(payload);
            9 + n
        }

        let mut buf = [0u8; 64];

        // Create stream 1 on the server (empty header block, END_HEADERS).
        let n = raw_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &[], &mut buf);
        server.feed_data(&mut sio.as_io(), &buf[..n]).unwrap();

        // Push stream 1's send_window to exactly i32::MAX via WINDOW_UPDATE
        // (default initial window is 65535).
        let inc: u32 = 0x7fff_ffff - 65535;
        let n = raw_frame(FRAME_WINDOW_UPDATE, 0, 1, &inc.to_be_bytes(), &mut buf);
        server.feed_data(&mut sio.as_io(), &buf[..n]).unwrap();

        // SETTINGS raising INITIAL_WINDOW_SIZE by +1 would overflow send_window.
        let mut setting = [0u8; 6];
        setting[0..2].copy_from_slice(&SETTINGS_INITIAL_WINDOW_SIZE.to_be_bytes());
        setting[2..6].copy_from_slice(&65536u32.to_be_bytes());
        let n = raw_frame(FRAME_SETTINGS, 0, 0, &setting, &mut buf);
        let res = server.feed_data(&mut sio.as_io(), &buf[..n]);

        assert_eq!(
            res,
            Err(Error::Http2(crate::error::H2Error::FlowControlError)),
            "SETTINGS-induced stream window overflow must be FLOW_CONTROL_ERROR"
        );
    }

    #[test]
    fn stream_recv_flow_control_enforced() {
        // RFC 9113 §6.9.1: exceeding the stream-level receive window is a
        // FLOW_CONTROL_ERROR. Raise the connection window first so the stream
        // limit is the one that binds.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<65536>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<65536>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        fn raw_frame(ty: u8, flags: u8, stream_id: u32, payload: &[u8], out: &mut [u8]) -> usize {
            let n = payload.len();
            out[0] = (n >> 16) as u8;
            out[1] = (n >> 8) as u8;
            out[2] = n as u8;
            out[3] = ty;
            out[4] = flags;
            out[5..9].copy_from_slice(&stream_id.to_be_bytes());
            out[9..9 + n].copy_from_slice(payload);
            9 + n
        }

        let mut buf = [0u8; 20_000];

        // Open stream 1.
        let n = raw_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &[], &mut buf);
        server.feed_data(&mut sio.as_io(), &buf[..n]).unwrap();

        // Lift the connection-level *receive* window well above the stream
        // window so the per-stream limit is the one that binds.
        server.conn_recv_fc.replenish(2_000_000).unwrap();

        // Send DATA past the 65535 stream window in 16384-byte frames.
        let payload = [0u8; 16384];
        let mut result = Ok(());
        for _ in 0..5 {
            let n = raw_frame(FRAME_DATA, 0, 1, &payload, &mut buf);
            result = server.feed_data(&mut sio.as_io(), &buf[..n]);
            if result.is_err() {
                break;
            }
        }
        assert_eq!(
            result,
            Err(Error::Http2(crate::error::H2Error::FlowControlError)),
            "exceeding the stream receive window must be FLOW_CONTROL_ERROR"
        );
    }

    #[test]
    fn server_rejects_even_stream_id_headers() {
        // RFC 9113 §5.1.1: a server must not accept a new stream on an
        // even (server-initiated) stream ID from the client.
        let mut client = H2Connection::<16>::new_client();
        let mut cio = H2IoBufs::<8192>::new();
        let mut server = H2Connection::<16>::new_server();
        let mut sio = H2IoBufs::<8192>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let mut buf = [0u8; 32];
        // HEADERS on stream 2 (even) -> illegal for a client to open.
        let payload_len = 0usize;
        buf[0] = 0;
        buf[1] = 0;
        buf[2] = payload_len as u8;
        buf[3] = FRAME_HEADERS;
        buf[4] = FLAG_END_HEADERS;
        buf[5..9].copy_from_slice(&2u32.to_be_bytes());
        let res = server.feed_data(&mut sio.as_io(), &buf[..9 + payload_len]);
        assert_eq!(
            res,
            Err(Error::Http2(crate::error::H2Error::ProtocolError)),
            "HEADERS on an even stream id must be a PROTOCOL_ERROR for a server"
        );
    }

    // ====== Item 4: Invalid SETTINGS Rejection ======

    #[test]
    fn invalid_settings_rejected() {
        // Sub-check 1: ENABLE_PUSH = 2 → ProtocolError
        {
            let mut conn = H2Connection::<16>::new_client();
            let mut io = H2IoBufs::<8192>::new();
            let frame: &[u8] = &[
                0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
                0x02,
            ];
            let result = conn.feed_data(&mut io.as_io(), frame);
            assert_eq!(
                result,
                Err(Error::Http2(crate::error::H2Error::ProtocolError))
            );
        }

        // Sub-check 2: INITIAL_WINDOW_SIZE = 0x8000_0000 → FlowControlError
        {
            let mut conn = H2Connection::<16>::new_client();
            let mut io = H2IoBufs::<8192>::new();
            let frame: &[u8] = &[
                0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x80, 0x00, 0x00,
                0x00,
            ];
            let result = conn.feed_data(&mut io.as_io(), frame);
            assert_eq!(
                result,
                Err(Error::Http2(crate::error::H2Error::FlowControlError))
            );
        }

        // Sub-check 3: MAX_FRAME_SIZE = 100 → ProtocolError
        {
            let mut conn = H2Connection::<16>::new_client();
            let mut io = H2IoBufs::<8192>::new();
            let frame: &[u8] = &[
                0x00, 0x00, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
                0x64,
            ];
            let result = conn.feed_data(&mut io.as_io(), frame);
            assert_eq!(
                result,
                Err(Error::Http2(crate::error::H2Error::ProtocolError))
            );
        }
    }

    // ====== Item 5: Stream Limit ======

    #[cfg(not(feature = "alloc"))]
    #[test]
    fn stream_vec_full_returns_error() {
        let mut client = H2Connection::<4>::new_client();
        let mut cio = H2IoBufs::<8192>::new();
        let mut server = H2Connection::<4>::new_server();
        let mut sio = H2IoBufs::<8192>::new();
        run_handshake(&mut client, &mut cio, &mut server, &mut sio);

        let headers: &[(&[u8], &[u8])] = &[
            (b":method", b"GET"),
            (b":path", b"/"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
        ];

        for i in 0..4u64 {
            let result = client.open_stream(&mut cio.as_io(), headers, true);
            assert!(result.is_ok(), "stream {} should open successfully", i);
        }
        exchange(&mut client, &mut cio, &mut server, &mut sio);

        let result = client.open_stream(&mut cio.as_io(), headers, true);
        assert!(result.is_ok(), "open_stream succeeds (HEADERS encoded)");
        let overflow_id = result.unwrap();

        let send_result = client.send_data(&mut cio.as_io(), overflow_id, b"x", true);
        assert_eq!(send_result, Err(Error::WouldBlock));
    }
}
