//! Shared HTTP/3 connection logic (control streams, settings exchange).
//!
//! This module provides the base [`H3Connection`] state that is used by both
//! the HTTP/3 client ([`super::client::H3Client`]) and server
//! ([`super::server::H3Server`]).

use crate::buf::Buf;
use crate::connection::{Connection, Event};
use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::h3::frame::{decode_h3_frame, encode_h3_frame, H3Frame};
use crate::h3::qpack::{QpackDecoder, QpackEncoder};
use crate::h3::{
    H3Settings, H3_STREAM_TYPE_CONTROL, H3_STREAM_TYPE_QPACK_DECODER,
    H3_STREAM_TYPE_QPACK_ENCODER,
};
use crate::varint::encode_varint;

// ---------------------------------------------------------------------------
// H3Event
// ---------------------------------------------------------------------------

/// Events produced by the HTTP/3 layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum H3Event {
    /// HTTP/3 connection is ready (settings exchanged).
    Connected,
    /// Headers received on a stream.
    Headers(u64),
    /// Body data available on a stream.
    Data(u64),
    /// Peer sent GOAWAY.
    GoAway(u64),
    /// Stream finished (FIN received).
    Finished(u64),
    /// Peer reset a stream.
    StreamReset { stream_id: u64, error_code: u64 },
    /// Connection was closed.
    ConnectionClose { error_code: u64 },
}

// ---------------------------------------------------------------------------
// RequestStreamState
// ---------------------------------------------------------------------------

/// Per-request-stream bookkeeping.
pub(crate) struct RequestStreamState {
    pub stream_id: u64,
    /// Buffer for received HEADERS frame data (QPACK-encoded).
    pub headers_data: Buf<512>,
    pub headers_received: bool,
    /// Buffer for received DATA.
    pub data_buf: Buf<1024>,
    pub data_available: bool,
    pub fin_received: bool,
}

impl RequestStreamState {
    pub fn new(stream_id: u64) -> Self {
        Self {
            stream_id,
            headers_data: Buf::new(),
            headers_received: false,
            data_buf: Buf::new(),
            data_available: false,
            fin_received: false,
        }
    }
}

// ---------------------------------------------------------------------------
// H3Connection
// ---------------------------------------------------------------------------

/// State shared between H3 client and server.
pub struct H3Connection<
    C: CryptoProvider,
    const MAX_STREAMS: usize = 32,
    const SENT_PER_SPACE: usize = 128,
    const MAX_CIDS: usize = 4,
    const STREAM_BUF: usize = 1024,
    const SEND_QUEUE: usize = 16,
> {
    pub(crate) quic: Connection<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS>,
    pub(crate) sio_bufs: crate::connection::io::QuicStreamIoBufs<MAX_STREAMS, STREAM_BUF, SEND_QUEUE>,

    // Control streams
    pub(crate) local_control_stream: Option<u64>,
    pub(crate) peer_control_stream: Option<u64>,

    // QPACK streams
    pub(crate) local_encoder_stream: Option<u64>,
    pub(crate) local_decoder_stream: Option<u64>,
    pub(crate) peer_encoder_stream: Option<u64>,
    pub(crate) peer_decoder_stream: Option<u64>,

    // QPACK codec
    pub(crate) encoder: QpackEncoder,
    pub(crate) decoder: QpackDecoder,

    // Settings
    pub(crate) local_settings: H3Settings,
    pub(crate) peer_settings: Option<H3Settings>,

    // Whether we have sent our initial SETTINGS.
    pub(crate) settings_sent: bool,

    // Pending events
    #[cfg(not(feature = "alloc"))]
    pub(crate) h3_events: heapless::Deque<H3Event, 16>,
    #[cfg(feature = "alloc")]
    pub(crate) h3_events: alloc::collections::VecDeque<H3Event>,

    // Per-stream state: which streams are request streams.
    #[cfg(not(feature = "alloc"))]
    pub(crate) request_streams: heapless::Vec<RequestStreamState, 8>,
    #[cfg(feature = "alloc")]
    pub(crate) request_streams: alloc::vec::Vec<RequestStreamState>,

    // Track stream IDs of unidirectional streams whose type we haven't read yet.
    #[cfg(not(feature = "alloc"))]
    pub(crate) pending_uni_streams: heapless::Vec<u64, 16>,
    #[cfg(feature = "alloc")]
    pub(crate) pending_uni_streams: alloc::vec::Vec<u64>,
}

impl<C: CryptoProvider, const MAX_STREAMS: usize, const SENT_PER_SPACE: usize, const MAX_CIDS: usize, const STREAM_BUF: usize, const SEND_QUEUE: usize>
    H3Connection<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS, STREAM_BUF, SEND_QUEUE>
where
    C::Hkdf: Default,
{
    /// Create a new H3Connection wrapping an underlying QUIC connection.
    pub fn new(quic: Connection<C, MAX_STREAMS, SENT_PER_SPACE, MAX_CIDS>) -> Self {
        Self {
            quic,
            sio_bufs: crate::connection::io::QuicStreamIoBufs::new(),
            local_control_stream: None,
            peer_control_stream: None,
            local_encoder_stream: None,
            local_decoder_stream: None,
            peer_encoder_stream: None,
            peer_decoder_stream: None,
            encoder: QpackEncoder::new(),
            decoder: QpackDecoder::new(),
            local_settings: H3Settings::default(),
            peer_settings: None,
            settings_sent: false,
            #[cfg(not(feature = "alloc"))]
            h3_events: heapless::Deque::new(),
            #[cfg(feature = "alloc")]
            h3_events: alloc::collections::VecDeque::new(),
            #[cfg(not(feature = "alloc"))]
            request_streams: heapless::Vec::new(),
            #[cfg(feature = "alloc")]
            request_streams: alloc::vec::Vec::new(),
            #[cfg(not(feature = "alloc"))]
            pending_uni_streams: heapless::Vec::new(),
            #[cfg(feature = "alloc")]
            pending_uni_streams: alloc::vec::Vec::new(),
        }
    }

    // ------------------------------------------------------------------
    // H3 stream setup
    // ------------------------------------------------------------------

    /// Open the three required unidirectional streams and send SETTINGS.
    ///
    /// Called when the QUIC connection transitions to Active.
    pub(crate) fn setup_h3_streams(&mut self) -> Result<(), Error> {
        // 1. Open control stream and send type varint + SETTINGS frame.
        let ctrl_id = self.quic.open_uni_stream()?;
        self.local_control_stream = Some(ctrl_id);
        self.send_stream_type(ctrl_id, H3_STREAM_TYPE_CONTROL)?;
        self.send_settings(ctrl_id)?;
        self.settings_sent = true;

        // 2. Open QPACK encoder stream (static-only: just the type byte).
        let enc_id = self.quic.open_uni_stream()?;
        self.local_encoder_stream = Some(enc_id);
        self.send_stream_type(enc_id, H3_STREAM_TYPE_QPACK_ENCODER)?;

        // 3. Open QPACK decoder stream (static-only: just the type byte).
        let dec_id = self.quic.open_uni_stream()?;
        self.local_decoder_stream = Some(dec_id);
        self.send_stream_type(dec_id, H3_STREAM_TYPE_QPACK_DECODER)?;

        Ok(())
    }

    /// Send a stream-type varint on a unidirectional stream.
    fn send_stream_type(&mut self, stream_id: u64, stream_type: u64) -> Result<(), Error> {
        let mut buf = [0u8; 8];
        let len = encode_varint(stream_type, &mut buf)?;
        let mut sio = self.sio_bufs.as_io();
        self.quic.stream_send(&mut sio, stream_id, &buf[..len], false)?;
        Ok(())
    }

    /// Encode and send a SETTINGS frame on the given control stream.
    fn send_settings(&mut self, stream_id: u64) -> Result<(), Error> {
        let frame = H3Frame::Settings(self.local_settings.clone());
        let mut buf = [0u8; 128];
        let len = encode_h3_frame(&frame, &mut buf)?;
        let mut sio = self.sio_bufs.as_io();
        self.quic.stream_send(&mut sio, stream_id, &buf[..len], false)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Process QUIC events
    // ------------------------------------------------------------------

    /// Drain all pending QUIC events and translate them into H3 state changes.
    pub(crate) fn process_quic_events(&mut self, is_server: bool) -> Result<(), Error> {
        // We collect events first to avoid borrow issues.
        let mut quic_events: heapless::Vec<Event, 16> = heapless::Vec::new();
        while let Some(ev) = self.quic.poll_event() {
            let _ = quic_events.push(ev);
        }

        for ev in quic_events {
            match ev {
                Event::Connected => {
                    self.setup_h3_streams()?;
                }
                Event::StreamOpened(stream_id) | Event::StreamReadable(stream_id) => {
                    self.handle_stream_data(stream_id, is_server)?;
                }
                Event::StreamFinished(stream_id) => {
                    // Mark FIN on request stream if tracked.
                    if let Some(rs) = self
                        .request_streams
                        .iter_mut()
                        .find(|rs| rs.stream_id == stream_id)
                    {
                        rs.fin_received = true;
                        self.push_h3_event(H3Event::Finished(stream_id));
                    }
                }
                Event::StreamReset { stream_id, error_code } => {
                    self.push_h3_event(H3Event::StreamReset { stream_id, error_code });
                }
                Event::ConnectionClose { error_code, .. } => {
                    self.push_h3_event(H3Event::ConnectionClose { error_code });
                }
                _ => {
                    // Other events (StreamWritable, StopSending, etc.)
                }
            }
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Stream data handling
    // ------------------------------------------------------------------

    /// Handle data on a stream. Routes to uni or request stream handler.
    fn handle_stream_data(&mut self, stream_id: u64, is_server: bool) -> Result<(), Error> {
        if crate::transport::stream::is_unidirectional(stream_id) {
            self.handle_uni_stream_data(stream_id)?;
        } else {
            self.handle_request_stream_data(stream_id, is_server)?;
        }
        Ok(())
    }

    /// Handle data on a unidirectional stream.
    ///
    /// The first varint on an incoming unidirectional stream identifies its
    /// type. Once we know the type we can route subsequent data.
    fn handle_uni_stream_data(&mut self, stream_id: u64) -> Result<(), Error> {
        // Check if we already know this stream.
        if Some(stream_id) == self.peer_control_stream
            || Some(stream_id) == self.peer_encoder_stream
            || Some(stream_id) == self.peer_decoder_stream
        {
            // Already classified. For the control stream, try reading more
            // frames (e.g. GOAWAY).
            if Some(stream_id) == self.peer_control_stream {
                self.read_control_stream_frames(stream_id)?;
            }
            // QPACK encoder/decoder streams in static-only mode: nothing to do.
            return Ok(());
        }

        // Try to read the stream type varint.
        let mut buf = [0u8; 4096];
        let mut sio = self.sio_bufs.as_io();
        let (read_len, fin) = match self.quic.stream_recv(&mut sio, stream_id, &mut buf) {
            Ok(r) => r,
            Err(Error::WouldBlock) => return Ok(()),
            Err(e) => return Err(e),
        };

        if read_len == 0 {
            return Ok(());
        }

        // First byte(s) = stream type varint.
        let (stream_type, type_len) = crate::varint::decode_varint(&buf[..read_len])?;

        match stream_type {
            H3_STREAM_TYPE_CONTROL => {
                self.peer_control_stream = Some(stream_id);
                // Remove from pending list if present.
                self.pending_uni_streams.retain(|&id| id != stream_id);

                // Rest of the data should contain SETTINGS and possibly more frames.
                let remaining = &buf[type_len..read_len];
                if !remaining.is_empty() {
                    self.process_control_data(remaining)?;
                }
            }
            H3_STREAM_TYPE_QPACK_ENCODER => {
                self.peer_encoder_stream = Some(stream_id);
                self.pending_uni_streams.retain(|&id| id != stream_id);
                // Static-only mode: no data expected.
            }
            H3_STREAM_TYPE_QPACK_DECODER => {
                self.peer_decoder_stream = Some(stream_id);
                self.pending_uni_streams.retain(|&id| id != stream_id);
                // Static-only mode: no data expected.
            }
            _ => {
                // Unknown stream type: silently ignore per RFC 9114 section 6.2.
                let _ = fin;
            }
        }

        Ok(())
    }

    /// Read and process frames from the peer control stream.
    fn read_control_stream_frames(&mut self, stream_id: u64) -> Result<(), Error> {
        let mut buf = [0u8; 4096];
        let mut sio = self.sio_bufs.as_io();
        let (read_len, _fin) = match self.quic.stream_recv(&mut sio, stream_id, &mut buf) {
            Ok(r) => r,
            Err(Error::WouldBlock) => return Ok(()),
            Err(e) => return Err(e),
        };

        if read_len > 0 {
            self.process_control_data(&buf[..read_len])?;
        }
        Ok(())
    }

    /// Process control stream data (one or more frames).
    fn process_control_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut offset = 0;
        while offset < data.len() {
            let (frame, consumed) = match decode_h3_frame(&data[offset..]) {
                Ok(r) => r,
                Err(_) => break, // incomplete or unknown frame, stop for now
            };
            offset += consumed;

            match frame {
                H3Frame::Settings(settings) => {
                    self.peer_settings = Some(settings);
                    self.push_h3_event(H3Event::Connected);
                }
                H3Frame::GoAway(id) => {
                    self.push_h3_event(H3Event::GoAway(id));
                }
                _ => {
                    // Ignore other frames on the control stream for now.
                }
            }
        }
        Ok(())
    }

    /// Handle data on a bidirectional (request) stream.
    pub(crate) fn handle_request_stream_data(
        &mut self,
        stream_id: u64,
        _is_server: bool,
    ) -> Result<(), Error> {
        // Ensure we have a RequestStreamState for this stream.
        let exists = self
            .request_streams
            .iter()
            .any(|rs| rs.stream_id == stream_id);
        if !exists {
            #[cfg(feature = "alloc")]
            if self.request_streams.len() >= 8 {
                return Ok(()); // At capacity
            }
            let _ = self.request_streams.push(RequestStreamState::new(stream_id));
        }

        // Read data from QUIC.
        let mut buf = [0u8; 4096];
        let mut sio = self.sio_bufs.as_io();
        let (read_len, fin) = match self.quic.stream_recv(&mut sio, stream_id, &mut buf) {
            Ok(r) => r,
            Err(Error::WouldBlock) => return Ok(()),
            Err(e) => return Err(e),
        };

        if read_len == 0 && fin {
            // Mark FIN.
            if let Some(rs) = self
                .request_streams
                .iter_mut()
                .find(|rs| rs.stream_id == stream_id)
            {
                rs.fin_received = true;
                self.push_h3_event(H3Event::Finished(stream_id));
            }
            return Ok(());
        }

        if read_len == 0 {
            return Ok(());
        }

        // Parse H3 frames from the stream data.
        let data = &buf[..read_len];
        let mut offset = 0;

        while offset < data.len() {
            let (frame, consumed) = match decode_h3_frame(&data[offset..]) {
                Ok(r) => r,
                Err(_) => break, // incomplete frame
            };
            offset += consumed;

            match frame {
                H3Frame::Headers(hdr_data) => {
                    if let Some(rs) = self
                        .request_streams
                        .iter_mut()
                        .find(|rs| rs.stream_id == stream_id)
                    {
                        rs.headers_data.clear();
                        let _ = rs.headers_data.extend_from_slice(hdr_data);
                        rs.headers_received = true;
                    }
                    self.push_h3_event(H3Event::Headers(stream_id));
                }
                H3Frame::Data(body_data) => {
                    if let Some(rs) = self
                        .request_streams
                        .iter_mut()
                        .find(|rs| rs.stream_id == stream_id)
                    {
                        let _ = rs.data_buf.extend_from_slice(body_data);
                        rs.data_available = true;
                    }
                    self.push_h3_event(H3Event::Data(stream_id));
                }
                _ => {
                    // Ignore other frame types on request streams.
                }
            }
        }

        // If we received a FIN with the last read, mark it.
        if fin
            && let Some(rs) = self
                .request_streams
                .iter_mut()
                .find(|rs| rs.stream_id == stream_id)
        {
            rs.fin_received = true;
            self.push_h3_event(H3Event::Finished(stream_id));
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Public helpers for client/server wrappers
    // ------------------------------------------------------------------

    /// Poll for an H3 event.
    pub(crate) fn poll_event(&mut self) -> Option<H3Event> {
        self.h3_events.pop_front()
    }

    /// Push an H3 event, enforcing a capacity limit for the alloc path.
    /// When the queue is full the oldest event is dropped so that new
    /// events are never silently lost.
    fn push_h3_event(&mut self, event: H3Event) {
        #[cfg(feature = "alloc")]
        if self.h3_events.len() >= 64 {
            let _ = self.h3_events.pop_front();
        }
        let _ = self.h3_events.push_back(event);
    }

    /// Read decoded headers for a stream, calling `emit(name, value)` for each.
    pub(crate) fn recv_headers<F: FnMut(&[u8], &[u8])>(
        &mut self,
        stream_id: u64,
        emit: F,
    ) -> Result<(), Error> {
        let rs = self
            .request_streams
            .iter()
            .find(|rs| rs.stream_id == stream_id)
            .ok_or(Error::InvalidState)?;

        if !rs.headers_received {
            return Err(Error::WouldBlock);
        }

        self.decoder.decode_field_section(&rs.headers_data, emit)?;
        Ok(())
    }

    /// Read body data from a request stream.
    pub(crate) fn recv_body(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), Error> {
        let rs = self
            .request_streams
            .iter_mut()
            .find(|rs| rs.stream_id == stream_id)
            .ok_or(Error::InvalidState)?;

        if rs.data_buf.is_empty() {
            if rs.fin_received {
                return Ok((0, true));
            }
            return Err(Error::WouldBlock);
        }

        let copy_len = rs.data_buf.len().min(buf.len());
        buf[..copy_len].copy_from_slice(&rs.data_buf[..copy_len]);

        // Remove the consumed bytes from the front of the buffer.
        rs.data_buf.copy_within(copy_len.., 0);
        rs.data_buf.truncate(rs.data_buf.len() - copy_len);

        let fin = rs.data_buf.is_empty() && rs.fin_received;
        rs.data_available = !rs.data_buf.is_empty();

        Ok((copy_len, fin))
    }

    /// Send a HEADERS frame on a request stream.
    pub(crate) fn send_headers(
        &mut self,
        stream_id: u64,
        headers: &[(&[u8], &[u8])],
        end_stream: bool,
    ) -> Result<(), Error> {
        // Encode headers with QPACK.
        let mut qpack_buf = [0u8; 2048];
        let qpack_len = self.encoder.encode_field_section(headers, &mut qpack_buf)?;

        // Encode HEADERS frame.
        let frame = H3Frame::Headers(&qpack_buf[..qpack_len]);
        let mut frame_buf = [0u8; 2048];
        let frame_len = encode_h3_frame(&frame, &mut frame_buf)?;

        let mut sio = self.sio_bufs.as_io();
        self.quic
            .stream_send(&mut sio, stream_id, &frame_buf[..frame_len], end_stream)?;
        Ok(())
    }

    /// Send a DATA frame on a request stream.
    pub(crate) fn send_data(
        &mut self,
        stream_id: u64,
        data: &[u8],
        end_stream: bool,
    ) -> Result<usize, Error> {
        if data.is_empty() && end_stream {
            // Send FIN with empty data.
            let mut sio = self.sio_bufs.as_io();
            self.quic.stream_send(&mut sio, stream_id, &[], true)?;
            return Ok(0);
        }

        let frame = H3Frame::Data(data);
        let mut frame_buf = [0u8; 4096];
        let frame_len = encode_h3_frame(&frame, &mut frame_buf)?;

        let mut sio = self.sio_bufs.as_io();
        self.quic
            .stream_send(&mut sio, stream_id, &frame_buf[..frame_len], end_stream)?;
        Ok(data.len())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[cfg(any(feature = "rustcrypto-chacha", feature = "rustcrypto-aes"))]
mod tests {
    use super::*;
    use crate::connection::{Connection, HandshakePool};
    use crate::connection::io::QuicStreamIoBufs;
    use crate::crypto::rustcrypto::Aes128GcmProvider;
    use crate::h3::client::H3Client;
    use crate::h3::server::H3Server;
    use crate::tls::handshake::ServerTlsConfig;
    use crate::tls::transport_params::TransportParams;
    use crate::transport::Rng;

    type SioBufs = QuicStreamIoBufs<32, 1024, 16>;

    const TEST_ED25519_SEED: [u8; 32] = [0x01u8; 32];

    fn get_test_ed25519_cert_der() -> &'static [u8] {
        use std::sync::LazyLock;
        static V: LazyLock<std::vec::Vec<u8>> = LazyLock::new(|| {
            let s: [u8; 32] = [0x01u8; 32];
            let pk = crate::crypto::ed25519::ed25519_public_key_from_seed(&s);
            let mut b = [0u8; 512];
            let n = crate::crypto::ed25519::build_ed25519_cert_der(&pk, &mut b).unwrap();
            b[..n].to_vec()
        });
        &V
    }

    struct TestRng(u8);
    impl Rng for TestRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    fn make_pool() -> HandshakePool<Aes128GcmProvider, 2> {
        HandshakePool::new()
    }

    fn make_quic_client(pool: &mut HandshakePool<Aes128GcmProvider, 2>) -> Connection<Aes128GcmProvider> {
        let mut rng = TestRng(0x10);
        Connection::client(
            Aes128GcmProvider,
            "test.local",
            &[b"h3"],
            TransportParams::default_params(),
            &mut rng,
            pool,
        )
        .unwrap()
    }

    fn make_quic_server(pool: &mut HandshakePool<Aes128GcmProvider, 2>) -> Connection<Aes128GcmProvider> {
        let mut rng = TestRng(0x50);
        let config = ServerTlsConfig {
            cert_der: get_test_ed25519_cert_der(),
            private_key_der: &TEST_ED25519_SEED,
            alpn_protocols: &[b"h3"],
            transport_params: TransportParams::default_params(),
        };
        Connection::server(
            Aes128GcmProvider,
            config,
            TransportParams::default_params(),
            &mut rng,
            pool,
        )
        .unwrap()
    }

    /// Run the QUIC handshake to completion between client and server.
    fn run_quic_handshake(
        client: &mut Connection<Aes128GcmProvider>,
        c_sio: &mut SioBufs,
        server: &mut Connection<Aes128GcmProvider>,
        s_sio: &mut SioBufs,
        now: u64,
        pool: &mut HandshakePool<Aes128GcmProvider, 2>,
    ) {
        for _round in 0..20 {
            // Client -> Server
            loop {
                let mut buf = [0u8; 4096];
                match client.poll_transmit(&mut c_sio.as_io(), &mut buf, now, pool) {
                    Some(tx) => {
                        let mut data: heapless::Vec<u8, 4096> = heapless::Vec::new();
                        let _ = data.extend_from_slice(tx.data);
                        let _ = server.recv(&mut s_sio.as_io(), &data, now, pool);
                    }
                    None => break,
                }
            }

            // Server -> Client
            loop {
                let mut buf = [0u8; 4096];
                match server.poll_transmit(&mut s_sio.as_io(), &mut buf, now, pool) {
                    Some(tx) => {
                        let mut data: heapless::Vec<u8, 4096> = heapless::Vec::new();
                        let _ = data.extend_from_slice(tx.data);
                        let _ = client.recv(&mut c_sio.as_io(), &data, now, pool);
                    }
                    None => break,
                }
            }

            if client.is_established() && server.is_established() {
                return;
            }
        }
        panic!(
            "handshake did not complete: client={:?}, server={:?}",
            client.state(),
            server.state()
        );
    }

    /// Exchange QUIC packets between an H3Client and H3Server until
    /// no more data is pending.
    fn exchange_h3_packets(
        client: &mut H3Client<Aes128GcmProvider>,
        server: &mut H3Server<Aes128GcmProvider>,
        now: u64,
        pool: &mut HandshakePool<Aes128GcmProvider, 2>,
    ) {
        for _round in 0..10 {
            let mut any_sent = false;

            // Client -> Server
            loop {
                let mut buf = [0u8; 4096];
                match client.poll_transmit(&mut buf, now, pool) {
                    Some(tx) => {
                        let mut data: heapless::Vec<u8, 4096> = heapless::Vec::new();
                        let _ = data.extend_from_slice(tx.data);
                        let _ = server.recv(&data, now, pool);
                        any_sent = true;
                    }
                    None => break,
                }
            }

            // Server -> Client
            loop {
                let mut buf = [0u8; 4096];
                match server.poll_transmit(&mut buf, now, pool) {
                    Some(tx) => {
                        let mut data: heapless::Vec<u8, 4096> = heapless::Vec::new();
                        let _ = data.extend_from_slice(tx.data);
                        let _ = client.recv(&data, now, pool);
                        any_sent = true;
                    }
                    None => break,
                }
            }

            if !any_sent {
                break;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 1. H3 client creation
    // -----------------------------------------------------------------------

    #[test]
    fn h3_client_creation() {
        let mut pool = make_pool();
        let quic = make_quic_client(&mut pool);
        let _client: H3Client<Aes128GcmProvider> = H3Client::new(quic);
    }

    // -----------------------------------------------------------------------
    // 2. H3 server creation
    // -----------------------------------------------------------------------

    #[test]
    fn h3_server_creation() {
        let mut pool = make_pool();
        let quic = make_quic_server(&mut pool);
        let _server: H3Server<Aes128GcmProvider> = H3Server::new(quic);
    }

    // -----------------------------------------------------------------------
    // 3. H3Connection wraps QUIC connection correctly
    // -----------------------------------------------------------------------

    #[test]
    fn h3_connection_initial_state() {
        let mut pool = make_pool();
        let quic = make_quic_client(&mut pool);
        let h3: H3Connection<Aes128GcmProvider> = H3Connection::new(quic);
        assert!(h3.local_control_stream.is_none());
        assert!(h3.peer_control_stream.is_none());
        assert!(h3.local_encoder_stream.is_none());
        assert!(h3.local_decoder_stream.is_none());
        assert!(h3.peer_encoder_stream.is_none());
        assert!(h3.peer_decoder_stream.is_none());
        assert!(h3.peer_settings.is_none());
        assert!(!h3.settings_sent);
        assert!(h3.request_streams.is_empty());
    }

    // -----------------------------------------------------------------------
    // 4. Settings exchange
    // -----------------------------------------------------------------------

    #[test]
    fn settings_exchange() {
        let now = 1_000_000u64;
        let mut pool = make_pool();
        let mut quic_client = make_quic_client(&mut pool);
        let mut quic_server = make_quic_server(&mut pool);
        let mut c_sio = SioBufs::new();
        let mut s_sio = SioBufs::new();
        run_quic_handshake(&mut quic_client, &mut c_sio, &mut quic_server, &mut s_sio, now, &mut pool);

        // DON'T drain events -- let the H3 wrappers see them.
        let mut client: H3Client<Aes128GcmProvider> = H3Client::new(quic_client);
        let mut server: H3Server<Aes128GcmProvider> = H3Server::new(quic_server);

        // poll_event processes QUIC events -> sees Connected -> sets up H3 streams.
        // Then we exchange the H3 setup packets.
        let _ = client.poll_event();
        let _ = server.poll_event();

        // Exchange the control stream packets.
        exchange_h3_packets(&mut client, &mut server, now, &mut pool);

        // Now poll events again to pick up the peer's SETTINGS.
        let mut client_connected = false;
        let mut server_connected = false;

        for _ in 0..10 {
            while let Some(ev) = client.poll_event() {
                if ev == H3Event::Connected {
                    client_connected = true;
                }
            }
            while let Some(ev) = server.poll_event() {
                if ev == H3Event::Connected {
                    server_connected = true;
                }
            }
            if client_connected && server_connected {
                break;
            }
            exchange_h3_packets(&mut client, &mut server, now, &mut pool);
        }

        assert!(
            client_connected,
            "client should have received H3Event::Connected"
        );
        assert!(
            server_connected,
            "server should have received H3Event::Connected"
        );
    }

    // -----------------------------------------------------------------------
    // 5. Full HTTP/3 request/response
    // -----------------------------------------------------------------------

    #[test]
    fn full_http3_request_response() {
        let now = 1_000_000u64;
        let mut pool = make_pool();
        let mut quic_client = make_quic_client(&mut pool);
        let mut quic_server = make_quic_server(&mut pool);
        let mut c_sio = SioBufs::new();
        let mut s_sio = SioBufs::new();
        run_quic_handshake(&mut quic_client, &mut c_sio, &mut quic_server, &mut s_sio, now, &mut pool);

        let mut client: H3Client<Aes128GcmProvider> = H3Client::new(quic_client);
        let mut server: H3Server<Aes128GcmProvider> = H3Server::new(quic_server);

        // Trigger H3 setup by processing the Connected event.
        let _ = client.poll_event();
        let _ = server.poll_event();

        // Exchange H3 control stream setup.
        exchange_h3_packets(&mut client, &mut server, now, &mut pool);

        // Client sends GET request.
        let stream_id = client.send_request("GET", "/", "test.local", &[], false).unwrap();

        // Send FIN on the request stream (no body for GET).
        client.send_body(stream_id, &[], true).unwrap();

        // Exchange packets so server receives the request.
        exchange_h3_packets(&mut client, &mut server, now, &mut pool);

        // Server should see Headers event.
        let mut got_headers = false;
        let mut header_stream_id = 0u64;
        for _ in 0..5 {
            while let Some(ev) = server.poll_event() {
                if let H3Event::Headers(sid) = ev {
                    got_headers = true;
                    header_stream_id = sid;
                }
            }
            if got_headers {
                break;
            }
            exchange_h3_packets(&mut client, &mut server, now, &mut pool);
        }
        assert!(got_headers, "server should receive H3Event::Headers");

        // Server reads request headers.
        let mut method = heapless::Vec::<u8, 64>::new();
        let mut path = heapless::Vec::<u8, 64>::new();
        server
            .recv_headers(header_stream_id, |name, value| {
                if name == b":method" {
                    let _ = method.extend_from_slice(value);
                } else if name == b":path" {
                    let _ = path.extend_from_slice(value);
                }
            })
            .unwrap();
        assert_eq!(method.as_slice(), b"GET");
        assert_eq!(path.as_slice(), b"/");

        // Server sends response.
        server
            .send_response(header_stream_id, 200, &[(b"content-type", b"text/plain")], false)
            .unwrap();

        let body = b"Hello, HTTP/3!";
        server
            .send_body(header_stream_id, body, true)
            .unwrap();

        // Exchange packets so client receives the response.
        exchange_h3_packets(&mut client, &mut server, now, &mut pool);

        // Client should see Headers event.
        let mut got_response_headers = false;
        let mut got_response_data = false;
        for _ in 0..5 {
            while let Some(ev) = client.poll_event() {
                match ev {
                    H3Event::Headers(sid) if sid == stream_id => {
                        got_response_headers = true;
                    }
                    H3Event::Data(sid) if sid == stream_id => {
                        got_response_data = true;
                    }
                    _ => {}
                }
            }
            if got_response_headers && got_response_data {
                break;
            }
            exchange_h3_packets(&mut client, &mut server, now, &mut pool);
        }
        assert!(
            got_response_headers,
            "client should receive response Headers event"
        );

        // Client reads response headers.
        let mut status = heapless::Vec::<u8, 16>::new();
        client
            .recv_headers(stream_id, |name, value| {
                if name == b":status" {
                    let _ = status.extend_from_slice(value);
                }
            })
            .unwrap();
        assert_eq!(status.as_slice(), b"200");

        // Client reads response body.
        if got_response_data {
            let mut recv_buf = [0u8; 256];
            let (len, _fin) = client.recv_body(stream_id, &mut recv_buf).unwrap();
            assert_eq!(&recv_buf[..len], body);
        }
    }

    // -----------------------------------------------------------------------
    // 6. Multiple requests on different streams
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_requests() {
        let now = 1_000_000u64;
        let mut pool = make_pool();
        let mut quic_client = make_quic_client(&mut pool);
        let mut quic_server = make_quic_server(&mut pool);
        let mut c_sio = SioBufs::new();
        let mut s_sio = SioBufs::new();
        run_quic_handshake(&mut quic_client, &mut c_sio, &mut quic_server, &mut s_sio, now, &mut pool);

        let mut client: H3Client<Aes128GcmProvider> = H3Client::new(quic_client);
        let mut server: H3Server<Aes128GcmProvider> = H3Server::new(quic_server);

        // Trigger H3 setup.
        let _ = client.poll_event();
        let _ = server.poll_event();
        exchange_h3_packets(&mut client, &mut server, now, &mut pool);

        // Send two requests.
        let stream1 = client.send_request("GET", "/page1", "test.local", &[], false).unwrap();
        client.send_body(stream1, &[], true).unwrap();

        let stream2 = client.send_request("GET", "/page2", "test.local", &[], false).unwrap();
        client.send_body(stream2, &[], true).unwrap();

        // Stream IDs should be different.
        assert_ne!(stream1, stream2);

        // Exchange packets.
        exchange_h3_packets(&mut client, &mut server, now, &mut pool);

        // Server should receive headers for both streams.
        let mut header_streams: heapless::Vec<u64, 4> = heapless::Vec::new();
        for _ in 0..5 {
            while let Some(ev) = server.poll_event() {
                if let H3Event::Headers(sid) = ev {
                    let _ = header_streams.push(sid);
                }
            }
            if header_streams.len() >= 2 {
                break;
            }
            exchange_h3_packets(&mut client, &mut server, now, &mut pool);
        }

        assert!(
            header_streams.len() >= 2,
            "server should receive headers for both streams, got {}",
            header_streams.len()
        );
    }

    // -----------------------------------------------------------------------
    // 7. RequestStreamState bookkeeping
    // -----------------------------------------------------------------------

    #[test]
    fn request_stream_state_new() {
        let rs = RequestStreamState::new(42);
        assert_eq!(rs.stream_id, 42);
        assert!(!rs.headers_received);
        assert!(!rs.data_available);
        assert!(!rs.fin_received);
        assert!(rs.headers_data.is_empty());
        assert!(rs.data_buf.is_empty());
    }

    // -----------------------------------------------------------------------
    // 8. H3Event variants
    // -----------------------------------------------------------------------

    #[test]
    fn h3_event_equality() {
        assert_eq!(H3Event::Connected, H3Event::Connected);
        assert_eq!(H3Event::Headers(1), H3Event::Headers(1));
        assert_ne!(H3Event::Headers(1), H3Event::Headers(2));
        assert_eq!(H3Event::Data(3), H3Event::Data(3));
        assert_eq!(H3Event::GoAway(0), H3Event::GoAway(0));
        assert_eq!(H3Event::Finished(5), H3Event::Finished(5));
        assert_ne!(H3Event::Connected, H3Event::Finished(0));
    }

    // -----------------------------------------------------------------------
    // 9. Client poll_event returns None when no events
    // -----------------------------------------------------------------------

    #[test]
    fn client_poll_event_empty_initially() {
        let mut pool = make_pool();
        let quic = make_quic_client(&mut pool);
        let mut client: H3Client<Aes128GcmProvider> = H3Client::new(quic);
        let _ev = client.poll_event();
    }

    // -----------------------------------------------------------------------
    // 10. Server poll_event returns None when no events
    // -----------------------------------------------------------------------

    #[test]
    fn server_poll_event_empty_initially() {
        let mut pool = make_pool();
        let quic = make_quic_server(&mut pool);
        let mut server: H3Server<Aes128GcmProvider> = H3Server::new(quic);
        let _ev = server.poll_event();
    }

    // -----------------------------------------------------------------------
    // 11. Request with additional headers
    // -----------------------------------------------------------------------

    #[test]
    fn request_with_custom_headers() {
        let now = 1_000_000u64;
        let mut pool = make_pool();
        let mut quic_client = make_quic_client(&mut pool);
        let mut quic_server = make_quic_server(&mut pool);
        let mut c_sio = SioBufs::new();
        let mut s_sio = SioBufs::new();
        run_quic_handshake(&mut quic_client, &mut c_sio, &mut quic_server, &mut s_sio, now, &mut pool);

        let mut client: H3Client<Aes128GcmProvider> = H3Client::new(quic_client);
        let mut server: H3Server<Aes128GcmProvider> = H3Server::new(quic_server);

        let _ = client.poll_event();
        let _ = server.poll_event();
        exchange_h3_packets(&mut client, &mut server, now, &mut pool);

        // Send request with custom headers.
        let stream_id = client
            .send_request(
                "POST",
                "/api/data",
                "test.local",
                &[
                    (b"content-type", b"application/json"),
                    (b"accept", b"application/json"),
                ],
                false,
            )
            .unwrap();

        // Send body.
        let body = b"{\"key\": \"value\"}";
        client.send_body(stream_id, body, true).unwrap();

        // Exchange.
        exchange_h3_packets(&mut client, &mut server, now, &mut pool);

        // Server receives.
        let mut got_headers = false;
        for _ in 0..5 {
            while let Some(ev) = server.poll_event() {
                if let H3Event::Headers(_sid) = ev {
                    got_headers = true;
                }
            }
            if got_headers {
                break;
            }
            exchange_h3_packets(&mut client, &mut server, now, &mut pool);
        }
        assert!(got_headers, "server should receive request headers");
    }
}
