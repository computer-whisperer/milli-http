//! TCP TLS record layer (RFC 8446).
//!
//! Standalone middleware: TCP socket ↔ TlsConnection ↔ H2Connection / Http1Connection.

pub mod client;
pub mod connection;
pub mod io;
pub mod record;
pub mod server;

pub use client::TlsClient;
pub use connection::{TlsConnection, TlsEvent};
pub use io::{TlsIo, TlsIoBufs};
pub use server::TlsServer;

use crate::buf::Buf;
use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::tls::handshake::ServerTlsConfig;

/// Pre-handshake TLS state with shared buffers.
///
/// Used by the connection manager to drive TLS handshake before protocol
/// selection (ALPN). Once the handshake completes, call `alpn()` and then
/// construct the appropriate HTTP type via `from_parts`.
pub struct TlsParts<C: CryptoProvider, const BUF: usize = 18432> {
    pub tls: TlsConnection<C>,
    pub net_recv: Buf<BUF>,
    pub net_send: Buf<BUF>,
    pub app_recv: Buf<BUF>,
    pub app_send: Buf<BUF>,
}

impl<C: CryptoProvider, const BUF: usize> TlsParts<C, BUF>
where
    C::Hkdf: Default,
{
    /// Create new server-side TLS parts.
    pub fn new_server(
        provider: C,
        config: ServerTlsConfig,
        secret: [u8; 32],
        random: [u8; 32],
    ) -> Self {
        Self {
            tls: TlsConnection::new_server(provider, config, secret, random),
            net_recv: Buf::new(),
            net_send: Buf::new(),
            app_recv: Buf::new(),
            app_send: Buf::new(),
        }
    }

    /// Feed encrypted TCP data, driving the TLS handshake forward.
    pub fn feed_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut tls_io: TlsIo<'_, BUF> = TlsIo {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.net_send,
            app_recv_buf: &mut self.app_recv,
            app_send_buf: &mut self.app_send,
        };
        self.tls.feed_data(&mut tls_io, data)
    }

    /// Pull outgoing encrypted TLS data (handshake messages).
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        let mut tls_io: TlsIo<'_, BUF> = TlsIo {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.net_send,
            app_recv_buf: &mut self.app_recv,
            app_send_buf: &mut self.app_send,
        };
        self.tls.poll_output(&mut tls_io, buf)
    }

    /// Whether the TLS handshake is complete.
    pub fn is_active(&self) -> bool {
        self.tls.is_active()
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.tls.is_closed()
    }

    /// Get the negotiated ALPN protocol (available after handshake).
    pub fn alpn(&self) -> Option<&[u8]> {
        self.tls.alpn()
    }
}
