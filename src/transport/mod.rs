pub mod congestion;
pub mod flow_control;
pub mod loss;
pub mod recovery;
pub mod stream;

use core::task::{Context, Poll};

/// Timestamp in microseconds from an arbitrary epoch.
/// Used for RTT measurement and loss detection timers.
pub type Instant = u64;

/// Clock for loss detection timers and RTT measurement.
pub trait Clock {
    /// Current time in microseconds from an arbitrary epoch.
    fn now(&self) -> Instant;
}

/// Random bytes for connection IDs and nonces.
///
/// On RP2350: implement via hardware TRNG peripheral.
/// Elsewhere: any cryptographic RNG source.
pub trait Rng {
    /// Fill `buf` with random bytes.
    fn fill(&mut self, buf: &mut [u8]);
}

/// Address type — opaque to the QUIC stack, meaningful to the caller.
pub trait Address: Clone + PartialEq {}

// Blanket impl: anything Clone + PartialEq is an Address.
impl<T: Clone + PartialEq> Address for T {}

// ---------------------------------------------------------------------------
// Poll-based socket traits
// ---------------------------------------------------------------------------

/// Poll-based TCP byte stream.
///
/// Implementors: Embassy `TcpSocket`, Tokio `AsyncFd`-wrapped sockets, smoltcp, etc.
pub trait TcpStream {
    type Error;

    /// Attempt to read data. Registers waker if `Poll::Pending`.
    fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Self::Error>>;

    /// Attempt to write data. Registers waker if `Poll::Pending`.
    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Self::Error>>;
}

/// Poll-based TCP listener.
pub trait TcpAccept {
    type Stream: TcpStream;
    type Error;

    /// Attempt to accept a new connection. Registers waker if `Poll::Pending`.
    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<Self::Stream, Self::Error>>;
}

/// Poll-based UDP socket.
pub trait UdpSocket {
    type Addr: Address;
    type Error;

    /// Attempt to receive a datagram. Registers waker if `Poll::Pending`.
    fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<(usize, Self::Addr), Self::Error>>;

    /// Attempt to send a datagram. Registers waker if `Poll::Pending`.
    fn poll_send_to(
        &mut self,
        cx: &mut Context<'_>,
        buf: &[u8],
        addr: &Self::Addr,
    ) -> Poll<Result<(), Self::Error>>;
}

/// A [`UdpSocket`] that never receives and discards sends.
///
/// TCP-only server builds (`h3` feature disabled) still name a UDP socket type
/// in the server runner's generics; this zero-sized placeholder is the
/// canonical choice. The runner never polls UDP when `h3` is off, so neither
/// method is reached in practice.
pub struct NoUdp<A>(core::marker::PhantomData<A>);

impl<A> NoUdp<A> {
    pub const fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<A> Default for NoUdp<A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<A: Address> UdpSocket for NoUdp<A> {
    type Addr = A;
    type Error = core::convert::Infallible;

    fn poll_recv_from(
        &mut self,
        _cx: &mut Context<'_>,
        _buf: &mut [u8],
    ) -> Poll<Result<(usize, Self::Addr), Self::Error>> {
        Poll::Pending
    }

    fn poll_send_to(
        &mut self,
        _cx: &mut Context<'_>,
        _buf: &[u8],
        _addr: &Self::Addr,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
