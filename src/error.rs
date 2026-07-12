/// QUIC transport error codes (RFC 9000 §20).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum TransportError {
    NoError = 0x00,
    InternalError = 0x01,
    ConnectionRefused = 0x02,
    FlowControlError = 0x03,
    StreamLimitError = 0x04,
    StreamStateError = 0x05,
    FinalSizeError = 0x06,
    FrameEncodingError = 0x07,
    TransportParameterError = 0x08,
    ConnectionIdLimitError = 0x09,
    ProtocolViolation = 0x0a,
    InvalidToken = 0x0b,
    ApplicationError = 0x0c,
    CryptoBufferExceeded = 0x0d,
    KeyUpdateError = 0x0e,
    AeadLimitReached = 0x0f,
    NoViablePath = 0x10,
    VersionNegotiationError = 0x11,
}

impl TransportError {
    /// Convert a transport error to its RFC 9000 wire code.
    pub const fn to_code(self) -> u64 {
        self as u64
    }

    /// Create a `CryptoError` transport error (0x0100 + TLS alert code).
    pub const fn crypto_error(alert_code: u8) -> u64 {
        0x0100 + alert_code as u64
    }

    /// Parse a wire error code into a `TransportError`.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0x00 => Some(Self::NoError),
            0x01 => Some(Self::InternalError),
            0x02 => Some(Self::ConnectionRefused),
            0x03 => Some(Self::FlowControlError),
            0x04 => Some(Self::StreamLimitError),
            0x05 => Some(Self::StreamStateError),
            0x06 => Some(Self::FinalSizeError),
            0x07 => Some(Self::FrameEncodingError),
            0x08 => Some(Self::TransportParameterError),
            0x09 => Some(Self::ConnectionIdLimitError),
            0x0a => Some(Self::ProtocolViolation),
            0x0b => Some(Self::InvalidToken),
            0x0c => Some(Self::ApplicationError),
            0x0d => Some(Self::CryptoBufferExceeded),
            0x0e => Some(Self::KeyUpdateError),
            0x0f => Some(Self::AeadLimitReached),
            0x10 => Some(Self::NoViablePath),
            0x11 => Some(Self::VersionNegotiationError),
            _ => None,
        }
    }
}

/// HTTP/3 error codes (RFC 9114 §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum H3Error {
    NoError = 0x0100,
    GeneralProtocolError = 0x0101,
    InternalError = 0x0102,
    StreamCreationError = 0x0103,
    ClosedCriticalStream = 0x0104,
    FrameUnexpected = 0x0105,
    FrameError = 0x0106,
    ExcessiveLoad = 0x0107,
    IdError = 0x0108,
    SettingsError = 0x0109,
    MissingSettings = 0x010a,
    RequestRejected = 0x010b,
    RequestCancelled = 0x010c,
    RequestIncomplete = 0x010d,
    MessageError = 0x010e,
    ConnectError = 0x010f,
    VersionFallback = 0x0110,
    QpackDecompressionFailed = 0x0200,
    QpackEncoderStreamError = 0x0201,
    QpackDecoderStreamError = 0x0202,
}

impl H3Error {
    pub const fn to_code(self) -> u64 {
        self as u64
    }
}

/// HTTP/2 error codes (RFC 9113 §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
#[cfg(feature = "h2")]
pub enum H2Error {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
}

#[cfg(feature = "h2")]
impl H2Error {
    pub const fn to_code(self) -> u32 {
        self as u32
    }

    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            0x0 => Some(Self::NoError),
            0x1 => Some(Self::ProtocolError),
            0x2 => Some(Self::InternalError),
            0x3 => Some(Self::FlowControlError),
            0x4 => Some(Self::SettingsTimeout),
            0x5 => Some(Self::StreamClosed),
            0x6 => Some(Self::FrameSizeError),
            0x7 => Some(Self::RefusedStream),
            0x8 => Some(Self::Cancel),
            0x9 => Some(Self::CompressionError),
            0xa => Some(Self::ConnectError),
            0xb => Some(Self::EnhanceYourCalm),
            0xc => Some(Self::InadequateSecurity),
            0xd => Some(Self::Http11Required),
            _ => None,
        }
    }
}

/// Top-level crate error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// QUIC transport error — connection must close.
    Transport(TransportError),
    /// HTTP/3 error.
    Http3(H3Error),
    /// HTTP/2 error.
    #[cfg(feature = "h2")]
    Http2(H2Error),
    /// Cryptographic operation failed.
    Crypto,
    /// TLS handshake error.
    Tls,
    /// Caller-provided buffer too small.
    BufferTooSmall { needed: usize },
    /// The allocator could not satisfy a buffer growth request. Unlike
    /// `BufferTooSmall` (a per-connection bound that clears as the peer
    /// drains), this signals global memory pressure — shedding the
    /// connection/subscriber is a reasonable response.
    OutOfMemory,
    /// No more stream slots available.
    StreamLimitExhausted,
    /// Connection is closed.
    Closed,
    /// Would block — no data available.
    WouldBlock,
    /// Invalid state for the requested operation.
    InvalidState,
    /// All handshake pool slots are in use.
    HandshakePoolExhausted,
    /// Too many headers for the fixed-size header list.
    TooManyHeaders,
}

impl From<TransportError> for Error {
    fn from(e: TransportError) -> Self {
        Error::Transport(e)
    }
}

impl From<H3Error> for Error {
    fn from(e: H3Error) -> Self {
        Error::Http3(e)
    }
}

#[cfg(feature = "h2")]
impl From<H2Error> for Error {
    fn from(e: H2Error) -> Self {
        Error::Http2(e)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Transport(e) => write!(f, "transport error: {e:?}"),
            Error::Http3(e) => write!(f, "HTTP/3 error: {e:?}"),
            #[cfg(feature = "h2")]
            Error::Http2(e) => write!(f, "HTTP/2 error: {e:?}"),
            Error::Crypto => write!(f, "cryptographic error"),
            Error::Tls => write!(f, "TLS error"),
            Error::BufferTooSmall { needed } => {
                write!(f, "buffer too small, need {needed} bytes")
            }
            Error::OutOfMemory => write!(f, "allocator exhausted"),
            Error::StreamLimitExhausted => write!(f, "stream limit exhausted"),
            Error::Closed => write!(f, "connection closed"),
            Error::WouldBlock => write!(f, "would block"),
            Error::InvalidState => write!(f, "invalid state"),
            Error::HandshakePoolExhausted => write!(f, "handshake pool exhausted"),
            Error::TooManyHeaders => write!(f, "too many headers"),
        }
    }
}
