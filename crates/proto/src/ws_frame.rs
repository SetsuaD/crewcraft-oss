//! WebSocket frames (RFC 6455 section 5): reading the frames a peer sends and writing the frames we send. The server
//! reads masked frames from clients and writes unmasked ones; a client does the reverse. Strict about what the RFC says a
//! receiver must refuse, because a connection that sends such a frame is closed rather than repaired. Messages built from
//! frames are `ws_message` (T209); the opening handshake is `websocket` (T207). Task T208.

/// Largest payload one frame may carry (1 MiB, as `frame::MAX_FRAME`). A longer announced length is refused as soon as its
/// header is read.
pub const MAX_PAYLOAD: usize = 1 << 20;
/// Largest payload of a control frame (close, ping, pong), RFC 6455 section 5.5.
pub const MAX_CONTROL_PAYLOAD: usize = 125;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

impl Opcode {
    /// 0 Continuation, 1 Text, 2 Binary, 8 Close, 9 Ping, 10 Pong; every other value is `None`.
    pub fn from_u8(value: u8) -> Option<Opcode> {
        match value {
            0 => Some(Opcode::Continuation),
            1 => Some(Opcode::Text),
            2 => Some(Opcode::Binary),
            8 => Some(Opcode::Close),
            9 => Some(Opcode::Ping),
            10 => Some(Opcode::Pong),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Opcode::Continuation => 0,
            Opcode::Text => 1,
            Opcode::Binary => 2,
            Opcode::Close => 8,
            Opcode::Ping => 9,
            Opcode::Pong => 10,
        }
    }

    /// Close, ping and pong.
    pub fn is_control(self) -> bool {
        matches!(self, Opcode::Close | Opcode::Ping | Opcode::Pong)
    }
}

/// One frame with its payload unmasked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The final fragment of a message.
    pub fin: bool,
    pub opcode: Opcode,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsError {
    /// RSV1, RSV2 or RSV3 set (no extension is negotiated).
    ReservedBits,
    /// An opcode that is not one of the six (carries it).
    BadOpcode(u8),
    /// A frame from a client without the mask bit.
    Unmasked,
    /// A frame from the server with the mask bit.
    Masked,
    /// A payload longer than `MAX_PAYLOAD` (carries the announced or given length), or a length with its top bit set.
    TooLarge(u64),
    /// A control frame with more than `MAX_CONTROL_PAYLOAD` bytes.
    ControlTooLong,
    /// A control frame with `fin` clear.
    ControlFragmented,
    /// A length written in a longer form than needed (126 for under 126, 127 for 65535 or less).
    NonMinimalLength,
    // The variants below belong to `ws_message` (T209); `ws_frame` never returns them.
    /// A continuation frame with no message in progress.
    UnexpectedContinuation,
    /// A text or binary frame while a fragmented message is still in progress.
    InterleavedData,
    /// A message longer than the assembler's limit.
    MessageTooLarge,
    /// A text message, or a close reason, that is not UTF-8.
    BadUtf8,
    /// A close frame with a one-byte payload or an invalid status code.
    BadClose,
}

/// Which side sent the frames a decoder reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    /// A client: every frame must be masked (`Unmasked` otherwise). The server reads these.
    Client,
    /// The server: no frame may be masked (`Masked` otherwise). A client reads these.
    Server,
}

/// Incremental decoder: push bytes as they arrive, then take whole frames out.
#[derive(Debug)]
pub struct FrameDecoder {
    peer: Peer,
    buf: Vec<u8>,
}

#[allow(clippy::todo, reason = "stubs until task T208 lands; remove this allow with them")]
impl FrameDecoder {
    pub fn new(peer: Peer) -> Self {
        Self { peer, buf: Vec::new() }
    }

    /// Append received bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next complete frame, unmasked, removed from the buffer; `Ok(None)` while more bytes are needed. Each rule is
    /// checked as soon as the bytes it needs have arrived, in this order, so a bad frame is refused without waiting for its
    /// payload: reserved bits, opcode, fragmented control frame (`fin` clear on a control opcode), mask bit against `peer`,
    /// control payload length (7-bit length above 125), then the extended length (`NonMinimalLength`; a 64-bit length with
    /// its top bit set, or above `MAX_PAYLOAD`, is `TooLarge`). After an error the decoder is not used again: the caller
    /// closes the connection.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, WsError> {
        let _ = (self.peer, &self.buf);
        todo!("T208: next_frame")
    }
}

/// A frame as a server sends it: no mask. Lengths use the shortest form (under 126 inline, up to 65535 as 126 and two
/// bytes, else 127 and eight bytes). `TooLarge(len)` over `MAX_PAYLOAD`; for a control frame, `ControlFragmented` when
/// `fin` is clear and `ControlTooLong` over `MAX_CONTROL_PAYLOAD`.
#[allow(clippy::todo, reason = "stubs until task T208 lands; remove this allow with them")]
pub fn encode_server_frame(frame: &Frame) -> Result<Vec<u8>, WsError> {
    let _ = frame;
    todo!("T208: encode_server_frame")
}

/// A frame as a client sends it: mask bit set, then the 4 mask bytes, then the payload XOR-ed with them (byte `i` with
/// `mask[i % 4]`). Same length rules and errors as `encode_server_frame`. The mask must come from a random source the
/// caller owns; a client's masks must be unpredictable (RFC 6455 section 5.3).
#[allow(clippy::todo, reason = "stubs until task T208 lands; remove this allow with them")]
pub fn encode_client_frame(frame: &Frame, mask: [u8; 4]) -> Result<Vec<u8>, WsError> {
    let _ = (frame, mask);
    todo!("T208: encode_client_frame")
}
