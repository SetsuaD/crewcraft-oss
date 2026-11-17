//! Length-prefixed frames: a 4-byte big-endian length, then that many payload bytes. Every message on a CrewCraft
//! connection is one frame. Task T100.

use std::fmt;
use std::io::{self, Read};

/// Largest payload a frame may carry (1 MiB). A longer length is refused as soon as its header is read.
pub const MAX_FRAME: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// A frame (to send, or announced by a received header) longer than `MAX_FRAME`; carries that length.
    TooLarge(usize),
}

/// Encode one payload as a frame.
pub fn encode(payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// One received frame, including its length prefix.
pub struct ReceivedFrame(Vec<u8>);

impl ReceivedFrame {
    /// The length prefix and payload, for the existing incremental session APIs.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The message inside the frame, for a protocol-phase decoder.
    pub fn payload(&self) -> &[u8] {
        &self.0[4..]
    }
}

impl fmt::Debug for ReceivedFrame {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.debug_struct("ReceivedFrame").field("payload_len", &self.payload().len()).finish()
    }
}

/// Read one complete frame, leaving any later frame unread. The caller supplies the limit for the current phase.
/// Clean EOF before the header returns `None`. A partial header or payload is `UnexpectedEof`.
/// Reject lengths above either limit before allocating or reading the payload.
/// On an error the caller closes the connection. The stream supplies its own I/O deadline.
pub fn read_frame(reader: &mut impl Read, payload_limit: usize) -> io::Result<Option<ReceivedFrame>> {
    let mut header = [0; 4];
    match reader.read_exact(&mut header[..1]) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    reader.read_exact(&mut header[1..])?;
    let len = u32::from_be_bytes(header) as usize;
    if len > payload_limit.min(MAX_FRAME) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "protocol frame exceeds its phase limit"));
    }

    let mut frame = vec![0; 4 + len];
    frame[..4].copy_from_slice(&header);
    reader.read_exact(&mut frame[4..])?;
    Ok(Some(ReceivedFrame(frame)))
}

/// Incremental decoder: push bytes as they arrive, then take whole frames out.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Append received bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next complete frame's payload; `Ok(None)` while more bytes are needed; `Err(TooLarge)` as soon as a header
    /// announces a frame longer than `MAX_FRAME`, without waiting for its body.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let header = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if header > MAX_FRAME {
            self.buf.clear();
            return Err(FrameError::TooLarge(header));
        }
        if self.buf.len() < 4 + header {
            return Ok(None);
        }
        let payload = self.buf[4..4 + header].to_vec();
        self.buf.drain(..4 + header);
        Ok(Some(payload))
    }

    /// Bytes held that do not yet form a whole frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }
}
