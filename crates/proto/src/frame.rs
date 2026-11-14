//! Length-prefixed frames: a 4-byte big-endian length, then that many payload bytes. Every message on a CrewCraft
//! connection is one frame. Task T100.

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
