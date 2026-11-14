//! WebSocket messages from frames (RFC 6455 sections 5.4 and 5.5): joining the fragments of a text or binary message,
//! letting control frames through between fragments, and decoding close frames. One `Assembler` per connection and
//! direction. Frames are `ws_frame` (T208). Task T209.

use crate::ws_frame::{Frame, Opcode, WsError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    /// `code` is `None` for a close frame with no payload.
    Close {
        code: Option<u16>,
        reason: String,
    },
}

/// Joins frames into messages, refusing a message longer than `max_message` bytes.
#[derive(Debug)]
pub struct Assembler {
    max_message: usize,
    // The message being collected: whether it is text, and the bytes so far. `None` between messages.
    partial: Option<(bool, Vec<u8>)>,
}

#[allow(clippy::todo, reason = "stubs until task T209 lands; remove this allow with them")]
impl Assembler {
    pub fn new(max_message: usize) -> Self {
        Self { max_message, partial: None }
    }

    /// Take the next frame in arrival order; `Ok(Some(message))` when it completes a message or is a control frame.
    /// - `Ping`, `Pong` and `Close` frames are returned at once as `Ping`, `Pong` and `Close`, even while a fragmented
    ///   message is in progress, and do not disturb it. A close payload is empty (`code: None`), or a big-endian status
    ///   code and then a UTF-8 reason; one byte is `BadClose`, an invalid code is `BadClose` (valid are 1000 to 1003, 1007
    ///   to 1011 and 3000 to 4999), a reason that is not UTF-8 is `BadUtf8`.
    /// - `Text` or `Binary` with `fin` set, with no message in progress, is a whole message. With `fin` clear it starts
    ///   one (`Ok(None)`). Either while one is in progress is `InterleavedData`.
    /// - `Continuation` adds to the message in progress (`Ok(None)`, or the message when `fin` is set); with none in
    ///   progress it is `UnexpectedContinuation`.
    /// - A message whose bytes so far exceed `max_message` is `MessageTooLarge` (checked as each frame is added). A text
    ///   message is checked to be UTF-8 when it completes (`BadUtf8`), so a character may be split across fragments.
    ///
    /// After an error the assembler is not used again: the caller closes the connection.
    pub fn push(&mut self, frame: Frame) -> Result<Option<Message>, WsError> {
        let _ = (frame, self.max_message, &self.partial, Opcode::Text);
        todo!("T209: push")
    }
}

/// The frame that carries `message`, `fin` set. `Close` has the status code big-endian and then the reason as its payload
/// (no payload at all for `code: None`); `Text` is the string's UTF-8 bytes.
#[allow(clippy::todo, reason = "stub until task T209 lands; remove this allow with the stub")]
pub fn to_frame(message: &Message) -> Frame {
    let _ = message;
    todo!("T209: to_frame")
}
