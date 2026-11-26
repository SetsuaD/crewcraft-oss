//! The control connection from the chat server to a media server (docs/CALLS.md "Admission", task T360b3): what the
//! media server must do now that someone left a call or it ended. Each message is the payload of one frame
//! (`frame`, T100), over mutual TLS.
//!
//! Owns: the messages' bytes. Called by: the chat server binary (it sends) and the media server binary (it answers).
//!
//! Integers big-endian, `str` a `u16` length then UTF-8. The chat server numbers its messages (`seq`, from 1) and
//! the media server answers each with an `Ack` once it has taken it in; a message not acknowledged is sent again on
//! the next connection, which is safe because dropping someone who is gone, or ending a call that ended, does nothing.
//!
//! - kind 1 `DropPerson`: `u64 seq | u64 call | str person (1 to MAX_PERSON)`, drop every session of `person` in `call`
//! - kind 2 `EndCall`: `u64 seq | u64 call`, drop everyone in `call`
//! - kind 128 `Ack`: `u64 seq`, from the media server

use crate::message::CodecError;

/// The longest person (an email address), in bytes.
pub const MAX_PERSON: usize = 320;
/// The largest control message, in bytes: a frame payload limit for both sides.
pub const MAX_CONTROL_MESSAGE: usize = 1 + 8 + 8 + 2 + MAX_PERSON;

const DROP_PERSON: u8 = 1;
const END_CALL: u8 = 2;
const ACK: u8 = 128;

/// A message on the control connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    DropPerson { seq: u64, call: u64, person: String },
    EndCall { seq: u64, call: u64 },
    Ack { seq: u64 },
}

/// Encode `message`; `FieldLength` for an empty or too long person.
pub fn encode_control(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::with_capacity(MAX_CONTROL_MESSAGE);
    match message {
        ControlMessage::DropPerson { seq, call, person } => {
            if person.is_empty() || person.len() > MAX_PERSON {
                return Err(CodecError::FieldLength);
            }
            out.push(DROP_PERSON);
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(&call.to_be_bytes());
            out.extend_from_slice(&(person.len() as u16).to_be_bytes());
            out.extend_from_slice(person.as_bytes());
        }
        ControlMessage::EndCall { seq, call } => {
            out.push(END_CALL);
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(&call.to_be_bytes());
        }
        ControlMessage::Ack { seq } => {
            out.push(ACK);
            out.extend_from_slice(&seq.to_be_bytes());
        }
    }
    Ok(out)
}

fn take<'a>(bytes: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], CodecError> {
    let end = pos.checked_add(len).filter(|end| *end <= bytes.len()).ok_or(CodecError::Truncated)?;
    let part = &bytes[*pos..end];
    *pos = end;
    Ok(part)
}

fn u64_at(bytes: &[u8], pos: &mut usize) -> Result<u64, CodecError> {
    let mut out = [0u8; 8];
    out.copy_from_slice(take(bytes, pos, 8)?);
    Ok(u64::from_be_bytes(out))
}

/// Decode exactly one message: `BadKind` for an unknown kind, `FieldLength` for a bad person length, `BadUtf8`,
/// `Truncated`, then `TrailingBytes`.
pub fn decode_control(bytes: &[u8]) -> Result<ControlMessage, CodecError> {
    let mut pos = 0;
    let kind = take(bytes, &mut pos, 1)?[0];
    let message = match kind {
        DROP_PERSON => {
            let seq = u64_at(bytes, &mut pos)?;
            let call = u64_at(bytes, &mut pos)?;
            let length = take(bytes, &mut pos, 2)?;
            let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
            if length == 0 || length > MAX_PERSON {
                return Err(CodecError::FieldLength);
            }
            let person = std::str::from_utf8(take(bytes, &mut pos, length)?).map_err(|_| CodecError::BadUtf8)?.to_owned();
            ControlMessage::DropPerson { seq, call, person }
        }
        END_CALL => ControlMessage::EndCall { seq: u64_at(bytes, &mut pos)?, call: u64_at(bytes, &mut pos)? },
        ACK => ControlMessage::Ack { seq: u64_at(bytes, &mut pos)? },
        other => return Err(CodecError::BadKind(other)),
    };
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(message)
}
