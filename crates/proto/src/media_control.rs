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
//! - kind 3 `Join` (task T360b6): `u64 seq | u64 call | u16 n | n bytes credential | u32 m | m bytes offer`, a
//!   participant's WebRTC offer relayed from their device connection; answered by `JoinAnswer` or `JoinRefused`, never
//!   by `Ack`, and never sent again (the credential admits once)
//! - kind 128 `Ack`: `u64 seq`, from the media server
//! - kind 129 `JoinAnswer`: `u64 seq | u32 m | m bytes SDP answer`
//! - kind 130 `JoinRefused`: `u64 seq | u8 reason` (`REFUSED_*`)

use crate::message::CodecError;
use crate::request::{MAX_CREDENTIAL, MAX_SDP};

/// The longest person (an email address), in bytes.
pub const MAX_PERSON: usize = 320;
/// The largest control message, in bytes (a `Join`): a frame payload limit for both sides.
pub const MAX_CONTROL_MESSAGE: usize = 1 + 8 + 8 + 2 + MAX_CREDENTIAL + 4 + MAX_SDP;

/// Why the media server refused a `Join`: the offer was unusable.
pub const REFUSED_OFFER: u8 = 1;
/// The credential was refused: forged, expired, already used, or for another media server.
pub const REFUSED_CREDENTIAL: u8 = 2;
/// The credential is for another call.
pub const REFUSED_WRONG_CALL: u8 = 3;
/// The call is full.
pub const REFUSED_CALL_FULL: u8 = 4;
/// The media server is stopping.
pub const REFUSED_STOPPED: u8 = 5;

const DROP_PERSON: u8 = 1;
const END_CALL: u8 = 2;
const JOIN: u8 = 3;
const ACK: u8 = 128;
const JOIN_ANSWER: u8 = 129;
const JOIN_REFUSED: u8 = 130;

/// A message on the control connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMessage {
    DropPerson { seq: u64, call: u64, person: String },
    EndCall { seq: u64, call: u64 },
    Join { seq: u64, call: u64, credential: Vec<u8>, offer: String },
    Ack { seq: u64 },
    JoinAnswer { seq: u64, answer: String },
    JoinRefused { seq: u64, reason: u8 },
}

/// Encode `message`; `FieldLength` for an empty or too long person, credential, offer or answer.
pub fn encode_control(message: &ControlMessage) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
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
        ControlMessage::Join { seq, call, credential, offer } => {
            if credential.is_empty() || credential.len() > MAX_CREDENTIAL || offer.is_empty() || offer.len() > MAX_SDP {
                return Err(CodecError::FieldLength);
            }
            out.push(JOIN);
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(&call.to_be_bytes());
            out.extend_from_slice(&(credential.len() as u16).to_be_bytes());
            out.extend_from_slice(credential);
            out.extend_from_slice(&(offer.len() as u32).to_be_bytes());
            out.extend_from_slice(offer.as_bytes());
        }
        ControlMessage::Ack { seq } => {
            out.push(ACK);
            out.extend_from_slice(&seq.to_be_bytes());
        }
        ControlMessage::JoinAnswer { seq, answer } => {
            if answer.is_empty() || answer.len() > MAX_SDP {
                return Err(CodecError::FieldLength);
            }
            out.push(JOIN_ANSWER);
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(&(answer.len() as u32).to_be_bytes());
            out.extend_from_slice(answer.as_bytes());
        }
        ControlMessage::JoinRefused { seq, reason } => {
            out.push(JOIN_REFUSED);
            out.extend_from_slice(&seq.to_be_bytes());
            out.push(*reason);
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

/// `count` bytes (1 to `max`).
fn counted(bytes: &[u8], pos: &mut usize, count: usize, max: usize) -> Result<Vec<u8>, CodecError> {
    if count == 0 || count > max {
        return Err(CodecError::FieldLength);
    }
    Ok(take(bytes, pos, count)?.to_vec())
}

fn u32_at(bytes: &[u8], pos: &mut usize) -> Result<usize, CodecError> {
    let mut out = [0u8; 4];
    out.copy_from_slice(take(bytes, pos, 4)?);
    usize::try_from(u32::from_be_bytes(out)).map_err(|_| CodecError::FieldLength)
}

fn utf8(bytes: Vec<u8>) -> Result<String, CodecError> {
    String::from_utf8(bytes).map_err(|_| CodecError::BadUtf8)
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
        JOIN => {
            let seq = u64_at(bytes, &mut pos)?;
            let call = u64_at(bytes, &mut pos)?;
            let length = take(bytes, &mut pos, 2)?;
            let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
            let credential = counted(bytes, &mut pos, length, MAX_CREDENTIAL)?;
            let length = u32_at(bytes, &mut pos)?;
            let offer = utf8(counted(bytes, &mut pos, length, MAX_SDP)?)?;
            ControlMessage::Join { seq, call, credential, offer }
        }
        ACK => ControlMessage::Ack { seq: u64_at(bytes, &mut pos)? },
        JOIN_ANSWER => {
            let seq = u64_at(bytes, &mut pos)?;
            let length = u32_at(bytes, &mut pos)?;
            ControlMessage::JoinAnswer { seq, answer: utf8(counted(bytes, &mut pos, length, MAX_SDP)?)? }
        }
        JOIN_REFUSED => ControlMessage::JoinRefused { seq: u64_at(bytes, &mut pos)?, reason: take(bytes, &mut pos, 1)?[0] },
        other => return Err(CodecError::BadKind(other)),
    };
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(message)
}
