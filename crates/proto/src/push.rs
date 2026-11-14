//! Events the server pushes to a client after `Sync`: the payload of a frame (`frame`, T100), next to the replies of
//! `request` (T124). Task T131.
//!
//! Wire format, integers big-endian; `str` is a `u16` byte length then that many bytes of UTF-8 (as in `message`).
//! Every push is `u8 tag | str room | u64 cursor | fields`:
//! - tag 64 `Posted`: `str author | str html | u8 count | count × str mention`
//! - tag 65 `Edited`: `u64 target | str html | u8 count | count × str mention`
//! - tag 66 `Deleted`: `u64 target`
//! - tag 67 `Other` (membership and settings changes): no fields
//!
//! `room`, `author` and each mention are 1 to `message::MAX_NAME` bytes; `html` is 0 to `MAX_HTML` bytes; at most
//! `MAX_MENTIONS` mentions.

use crate::message::{CodecError, MAX_NAME};

/// Below `u16::MAX`, the largest length a `str` prefix can carry. A rendered 4,000-character message is at most about
/// 24 KB even when every character is escaped.
pub const MAX_HTML: usize = 60 * 1024;
pub const MAX_MENTIONS: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Push {
    Posted { room: String, cursor: u64, author: String, html: String, mentions: Vec<String> },
    Edited { room: String, cursor: u64, target: u64, html: String, mentions: Vec<String> },
    Deleted { room: String, cursor: u64, target: u64 },
    Other { room: String, cursor: u64 },
}

fn write_str(out: &mut Vec<u8>, s: &str, min: usize, max: usize) -> Result<(), CodecError> {
    let b = s.as_bytes();
    if b.len() < min || b.len() > max {
        return Err(CodecError::FieldLength);
    }
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
    Ok(())
}

fn read_string(bytes: &[u8], pos: &mut usize, min: usize, max: usize) -> Result<String, CodecError> {
    if *pos + 2 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let len = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]) as usize;
    *pos += 2;
    if len < min || len > max {
        return Err(CodecError::FieldLength);
    }
    if *pos + len > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let s = std::str::from_utf8(&bytes[*pos..*pos + len]).map_err(|_| CodecError::BadUtf8)?;
    *pos += len;
    Ok(s.to_owned())
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> Result<u64, CodecError> {
    if *pos + 8 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let value = u64::from_be_bytes([
        bytes[*pos],
        bytes[*pos + 1],
        bytes[*pos + 2],
        bytes[*pos + 3],
        bytes[*pos + 4],
        bytes[*pos + 5],
        bytes[*pos + 6],
        bytes[*pos + 7],
    ]);
    *pos += 8;
    Ok(value)
}

fn read_u8(bytes: &[u8], pos: &mut usize) -> Result<u8, CodecError> {
    if *pos + 1 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let value = bytes[*pos];
    *pos += 1;
    Ok(value)
}

/// `FieldLength` if a field is outside its range or there are more than `MAX_MENTIONS` mentions.
pub fn encode_push(push: &Push) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    match push {
        Push::Posted { room, cursor, author, html, mentions } => {
            if mentions.len() > MAX_MENTIONS {
                return Err(CodecError::FieldLength);
            }
            out.push(64);
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&cursor.to_be_bytes());
            write_str(&mut out, author, 1, MAX_NAME)?;
            write_str(&mut out, html, 0, MAX_HTML)?;
            out.push(mentions.len() as u8);
            for m in mentions {
                write_str(&mut out, m, 1, MAX_NAME)?;
            }
        }
        Push::Edited { room, cursor, target, html, mentions } => {
            if mentions.len() > MAX_MENTIONS {
                return Err(CodecError::FieldLength);
            }
            out.push(65);
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&cursor.to_be_bytes());
            out.extend_from_slice(&target.to_be_bytes());
            write_str(&mut out, html, 0, MAX_HTML)?;
            out.push(mentions.len() as u8);
            for m in mentions {
                write_str(&mut out, m, 1, MAX_NAME)?;
            }
        }
        Push::Deleted { room, cursor, target } => {
            out.push(66);
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&cursor.to_be_bytes());
            out.extend_from_slice(&target.to_be_bytes());
        }
        Push::Other { room, cursor } => {
            out.push(67);
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&cursor.to_be_bytes());
        }
    }
    Ok(out)
}

/// Decode exactly one push. Errors in the order the bytes are read: the tag (`Truncated`, or `BadKind(tag)` for any
/// other tag), then each field in order: a string's length is checked against its range (`FieldLength`) before its
/// bytes are read, and so is the mention count; `Truncated` when bytes run out; `BadUtf8`; then `TrailingBytes`.
pub fn decode_push(bytes: &[u8]) -> Result<Push, CodecError> {
    if bytes.is_empty() {
        return Err(CodecError::Truncated);
    }
    let tag = bytes[0];
    if !(64..=67).contains(&tag) {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos: usize = 1;
    let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
    let cursor = read_u64(bytes, &mut pos)?;

    let push = match tag {
        64 => {
            let author = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let html = read_string(bytes, &mut pos, 0, MAX_HTML)?;
            let count = read_u8(bytes, &mut pos)? as usize;
            if count > MAX_MENTIONS {
                return Err(CodecError::FieldLength);
            }
            let mut mentions = Vec::with_capacity(count);
            for _ in 0..count {
                mentions.push(read_string(bytes, &mut pos, 1, MAX_NAME)?);
            }
            Push::Posted { room, cursor, author, html, mentions }
        }
        65 => {
            let target = read_u64(bytes, &mut pos)?;
            let html = read_string(bytes, &mut pos, 0, MAX_HTML)?;
            let count = read_u8(bytes, &mut pos)? as usize;
            if count > MAX_MENTIONS {
                return Err(CodecError::FieldLength);
            }
            let mut mentions = Vec::with_capacity(count);
            for _ in 0..count {
                mentions.push(read_string(bytes, &mut pos, 1, MAX_NAME)?);
            }
            Push::Edited { room, cursor, target, html, mentions }
        }
        66 => {
            let target = read_u64(bytes, &mut pos)?;
            Push::Deleted { room, cursor, target }
        }
        67 => Push::Other { room, cursor },
        _ => return Err(CodecError::BadKind(tag)),
    };

    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(push)
}
