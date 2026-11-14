//! Binary encoding of one chat message: the payload of a frame (`frame`, T100). Task T110.
//!
//! Wire format, version 1, integers big-endian:
//! `u8 version (1) | u8 kind | u64 cursor | str room | str author | str body`, where `str` is a `u16` byte length then
//! that many bytes of UTF-8. `room` and `author` are 1 to `MAX_NAME` bytes, `body` 0 to `MAX_BODY` bytes.

pub const VERSION: u8 = 1;
pub const MAX_NAME: usize = 64;
pub const MAX_BODY: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text = 0,
    Edit = 1,
    Delete = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub kind: Kind,
    pub cursor: u64,
    pub room: String,
    pub author: String,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodecError {
    /// The bytes end before the message does.
    Truncated,
    BadVersion(u8),
    BadKind(u8),
    BadUtf8,
    /// A field's length is outside its range (on decode, checked from the length prefix before reading the bytes).
    FieldLength,
    /// Bytes left over after the body.
    TrailingBytes,
}

/// Encode a message; `FieldLength` if room, author or body is outside its range.
pub fn encode(message: &Message) -> Result<Vec<u8>, CodecError> {
    let room_bytes = message.room.as_bytes();
    let author_bytes = message.author.as_bytes();
    let body_bytes = message.body.as_bytes();

    if room_bytes.is_empty() || room_bytes.len() > MAX_NAME {
        return Err(CodecError::FieldLength);
    }
    if author_bytes.is_empty() || author_bytes.len() > MAX_NAME {
        return Err(CodecError::FieldLength);
    }
    if body_bytes.len() > MAX_BODY {
        return Err(CodecError::FieldLength);
    }

    let mut out = Vec::with_capacity(1 + 1 + 8 + 2 + room_bytes.len() + 2 + author_bytes.len() + 2 + body_bytes.len());
    out.push(VERSION);
    out.push(message.kind as u8);
    out.extend_from_slice(&message.cursor.to_be_bytes());
    out.extend_from_slice(&(room_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(room_bytes);
    out.extend_from_slice(&(author_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(author_bytes);
    out.extend_from_slice(&(body_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(body_bytes);
    Ok(out)
}

/// Decode exactly one message. Errors in the order the bytes are read: version, kind, cursor, then each string's length
/// (`Truncated` / `FieldLength`), bytes (`Truncated`) and UTF-8 (`BadUtf8`), then `TrailingBytes`.
pub fn decode(bytes: &[u8]) -> Result<Message, CodecError> {
    let mut pos: usize = 0;

    // version
    if pos + 1 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let version = bytes[pos];
    pos += 1;
    if version != VERSION {
        return Err(CodecError::BadVersion(version));
    }

    // kind
    if pos + 1 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let kind_byte = bytes[pos];
    pos += 1;
    let kind = match kind_byte {
        0 => Kind::Text,
        1 => Kind::Edit,
        2 => Kind::Delete,
        _ => return Err(CodecError::BadKind(kind_byte)),
    };

    // cursor
    if pos + 8 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let cursor = u64::from_be_bytes([
        bytes[pos],
        bytes[pos + 1],
        bytes[pos + 2],
        bytes[pos + 3],
        bytes[pos + 4],
        bytes[pos + 5],
        bytes[pos + 6],
        bytes[pos + 7],
    ]);
    pos += 8;

    // room
    if pos + 2 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let room_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;
    if !(1..=MAX_NAME).contains(&room_len) {
        return Err(CodecError::FieldLength);
    }
    if pos + room_len > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let room = match str::from_utf8(&bytes[pos..pos + room_len]) {
        Ok(s) => s.to_owned(),
        Err(_) => return Err(CodecError::BadUtf8),
    };
    pos += room_len;

    // author
    if pos + 2 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let author_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;
    if !(1..=MAX_NAME).contains(&author_len) {
        return Err(CodecError::FieldLength);
    }
    if pos + author_len > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let author = match str::from_utf8(&bytes[pos..pos + author_len]) {
        Ok(s) => s.to_owned(),
        Err(_) => return Err(CodecError::BadUtf8),
    };
    pos += author_len;

    // body
    if pos + 2 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let body_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;
    if body_len > MAX_BODY {
        return Err(CodecError::FieldLength);
    }
    if pos + body_len > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let body = match str::from_utf8(&bytes[pos..pos + body_len]) {
        Ok(s) => s.to_owned(),
        Err(_) => return Err(CodecError::BadUtf8),
    };
    pos += body_len;

    // trailing bytes
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }

    Ok(Message { kind, cursor, room, author, body })
}
