//! The first frame on every connection: the client says which protocol versions and features it speaks, and the server
//! agrees on one version and the shared features, or refuses. Task T133.
//!
//! Wire format, integers big-endian; `str` is a `u16` byte length then that many bytes of UTF-8 (as in `message`):
//! - `Hello` (client to server): `u8 tag (1) | u16 min_version | u16 max_version | u32 features | str client`
//! - `Welcome` (server to client): `u8 tag (2) | u16 version | u32 features | str server`
//! - `Refuse` (server to client): `u8 tag (3) | u16 min_version | u16 max_version`, the range the server speaks
//!
//! `client` and `server` are 1 to `message::MAX_NAME` bytes.

use crate::message::{CodecError, MAX_NAME};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub min_version: u16,
    pub max_version: u16,
    /// One bit per optional feature.
    pub features: u32,
    /// The client's name and version, for logs (for example "crewcraft-desktop 0.1").
    pub client: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Welcome { version: u16, features: u32, server: String },
    Refuse { min_version: u16, max_version: u16 },
}

/// What the server speaks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSide {
    pub min_version: u16,
    pub max_version: u16,
    pub features: u32,
    pub name: String,
}

/// The server's answer to `hello`: `Welcome` with the highest version both ranges contain and the features both sides
/// set (bitwise AND); `Refuse` with the server's own range when the ranges do not overlap, or when either range is
/// empty (its min above its max).
pub fn negotiate(hello: &Hello, server: &ServerSide) -> Reply {
    let hello_empty = hello.min_version > hello.max_version;
    let server_empty = server.min_version > server.max_version;
    if hello_empty || server_empty {
        return Reply::Refuse { min_version: server.min_version, max_version: server.max_version };
    }
    let lo = hello.min_version.max(server.min_version);
    let hi = hello.max_version.min(server.max_version);
    if lo > hi {
        return Reply::Refuse { min_version: server.min_version, max_version: server.max_version };
    }
    Reply::Welcome { version: hi, features: hello.features & server.features, server: server.name.clone() }
}

/// `FieldLength` if `client` is outside its range.
pub fn encode_hello(hello: &Hello) -> Result<Vec<u8>, CodecError> {
    let b = hello.client.as_bytes();
    if b.is_empty() || b.len() > MAX_NAME {
        return Err(CodecError::FieldLength);
    }
    let mut out = Vec::new();
    out.push(1);
    out.extend_from_slice(&hello.min_version.to_be_bytes());
    out.extend_from_slice(&hello.max_version.to_be_bytes());
    out.extend_from_slice(&hello.features.to_be_bytes());
    out.extend_from_slice(&(b.len() as u16).to_be_bytes());
    out.extend_from_slice(b);
    Ok(out)
}

/// Decode exactly one `Hello`. Errors in the order the bytes are read: the tag (`Truncated`, or `BadKind(tag)` for
/// anything but 1), then each field (`Truncated` when bytes run out; the string's length is checked against its range,
/// `FieldLength`, before its bytes are read; `BadUtf8`), then `TrailingBytes`.
pub fn decode_hello(bytes: &[u8]) -> Result<Hello, CodecError> {
    if bytes.is_empty() {
        return Err(CodecError::Truncated);
    }
    let tag = bytes[0];
    if tag != 1 {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos: usize = 1;
    if pos + 2 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let min_version = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
    pos += 2;
    if pos + 2 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let max_version = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
    pos += 2;
    if pos + 4 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let features = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    pos += 4;
    if pos + 2 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;
    if !(1..=MAX_NAME).contains(&len) {
        return Err(CodecError::FieldLength);
    }
    if pos + len > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let client = std::str::from_utf8(&bytes[pos..pos + len]).map_err(|_| CodecError::BadUtf8)?.to_owned();
    pos += len;
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(Hello { min_version, max_version, features, client })
}

/// `FieldLength` if a `Welcome`'s `server` is outside its range.
pub fn encode_reply(reply: &Reply) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    match reply {
        Reply::Welcome { version, features, server } => {
            let b = server.as_bytes();
            if b.is_empty() || b.len() > MAX_NAME {
                return Err(CodecError::FieldLength);
            }
            out.push(2);
            out.extend_from_slice(&version.to_be_bytes());
            out.extend_from_slice(&features.to_be_bytes());
            out.extend_from_slice(&(b.len() as u16).to_be_bytes());
            out.extend_from_slice(b);
        }
        Reply::Refuse { min_version, max_version } => {
            out.push(3);
            out.extend_from_slice(&min_version.to_be_bytes());
            out.extend_from_slice(&max_version.to_be_bytes());
        }
    }
    Ok(out)
}

/// As `decode_hello`, for a `Welcome` (tag 2) or `Refuse` (tag 3); `BadKind(tag)` for any other tag.
pub fn decode_reply(bytes: &[u8]) -> Result<Reply, CodecError> {
    if bytes.is_empty() {
        return Err(CodecError::Truncated);
    }
    let tag = bytes[0];
    if tag != 2 && tag != 3 {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos: usize = 1;
    let reply = if tag == 2 {
        if pos + 2 > bytes.len() {
            return Err(CodecError::Truncated);
        }
        let version = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        pos += 2;
        if pos + 4 > bytes.len() {
            return Err(CodecError::Truncated);
        }
        let features = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
        pos += 4;
        if pos + 2 > bytes.len() {
            return Err(CodecError::Truncated);
        }
        let len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        if !(1..=MAX_NAME).contains(&len) {
            return Err(CodecError::FieldLength);
        }
        if pos + len > bytes.len() {
            return Err(CodecError::Truncated);
        }
        let server = std::str::from_utf8(&bytes[pos..pos + len]).map_err(|_| CodecError::BadUtf8)?.to_owned();
        pos += len;
        Reply::Welcome { version, features, server }
    } else {
        if pos + 2 > bytes.len() {
            return Err(CodecError::Truncated);
        }
        let min_version = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        pos += 2;
        if pos + 2 > bytes.len() {
            return Err(CodecError::Truncated);
        }
        let max_version = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        pos += 2;
        Reply::Refuse { min_version, max_version }
    };
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(reply)
}
