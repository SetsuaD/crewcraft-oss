//! Client requests and the server's replies: the payload of a frame (`frame`, T100). Task T124.
//!
//! Wire format, integers big-endian; `str` is a `u16` byte length then that many bytes of UTF-8 (as in `message`).
//!
//! A request is `u8 tag | u32 id | fields`:
//! - tag 1 `Post`: `str room | str text`
//! - tag 2 `Edit`: `str room | u64 target | str text`
//! - tag 3 `Delete`: `str room | u64 target`
//! - tag 4 `Sync`: `str room | u64 cursor`
//! - tag 5 `MarkRead`: `str room | u64 cursor`
//! - tag 6 `Ping`: no fields
//!
//! A response is `u8 tag | u32 id | fields`, where `id` repeats the request's:
//! - tag 128 `Ok`: `u64 cursor`
//! - tag 129 `Error`: `u16 code | str detail`
//!
//! `room` is 1 to `message::MAX_NAME` bytes, `text` 0 to `message::MAX_BODY` bytes, `detail` 0 to `MAX_DETAIL` bytes.

use crate::message::{CodecError, MAX_BODY, MAX_NAME};

pub const MAX_DETAIL: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Post { room: String, text: String },
    Edit { room: String, target: u64, text: String },
    Delete { room: String, target: u64 },
    Sync { room: String, cursor: u64 },
    MarkRead { room: String, cursor: u64 },
    Ping,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Ok { cursor: u64 },
    Error { code: u16, detail: String },
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

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, CodecError> {
    if *pos + 4 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let value = u32::from_be_bytes([bytes[*pos], bytes[*pos + 1], bytes[*pos + 2], bytes[*pos + 3]]);
    *pos += 4;
    Ok(value)
}

/// `FieldLength` if a field is outside its range.
pub fn encode_request(id: u32, request: &Request) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    match request {
        Request::Post { room, text } => {
            out.push(1);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            write_str(&mut out, text, 0, MAX_BODY)?;
        }
        Request::Edit { room, target, text } => {
            out.push(2);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&target.to_be_bytes());
            write_str(&mut out, text, 0, MAX_BODY)?;
        }
        Request::Delete { room, target } => {
            out.push(3);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&target.to_be_bytes());
        }
        Request::Sync { room, cursor } => {
            out.push(4);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&cursor.to_be_bytes());
        }
        Request::MarkRead { room, cursor } => {
            out.push(5);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&cursor.to_be_bytes());
        }
        Request::Ping => {
            out.push(6);
            out.extend_from_slice(&id.to_be_bytes());
        }
    }
    Ok(out)
}

/// Decode exactly one request. Errors in the order the bytes are read: the tag (`Truncated`, or `BadKind(tag)` for any
/// tag that is not a request's), the id, then each field in order (a string's length is checked against its range,
/// `FieldLength`, before its bytes are read; `Truncated` when bytes run out; `BadUtf8`), then `TrailingBytes`.
pub fn decode_request(bytes: &[u8]) -> Result<(u32, Request), CodecError> {
    if bytes.is_empty() {
        return Err(CodecError::Truncated);
    }
    let tag = bytes[0];
    if !(1..=6).contains(&tag) {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos: usize = 1;
    let id = read_u32(bytes, &mut pos)?;
    let request = match tag {
        1 => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let text = read_string(bytes, &mut pos, 0, MAX_BODY)?;
            Request::Post { room, text }
        }
        2 => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let target = read_u64(bytes, &mut pos)?;
            let text = read_string(bytes, &mut pos, 0, MAX_BODY)?;
            Request::Edit { room, target, text }
        }
        3 => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let target = read_u64(bytes, &mut pos)?;
            Request::Delete { room, target }
        }
        4 => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let cursor = read_u64(bytes, &mut pos)?;
            Request::Sync { room, cursor }
        }
        5 => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let cursor = read_u64(bytes, &mut pos)?;
            Request::MarkRead { room, cursor }
        }
        6 => Request::Ping,
        _ => return Err(CodecError::BadKind(tag)),
    };
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, request))
}

/// `FieldLength` if `detail` is longer than `MAX_DETAIL` bytes.
pub fn encode_response(id: u32, response: &Response) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    match response {
        Response::Ok { cursor } => {
            out.push(128);
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&cursor.to_be_bytes());
        }
        Response::Error { code, detail } => {
            out.push(129);
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&code.to_be_bytes());
            write_str(&mut out, detail, 0, MAX_DETAIL)?;
        }
    }
    Ok(out)
}

/// As `decode_request`, for responses (`BadKind(tag)` for any tag that is not a response's).
pub fn decode_response(bytes: &[u8]) -> Result<(u32, Response), CodecError> {
    if bytes.is_empty() {
        return Err(CodecError::Truncated);
    }
    let tag = bytes[0];
    if !(128..=129).contains(&tag) {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos: usize = 1;
    let id = read_u32(bytes, &mut pos)?;
    let response = match tag {
        128 => {
            let cursor = read_u64(bytes, &mut pos)?;
            Response::Ok { cursor }
        }
        _ => {
            if pos + 2 > bytes.len() {
                return Err(CodecError::Truncated);
            }
            let code = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
            pos += 2;
            let detail = read_string(bytes, &mut pos, 0, MAX_DETAIL)?;
            Response::Error { code, detail }
        }
    };
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, response))
}
