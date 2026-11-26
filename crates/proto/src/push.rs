//! Events the server pushes to a client after `Sync`: the payload of a frame (`frame`, T100), next to the replies of
//! `request` (T124). Task T131.
//!
//! Wire format, integers big-endian; `str` is a `u16` byte length then that many bytes of UTF-8 (as in `message`).
//! Every push is `u8 tag | str room | u64 cursor | fields`:
//! - tag 64 `Posted`: `str author | str html | u8 count | count × str mention`
//! - tag 65 `Edited`: `u64 target | str html | u8 count | count × str mention`
//! - tag 66 `Deleted`: `u64 target`
//! - tag 67 `Other` (membership and settings changes): no fields
//! - tag 71 `Threaded` (task T340a): `u64 parent`. Its `cursor` is the reply's own; it follows the reply's `Posted`
//!   and advances nothing. Only a client that agreed to `request::FEATURE_THREADS` is sent it.
//! - tag 70 `Attached` (task T330c; 68 and 69 stay unassigned): `u8 count (1 to MAX_ATTACHMENTS) | count × (16 file id | str name | u64 size |
//!   u8 has image size | [u32 width | u32 height])`. Its `cursor` is the message's own; it follows that message's
//!   `Posted` and advances nothing. Only a client that agreed to `request::FEATURE_FILES` is sent it.
//! - tag 73 `Archived` (task T350d1): no fields. Sent after a `Sync` of an archive room (docs/IMPORT.md), before its
//!   events; its `cursor` is 0 and it advances nothing.
//! - tag 74 `Sent` (task T350d1): `u64 sent_ms`. The original time of the imported message at `cursor`; it follows
//!   that message's `Posted` and advances nothing. Both only to a client that agreed to `request::FEATURE_ARCHIVE`.
//! - tag 72 `Reacted` (task T341a): `u64 target | str author | u8 reaction (1 to REACTIONS.len()) | u8 on (0 or 1)`.
//!   An event of its own: it advances the cursor like `Other`. A client that did not agree to
//!   `request::FEATURE_REACTIONS` is sent `Other` in its place.
//!
//! `room`, `author` and each mention are 1 to `message::MAX_NAME` bytes; `html` is 0 to `MAX_HTML` bytes; at most
//! `MAX_MENTIONS` mentions.

use crate::message::{CodecError, MAX_NAME};

/// Below `u16::MAX`, the largest length a `str` prefix can carry. A rendered 4,000-character message is at most about
/// 24 KB even when every character is escaped.
pub const MAX_HTML: usize = 60 * 1024;
pub const MAX_MENTIONS: usize = 32;
/// The tag of `Push::Attached` (task T330c).
pub const ATTACHED: u8 = 70;
/// The tag of `Push::Threaded` (task T340a).
pub const THREADED: u8 = 71;
/// The tags of `Push::Archived` and `Push::Sent` (task T350d1).
pub const ARCHIVED: u8 = 73;
pub const SENT: u8 = 74;
/// The tag of `Push::Reacted` (task T341a).
pub const REACTED: u8 = 72;
/// The reactions, by code: code `n` is `REACTIONS[n - 1]` (task T341a). A fixed set, as Teams has, named in words: the
/// bundled font has no emoji, and a fixed set keeps imported reactions and every client in step.
pub const REACTIONS: [&str; 6] = ["Like", "Heart", "Laugh", "Surprised", "Sad", "Angry"];

/// The name of reaction `code`, or `None` for a code outside `REACTIONS`.
pub fn reaction_name(code: u8) -> Option<&'static str> {
    REACTIONS.get(usize::from(code).checked_sub(1)?).copied()
}

/// The most files one message carries (task T330c).
pub const MAX_ATTACHMENTS: usize = 10;
/// The longest file name, in bytes (as `request::MAX_FILE_NAME`).
pub const MAX_ATTACHMENT_NAME: usize = 255;

/// One file a message carries (task T330c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedFile {
    pub file: [u8; 16],
    pub name: String,
    pub size: u64,
    /// Width and height, for an image.
    pub image: Option<(u32, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Push {
    Posted {
        room: String,
        cursor: u64,
        author: String,
        html: String,
        mentions: Vec<String>,
    },
    Edited {
        room: String,
        cursor: u64,
        target: u64,
        html: String,
        mentions: Vec<String>,
    },
    Deleted {
        room: String,
        cursor: u64,
        target: u64,
    },
    Other {
        room: String,
        cursor: u64,
    },
    /// The files the message at `cursor` carries (task T330c).
    Attached {
        room: String,
        cursor: u64,
        files: Vec<AttachedFile>,
    },
    /// The message at `cursor` is a reply in the thread of the message at `parent` (task T340a).
    Threaded {
        room: String,
        cursor: u64,
        parent: u64,
    },
    /// `author` added (`on`) or took back their `reaction` (a code, see `REACTIONS`) on the message at `target`
    /// (task T341a). The event's own cursor is `cursor`.
    Reacted {
        room: String,
        cursor: u64,
        target: u64,
        author: String,
        reaction: u8,
        on: bool,
    },
    /// `room` is an archive room: read-only, imported from another system (task T350d1). `cursor` is 0.
    Archived {
        room: String,
        cursor: u64,
    },
    /// The imported message at `cursor` was first sent at `sent_ms` (Unix milliseconds) in the system it came from
    /// (task T350d1).
    Sent {
        room: String,
        cursor: u64,
        sent_ms: u64,
    },
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
        Push::Reacted { room, cursor, target, author, reaction, on } => {
            if reaction_name(*reaction).is_none() {
                return Err(CodecError::BadKind(*reaction));
            }
            out.push(REACTED);
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&cursor.to_be_bytes());
            out.extend_from_slice(&target.to_be_bytes());
            write_str(&mut out, author, 1, MAX_NAME)?;
            out.push(*reaction);
            out.push(u8::from(*on));
        }
        Push::Archived { room, cursor } => {
            out.push(ARCHIVED);
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&cursor.to_be_bytes());
        }
        Push::Sent { room, cursor, sent_ms } => {
            out.push(SENT);
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&cursor.to_be_bytes());
            out.extend_from_slice(&sent_ms.to_be_bytes());
        }
        Push::Threaded { room, cursor, parent } => {
            out.push(THREADED);
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&cursor.to_be_bytes());
            out.extend_from_slice(&parent.to_be_bytes());
        }
        Push::Attached { room, cursor, files } => {
            if files.is_empty() || files.len() > MAX_ATTACHMENTS {
                return Err(CodecError::FieldLength);
            }
            out.push(ATTACHED);
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&cursor.to_be_bytes());
            out.push(files.len() as u8);
            for file in files {
                out.extend_from_slice(&file.file);
                write_str(&mut out, &file.name, 1, MAX_ATTACHMENT_NAME)?;
                out.extend_from_slice(&file.size.to_be_bytes());
                match file.image {
                    None => out.push(0),
                    Some((width, height)) => {
                        out.push(1);
                        out.extend_from_slice(&width.to_be_bytes());
                        out.extend_from_slice(&height.to_be_bytes());
                    }
                }
            }
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
    if !(64..=67).contains(&tag) && tag != ATTACHED && tag != THREADED && tag != REACTED && tag != ARCHIVED && tag != SENT {
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
        THREADED => Push::Threaded { room, cursor, parent: read_u64(bytes, &mut pos)? },
        ARCHIVED => Push::Archived { room, cursor },
        SENT => Push::Sent { room, cursor, sent_ms: read_u64(bytes, &mut pos)? },
        REACTED => {
            let target = read_u64(bytes, &mut pos)?;
            let author = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let reaction = read_u8(bytes, &mut pos)?;
            if reaction_name(reaction).is_none() {
                return Err(CodecError::BadKind(reaction));
            }
            let on = match read_u8(bytes, &mut pos)? {
                0 => false,
                1 => true,
                other => return Err(CodecError::BadKind(other)),
            };
            Push::Reacted { room, cursor, target, author, reaction, on }
        }
        ATTACHED => {
            let count = usize::from(*bytes.get(pos).ok_or(CodecError::Truncated)?);
            pos += 1;
            if count == 0 || count > MAX_ATTACHMENTS {
                return Err(CodecError::FieldLength);
            }
            let mut files = Vec::with_capacity(count);
            for _ in 0..count {
                let end = pos.checked_add(16).filter(|end| *end <= bytes.len()).ok_or(CodecError::Truncated)?;
                let mut file = [0u8; 16];
                file.copy_from_slice(&bytes[pos..end]);
                pos = end;
                let name = read_string(bytes, &mut pos, 1, MAX_ATTACHMENT_NAME)?;
                let size = read_u64(bytes, &mut pos)?;
                let has_image = *bytes.get(pos).ok_or(CodecError::Truncated)?;
                pos += 1;
                let image = match has_image {
                    0 => None,
                    1 => {
                        let width = read_u32(bytes, &mut pos)?;
                        let height = read_u32(bytes, &mut pos)?;
                        Some((width, height))
                    }
                    other => return Err(CodecError::BadKind(other)),
                };
                files.push(AttachedFile { file, name, size, image });
            }
            Push::Attached { room, cursor, files }
        }
        _ => return Err(CodecError::BadKind(tag)),
    };

    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(push)
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, CodecError> {
    let end = pos.checked_add(4).filter(|end| *end <= bytes.len()).ok_or(CodecError::Truncated)?;
    let value = u32::from_be_bytes([bytes[*pos], bytes[*pos + 1], bytes[*pos + 2], bytes[*pos + 3]]);
    *pos = end;
    Ok(value)
}
