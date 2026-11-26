//! The server's changes as records: each successful change to `server::Server` is one `Op`, written to the journal
//! (`journal`, T140) so the server can be rebuilt by replaying them. Task T143.
//!
//! Wire format, integers big-endian; `str` here is a `u32` byte length then that many bytes of UTF-8, at most
//! `MAX_STR` bytes. A record is `u8 tag | fields`:
//! - tag 1 `CreateRoom`: `str owner | str name`
//! - tag 2 `AddMember`: `str slug | str actor | str user | u8 role` (0 Guest, 1 Member, 2 Admin, 3 Owner)
//! - tag 3 `RemoveMember`: `str slug | str actor | str user`
//! - tag 4 `Post`: `str slug | str author | str text | u64 now_ms`
//! - tag 5 `Edit`: `str slug | str actor | u64 target | str text | u64 now_ms`
//! - tag 6 `Delete`: `str slug | str actor | u64 target`
//! - tag 7 `MarkRead`: `str slug | str user | u64 cursor`
//! - tag 19 `React` (task T341a): `str slug | str actor | u64 target | u8 reaction | u8 on (0 or 1) | u64 now_ms`
//! - tag 20 `ImportRoom` (task T350a): `str key | str name`
//! - tag 21 `ImportMessage`: `str slug | str key | str author | u64 sent_ms | str text | u8 deleted (0 or 1) | u64 parent
//!   (0 for none)`
//! - tag 22 `ImportEdit`: `str slug | str key | str text | u64 edited_ms`
//! - tag 23 `ImportDelete`: `str slug | str key`
//! - tag 24 `ImportFiles` (task T350e): `str slug | str key | u8 count | count × (str name | u64 size | u8 stored (0 or
//!   1) | [16 file id when stored])`, the message's whole file list

use crewcraft_proto::message::CodecError;

use crate::room::Role;

/// Longest string field, in bytes.
pub const MAX_STR: usize = 1 << 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    CreateRoom {
        owner: String,
        name: String,
    },
    AddMember {
        slug: String,
        actor: String,
        user: String,
        role: Role,
    },
    RemoveMember {
        slug: String,
        actor: String,
        user: String,
    },
    Post {
        slug: String,
        author: String,
        text: String,
        now_ms: u64,
    },
    Edit {
        slug: String,
        actor: String,
        target: u64,
        text: String,
        now_ms: u64,
    },
    Delete {
        slug: String,
        actor: String,
        target: u64,
    },
    MarkRead {
        slug: String,
        user: String,
        cursor: u64,
    },
    /// An archive room made by an import, with its external key `source:key` (task T350a).
    ImportRoom {
        key: String,
        name: String,
    },
    /// An imported message, with its external key `source:room:key`, original author and time (task T350a). `parent`
    /// is the cursor of the message it replies to, or 0.
    ImportMessage {
        slug: String,
        key: String,
        author: String,
        sent_ms: u64,
        text: String,
        deleted: bool,
        parent: u64,
    },
    /// An imported message's text, as the source edited it (task T350a).
    ImportEdit {
        slug: String,
        key: String,
        text: String,
        edited_ms: u64,
    },
    /// An imported message the source has since deleted (task T350a).
    ImportDelete {
        slug: String,
        key: String,
    },
    /// An imported message's files, each stored (with its file id) or not archived (task T350e).
    ImportFiles {
        slug: String,
        key: String,
        files: Vec<(String, u64, Option<[u8; 16]>)>,
    },
    /// A reaction added or taken back (task T341a).
    React {
        slug: String,
        actor: String,
        target: u64,
        reaction: u8,
        on: bool,
        now_ms: u64,
    },
    /// A finished upload's record (docs/FILES.md, task T330a): who uploaded which bytes to which room, under which name.
    /// Tag 16 (8 to 15 stay unassigned): `str slug | str uploader | 16 file id | 32 SHA-256 | u64 size | str name | u8 has image size |
    /// [u32 width | u32 height]`.
    FileStored {
        slug: String,
        uploader: String,
        file: [u8; 16],
        sha256: [u8; 32],
        size: u64,
        name: String,
        image: Option<(u32, u32)>,
    },
    /// A post with files, in one record (task T330c). Tag 17: the fields of `Post`, then `u8 count | count × 16 file id`.
    PostFiles {
        slug: String,
        author: String,
        text: String,
        now_ms: u64,
        files: Vec<[u8; 16]>,
    },
    /// A reply in the thread of the message at `parent` (task T340a). Tag 18: `str slug | str author | u64 parent |
    /// str text | u64 now_ms`.
    Reply {
        slug: String,
        author: String,
        parent: u64,
        text: String,
        now_ms: u64,
    },
}

/// `FieldLength` if a string is longer than `MAX_STR` bytes. (Strings may be empty here: `Server` decides what is
/// valid, and only changes it accepted are ever recorded.)
pub fn encode_op(op: &Op) -> Result<Vec<u8>, CodecError> {
    let mut out = Vec::new();
    match op {
        Op::CreateRoom { owner, name } => {
            out.push(1);
            encode_str(&mut out, owner)?;
            encode_str(&mut out, name)?;
        }
        Op::AddMember { slug, actor, user, role } => {
            out.push(2);
            encode_str(&mut out, slug)?;
            encode_str(&mut out, actor)?;
            encode_str(&mut out, user)?;
            let role_byte = match role {
                Role::Guest => 0,
                Role::Member => 1,
                Role::Admin => 2,
                Role::Owner => 3,
            };
            out.push(role_byte);
        }
        Op::RemoveMember { slug, actor, user } => {
            out.push(3);
            encode_str(&mut out, slug)?;
            encode_str(&mut out, actor)?;
            encode_str(&mut out, user)?;
        }
        Op::Post { slug, author, text, now_ms } => {
            out.push(4);
            encode_str(&mut out, slug)?;
            encode_str(&mut out, author)?;
            encode_str(&mut out, text)?;
            out.extend_from_slice(&now_ms.to_be_bytes());
        }
        Op::Edit { slug, actor, target, text, now_ms } => {
            out.push(5);
            encode_str(&mut out, slug)?;
            encode_str(&mut out, actor)?;
            out.extend_from_slice(&target.to_be_bytes());
            encode_str(&mut out, text)?;
            out.extend_from_slice(&now_ms.to_be_bytes());
        }
        Op::Delete { slug, actor, target } => {
            out.push(6);
            encode_str(&mut out, slug)?;
            encode_str(&mut out, actor)?;
            out.extend_from_slice(&target.to_be_bytes());
        }
        Op::MarkRead { slug, user, cursor } => {
            out.push(7);
            encode_str(&mut out, slug)?;
            encode_str(&mut out, user)?;
            out.extend_from_slice(&cursor.to_be_bytes());
        }
        Op::FileStored { slug, uploader, file, sha256, size, name, image } => {
            out.push(FILE_STORED);
            encode_str(&mut out, slug)?;
            encode_str(&mut out, uploader)?;
            out.extend_from_slice(file);
            out.extend_from_slice(sha256);
            out.extend_from_slice(&size.to_be_bytes());
            encode_str(&mut out, name)?;
            match image {
                None => out.push(0),
                Some((width, height)) => {
                    out.push(1);
                    out.extend_from_slice(&width.to_be_bytes());
                    out.extend_from_slice(&height.to_be_bytes());
                }
            }
        }
        Op::PostFiles { slug, author, text, now_ms, files } => {
            out.push(POST_FILES);
            encode_str(&mut out, slug)?;
            encode_str(&mut out, author)?;
            encode_str(&mut out, text)?;
            out.extend_from_slice(&now_ms.to_be_bytes());
            out.push(u8::try_from(files.len()).map_err(|_| CodecError::FieldLength)?);
            for file in files {
                out.extend_from_slice(file);
            }
        }
        Op::ImportRoom { key, name } => {
            out.push(IMPORT_ROOM);
            encode_str(&mut out, key)?;
            encode_str(&mut out, name)?;
        }
        Op::ImportMessage { slug, key, author, sent_ms, text, deleted, parent } => {
            out.push(IMPORT_MESSAGE);
            encode_str(&mut out, slug)?;
            encode_str(&mut out, key)?;
            encode_str(&mut out, author)?;
            out.extend_from_slice(&sent_ms.to_be_bytes());
            encode_str(&mut out, text)?;
            out.push(u8::from(*deleted));
            out.extend_from_slice(&parent.to_be_bytes());
        }
        Op::ImportEdit { slug, key, text, edited_ms } => {
            out.push(IMPORT_EDIT);
            encode_str(&mut out, slug)?;
            encode_str(&mut out, key)?;
            encode_str(&mut out, text)?;
            out.extend_from_slice(&edited_ms.to_be_bytes());
        }
        Op::ImportDelete { slug, key } => {
            out.push(IMPORT_DELETE);
            encode_str(&mut out, slug)?;
            encode_str(&mut out, key)?;
        }
        Op::ImportFiles { slug, key, files } => {
            out.push(IMPORT_FILES);
            encode_str(&mut out, slug)?;
            encode_str(&mut out, key)?;
            out.push(u8::try_from(files.len()).map_err(|_| CodecError::FieldLength)?);
            for (name, size, id) in files {
                encode_str(&mut out, name)?;
                out.extend_from_slice(&size.to_be_bytes());
                match id {
                    Some(id) => {
                        out.push(1);
                        out.extend_from_slice(id);
                    }
                    None => out.push(0),
                }
            }
        }
        Op::React { slug, actor, target, reaction, on, now_ms } => {
            out.push(REACT);
            encode_str(&mut out, slug)?;
            encode_str(&mut out, actor)?;
            out.extend_from_slice(&target.to_be_bytes());
            out.push(*reaction);
            out.push(u8::from(*on));
            out.extend_from_slice(&now_ms.to_be_bytes());
        }
        Op::Reply { slug, author, parent, text, now_ms } => {
            out.push(REPLY);
            encode_str(&mut out, slug)?;
            encode_str(&mut out, author)?;
            out.extend_from_slice(&parent.to_be_bytes());
            encode_str(&mut out, text)?;
            out.extend_from_slice(&now_ms.to_be_bytes());
        }
    }
    Ok(out)
}

/// Decode exactly one record. Errors in the order the bytes are read: the tag (`Truncated`, or `BadKind(tag)` for any
/// other tag), then each field in order (a string's length is checked against `MAX_STR`, `FieldLength`, before its
/// bytes are read; `Truncated` when bytes run out; `BadUtf8`; a role byte above 3 is `BadKind(byte)`), then
/// `TrailingBytes`.
pub fn decode_op(bytes: &[u8]) -> Result<Op, CodecError> {
    let mut pos: usize = 0;

    if pos + 1 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let tag = bytes[pos];
    pos += 1;

    match tag {
        1 => {
            let owner = decode_str(bytes, &mut pos)?;
            let name = decode_str(bytes, &mut pos)?;
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::CreateRoom { owner, name })
        }
        2 => {
            let slug = decode_str(bytes, &mut pos)?;
            let actor = decode_str(bytes, &mut pos)?;
            let user = decode_str(bytes, &mut pos)?;
            if pos + 1 > bytes.len() {
                return Err(CodecError::Truncated);
            }
            let role_byte = bytes[pos];
            pos += 1;
            let role = match role_byte {
                0 => Role::Guest,
                1 => Role::Member,
                2 => Role::Admin,
                3 => Role::Owner,
                _ => return Err(CodecError::BadKind(role_byte)),
            };
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::AddMember { slug, actor, user, role })
        }
        3 => {
            let slug = decode_str(bytes, &mut pos)?;
            let actor = decode_str(bytes, &mut pos)?;
            let user = decode_str(bytes, &mut pos)?;
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::RemoveMember { slug, actor, user })
        }
        4 => {
            let slug = decode_str(bytes, &mut pos)?;
            let author = decode_str(bytes, &mut pos)?;
            let text = decode_str(bytes, &mut pos)?;
            let now_ms = decode_u64(bytes, &mut pos)?;
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::Post { slug, author, text, now_ms })
        }
        5 => {
            let slug = decode_str(bytes, &mut pos)?;
            let actor = decode_str(bytes, &mut pos)?;
            let target = decode_u64(bytes, &mut pos)?;
            let text = decode_str(bytes, &mut pos)?;
            let now_ms = decode_u64(bytes, &mut pos)?;
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::Edit { slug, actor, target, text, now_ms })
        }
        6 => {
            let slug = decode_str(bytes, &mut pos)?;
            let actor = decode_str(bytes, &mut pos)?;
            let target = decode_u64(bytes, &mut pos)?;
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::Delete { slug, actor, target })
        }
        7 => {
            let slug = decode_str(bytes, &mut pos)?;
            let user = decode_str(bytes, &mut pos)?;
            let cursor = decode_u64(bytes, &mut pos)?;
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::MarkRead { slug, user, cursor })
        }
        FILE_STORED => {
            let slug = decode_str(bytes, &mut pos)?;
            let uploader = decode_str(bytes, &mut pos)?;
            let file = decode_array::<16>(bytes, &mut pos)?;
            let sha256 = decode_array::<32>(bytes, &mut pos)?;
            let size = decode_u64(bytes, &mut pos)?;
            let name = decode_str(bytes, &mut pos)?;
            let [has_image] = decode_array::<1>(bytes, &mut pos)?;
            let image = match has_image {
                0 => None,
                1 => {
                    let [w0, w1, w2, w3] = decode_array::<4>(bytes, &mut pos)?;
                    let [h0, h1, h2, h3] = decode_array::<4>(bytes, &mut pos)?;
                    Some((u32::from_be_bytes([w0, w1, w2, w3]), u32::from_be_bytes([h0, h1, h2, h3])))
                }
                other => return Err(CodecError::BadKind(other)),
            };
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::FileStored { slug, uploader, file, sha256, size, name, image })
        }
        POST_FILES => {
            let slug = decode_str(bytes, &mut pos)?;
            let author = decode_str(bytes, &mut pos)?;
            let text = decode_str(bytes, &mut pos)?;
            let now_ms = decode_u64(bytes, &mut pos)?;
            let [count] = decode_array::<1>(bytes, &mut pos)?;
            let mut files = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                files.push(decode_array::<16>(bytes, &mut pos)?);
            }
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::PostFiles { slug, author, text, now_ms, files })
        }
        REPLY => {
            let slug = decode_str(bytes, &mut pos)?;
            let author = decode_str(bytes, &mut pos)?;
            let parent = decode_u64(bytes, &mut pos)?;
            let text = decode_str(bytes, &mut pos)?;
            let now_ms = decode_u64(bytes, &mut pos)?;
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::Reply { slug, author, parent, text, now_ms })
        }
        REACT => {
            let slug = decode_str(bytes, &mut pos)?;
            let actor = decode_str(bytes, &mut pos)?;
            let target = decode_u64(bytes, &mut pos)?;
            let [reaction, on] = decode_array::<2>(bytes, &mut pos)?;
            let on = match on {
                0 => false,
                1 => true,
                other => return Err(CodecError::BadKind(other)),
            };
            let now_ms = decode_u64(bytes, &mut pos)?;
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::React { slug, actor, target, reaction, on, now_ms })
        }
        IMPORT_ROOM => {
            let key = decode_str(bytes, &mut pos)?;
            let name = decode_str(bytes, &mut pos)?;
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::ImportRoom { key, name })
        }
        IMPORT_MESSAGE => {
            let slug = decode_str(bytes, &mut pos)?;
            let key = decode_str(bytes, &mut pos)?;
            let author = decode_str(bytes, &mut pos)?;
            let sent_ms = decode_u64(bytes, &mut pos)?;
            let text = decode_str(bytes, &mut pos)?;
            let deleted = match decode_array::<1>(bytes, &mut pos)? {
                [0] => false,
                [1] => true,
                [other] => return Err(CodecError::BadKind(other)),
            };
            let parent = decode_u64(bytes, &mut pos)?;
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::ImportMessage { slug, key, author, sent_ms, text, deleted, parent })
        }
        IMPORT_EDIT => {
            let slug = decode_str(bytes, &mut pos)?;
            let key = decode_str(bytes, &mut pos)?;
            let text = decode_str(bytes, &mut pos)?;
            let edited_ms = decode_u64(bytes, &mut pos)?;
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::ImportEdit { slug, key, text, edited_ms })
        }
        IMPORT_DELETE => {
            let slug = decode_str(bytes, &mut pos)?;
            let key = decode_str(bytes, &mut pos)?;
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::ImportDelete { slug, key })
        }
        IMPORT_FILES => {
            let slug = decode_str(bytes, &mut pos)?;
            let key = decode_str(bytes, &mut pos)?;
            let [count] = decode_array::<1>(bytes, &mut pos)?;
            let mut files = Vec::with_capacity(usize::from(count));
            for _ in 0..count {
                let name = decode_str(bytes, &mut pos)?;
                let size = decode_u64(bytes, &mut pos)?;
                let id = match decode_array::<1>(bytes, &mut pos)? {
                    [0] => None,
                    [1] => Some(decode_array::<16>(bytes, &mut pos)?),
                    [other] => return Err(CodecError::BadKind(other)),
                };
                files.push((name, size, id));
            }
            if pos != bytes.len() {
                return Err(CodecError::TrailingBytes);
            }
            Ok(Op::ImportFiles { slug, key, files })
        }
        _ => Err(CodecError::BadKind(tag)),
    }
}

/// The tag of `Op::FileStored` (task T330a).
const FILE_STORED: u8 = 16;
/// The tag of `Op::PostFiles` (task T330c).
const POST_FILES: u8 = 17;
/// The tag of `Op::Reply` (task T340a).
const REPLY: u8 = 18;
/// The tag of `Op::React` (task T341a).
const REACT: u8 = 19;
/// The tags of the import records (task T350a).
const IMPORT_ROOM: u8 = 20;
const IMPORT_MESSAGE: u8 = 21;
const IMPORT_EDIT: u8 = 22;
const IMPORT_DELETE: u8 = 23;
const IMPORT_FILES: u8 = 24;

fn decode_array<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N], CodecError> {
    let end = pos.checked_add(N).ok_or(CodecError::Truncated)?;
    let array: [u8; N] = bytes.get(*pos..end).ok_or(CodecError::Truncated)?.try_into().map_err(|_| CodecError::Truncated)?;
    *pos = end;
    Ok(array)
}

fn encode_str(out: &mut Vec<u8>, s: &str) -> Result<(), CodecError> {
    let bytes = s.as_bytes();
    if bytes.len() > MAX_STR {
        return Err(CodecError::FieldLength);
    }
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn decode_str(bytes: &[u8], pos: &mut usize) -> Result<String, CodecError> {
    if *pos + 4 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let len = u32::from_be_bytes([bytes[*pos], bytes[*pos + 1], bytes[*pos + 2], bytes[*pos + 3]]) as usize;
    *pos += 4;
    if len > MAX_STR {
        return Err(CodecError::FieldLength);
    }
    if *pos + len > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let s = match std::str::from_utf8(&bytes[*pos..*pos + len]) {
        Ok(s) => s.to_owned(),
        Err(_) => return Err(CodecError::BadUtf8),
    };
    *pos += len;
    Ok(s)
}

fn decode_u64(bytes: &[u8], pos: &mut usize) -> Result<u64, CodecError> {
    if *pos + 8 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let val = u64::from_be_bytes([
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
    Ok(val)
}
