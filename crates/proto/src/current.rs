//! Bounded current-state recovery after a cursor-log gap (T345, docs/GAP-REPLAY.md).
//!
//! One Current request is answered by Ok at the captured head, then CurrentPage frames sharing its request id.
//! Wire: tag139 | u32 id | str room | u64 head | u32 index | bool last | bool older | bool archived | u8 count |
//! records. A record starts with kind0/1/2 and u64 message cursor. Message: str author | str html | bool edited |
//! u64 parent (zero for none) | bool has_time | [u64 time]. File: u8 index | 16 id | str name | u64 size |
//! bool has_image | [u32 width | u32 height]. Reaction: u8 code | str author. Strings have u16 byte lengths;
//! integers are big-endian and booleans are exactly zero or one. Pages are locally ordered; the receiver also
//! validates the complete stream, including page continuity and metadata belonging to captured messages.

use crate::frame::MAX_FRAME;
use crate::message::{CodecError, MAX_NAME};
use crate::push::{AttachedFile, MAX_ATTACHMENT_NAME, MAX_ATTACHMENTS, MAX_HTML, reaction_name};
use crate::request::MAX_AUTHOR;

pub const CURRENT_TAG: u8 = 139;
pub const MAX_CURRENT_MESSAGES: usize = 50;
pub const MAX_CURRENT_PAGE_RECORDS: usize = 16;
pub const MAX_CURRENT_RECORDS: usize = 32_768;
/// Sum of framed follow bytes; the fixed Ok acknowledgement is not part of this budget.
pub const MAX_CURRENT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentPage {
    pub room: String,
    pub head: u64,
    pub index: u32,
    pub last: bool,
    pub older: bool,
    pub archived: bool,
    pub records: Vec<CurrentRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CurrentRecord {
    Message {
        cursor: u64,
        author: String,
        html: String,
        edited: bool,
        parent: Option<u64>,
        sent_ms: Option<u64>,
    },
    File {
        cursor: u64,
        index: u8,
        file: AttachedFile,
    },
    Reaction {
        cursor: u64,
        reaction: u8,
        author: String,
    },
}

impl CurrentRecord {
    /// Strict stream order: message cursor, kind, file index or reaction code, and reaction author.
    pub fn key(&self) -> (u64, u8, u8, &str) {
        match self {
            Self::Message { cursor, .. } => (*cursor, 0, 0, ""),
            Self::File { cursor, index, .. } => (*cursor, 1, *index, ""),
            Self::Reaction { cursor, reaction, author } => (*cursor, 2, *reaction, author),
        }
    }
}

/// Encode one page, refusing malformed fields, local ordering and individual frame overflow.
pub fn encode_page(id: u32, page: &CurrentPage) -> Result<Vec<u8>, CodecError> {
    check_page(page)?;
    let mut out = vec![CURRENT_TAG];
    out.extend_from_slice(&id.to_be_bytes());
    write_string(&mut out, &page.room, 1, MAX_NAME)?;
    out.extend_from_slice(&page.head.to_be_bytes());
    out.extend_from_slice(&page.index.to_be_bytes());
    out.extend_from_slice(&[u8::from(page.last), u8::from(page.older), u8::from(page.archived), page.records.len() as u8]);
    for record in &page.records {
        encode_record(&mut out, record)?;
        if out.len() > MAX_FRAME {
            return Err(CodecError::FieldLength);
        }
    }
    Ok(out)
}

/// Decode one exact page. Counts are checked before allocation; a complete stream needs additional validation.
pub fn decode_page(bytes: &[u8]) -> Result<(u32, CurrentPage), CodecError> {
    if bytes.len() > MAX_FRAME {
        return Err(CodecError::FieldLength);
    }
    let mut reader = Reader { bytes, position: 0 };
    let tag = reader.byte()?;
    if tag != CURRENT_TAG {
        return Err(CodecError::BadKind(tag));
    }
    let id = u32::from_be_bytes(reader.array()?);
    let room = reader.string(1, MAX_NAME)?;
    let head = u64::from_be_bytes(reader.array()?);
    let index = u32::from_be_bytes(reader.array()?);
    let last = reader.boolean()?;
    let older = reader.boolean()?;
    let archived = reader.boolean()?;
    let count = usize::from(reader.byte()?);
    if count > MAX_CURRENT_PAGE_RECORDS {
        return Err(CodecError::FieldLength);
    }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(reader.record()?);
    }
    if reader.position != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    let page = CurrentPage { room, head, index, last, older, archived, records };
    check_page(&page)?;
    Ok((id, page))
}

fn check_page(page: &CurrentPage) -> Result<(), CodecError> {
    if page.room.is_empty() || page.room.len() > MAX_NAME || page.records.len() > MAX_CURRENT_PAGE_RECORDS
        || page.index >= MAX_CURRENT_RECORDS as u32
        || (page.records.is_empty() && (!page.last || page.index != 0 || page.older))
    {
        return Err(CodecError::FieldLength);
    }
    let mut previous: Option<&CurrentRecord> = None;
    for record in &page.records {
        let key = record.key();
        if key.0 == 0 || key.0 > page.head || previous.is_some_and(|previous| previous.key() >= key) {
            return Err(CodecError::FieldLength);
        }
        // A continuation page may start in a message's metadata; a new cursor must always start with its body.
        if key.1 != 0 && previous.map_or(page.index == 0, |previous| previous.key().0 != key.0) {
            return Err(CodecError::FieldLength);
        }
        match record {
            CurrentRecord::Message { author, html, parent, .. } => {
                check_string(author, 1, MAX_AUTHOR)?;
                check_string(html, 0, MAX_HTML)?;
                if *parent == Some(0) {
                    return Err(CodecError::FieldLength);
                }
            }
            CurrentRecord::File { index, file, .. } => {
                check_string(&file.name, 1, MAX_ATTACHMENT_NAME)?;
                if usize::from(*index) >= MAX_ATTACHMENTS {
                    return Err(CodecError::FieldLength);
                }
                if let Some(previous) = previous.filter(|previous| previous.key().0 == key.0) {
                    let expected = match previous {
                        CurrentRecord::Message { .. } => 0,
                        CurrentRecord::File { index, .. } => index.saturating_add(1),
                        CurrentRecord::Reaction { .. } => return Err(CodecError::FieldLength),
                    };
                    if *index != expected {
                        return Err(CodecError::FieldLength);
                    }
                }
            }
            CurrentRecord::Reaction { reaction, author, .. } => {
                check_string(author, 1, MAX_AUTHOR)?;
                if reaction_name(*reaction).is_none() {
                    return Err(CodecError::BadKind(*reaction));
                }
            }
        }
        previous = Some(record);
    }
    Ok(())
}

fn encode_record(out: &mut Vec<u8>, record: &CurrentRecord) -> Result<(), CodecError> {
    let (cursor, kind, _, _) = record.key();
    out.push(kind);
    out.extend_from_slice(&cursor.to_be_bytes());
    match record {
        CurrentRecord::Message { author, html, edited, parent, sent_ms, .. } => {
            write_string(out, author, 1, MAX_AUTHOR)?;
            write_string(out, html, 0, MAX_HTML)?;
            out.push(u8::from(*edited));
            out.extend_from_slice(&parent.unwrap_or(0).to_be_bytes());
            out.push(u8::from(sent_ms.is_some()));
            if let Some(time) = sent_ms {
                out.extend_from_slice(&time.to_be_bytes());
            }
        }
        CurrentRecord::File { index, file, .. } => {
            out.push(*index);
            out.extend_from_slice(&file.file);
            write_string(out, &file.name, 1, MAX_ATTACHMENT_NAME)?;
            out.extend_from_slice(&file.size.to_be_bytes());
            out.push(u8::from(file.image.is_some()));
            if let Some((width, height)) = file.image {
                out.extend_from_slice(&width.to_be_bytes());
                out.extend_from_slice(&height.to_be_bytes());
            }
        }
        CurrentRecord::Reaction { reaction, author, .. } => {
            out.push(*reaction);
            write_string(out, author, 1, MAX_AUTHOR)?;
        }
    }
    Ok(())
}

fn check_string(text: &str, min: usize, max: usize) -> Result<(), CodecError> {
    if text.len() < min || text.len() > max { Err(CodecError::FieldLength) } else { Ok(()) }
}

fn write_string(out: &mut Vec<u8>, text: &str, min: usize, max: usize) -> Result<(), CodecError> {
    check_string(text, min, max)?;
    out.extend_from_slice(&(text.len() as u16).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let end = self.position.checked_add(N).ok_or(CodecError::Truncated)?;
        let value = self.bytes.get(self.position..end).ok_or(CodecError::Truncated)?.try_into().map_err(|_| CodecError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, CodecError> {
        Ok(self.array::<1>()?[0])
    }

    fn boolean(&mut self) -> Result<bool, CodecError> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(CodecError::BadKind(other)),
        }
    }

    fn string(&mut self, min: usize, max: usize) -> Result<String, CodecError> {
        let length = usize::from(u16::from_be_bytes(self.array()?));
        if length < min || length > max {
            return Err(CodecError::FieldLength);
        }
        let end = self.position.checked_add(length).ok_or(CodecError::Truncated)?;
        let text = self.bytes.get(self.position..end).ok_or(CodecError::Truncated)?;
        self.position = end;
        Ok(std::str::from_utf8(text).map_err(|_| CodecError::BadUtf8)?.to_owned())
    }

    fn record(&mut self) -> Result<CurrentRecord, CodecError> {
        let kind = self.byte()?;
        if kind > 2 { return Err(CodecError::BadKind(kind)); }
        let cursor = u64::from_be_bytes(self.array()?);
        match kind {
            0 => {
                let author = self.string(1, MAX_AUTHOR)?;
                let html = self.string(0, MAX_HTML)?;
                let edited = self.boolean()?;
                let parent = u64::from_be_bytes(self.array()?);
                let parent = (parent != 0).then_some(parent);
                let sent_ms = if self.boolean()? { Some(u64::from_be_bytes(self.array()?)) } else { None };
                Ok(CurrentRecord::Message { cursor, author, html, edited, parent, sent_ms })
            }
            1 => {
                let index = self.byte()?;
                let file = self.array()?;
                let name = self.string(1, MAX_ATTACHMENT_NAME)?;
                let size = u64::from_be_bytes(self.array()?);
                let image = if self.boolean()? {
                    Some((u32::from_be_bytes(self.array()?), u32::from_be_bytes(self.array()?)))
                } else { None };
                Ok(CurrentRecord::File { cursor, index, file: AttachedFile { file, name, size, image } })
            }
            2 => {
                let reaction = self.byte()?;
                if reaction_name(reaction).is_none() { return Err(CodecError::BadKind(reaction)); }
                let author = self.string(1, MAX_AUTHOR)?;
                Ok(CurrentRecord::Reaction { cursor, reaction, author })
            }
            other => Err(CodecError::BadKind(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(cursor: u64, html: String) -> CurrentRecord {
        CurrentRecord::Message { cursor, author: "author".into(), html, edited: true, parent: Some(1), sent_ms: Some(0) }
    }

    fn page(records: Vec<CurrentRecord>) -> CurrentPage {
        CurrentPage { room: "room".into(), head: 20, index: 0, last: true, older: false, archived: true, records }
    }

    #[test]
    fn current_pages_refuse_hostile_lengths_booleans_kinds_order_and_partial_frames() -> Result<(), CodecError> {
        let original = page(vec![message(3, String::new()), CurrentRecord::Reaction { cursor: 3, reaction: 1, author: "reader".into() }]);
        let bytes = encode_page(7, &original)?;
        assert_eq!(decode_page(&bytes)?, (7, original.clone()));
        for end in 0..bytes.len() { assert!(decode_page(&bytes[..end]).is_err()); }
        let flags = 1 + 4 + 2 + original.room.len() + 8 + 4;
        for offset in flags..flags + 3 {
            let mut hostile = bytes.clone();
            hostile[offset] = 2;
            assert_eq!(decode_page(&hostile), Err(CodecError::BadKind(2)));
        }
        let mut hostile = bytes.clone();
        hostile[flags + 3] = (MAX_CURRENT_PAGE_RECORDS + 1) as u8;
        assert_eq!(decode_page(&hostile), Err(CodecError::FieldLength));
        hostile = bytes.clone();
        hostile[flags + 4] = 3;
        assert_eq!(decode_page(&hostile), Err(CodecError::BadKind(3)));
        hostile = bytes.clone();
        hostile[7] = 255;
        assert_eq!(decode_page(&hostile), Err(CodecError::BadUtf8));
        hostile = bytes;
        hostile.push(0);
        assert_eq!(decode_page(&hostile), Err(CodecError::TrailingBytes));
        assert!(encode_page(7, &page(vec![message(3, "old".into()), message(3, "duplicate".into())])).is_err());
        assert!(encode_page(7, &page(vec![message(21, "future".into())])).is_err());
        assert!(encode_page(7, &page(vec![CurrentRecord::Reaction { cursor: 3, reaction: 1, author: "reader".into() }])).is_err());
        let mut continuation = page(vec![CurrentRecord::Reaction { cursor: 3, reaction: 1, author: "reader".into() }]);
        continuation.index = 1;
        assert_eq!(decode_page(&encode_page(7, &continuation)?)?, (7, continuation));
        Ok(())
    }

    #[test]
    fn files_are_contiguous_and_empty_terminal_shapes_are_unambiguous() -> Result<(), CodecError> {
        let file = AttachedFile { file: [3; 16], name: "file.txt".into(), size: 8, image: None };
        let valid = page(vec![message(3, "body".into()), CurrentRecord::File { cursor: 3, index: 0, file: file.clone() }]);
        assert_eq!(decode_page(&encode_page(2, &valid)?)?, (2, valid));
        assert!(encode_page(2, &page(vec![message(3, "body".into()), CurrentRecord::File { cursor: 3, index: 1, file }])).is_err());
        let mut empty = page(Vec::new());
        assert_eq!(decode_page(&encode_page(2, &empty)?)?, (2, empty.clone()));
        empty.last = false;
        assert!(encode_page(2, &empty).is_err());
        empty.last = true;
        empty.index = 1;
        assert!(encode_page(2, &empty).is_err());
        Ok(())
    }

    #[test]
    fn sixteen_maximum_bodies_fit_one_frame_without_truncation() -> Result<(), CodecError> {
        let original = page((1..=MAX_CURRENT_PAGE_RECORDS).map(|cursor| message(cursor as u64, "x".repeat(MAX_HTML))).collect());
        let bytes = encode_page(9, &original)?;
        assert!(bytes.len() < MAX_FRAME);
        assert_eq!(decode_page(&bytes)?, (9, original));
        Ok(())
    }
}
