//! Personal activity snapshots for T347 (`docs/ACTIVITY.md`). All integers are big-endian.
//!
//! Follow frame: tag 144 | u32 request id | u64 head | u64 seen | u16 unread | u8 more | u8 count | rows.
//! Each row is u64 id | str room | str actor | u64 at_ms | u64 target | u64 parent (zero for none) |
//! u8 kind (1 mention, 2 reply, 3 both, 4 reaction, 5 missed call) | [u8 reaction for kind 4] | str snippet.
//! Strings carry a u16 byte length. A message target is a room cursor; a missed-call target is a call id.

use crate::message::{CodecError, MAX_NAME};
use crate::request::{MAX_AUTHOR, MAX_SNIPPET, read_array, read_bool, read_string, read_u32, read_u64, write_str};

pub const ACTIVITY_TAG: u8 = 144;
/// Maximum rows in a snapshot for one filter.
pub const MAX_ACTIVITY_ITEMS: usize = 64;
/// Maximum recent references retained for each person, independent of the filter.
pub const MAX_ACTIVITY_HISTORY: usize = 256;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ActivityFilter {
    #[default]
    All = 0,
    Unread = 1,
    Mentions = 2,
    Saved = 3,
    /// Counters only, for the app bar when the feed is closed.
    Badge = 4,
}

impl TryFrom<u8> for ActivityFilter {
    type Error = CodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::All),
            1 => Ok(Self::Unread),
            2 => Ok(Self::Mentions),
            3 => Ok(Self::Saved),
            4 => Ok(Self::Badge),
            other => Err(CodecError::BadKind(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityKind {
    Message { mentioned: bool, replied: bool },
    Reaction { reaction: u8 },
    MissedCall,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityItem {
    pub id: u64,
    pub room: String,
    pub actor: String,
    pub at_ms: u64,
    pub target: u64,
    pub parent: Option<u64>,
    pub kind: ActivityKind,
    pub snippet: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ActivitySnapshot {
    /// The most recent id issued to this person, even if its row is no longer visible.
    pub head: u64,
    pub seen: u64,
    /// Visible unseen activity across all filters within the retained window.
    pub unread: u16,
    pub more: bool,
    pub items: Vec<ActivityItem>,
}

pub fn encode_snapshot(id: u32, snapshot: &ActivitySnapshot) -> Result<Vec<u8>, CodecError> {
    check_snapshot(snapshot)?;
    let mut bytes = vec![ACTIVITY_TAG];
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&snapshot.head.to_be_bytes());
    bytes.extend_from_slice(&snapshot.seen.to_be_bytes());
    bytes.extend_from_slice(&snapshot.unread.to_be_bytes());
    bytes.extend_from_slice(&[u8::from(snapshot.more), snapshot.items.len() as u8]);
    for item in &snapshot.items {
        bytes.extend_from_slice(&item.id.to_be_bytes());
        write_str(&mut bytes, &item.room, 1, MAX_NAME)?;
        write_str(&mut bytes, &item.actor, 1, MAX_AUTHOR)?;
        bytes.extend_from_slice(&item.at_ms.to_be_bytes());
        bytes.extend_from_slice(&item.target.to_be_bytes());
        bytes.extend_from_slice(&item.parent.unwrap_or(0).to_be_bytes());
        match item.kind {
            ActivityKind::Message { mentioned, replied } => bytes.push(u8::from(mentioned) | (u8::from(replied) << 1)),
            ActivityKind::Reaction { reaction } => bytes.extend_from_slice(&[4, reaction]),
            ActivityKind::MissedCall => bytes.push(5),
        }
        write_str(&mut bytes, &item.snippet, 0, MAX_SNIPPET)?;
    }
    Ok(bytes)
}

pub fn decode_snapshot(bytes: &[u8]) -> Result<(u32, ActivitySnapshot), CodecError> {
    let mut pos = 0;
    let [tag] = read_array(bytes, &mut pos)?;
    if tag != ACTIVITY_TAG {
        return Err(CodecError::BadKind(tag));
    }
    let id = read_u32(bytes, &mut pos)?;
    let head = read_u64(bytes, &mut pos)?;
    let seen = read_u64(bytes, &mut pos)?;
    let unread = u16::from_be_bytes(read_array(bytes, &mut pos)?);
    let more = read_bool(bytes, &mut pos)?;
    let [count] = read_array(bytes, &mut pos)?;
    let count = usize::from(count);
    if count > MAX_ACTIVITY_ITEMS {
        return Err(CodecError::FieldLength);
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let id = read_u64(bytes, &mut pos)?;
        let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
        let actor = read_string(bytes, &mut pos, 1, MAX_AUTHOR)?;
        let at_ms = read_u64(bytes, &mut pos)?;
        let target = read_u64(bytes, &mut pos)?;
        let parent = read_u64(bytes, &mut pos)?;
        let parent = (parent != 0).then_some(parent);
        let kind = match read_array(bytes, &mut pos)? {
            [value @ 1..=3] => ActivityKind::Message { mentioned: value & 1 != 0, replied: value & 2 != 0 },
            [4] => {
                let [reaction] = read_array(bytes, &mut pos)?;
                ActivityKind::Reaction { reaction }
            }
            [5] => ActivityKind::MissedCall,
            [other] => return Err(CodecError::BadKind(other)),
        };
        let snippet = read_string(bytes, &mut pos, 0, MAX_SNIPPET)?;
        items.push(ActivityItem { id, room, actor, at_ms, target, parent, kind, snippet });
    }
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    let snapshot = ActivitySnapshot { head, seen, unread, more, items };
    check_snapshot(&snapshot)?;
    Ok((id, snapshot))
}

fn check_snapshot(snapshot: &ActivitySnapshot) -> Result<(), CodecError> {
    let count = snapshot.items.len();
    let unread = usize::from(snapshot.unread);
    if snapshot.seen > snapshot.head
        || count > MAX_ACTIVITY_ITEMS
        || (snapshot.more && count != MAX_ACTIVITY_ITEMS)
        || unread > MAX_ACTIVITY_HISTORY
        || snapshot.items.iter().filter(|item| item.id > snapshot.seen).count() > unread
        || snapshot.items.windows(2).any(|pair| pair[0].id <= pair[1].id)
    {
        return Err(CodecError::FieldLength);
    }
    for item in &snapshot.items {
        if item.id == 0 || item.id > snapshot.head || item.target == 0 {
            return Err(CodecError::FieldLength);
        }
        let valid = match item.kind {
            ActivityKind::Message { mentioned, replied } => {
                (mentioned || replied) && (!replied || item.parent.is_some()) && item.parent.is_none_or(|p| p != 0 && p < item.target)
            }
            ActivityKind::Reaction { reaction } => crate::push::reaction_name(reaction).is_some() && item.parent.is_none(),
            ActivityKind::MissedCall => item.parent.is_none() && item.snippet.is_empty(),
        };
        if !valid {
            return Err(CodecError::FieldLength);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ActivityFilter, ActivityItem, ActivityKind, ActivitySnapshot, CodecError, decode_snapshot, encode_snapshot};
    use crate::request::{Request, decode_request, encode_request};

    #[test]
    fn activity_requests_are_admitted_by_the_chat_decoder() -> Result<(), CodecError> {
        let requests = [Request::ListActivity { filter: ActivityFilter::Unread }, Request::MarkActivitySeen { through: 41 }];
        for request in requests {
            let payload = encode_request(42, &request)?;
            assert_eq!(decode_request(&payload)?, (42, request));
        }
        Ok(())
    }

    fn snapshot() -> ActivitySnapshot {
        ActivitySnapshot {
            head: 7,
            seen: 3,
            unread: 2,
            more: false,
            items: vec![
                ActivityItem {
                    id: 7,
                    room: "test-room".into(),
                    actor: "writer@example.org".into(),
                    at_ms: 120,
                    target: 10,
                    parent: Some(5),
                    kind: ActivityKind::Message { mentioned: true, replied: true },
                    snippet: "a reply with a mention".into(),
                },
                ActivityItem {
                    id: 5,
                    room: "test-room".into(),
                    actor: "caller@example.org".into(),
                    at_ms: 112,
                    target: 1,
                    parent: None,
                    kind: ActivityKind::MissedCall,
                    snippet: String::new(),
                },
            ],
        }
    }

    #[test]
    fn activity_codec_keeps_distinct_targets_and_refuses_partial_or_extra_rows() -> Result<(), CodecError> {
        let snapshot = snapshot();
        let mut encoded = encode_snapshot(42, &snapshot)?;
        assert_eq!(decode_snapshot(&encoded)?, (42, snapshot));
        for end in 0..encoded.len() {
            assert!(decode_snapshot(&encoded[..end]).is_err());
        }
        encoded.push(0);
        assert_eq!(decode_snapshot(&encoded), Err(CodecError::TrailingBytes));
        Ok(())
    }

    #[test]
    fn activity_codec_refuses_a_future_seen_position_duplicate_ids_and_a_reply_without_parent() {
        let mut invalid = snapshot();
        invalid.seen = invalid.head + 1;
        assert_eq!(encode_snapshot(1, &invalid), Err(CodecError::FieldLength));

        let mut invalid = snapshot();
        invalid.items[1].id = invalid.items[0].id;
        assert_eq!(encode_snapshot(1, &invalid), Err(CodecError::FieldLength));

        let mut invalid = snapshot();
        invalid.items[0].parent = None;
        assert_eq!(encode_snapshot(1, &invalid), Err(CodecError::FieldLength));
    }
}
