//! Meetings on the wire (docs/MEETINGS.md, task T370a): the meeting record as the server describes it, the meetings
//! frame that follows the answer to `MeetingSave` and `MeetingList`, and the limits both sides check. The requests
//! themselves are in `request`, the `MeetingLine` push in `push`.
//!
//! Owns: `Meeting`, `MeetingPage`, `Audience`, `MeetingState`, `MeetingChange`, `encode_meetings`, `decode_meetings`.
//!
//! Meetings frame, integers big-endian, `str` a `u16` byte length then UTF-8: `u8 tag (MEETINGS_TAG) | u32 id | u8 more
//! (0 or 1) | u16 n | n × (u64 meeting | str room (1 to MAX_NAME) | u64 version | str owner (1 to MAX_AUTHOR) | u8
//! audience | u64 start_ms | u16 duration minutes | str title (1 to MAX_TITLE_BYTES) | str agenda (0 to MAX_BODY) | u8
//! state)`, at most `MAX_LISTED_MEETINGS` meetings and `frame::MAX_FRAME` bytes.

use crate::message::{CodecError, MAX_BODY, MAX_NAME};
use crate::request::MAX_AUTHOR;

/// The first byte of a meetings frame.
pub const MEETINGS_TAG: u8 = 143;
/// The longest title, in characters after trimming.
pub const MAX_TITLE: usize = 200;
/// The longest title on the wire, in bytes.
pub const MAX_TITLE_BYTES: usize = MAX_TITLE * 4;
/// The longest agenda, in characters (a message's length).
pub const MAX_AGENDA: usize = 4000;
/// The longest meeting, in minutes.
pub const MAX_DURATION: u16 = 24 * 60;
/// The widest `MeetingList` window: 8 days, a work week in any time zone with room to spare.
pub const MAX_WINDOW_MS: u64 = 8 * 24 * 60 * 60 * 1000;
/// The most meetings one meetings frame lists.
pub const MAX_LISTED_MEETINGS: usize = 200;

/// Who may join a meeting, fixed when it is made. A staff meeting never becomes a guest meeting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Audience {
    /// Room members only, no guest link.
    Staff,
    /// Guests through a link and the lobby (a later slice; the server makes none yet).
    Guests,
}

/// Where a meeting stands, as the server sees it now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeetingState {
    /// No call yet: it can still be edited, rescheduled or cancelled.
    Scheduled,
    /// Its call is open.
    InProgress,
    /// It had calls and none is open.
    Held,
    Cancelled,
}

/// What a `MeetingLine` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeetingChange {
    Scheduled,
    Edited,
    Cancelled,
}

impl MeetingChange {
    /// The byte on the wire: 1, 2, 3.
    pub fn code(self) -> u8 {
        match self {
            Self::Scheduled => 1,
            Self::Edited => 2,
            Self::Cancelled => 3,
        }
    }

    /// The change for a wire byte, if it is one.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Scheduled),
            2 => Some(Self::Edited),
            3 => Some(Self::Cancelled),
            _ => None,
        }
    }
}

/// One meeting as the server describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meeting {
    pub id: u64,
    pub room: String,
    pub version: u64,
    pub owner: String,
    pub audience: Audience,
    /// UTC, Unix milliseconds.
    pub start_ms: u64,
    /// Minutes, 1 to `MAX_DURATION`.
    pub duration: u16,
    pub title: String,
    pub agenda: String,
    pub state: MeetingState,
}

/// A meetings frame's meetings; `more` when the server had more than fit (the client narrows the window).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MeetingPage {
    pub meetings: Vec<Meeting>,
    pub more: bool,
}

/// The bytes `meeting` takes in a meetings frame (the server fills a frame up to `frame::MAX_FRAME` with this).
pub fn wire_len(meeting: &Meeting) -> usize {
    8 + 2 + meeting.room.len() + 8 + 2 + meeting.owner.len() + 1 + 8 + 2 + 2 + meeting.title.len() + 2 + meeting.agenda.len() + 1
}

/// The bytes a meetings frame takes before its meetings.
pub const FRAME_HEADER: usize = 1 + 4 + 1 + 2;

/// Encode the meetings frame answering request `id`. `FieldLength` for more than `MAX_LISTED_MEETINGS` meetings, a
/// field out of its range, or a frame over `frame::MAX_FRAME`.
pub fn encode_meetings(id: u32, page: &MeetingPage) -> Result<Vec<u8>, CodecError> {
    if page.meetings.len() > MAX_LISTED_MEETINGS {
        return Err(CodecError::FieldLength);
    }
    let mut out = vec![MEETINGS_TAG];
    out.extend_from_slice(&id.to_be_bytes());
    out.push(u8::from(page.more));
    out.extend_from_slice(&(page.meetings.len() as u16).to_be_bytes());
    for meeting in &page.meetings {
        if meeting.duration == 0 || meeting.duration > MAX_DURATION {
            return Err(CodecError::FieldLength);
        }
        out.extend_from_slice(&meeting.id.to_be_bytes());
        write_str(&mut out, &meeting.room, 1, MAX_NAME)?;
        out.extend_from_slice(&meeting.version.to_be_bytes());
        write_str(&mut out, &meeting.owner, 1, MAX_AUTHOR)?;
        out.push(match meeting.audience {
            Audience::Staff => 0,
            Audience::Guests => 1,
        });
        out.extend_from_slice(&meeting.start_ms.to_be_bytes());
        out.extend_from_slice(&meeting.duration.to_be_bytes());
        write_str(&mut out, &meeting.title, 1, MAX_TITLE_BYTES)?;
        write_str(&mut out, &meeting.agenda, 0, MAX_BODY)?;
        out.push(match meeting.state {
            MeetingState::Scheduled => 0,
            MeetingState::InProgress => 1,
            MeetingState::Held => 2,
            MeetingState::Cancelled => 3,
        });
    }
    if out.len() > crate::frame::MAX_FRAME {
        return Err(CodecError::FieldLength);
    }
    Ok(out)
}

/// Decode exactly one meetings frame: its request id and page. Errors in the order the bytes are read: the tag
/// (`BadKind` for anything but `MEETINGS_TAG`), the id, `more`, the count (`FieldLength` above `MAX_LISTED_MEETINGS`),
/// each meeting's fields (an unknown audience or state is `BadKind`, a duration outside 1 to `MAX_DURATION`
/// `FieldLength`), then `TrailingBytes`.
pub fn decode_meetings(bytes: &[u8]) -> Result<(u32, MeetingPage), CodecError> {
    let Some(&tag) = bytes.first() else { return Err(CodecError::Truncated) };
    if tag != MEETINGS_TAG {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos = 1;
    let id = u32::from_be_bytes(read_array::<4>(bytes, &mut pos)?);
    let more = match read_array::<1>(bytes, &mut pos)? {
        [0] => false,
        [1] => true,
        [other] => return Err(CodecError::BadKind(other)),
    };
    let count = usize::from(u16::from_be_bytes(read_array::<2>(bytes, &mut pos)?));
    if count > MAX_LISTED_MEETINGS {
        return Err(CodecError::FieldLength);
    }
    let mut meetings = Vec::with_capacity(count);
    for _ in 0..count {
        let id = read_u64(bytes, &mut pos)?;
        let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
        let version = read_u64(bytes, &mut pos)?;
        let owner = read_string(bytes, &mut pos, 1, MAX_AUTHOR)?;
        let audience = match read_array::<1>(bytes, &mut pos)? {
            [0] => Audience::Staff,
            [1] => Audience::Guests,
            [other] => return Err(CodecError::BadKind(other)),
        };
        let start_ms = read_u64(bytes, &mut pos)?;
        let duration = u16::from_be_bytes(read_array::<2>(bytes, &mut pos)?);
        if duration == 0 || duration > MAX_DURATION {
            return Err(CodecError::FieldLength);
        }
        let title = read_string(bytes, &mut pos, 1, MAX_TITLE_BYTES)?;
        let agenda = read_string(bytes, &mut pos, 0, MAX_BODY)?;
        let state = match read_array::<1>(bytes, &mut pos)? {
            [0] => MeetingState::Scheduled,
            [1] => MeetingState::InProgress,
            [2] => MeetingState::Held,
            [3] => MeetingState::Cancelled,
            [other] => return Err(CodecError::BadKind(other)),
        };
        meetings.push(Meeting { id, room, version, owner, audience, start_ms, duration, title, agenda, state });
    }
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, MeetingPage { meetings, more }))
}

fn write_str(out: &mut Vec<u8>, s: &str, min: usize, max: usize) -> Result<(), CodecError> {
    let bytes = s.as_bytes();
    if bytes.len() < min || bytes.len() > max {
        return Err(CodecError::FieldLength);
    }
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn read_array<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N], CodecError> {
    let end = pos.checked_add(N).filter(|end| *end <= bytes.len()).ok_or(CodecError::Truncated)?;
    let mut array = [0u8; N];
    array.copy_from_slice(&bytes[*pos..end]);
    *pos = end;
    Ok(array)
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> Result<u64, CodecError> {
    Ok(u64::from_be_bytes(read_array::<8>(bytes, pos)?))
}

fn read_string(bytes: &[u8], pos: &mut usize, min: usize, max: usize) -> Result<String, CodecError> {
    let len = usize::from(u16::from_be_bytes(read_array::<2>(bytes, pos)?));
    if len < min || len > max {
        return Err(CodecError::FieldLength);
    }
    let end = pos.checked_add(len).filter(|end| *end <= bytes.len()).ok_or(CodecError::Truncated)?;
    let text = std::str::from_utf8(&bytes[*pos..end]).map_err(|_| CodecError::BadUtf8)?.to_owned();
    *pos = end;
    Ok(text)
}
