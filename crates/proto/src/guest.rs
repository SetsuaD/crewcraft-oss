//! Staff-side guest meeting messages (T370c, docs/MEETINGS.md).
//!
//! Follow frame: tag 145 | u32 request id | u8 kind (0 lobby, 1 created) | u64 meeting | u64 revision |
//! u64 expires_ms | u8 lobby | u8 closed | u8 count | count × (u64 guest | str name | u8 state | u64 revision).
//! Kind 1 alone ends with the 24 ASCII bytes of the new link code. Strings carry a big-endian u16 length.

use std::collections::BTreeSet;
use std::fmt;

use crate::message::CodecError;
use crate::request::{read_array, read_bool, read_string, read_u32, read_u64, write_str};

pub const GUEST_TAG: u8 = 145;
pub const GUEST_CODE_LEN: usize = 24;
pub const MAX_GUEST_NAME: usize = 60;
pub const MAX_GUEST_NAME_BYTES: usize = MAX_GUEST_NAME * 4;
pub const MAX_GUEST_ENTRIES: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestMeetingDraft {
    pub room: String,
    pub start_ms: u64,
    pub duration: u16,
    pub title: String,
    pub agenda: String,
    pub host_name: String,
    pub expires_ms: u64,
    pub lobby: bool,
    pub confirm_direct: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestMeetingChange {
    Create(GuestMeetingDraft),
    SetLobby { meeting: u64, revision: u64, lobby: bool, confirm_direct: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestDecision {
    Admit,
    Decline,
    Remove,
}

impl GuestDecision {
    pub fn code(self) -> u8 {
        match self {
            Self::Admit => 1,
            Self::Decline => 2,
            Self::Remove => 3,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Admit),
            2 => Some(Self::Decline),
            3 => Some(Self::Remove),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestState {
    Waiting,
    Admitted,
    Declined,
    Removed,
}

impl GuestState {
    pub fn code(self) -> u8 {
        match self {
            Self::Waiting => 0,
            Self::Admitted => 1,
            Self::Declined => 2,
            Self::Removed => 3,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::Waiting),
            1 => Some(Self::Admitted),
            2 => Some(Self::Declined),
            3 => Some(Self::Removed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestEntry {
    pub guest: u64,
    pub name: String,
    pub state: GuestState,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestLobby {
    pub meeting: u64,
    pub revision: u64,
    pub expires_ms: u64,
    pub lobby: bool,
    pub closed: bool,
    pub entries: Vec<GuestEntry>,
}

/// A creation-only link credential. Encoding requires the unpadded uppercase RFC 4648 alphabet.
#[derive(Clone, PartialEq, Eq)]
pub struct GuestCode(pub String);

impl GuestCode {
    pub fn is_valid(&self) -> bool {
        self.0.len() == GUEST_CODE_LEN && self.0.bytes().all(|byte| matches!(byte, b'A'..=b'Z' | b'2'..=b'7'))
    }
}

impl fmt::Debug for GuestCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GuestCode([redacted])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestReply {
    Created { lobby: GuestLobby, code: GuestCode },
    Lobby(GuestLobby),
}

pub fn encode_guest(id: u32, reply: &GuestReply) -> Result<Vec<u8>, CodecError> {
    let (lobby, code) = match reply {
        GuestReply::Created { lobby, code } => (lobby, Some(code)),
        GuestReply::Lobby(lobby) => (lobby, None),
    };
    check_lobby(lobby)?;
    if code.is_some_and(|code| lobby.closed || !code.is_valid()) {
        return Err(CodecError::FieldLength);
    }

    let mut out = vec![GUEST_TAG];
    out.extend_from_slice(&id.to_be_bytes());
    out.push(u8::from(code.is_some()));
    out.extend_from_slice(&lobby.meeting.to_be_bytes());
    out.extend_from_slice(&lobby.revision.to_be_bytes());
    out.extend_from_slice(&lobby.expires_ms.to_be_bytes());
    out.extend_from_slice(&[u8::from(lobby.lobby), u8::from(lobby.closed), lobby.entries.len() as u8]);
    for entry in &lobby.entries {
        out.extend_from_slice(&entry.guest.to_be_bytes());
        write_str(&mut out, &entry.name, 1, MAX_GUEST_NAME_BYTES)?;
        out.push(entry.state.code());
        out.extend_from_slice(&entry.revision.to_be_bytes());
    }
    if let Some(code) = code {
        out.extend_from_slice(code.0.as_bytes());
    }
    Ok(out)
}

pub fn decode_guest(bytes: &[u8]) -> Result<(u32, GuestReply), CodecError> {
    let mut pos = 0;
    let [tag] = read_array(bytes, &mut pos)?;
    if tag != GUEST_TAG {
        return Err(CodecError::BadKind(tag));
    }
    let id = read_u32(bytes, &mut pos)?;
    let created = read_bool(bytes, &mut pos)?;
    let meeting = read_u64(bytes, &mut pos)?;
    let revision = read_u64(bytes, &mut pos)?;
    let expires_ms = read_u64(bytes, &mut pos)?;
    let lobby = read_bool(bytes, &mut pos)?;
    let closed = read_bool(bytes, &mut pos)?;
    let [count] = read_array(bytes, &mut pos)?;
    let count = usize::from(count);
    if count > MAX_GUEST_ENTRIES {
        return Err(CodecError::FieldLength);
    }

    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let guest = read_u64(bytes, &mut pos)?;
        let name = read_string(bytes, &mut pos, 1, MAX_GUEST_NAME_BYTES)?;
        let [state] = read_array(bytes, &mut pos)?;
        let state = GuestState::from_code(state).ok_or(CodecError::BadKind(state))?;
        let revision = read_u64(bytes, &mut pos)?;
        entries.push(GuestEntry { guest, name, state, revision });
    }

    let lobby = GuestLobby { meeting, revision, expires_ms, lobby, closed, entries };
    check_lobby(&lobby)?;
    let reply = if created {
        let code = read_array::<GUEST_CODE_LEN>(bytes, &mut pos)?;
        let code = GuestCode(String::from_utf8(code.to_vec()).map_err(|_| CodecError::BadUtf8)?);
        if lobby.closed || !code.is_valid() {
            return Err(CodecError::FieldLength);
        }
        GuestReply::Created { lobby, code }
    } else {
        GuestReply::Lobby(lobby)
    };
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, reply))
}

fn check_lobby(lobby: &GuestLobby) -> Result<(), CodecError> {
    if lobby.meeting == 0 || lobby.revision == 0 || lobby.expires_ms == 0 || lobby.entries.len() > MAX_GUEST_ENTRIES {
        return Err(CodecError::FieldLength);
    }
    let mut guests = BTreeSet::new();
    for entry in &lobby.entries {
        if entry.guest == 0
            || entry.revision == 0
            || !guests.insert(entry.guest)
            || entry.name.trim() != entry.name
            || !(1..=MAX_GUEST_NAME).contains(&entry.name.chars().count())
            || entry.name.chars().any(|ch| ch.is_control() || matches!(ch, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
            || (lobby.closed && matches!(entry.state, GuestState::Waiting | GuestState::Admitted))
        {
            return Err(CodecError::FieldLength);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::meeting::MeetingChange;
    use crate::push::{Push, decode_push, encode_push};
    use crate::request::{Request, decode_request, encode_request};

    fn lobby() -> GuestLobby {
        GuestLobby { meeting: 2, revision: 1, expires_ms: 1_800_000_000_000, lobby: true, closed: false, entries: Vec::new() }
    }

    #[test]
    fn guest_follow_is_correlated_bounded_and_carries_a_redacted_code_only_on_creation() -> Result<(), CodecError> {
        let code = GuestCode("A".repeat(GUEST_CODE_LEN));
        let created = GuestReply::Created { lobby: lobby(), code: code.clone() };
        assert!(!format!("{created:?}").contains(&code.0));
        let mut listed = lobby();
        listed.entries.push(GuestEntry { guest: 4, name: "Guest name".into(), state: GuestState::Waiting, revision: 1 });
        for reply in [created, GuestReply::Lobby(listed)] {
            let mut encoded = encode_guest(17, &reply)?;
            assert_eq!(decode_guest(&encoded)?, (17, reply));
            for end in 0..encoded.len() {
                assert!(decode_guest(&encoded[..end]).is_err());
            }
            encoded.push(0);
            assert_eq!(decode_guest(&encoded), Err(CodecError::TrailingBytes));
        }
        Ok(())
    }

    #[test]
    fn guest_follow_refuses_invalid_credentials_states_and_roster_bounds() -> Result<(), CodecError> {
        for raw in ["short".into(), "a".repeat(GUEST_CODE_LEN), "0".repeat(GUEST_CODE_LEN)] {
            assert!(encode_guest(17, &GuestReply::Created { lobby: lobby(), code: GuestCode(raw) }).is_err());
        }
        let mut listed = lobby();
        let waiting = GuestEntry { guest: 4, name: "Guest".into(), state: GuestState::Waiting, revision: 1 };
        listed.entries.push(waiting.clone());
        let mut encoded = encode_guest(17, &GuestReply::Lobby(listed.clone()))?;
        let state_index = encoded.len() - 9;
        encoded[state_index] = 4;
        assert_eq!(decode_guest(&encoded), Err(CodecError::BadKind(4)));

        listed.closed = true;
        assert!(encode_guest(17, &GuestReply::Lobby(listed.clone())).is_err());
        listed.closed = false;
        listed.entries.push(waiting.clone());
        assert!(encode_guest(17, &GuestReply::Lobby(listed.clone())).is_err());
        listed.entries = vec![waiting; MAX_GUEST_ENTRIES + 1];
        assert!(encode_guest(17, &GuestReply::Lobby(listed)).is_err());
        Ok(())
    }

    #[test]
    fn staff_guest_requests_are_admitted_to_the_decoder_without_accepting_bad_kinds_or_booleans() -> Result<(), CodecError> {
        let draft = GuestMeetingDraft {
            room: "planning".into(),
            start_ms: 1_800_000_000_000,
            duration: 30,
            title: "Planning".into(),
            agenda: String::new(),
            host_name: "Host".into(),
            expires_ms: 1_800_036_000_000,
            lobby: true,
            confirm_direct: false,
        };
        let requests = [
            Request::GuestMeetingSave { change: GuestMeetingChange::Create(draft) },
            Request::GuestMeetingSave { change: GuestMeetingChange::SetLobby { meeting: 1, revision: 2, lobby: false, confirm_direct: true } },
            Request::GuestLinkClose { meeting: 1, revision: 2 },
            Request::GuestLobbyList { meeting: 1 },
            Request::GuestLobbyDecide { meeting: 1, guest: 3, revision: 2, decision: GuestDecision::Admit },
            Request::GuestLobbyDecide { meeting: 1, guest: 3, revision: 2, decision: GuestDecision::Decline },
            Request::GuestLobbyDecide { meeting: 1, guest: 3, revision: 2, decision: GuestDecision::Remove },
        ];
        for (tag, request) in [50, 50, 51, 52, 53, 53, 53].into_iter().zip(requests) {
            let mut bytes = encode_request(8, &request)?;
            assert_eq!(bytes[0], tag);
            assert_eq!(decode_request(&bytes)?, (8, request));
            for end in 0..bytes.len() {
                assert!(decode_request(&bytes[..end]).is_err());
            }
            bytes.push(0);
            assert_eq!(decode_request(&bytes), Err(CodecError::TrailingBytes));
        }

        let change = GuestMeetingChange::SetLobby { meeting: 1, revision: 2, lobby: false, confirm_direct: true };
        let request = Request::GuestMeetingSave { change };
        let mut bytes = encode_request(8, &request)?;
        let last = bytes.len() - 1;
        bytes[last] = 2;
        assert_eq!(decode_request(&bytes), Err(CodecError::BadKind(2)));
        bytes[5] = 3;
        assert_eq!(decode_request(&bytes), Err(CodecError::BadKind(3)));
        let mut bytes = encode_request(8, &Request::GuestLobbyDecide { meeting: 1, guest: 3, revision: 2, decision: GuestDecision::Remove })?;
        let last = bytes.len() - 1;
        bytes[last] = 4;
        assert_eq!(decode_request(&bytes), Err(CodecError::BadKind(4)));
        Ok(())
    }

    #[test]
    fn lobby_count_and_line_cover_zero_waiting_and_independent_room_revisions() -> Result<(), CodecError> {
        let empty = Push::GuestLobbyState { room: "planning".into(), cursor: 0, revision: 0, waiting: 0 };
        let changed = Push::GuestLobbyState { room: "planning".into(), cursor: 14, revision: 8, waiting: 51 };
        let line = Push::MeetingLine {
            room: "planning".into(),
            cursor: 14,
            meeting: 1,
            change: MeetingChange::Lobby,
            version: 8,
            author: "host".into(),
            text: "closed the guest link".into(),
        };
        for (tag, push) in [(87, empty), (87, changed), (85, line)] {
            let mut bytes = encode_push(&push)?;
            assert_eq!(bytes[0], tag);
            assert_eq!(decode_push(&bytes)?, push);
            for end in 0..bytes.len() {
                assert!(decode_push(&bytes[..end]).is_err());
            }
            bytes.push(0);
            assert_eq!(decode_push(&bytes), Err(CodecError::TrailingBytes));
        }
        Ok(())
    }
}
