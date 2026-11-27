//! Personal room settings (T346, REQUIREMENTS 2.2 "Personal room settings"): each person can pin a room to the top of
//! their list, mute it or hide it. The settings belong to one person and one room, are shared by all of that person's
//! devices, and change nothing for anyone else. Announced by `request::FEATURE_ROOM_SETTINGS`.
//!
//! Wire (integers big-endian; `str` is a `u16` byte length then UTF-8):
//! - request `SetRoomSetting` (`request::SET_ROOM_SETTING`, tag 41): `str room | u8 setting (1 pinned, 2 muted, 3 hidden) |
//!   u8 on (0 or 1)`, answered `Ok { cursor }` with the person's settings revision for that room afterwards. A request
//!   that changes nothing keeps the revision.
//! - request `ListRoomSettings` (`request::LIST_ROOM_SETTINGS`, tag 42): no fields, answered `Ok { cursor: n }` and then one
//!   settings frame: `u8 tag (141) | u32 id | u16 n | n × (str room | u64 revision | u8 flags)`, rows strictly ordered
//!   by room, `n` at most `request::MAX_ROOMS`: the same rooms `ListRooms` lists.
//! - push `RoomSettings` (`push::ROOM_SETTINGS`, tag 83): `str room | u64 cursor | u64 revision | u8 flags`, after
//!   every successful Sync, including an equal head and a history gap. Its cursor is the room head and advances no
//!   timeline; clients keep the highest revision.
//!
//! Flags: bit 0 pinned, bit 1 muted, bit 2 hidden; any other bit is refused (`FieldLength`).
//!
//! A hidden room is still a real membership: it stays in `ListRooms`, search still finds its messages and a new
//! message in it does not unhide it. Only the person's clients leave it out of their room list.

use crate::message::{CodecError, MAX_NAME};
use crate::request::MAX_ROOMS;

/// The first byte of a settings frame.
pub const ROOM_SETTINGS_TAG: u8 = 141;

const PINNED: u8 = 1;
const MUTED: u8 = 2;
const HIDDEN: u8 = 4;

/// One personal setting of a room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomSetting {
    /// Shown at the top of the person's room list.
    Pinned,
    /// No notifications and no part in the person's unread total.
    Muted,
    /// Left out of the person's room list; still a membership.
    Hidden,
}

impl RoomSetting {
    /// The setting's wire code (1 to 3).
    pub fn code(self) -> u8 {
        match self {
            Self::Pinned => 1,
            Self::Muted => 2,
            Self::Hidden => 3,
        }
    }

    /// The setting for a wire code; `None` for any other value.
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Pinned),
            2 => Some(Self::Muted),
            3 => Some(Self::Hidden),
            _ => None,
        }
    }
}

/// One person's settings for one room. The default is none set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoomSettings {
    pub pinned: bool,
    pub muted: bool,
    pub hidden: bool,
}

impl RoomSettings {
    /// Whether `setting` is on.
    pub fn get(self, setting: RoomSetting) -> bool {
        match setting {
            RoomSetting::Pinned => self.pinned,
            RoomSetting::Muted => self.muted,
            RoomSetting::Hidden => self.hidden,
        }
    }

    /// The same settings with `setting` turned on or off.
    pub fn with(mut self, setting: RoomSetting, on: bool) -> Self {
        match setting {
            RoomSetting::Pinned => self.pinned = on,
            RoomSetting::Muted => self.muted = on,
            RoomSetting::Hidden => self.hidden = on,
        }
        self
    }

    /// The flags byte.
    pub fn flags(self) -> u8 {
        (if self.pinned { PINNED } else { 0 }) | (if self.muted { MUTED } else { 0 }) | (if self.hidden { HIDDEN } else { 0 })
    }

    /// The settings a flags byte holds; `FieldLength` when an unknown bit is set.
    pub fn from_flags(flags: u8) -> Result<Self, CodecError> {
        if flags & !(PINNED | MUTED | HIDDEN) != 0 {
            return Err(CodecError::FieldLength);
        }
        Ok(Self { pinned: flags & PINNED != 0, muted: flags & MUTED != 0, hidden: flags & HIDDEN != 0 })
    }
}

/// One row of a settings frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedRoomSettings {
    pub room: String,
    /// The person's settings revision for the room; zero when nothing was ever set.
    pub revision: u64,
    pub settings: RoomSettings,
}

/// Encode the settings frame answering `ListRoomSettings` request `id`. `FieldLength` for more than `MAX_ROOMS`
/// rows or a room outside 1 to `MAX_NAME` bytes, `BadKind(ROOM_SETTINGS_TAG)` for rows not strictly ordered by room.
pub fn encode_list(id: u32, rows: &[ListedRoomSettings]) -> Result<Vec<u8>, CodecError> {
    if rows.len() > MAX_ROOMS {
        return Err(CodecError::FieldLength);
    }
    check_order(rows)?;
    let mut out = vec![ROOM_SETTINGS_TAG];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(rows.len() as u16).to_be_bytes());
    for row in rows {
        let room = row.room.as_bytes();
        if room.is_empty() || room.len() > MAX_NAME {
            return Err(CodecError::FieldLength);
        }
        out.extend_from_slice(&(room.len() as u16).to_be_bytes());
        out.extend_from_slice(room);
        out.extend_from_slice(&row.revision.to_be_bytes());
        out.push(row.settings.flags());
    }
    Ok(out)
}

/// Decode exactly one settings frame: its request id and rows. Errors in the order the bytes are read; rows out of
/// order are `BadKind(ROOM_SETTINGS_TAG)`, so a client never applies a repeated room twice.
pub fn decode_list(bytes: &[u8]) -> Result<(u32, Vec<ListedRoomSettings>), CodecError> {
    let Some(&tag) = bytes.first() else {
        return Err(CodecError::Truncated);
    };
    if tag != ROOM_SETTINGS_TAG {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos = 1;
    let id = u32::from_be_bytes(take::<4>(bytes, &mut pos)?);
    let count = u16::from_be_bytes(take::<2>(bytes, &mut pos)?) as usize;
    if count > MAX_ROOMS {
        return Err(CodecError::FieldLength);
    }
    let mut rows = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u16::from_be_bytes(take::<2>(bytes, &mut pos)?) as usize;
        if len == 0 || len > MAX_NAME {
            return Err(CodecError::FieldLength);
        }
        let end = pos.checked_add(len).filter(|end| *end <= bytes.len()).ok_or(CodecError::Truncated)?;
        let room = std::str::from_utf8(&bytes[pos..end]).map_err(|_| CodecError::BadUtf8)?.to_owned();
        pos = end;
        let revision = u64::from_be_bytes(take::<8>(bytes, &mut pos)?);
        let [flags] = take::<1>(bytes, &mut pos)?;
        rows.push(ListedRoomSettings { room, revision, settings: RoomSettings::from_flags(flags)? });
    }
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    check_order(&rows)?;
    Ok((id, rows))
}

fn check_order(rows: &[ListedRoomSettings]) -> Result<(), CodecError> {
    if rows.windows(2).any(|pair| pair[0].room >= pair[1].room) {
        return Err(CodecError::BadKind(ROOM_SETTINGS_TAG));
    }
    Ok(())
}

fn take<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N], CodecError> {
    let end = pos.checked_add(N).filter(|end| *end <= bytes.len()).ok_or(CodecError::Truncated)?;
    let mut array = [0u8; N];
    array.copy_from_slice(&bytes[*pos..end]);
    *pos = end;
    Ok(array)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(room: &str, revision: u64, flags: u8) -> ListedRoomSettings {
        ListedRoomSettings { room: room.into(), revision, settings: RoomSettings::from_flags(flags).unwrap_or_default() }
    }

    #[test]
    fn every_combination_survives_the_flags_byte_and_unknown_bits_are_refused() {
        for flags in 0..8u8 {
            assert_eq!(RoomSettings::from_flags(flags).map(RoomSettings::flags), Ok(flags));
        }
        for flags in [8u8, 16, 128, 255] {
            assert_eq!(RoomSettings::from_flags(flags), Err(CodecError::FieldLength));
        }
        for setting in [RoomSetting::Pinned, RoomSetting::Muted, RoomSetting::Hidden] {
            assert_eq!(RoomSetting::from_code(setting.code()), Some(setting));
            let on = RoomSettings::default().with(setting, true);
            assert!(on.get(setting));
            assert!(!on.with(setting, false).get(setting));
        }
        assert_eq!(RoomSetting::from_code(0), None);
        assert_eq!(RoomSetting::from_code(4), None);
    }

    #[test]
    fn the_list_frame_round_trips_and_refuses_cut_extra_unordered_or_repeated_rows() -> Result<(), CodecError> {
        let rows = vec![row("alpha", 0, 0), row("beta", 7, 5), row("gamma", u64::MAX, 7)];
        let bytes = encode_list(9, &rows)?;
        assert_eq!(bytes[0], ROOM_SETTINGS_TAG);
        assert_eq!(decode_list(&bytes)?, (9, rows.clone()));
        for end in 0..bytes.len() {
            assert!(decode_list(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode_list(&trailing), Err(CodecError::TrailingBytes));
        let mut bad_flags = bytes.clone();
        let last = bad_flags.len() - 1;
        bad_flags[last] = 8;
        assert_eq!(decode_list(&bad_flags), Err(CodecError::FieldLength));
        let repeated = vec![row("alpha", 1, 0), row("alpha", 2, 1)];
        assert!(encode_list(1, &repeated).is_err());
        let unordered = vec![rows[1].clone(), rows[0].clone()];
        assert!(encode_list(1, &unordered).is_err());
        assert!(encode_list(1, &[row("", 0, 0)]).is_err());
        assert_eq!(decode_list(&encode_list(3, &[])?)?, (3, Vec::new()));
        Ok(())
    }
}
