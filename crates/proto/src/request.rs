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
//! - tag 8 `ListRooms`: no fields (task T233; tag 7 is unassigned)
//! - tag 9 `Search`: `str query` (1 to `MAX_QUERY` bytes; task T320b)
//! - tag 10 `UploadBegin`: `str room | str name (1 to MAX_FILE_NAME) | u64 size | 32 SHA-256` (task T330b)
//! - tag 11 `UploadChunk`: `16 upload id | u64 offset | u32 length | bytes (1 to MAX_CHUNK)`
//! - tag 12 `UploadFinish`: `16 upload id`
//! - tag 16 `Reply` (task T340a): `str room | u64 parent | str text (0 to MAX_BODY)`, answered as `Post`; announced by
//!   `FEATURE_THREADS`
//! - tag 15 `PostFiles` (task T330c): `str room | str text (0 to MAX_BODY) | u8 count (1 to 10) | count × 16 file id`
//! - tag 14 `Download`: `16 file id | u64 offset | u32 length (1 to MAX_CHUNK)` (task T330d; tag 13 is unassigned)
//! - tags 18 to 21 (task T360a1, docs/CALLS.md), announced by `FEATURE_CALLS`, each answered `Ok { cursor }` with the
//!   call's id: 18 `CallStart`: `str room | u8 video (0 or 1)` (joins the room's open call if it has one); 19
//!   `CallJoin`, 20 `CallHeartbeat` and 21 `CallLeave`: `str room | u64 call`
//! - tags 22 and 23, call keys (task T360d2), answered `Ok { cursor }` with the call's id: 22 `CallKey`: `str room | u64
//!   call | 32 X25519 public key`, the sender's device's key for the call; 23 `CallSeal`: `str room | u64 call | str to
//!   | u64 kid | u16 length | 1 to MAX_SEALED bytes`, a sender key sealed to one participant (`crewcraft_sframe::seal`)
//! - tag 24 `ListFiles` (task T331a): no fields; announced by `FEATURE_FILE_LIST`. Answered `Ok { cursor: n }`, then
//!   by one files frame (`encode_files`): `u8 tag (135) | u32 id | u16 n | n × (16 file id | str room | u64 message
//!   cursor | str uploader (0 to MAX_AUTHOR) | str name (1 to MAX_FILE_NAME) | u64 size | u8 has image size | [u32
//!   width | u32 height])`, n at most `MAX_LISTED_FILES`
//! - tag 25 `StorageUse` (task T332a): no fields; behind `FEATURE_FILES`. Answered `Ok { cursor }` with the bytes the
//!   person's files take, then by an id frame whose 16 bytes are that number and the person's quota, each a big-endian
//!   u64 (`storage_of`)
//! - tag 17 `React` (task T341a): `str room | u64 target | u8 reaction (1 to push::REACTIONS.len()) | u8 on (0 or 1)`,
//!   answered `Ok { cursor }` of the reaction's event; announced by `FEATURE_REACTIONS`
//! - tags 26 to 28 (task T343), announced by `FEATURE_PINS_SAVED`: 26 `Pin` and 27 `SaveMessage` each carry
//!   `str room | u64 target | u8 on (0 or 1)`. Pin replaces the room's pin, or clears only the matching target, and
//!   answers with its room event cursor. SaveMessage changes a personal reference and answers `Ok { cursor: 0 }`.
//!   28 `ListSaved` carries `str after_room (0 to MAX_NAME) | u64 after_cursor`; empty room and zero start the list.
//!   Its `Ok` counts one saved page, followed by `u8 tag (136) | u32 id | u8 more | u8 n | n × (str room | u64 cursor |
//!   str author | str html | u8 edited)`. Rows contain current full HTML and are strictly ordered by room and cursor;
//!   at most `MAX_SAVED_PAGE` rows fit a frame. Continue after the last row while `more` is true. Booleans are 0 or 1.
//! - tag 29 `MarkUnread` (task T344), announced by `FEATURE_READ_STATE`: `str room | u64 target`. Zero chooses the
//!   newest live message by someone else. `Ok.cursor` is the resulting personal read position, not the room head.
//! - tag 30 `Current` (T345), announced by `FEATURE_GAP_REPLAY`: `str room`. `Ok.cursor` is the captured event head,
//!   followed by bounded `current::CurrentPage` frames until their explicit last flag. See `current` for the codec.
//! - tag 43 `Continue` (task T352), announced by `FEATURE_CONTINUE`: `str archive`, an archive room the signed-in
//!   person can read. Answered `Ok { cursor: 0 }`, then by one continued frame (`encode_continued`): `u8 tag (142) |
//!   u32 id | str room`, the room the conversation continues in (docs/REQUIREMENTS.md "Continuing a conversation").
//!   Asking again answers the same room.
//! - tags 41 `SetRoomSetting` and 42 `ListRoomSettings` (task T346), announced by `FEATURE_ROOM_SETTINGS`: a person's
//!   own pin, mute and hide settings for a room. See `room_settings` for their fields and the settings frame (141).
//!   Tags 32 to 40 belong to the enrollment and sign-in openings (`bootstrap`, `signin`) and are never chat requests.
//!
//! - tags 44 to 47, meetings (task T370a, docs/MEETINGS.md), announced by `FEATURE_MEETINGS`: 44 `MeetingSave`: `str
//!   room | u64 meeting (0 makes a new one) | u64 version (0 exactly when meeting is 0) | u64 start_ms | u16 duration
//!   minutes | str title (1 to meeting::MAX_TITLE_BYTES) | str agenda (0 to MAX_BODY)`, answered `Ok { cursor }` with
//!   the meeting's id and then a meetings frame (`meeting::encode_meetings`) holding the saved meeting; 45
//!   `MeetingCancel`: `str room | u64 meeting | u64 version`, answered `Ok { cursor }` with the new version; 46
//!   `MeetingList`: `u64 from_ms | u64 to_ms`, answered `Ok { cursor: n }` and a meetings frame of the n meetings in
//!   the person's rooms that overlap the window; 47 `MeetingJoin`: `u64 meeting`, answered as `CallStart` is (the
//!   call's id, and with `FEATURE_MEDIA` the media frame)
//!
//! A response is `u8 tag | u32 id | fields`, where `id` repeats the request's:
//! - tag 128 `Ok`: `u64 cursor`
//! - tag 129 `Error`: `u16 code | str detail`
//!
//! `ListRooms` is answered `Ok { cursor: n }`, and then, as `Sync`'s events follow its answer, by one room-list frame
//! (`encode_rooms`): `u8 tag (131) | u32 id | u16 n | n × str room`, where `id` repeats the request's and `n` is 0 to
//! `MAX_ROOMS`. Tag 130 is unassigned.
//!
//! `Search` is answered `Ok { cursor: n }`, and then by one hits frame (`encode_hits`): `u8 tag (132) | u32 id | u16 n |
//! n × (str room | u64 cursor | str author | str snippet)`, where `n` is 0 to `MAX_HITS`, newest first: the messages the
//! signed-in person can read whose words begin with every word of the query. `cursor` is the message's own (the key for
//! opening it), `author` 0 to `MAX_AUTHOR` bytes (empty when the server no longer knows it), `snippet` 0 to
//! `MAX_SNIPPET` bytes of the message's current plain text.
//!
//! `UploadBegin` and `UploadFinish` are answered `Ok { cursor: 0 }`, and then by one id frame (`encode_id`): `u8 tag
//! (133) | u32 id | 16 value`, the new upload's id or the finished file's id. `UploadChunk` is answered `Ok` with the
//! number of bytes the upload has received so far. All three are announced by `FEATURE_FILES` (docs/FILES.md).
//!
//! `Download` is answered `Ok { cursor: n }` and then by one bytes frame (`encode_bytes`): `u8 tag (134) | u32 id |
//! u32 n | n bytes`, the file's bytes from `offset`, at most `length` (fewer at the end of the file, none past it).
//!
//! With `FEATURE_MEDIA` (task T360b2, docs/CALLS.md "Admission"), a successful `CallStart` or `CallJoin` is followed by
//! one media frame (`encode_media`): `u8 tag (137) | u32 id | str media server address (1 to MAX_MEDIA_ADDRESS) | u16 n
//! | n bytes`, the media credential (`crewcraft-media-auth`, 1 to `MAX_CREDENTIAL` bytes) for the signed-in device to
//! join that call on that media server. A server with no media server configured does not announce the bit.
//!
//! Also with `FEATURE_MEDIA`, tag 31 `CallOffer` (task T360b6): `str room | u64 call | u16 n | n bytes credential (1 to
//! MAX_CREDENTIAL) | u32 m | m bytes WebRTC offer (SDP, UTF-8, 1 to MAX_SDP)`, from someone in the call: the server relays
//! it to the media server and answers `Ok { cursor }` with the call's id, followed by one answer frame (`encode_answer`):
//! `u8 tag (140) | u32 id | u32 m | m bytes SDP answer`; or an `Error` when the media server refused or cannot be reached.
//!
//! `room` is 1 to `message::MAX_NAME` bytes, `text` 0 to `message::MAX_BODY` bytes, `detail` 0 to `MAX_DETAIL` bytes.
//!
//! `ListRooms` is an addition to protocol version 1, announced by the handshake feature bit `FEATURE_LIST_ROOMS`. A
//! client sends it only when the server's `Welcome` carries that bit: an older server does not know the tag and
//! would close the connection. `Search` is announced the same way by `FEATURE_SEARCH`.

use crate::message::{CodecError, MAX_BODY, MAX_NAME};

pub const MAX_DETAIL: usize = 256;
/// The most rooms one room-list frame carries.
pub const MAX_ROOMS: usize = 512;
/// The handshake feature bit (`handshake::Hello::features`) for `ListRooms` and its room-list frame.
pub const FEATURE_LIST_ROOMS: u32 = 1;
/// The first byte of a room-list frame.
pub const ROOMS_TAG: u8 = 131;
/// The handshake feature bit for `Search` and its hits frame (task T320b).
pub const FEATURE_SEARCH: u32 = 2;
/// The first byte of a hits frame.
pub const HITS_TAG: u8 = 132;
/// The longest search query, in bytes.
pub const MAX_QUERY: usize = 200;
/// The most hits one hits frame carries.
pub const MAX_HITS: usize = 100;
/// The handshake feature bit for uploads (task T330b).
pub const FEATURE_FILES: u32 = 4;
/// The handshake feature bit for threads: `Reply` and the `Threaded` push (task T340a).
pub const FEATURE_THREADS: u32 = 8;
/// The handshake feature bit for reactions: `React` and the `Reacted` push (task T341a).
pub const FEATURE_REACTIONS: u32 = 16;
/// The handshake feature bit for archive rooms: the `Archived` and `Sent` pushes (task T350d1).
pub const FEATURE_ARCHIVE: u32 = 32;
/// The handshake feature bit for calls: the call requests and the `CallLine` and `CallState` pushes (task T360a1).
pub const FEATURE_CALLS: u32 = 64;
/// The handshake feature bit for the file list: `ListFiles` and its files frame (task T331a).
pub const FEATURE_FILE_LIST: u32 = 128;
/// The handshake feature bit for pin snapshots and personal saved messages (task T343).
pub const FEATURE_PINS_SAVED: u32 = 256;
/// Authoritative personal read positions and the mark-as-unread request (task T344).
pub const FEATURE_READ_STATE: u32 = 1024;
/// Explicit event gaps and bounded, atomic current-message recovery (T345).
pub const FEATURE_GAP_REPLAY: u32 = 2048;
/// Continuing an archived conversation: `Continue`, its continued frame and the `Continued` push (task T352).
pub const FEATURE_CONTINUE: u32 = 8192;
/// The first byte of a continued frame (task T352).
pub const CONTINUED_TAG: u8 = 142;
/// Personal room settings: `SetRoomSetting`, `ListRoomSettings` and the `RoomSettings` push (task T346).
pub const FEATURE_ROOM_SETTINGS: u32 = 4096;
/// Meetings and the calendar: the meeting requests, the meetings frame and the `MeetingLine` push (task T370a).
pub const FEATURE_MEETINGS: u32 = 16384;
/// The first byte of a saved-message page.
pub const SAVED_TAG: u8 = 136;
/// Sixteen full rendered bodies, including their metadata, fit inside `frame::MAX_FRAME`.
pub const MAX_SAVED_PAGE: usize = 16;
/// The first byte of a files frame (task T331a).
pub const FILES_TAG: u8 = 135;
/// The most files one files frame lists.
pub const MAX_LISTED_FILES: usize = 500;
/// The first byte of an id frame.
pub const ID_TAG: u8 = 133;
/// The first byte of a bytes frame (task T330d).
pub const BYTES_TAG: u8 = 134;
/// The handshake feature bit for media credentials: the media frame after `CallStart` and `CallJoin` (task T360b2).
pub const FEATURE_MEDIA: u32 = 512;
/// The first byte of a media frame (task T360b2).
pub const MEDIA_TAG: u8 = 137;
/// The longest media server address in a media frame, in bytes.
pub const MAX_MEDIA_ADDRESS: usize = 255;
/// The first byte of an answer frame (task T360b6).
pub const ANSWER_TAG: u8 = 140;
/// The longest WebRTC offer or answer (SDP) a `CallOffer` or answer frame carries, in bytes.
pub const MAX_SDP: usize = 64 * 1024;
/// The longest media credential in a media frame, in bytes (a credential with three names of the longest is 1,071).
pub const MAX_CREDENTIAL: usize = 1200;
/// The longest file name, in bytes.
pub const MAX_FILE_NAME: usize = 255;
/// The most bytes one upload chunk carries.
pub const MAX_CHUNK: usize = 256 * 1024;
/// The longest author in a hit, in bytes (an email address).
pub const MAX_AUTHOR: usize = 320;
/// The longest snippet in a hit, in bytes.
pub const MAX_SNIPPET: usize = 400;

const LIST_ROOMS: u8 = 8;
const SEARCH: u8 = 9;
const UPLOAD_BEGIN: u8 = 10;
const UPLOAD_CHUNK: u8 = 11;
const UPLOAD_FINISH: u8 = 12;
const DOWNLOAD: u8 = 14;
const POST_FILES: u8 = 15;
const REPLY: u8 = 16;
const REACT: u8 = 17;
const CALL_START: u8 = 18;
const CALL_JOIN: u8 = 19;
const CALL_HEARTBEAT: u8 = 20;
const CALL_LEAVE: u8 = 21;
const CALL_KEY: u8 = 22;
const CALL_SEAL: u8 = 23;
const LIST_FILES: u8 = 24;
const STORAGE_USE: u8 = 25;
const PIN: u8 = 26;
const SAVE_MESSAGE: u8 = 27;
const LIST_SAVED: u8 = 28;
const MARK_UNREAD: u8 = 29;
const CURRENT: u8 = 30;
const CALL_OFFER: u8 = 31;
const CONTINUE: u8 = 43;
/// `SetRoomSetting` (task T346).
pub const SET_ROOM_SETTING: u8 = 41;
/// `ListRoomSettings` (task T346).
pub const LIST_ROOM_SETTINGS: u8 = 42;
const MEETING_SAVE: u8 = 44;
const MEETING_CANCEL: u8 = 45;
const MEETING_LIST: u8 = 46;
const MEETING_JOIN: u8 = 47;
/// The largest sealed sender key a `CallSeal` carries.
pub const MAX_SEALED: usize = 256;
/// The most files one `PostFiles` attaches (task T330c).
pub const MAX_POST_FILES: usize = 10;

/// A request. `ListRooms` asks for the rooms the signed-in person is a member of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Post {
        room: String,
        text: String,
    },
    Edit {
        room: String,
        target: u64,
        text: String,
    },
    Delete {
        room: String,
        target: u64,
    },
    Sync {
        room: String,
        cursor: u64,
    },
    MarkRead {
        room: String,
        cursor: u64,
    },
    /// Set this person's read position just before the target, or newest live other-author message for target zero.
    MarkUnread {
        room: String,
        target: u64,
    },
    /// The newest bounded current-message window, independent of the retained event tail (T345).
    Current {
        room: String,
    },
    /// Turn one of the asking person's own settings for a room on or off (task T346).
    SetRoomSetting {
        room: String,
        setting: crate::room_settings::RoomSetting,
        on: bool,
    },
    /// The asking person's settings for every room `ListRooms` lists (task T346).
    ListRoomSettings,
    Ping,
    ListRooms,
    /// Messages the signed-in person can read, by the words they begin with (task T320b).
    Search {
        query: String,
    },
    /// Start uploading a file of `size` bytes whose SHA-256 is `sha256` to `room` (task T330b).
    UploadBegin {
        room: String,
        name: String,
        size: u64,
        sha256: [u8; 32],
    },
    /// Part of an upload, at `offset`.
    UploadChunk {
        upload: [u8; 16],
        offset: u64,
        bytes: Vec<u8>,
    },
    /// Finish an upload: the file is recorded once its bytes check out.
    UploadFinish {
        upload: [u8; 16],
    },
    /// Post `text` with `files`, the poster's own unattached uploads in `room` (task T330c). `text` may be empty.
    PostFiles {
        room: String,
        text: String,
        files: Vec<[u8; 16]>,
    },
    /// Reply to the top-level message at `parent` in `room`, in its thread (task T340a).
    Reply {
        room: String,
        parent: u64,
        text: String,
    },
    /// Add (`on`) or take back the signed-in person's `reaction` (a code, see `push::REACTIONS`) on the message at
    /// `target` in `room` (task T341a).
    React {
        room: String,
        target: u64,
        reaction: u8,
        on: bool,
    },
    /// Start a call in `room`, or join its open one (task T360a1).
    CallStart {
        room: String,
        video: bool,
    },
    /// Join the open call `call` of `room`.
    CallJoin {
        room: String,
        call: u64,
    },
    /// Say "still here" in call `call` of `room` (docs/CALLS.md liveness).
    CallHeartbeat {
        room: String,
        call: u64,
    },
    /// Leave call `call` of `room`.
    CallLeave {
        room: String,
        call: u64,
    },
    /// This device's X25519 public key for call `call` of `room`, for others to seal their keys to (task T360d2).
    CallKey {
        room: String,
        call: u64,
        public: [u8; 32],
    },
    /// The sender's key `kid` for call `call`, sealed to participant `to` (task T360d2).
    CallSeal {
        room: String,
        call: u64,
        to: String,
        kid: u64,
        sealed: Vec<u8>,
    },
    /// The files on messages in the signed-in person's rooms (task T331a).
    ListFiles,
    /// How much storage the signed-in person's files take, and their quota (task T332a).
    StorageUse,
    /// Replace the room's pin, or clear it only when it still names `target` (task T343).
    Pin {
        room: String,
        target: u64,
        on: bool,
    },
    /// Add or remove a personal bookmark. It changes no room timeline (task T343).
    SaveMessage {
        room: String,
        target: u64,
        on: bool,
    },
    /// The next saved-message page after this room/cursor pair; empty room and zero start a list (task T343).
    ListSaved {
        after_room: String,
        after_cursor: u64,
    },
    /// Up to `length` bytes of file `file` from `offset` (task T330d).
    Download {
        file: [u8; 16],
        offset: u64,
        length: u32,
    },
    /// Continue the archive room `archive` as an active conversation (task T352).
    Continue {
        archive: String,
    },
    /// This device's WebRTC `offer` for call `call` of `room`, with the media `credential` it was given, for the
    /// media server (task T360b6).
    CallOffer {
        room: String,
        call: u64,
        credential: Vec<u8>,
        offer: String,
    },
    /// Schedule a meeting in `room` (`meeting` and `version` 0), or edit meeting `meeting` last seen at `version`
    /// (task T370a). `start_ms` is UTC; `duration` is in minutes.
    MeetingSave {
        room: String,
        meeting: u64,
        version: u64,
        start_ms: u64,
        duration: u16,
        title: String,
        agenda: String,
    },
    /// Cancel meeting `meeting` of `room`, last seen at `version` (task T370a).
    MeetingCancel {
        room: String,
        meeting: u64,
        version: u64,
    },
    /// The meetings in the signed-in person's rooms that overlap `from_ms` to `to_ms`, UTC (task T370a).
    MeetingList {
        from_ms: u64,
        to_ms: u64,
    },
    /// Join meeting `meeting`'s call: its room's open call, or a new one (task T370a).
    MeetingJoin {
        meeting: u64,
    },
}

/// One message a search found (task T320b).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    pub room: String,
    /// The message's own cursor.
    pub cursor: u64,
    pub author: String,
    /// The start of the message's current plain text.
    pub snippet: String,
}

/// A bookmark resolved against its message's current state, never a copied historical body (task T343).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedMessage {
    pub room: String,
    pub cursor: u64,
    pub author: String,
    pub html: String,
    pub edited: bool,
}

/// One page, in ascending `(room, cursor)` order. Continue after its final message when `more` is true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedPage {
    pub messages: Vec<SavedMessage>,
    pub more: bool,
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

fn read_array<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N], CodecError> {
    let end = pos.checked_add(N).filter(|end| *end <= bytes.len()).ok_or(CodecError::Truncated)?;
    let mut array = [0u8; N];
    array.copy_from_slice(&bytes[*pos..end]);
    *pos = end;
    Ok(array)
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
        Request::MarkUnread { room, target } => {
            out.push(MARK_UNREAD);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&target.to_be_bytes());
        }
        Request::Current { room } => {
            out.push(CURRENT);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
        }
        Request::Continue { archive } => {
            out.push(CONTINUE);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, archive, 1, MAX_NAME)?;
        }
        Request::SetRoomSetting { room, setting, on } => {
            out.push(SET_ROOM_SETTING);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.push(setting.code());
            out.push(u8::from(*on));
        }
        Request::ListRoomSettings => {
            out.push(LIST_ROOM_SETTINGS);
            out.extend_from_slice(&id.to_be_bytes());
        }
        Request::Ping => {
            out.push(6);
            out.extend_from_slice(&id.to_be_bytes());
        }
        Request::ListRooms => {
            out.push(LIST_ROOMS);
            out.extend_from_slice(&id.to_be_bytes());
        }
        Request::Search { query } => {
            out.push(SEARCH);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, query, 1, MAX_QUERY)?;
        }
        Request::UploadBegin { room, name, size, sha256 } => {
            out.push(UPLOAD_BEGIN);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            write_str(&mut out, name, 1, MAX_FILE_NAME)?;
            out.extend_from_slice(&size.to_be_bytes());
            out.extend_from_slice(sha256);
        }
        Request::UploadChunk { upload, offset, bytes } => {
            if bytes.is_empty() || bytes.len() > MAX_CHUNK {
                return Err(CodecError::FieldLength);
            }
            out.push(UPLOAD_CHUNK);
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(upload);
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        Request::UploadFinish { upload } => {
            out.push(UPLOAD_FINISH);
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(upload);
        }
        Request::PostFiles { room, text, files } => {
            if files.is_empty() || files.len() > MAX_POST_FILES {
                return Err(CodecError::FieldLength);
            }
            out.push(POST_FILES);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            write_str(&mut out, text, 0, MAX_BODY)?;
            out.push(files.len() as u8);
            for file in files {
                out.extend_from_slice(file);
            }
        }
        Request::Reply { room, parent, text } => {
            out.push(REPLY);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&parent.to_be_bytes());
            write_str(&mut out, text, 0, MAX_BODY)?;
        }
        Request::React { room, target, reaction, on } => {
            if crate::push::reaction_name(*reaction).is_none() {
                return Err(CodecError::BadKind(*reaction));
            }
            out.push(REACT);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&target.to_be_bytes());
            out.push(*reaction);
            out.push(u8::from(*on));
        }
        Request::Pin { room, target, on } | Request::SaveMessage { room, target, on } => {
            out.push(if matches!(request, Request::Pin { .. }) { PIN } else { SAVE_MESSAGE });
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&target.to_be_bytes());
            out.push(u8::from(*on));
        }
        Request::ListSaved { after_room, after_cursor } => {
            if after_room.is_empty() != (*after_cursor == 0) {
                return Err(CodecError::FieldLength);
            }
            out.push(LIST_SAVED);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, after_room, 0, MAX_NAME)?;
            out.extend_from_slice(&after_cursor.to_be_bytes());
        }
        Request::CallKey { room, call, public } => {
            out.push(CALL_KEY);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&call.to_be_bytes());
            out.extend_from_slice(public);
        }
        Request::CallOffer { room, call, credential, offer } => {
            if credential.is_empty() || credential.len() > MAX_CREDENTIAL || offer.is_empty() || offer.len() > MAX_SDP {
                return Err(CodecError::FieldLength);
            }
            out.push(CALL_OFFER);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&call.to_be_bytes());
            out.extend_from_slice(&(credential.len() as u16).to_be_bytes());
            out.extend_from_slice(credential);
            out.extend_from_slice(&(offer.len() as u32).to_be_bytes());
            out.extend_from_slice(offer.as_bytes());
        }
        Request::CallSeal { room, call, to, kid, sealed } => {
            if sealed.is_empty() || sealed.len() > MAX_SEALED {
                return Err(CodecError::FieldLength);
            }
            out.push(CALL_SEAL);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&call.to_be_bytes());
            write_str(&mut out, to, 1, MAX_NAME)?;
            out.extend_from_slice(&kid.to_be_bytes());
            out.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
            out.extend_from_slice(sealed);
        }
        Request::ListFiles => {
            out.push(LIST_FILES);
            out.extend_from_slice(&id.to_be_bytes());
        }
        Request::StorageUse => {
            out.push(STORAGE_USE);
            out.extend_from_slice(&id.to_be_bytes());
        }
        Request::CallStart { room, video } => {
            out.push(CALL_START);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.push(u8::from(*video));
        }
        Request::CallJoin { room, call } | Request::CallHeartbeat { room, call } | Request::CallLeave { room, call } => {
            out.push(match request {
                Request::CallJoin { .. } => CALL_JOIN,
                Request::CallHeartbeat { .. } => CALL_HEARTBEAT,
                _ => CALL_LEAVE,
            });
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&call.to_be_bytes());
        }
        Request::MeetingSave { room, meeting, version, start_ms, duration, title, agenda } => {
            if (*meeting == 0) != (*version == 0) {
                return Err(CodecError::FieldLength);
            }
            out.push(MEETING_SAVE);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&meeting.to_be_bytes());
            out.extend_from_slice(&version.to_be_bytes());
            out.extend_from_slice(&start_ms.to_be_bytes());
            out.extend_from_slice(&duration.to_be_bytes());
            write_str(&mut out, title, 1, crate::meeting::MAX_TITLE_BYTES)?;
            write_str(&mut out, agenda, 0, MAX_BODY)?;
        }
        Request::MeetingCancel { room, meeting, version } => {
            out.push(MEETING_CANCEL);
            out.extend_from_slice(&id.to_be_bytes());
            write_str(&mut out, room, 1, MAX_NAME)?;
            out.extend_from_slice(&meeting.to_be_bytes());
            out.extend_from_slice(&version.to_be_bytes());
        }
        Request::MeetingList { from_ms, to_ms } => {
            out.push(MEETING_LIST);
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&from_ms.to_be_bytes());
            out.extend_from_slice(&to_ms.to_be_bytes());
        }
        Request::MeetingJoin { meeting } => {
            out.push(MEETING_JOIN);
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&meeting.to_be_bytes());
        }
        Request::Download { file, offset, length } => {
            if *length == 0 || *length as usize > MAX_CHUNK {
                return Err(CodecError::FieldLength);
            }
            out.push(DOWNLOAD);
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(file);
            out.extend_from_slice(&offset.to_be_bytes());
            out.extend_from_slice(&length.to_be_bytes());
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
    if !(1..=6).contains(&tag)
        && !(LIST_ROOMS..=UPLOAD_FINISH).contains(&tag)
        && !matches!(
            tag,
            DOWNLOAD
                | POST_FILES
                | REPLY
                | REACT
                | PIN
                | SAVE_MESSAGE
                | LIST_SAVED
                | MARK_UNREAD
                | CURRENT
                | CALL_OFFER
                | CONTINUE
                | SET_ROOM_SETTING
                | LIST_ROOM_SETTINGS
        )
        && !(CALL_START..=STORAGE_USE).contains(&tag)
        && !(MEETING_SAVE..=MEETING_JOIN).contains(&tag)
    {
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
        MARK_UNREAD => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let target = read_u64(bytes, &mut pos)?;
            Request::MarkUnread { room, target }
        }
        CURRENT => Request::Current { room: read_string(bytes, &mut pos, 1, MAX_NAME)? },
        CONTINUE => Request::Continue { archive: read_string(bytes, &mut pos, 1, MAX_NAME)? },
        SET_ROOM_SETTING => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let [code, on] = read_array::<2>(bytes, &mut pos)?;
            let setting = crate::room_settings::RoomSetting::from_code(code).ok_or(CodecError::BadKind(code))?;
            let on = match on {
                0 => false,
                1 => true,
                other => return Err(CodecError::BadKind(other)),
            };
            Request::SetRoomSetting { room, setting, on }
        }
        LIST_ROOM_SETTINGS => Request::ListRoomSettings,
        6 => Request::Ping,
        LIST_ROOMS => Request::ListRooms,
        SEARCH => Request::Search { query: read_string(bytes, &mut pos, 1, MAX_QUERY)? },
        UPLOAD_BEGIN => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let name = read_string(bytes, &mut pos, 1, MAX_FILE_NAME)?;
            let size = read_u64(bytes, &mut pos)?;
            let sha256 = read_array::<32>(bytes, &mut pos)?;
            Request::UploadBegin { room, name, size, sha256 }
        }
        UPLOAD_CHUNK => {
            let upload = read_array::<16>(bytes, &mut pos)?;
            let offset = read_u64(bytes, &mut pos)?;
            let length = read_u32(bytes, &mut pos)? as usize;
            if length == 0 || length > MAX_CHUNK {
                return Err(CodecError::FieldLength);
            }
            let end = pos.checked_add(length).filter(|end| *end <= bytes.len()).ok_or(CodecError::Truncated)?;
            let chunk = bytes[pos..end].to_vec();
            pos = end;
            Request::UploadChunk { upload, offset, bytes: chunk }
        }
        UPLOAD_FINISH => Request::UploadFinish { upload: read_array::<16>(bytes, &mut pos)? },
        POST_FILES => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let text = read_string(bytes, &mut pos, 0, MAX_BODY)?;
            let [count] = read_array::<1>(bytes, &mut pos)?;
            let count = usize::from(count);
            if count == 0 || count > MAX_POST_FILES {
                return Err(CodecError::FieldLength);
            }
            let mut files = Vec::with_capacity(count);
            for _ in 0..count {
                files.push(read_array::<16>(bytes, &mut pos)?);
            }
            Request::PostFiles { room, text, files }
        }
        REPLY => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let parent = read_u64(bytes, &mut pos)?;
            let text = read_string(bytes, &mut pos, 0, MAX_BODY)?;
            Request::Reply { room, parent, text }
        }
        REACT => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let target = read_u64(bytes, &mut pos)?;
            let [reaction] = read_array::<1>(bytes, &mut pos)?;
            if crate::push::reaction_name(reaction).is_none() {
                return Err(CodecError::BadKind(reaction));
            }
            let on = match read_array::<1>(bytes, &mut pos)? {
                [0] => false,
                [1] => true,
                [other] => return Err(CodecError::BadKind(other)),
            };
            Request::React { room, target, reaction, on }
        }
        PIN | SAVE_MESSAGE => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let target = read_u64(bytes, &mut pos)?;
            let on = match read_array::<1>(bytes, &mut pos)? {
                [0] => false,
                [1] => true,
                [other] => return Err(CodecError::BadKind(other)),
            };
            if tag == PIN { Request::Pin { room, target, on } } else { Request::SaveMessage { room, target, on } }
        }
        LIST_SAVED => {
            let after_room = read_string(bytes, &mut pos, 0, MAX_NAME)?;
            let after_cursor = read_u64(bytes, &mut pos)?;
            if after_room.is_empty() != (after_cursor == 0) {
                return Err(CodecError::FieldLength);
            }
            Request::ListSaved { after_room, after_cursor }
        }
        CALL_START => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let video = match read_array::<1>(bytes, &mut pos)? {
                [0] => false,
                [1] => true,
                [other] => return Err(CodecError::BadKind(other)),
            };
            Request::CallStart { room, video }
        }
        LIST_FILES => Request::ListFiles,
        STORAGE_USE => Request::StorageUse,
        CALL_KEY => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let call = read_u64(bytes, &mut pos)?;
            let public = read_array::<32>(bytes, &mut pos)?;
            Request::CallKey { room, call, public }
        }
        CALL_SEAL => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let call = read_u64(bytes, &mut pos)?;
            let to = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let kid = read_u64(bytes, &mut pos)?;
            let [high, low] = read_array::<2>(bytes, &mut pos)?;
            let len = usize::from(u16::from_be_bytes([high, low]));
            if len == 0 || len > MAX_SEALED {
                return Err(CodecError::FieldLength);
            }
            let end = pos.checked_add(len).filter(|end| *end <= bytes.len()).ok_or(CodecError::Truncated)?;
            let sealed = bytes[pos..end].to_vec();
            pos = end;
            Request::CallSeal { room, call, to, kid, sealed }
        }
        CALL_OFFER => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let call = read_u64(bytes, &mut pos)?;
            let [high, low] = read_array::<2>(bytes, &mut pos)?;
            let credential = read_counted(bytes, &mut pos, usize::from(u16::from_be_bytes([high, low])), MAX_CREDENTIAL)?;
            let length = read_u32(bytes, &mut pos)? as usize;
            let offer = String::from_utf8(read_counted(bytes, &mut pos, length, MAX_SDP)?).map_err(|_| CodecError::BadUtf8)?;
            Request::CallOffer { room, call, credential, offer }
        }
        CALL_JOIN | CALL_HEARTBEAT | CALL_LEAVE => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let call = read_u64(bytes, &mut pos)?;
            match tag {
                CALL_JOIN => Request::CallJoin { room, call },
                CALL_HEARTBEAT => Request::CallHeartbeat { room, call },
                _ => Request::CallLeave { room, call },
            }
        }
        MEETING_SAVE => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let meeting = read_u64(bytes, &mut pos)?;
            let version = read_u64(bytes, &mut pos)?;
            let start_ms = read_u64(bytes, &mut pos)?;
            let duration = u16::from_be_bytes(read_array::<2>(bytes, &mut pos)?);
            let title = read_string(bytes, &mut pos, 1, crate::meeting::MAX_TITLE_BYTES)?;
            let agenda = read_string(bytes, &mut pos, 0, MAX_BODY)?;
            if (meeting == 0) != (version == 0) {
                return Err(CodecError::FieldLength);
            }
            Request::MeetingSave { room, meeting, version, start_ms, duration, title, agenda }
        }
        MEETING_CANCEL => {
            let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
            let meeting = read_u64(bytes, &mut pos)?;
            let version = read_u64(bytes, &mut pos)?;
            Request::MeetingCancel { room, meeting, version }
        }
        MEETING_LIST => {
            let from_ms = read_u64(bytes, &mut pos)?;
            let to_ms = read_u64(bytes, &mut pos)?;
            Request::MeetingList { from_ms, to_ms }
        }
        MEETING_JOIN => Request::MeetingJoin { meeting: read_u64(bytes, &mut pos)? },
        DOWNLOAD => {
            let file = read_array::<16>(bytes, &mut pos)?;
            let offset = read_u64(bytes, &mut pos)?;
            let length = read_u32(bytes, &mut pos)?;
            if length == 0 || length as usize > MAX_CHUNK {
                return Err(CodecError::FieldLength);
            }
            Request::Download { file, offset, length }
        }
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

/// Encode the room-list frame that follows the `Ok` answering `ListRooms` request `id`. `FieldLength` if there are
/// more than `MAX_ROOMS` rooms, or a room is empty or longer than `message::MAX_NAME` bytes.
pub fn encode_rooms(id: u32, rooms: &[String]) -> Result<Vec<u8>, CodecError> {
    if rooms.len() > MAX_ROOMS {
        return Err(CodecError::FieldLength);
    }
    let mut out = vec![ROOMS_TAG];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(rooms.len() as u16).to_be_bytes());
    for room in rooms {
        write_str(&mut out, room, 1, MAX_NAME)?;
    }
    Ok(out)
}

/// Decode exactly one room-list frame: its request id and the rooms. Errors in the order the bytes are read: the tag
/// (`Truncated`, or `BadKind(tag)` for anything but `ROOMS_TAG`), the id, the count (`FieldLength` above `MAX_ROOMS`,
/// before any room is read), each room as a string field, then `TrailingBytes`.
pub fn decode_rooms(bytes: &[u8]) -> Result<(u32, Vec<String>), CodecError> {
    let Some(&tag) = bytes.first() else {
        return Err(CodecError::Truncated);
    };
    if tag != ROOMS_TAG {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos: usize = 1;
    let id = read_u32(bytes, &mut pos)?;
    if pos + 2 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let count = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;
    if count > MAX_ROOMS {
        return Err(CodecError::FieldLength);
    }
    let mut rooms = Vec::with_capacity(count);
    for _ in 0..count {
        rooms.push(read_string(bytes, &mut pos, 1, MAX_NAME)?);
    }
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, rooms))
}

/// Encode the hits frame that follows the `Ok` answering `Search` request `id` (task T320b). `FieldLength` if there are
/// more than `MAX_HITS` hits or a field is out of its range (room 1 to `message::MAX_NAME` bytes, author up to
/// `MAX_AUTHOR`, snippet up to `MAX_SNIPPET`).
pub fn encode_hits(id: u32, hits: &[SearchHit]) -> Result<Vec<u8>, CodecError> {
    if hits.len() > MAX_HITS {
        return Err(CodecError::FieldLength);
    }
    let mut out = vec![HITS_TAG];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(hits.len() as u16).to_be_bytes());
    for hit in hits {
        write_str(&mut out, &hit.room, 1, MAX_NAME)?;
        out.extend_from_slice(&hit.cursor.to_be_bytes());
        write_str(&mut out, &hit.author, 0, MAX_AUTHOR)?;
        write_str(&mut out, &hit.snippet, 0, MAX_SNIPPET)?;
    }
    Ok(out)
}

/// Decode exactly one hits frame: its request id and the hits. Errors in the order the bytes are read, as
/// `decode_rooms`: the tag (`BadKind` for anything but `HITS_TAG`), the id, the count (`FieldLength` above `MAX_HITS`),
/// each hit's fields, then `TrailingBytes`.
pub fn decode_hits(bytes: &[u8]) -> Result<(u32, Vec<SearchHit>), CodecError> {
    let Some(&tag) = bytes.first() else {
        return Err(CodecError::Truncated);
    };
    if tag != HITS_TAG {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos: usize = 1;
    let id = read_u32(bytes, &mut pos)?;
    if pos + 2 > bytes.len() {
        return Err(CodecError::Truncated);
    }
    let count = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;
    if count > MAX_HITS {
        return Err(CodecError::FieldLength);
    }
    let mut hits = Vec::with_capacity(count);
    for _ in 0..count {
        let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
        let cursor = read_u64(bytes, &mut pos)?;
        let author = read_string(bytes, &mut pos, 0, MAX_AUTHOR)?;
        let snippet = read_string(bytes, &mut pos, 0, MAX_SNIPPET)?;
        hits.push(SearchHit { room, cursor, author, snippet });
    }
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, hits))
}

/// Encode the continued frame that follows the `Ok` answering `Continue` request `id` (task T352): the room the
/// conversation continues in. `FieldLength` if `room` is empty or longer than `message::MAX_NAME` bytes.
pub fn encode_continued(id: u32, room: &str) -> Result<Vec<u8>, CodecError> {
    let mut out = vec![CONTINUED_TAG];
    out.extend_from_slice(&id.to_be_bytes());
    write_str(&mut out, room, 1, MAX_NAME)?;
    Ok(out)
}

/// Decode exactly one continued frame: its request id and the room. Errors in the order the bytes are read: the tag
/// (`BadKind` for anything but `CONTINUED_TAG`), the id, the room as a string field, then `TrailingBytes`.
pub fn decode_continued(bytes: &[u8]) -> Result<(u32, String), CodecError> {
    let Some(&tag) = bytes.first() else {
        return Err(CodecError::Truncated);
    };
    if tag != CONTINUED_TAG {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos: usize = 1;
    let id = read_u32(bytes, &mut pos)?;
    let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, room))
}

/// The 16 bytes of the id frame answering `StorageUse` (task T332a): the bytes used and the quota.
pub fn storage_frame(used: u64, quota: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&used.to_be_bytes());
    out[8..].copy_from_slice(&quota.to_be_bytes());
    out
}

/// The bytes used and the quota from the id frame answering `StorageUse` (task T332a).
pub fn storage_of(frame: &[u8; 16]) -> (u64, u64) {
    let mut used = [0u8; 8];
    let mut quota = [0u8; 8];
    used.copy_from_slice(&frame[..8]);
    quota.copy_from_slice(&frame[8..]);
    (u64::from_be_bytes(used), u64::from_be_bytes(quota))
}

/// One file the files frame lists (task T331a).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedFile {
    pub file: [u8; 16],
    pub room: String,
    /// The cursor of the message that carries it.
    pub cursor: u64,
    /// Who uploaded it (an imported file names the archive owner); may be empty.
    pub uploader: String,
    pub name: String,
    pub size: u64,
    pub image: Option<(u32, u32)>,
}

/// Encode the files frame that follows the `Ok` answering `ListFiles` request `id` (task T331a).
pub fn encode_files(id: u32, files: &[ListedFile]) -> Result<Vec<u8>, CodecError> {
    if files.len() > MAX_LISTED_FILES {
        return Err(CodecError::FieldLength);
    }
    let mut out = vec![FILES_TAG];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(files.len() as u16).to_be_bytes());
    for file in files {
        out.extend_from_slice(&file.file);
        write_str(&mut out, &file.room, 1, MAX_NAME)?;
        out.extend_from_slice(&file.cursor.to_be_bytes());
        write_str(&mut out, &file.uploader, 0, MAX_AUTHOR)?;
        write_str(&mut out, &file.name, 1, MAX_FILE_NAME)?;
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
    Ok(out)
}

/// Decode exactly one files frame: its request id and the files. Errors in the order the bytes are read, as
/// `decode_hits`.
pub fn decode_files(bytes: &[u8]) -> Result<(u32, Vec<ListedFile>), CodecError> {
    let Some(&tag) = bytes.first() else {
        return Err(CodecError::Truncated);
    };
    if tag != FILES_TAG {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos: usize = 1;
    let id = read_u32(bytes, &mut pos)?;
    let [high, low] = read_array::<2>(bytes, &mut pos)?;
    let count = usize::from(u16::from_be_bytes([high, low]));
    if count > MAX_LISTED_FILES {
        return Err(CodecError::FieldLength);
    }
    let mut files = Vec::with_capacity(count);
    for _ in 0..count {
        let file = read_array::<16>(bytes, &mut pos)?;
        let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
        let cursor = read_u64(bytes, &mut pos)?;
        let uploader = read_string(bytes, &mut pos, 0, MAX_AUTHOR)?;
        let name = read_string(bytes, &mut pos, 1, MAX_FILE_NAME)?;
        let size = read_u64(bytes, &mut pos)?;
        let image = match read_array::<1>(bytes, &mut pos)? {
            [0] => None,
            [1] => {
                let width = read_u32(bytes, &mut pos)?;
                let height = read_u32(bytes, &mut pos)?;
                Some((width, height))
            }
            [other] => return Err(CodecError::BadKind(other)),
        };
        files.push(ListedFile { file, room, cursor, uploader, name, size, image });
    }
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, files))
}

/// Encode the id frame that follows the `Ok` answering `UploadBegin` or `UploadFinish` request `id` (task T330b): the
/// new upload's id, or the finished file's.
pub fn encode_id(id: u32, value: &[u8; 16]) -> Vec<u8> {
    let mut out = vec![ID_TAG];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// Decode exactly one id frame: its request id and the value. `BadKind` for any tag but `ID_TAG`, `Truncated`, then
/// `TrailingBytes`.
pub fn decode_id(bytes: &[u8]) -> Result<(u32, [u8; 16]), CodecError> {
    let Some(&tag) = bytes.first() else {
        return Err(CodecError::Truncated);
    };
    if tag != ID_TAG {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos: usize = 1;
    let id = read_u32(bytes, &mut pos)?;
    let value = read_array::<16>(bytes, &mut pos)?;
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, value))
}

/// Encode the bytes frame that follows the `Ok` answering `Download` request `id` (task T330d). `FieldLength` for more
/// than `MAX_CHUNK` bytes.
pub fn encode_bytes(id: u32, bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    if bytes.len() > MAX_CHUNK {
        return Err(CodecError::FieldLength);
    }
    let mut out = vec![BYTES_TAG];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(out)
}

/// Decode exactly one bytes frame: its request id and the bytes. `BadKind` for any tag but `BYTES_TAG`, `FieldLength`
/// for a count over `MAX_CHUNK`, `Truncated`, then `TrailingBytes`.
pub fn decode_bytes(bytes: &[u8]) -> Result<(u32, Vec<u8>), CodecError> {
    let Some(&tag) = bytes.first() else {
        return Err(CodecError::Truncated);
    };
    if tag != BYTES_TAG {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos: usize = 1;
    let id = read_u32(bytes, &mut pos)?;
    let count = read_u32(bytes, &mut pos)? as usize;
    if count > MAX_CHUNK {
        return Err(CodecError::FieldLength);
    }
    let end = pos.checked_add(count).filter(|end| *end <= bytes.len()).ok_or(CodecError::Truncated)?;
    let data = bytes[pos..end].to_vec();
    if end != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, data))
}

/// `count` bytes (1 to `max`) at `pos`: `FieldLength` for a count out of range, `Truncated` when the bytes run out.
fn read_counted(bytes: &[u8], pos: &mut usize, count: usize, max: usize) -> Result<Vec<u8>, CodecError> {
    if count == 0 || count > max {
        return Err(CodecError::FieldLength);
    }
    let end = pos.checked_add(count).filter(|end| *end <= bytes.len()).ok_or(CodecError::Truncated)?;
    let out = bytes[*pos..end].to_vec();
    *pos = end;
    Ok(out)
}

/// Encode the answer frame that follows the `Ok` answering `CallOffer` request `id` (task T360b6): the media server's
/// SDP answer. `FieldLength` when it is empty or longer than `MAX_SDP`.
pub fn encode_answer(id: u32, answer: &str) -> Result<Vec<u8>, CodecError> {
    if answer.is_empty() || answer.len() > MAX_SDP {
        return Err(CodecError::FieldLength);
    }
    let mut out = vec![ANSWER_TAG];
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(answer.len() as u32).to_be_bytes());
    out.extend_from_slice(answer.as_bytes());
    Ok(out)
}

/// Decode exactly one answer frame: its request id and the SDP answer. `BadKind` for any tag but `ANSWER_TAG`,
/// `FieldLength`, `Truncated`, `BadUtf8`, then `TrailingBytes`.
pub fn decode_answer(bytes: &[u8]) -> Result<(u32, String), CodecError> {
    let Some(&tag) = bytes.first() else {
        return Err(CodecError::Truncated);
    };
    if tag != ANSWER_TAG {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos: usize = 1;
    let id = read_u32(bytes, &mut pos)?;
    let length = read_u32(bytes, &mut pos)? as usize;
    let answer = String::from_utf8(read_counted(bytes, &mut pos, length, MAX_SDP)?).map_err(|_| CodecError::BadUtf8)?;
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, answer))
}

/// Encode the media frame that follows the `Ok` answering `CallStart` or `CallJoin` request `id` (task T360b2): the
/// media server's `address` and the `credential`. `FieldLength` when either is empty or too long.
pub fn encode_media(id: u32, address: &str, credential: &[u8]) -> Result<Vec<u8>, CodecError> {
    if credential.is_empty() || credential.len() > MAX_CREDENTIAL {
        return Err(CodecError::FieldLength);
    }
    let mut out = vec![MEDIA_TAG];
    out.extend_from_slice(&id.to_be_bytes());
    write_str(&mut out, address, 1, MAX_MEDIA_ADDRESS)?;
    out.extend_from_slice(&(credential.len() as u16).to_be_bytes());
    out.extend_from_slice(credential);
    Ok(out)
}

/// Decode exactly one media frame: its request id, the media server's address and the credential. `BadKind` for any
/// tag but `MEDIA_TAG`, `FieldLength` for an empty or too long field, `Truncated`, then `TrailingBytes`.
pub fn decode_media(bytes: &[u8]) -> Result<(u32, String, Vec<u8>), CodecError> {
    let Some(&tag) = bytes.first() else {
        return Err(CodecError::Truncated);
    };
    if tag != MEDIA_TAG {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos: usize = 1;
    let id = read_u32(bytes, &mut pos)?;
    let address = read_string(bytes, &mut pos, 1, MAX_MEDIA_ADDRESS)?;
    let [high, low] = read_array::<2>(bytes, &mut pos)?;
    let count = usize::from(u16::from_be_bytes([high, low]));
    if count == 0 || count > MAX_CREDENTIAL {
        return Err(CodecError::FieldLength);
    }
    let end = pos.checked_add(count).filter(|end| *end <= bytes.len()).ok_or(CodecError::Truncated)?;
    let credential = bytes[pos..end].to_vec();
    if end != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, address, credential))
}

/// Encode one bounded page of current saved messages (task T343). Rows are strictly ordered so pagination advances.
pub fn encode_saved(id: u32, page: &SavedPage) -> Result<Vec<u8>, CodecError> {
    check_saved_page(page)?;
    let mut out = vec![SAVED_TAG];
    out.extend_from_slice(&id.to_be_bytes());
    out.push(u8::from(page.more));
    out.push(page.messages.len() as u8);
    for message in &page.messages {
        write_str(&mut out, &message.room, 1, MAX_NAME)?;
        out.extend_from_slice(&message.cursor.to_be_bytes());
        write_str(&mut out, &message.author, 1, MAX_AUTHOR)?;
        write_str(&mut out, &message.html, 0, crate::push::MAX_HTML)?;
        out.push(u8::from(message.edited));
    }
    if out.len() > crate::frame::MAX_FRAME {
        return Err(CodecError::FieldLength);
    }
    Ok(out)
}

/// Decode exactly one saved-message page, refusing malformed booleans, ordering, counts and trailing bytes.
pub fn decode_saved(bytes: &[u8]) -> Result<(u32, SavedPage), CodecError> {
    let Some(&tag) = bytes.first() else { return Err(CodecError::Truncated) };
    if tag != SAVED_TAG {
        return Err(CodecError::BadKind(tag));
    }
    let mut pos = 1;
    let id = read_u32(bytes, &mut pos)?;
    let more = read_bool(bytes, &mut pos)?;
    let [count] = read_array::<1>(bytes, &mut pos)?;
    let count = usize::from(count);
    if count > MAX_SAVED_PAGE || bytes.len() > crate::frame::MAX_FRAME {
        return Err(CodecError::FieldLength);
    }
    let mut messages = Vec::with_capacity(count);
    for _ in 0..count {
        let room = read_string(bytes, &mut pos, 1, MAX_NAME)?;
        let cursor = read_u64(bytes, &mut pos)?;
        let author = read_string(bytes, &mut pos, 1, MAX_AUTHOR)?;
        let html = read_string(bytes, &mut pos, 0, crate::push::MAX_HTML)?;
        let edited = read_bool(bytes, &mut pos)?;
        messages.push(SavedMessage { room, cursor, author, html, edited });
    }
    if pos != bytes.len() {
        return Err(CodecError::TrailingBytes);
    }
    let page = SavedPage { messages, more };
    check_saved_page(&page)?;
    Ok((id, page))
}

fn read_bool(bytes: &[u8], pos: &mut usize) -> Result<bool, CodecError> {
    match read_array::<1>(bytes, pos)? {
        [0] => Ok(false),
        [1] => Ok(true),
        [other] => Err(CodecError::BadKind(other)),
    }
}

fn check_saved_page(page: &SavedPage) -> Result<(), CodecError> {
    if page.messages.len() > MAX_SAVED_PAGE
        || (page.more && page.messages.is_empty())
        || page.messages.iter().any(|message| message.cursor == 0)
        || page.messages.windows(2).any(|pair| (pair[0].room.as_str(), pair[0].cursor) >= (pair[1].room.as_str(), pair[1].cursor))
    {
        return Err(CodecError::FieldLength);
    }
    Ok(())
}

#[cfg(test)]
mod continue_tests {
    use super::*;

    #[test]
    fn continue_and_its_frame_refuse_partial_trailing_and_empty_rooms() -> Result<(), CodecError> {
        let request = Request::Continue { archive: "old-team".into() };
        let bytes = encode_request(9, &request)?;
        assert_eq!(decode_request(&bytes)?, (9, request));
        let frame = encode_continued(9, "old-team-2")?;
        assert_eq!(decode_continued(&frame)?, (9, "old-team-2".to_owned()));
        for whole in [&bytes, &frame] {
            for end in 0..whole.len() {
                assert!(decode_request(&whole[..end]).is_err() && decode_continued(&whole[..end]).is_err());
            }
        }
        let mut trailing = frame;
        trailing.push(0);
        assert_eq!(decode_continued(&trailing), Err(CodecError::TrailingBytes));
        assert!(encode_request(9, &Request::Continue { archive: String::new() }).is_err());
        assert!(encode_continued(9, "").is_err());
        Ok(())
    }
}

#[cfg(test)]
mod room_settings_tests {
    use super::*;
    use crate::room_settings::RoomSetting;

    #[test]
    fn room_setting_requests_round_trip_and_refuse_unknown_settings_booleans_cuts_and_extra_bytes() -> Result<(), CodecError> {
        for setting in [RoomSetting::Pinned, RoomSetting::Muted, RoomSetting::Hidden] {
            for on in [false, true] {
                let request = Request::SetRoomSetting { room: "room".into(), setting, on };
                let bytes = encode_request(5, &request)?;
                assert_eq!(decode_request(&bytes)?, (5, request));
                for end in 0..bytes.len() {
                    assert!(decode_request(&bytes[..end]).is_err());
                }
                let mut trailing = bytes.clone();
                trailing.push(0);
                assert_eq!(decode_request(&trailing), Err(CodecError::TrailingBytes));
                let mut bad = bytes.clone();
                let last = bad.len() - 1;
                bad[last] = 2;
                assert_eq!(decode_request(&bad), Err(CodecError::BadKind(2)));
                bad[last] = u8::from(on);
                bad[last - 1] = 4;
                assert_eq!(decode_request(&bad), Err(CodecError::BadKind(4)));
            }
        }
        assert!(encode_request(5, &Request::SetRoomSetting { room: String::new(), setting: RoomSetting::Muted, on: true }).is_err());
        // The enrollment and sign-in openings keep their own tags: the chat decoder never takes one for a request.
        for tag in 32u8..=40 {
            assert_eq!(decode_request(&[tag, 0, 0, 0, 1]), Err(CodecError::BadKind(tag)));
        }
        let list = encode_request(6, &Request::ListRoomSettings)?;
        assert_eq!(decode_request(&list)?, (6, Request::ListRoomSettings));
        let mut trailing = list;
        trailing.push(0);
        assert_eq!(decode_request(&trailing), Err(CodecError::TrailingBytes));
        Ok(())
    }
}

#[cfg(test)]
mod read_state_tests {
    use super::*;

    #[test]
    fn current_request_refuses_partial_trailing_and_empty_room_fields() -> Result<(), CodecError> {
        let request = Request::Current { room: "room".into() };
        let bytes = encode_request(22, &request)?;
        assert_eq!(decode_request(&bytes)?, (22, request));
        for end in 0..bytes.len() {
            assert!(decode_request(&bytes[..end]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(decode_request(&trailing), Err(CodecError::TrailingBytes));
        assert!(encode_request(22, &Request::Current { room: String::new() }).is_err());
        Ok(())
    }

    #[test]
    fn mark_unread_accepts_default_and_full_cursor_but_rejects_partial_or_extra_fields() -> Result<(), CodecError> {
        for target in [0, 1, u64::MAX] {
            let request = Request::MarkUnread { room: "room".into(), target };
            let bytes = encode_request(17, &request)?;
            assert_eq!(bytes[0], 29);
            assert_eq!(decode_request(&bytes)?, (17, request));
            for end in 0..bytes.len() {
                assert!(decode_request(&bytes[..end]).is_err());
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert_eq!(decode_request(&trailing), Err(CodecError::TrailingBytes));
            let mut empty_room = bytes;
            empty_room[5..7].copy_from_slice(&0u16.to_be_bytes());
            assert_eq!(decode_request(&empty_room), Err(CodecError::FieldLength));
        }
        assert!(encode_request(17, &Request::MarkUnread { room: String::new(), target: 0 }).is_err());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod pins_saved_tests {
    use super::*;

    fn message(cursor: u64, html: &str) -> SavedMessage {
        SavedMessage { room: "room".into(), cursor, author: "author".into(), html: html.into(), edited: false }
    }

    #[test]
    fn pin_and_save_requests_refuse_malformed_booleans_and_continuations() {
        for (tag, request) in [
            (PIN, Request::Pin { room: "room".into(), target: 4, on: true }),
            (SAVE_MESSAGE, Request::SaveMessage { room: "room".into(), target: 4, on: false }),
        ] {
            let mut bytes = encode_request(7, &request).unwrap();
            assert_eq!(bytes[0], tag);
            assert_eq!(decode_request(&bytes).unwrap(), (7, request));
            let last = bytes.len() - 1;
            bytes[last] = 2;
            assert_eq!(decode_request(&bytes), Err(CodecError::BadKind(2)));
        }
        for (after_room, after_cursor) in [(String::new(), 0), ("room".into(), 4)] {
            let request = Request::ListSaved { after_room, after_cursor };
            assert_eq!(decode_request(&encode_request(8, &request).unwrap()).unwrap(), (8, request));
        }
        for tag in [0, 7, 13, 50, 63, 128, SAVED_TAG, 255] {
            assert_eq!(decode_request(&[tag]), Err(CodecError::BadKind(tag)));
        }
        assert!(encode_request(8, &Request::ListSaved { after_room: String::new(), after_cursor: 4 }).is_err());
        assert!(encode_request(8, &Request::ListSaved { after_room: "room".into(), after_cursor: 0 }).is_err());
        let mut bytes = encode_request(8, &Request::ListSaved { after_room: String::new(), after_cursor: 0 }).unwrap();
        let last = bytes.len() - 1;
        bytes[last] = 4;
        assert_eq!(decode_request(&bytes), Err(CodecError::FieldLength));
    }

    #[test]
    fn a_maximum_saved_page_fits_one_frame_with_full_bodies() {
        let messages = (1..=MAX_SAVED_PAGE)
            .map(|cursor| SavedMessage {
                room: "r".repeat(MAX_NAME),
                cursor: cursor as u64,
                author: "a".repeat(MAX_AUTHOR),
                html: "x".repeat(crate::push::MAX_HTML),
                edited: true,
            })
            .collect();
        let page = SavedPage { messages, more: true };
        let bytes = encode_saved(19, &page).unwrap();
        assert!(bytes.len() <= crate::frame::MAX_FRAME);
        assert!(crate::frame::encode(&bytes).is_ok());
        assert_eq!(decode_saved(&bytes).unwrap(), (19, page));
    }

    #[test]
    fn saved_pages_accept_empty_bodies_and_refuse_bad_rows_counts_and_trailing_bytes() {
        let page = SavedPage { messages: vec![message(1, "")], more: false };
        let bytes = encode_saved(2, &page).unwrap();
        assert_eq!(decode_saved(&bytes).unwrap(), (2, page));
        for end in 0..bytes.len() {
            assert!(decode_saved(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode_saved(&trailing), Err(CodecError::TrailingBytes));
        let mut bad_more = bytes.clone();
        bad_more[5] = 2;
        assert_eq!(decode_saved(&bad_more), Err(CodecError::BadKind(2)));
        let mut bad_count = bytes.clone();
        bad_count[6] = (MAX_SAVED_PAGE + 1) as u8;
        assert_eq!(decode_saved(&bad_count), Err(CodecError::FieldLength));
        let mut bad_edited = bytes.clone();
        let last = bad_edited.len() - 1;
        bad_edited[last] = 2;
        assert_eq!(decode_saved(&bad_edited), Err(CodecError::BadKind(2)));
        let mut duplicate = bytes.clone();
        duplicate[6] = 2;
        duplicate.extend_from_slice(&bytes[7..]);
        assert_eq!(decode_saved(&duplicate), Err(CodecError::FieldLength));
        assert!(encode_saved(2, &SavedPage { messages: Vec::new(), more: true }).is_err());
        assert!(encode_saved(2, &SavedPage { messages: vec![message(0, "x")], more: false }).is_err());
    }
}
