//! A signed-in chat connection, and the credentials that open one.
//!
//! Owns: `Credentials` (email, password and a current TOTP code, checked for shape and never printed),
//! `SignedInSession` (post, edit, delete, sync and the room list over one connection) and the sign-in step itself. Called by the lab
//! endpoint (`lab_client`), the server endpoint (`server_endpoint`) and the connection worker (`worker`). Calls
//! `chat_session` for the protocol.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::room_view::{GuestLobbyState, Shown};
use crewcraft_proto::guest::{GuestDecision, GuestLobby, GuestMeetingChange, GuestReply};
use crewcraft_proto::handshake::Hello;
use crewcraft_proto::message::MAX_NAME;
use crewcraft_proto::push::AttachedFile;
use crewcraft_proto::request::{
    FEATURE_ACTIVITY, FEATURE_ARCHIVE, FEATURE_CALLS, FEATURE_CONTINUE, FEATURE_FILE_LIST, FEATURE_FILES, FEATURE_GAP_REPLAY, FEATURE_LIST_ROOMS,
    FEATURE_PINS_SAVED, FEATURE_REACTIONS, FEATURE_READ_STATE, FEATURE_SEARCH, FEATURE_THREADS, MAX_CHUNK, Request, SavedMessage, SearchHit,
};
use crewcraft_proto::signin::{CODE_LEN, MAX_EMAIL_BYTES, MAX_PASSWORD_BYTES, SignIn, TOKEN_LEN};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::chat_session::{ChatError, ChatSession, Negotiation};
use crate::connect::Transport;
use crate::lab_client::LabError;

const FRAME_TIMEOUT: Duration = Duration::from_secs(3);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

type SetDeadline = fn(&mut Transport, Instant);

/// A file just uploaded (task T330e).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uploaded {
    pub file: [u8; 16],
    pub name: String,
    pub size: u64,
}

/// Why a file could not be uploaded or downloaded (task T330e): this computer's file, or the server.
#[derive(Debug)]
pub enum FileOpError {
    Local(io::ErrorKind),
    Lab(LabError),
}

/// The person's email, password and a current authenticator code, for exactly one sign-in. The password and code are
/// wiped from memory when this is dropped, and `Debug` prints none of the fields.
pub struct Credentials {
    email: String,
    password: Zeroizing<String>,
    code: Zeroizing<String>,
}

impl Credentials {
    /// `None` unless the email is 1 to 320 bytes, the password 1 to 1024 bytes, neither holds a control character,
    /// and the code is exactly six ASCII digits.
    pub fn new(email: &str, password: &str, code: &str) -> Option<Self> {
        let text_ok = |text: &str, max: usize| !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control);
        let code_ok = code.len() == CODE_LEN && code.bytes().all(|byte| byte.is_ascii_digit());
        (text_ok(email, MAX_EMAIL_BYTES) && text_ok(password, MAX_PASSWORD_BYTES) && code_ok).then(|| Self {
            email: email.to_owned(),
            password: Zeroizing::new(password.to_owned()),
            code: Zeroizing::new(code.to_owned()),
        })
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub(crate) fn sign_in(&self) -> SignIn<'_> {
        SignIn { email: &self.email, password: &self.password, code: &self.code }
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("Credentials { .. }")
    }
}

/// Whether `email` can name the person in a sign-in: 1 to 320 bytes with no control character, the rule
/// `Credentials::new` applies (used for the external sign-in, task T611h).
pub fn valid_email(email: &str) -> bool {
    !email.is_empty() && email.len() <= MAX_EMAIL_BYTES && !email.chars().any(char::is_control)
}

/// What reopens a signed-in session without a password or code (task T240): the person's email and the session token
/// the server returned. The server accepts it only from the same device, within 12 hours of the sign-in. Wiped from
/// memory when dropped; `Debug` shows neither field.
#[derive(Clone, PartialEq, Eq)]
pub struct ResumeTicket {
    email: String,
    token: Zeroizing<String>,
}

impl ResumeTicket {
    /// `None` unless the email is valid for a sign-in and the token has the form the server issues.
    pub fn new(email: &str, token: &str) -> Option<Self> {
        let email_ok = !email.is_empty() && email.len() <= MAX_EMAIL_BYTES && !email.chars().any(char::is_control);
        let token_ok = token.len() == TOKEN_LEN && token.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        (email_ok && token_ok).then(|| Self { email: email.to_owned(), token: Zeroizing::new(token.to_owned()) })
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    /// The session token: a secret, to be stored only where the device record is.
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl fmt::Debug for ResumeTicket {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("ResumeTicket { .. }")
    }
}

pub(crate) fn valid_room(room: &str) -> bool {
    !room.is_empty() && room.len() <= MAX_NAME && room.chars().all(|ch| !ch.is_control() && !ch.is_whitespace())
}

/// A meeting to schedule (`meeting` and `version` 0) or edit (task T370b). `start_ms` is UTC; `duration` is in minutes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeetingSave {
    pub room: String,
    pub meeting: u64,
    pub version: u64,
    pub start_ms: u64,
    pub duration: u16,
    pub title: String,
    pub agenda: String,
}

/// Sign in over a verified device connection and negotiate the chat protocol, all within one operation deadline. The
/// client offers `FEATURE_LIST_ROOMS`; a server that does not agree to it is still used, without the room list.
pub(crate) fn sign_in(stream: Transport, credentials: &SignIn<'_>, client: &str) -> Result<SignedInSession, LabError> {
    let hello = Hello {
        min_version: 1,
        max_version: 1,
        features: FEATURE_LIST_ROOMS
            | FEATURE_SEARCH
            | FEATURE_FILES
            | FEATURE_THREADS
            | FEATURE_REACTIONS
            | FEATURE_ARCHIVE
            | FEATURE_CALLS
            | FEATURE_FILE_LIST
            | FEATURE_PINS_SAVED
            | FEATURE_READ_STATE
            | FEATURE_GAP_REPLAY
            | FEATURE_CONTINUE
            | crewcraft_proto::request::FEATURE_ROOM_SETTINGS
            | FEATURE_ACTIVITY
            | crewcraft_proto::request::FEATURE_MEETINGS
            | crewcraft_proto::request::FEATURE_GUEST_MEETINGS,
        client: client.into(),
    };
    let settings = Settings::new(credentials.email);
    let set_deadline: SetDeadline = |stream, deadline| stream.get_mut().set_deadline(deadline);
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    let chat = ChatSession::connect(stream, set_deadline, credentials, hello, settings, FRAME_TIMEOUT, deadline).map_err(LabError::Chat)?;
    Ok(SignedInSession { chat, email: credentials.email.to_owned() })
}

/// As `sign_in`, reopening the session `ticket` names instead (task T240). A ticket the server no longer accepts is
/// `LabError::Chat(ChatError::SignInRefused)`.
pub(crate) fn resume(stream: Transport, ticket: &ResumeTicket, client: &str) -> Result<SignedInSession, LabError> {
    let hello = Hello {
        min_version: 1,
        max_version: 1,
        features: FEATURE_LIST_ROOMS
            | FEATURE_SEARCH
            | FEATURE_FILES
            | FEATURE_THREADS
            | FEATURE_REACTIONS
            | FEATURE_ARCHIVE
            | FEATURE_CALLS
            | FEATURE_FILE_LIST
            | FEATURE_PINS_SAVED
            | FEATURE_READ_STATE
            | FEATURE_GAP_REPLAY
            | FEATURE_CONTINUE
            | crewcraft_proto::request::FEATURE_ROOM_SETTINGS
            | FEATURE_ACTIVITY
            | crewcraft_proto::request::FEATURE_MEETINGS
            | crewcraft_proto::request::FEATURE_GUEST_MEETINGS,
        client: client.into(),
    };
    let settings = Settings::new(ticket.email());
    let set_deadline: SetDeadline = |stream, deadline| stream.get_mut().set_deadline(deadline);
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    let negotiation = Negotiation { hello, settings, frame_timeout: FRAME_TIMEOUT, deadline };
    let chat = ChatSession::resume(stream, set_deadline, ticket.email(), ticket.token(), negotiation).map_err(LabError::Chat)?;
    Ok(SignedInSession { chat, email: ticket.email().to_owned() })
}

/// Begin an external sign-in over a fresh device connection (task T611g). `None` when the server offers none.
pub(crate) fn begin_external(mut stream: Transport) -> Result<Option<crate::chat_session::ExternalStart>, LabError> {
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    crate::chat_session::begin_external(&mut stream, |stream: &mut Transport, deadline| stream.get_mut().set_deadline(deadline), deadline)
        .map_err(LabError::Chat)
}

/// Finish an external sign-in over a fresh device connection and negotiate the chat protocol (task T611g). `email` is
/// the person this device is enrolled for.
pub(crate) fn finish_external(
    stream: Transport,
    email: &str,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
    client: &str,
) -> Result<SignedInSession, LabError> {
    let hello = Hello {
        min_version: 1,
        max_version: 1,
        features: FEATURE_LIST_ROOMS
            | FEATURE_SEARCH
            | FEATURE_FILES
            | FEATURE_THREADS
            | FEATURE_REACTIONS
            | FEATURE_ARCHIVE
            | FEATURE_CALLS
            | FEATURE_FILE_LIST
            | FEATURE_PINS_SAVED
            | FEATURE_READ_STATE
            | FEATURE_GAP_REPLAY
            | FEATURE_CONTINUE
            | crewcraft_proto::request::FEATURE_ROOM_SETTINGS
            | FEATURE_ACTIVITY
            | crewcraft_proto::request::FEATURE_MEETINGS
            | crewcraft_proto::request::FEATURE_GUEST_MEETINGS,
        client: client.into(),
    };
    let settings = Settings::new(email);
    let set_deadline: SetDeadline = |stream, deadline| stream.get_mut().set_deadline(deadline);
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    let negotiation = Negotiation { hello, settings, frame_timeout: FRAME_TIMEOUT, deadline };
    let chat = ChatSession::finish_external(stream, set_deadline, email, code, verifier, redirect_uri, negotiation).map_err(LabError::Chat)?;
    Ok(SignedInSession { chat, email: email.to_owned() })
}

/// Ask the server to end the session `ticket` names (task T240), over a fresh device connection.
pub(crate) fn end(mut stream: Transport, ticket: &ResumeTicket) -> Result<(), LabError> {
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    crate::chat_session::end_session(
        &mut stream,
        |stream: &mut Transport, deadline| stream.get_mut().set_deadline(deadline),
        ticket.token(),
        deadline,
    )
    .map_err(LabError::Chat)
}

/// Every participant's call key in one call, by person (task T360d3).
pub type CallKeys = BTreeMap<String, [u8; 32]>;
/// The sender keys sealed to this person in one call, by (sender, key id) (task T360d3).
pub type SealedSenderKeys = BTreeMap<(String, u64), Vec<u8>>;

/// An authenticated connection. Dropping it ends the local session. Commands use the same connection and the same
/// room views until the connection closes.
pub struct SignedInSession {
    chat: ChatSession<Transport, SetDeadline>,
    email: String,
}

impl SignedInSession {
    /// The ticket that reopens this session later from this device without a new code (task T240).
    pub fn resume_ticket(&self) -> Option<ResumeTicket> {
        ResumeTicket::new(&self.email, self.chat.token())
    }

    /// `text` comes from the caller's protected input and is sent only on this connection.
    pub fn post(&mut self, room: &str, text: &str) -> Result<u64, LabError> {
        if !valid_room(room) {
            return Err(LabError::Usage);
        }
        self.chat.post(room, text, 0, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Upload the file at `path` to `room` under its own name (task T330e): hash it, then send it in `MAX_CHUNK`
    /// chunks, calling `progress(sent, size)` after each. Returns the uploaded file.
    pub fn upload(&mut self, room: &str, path: &Path, progress: &mut dyn FnMut(u64, u64)) -> Result<Uploaded, FileOpError> {
        if !valid_room(room) {
            return Err(FileOpError::Lab(LabError::Usage));
        }
        let name = path.file_name().and_then(|name| name.to_str()).map(str::to_owned).ok_or(FileOpError::Local(io::ErrorKind::InvalidInput))?;
        let local = |error: io::Error| FileOpError::Local(error.kind());
        let size = std::fs::metadata(path).map_err(local)?.len();
        let mut hasher = Sha256::new();
        let mut file = File::open(path).map_err(local)?;
        let mut buffer = vec![0u8; MAX_CHUNK];
        loop {
            let n = file.read(&mut buffer).map_err(local)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        let sha256: [u8; 32] = hasher.finalize().into();
        let lab = |error: ChatError| FileOpError::Lab(LabError::Chat(error));
        let upload = self.chat.upload_begin(room, &name, size, sha256, 0, Instant::now() + OPERATION_TIMEOUT).map_err(lab)?;
        let mut file = File::open(path).map_err(local)?;
        let mut offset = 0u64;
        loop {
            let n = file.read(&mut buffer).map_err(local)?;
            if n == 0 {
                break;
            }
            self.chat.upload_chunk(upload, offset, buffer[..n].to_vec(), 0, Instant::now() + OPERATION_TIMEOUT).map_err(lab)?;
            offset += n as u64;
            progress(offset, size);
        }
        let file = self.chat.upload_finish(upload, 0, Instant::now() + OPERATION_TIMEOUT).map_err(lab)?;
        Ok(Uploaded { file, name, size })
    }

    /// Post `text` with `files` to `room` (task T330e). `text` may be empty.
    pub fn post_files(&mut self, room: &str, text: &str, files: Vec<[u8; 16]>) -> Result<u64, LabError> {
        if !valid_room(room) || files.is_empty() {
            return Err(LabError::Usage);
        }
        self.chat.post_files(room, text, files, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Download file `file` (`size` bytes) to a new file at `to` (task T330e). `to` must not exist; a failed download
    /// removes what it wrote.
    pub fn download_to(&mut self, file: [u8; 16], size: u64, to: &Path) -> Result<(), FileOpError> {
        let local = |error: io::Error| FileOpError::Local(error.kind());
        let mut out = OpenOptions::new().write(true).create_new(true).open(to).map_err(local)?;
        let result = (|| {
            let mut offset = 0u64;
            while offset < size {
                let length = u32::try_from((size - offset).min(MAX_CHUNK as u64)).unwrap_or(MAX_CHUNK as u32);
                let data = self
                    .chat
                    .download(file, offset, length, 0, Instant::now() + OPERATION_TIMEOUT)
                    .map_err(|e| FileOpError::Lab(LabError::Chat(e)))?;
                if data.is_empty() {
                    return Err(FileOpError::Lab(LabError::Chat(ChatError::UnexpectedResponse)));
                }
                out.write_all(&data).map_err(local)?;
                offset += data.len() as u64;
            }
            out.sync_all().map_err(local)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(to);
        }
        result
    }

    /// The bytes of `file` (`size` bytes, at most `cap`), in memory, for a preview (task T333).
    pub fn download_bytes(&mut self, file: [u8; 16], size: u64, cap: u64) -> Result<Vec<u8>, FileOpError> {
        if size == 0 || size > cap {
            return Err(FileOpError::Lab(LabError::Usage));
        }
        let mut out = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
        let mut offset = 0u64;
        while offset < size {
            let length = u32::try_from((size - offset).min(MAX_CHUNK as u64)).unwrap_or(MAX_CHUNK as u32);
            let data =
                self.chat.download(file, offset, length, 0, Instant::now() + OPERATION_TIMEOUT).map_err(|e| FileOpError::Lab(LabError::Chat(e)))?;
            if data.is_empty() {
                return Err(FileOpError::Lab(LabError::Chat(ChatError::UnexpectedResponse)));
            }
            out.extend_from_slice(&data);
            offset += data.len() as u64;
        }
        Ok(out)
    }

    /// Reply to the message at `parent` in `room`, in its thread (task T340b).
    pub fn reply(&mut self, room: &str, parent: u64, text: &str) -> Result<u64, LabError> {
        if !valid_room(room) || parent == 0 {
            return Err(LabError::Usage);
        }
        self.chat.reply(room, parent, text, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Add (`on`) or take back `reaction` on the message at `target` in `room` (task T341b).
    pub fn react(&mut self, room: &str, target: u64, reaction: u8, on: bool) -> Result<u64, LabError> {
        if !valid_room(room) || target == 0 || crewcraft_proto::push::reaction_name(reaction).is_none() {
            return Err(LabError::Usage);
        }
        self.chat.react(room, target, reaction, on, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Who reacted to each message in `room` with what, as the server pushed it (task T341b): by cursor, the reaction
    /// codes in order, each with the people, sorted.
    pub fn reactions(&mut self, room: &str) -> crewcraft_ui_model::RoomReactions {
        let Some(view) = self.chat.view(room) else { return Vec::new() };
        view.reactions()
            .iter()
            .map(|(cursor, by_code)| (*cursor, by_code.iter().map(|(code, who)| (*code, who.iter().cloned().collect())).collect()))
            .collect()
    }

    /// Whether room pins and personal saved messages were negotiated (T343).
    pub fn pins_saved(&self) -> bool {
        self.chat.pins_saved()
    }

    pub fn read_states(&self) -> bool {
        self.chat.read_states()
    }

    pub fn activities(&self) -> bool {
        self.chat.activities()
    }

    pub fn activity(&mut self, filter: crewcraft_proto::activity::ActivityFilter) -> Result<crewcraft_proto::activity::ActivitySnapshot, LabError> {
        self.chat.activity(filter, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    pub fn mark_activity_seen(&mut self, through: u64) -> Result<u64, LabError> {
        self.chat.mark_activity_seen(through, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Mark a chosen message unread; zero asks the server for the newest live message written by somebody else.
    pub fn mark_unread(&mut self, room: &str, target: u64) -> Result<u64, LabError> {
        if !valid_room(room) {
            return Err(LabError::Usage);
        }
        self.chat.mark_unread(room, target, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Record an explicit read through `cursor`, using the existing monotonic marker.
    pub fn mark_read(&mut self, room: &str, cursor: u64) -> Result<u64, LabError> {
        if !valid_room(room) {
            return Err(LabError::Usage);
        }
        self.chat.mark_read(room, cursor, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    pub fn read_state(&mut self, room: &str) -> Option<crewcraft_client_core::room_view::ReadState> {
        let view = self.chat.view(room)?;
        if view.awaiting_read_state() { None } else { view.read_state().cloned() }
    }

    /// Whether the server keeps personal room settings (T346).
    pub fn room_settings_offered(&self) -> bool {
        self.chat.room_settings()
    }

    /// Turn one of the person's own settings for `room` on or off; returns their settings revision for it (T346).
    pub fn set_room_setting(&mut self, room: &str, setting: crewcraft_proto::room_settings::RoomSetting, on: bool) -> Result<u64, LabError> {
        if !valid_room(room) {
            return Err(LabError::Usage);
        }
        self.chat.set_room_setting(room, setting, on, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// The person's own settings for every room they are in (T346); `None` when the server does not keep them.
    pub fn list_room_settings(&mut self) -> Result<Option<Vec<crewcraft_proto::room_settings::ListedRoomSettings>>, LabError> {
        if !self.chat.room_settings() {
            return Ok(None);
        }
        self.chat.list_room_settings(0, Instant::now() + OPERATION_TIMEOUT).map(Some).map_err(LabError::Chat)
    }

    /// The person's own settings for a followed room, as the last completed Sync delivered them (T346).
    pub fn room_settings(&mut self, room: &str) -> Option<crewcraft_client_core::room_view::RoomSettingsState> {
        let view = self.chat.view(room)?;
        if view.awaiting_room_settings() { None } else { view.room_settings().copied() }
    }

    pub fn gap_notice(&mut self, room: &str) -> Option<crewcraft_client_core::room_view::GapNotice> {
        self.chat.view(room)?.gap_notice().cloned()
    }

    pub fn recovery_epoch(&mut self, room: &str) -> u64 {
        self.chat.view(room).map_or(0, |view| view.recovery_epoch())
    }

    /// The last completely installed room view, including after a follow-up Sync failed (T345).
    pub fn room_shown(&mut self, room: &str) -> Option<Vec<Shown>> {
        Some(self.chat.view(room)?.shown())
    }

    /// Pin or conditionally unpin the message at `target` (T343).
    pub fn pin(&mut self, room: &str, target: u64, on: bool) -> Result<u64, LabError> {
        if !valid_room(room) || target == 0 {
            return Err(LabError::Usage);
        }
        self.chat.pin(room, target, on, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Add or remove the person's bookmark (T343).
    pub fn save_message(&mut self, room: &str, target: u64, on: bool) -> Result<u64, LabError> {
        if !valid_room(room) || target == 0 {
            return Err(LabError::Usage);
        }
        self.chat.save_message(room, target, on, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Every readable saved message in its current state, walking all server pages (T343).
    pub fn saved_messages(&mut self) -> Result<Vec<SavedMessage>, LabError> {
        self.chat.saved_messages(0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// The room's current pin, including its body when it is outside the current history page (T343).
    pub fn pinned(&mut self, room: &str) -> Option<crewcraft_client_core::room_view::PinnedMessage> {
        self.chat.view(room).and_then(|view| view.pinned_message().cloned())
    }

    /// Start a call in `room`, or join its open one (task T360a2); returns the call id.
    pub fn call_start(&mut self, room: &str, video: bool) -> Result<u64, LabError> {
        if !valid_room(room) {
            return Err(LabError::Usage);
        }
        self.chat.call_request(Request::CallStart { room: room.to_owned(), video }, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Join, heartbeat or leave call `call` of `room` (task T360a2): `request` builds the request.
    pub fn call(&mut self, room: &str, call: u64, request: fn(String, u64) -> Request) -> Result<u64, LabError> {
        if !valid_room(room) || call == 0 {
            return Err(LabError::Usage);
        }
        self.chat.call_request(request(room.to_owned(), call), Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Send a call request as it is (task T360d3: `CallKey`, `CallSeal`).
    pub fn call_send(&mut self, request: Request) -> Result<u64, LabError> {
        self.chat.call_request(request, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// What the server last said about `call`'s keys (task T360d3): every participant's call key, and the sender keys
    /// sealed to this person by (sender, kid).
    pub fn call_inputs(&mut self, room: &str, call: u64) -> (CallKeys, SealedSenderKeys) {
        let Some(view) = self.chat.view(room) else { return (BTreeMap::new(), BTreeMap::new()) };
        (view.call_keys(call).cloned().unwrap_or_default(), view.sealed(call).cloned().unwrap_or_default())
    }

    /// The room's open call and its call history lines by cursor, as the server pushed them (task T360a2).
    /// Meeting lines (task T370b2) are among the history lines, in cursor order.
    pub fn calls(&mut self, room: &str) -> (Option<crewcraft_client_core::room_view::OpenCall>, Vec<(u64, String)>) {
        let meetings = self.chat.meeting_lines(room);
        let Some(view) = self.chat.view(room) else { return (None, Vec::new()) };
        let mut lines: Vec<(u64, String)> = view.call_lines().iter().map(|(cursor, line)| (*cursor, line.text.clone())).collect();
        lines.extend(meetings);
        lines.sort_by_key(|(cursor, _)| *cursor);
        (view.call().cloned(), lines)
    }

    /// How many meeting lines this session has seen: when it changes, a meeting changed (task T370b2).
    pub fn meeting_changes(&self) -> u64 {
        self.chat.meeting_changes()
    }

    /// Whether the server agreed to meetings and the calendar (task T370b).
    pub fn meetings(&self) -> bool {
        self.chat.meetings()
    }

    pub fn guest_meetings_offered(&self) -> bool {
        self.chat.guest_meetings_offered()
    }

    pub fn guest_lobby_state(&mut self, room: &str) -> Option<GuestLobbyState> {
        self.chat.guest_lobby_state(room)
    }

    pub(crate) fn forget_guest_lobby_room(&mut self, room: &str) {
        self.chat.forget_guest_lobby_room(room);
    }

    pub fn guest_save(&mut self, change: GuestMeetingChange) -> Result<GuestReply, LabError> {
        if matches!(&change, GuestMeetingChange::Create(draft) if !valid_room(&draft.room)) {
            return Err(LabError::Usage);
        }
        self.chat.guest_save(change, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    pub fn guest_list(&mut self, meeting: u64) -> Result<GuestLobby, LabError> {
        self.chat.guest_list(meeting, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    pub fn guest_close(&mut self, meeting: u64, revision: u64) -> Result<GuestLobby, LabError> {
        self.chat.guest_close(meeting, revision, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    pub fn guest_decide(&mut self, meeting: u64, guest: u64, revision: u64, decision: GuestDecision) -> Result<GuestLobby, LabError> {
        self.chat.guest_decide(meeting, guest, revision, decision, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// The meetings in my rooms that overlap the UTC window `from_ms` to `to_ms` (task T370b).
    pub fn meeting_list(&mut self, from_ms: u64, to_ms: u64) -> Result<crewcraft_proto::meeting::MeetingPage, LabError> {
        self.chat.meeting_list(from_ms, to_ms, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Schedule (`meeting` 0) or edit a meeting last seen at `version` (task T370b), returning it as saved.
    pub fn meeting_save(&mut self, save: MeetingSave) -> Result<crewcraft_proto::meeting::Meeting, LabError> {
        if !valid_room(&save.room) {
            return Err(LabError::Usage);
        }
        let MeetingSave { room, meeting, version, start_ms, duration, title, agenda } = save;
        let request = Request::MeetingSave { room, meeting, version, start_ms, duration, title, agenda };
        self.chat.meeting_save(request, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Cancel meeting `meeting` of `room`, last seen at `version` (task T370b); returns the new version.
    pub fn meeting_cancel(&mut self, room: &str, meeting: u64, version: u64) -> Result<u64, LabError> {
        if !valid_room(room) || meeting == 0 {
            return Err(LabError::Usage);
        }
        let request = Request::MeetingCancel { room: room.to_owned(), meeting, version };
        self.chat.meeting_request(request, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Join meeting `meeting`'s call (task T370b); returns the call's id.
    pub fn meeting_join(&mut self, meeting: u64) -> Result<u64, LabError> {
        if meeting == 0 {
            return Err(LabError::Usage);
        }
        self.chat.meeting_request(Request::MeetingJoin { meeting }, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Whether the server agreed to continuing archived conversations (task T352).
    pub fn continues(&self) -> bool {
        self.chat.continues()
    }

    /// Continue the archive room `archive` as an active conversation (task T352): the room it continues in, the same
    /// room every time.
    pub fn continue_archive(&mut self, archive: &str) -> Result<String, LabError> {
        if !valid_room(archive) {
            return Err(LabError::Usage);
        }
        self.chat.continue_archive(archive, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// The lines in `room` that link back to the archives it continues, by cursor: `(cursor, archive, text)`, as the
    /// server pushed them (task T352).
    pub fn continued_lines(&mut self, room: &str) -> Vec<(u64, String, String)> {
        let Some(view) = self.chat.view(room) else { return Vec::new() };
        view.continued_lines().iter().map(|(cursor, line)| (*cursor, line.archive.clone(), line.text.clone())).collect()
    }

    /// For an archive room, its imported messages' original times by cursor (task T350d2); `None` for any other room.
    pub fn archive(&mut self, room: &str) -> Option<Vec<(u64, u64)>> {
        let view = self.chat.view(room)?;
        view.archived().then(|| view.sent_times().iter().map(|(cursor, ms)| (*cursor, *ms)).collect())
    }

    /// Each reply's parent in `room`, by the reply's cursor, as the server pushed them (task T340b).
    pub fn parents(&mut self, room: &str) -> BTreeMap<u64, u64> {
        self.chat.view(room).map(|view| view.parents().clone()).unwrap_or_default()
    }

    /// The files each message in `room` carries, as the server pushed them (task T330e).
    pub fn attachments(&mut self, room: &str) -> BTreeMap<u64, Vec<AttachedFile>> {
        self.chat.view(room).map(|view| view.attachments().clone()).unwrap_or_default()
    }

    pub fn edit(&mut self, room: &str, target: u64, text: &str) -> Result<u64, LabError> {
        if !valid_room(room) || target == 0 {
            return Err(LabError::Usage);
        }
        self.chat.edit(room, target, text, 0, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    pub fn delete(&mut self, room: &str, target: u64) -> Result<u64, LabError> {
        if !valid_room(room) || target == 0 {
            return Err(LabError::Usage);
        }
        self.chat.delete(room, target, 0, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Ask the server to answer, which keeps an idle connection open.
    pub fn ping(&mut self) -> Result<(), LabError> {
        self.chat.ping(0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// The rooms the signed-in person is a member of, sorted, or `None` when the server is too old to list them (it did
    /// not agree to `FEATURE_LIST_ROOMS` in the handshake; nothing is sent then).
    pub fn list_rooms(&mut self) -> Result<Option<Vec<String>>, LabError> {
        if !self.chat.lists_rooms() {
            return Ok(None);
        }
        self.chat.list_rooms(0, Instant::now() + OPERATION_TIMEOUT).map(Some).map_err(LabError::Chat)
    }

    /// The messages the person can read that match `query`, newest first (task T320c). `None` when the server did not
    /// agree to `FEATURE_SEARCH` (nothing is sent then). `query` must be 1 to `request::MAX_QUERY` bytes.
    /// The bytes the person's files take and their quota (task T332b); `None` when the server keeps no files.
    pub fn storage_use(&mut self) -> Result<Option<(u64, u64)>, LabError> {
        if !self.chat.files() {
            return Ok(None);
        }
        self.chat.storage_use(0, Instant::now() + OPERATION_TIMEOUT).map(Some).map_err(LabError::Chat)
    }

    /// The files in the person's rooms (task T331b); `None` when the server does not list files.
    pub fn list_files(&mut self) -> Result<Option<Vec<crewcraft_proto::request::ListedFile>>, LabError> {
        if !self.chat.lists_files() {
            return Ok(None);
        }
        self.chat.list_files(0, Instant::now() + OPERATION_TIMEOUT).map(Some).map_err(LabError::Chat)
    }

    pub fn search(&mut self, query: &str) -> Result<Option<Vec<SearchHit>>, LabError> {
        if query.is_empty() || query.len() > crewcraft_proto::request::MAX_QUERY {
            return Err(LabError::Usage);
        }
        if !self.chat.searches() {
            return Ok(None);
        }
        self.chat.search(query, 0, Instant::now() + OPERATION_TIMEOUT).map(Some).map_err(LabError::Chat)
    }

    /// Fetch the room's events after the cursor already held and return the acknowledged head and the whole room as
    /// it is drawn.
    pub fn sync(&mut self, room: &str) -> Result<(u64, Vec<Shown>), LabError> {
        if !valid_room(room) {
            return Err(LabError::Usage);
        }
        let head = self.chat.sync(room, false, 0, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)?;
        let lines = self.chat.view(room).ok_or(LabError::MissingTimeline)?.shown();
        Ok((head, lines))
    }
}
