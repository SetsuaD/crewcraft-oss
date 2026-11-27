//! Synchronous chat over an already verified, enrolled device connection. Task T215.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use crewcraft_client_core::client::{Client, ClientEvent};
use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::requests::Reply as RequestReply;
use crewcraft_client_core::room_view::{CurrentWindow, RoomView};
use crewcraft_client_core::session::{ClientSession, Phase, SessionError};
use crewcraft_proto::activity::{ActivityFilter, ActivityKind, ActivitySnapshot};
use crewcraft_proto::frame::{self, ReceivedFrame};
use crewcraft_proto::handshake::Hello;
use crewcraft_proto::meeting::{Meeting, MeetingPage};
use crewcraft_proto::message::{CodecError, MAX_NAME};
use crewcraft_proto::request::{
    FEATURE_ACTIVITY, FEATURE_CALLS, FEATURE_CONTINUE, FEATURE_FILE_LIST, FEATURE_FILES, FEATURE_GAP_REPLAY, FEATURE_LIST_ROOMS, FEATURE_PINS_SAVED,
    FEATURE_REACTIONS, FEATURE_READ_STATE, FEATURE_SEARCH, FEATURE_THREADS, MAX_SAVED_PAGE, Request, Response, SavedMessage, SavedPage, SearchHit,
};
use crewcraft_proto::signin::{self, Opening, SignIn};
use zeroize::Zeroizing;

const SIGN_IN_REPLY_LIMIT: usize = 1 + signin::TOKEN_LEN;
/// The largest `ExternalStart` reply (task T611g): issuer, client id, authorization endpoint and nonce, each with a
/// `u16` length.
const EXTERNAL_START_LIMIT: usize =
    1 + 2 + signin::MAX_URL_BYTES + 2 + signin::MAX_CLIENT_ID_BYTES + 2 + signin::MAX_URL_BYTES + 2 + signin::TOKEN_LEN;
const WELCOME_LIMIT: usize = 9 + MAX_NAME;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatError {
    Io(io::ErrorKind),
    SignInProtocol,
    SignInRefused,
    HandshakeRefused,
    Session(SessionError),
    Request(CodecError),
    Rejected(u16),
    Closed,
    /// An out-of-order event or a head behind the local cursor requires resync.
    HistoryGap {
        reached: u64,
        head: u64,
    },
    /// The stream stopped or the deadline expired before the advertised head arrived.
    SyncIncomplete {
        reached: u64,
        head: u64,
        reason: io::ErrorKind,
    },
    /// The server did not agree to the feature this request needs (an older server); nothing was sent.
    Unsupported,
    /// The server's room list did not match the count its answer announced; the connection is closed.
    UnexpectedResponse,
}

/// What the client offers once it is signed in (its hello and notification settings), and the time allowed: each frame,
/// and the whole opening.
pub struct Negotiation {
    pub hello: Hello,
    pub settings: Settings,
    pub frame_timeout: Duration,
    pub deadline: Instant,
}

pub struct ChatSession<S, D> {
    stream: S,
    set_deadline: D,
    frame_timeout: Duration,
    session: ClientSession,
    closed: bool,
    /// The session token the server returned; it resumes this session later (task T240). Wiped on drop.
    token: Zeroizing<String>,
    activity_position: (u64, u64),
}

impl<S: Read + Write, D: FnMut(&mut S, Instant)> ChatSession<S, D> {
    /// The stream has already authenticated both peers. `set_deadline` must enforce one absolute
    /// cutoff across all I/O for a frame. The same operation deadline covers sign-in and negotiation.
    pub fn connect(
        stream: S,
        set_deadline: D,
        credentials: &SignIn<'_>,
        hello: Hello,
        settings: Settings,
        frame_timeout: Duration,
        deadline: Instant,
    ) -> Result<Self, ChatError> {
        let opening = Opening::SignIn(SignIn { email: credentials.email, password: credentials.password, code: credentials.code });
        Self::open(stream, set_deadline, &opening, credentials.email, Negotiation { hello, settings, frame_timeout, deadline })
    }

    /// As `connect`, but reopening the session `token` belongs to instead of signing in (task T240). A token the server
    /// no longer accepts is `SignInRefused`.
    pub fn resume(stream: S, set_deadline: D, email: &str, token: &str, negotiation: Negotiation) -> Result<Self, ChatError> {
        Self::open(stream, set_deadline, &Opening::Resume { token }, email, negotiation)
    }

    /// As `connect`, but finishing a sign-in through the server's external identity provider (task T611g): the code
    /// from the loopback redirect, the PKCE verifier and that redirect URI. A refusal is `SignInRefused`.
    pub fn finish_external(
        stream: S,
        set_deadline: D,
        email: &str,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        negotiation: Negotiation,
    ) -> Result<Self, ChatError> {
        let opening = Opening::FinishExternal { code, verifier, redirect_uri };
        Self::open(stream, set_deadline, &opening, email, negotiation)
    }

    /// The session token, for a later `resume`. A secret: keep it as the device record is kept, never in a log.
    pub fn token(&self) -> &str {
        &self.token
    }

    fn open(stream: S, set_deadline: D, opening: &Opening<'_>, email: &str, negotiation: Negotiation) -> Result<Self, ChatError> {
        let Negotiation { hello, settings, frame_timeout, deadline } = negotiation;
        let versions = hello.min_version..=hello.max_version;
        let supported_features = hello.features;
        let client = Client::new(email, settings);
        let mut chat = Self {
            stream,
            set_deadline,
            frame_timeout,
            session: ClientSession::new(hello, client),
            closed: false,
            token: Zeroizing::default(),
            activity_position: (0, 0),
        };
        chat.token = chat.authenticate(opening, deadline)?;

        let hello = chat.session.start().map_err(ChatError::Session)?;
        chat.write_frame(&hello, deadline)?;
        let reply = chat.read_frame(WELCOME_LIMIT, deadline)?;
        chat.session.receive(reply.as_bytes(), 0, 0).map_err(ChatError::Session)?;
        match chat.session.phase() {
            Phase::Open { version, features } if versions.contains(&version) && features & !supported_features == 0 => Ok(chat),
            _ => Err(ChatError::HandshakeRefused),
        }
    }

    /// Send one post and return only its matched server acknowledgement. A transport failure
    /// after dispatch leaves the result unknown. The runtime does not retry a write.
    pub fn post(&mut self, room: &str, text: &str, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<u64, ChatError> {
        self.request(Request::Post { room: room.to_owned(), text: text.to_owned() }, now_ms, local_minute, deadline)
    }

    pub fn edit(&mut self, room: &str, target: u64, text: &str, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<u64, ChatError> {
        self.request(Request::Edit { room: room.to_owned(), target, text: text.to_owned() }, now_ms, local_minute, deadline)
    }

    pub fn delete(&mut self, room: &str, target: u64, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<u64, ChatError> {
        self.request(Request::Delete { room: room.to_owned(), target }, now_ms, local_minute, deadline)
    }

    /// The features both sides agreed on in the handshake (`handshake::Hello::features`).
    pub fn features(&self) -> u32 {
        match self.session.phase() {
            Phase::Open { features, .. } => features,
            _ => 0,
        }
    }

    /// Whether the server agreed to `ListRooms` (`request::FEATURE_LIST_ROOMS`).
    pub fn lists_rooms(&self) -> bool {
        self.features() & FEATURE_LIST_ROOMS != 0
    }

    /// The rooms the signed-in person is a member of, as the server lists them. `Unsupported`, with nothing sent, when
    /// the server did not agree to `FEATURE_LIST_ROOMS`. The answer announces how many rooms follow; a room list of
    /// another length is `UnexpectedResponse` and closes the session.
    pub fn list_rooms(&mut self, now_ms: u64, deadline: Instant) -> Result<Vec<String>, ChatError> {
        if !self.lists_rooms() {
            return Err(ChatError::Unsupported);
        }
        let (id, count) = match self.exchange(Request::ListRooms, now_ms, 0, deadline)? {
            (id, Response::Ok { cursor }) => (id, cursor),
            (_, Response::Error { code, .. }) => return Err(ChatError::Rejected(code)),
        };
        loop {
            for event in self.receive(now_ms, 0, deadline)? {
                if let ClientEvent::Rooms { id: answered, rooms } = event
                    && answered == id
                {
                    if u64::try_from(rooms.len()).ok() != Some(count) {
                        self.closed = true;
                        return Err(ChatError::UnexpectedResponse);
                    }
                    return Ok(rooms);
                }
            }
        }
    }

    /// Whether the server agreed to `Search` (`request::FEATURE_SEARCH`, task T320c).
    pub fn searches(&self) -> bool {
        self.features() & FEATURE_SEARCH != 0
    }

    /// Whether the server agreed to the file list (`request::FEATURE_FILE_LIST`, task T331b).
    pub fn lists_files(&self) -> bool {
        self.features() & FEATURE_FILE_LIST != 0
    }

    /// The files on messages in the signed-in person's rooms, as the server lists them (task T331b). `Unsupported`,
    /// with nothing sent, without the feature; a files frame of another length than the answer said closes the session.
    pub fn list_files(&mut self, now_ms: u64, deadline: Instant) -> Result<Vec<crewcraft_proto::request::ListedFile>, ChatError> {
        if !self.lists_files() {
            return Err(ChatError::Unsupported);
        }
        let (id, count) = match self.exchange(Request::ListFiles, now_ms, 0, deadline)? {
            (id, Response::Ok { cursor }) => (id, cursor),
            (_, Response::Error { code, .. }) => return Err(ChatError::Rejected(code)),
        };
        loop {
            for event in self.receive(now_ms, 0, deadline)? {
                if let ClientEvent::Files { id: answered, files } = event
                    && answered == id
                {
                    if u64::try_from(files.len()).ok() != Some(count) {
                        self.closed = true;
                        return Err(ChatError::UnexpectedResponse);
                    }
                    return Ok(files);
                }
            }
        }
    }

    /// The messages the signed-in person can read that match `query`, newest first, as the server finds them (task
    /// T320c). `Unsupported`, with nothing sent, when the server did not agree to `FEATURE_SEARCH`. The answer counts
    /// the hits that follow; a hits frame of another length is `UnexpectedResponse` and closes the session.
    pub fn search(&mut self, query: &str, now_ms: u64, deadline: Instant) -> Result<Vec<SearchHit>, ChatError> {
        if !self.searches() {
            return Err(ChatError::Unsupported);
        }
        let (id, count) = match self.exchange(Request::Search { query: query.to_owned() }, now_ms, 0, deadline)? {
            (id, Response::Ok { cursor }) => (id, cursor),
            (_, Response::Error { code, .. }) => return Err(ChatError::Rejected(code)),
        };
        loop {
            for event in self.receive(now_ms, 0, deadline)? {
                if let ClientEvent::Hits { id: answered, hits } = event
                    && answered == id
                {
                    if u64::try_from(hits.len()).ok() != Some(count) {
                        self.closed = true;
                        return Err(ChatError::UnexpectedResponse);
                    }
                    return Ok(hits);
                }
            }
        }
    }

    /// Whether the server agreed to files (`request::FEATURE_FILES`, task T330e).
    pub fn files(&self) -> bool {
        self.features() & FEATURE_FILES != 0
    }

    /// Start an upload (task T330e) and return its id: `UploadBegin`, then the id frame.
    pub fn upload_begin(
        &mut self,
        room: &str,
        name: &str,
        size: u64,
        sha256: [u8; 32],
        now_ms: u64,
        deadline: Instant,
    ) -> Result<[u8; 16], ChatError> {
        self.files_only()?;
        let request = Request::UploadBegin { room: room.to_owned(), name: name.to_owned(), size, sha256 };
        self.exchange_with_id(request, now_ms, deadline)
    }

    /// Send one chunk of an upload; returns how many bytes the server has received so far.
    pub fn upload_chunk(&mut self, upload: [u8; 16], offset: u64, bytes: Vec<u8>, now_ms: u64, deadline: Instant) -> Result<u64, ChatError> {
        self.files_only()?;
        self.request(Request::UploadChunk { upload, offset, bytes }, now_ms, 0, deadline)
    }

    /// Finish an upload and return the new file's id: `UploadFinish`, then the id frame.
    pub fn upload_finish(&mut self, upload: [u8; 16], now_ms: u64, deadline: Instant) -> Result<[u8; 16], ChatError> {
        self.files_only()?;
        self.exchange_with_id(Request::UploadFinish { upload }, now_ms, deadline)
    }

    /// Post `text` with `files` (task T330e); returns the message's cursor.
    pub fn post_files(&mut self, room: &str, text: &str, files: Vec<[u8; 16]>, now_ms: u64, deadline: Instant) -> Result<u64, ChatError> {
        self.files_only()?;
        self.request(Request::PostFiles { room: room.to_owned(), text: text.to_owned(), files }, now_ms, 0, deadline)
    }

    /// Up to `length` bytes of file `file` from `offset` (task T330e): `Download`, then the bytes frame, whose length
    /// must be the one the answer announced.
    pub fn download(&mut self, file: [u8; 16], offset: u64, length: u32, now_ms: u64, deadline: Instant) -> Result<Vec<u8>, ChatError> {
        self.files_only()?;
        let (id, count) = match self.exchange(Request::Download { file, offset, length }, now_ms, 0, deadline)? {
            (id, Response::Ok { cursor }) => (id, cursor),
            (_, Response::Error { code, .. }) => return Err(ChatError::Rejected(code)),
        };
        loop {
            for event in self.receive(now_ms, 0, deadline)? {
                if let ClientEvent::Bytes { id: answered, data } = event
                    && answered == id
                {
                    if u64::try_from(data.len()).ok() != Some(count) {
                        self.closed = true;
                        return Err(ChatError::UnexpectedResponse);
                    }
                    return Ok(data);
                }
            }
        }
    }

    /// Whether the server agreed to threads (`request::FEATURE_THREADS`, task T340b).
    pub fn threads(&self) -> bool {
        self.features() & FEATURE_THREADS != 0
    }

    /// Whether the server agreed to calls (`request::FEATURE_CALLS`, task T360a2).
    pub fn calls(&self) -> bool {
        self.features() & FEATURE_CALLS != 0
    }

    /// A call request (`CallStart`, `CallJoin`, `CallHeartbeat`, `CallLeave`; task T360a2); returns the call id.
    /// `Unsupported` without the feature.
    pub fn call_request(&mut self, request: Request, deadline: Instant) -> Result<u64, ChatError> {
        if !self.calls() {
            return Err(ChatError::Unsupported);
        }
        self.request(request, 0, 0, deadline)
    }

    /// Whether the server agreed to reactions (`request::FEATURE_REACTIONS`, task T341b).
    pub fn reactions(&self) -> bool {
        self.features() & FEATURE_REACTIONS != 0
    }

    /// Add (`on`) or take back a reaction on the message at `target` (task T341b); returns the reaction's cursor.
    /// `Unsupported` without the feature.
    pub fn react(&mut self, room: &str, target: u64, reaction: u8, on: bool, now_ms: u64, deadline: Instant) -> Result<u64, ChatError> {
        if !self.reactions() {
            return Err(ChatError::Unsupported);
        }
        self.request(Request::React { room: room.to_owned(), target, reaction, on }, now_ms, 0, deadline)
    }

    /// Whether the server agreed to room pins and personal saved messages (T343).
    pub fn pins_saved(&self) -> bool {
        self.features() & FEATURE_PINS_SAVED != 0
    }

    /// Whether authoritative personal read state was negotiated (T344).
    pub fn read_states(&self) -> bool {
        self.features() & FEATURE_READ_STATE != 0
    }

    pub fn activities(&self) -> bool {
        self.features() & FEATURE_ACTIVITY != 0
    }

    /// One current-membership Activity result, correlated to its exact request and selected filter (T347).
    pub fn activity(&mut self, filter: ActivityFilter, now_ms: u64, deadline: Instant) -> Result<ActivitySnapshot, ChatError> {
        if !self.activities() {
            return Err(ChatError::Unsupported);
        }
        let (id, head) = match self.exchange(Request::ListActivity { filter }, now_ms, 0, deadline)? {
            (id, Response::Ok { cursor }) => (id, cursor),
            (_, Response::Error { code, .. }) => return Err(ChatError::Rejected(code)),
        };
        let frame = self.read_frame(frame::MAX_FRAME, deadline)?;
        let (answered, snapshot) = crewcraft_proto::activity::decode_snapshot(frame.payload()).map_err(|_| {
            self.closed = true;
            ChatError::UnexpectedResponse
        })?;
        let wrong_filter = match filter {
            ActivityFilter::Badge => !snapshot.items.is_empty() || snapshot.more,
            ActivityFilter::Unread => snapshot.items.iter().any(|item| item.id <= snapshot.seen),
            ActivityFilter::Mentions => snapshot.items.iter().any(|item| !matches!(item.kind, ActivityKind::Message { mentioned: true, .. })),
            ActivityFilter::Saved => snapshot.items.iter().any(|item| matches!(item.kind, ActivityKind::MissedCall)),
            ActivityFilter::All => false,
        };
        if answered != id
            || snapshot.head != head
            || snapshot.head < self.activity_position.0
            || snapshot.seen < self.activity_position.1
            || wrong_filter
        {
            self.closed = true;
            return Err(ChatError::UnexpectedResponse);
        }
        self.activity_position = (snapshot.head, snapshot.seen);
        Ok(snapshot)
    }

    /// Acknowledge the displayed watermark only; the next list supplies confirmed counters and current rows.
    pub fn mark_activity_seen(&mut self, through: u64, now_ms: u64, deadline: Instant) -> Result<u64, ChatError> {
        if !self.activities() {
            return Err(ChatError::Unsupported);
        }
        let seen = self.request(Request::MarkActivitySeen { through }, now_ms, 0, deadline)?;
        if seen < through || seen < self.activity_position.1 {
            self.closed = true;
            return Err(ChatError::UnexpectedResponse);
        }
        self.activity_position = (self.activity_position.0.max(seen), seen);
        Ok(seen)
    }

    /// Rewind the read position to before `target`, or before the newest other person's message for zero (T344).
    pub fn mark_unread(&mut self, room: &str, target: u64, now_ms: u64, deadline: Instant) -> Result<u64, ChatError> {
        if !self.read_states() {
            return Err(ChatError::Unsupported);
        }
        self.request(Request::MarkUnread { room: room.to_owned(), target }, now_ms, 0, deadline)
    }

    /// Whether the server agreed to continuing archived conversations (`request::FEATURE_CONTINUE`, task T352).
    pub fn continues(&self) -> bool {
        self.features() & FEATURE_CONTINUE != 0
    }

    /// Whether the server agreed to meetings and the calendar (`request::FEATURE_MEETINGS`, task T370b).
    pub fn meetings(&self) -> bool {
        self.features() & crewcraft_proto::request::FEATURE_MEETINGS != 0
    }

    /// The meetings in the signed-in person's rooms that overlap `from_ms` to `to_ms`, UTC (task T370b): `MeetingList`,
    /// then the meetings frame, whose length must be the one the answer announced. `Unsupported` without the feature.
    pub fn meeting_list(&mut self, from_ms: u64, to_ms: u64, deadline: Instant) -> Result<MeetingPage, ChatError> {
        if !self.meetings() {
            return Err(ChatError::Unsupported);
        }
        let (id, count) = match self.exchange(Request::MeetingList { from_ms, to_ms }, 0, 0, deadline)? {
            (id, Response::Ok { cursor }) => (id, cursor),
            (_, Response::Error { code, .. }) => return Err(ChatError::Rejected(code)),
        };
        let page = self.meetings_frame(id, deadline)?;
        if u64::try_from(page.meetings.len()).ok() != Some(count) {
            self.closed = true;
            return Err(ChatError::UnexpectedResponse);
        }
        Ok(page)
    }

    /// Schedule (`save.meeting` 0) or edit a meeting (task T370b) and return it as the server saved it: `MeetingSave`,
    /// then the meetings frame holding that one meeting. A stale version is `Rejected(13)`, a conflict; nothing is
    /// resent. `Unsupported` without the feature.
    pub fn meeting_save(&mut self, save: Request, deadline: Instant) -> Result<Meeting, ChatError> {
        if !self.meetings() || !matches!(save, Request::MeetingSave { .. }) {
            return Err(ChatError::Unsupported);
        }
        let (id, saved) = match self.exchange(save, 0, 0, deadline)? {
            (id, Response::Ok { cursor }) => (id, cursor),
            (_, Response::Error { code, .. }) => return Err(ChatError::Rejected(code)),
        };
        let page = self.meetings_frame(id, deadline)?;
        match <[Meeting; 1]>::try_from(page.meetings) {
            Ok([meeting]) if meeting.id == saved => Ok(meeting),
            _ => {
                self.closed = true;
                Err(ChatError::UnexpectedResponse)
            }
        }
    }

    /// Cancel or join a meeting (`MeetingCancel`, `MeetingJoin`; task T370b): the new version, or the call's id.
    /// `Unsupported` without the feature.
    pub fn meeting_request(&mut self, request: Request, deadline: Instant) -> Result<u64, ChatError> {
        if !self.meetings() || !matches!(request, Request::MeetingCancel { .. } | Request::MeetingJoin { .. }) {
            return Err(ChatError::Unsupported);
        }
        self.request(request, 0, 0, deadline)
    }

    fn meetings_frame(&mut self, id: u32, deadline: Instant) -> Result<MeetingPage, ChatError> {
        loop {
            for event in self.receive(0, 0, deadline)? {
                if let ClientEvent::Meetings { id: answered, page } = event
                    && answered == id
                {
                    return Ok(page);
                }
            }
        }
    }

    /// Continue the archive room `archive` (task T352) and return the room the conversation continues in: `Continue`,
    /// then the continued frame. `Unsupported`, with nothing sent, without the feature.
    pub fn continue_archive(&mut self, archive: &str, now_ms: u64, deadline: Instant) -> Result<String, ChatError> {
        if !self.continues() {
            return Err(ChatError::Unsupported);
        }
        let id = match self.exchange(Request::Continue { archive: archive.to_owned() }, now_ms, 0, deadline)? {
            (id, Response::Ok { .. }) => id,
            (_, Response::Error { code, .. }) => return Err(ChatError::Rejected(code)),
        };
        loop {
            for event in self.receive(now_ms, 0, deadline)? {
                if let ClientEvent::Continued { id: answered, room } = event
                    && answered == id
                {
                    return Ok(room);
                }
            }
        }
    }

    /// A deliberate read advances the existing monotonic server marker (T344).
    pub fn mark_read(&mut self, room: &str, cursor: u64, now_ms: u64, deadline: Instant) -> Result<u64, ChatError> {
        self.request(Request::MarkRead { room: room.to_owned(), cursor }, now_ms, 0, deadline)
    }

    /// Whether personal room settings were negotiated (T346).
    pub fn room_settings(&self) -> bool {
        self.features() & crewcraft_proto::request::FEATURE_ROOM_SETTINGS != 0
    }

    /// Turn one of the person's own settings for `room` on or off; returns their settings revision for it (T346).
    pub fn set_room_setting(
        &mut self,
        room: &str,
        setting: crewcraft_proto::room_settings::RoomSetting,
        on: bool,
        now_ms: u64,
        deadline: Instant,
    ) -> Result<u64, ChatError> {
        if !self.room_settings() {
            return Err(ChatError::Unsupported);
        }
        self.request(Request::SetRoomSetting { room: room.to_owned(), setting, on }, now_ms, 0, deadline)
    }

    /// The person's own settings for every room they are in, as the server lists them (T346). A settings frame of
    /// another length than the answer said closes the session.
    pub fn list_room_settings(
        &mut self,
        now_ms: u64,
        deadline: Instant,
    ) -> Result<Vec<crewcraft_proto::room_settings::ListedRoomSettings>, ChatError> {
        if !self.room_settings() {
            return Err(ChatError::Unsupported);
        }
        let (id, count) = match self.exchange(Request::ListRoomSettings, now_ms, 0, deadline)? {
            (id, Response::Ok { cursor }) => (id, cursor),
            (_, Response::Error { code, .. }) => return Err(ChatError::Rejected(code)),
        };
        loop {
            for event in self.receive(now_ms, 0, deadline)? {
                if let ClientEvent::RoomSettings { id: answered, rows } = event
                    && answered == id
                {
                    if u64::try_from(rows.len()).ok() != Some(count) {
                        self.closed = true;
                        return Err(ChatError::UnexpectedResponse);
                    }
                    let inbox = self.session.client_mut().inbox_mut();
                    for row in &rows {
                        inbox.set_muted(&row.room, row.settings.muted);
                    }
                    return Ok(rows);
                }
            }
        }
    }

    /// Pin a message, or unpin it only if it is still the room's pin (T343).
    pub fn pin(&mut self, room: &str, target: u64, on: bool, now_ms: u64, deadline: Instant) -> Result<u64, ChatError> {
        if !self.pins_saved() {
            return Err(ChatError::Unsupported);
        }
        self.request(Request::Pin { room: room.to_owned(), target, on }, now_ms, 0, deadline)
    }

    /// Add or remove a personal bookmark for a message (T343).
    pub fn save_message(&mut self, room: &str, target: u64, on: bool, now_ms: u64, deadline: Instant) -> Result<u64, ChatError> {
        if !self.pins_saved() {
            return Err(ChatError::Unsupported);
        }
        self.request(Request::SaveMessage { room: room.to_owned(), target, on }, now_ms, 0, deadline)
    }

    /// Fetch every page of the person's saved messages, using their current state (T343). The same operation
    /// deadline bounds the whole walk. A repeated or unordered continuation closes the connection.
    pub fn saved_messages(&mut self, now_ms: u64, deadline: Instant) -> Result<Vec<SavedMessage>, ChatError> {
        if !self.pins_saved() {
            return Err(ChatError::Unsupported);
        }
        let mut after_room = String::new();
        let mut after_cursor = 0;
        let mut messages = Vec::new();
        loop {
            let page = self.saved_page(&after_room, after_cursor, now_ms, deadline)?;
            if page.messages.len() > MAX_SAVED_PAGE || (page.more && page.messages.is_empty()) {
                self.closed = true;
                return Err(ChatError::UnexpectedResponse);
            }
            for message in &page.messages {
                if (message.room.as_str(), message.cursor) <= (after_room.as_str(), after_cursor) {
                    self.closed = true;
                    return Err(ChatError::UnexpectedResponse);
                }
                after_room.clone_from(&message.room);
                after_cursor = message.cursor;
            }
            messages.extend(page.messages);
            if !page.more {
                return Ok(messages);
            }
        }
    }

    fn saved_page(&mut self, after_room: &str, after_cursor: u64, now_ms: u64, deadline: Instant) -> Result<SavedPage, ChatError> {
        let (id, count) = match self.exchange(Request::ListSaved { after_room: after_room.to_owned(), after_cursor }, now_ms, 0, deadline)? {
            (id, Response::Ok { cursor }) => (id, cursor),
            (_, Response::Error { code, .. }) => return Err(ChatError::Rejected(code)),
        };
        loop {
            for event in self.receive(now_ms, 0, deadline)? {
                if let ClientEvent::Saved { id: answered, page } = event
                    && answered == id
                {
                    if u64::try_from(page.messages.len()).ok() != Some(count) {
                        self.closed = true;
                        return Err(ChatError::UnexpectedResponse);
                    }
                    return Ok(page);
                }
            }
        }
    }

    /// Reply to the message at `parent`, in its thread (task T340b); returns the reply's cursor. `Unsupported` without
    /// the feature.
    pub fn reply(&mut self, room: &str, parent: u64, text: &str, now_ms: u64, deadline: Instant) -> Result<u64, ChatError> {
        if !self.threads() {
            return Err(ChatError::Unsupported);
        }
        self.request(Request::Reply { room: room.to_owned(), parent, text: text.to_owned() }, now_ms, 0, deadline)
    }

    /// The bytes the signed-in person's files take and their quota (task T332b). `Unsupported` without files.
    pub fn storage_use(&mut self, now_ms: u64, deadline: Instant) -> Result<(u64, u64), ChatError> {
        self.files_only()?;
        let frame = self.exchange_with_id(Request::StorageUse, now_ms, deadline)?;
        Ok(crewcraft_proto::request::storage_of(&frame))
    }

    fn files_only(&self) -> Result<(), ChatError> {
        if self.files() { Ok(()) } else { Err(ChatError::Unsupported) }
    }

    /// Send `request`, whose `Ok` is followed by an id frame, and return that id.
    fn exchange_with_id(&mut self, request: Request, now_ms: u64, deadline: Instant) -> Result<[u8; 16], ChatError> {
        let id = match self.exchange(request, now_ms, 0, deadline)? {
            (id, Response::Ok { .. }) => id,
            (_, Response::Error { code, .. }) => return Err(ChatError::Rejected(code)),
        };
        loop {
            for event in self.receive(now_ms, 0, deadline)? {
                if let ClientEvent::Id { id: answered, value } = event
                    && answered == id
                {
                    return Ok(value);
                }
            }
        }
    }

    /// A request that needs no room and never fails at the server, to keep an idle connection open.
    pub fn ping(&mut self, now_ms: u64, deadline: Instant) -> Result<(), ChatError> {
        self.request(Request::Ping, now_ms, 0, deadline).map(|_| ())
    }

    /// Follow the room and fetch events after its current cursor. Return the acknowledged head
    /// after the timeline reaches it. A gap or incomplete replay leaves the applied prefix visible.
    pub fn sync(&mut self, room: &str, direct: bool, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<u64, ChatError> {
        let (head, gap) = self.sync_once(room, direct, now_ms, local_minute, deadline)?;
        if !gap {
            return Ok(head);
        }
        self.current(room, head, now_ms, local_minute, deadline)?;
        // One recovery attempt per original operation, even when a busy room has lost another tail meanwhile.
        let (head, gap) = self.sync_once(room, direct, now_ms, local_minute, deadline)?;
        if gap {
            let reached = self.view(room).ok_or(ChatError::Closed)?.cursor();
            Err(ChatError::HistoryGap { reached, head })
        } else {
            // Without a terminal pin/read snapshot, Sync can stop at a post before its file, thread or time
            // sidebands, or at an equal head before call metadata. Ping drains all of them before success.
            if !self.pins_saved() && !self.read_states() && !self.room_settings() {
                self.ping(now_ms, deadline)?;
            }
            Ok(head)
        }
    }

    /// A negotiated explicit gap ends this Sync only after its other metadata has arrived.
    fn sync_once(&mut self, room: &str, direct: bool, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<(u64, bool), ChatError> {
        if self.closed {
            return Err(ChatError::Closed);
        }
        let inbox = self.session.client_mut().inbox_mut();
        inbox.follow(room, direct);
        let start = inbox.view(room).ok_or(ChatError::Closed)?.cursor();
        let head = self.request(Request::Sync { room: room.to_owned(), cursor: start }, now_ms, local_minute, deadline)?;
        let pins_saved = self.pins_saved();
        let read_states = self.read_states();
        let gap_replay = self.features() & FEATURE_GAP_REPLAY != 0;
        let room_settings = self.room_settings();
        if room_settings {
            self.session.client_mut().inbox_mut().view_mut(room).ok_or(ChatError::Closed)?.expect_room_settings();
        }
        if pins_saved {
            // receive() reads exactly one framed payload. Older sideband frames were drained before the matched
            // response, and this response cannot also consume its following pin snapshot.
            self.session.client_mut().inbox_mut().view_mut(room).ok_or(ChatError::Closed)?.expect_pin_state();
        }
        if read_states {
            self.session.client_mut().inbox_mut().view_mut(room).ok_or(ChatError::Closed)?.expect_read_state();
        }

        loop {
            let view = self.view(room).ok_or(ChatError::Closed)?;
            let reached = view.cursor();
            let pin_received = !view.awaiting_pin() && view.pin_revision().is_some_and(|revision| revision >= head);
            let read_received = !view.awaiting_read_state() && view.read_state().is_some_and(|state| state.head >= head);
            let settings_received =
                !room_settings || (!view.awaiting_room_settings() && view.room_settings().is_some_and(|state| state.head >= head));
            let metadata_received = (!pins_saved || pin_received) && (!read_states || read_received) && settings_received;
            if head < start {
                self.closed = true;
                return Err(ChatError::HistoryGap { reached, head });
            }
            if !gap_replay && view.needs_resync() && metadata_received {
                self.closed = !pins_saved && !read_states && !room_settings;
                return Err(ChatError::HistoryGap { reached, head });
            }
            if reached >= head && metadata_received {
                return Ok((head, false));
            }
            // The pin snapshot ends this sync even when retained history cannot replay its prefix. Keep the
            // authoritative pin and a usable transport for saved messages while reporting the history gap.
            if !gap_replay && (pins_saved || read_states || room_settings) && metadata_received && reached < head {
                return Err(ChatError::HistoryGap { reached, head });
            }
            match self.receive(now_ms, local_minute, deadline) {
                Err(ChatError::Io(reason)) => return Err(ChatError::SyncIncomplete { reached, head, reason }),
                Err(error) => return Err(error),
                Ok(events) => {
                    for event in events {
                        if let ClientEvent::Gap { room: of, head: gap_head, after, .. } = event {
                            if !gap_replay || of != room || gap_head != head || after != start {
                                self.closed = true;
                                return Err(ChatError::UnexpectedResponse);
                            }
                            let view = self.view(room).ok_or(ChatError::Closed)?;
                            let pins = !pins_saved || (!view.awaiting_pin() && view.pin_revision().is_some_and(|revision| revision >= head));
                            let reads = !read_states || (!view.awaiting_read_state() && view.read_state().is_some_and(|state| state.head >= head));
                            let settings =
                                !room_settings || (!view.awaiting_room_settings() && view.room_settings().is_some_and(|state| state.head >= head));
                            if !pins || !reads || !settings {
                                self.closed = true;
                                return Err(ChatError::UnexpectedResponse);
                            }
                            return Ok((head, true));
                        }
                    }
                }
            }
        }
    }

    fn current(&mut self, room: &str, gap_head: u64, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<(), ChatError> {
        let (id, head) = match self.exchange(Request::Current { room: room.to_owned() }, now_ms, local_minute, deadline)? {
            (id, Response::Ok { cursor }) => (id, cursor),
            (_, Response::Error { code, .. }) => return Err(ChatError::Rejected(code)),
        };
        let reached = self.view(room).ok_or(ChatError::Closed)?.cursor();
        if head < reached || head < gap_head {
            self.closed = true;
            return Err(ChatError::UnexpectedResponse);
        }
        let mut window = CurrentWindow::new(room, head);
        loop {
            // Capture pages never enter the ordinary push path, so unexpected records cannot change the old view.
            let frame = self.read_frame(frame::MAX_FRAME, deadline)?;
            let (answered, page) = crewcraft_proto::current::decode_page(frame.payload()).map_err(|_| {
                self.closed = true;
                ChatError::UnexpectedResponse
            })?;
            if answered != id {
                self.closed = true;
                return Err(ChatError::UnexpectedResponse);
            }
            let complete = window.page(page, frame.as_bytes().len()).map_err(|_| {
                self.closed = true;
                ChatError::UnexpectedResponse
            })?;
            if complete {
                // Seal the stream before installation. Ordinary receive refuses any page after the last flag;
                // Ping's matched reply proves no duplicate or surplus capture page was left unread.
                self.ping(now_ms, deadline)?;
                let view = self.session.client_mut().inbox_mut().view_mut(room).ok_or(ChatError::Closed)?;
                return view.install_current(window).map_err(|_| {
                    self.closed = true;
                    ChatError::UnexpectedResponse
                });
            }
        }
    }

    pub fn view(&mut self, room: &str) -> Option<&RoomView> {
        self.session.client_mut().inbox().view(room)
    }

    fn authenticate(&mut self, opening: &Opening<'_>, deadline: Instant) -> Result<Zeroizing<String>, ChatError> {
        let request = Zeroizing::new(signin::encode_opening(opening).map_err(|_| ChatError::SignInProtocol)?);
        let framed = Zeroizing::new(frame::encode(&request).map_err(|_| ChatError::SignInProtocol)?);
        self.write_frame(&framed, deadline)?;

        let reply = self.read_frame(SIGN_IN_REPLY_LIMIT, deadline)?;
        match signin::decode_reply(reply.payload()).map_err(|_| ChatError::SignInProtocol)? {
            signin::Reply::Accepted { token } => Ok(Zeroizing::new(token.to_owned())),
            signin::Reply::Refused => Err(ChatError::SignInRefused),
            // An external-sign-in start is only an answer to BeginExternal (task T611a), never to these openings.
            signin::Reply::Ended | signin::Reply::ExternalStart { .. } => Err(ChatError::SignInProtocol),
        }
    }

    fn request(&mut self, request: Request, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<u64, ChatError> {
        match self.exchange(request, now_ms, local_minute, deadline)?.1 {
            Response::Ok { cursor } => Ok(cursor),
            Response::Error { code, .. } => Err(ChatError::Rejected(code)),
        }
    }

    /// Send one request and return its id and matched response.
    fn exchange(&mut self, request: Request, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<(u32, Response), ChatError> {
        if self.closed {
            return Err(ChatError::Closed);
        }
        let frame = self.session.client_mut().send(request, now_ms).map_err(ChatError::Request)?;
        self.write_frame(&frame, deadline)?;

        // There is exactly one request in flight. Client::receive matches its id and ignores old ids.
        loop {
            let events = self.receive(now_ms, local_minute, deadline)?;
            if let Some(ClientEvent::Reply(RequestReply::Done { id, response, .. })) = events.into_iter().next() {
                return Ok((id, response));
            }
        }
    }

    fn receive(&mut self, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<Vec<ClientEvent>, ChatError> {
        let frame = self.read_frame(frame::MAX_FRAME, deadline)?;
        let events = self.session.receive(frame.as_bytes(), now_ms, local_minute).map_err(|error| {
            self.closed = true;
            ChatError::Session(error)
        })?;
        if events.iter().any(|event| matches!(event, ClientEvent::Current { .. } | ClientEvent::Activity { .. })) {
            self.closed = true;
            return Err(ChatError::UnexpectedResponse);
        }
        Ok(events)
    }

    fn prepare_frame(&mut self, deadline: Instant) -> Result<(), ChatError> {
        let now = Instant::now();
        if deadline <= now || self.frame_timeout.is_zero() {
            self.closed = true;
            return Err(ChatError::Io(io::ErrorKind::TimedOut));
        }
        let cutoff = now.checked_add(self.frame_timeout).map_or(deadline, |frame_deadline| frame_deadline.min(deadline));
        (self.set_deadline)(&mut self.stream, cutoff);
        Ok(())
    }

    fn write_frame(&mut self, frame: &[u8], deadline: Instant) -> Result<(), ChatError> {
        self.prepare_frame(deadline)?;
        self.stream.write_all(frame).and_then(|()| self.stream.flush()).map_err(|error| {
            self.closed = true;
            ChatError::Io(error.kind())
        })
    }

    fn read_frame(&mut self, limit: usize, deadline: Instant) -> Result<ReceivedFrame, ChatError> {
        self.prepare_frame(deadline)?;
        match frame::read_frame(&mut self.stream, limit) {
            Ok(Some(frame)) => Ok(frame),
            result => {
                self.closed = true;
                Err(ChatError::Io(result.err().map_or(io::ErrorKind::UnexpectedEof, |error| error.kind())))
            }
        }
    }
}

/// What the server answers to the start of an external sign-in (task T611g).
#[derive(Clone, PartialEq, Eq)]
pub struct ExternalStart {
    pub issuer: String,
    pub client_id: String,
    pub authorization_endpoint: String,
    /// Bound by the server to this device; the provider puts it in the ID token.
    pub nonce: Zeroizing<String>,
}

impl std::fmt::Debug for ExternalStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExternalStart")
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("authorization_endpoint", &self.authorization_endpoint)
            .finish_non_exhaustive()
    }
}

/// Ask the server to begin an external sign-in for this device (task T611g), over a stream that has authenticated the
/// device. `None` when the server has no identity provider, or refuses. The server then closes the connection: the
/// finish comes on a new one.
pub fn begin_external<S: Read + Write>(
    stream: &mut S,
    mut set_deadline: impl FnMut(&mut S, Instant),
    deadline: Instant,
) -> Result<Option<ExternalStart>, ChatError> {
    let request = signin::encode_opening(&Opening::BeginExternal).map_err(|_| ChatError::SignInProtocol)?;
    let framed = frame::encode(&request).map_err(|_| ChatError::SignInProtocol)?;
    set_deadline(stream, deadline);
    stream.write_all(&framed).and_then(|()| stream.flush()).map_err(|error| ChatError::Io(error.kind()))?;
    set_deadline(stream, deadline);
    let reply = match frame::read_frame(stream, EXTERNAL_START_LIMIT) {
        Ok(Some(reply)) => reply,
        Ok(None) => return Err(ChatError::Io(io::ErrorKind::UnexpectedEof)),
        Err(error) => return Err(ChatError::Io(error.kind())),
    };
    match signin::decode_reply(reply.payload()).map_err(|_| ChatError::SignInProtocol)? {
        signin::Reply::ExternalStart { issuer, client_id, authorization_endpoint, nonce } => Ok(Some(ExternalStart {
            issuer: issuer.to_owned(),
            client_id: client_id.to_owned(),
            authorization_endpoint: authorization_endpoint.to_owned(),
            nonce: Zeroizing::new(nonce.to_owned()),
        })),
        signin::Reply::Refused => Ok(None),
        _ => Err(ChatError::SignInProtocol),
    }
}

/// End the session `token` belongs to (task T240), over a stream whose device that session belongs to: the server
/// revokes it and answers `Ended` whether or not there was one. `set_deadline` bounds each frame as in `connect`.
pub fn end_session<S: Read + Write>(
    stream: &mut S,
    mut set_deadline: impl FnMut(&mut S, Instant),
    token: &str,
    deadline: Instant,
) -> Result<(), ChatError> {
    let request = Zeroizing::new(signin::encode_opening(&Opening::End { token }).map_err(|_| ChatError::SignInProtocol)?);
    let framed = Zeroizing::new(frame::encode(&request).map_err(|_| ChatError::SignInProtocol)?);
    set_deadline(stream, deadline);
    stream.write_all(&framed).and_then(|()| stream.flush()).map_err(|error| ChatError::Io(error.kind()))?;
    set_deadline(stream, deadline);
    let reply = match frame::read_frame(stream, SIGN_IN_REPLY_LIMIT) {
        Ok(Some(reply)) => reply,
        Ok(None) => return Err(ChatError::Io(io::ErrorKind::UnexpectedEof)),
        Err(error) => return Err(ChatError::Io(error.kind())),
    };
    match signin::decode_reply(reply.payload()).map_err(|_| ChatError::SignInProtocol)? {
        signin::Reply::Ended => Ok(()),
        _ => Err(ChatError::SignInProtocol),
    }
}
