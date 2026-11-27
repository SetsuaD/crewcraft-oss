//! One signed-in client's connection on the server: bytes in, bytes out. Frames (`proto::frame`, T100) carry requests
//! (`proto::request`, T124); each request is applied with `dispatch::handle` (T128) and answered with exactly one
//! response frame; after a successful `Sync`, the room's events follow as push frames (`proto::push`, T131), and after
//! a `ListRooms` the room-list frame follows (`proto::request::encode_rooms`, T233). Task T135.

use crewcraft_proto::frame::{Decoder, FrameError, encode};
use crewcraft_proto::message::CodecError;
use crewcraft_proto::push::{MAX_MENTIONS, Push, encode_push};
use crewcraft_proto::request::{Request, Response, SearchHit, decode_request, encode_bytes, encode_hits, encode_id, encode_response, encode_rooms};

use crate::cursor_log::Since;
use crate::dispatch::{Backend, handle, handle_backend, listed_rooms};
use crate::durable::{DurableError, DurableServer};
use crate::room_service::{Event, EventKind};
use crate::server::Server;

/// A fatal error: the connection must be closed, and nothing more is sent on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnError {
    /// The frame layer refused the bytes (a frame longer than `frame::MAX_FRAME`).
    Frame(FrameError),
    /// A complete frame is not a request (`decode_request` failed). Its id is unknown, so it cannot be answered.
    Request(CodecError),
}

/// Fatal failure of a connection backed by a durable server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableConnError {
    Protocol(ConnError),
    Storage(DurableError),
}

impl From<ConnError> for DurableConnError {
    fn from(error: ConnError) -> Self {
        Self::Protocol(error)
    }
}

/// Map a room event to its wire push. Redacted posts and edits use the same cursor-only `Push::Other` as membership
/// events. Live posts and edits include their body and up to the first `push::MAX_MENTIONS` mentions, so the push fits
/// the codec's mention limit. A deletion sends `Push::Deleted` with its target.
pub fn to_push(room: &str, cursor: u64, event: &Event) -> Push {
    match &event.kind {
        // Live post and edit bodies are nonempty. Advance through redacted entries without showing or notifying.
        EventKind::Posted | EventKind::Edited { .. } if event.html.is_empty() => Push::Other { room: room.to_string(), cursor },
        EventKind::Posted => {
            Push::Posted { room: room.to_string(), cursor, author: event.actor.clone(), html: event.html.clone(), mentions: first_mentions(event) }
        }
        EventKind::Edited { target } => {
            Push::Edited { room: room.to_string(), cursor, target: *target, html: event.html.clone(), mentions: first_mentions(event) }
        }
        EventKind::Deleted { target } => Push::Deleted { room: room.to_string(), cursor, target: *target },
        EventKind::Joined { .. } | EventKind::Left { .. } | EventKind::Pinned { .. } => Push::Other { room: room.to_string(), cursor },
        EventKind::CallLine { call, ended } => Push::CallLine {
            room: room.to_string(),
            cursor,
            call: *call,
            ended: *ended,
            author: event.actor.clone(),
            text: crate::html_text::html_text(&event.html),
        },
        EventKind::Continued { archive } => Push::Continued {
            room: room.to_string(),
            cursor,
            archive: archive.clone(),
            author: event.actor.clone(),
            text: crate::html_text::html_text(&event.html),
        },
        EventKind::MeetingLine { meeting, change, version } => Push::MeetingLine {
            room: room.to_string(),
            cursor,
            meeting: *meeting,
            change: *change,
            version: *version,
            author: event.actor.clone(),
            text: crate::html_text::html_text(&event.html),
        },
        EventKind::Reacted { target, reaction, on } => {
            Push::Reacted { room: room.to_string(), cursor, target: *target, author: event.actor.clone(), reaction: *reaction, on: *on }
        }
    }
}

fn first_mentions(event: &Event) -> Vec<String> {
    event.mentions.iter().take(MAX_MENTIONS).cloned().collect()
}

pub struct Connection {
    user: String,
    decoder: Decoder,
    /// The features the handshake agreed on: attachments are pushed only with `FEATURE_FILES` (task T330c).
    features: u32,
    /// The signed-in device, when the transport knows it: media credentials name it (task T360b2).
    device: Option<u64>,
    /// A `CallOffer` checked and waiting to be relayed to the media server (task T360b6).
    offer: Option<PendingOffer>,
}

/// A participant's WebRTC offer the chat server must relay to the media server, then answer request `id` with what
/// comes back (task T360b6). The connection checked that the person is in the call; the media server checks the
/// credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingOffer {
    pub id: u32,
    pub call: u64,
    pub credential: Vec<u8>,
    pub offer: String,
}

impl Connection {
    /// A connection for `user` (already signed in), with nothing buffered.
    pub fn new(user: &str) -> Self {
        Self { user: user.to_string(), decoder: Decoder::new(), features: 0, device: None, offer: None }
    }

    /// As `new`, for a session whose handshake agreed on `features` (task T330c).
    pub fn with_features(user: &str, features: u32) -> Self {
        Self { user: user.to_string(), decoder: Decoder::new(), features, device: None, offer: None }
    }

    /// The `CallOffer` the last `receive_durable` stopped at, if any (task T360b6). Its answer has not been written:
    /// the caller relays it to the media server (with no lock held), writes the answer for its id, and only then feeds
    /// the connection again, which goes on with any frames buffered after it.
    pub fn take_offer(&mut self) -> Option<PendingOffer> {
        self.offer.take()
    }

    /// The same connection, for the signed-in `device` (task T360b2): with `FEATURE_MEDIA` and a media server set, a
    /// successful `CallStart` or `CallJoin` is followed by a media credential for this device.
    pub fn with_device(mut self, device: Option<u64>) -> Self {
        self.device = device;
        self
    }

    /// Feed bytes received from the client at `now_ms`. Bytes are buffered until they form whole frames, so a request
    /// may arrive split across calls or several in one call. For each complete frame, in order:
    /// 1. decode the request (`ConnError::Request` on failure);
    /// 2. `dispatch::handle` it as this connection's user, and append the encoded response (`encode_response` with the
    ///    request's id), framed;
    /// 3. if it was a `Sync` and the response is `Ok`: append, framed, one push per event the room still holds after
    ///    the requested cursor (`RoomService::sync`), oldest first, using `to_push`. If the log no longer holds them
    ///    (`Since::Gap`), no timeline pushes follow: the client sees from the response's head that it must resync.
    ///    Negotiated pin, personal read and personal room-settings snapshots still follow a successful sync, including a
    ///    gap or equal head;
    /// 4. if it was a `ListRooms` and the response is `Ok`: append, framed, the room-list frame for this user
    ///    (`dispatch::listed_rooms`, which the response's cursor counts), with the request's id;
    /// 5. if it was a `Search` and the response is `Ok`: append, framed, the hits frame for this user
    ///    (`DurableServer::found`; none without a journal), with the request's id (task T320b).
    ///
    /// Returns everything to send, in that order. On a fatal error, returns only the error: no bytes from this call
    /// are sent and the caller closes the connection.
    pub fn receive(&mut self, server: &mut Server, bytes: &[u8], now_ms: u64) -> Result<Vec<u8>, ConnError> {
        self.receive_with(server, bytes, now_ms, |s, user, _, request, now| Ok((handle(s, user, request, now), None)))
    }

    /// Handle framed requests with the same wire behavior as [Self::receive].
    /// A successful mutation is acknowledged after it is recorded. Any storage
    /// failure is fatal and drops this call's buffered output. Earlier durable
    /// mutations in the same call remain committed.
    pub fn receive_durable(&mut self, server: &mut DurableServer, bytes: &[u8], now_ms: u64) -> Result<Vec<u8>, DurableConnError> {
        server.check_alive().map_err(DurableConnError::Storage)?;
        // Calls whose people stopped sending heartbeats close first (task T360a1).
        server.sweep_calls(now_ms).map_err(DurableConnError::Storage)?;
        let media_device = self.device.filter(|_| self.features & crewcraft_proto::request::FEATURE_MEDIA != 0);
        self.receive_with(server, bytes, now_ms, |s, user, id, request, now| {
            match current_answer(s, user, id, request)
                .or_else(|| upload(s, user, request, now))
                .or_else(|| calls(s, user, request, now, media_device))
                .or_else(|| continuation(s, user, request, now))
                .or_else(|| meetings(s, user, request, now, media_device))
            {
                Some(answer) => answer,
                None => handle_backend(&mut Backend::Durable(s), user, request, now).map(|r| (r, None)).map_err(DurableConnError::Storage),
            }
        })
    }

    fn receive_with<S: Reads, E: From<ConnError>>(
        &mut self,
        server: &mut S,
        bytes: &[u8],
        now_ms: u64,
        mut dispatch: impl FnMut(&mut S, &str, u32, &Request, u64) -> Result<Answered, E>,
    ) -> Result<Vec<u8>, E> {
        self.decoder.push(bytes);
        let mut out = Vec::new();

        while let Some(payload) = self.decoder.next_frame().map_err(ConnError::Frame)? {
            let (id, request) = decode_request(&payload).map_err(ConnError::Request)?;
            let pins_saved = self.features & crewcraft_proto::request::FEATURE_PINS_SAVED != 0;
            let reads = self.features & crewcraft_proto::request::FEATURE_READ_STATE != 0;
            let gap_replay = self.features & crewcraft_proto::request::FEATURE_GAP_REPLAY != 0;
            let continues = self.features & crewcraft_proto::request::FEATURE_CONTINUE != 0;
            let room_settings = self.features & crewcraft_proto::request::FEATURE_ROOM_SETTINGS != 0;
            let meetings_on = self.features & crewcraft_proto::request::FEATURE_MEETINGS != 0;
            let needs_pins_saved = matches!(request, Request::Pin { .. } | Request::SaveMessage { .. } | Request::ListSaved { .. });
            let (response, follow) = if (needs_pins_saved && !pins_saved)
                || (matches!(request, Request::MarkUnread { .. }) && !reads)
                || (matches!(request, Request::Current { .. }) && !gap_replay)
                || (matches!(request, Request::Continue { .. }) && !continues)
                || (matches!(request, Request::SetRoomSetting { .. } | Request::ListRoomSettings) && !room_settings)
                || (is_meeting(&request) && !meetings_on)
            {
                (refusal_of(crate::dispatch::E_NOT_ALLOWED), None)
            } else {
                dispatch(server, &self.user, id, &request, now_ms)?
            };
            // An offer to relay is answered by the caller, after the media server has answered (task T360b6). Nothing
            // after it is read yet, so answers stay in request order.
            if let Some(Follow::Relay { call, credential, offer }) = follow {
                self.offer = Some(PendingOffer { id, call, credential, offer });
                break;
            }
            let resp_bytes = encode_response(id, &response).map_err(ConnError::Request)?;
            let framed_resp = encode(&resp_bytes).map_err(ConnError::Frame)?;
            out.extend_from_slice(&framed_resp);
            // An upload's answer carries the new upload's id or the finished file's (task T330b); a download's, the bytes
            // (task T330d).
            match follow {
                Some(Follow::Current(frames)) => out.extend_from_slice(&frames),
                Some(Follow::Id(value)) => out.extend_from_slice(&encode(&encode_id(id, &value)).map_err(ConnError::Frame)?),
                Some(Follow::Files(files)) => {
                    let frame = crewcraft_proto::request::encode_files(id, &files).map_err(ConnError::Request)?;
                    out.extend_from_slice(&encode(&frame).map_err(ConnError::Frame)?);
                }
                Some(Follow::Bytes(data)) => {
                    out.extend_from_slice(&encode(&encode_bytes(id, &data).map_err(ConnError::Request)?).map_err(ConnError::Frame)?);
                }
                Some(Follow::Saved(page)) => {
                    let frame = crewcraft_proto::request::encode_saved(id, &page).map_err(ConnError::Request)?;
                    out.extend_from_slice(&encode(&frame).map_err(ConnError::Frame)?);
                }
                Some(Follow::Media { address, credential }) => {
                    let frame = crewcraft_proto::request::encode_media(id, &address, &credential).map_err(ConnError::Request)?;
                    out.extend_from_slice(&encode(&frame).map_err(ConnError::Frame)?);
                }
                Some(Follow::Continued(room)) => {
                    let frame = crewcraft_proto::request::encode_continued(id, &room).map_err(ConnError::Request)?;
                    out.extend_from_slice(&encode(&frame).map_err(ConnError::Frame)?);
                }
                Some(Follow::Meetings(page)) => {
                    let frame = crewcraft_proto::meeting::encode_meetings(id, &page).map_err(ConnError::Request)?;
                    out.extend_from_slice(&encode(&frame).map_err(ConnError::Frame)?);
                }
                Some(Follow::Relay { .. }) | None => {}
            }

            // After a successful Sync, append the room's events as push frames.
            if let Request::Sync { room, cursor } = &request
                && matches!(response, Response::Ok { .. })
                && let Ok(service) = server.server().room(room)
                && let Ok(Since::Events(events)) = service.sync(&self.user, *cursor)
            {
                let archive = self.features & crewcraft_proto::request::FEATURE_ARCHIVE != 0;
                let calls_on = self.features & crewcraft_proto::request::FEATURE_CALLS != 0;
                // The room's open call, before its events (task T360a1).
                if calls_on {
                    for state in server.call_state(room, &self.user) {
                        out.extend_from_slice(&encode(&encode_push(&state).map_err(ConnError::Request)?).map_err(ConnError::Frame)?);
                    }
                }
                // An archive room says so before its events (task T350d1).
                if archive && service.is_read_only() {
                    let archived = encode_push(&Push::Archived { room: room.clone(), cursor: 0 }).map_err(ConnError::Request)?;
                    out.extend_from_slice(&encode(&archived).map_err(ConnError::Frame)?);
                }
                for (ev_cursor, ev) in events {
                    let mut push = to_push(room, ev_cursor, &ev);
                    // A client that did not agree to reactions only advances past them (task T341a).
                    if matches!(push, Push::Reacted { .. }) && self.features & crewcraft_proto::request::FEATURE_REACTIONS == 0 {
                        push = Push::Other { room: room.clone(), cursor: ev_cursor };
                    }
                    // Nor to calls, past their history lines (task T360a1).
                    if matches!(push, Push::CallLine { .. }) && !calls_on {
                        push = Push::Other { room: room.clone(), cursor: ev_cursor };
                    }
                    // Nor to continuing archives, past the line that links back to one (task T352).
                    if matches!(push, Push::Continued { .. }) && !continues {
                        push = Push::Other { room: room.clone(), cursor: ev_cursor };
                    }
                    // Nor to meetings, past their system lines (task T370a).
                    if matches!(push, Push::MeetingLine { .. }) && !meetings_on {
                        push = Push::Other { room: room.clone(), cursor: ev_cursor };
                    }
                    let posted = matches!(push, Push::Posted { .. });
                    let push_bytes = encode_push(&push).map_err(ConnError::Request)?;
                    let framed_push = encode(&push_bytes).map_err(ConnError::Frame)?;
                    out.extend_from_slice(&framed_push);
                    // An imported message's original time follows its push (task T350d1).
                    if posted
                        && archive
                        && let Some(sent_ms) = server.sent_of(room, ev_cursor)
                    {
                        let sent = encode_push(&Push::Sent { room: room.clone(), cursor: ev_cursor, sent_ms }).map_err(ConnError::Request)?;
                        out.extend_from_slice(&encode(&sent).map_err(ConnError::Frame)?);
                    }
                    // A reply's thread follows its push, for a client that agreed to threads (task T340a).
                    if posted
                        && self.features & crewcraft_proto::request::FEATURE_THREADS != 0
                        && let Some(parent) = server.parent_of(room, ev_cursor)
                    {
                        let threaded = encode_push(&Push::Threaded { room: room.clone(), cursor: ev_cursor, parent }).map_err(ConnError::Request)?;
                        out.extend_from_slice(&encode(&threaded).map_err(ConnError::Frame)?);
                    }
                    // A message's files follow its push, for a client that agreed to them (task T330c).
                    if posted && self.features & crewcraft_proto::request::FEATURE_FILES != 0 {
                        let files = server.attachments(room, ev_cursor);
                        if !files.is_empty() {
                            let attached =
                                encode_push(&Push::Attached { room: room.clone(), cursor: ev_cursor, files }).map_err(ConnError::Request)?;
                            out.extend_from_slice(&encode(&attached).map_err(ConnError::Frame)?);
                        }
                    }
                }
            }
            if let Request::ListRooms = request
                && matches!(response, Response::Ok { .. })
            {
                let rooms = encode_rooms(id, &listed_rooms(server.server(), &self.user)).map_err(ConnError::Request)?;
                out.extend_from_slice(&encode(&rooms).map_err(ConnError::Frame)?);
            }
            // The complete pin projection follows every successful sync, even when the event tail has a gap.
            // Its cursor is a room-head revision, so a client never treats the snapshot as another timeline event.
            if let Request::Sync { room, .. } = &request
                && pins_saved
                && matches!(response, Response::Ok { .. })
                && let Some(pinned) = server.pin_state(room, &self.user)
            {
                let frame = encode_push(&pinned).map_err(ConnError::Request)?;
                out.extend_from_slice(&encode(&frame).map_err(ConnError::Frame)?);
            }
            // Personal read metadata changes independently of the room's event head and follows even an empty sync.
            if let Request::Sync { room, .. } = &request
                && reads
                && matches!(response, Response::Ok { .. })
                && let Some(state) = server.read_state(room, &self.user)
            {
                let frame = encode_push(&state).map_err(ConnError::Request)?;
                out.extend_from_slice(&encode(&frame).map_err(ConnError::Frame)?);
            }
            // The person's own room settings follow every successful sync, before any gap (task T346).
            if let Request::Sync { room, .. } = &request
                && room_settings
                && matches!(response, Response::Ok { .. })
                && let Ok(service) = server.server().room(room)
                && let Ok((settings, revision)) = service.room_settings(&self.user)
            {
                let push = Push::RoomSettings { room: room.clone(), cursor: service.head(), revision, settings };
                out.extend_from_slice(&encode(&encode_push(&push).map_err(ConnError::Request)?).map_err(ConnError::Frame)?);
            }
            // After a successful ListRoomSettings, the settings frame its answer counted (task T346).
            if let Request::ListRoomSettings = request
                && matches!(response, Response::Ok { .. })
            {
                let rows = crate::dispatch::listed_room_settings(server.server(), &self.user);
                let frame = crewcraft_proto::room_settings::encode_list(id, &rows).map_err(ConnError::Request)?;
                out.extend_from_slice(&encode(&frame).map_err(ConnError::Frame)?);
            }
            // After a successful Search, the hits frame (task T320b), as the response counted them.
            if let Request::Search { query } = &request
                && matches!(response, Response::Ok { .. })
            {
                let hits = encode_hits(id, &server.found(&self.user, query)).map_err(ConnError::Request)?;
                out.extend_from_slice(&encode(&hits).map_err(ConnError::Frame)?);
            }
            // This is deliberately the last frame of a successful gapped Sync: drain all negotiated metadata
            // before starting Current. Older clients retain their original explicit HistoryGap behavior.
            if let Request::Sync { room, cursor } = &request
                && gap_replay
                && matches!(response, Response::Ok { .. })
                && let Ok(service) = server.server().room(room)
                && let Ok(Since::Gap { oldest }) = service.sync(&self.user, *cursor)
            {
                let gap = Push::Gap { room: room.clone(), cursor: service.head(), after: *cursor, oldest };
                let frame = encode_push(&gap).map_err(ConnError::Request)?;
                out.extend_from_slice(&encode(&frame).map_err(ConnError::Frame)?);
            }
        }

        Ok(out)
    }
}

/// What a connection reads from the server it serves, besides dispatching requests. The in-memory server has rooms and
/// pinned messages and personal read positions; the durable one adds search, files, threads, imported times and calls.
trait Reads {
    fn server(&self) -> &Server;
    fn found(&self, user: &str, query: &str) -> Vec<SearchHit>;
    fn attachments(&self, room: &str, cursor: u64) -> Vec<crewcraft_proto::push::AttachedFile>;
    fn parent_of(&self, room: &str, cursor: u64) -> Option<u64>;
    fn sent_of(&self, room: &str, cursor: u64) -> Option<u64>;
    fn call_state(&self, room: &str, user: &str) -> Vec<Push>;
    fn pin_state(&self, room: &str, user: &str) -> Option<Push>;
    fn read_state(&self, room: &str, user: &str) -> Option<Push>;
}

impl Reads for Server {
    fn server(&self) -> &Server {
        self
    }
    fn found(&self, _: &str, _: &str) -> Vec<SearchHit> {
        Vec::new()
    }
    fn attachments(&self, _: &str, _: u64) -> Vec<crewcraft_proto::push::AttachedFile> {
        Vec::new()
    }
    fn parent_of(&self, _: &str, _: u64) -> Option<u64> {
        None
    }
    fn sent_of(&self, _: &str, _: u64) -> Option<u64> {
        None
    }
    fn call_state(&self, _: &str, _: &str) -> Vec<Push> {
        Vec::new()
    }
    fn pin_state(&self, room: &str, user: &str) -> Option<Push> {
        memory_pin_state(self, room, user)
    }
    fn read_state(&self, room: &str, user: &str) -> Option<Push> {
        memory_read_state(self, room, user)
    }
}

impl Reads for DurableServer {
    fn server(&self) -> &Server {
        DurableServer::server(self)
    }
    fn found(&self, user: &str, query: &str) -> Vec<SearchHit> {
        DurableServer::found(self, user, query)
    }
    fn attachments(&self, room: &str, cursor: u64) -> Vec<crewcraft_proto::push::AttachedFile> {
        DurableServer::attachments(self, room, cursor)
    }
    fn parent_of(&self, room: &str, cursor: u64) -> Option<u64> {
        DurableServer::parent_of(self, room, cursor)
    }
    fn sent_of(&self, room: &str, cursor: u64) -> Option<u64> {
        self.imported_sent_ms(room, cursor)
    }
    fn call_state(&self, room: &str, user: &str) -> Vec<Push> {
        call_state(self, room, user)
    }
    fn pin_state(&self, room: &str, user: &str) -> Option<Push> {
        DurableServer::pin_state(self, room, user)
    }
    fn read_state(&self, room: &str, user: &str) -> Option<Push> {
        DurableServer::read_state(self, room, user)
    }
}

fn memory_pin_state(server: &Server, slug: &str, user: &str) -> Option<Push> {
    let room = server.room(slug).ok()?;
    room.role(user)?;
    let (target, author, html, edited) = room.pinned_content().unwrap_or_default();
    Some(Push::Pinned { room: slug.to_owned(), cursor: room.head(), target, author, html, edited })
}

fn memory_read_state(server: &Server, slug: &str, user: &str) -> Option<Push> {
    let room = server.room(slug).ok()?;
    let (position, revision) = room.read_position(user).ok()?;
    let unread = room.unread(user).ok()? as u64;
    Some(Push::ReadState { room: slug.to_owned(), cursor: room.head(), position, revision, unread })
}

/// Build the complete bounded reply before returning its acknowledgement; storage failures remain fatal.
fn current_answer(server: &DurableServer, user: &str, id: u32, request: &Request) -> Option<Result<Answered, DurableConnError>> {
    use crate::current::CurrentError;
    let Request::Current { room } = request else { return None };
    Some(match server.current(room, user, id) {
        Ok((head, frames)) => Ok((Response::Ok { cursor: head }, Some(Follow::Current(frames)))),
        Err(CurrentError::NoSuchRoom) => Ok((refusal_of(crate::dispatch::E_NO_SUCH_ROOM), None)),
        Err(CurrentError::Unavailable) => Ok((refusal_of(crate::dispatch::E_NO_STORAGE), None)),
        Err(CurrentError::TooLarge) => Ok((refusal_of(crate::dispatch::E_OTHER), None)),
        Err(CurrentError::Storage(error)) => Err(DurableConnError::Storage(error)),
    })
}

/// Answer a call request over a durable server (task T360a1): `None` for any other request. `Ok { cursor }` carries
/// the call's id; a refusal is an `Error`; a storage failure is fatal. With `media_device` (the client agreed to
/// `FEATURE_MEDIA` and its device is known), a started or joined call is followed by that device's media credential
/// (task T360b2).
fn calls(
    server: &mut DurableServer,
    user: &str,
    request: &Request,
    now_ms: u64,
    media_device: Option<u64>,
) -> Option<Result<Answered, DurableConnError>> {
    use crate::calls::{CallError, SealedKey};
    let answer = match request {
        Request::CallStart { room, video } => server.call_start(room, user, *video, now_ms),
        Request::CallJoin { room, call } => server.call_join(room, user, *call, now_ms).map(|()| *call),
        Request::CallHeartbeat { room, call } => server.call_heartbeat(room, user, *call, now_ms).map(|()| *call),
        Request::CallLeave { room, call } => server.call_leave(room, user, *call, now_ms).map(|()| *call),
        Request::CallKey { room, call, public } => server.call_key(room, user, *call, *public, now_ms).map(|()| *call),
        Request::CallSeal { room, call, to, kid, sealed } => {
            server.call_seal(room, user, *call, SealedKey { to, kid: *kid, sealed: sealed.clone() }, now_ms).map(|()| *call)
        }
        // An offer needs media agreed and the device known; then only someone in the call may send one (task T360b6).
        Request::CallOffer { .. } if media_device.is_none() => Err(CallError::NotAllowed),
        Request::CallOffer { room, call, .. } => server.may_offer(room, user, *call).map(|()| *call),
        _ => return None,
    };
    Some(match answer {
        Ok(call) => {
            let follow = match (media_device, request) {
                (Some(device), Request::CallStart { room, .. } | Request::CallJoin { room, .. }) => {
                    media_follow(server, room, user, call, device, now_ms)
                }
                (_, Request::CallOffer { credential, offer, .. }) => {
                    Some(Follow::Relay { call, credential: credential.clone(), offer: offer.clone() })
                }
                _ => None,
            };
            Ok((Response::Ok { cursor: call }, follow))
        }
        Err(CallError::NotMember) => Ok((refusal_of(crate::dispatch::E_NO_SUCH_ROOM), None)),
        Err(CallError::NotAllowed) => Ok((refusal_of(crate::dispatch::E_NOT_ALLOWED), None)),
        Err(CallError::NoSuchCall) => Ok((refusal_of(crate::dispatch::E_NO_SUCH_CALL), None)),
        Err(CallError::MediaUnusable) => Ok((refusal_of(crate::dispatch::E_NOT_ALLOWED), None)),
        Err(CallError::Durable(error)) => Err(DurableConnError::Storage(error)),
    })
}

/// Answer `Continue` over a durable server (task T352): `None` for any other request. A person who cannot read the
/// room is answered as for a room that does not exist; a room that is not an archive is not allowed; a storage failure
/// is fatal.
fn continuation(server: &mut DurableServer, user: &str, request: &Request, now_ms: u64) -> Option<Result<Answered, DurableConnError>> {
    use crate::continuation::ContinueError;
    let Request::Continue { archive } = request else { return None };
    Some(match server.continue_archive(archive, user, now_ms) {
        // A room no request could name is never answered as the continuation.
        Ok(room) if room.is_empty() || room.len() > crewcraft_proto::message::MAX_NAME => Ok((refusal_of(crate::dispatch::E_OTHER), None)),
        Ok(room) => Ok((Response::Ok { cursor: 0 }, Some(Follow::Continued(room)))),
        Err(ContinueError::NotReadable) => Ok((refusal_of(crate::dispatch::E_NO_SUCH_ROOM), None)),
        Err(ContinueError::NotArchive) => Ok((refusal_of(crate::dispatch::E_NOT_ALLOWED), None)),
        Err(ContinueError::Durable(DurableError::Server(error))) => Ok((refusal_of(crate::dispatch::error_code(error)), None)),
        Err(ContinueError::Durable(error)) => Err(DurableConnError::Storage(error)),
    })
}

/// Whether `request` is one of the meeting requests, which need `FEATURE_MEETINGS` (task T370a).
fn is_meeting(request: &Request) -> bool {
    matches!(request, Request::MeetingSave { .. } | Request::MeetingCancel { .. } | Request::MeetingList { .. } | Request::MeetingJoin { .. })
}

/// Answer a meeting request over a durable server (task T370a): `None` for any other request. A saved meeting is
/// answered with its id and followed by a meetings frame holding it; a cancel with the new version; a list with the
/// count and a meetings frame; a join as `CallStart` is (the call's id, and with `media_device` the media frame). A
/// refusal is an `Error` (`dispatch::meeting_error_code`); a storage failure is fatal.
fn meetings(
    server: &mut DurableServer,
    user: &str,
    request: &Request,
    now_ms: u64,
    media_device: Option<u64>,
) -> Option<Result<Answered, DurableConnError>> {
    use crate::meetings::{Draft, MeetingError};
    use crewcraft_proto::meeting::MeetingPage;
    let answer = match request {
        Request::MeetingSave { room, meeting, version, start_ms, duration, title, agenda } => {
            let draft = Draft { title, start_ms: *start_ms, duration: *duration, agenda };
            let saved = if *meeting == 0 {
                server.schedule_meeting(room, user, &draft, now_ms)
            } else {
                server.edit_meeting(room, user, *meeting, *version, &draft, now_ms).map(|_| *meeting)
            };
            saved.map(|id| {
                let page = MeetingPage { meetings: server.meeting_for(user, id).into_iter().collect(), more: false };
                (Response::Ok { cursor: id }, Some(Follow::Meetings(page)))
            })
        }
        Request::MeetingCancel { room, meeting, version } => {
            server.cancel_meeting(room, user, *meeting, *version, now_ms).map(|version| (Response::Ok { cursor: version }, None))
        }
        Request::MeetingList { from_ms, to_ms } => server
            .meetings_between(user, *from_ms, *to_ms)
            .map(|page| (Response::Ok { cursor: page.meetings.len() as u64 }, Some(Follow::Meetings(page)))),
        Request::MeetingJoin { meeting } => server.join_meeting(user, *meeting, now_ms).map(|(room, call)| {
            let follow = media_device.and_then(|device| media_follow(server, &room, user, call, device, now_ms));
            (Response::Ok { cursor: call }, follow)
        }),
        _ => return None,
    };
    Some(match answer {
        Ok(answered) => Ok(answered),
        Err(MeetingError::Durable(DurableError::Server(error))) => Ok((refusal_of(crate::dispatch::error_code(error)), None)),
        Err(MeetingError::Durable(error)) => Err(DurableConnError::Storage(error)),
        Err(error) => Ok((refusal_of(crate::dispatch::meeting_error_code(error)), None)),
    })
}

/// The media credential frame for `device` of `user`, just admitted to `call` of `room` (task T360b2). None when
/// issuing failed (`CallError::MediaUnusable`): the person is in the call, without media. A server announces
/// `FEATURE_MEDIA` only with a media server set, so a client that agreed to it and gets no frame knows issuing failed.
fn media_follow(server: &DurableServer, room: &str, user: &str, call: u64, device: u64, now_ms: u64) -> Option<Follow> {
    let credential = server.media_credential(room, user, call, device, now_ms).ok().flatten()?;
    let address = server.media_address()?.to_owned();
    Some(Follow::Media { address, credential })
}

/// The open call of `room` for `user`: its `CallState`, the participants' call keys, and the sender keys sealed to
/// `user` (tasks T360a1, T360d2).
fn call_state(server: &DurableServer, room: &str, user: &str) -> Vec<Push> {
    let Some(call) = server.open_call(room) else { return Vec::new() };
    let mut pushes = vec![Push::CallState {
        room: room.to_owned(),
        cursor: 0,
        call: call.id,
        video: call.video,
        started_by: call.started_by.clone(),
        started_ms: call.started_ms,
        participants: call.present.keys().take(crewcraft_proto::push::MAX_PARTICIPANTS).cloned().collect(),
    }];
    if !call.keys.is_empty() {
        let keys = call.keys.iter().take(crewcraft_proto::push::MAX_PARTICIPANTS).map(|(person, key)| (person.clone(), *key)).collect();
        pushes.push(Push::CallKeys { room: room.to_owned(), cursor: 0, call: call.id, keys });
    }
    for ((to, from, kid), sealed) in &call.sealed {
        if to == user {
            pushes.push(Push::CallSealed { room: room.to_owned(), cursor: 0, call: call.id, from: from.clone(), kid: *kid, sealed: sealed.clone() });
        }
    }
    pushes
}

/// Answer an upload request over a durable server (task T330b): `None` for any other request. A refusal is an `Error`
/// with `dispatch::upload_error_code`; a storage failure (the journal, or a poisoned server) is fatal.
fn upload(server: &mut DurableServer, user: &str, request: &Request, now_ms: u64) -> Option<Result<Answered, DurableConnError>> {
    use crate::durable::UploadError;
    let answer = match request {
        Request::UploadBegin { room, name, size, sha256 } => {
            server.begin_upload(user, room, name, *size, *sha256, now_ms).map(|id| (0, Some(Follow::Id(id))))
        }
        Request::UploadChunk { upload, offset, bytes } => server.upload_chunk(user, upload, *offset, bytes, now_ms).map(|received| (received, None)),
        Request::UploadFinish { upload } => server.finish_upload(user, upload, now_ms).map(|file| (0, Some(Follow::Id(file)))),
        Request::PostFiles { room, text, files } => {
            return Some(match server.post_files(room, user, text, files, now_ms) {
                Ok(cursor) => Ok((Response::Ok { cursor }, None)),
                Err(crate::durable::AttachError::BadAttachment) => Ok((refusal_of(crate::dispatch::E_BAD_ATTACHMENT), None)),
                Err(crate::durable::AttachError::Durable(DurableError::Server(error))) => Ok((refusal_of(crate::dispatch::error_code(error)), None)),
                Err(crate::durable::AttachError::Durable(error)) => Err(DurableConnError::Storage(error)),
            });
        }
        Request::Reply { room, parent, text } => {
            return Some(match server.reply(room, user, *parent, text, now_ms) {
                Ok(cursor) => Ok((Response::Ok { cursor }, None)),
                Err(crate::durable::ReplyError::NoParent) => Ok((refusal_of(crate::dispatch::E_NO_SUCH_MESSAGE), None)),
                Err(crate::durable::ReplyError::Durable(DurableError::Server(error))) => Ok((refusal_of(crate::dispatch::error_code(error)), None)),
                Err(crate::durable::ReplyError::Durable(error)) => Err(DurableConnError::Storage(error)),
            });
        }
        Request::StorageUse => {
            let used = server.storage_used(user);
            let frame = crewcraft_proto::request::storage_frame(used, server.quota());
            return Some(Ok((Response::Ok { cursor: used }, Some(Follow::Id(frame)))));
        }
        Request::ListFiles => {
            let files = server.listed_files(user);
            return Some(Ok((Response::Ok { cursor: files.len() as u64 }, Some(Follow::Files(files)))));
        }
        Request::SaveMessage { room, target, on } => {
            return Some(match server.save_message(room, user, *target, *on) {
                Ok(()) => Ok((Response::Ok { cursor: 0 }, None)),
                Err(DurableError::Server(error)) => Ok((refusal_of(crate::dispatch::error_code(error)), None)),
                Err(error) => Err(DurableConnError::Storage(error)),
            });
        }
        Request::ListSaved { after_room, after_cursor } => {
            let page = server.saved(user, after_room, *after_cursor);
            return Some(Ok((Response::Ok { cursor: page.messages.len() as u64 }, Some(Follow::Saved(page)))));
        }
        Request::Download { file, offset, length } => {
            return Some(Ok(match server.download(user, file, *offset, *length as usize) {
                Ok(data) => (Response::Ok { cursor: data.len() as u64 }, Some(Follow::Bytes(data))),
                Err(crate::durable::DownloadError::NotFound) => (refusal_of(crate::dispatch::E_NO_SUCH_FILE), None),
                Err(crate::durable::DownloadError::NoStorage) => (refusal_of(crate::dispatch::E_NO_STORAGE), None),
                Err(crate::durable::DownloadError::Storage) => (refusal_of(crate::dispatch::E_OTHER), None),
            }));
        }
        _ => return None,
    };
    Some(match answer {
        Ok((cursor, follow)) => Ok((Response::Ok { cursor }, follow)),
        Err(UploadError::Durable(error)) => Err(DurableConnError::Storage(error)),
        Err(error) => Ok((Response::Error { code: crate::dispatch::upload_error_code(error), detail: String::new() }, None)),
    })
}

/// What follows a request's answer, when anything does: an id frame (an upload's id or a file's, task T330b) or a
/// bytes frame (a download, task T330d).
enum Follow {
    /// Already bounded, encoded follow pages captured at one room head (T345).
    Current(Vec<u8>),
    Id([u8; 16]),
    Bytes(Vec<u8>),
    /// The files frame answering `ListFiles` (task T331a).
    Files(Vec<crewcraft_proto::request::ListedFile>),
    Saved(crewcraft_proto::request::SavedPage),
    /// The media frame after a started or joined call (task T360b2).
    Media {
        address: String,
        credential: Vec<u8>,
    },
    /// The continued frame: the room an archive continues in (task T352).
    Continued(String),
    /// The meetings frame after a saved meeting or a list (task T370a).
    Meetings(crewcraft_proto::meeting::MeetingPage),
    /// An offer for the media server: the caller relays it and answers (task T360b6).
    Relay {
        call: u64,
        credential: Vec<u8>,
        offer: String,
    },
}

/// A request's answer, and what follows it.
type Answered = (Response, Option<Follow>);

fn refusal_of(code: u16) -> Response {
    Response::Error { code, detail: String::new() }
}
