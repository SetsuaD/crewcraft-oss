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
}

impl Connection {
    /// A connection for `user` (already signed in), with nothing buffered.
    pub fn new(user: &str) -> Self {
        Self { user: user.to_string(), decoder: Decoder::new(), features: 0 }
    }

    /// As `new`, for a session whose handshake agreed on `features` (task T330c).
    pub fn with_features(user: &str, features: u32) -> Self {
        Self { user: user.to_string(), decoder: Decoder::new(), features }
    }

    /// Feed bytes received from the client at `now_ms`. Bytes are buffered until they form whole frames, so a request
    /// may arrive split across calls or several in one call. For each complete frame, in order:
    /// 1. decode the request (`ConnError::Request` on failure);
    /// 2. `dispatch::handle` it as this connection's user, and append the encoded response (`encode_response` with the
    ///    request's id), framed;
    /// 3. if it was a `Sync` and the response is `Ok`: append, framed, one push per event the room still holds after
    ///    the requested cursor (`RoomService::sync`), oldest first, using `to_push`. If the log no longer holds them
    ///    (`Since::Gap`), no pushes follow: the client sees from the response's head that it must resync;
    /// 4. if it was a `ListRooms` and the response is `Ok`: append, framed, the room-list frame for this user
    ///    (`dispatch::listed_rooms`, which the response's cursor counts), with the request's id;
    /// 5. if it was a `Search` and the response is `Ok`: append, framed, the hits frame for this user
    ///    (`DurableServer::found`; none without a journal), with the request's id (task T320b).
    ///
    /// Returns everything to send, in that order. On a fatal error, returns only the error: no bytes from this call
    /// are sent and the caller closes the connection.
    pub fn receive(&mut self, server: &mut Server, bytes: &[u8], now_ms: u64) -> Result<Vec<u8>, ConnError> {
        self.receive_with(
            server,
            bytes,
            now_ms,
            |s, user, request, now| Ok((handle(s, user, request, now), None)),
            |s| s,
            |_, _, _| Vec::new(),
            |_, _, _| Vec::new(),
            |_, _, _| None,
            |_, _, _| None,
            |_, _, _| Vec::new(),
            memory_pin_state,
        )
    }

    /// Handle framed requests with the same wire behavior as [Self::receive].
    /// A successful mutation is acknowledged after it is recorded. Any storage
    /// failure is fatal and drops this call's buffered output. Earlier durable
    /// mutations in the same call remain committed.
    pub fn receive_durable(&mut self, server: &mut DurableServer, bytes: &[u8], now_ms: u64) -> Result<Vec<u8>, DurableConnError> {
        server.check_alive().map_err(DurableConnError::Storage)?;
        // Calls whose people stopped sending heartbeats close first (task T360a1).
        server.sweep_calls(now_ms).map_err(DurableConnError::Storage)?;
        self.receive_with(
            server,
            bytes,
            now_ms,
            |s, user, request, now| match upload(s, user, request, now).or_else(|| calls(s, user, request, now)) {
                Some(answer) => answer,
                None => handle_backend(&mut Backend::Durable(s), user, request, now).map(|r| (r, None)).map_err(DurableConnError::Storage),
            },
            DurableServer::server,
            DurableServer::found,
            DurableServer::attachments,
            DurableServer::parent_of,
            DurableServer::imported_sent_ms,
            call_state,
            DurableServer::pin_state,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn receive_with<S, E: From<ConnError>>(
        &mut self,
        server: &mut S,
        bytes: &[u8],
        now_ms: u64,
        mut dispatch: impl FnMut(&mut S, &str, &Request, u64) -> Result<Answered, E>,
        read: impl Fn(&S) -> &Server,
        found: impl Fn(&S, &str, &str) -> Vec<SearchHit>,
        attachments: impl Fn(&S, &str, u64) -> Vec<crewcraft_proto::push::AttachedFile>,
        parent_of: impl Fn(&S, &str, u64) -> Option<u64>,
        sent_of: impl Fn(&S, &str, u64) -> Option<u64>,
        call_state: impl Fn(&S, &str, &str) -> Vec<Push>,
        pin_state: impl Fn(&S, &str, &str) -> Option<Push>,
    ) -> Result<Vec<u8>, E> {
        self.decoder.push(bytes);
        let mut out = Vec::new();

        while let Some(payload) = self.decoder.next_frame().map_err(ConnError::Frame)? {
            let (id, request) = decode_request(&payload).map_err(ConnError::Request)?;
            let pins_saved = self.features & crewcraft_proto::request::FEATURE_PINS_SAVED != 0;
            let needs_pins_saved = matches!(request, Request::Pin { .. } | Request::SaveMessage { .. } | Request::ListSaved { .. });
            let (response, follow) = if needs_pins_saved && !pins_saved {
                (refusal_of(crate::dispatch::E_NOT_ALLOWED), None)
            } else {
                dispatch(server, &self.user, &request, now_ms)?
            };
            let resp_bytes = encode_response(id, &response).map_err(ConnError::Request)?;
            let framed_resp = encode(&resp_bytes).map_err(ConnError::Frame)?;
            out.extend_from_slice(&framed_resp);
            // An upload's answer carries the new upload's id or the finished file's (task T330b); a download's, the bytes
            // (task T330d).
            match follow {
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
                None => {}
            }

            // After a successful Sync, append the room's events as push frames.
            if let Request::Sync { room, cursor } = &request
                && matches!(response, Response::Ok { .. })
                && let Ok(service) = read(server).room(room)
                && let Ok(Since::Events(events)) = service.sync(&self.user, *cursor)
            {
                let archive = self.features & crewcraft_proto::request::FEATURE_ARCHIVE != 0;
                let calls_on = self.features & crewcraft_proto::request::FEATURE_CALLS != 0;
                // The room's open call, before its events (task T360a1).
                if calls_on {
                    for state in call_state(server, room, &self.user) {
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
                    let posted = matches!(push, Push::Posted { .. });
                    let push_bytes = encode_push(&push).map_err(ConnError::Request)?;
                    let framed_push = encode(&push_bytes).map_err(ConnError::Frame)?;
                    out.extend_from_slice(&framed_push);
                    // An imported message's original time follows its push (task T350d1).
                    if posted
                        && archive
                        && let Some(sent_ms) = sent_of(server, room, ev_cursor)
                    {
                        let sent = encode_push(&Push::Sent { room: room.clone(), cursor: ev_cursor, sent_ms }).map_err(ConnError::Request)?;
                        out.extend_from_slice(&encode(&sent).map_err(ConnError::Frame)?);
                    }
                    // A reply's thread follows its push, for a client that agreed to threads (task T340a).
                    if posted
                        && self.features & crewcraft_proto::request::FEATURE_THREADS != 0
                        && let Some(parent) = parent_of(server, room, ev_cursor)
                    {
                        let threaded = encode_push(&Push::Threaded { room: room.clone(), cursor: ev_cursor, parent }).map_err(ConnError::Request)?;
                        out.extend_from_slice(&encode(&threaded).map_err(ConnError::Frame)?);
                    }
                    // A message's files follow its push, for a client that agreed to them (task T330c).
                    if posted && self.features & crewcraft_proto::request::FEATURE_FILES != 0 {
                        let files = attachments(server, room, ev_cursor);
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
                let rooms = encode_rooms(id, &listed_rooms(read(server), &self.user)).map_err(ConnError::Request)?;
                out.extend_from_slice(&encode(&rooms).map_err(ConnError::Frame)?);
            }
            // The complete pin projection follows every successful sync, even when the event tail has a gap.
            // Its cursor is a room-head revision, so a client never treats the snapshot as another timeline event.
            if let Request::Sync { room, .. } = &request
                && pins_saved
                && matches!(response, Response::Ok { .. })
                && let Some(pinned) = pin_state(server, room, &self.user)
            {
                let frame = encode_push(&pinned).map_err(ConnError::Request)?;
                out.extend_from_slice(&encode(&frame).map_err(ConnError::Frame)?);
            }
            // After a successful Search, the hits frame (task T320b), as the response counted them.
            if let Request::Search { query } = &request
                && matches!(response, Response::Ok { .. })
            {
                let hits = encode_hits(id, &found(server, &self.user, query)).map_err(ConnError::Request)?;
                out.extend_from_slice(&encode(&hits).map_err(ConnError::Frame)?);
            }
        }

        Ok(out)
    }
}

fn memory_pin_state(server: &Server, slug: &str, user: &str) -> Option<Push> {
    let room = server.room(slug).ok()?;
    room.role(user)?;
    let (target, author, html, edited) = room.pinned_content().unwrap_or_default();
    Some(Push::Pinned { room: slug.to_owned(), cursor: room.head(), target, author, html, edited })
}

/// Answer a call request over a durable server (task T360a1): `None` for any other request. `Ok { cursor }` carries
/// the call's id; a refusal is an `Error`; a storage failure is fatal.
fn calls(server: &mut DurableServer, user: &str, request: &Request, now_ms: u64) -> Option<Result<Answered, DurableConnError>> {
    use crate::calls::CallError;
    let answer = match request {
        Request::CallStart { room, video } => server.call_start(room, user, *video, now_ms),
        Request::CallJoin { room, call } => server.call_join(room, user, *call, now_ms).map(|()| *call),
        Request::CallHeartbeat { room, call } => server.call_heartbeat(room, user, *call, now_ms).map(|()| *call),
        Request::CallLeave { room, call } => server.call_leave(room, user, *call, now_ms).map(|()| *call),
        Request::CallKey { room, call, public } => server.call_key(room, user, *call, *public, now_ms).map(|()| *call),
        Request::CallSeal { room, call, to, kid, sealed } => server.call_seal(room, user, *call, to, *kid, sealed.clone(), now_ms).map(|()| *call),
        _ => return None,
    };
    Some(match answer {
        Ok(call) => Ok((Response::Ok { cursor: call }, None)),
        Err(CallError::NotMember) => Ok((refusal_of(crate::dispatch::E_NO_SUCH_ROOM), None)),
        Err(CallError::NotAllowed) => Ok((refusal_of(crate::dispatch::E_NOT_ALLOWED), None)),
        Err(CallError::NoSuchCall) => Ok((refusal_of(crate::dispatch::E_NO_SUCH_CALL), None)),
        Err(CallError::Durable(error)) => Err(DurableConnError::Storage(error)),
    })
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
    Id([u8; 16]),
    Bytes(Vec<u8>),
    /// The files frame answering `ListFiles` (task T331a).
    Files(Vec<crewcraft_proto::request::ListedFile>),
    Saved(crewcraft_proto::request::SavedPage),
}

/// A request's answer, and what follows it.
type Answered = (Response, Option<Follow>);

fn refusal_of(code: u16) -> Response {
    Response::Error { code, detail: String::new() }
}
