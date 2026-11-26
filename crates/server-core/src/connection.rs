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
        EventKind::Joined { .. } | EventKind::Left { .. } => Push::Other { room: room.to_string(), cursor },
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
        )
    }

    /// Handle framed requests with the same wire behavior as [Self::receive].
    /// A successful mutation is acknowledged after it is recorded. Any storage
    /// failure is fatal and drops this call's buffered output. Earlier durable
    /// mutations in the same call remain committed.
    pub fn receive_durable(&mut self, server: &mut DurableServer, bytes: &[u8], now_ms: u64) -> Result<Vec<u8>, DurableConnError> {
        server.check_alive().map_err(DurableConnError::Storage)?;
        self.receive_with(
            server,
            bytes,
            now_ms,
            |s, user, request, now| match upload(s, user, request, now) {
                Some(answer) => answer,
                None => handle_backend(&mut Backend::Durable(s), user, request, now).map(|r| (r, None)).map_err(DurableConnError::Storage),
            },
            DurableServer::server,
            DurableServer::found,
            DurableServer::attachments,
            DurableServer::parent_of,
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
    ) -> Result<Vec<u8>, E> {
        self.decoder.push(bytes);
        let mut out = Vec::new();

        while let Some(payload) = self.decoder.next_frame().map_err(ConnError::Frame)? {
            let (id, request) = decode_request(&payload).map_err(ConnError::Request)?;
            let (response, follow) = dispatch(server, &self.user, &request, now_ms)?;
            let resp_bytes = encode_response(id, &response).map_err(ConnError::Request)?;
            let framed_resp = encode(&resp_bytes).map_err(ConnError::Frame)?;
            out.extend_from_slice(&framed_resp);
            // An upload's answer carries the new upload's id or the finished file's (task T330b); a download's, the bytes
            // (task T330d).
            match follow {
                Some(Follow::Id(value)) => out.extend_from_slice(&encode(&encode_id(id, &value)).map_err(ConnError::Frame)?),
                Some(Follow::Bytes(data)) => {
                    out.extend_from_slice(&encode(&encode_bytes(id, &data).map_err(ConnError::Request)?).map_err(ConnError::Frame)?);
                }
                None => {}
            }

            // After a successful Sync, append the room's events as push frames.
            if let Request::Sync { room, cursor } = &request
                && matches!(response, Response::Ok { .. })
                && let Ok(service) = read(server).room(room)
                && let Ok(Since::Events(events)) = service.sync(&self.user, *cursor)
            {
                for (ev_cursor, ev) in events {
                    let mut push = to_push(room, ev_cursor, &ev);
                    // A client that did not agree to reactions only advances past them (task T341a).
                    if matches!(push, Push::Reacted { .. }) && self.features & crewcraft_proto::request::FEATURE_REACTIONS == 0 {
                        push = Push::Other { room: room.clone(), cursor: ev_cursor };
                    }
                    let posted = matches!(push, Push::Posted { .. });
                    let push_bytes = encode_push(&push).map_err(ConnError::Request)?;
                    let framed_push = encode(&push_bytes).map_err(ConnError::Frame)?;
                    out.extend_from_slice(&framed_push);
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
}

/// A request's answer, and what follows it.
type Answered = (Response, Option<Follow>);

fn refusal_of(code: u16) -> Response {
    Response::Error { code, detail: String::new() }
}
