//! One signed-in client's connection on the server: bytes in, bytes out. Frames (`proto::frame`, T100) carry requests
//! (`proto::request`, T124); each request is applied with `dispatch::handle` (T128) and answered with exactly one
//! response frame; after a successful `Sync`, the room's events follow as push frames (`proto::push`, T131), and after
//! a `ListRooms` the room-list frame follows (`proto::request::encode_rooms`, T233). Task T135.

use crewcraft_proto::frame::{Decoder, FrameError, encode};
use crewcraft_proto::message::CodecError;
use crewcraft_proto::push::{MAX_MENTIONS, Push, encode_push};
use crewcraft_proto::request::{Request, Response, SearchHit, decode_request, encode_hits, encode_id, encode_response, encode_rooms};

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
    }
}

fn first_mentions(event: &Event) -> Vec<String> {
    event.mentions.iter().take(MAX_MENTIONS).cloned().collect()
}

pub struct Connection {
    user: String,
    decoder: Decoder,
}

impl Connection {
    /// A connection for `user` (already signed in), with nothing buffered.
    pub fn new(user: &str) -> Self {
        Self { user: user.to_string(), decoder: Decoder::new() }
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
        self.receive_with(server, bytes, now_ms, |s, user, request, now| Ok((handle(s, user, request, now), None)), |s| s, |_, _, _| Vec::new())
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
        )
    }

    fn receive_with<S, E: From<ConnError>>(
        &mut self,
        server: &mut S,
        bytes: &[u8],
        now_ms: u64,
        mut dispatch: impl FnMut(&mut S, &str, &Request, u64) -> Result<Answered, E>,
        read: impl Fn(&S) -> &Server,
        found: impl Fn(&S, &str, &str) -> Vec<SearchHit>,
    ) -> Result<Vec<u8>, E> {
        self.decoder.push(bytes);
        let mut out = Vec::new();

        while let Some(payload) = self.decoder.next_frame().map_err(ConnError::Frame)? {
            let (id, request) = decode_request(&payload).map_err(ConnError::Request)?;
            let (response, follow) = dispatch(server, &self.user, &request, now_ms)?;
            let resp_bytes = encode_response(id, &response).map_err(ConnError::Request)?;
            let framed_resp = encode(&resp_bytes).map_err(ConnError::Frame)?;
            out.extend_from_slice(&framed_resp);
            // An upload's answer carries the new upload's id or the finished file's (task T330b).
            if let Some(value) = follow {
                out.extend_from_slice(&encode(&encode_id(id, &value)).map_err(ConnError::Frame)?);
            }

            // After a successful Sync, append the room's events as push frames.
            if let Request::Sync { room, cursor } = &request
                && matches!(response, Response::Ok { .. })
                && let Ok(service) = read(server).room(room)
                && let Ok(Since::Events(events)) = service.sync(&self.user, *cursor)
            {
                for (ev_cursor, ev) in events {
                    let push = to_push(room, ev_cursor, &ev);
                    let push_bytes = encode_push(&push).map_err(ConnError::Request)?;
                    let framed_push = encode(&push_bytes).map_err(ConnError::Frame)?;
                    out.extend_from_slice(&framed_push);
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
        Request::UploadBegin { room, name, size, sha256 } => server.begin_upload(user, room, name, *size, *sha256, now_ms).map(|id| (0, Some(id))),
        Request::UploadChunk { upload, offset, bytes } => server.upload_chunk(user, upload, *offset, bytes, now_ms).map(|received| (received, None)),
        Request::UploadFinish { upload } => server.finish_upload(user, upload, now_ms).map(|file| (0, Some(file))),
        _ => return None,
    };
    Some(match answer {
        Ok((cursor, follow)) => Ok((Response::Ok { cursor }, follow)),
        Err(UploadError::Durable(error)) => Err(DurableConnError::Storage(error)),
        Err(error) => Ok((Response::Error { code: crate::dispatch::upload_error_code(error), detail: String::new() }, None)),
    })
}

/// A request's answer, and the id frame that follows it when there is one (an upload's id or a file's, task T330b).
type Answered = (Response, Option<[u8; 16]>);
