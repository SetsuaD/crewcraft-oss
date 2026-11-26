//! One request from a signed-in user, applied to the server: the server side of `proto::request` (T124) over
//! `server::Server` (T122). Task T128.

use crewcraft_proto::message::MAX_NAME;
use crewcraft_proto::request::{MAX_ROOMS, Request, Response};

use crate::durable::{DurableError, DurableServer};
use crate::room::RoomError;
use crate::room_service::ServiceError;
use crate::server::{Server, ServerError};

/// Error codes carried in `Response::Error`. Codes are the contract: `detail` is always empty, so no text about other
/// rooms or users leaks out.
///
/// A room the user is not a member of answers `E_NO_SUCH_ROOM`, exactly like a room that does not exist, so a
/// non-member cannot probe which rooms exist.
pub const E_NO_SUCH_ROOM: u16 = 1;
pub const E_RATE_LIMITED: u16 = 2;
/// `Service(NotAllowed)` and `Service(Room(Forbidden))`.
pub const E_NOT_ALLOWED: u16 = 3;
/// `Service(EmptyText)` and `Service(TooLong)`.
pub const E_BAD_TEXT: u16 = 4;
pub const E_NO_SUCH_MESSAGE: u16 = 5;
/// An upload that cannot be accepted: a bad name or size, a chunk outside it, bytes that do not match (task T330b).
pub const E_BAD_FILE: u16 = 6;
/// This server keeps no files (task T330b).
pub const E_NO_STORAGE: u16 = 7;
/// No such upload in progress for this person (task T330b).
pub const E_NO_SUCH_UPLOAD: u16 = 8;
/// No such file, or not one this person can reach (task T330d).
pub const E_NO_SUCH_FILE: u16 = 9;
/// A post's files are not the poster's own unattached uploads in that room (task T330c).
pub const E_BAD_ATTACHMENT: u16 = 10;
/// No such open call in the room, or the person is not in it (task T360a1): the client leaves the call.
pub const E_NO_SUCH_CALL: u16 = 11;
/// The upload would take the person past their storage quota (task T332a).
pub const E_OVER_QUOTA: u16 = 12;
/// Anything else (`AlreadyMember`, `LastOwner`, `BadName`).
pub const E_OTHER: u16 = 99;

/// The code for a refused upload request (task T330b). `Durable` is not here: a storage failure is fatal.
pub fn upload_error_code(error: crate::durable::UploadError) -> u16 {
    use crate::durable::UploadError as U;
    match error {
        U::NoStorage => E_NO_STORAGE,
        U::NotMember => E_NO_SUCH_ROOM,
        U::ReadOnly => E_NOT_ALLOWED,
        U::BadName | U::BadSize | U::BadChunk | U::WrongContent => E_BAD_FILE,
        U::TooMany => E_RATE_LIMITED,
        U::OverQuota => E_OVER_QUOTA,
        U::NoSuchUpload => E_NO_SUCH_UPLOAD,
        U::Storage | U::Durable(_) => E_OTHER,
    }
}

/// The code for an error: `NoSuchRoom` and `Service(Room(NotMember))` are `E_NO_SUCH_ROOM`, then as listed above.
pub fn error_code(error: ServerError) -> u16 {
    match error {
        ServerError::NoSuchRoom => E_NO_SUCH_ROOM,
        ServerError::RateLimited => E_RATE_LIMITED,
        ServerError::BadName(_) => E_OTHER,
        ServerError::Service(se) => match se {
            ServiceError::Room(re) => match re {
                RoomError::NotMember => E_NO_SUCH_ROOM,
                RoomError::Forbidden => E_NOT_ALLOWED,
                RoomError::AlreadyMember | RoomError::LastOwner => E_OTHER,
            },
            ServiceError::NotAllowed => E_NOT_ALLOWED,
            ServiceError::EmptyText | ServiceError::TooLong => E_BAD_TEXT,
            ServiceError::NoSuchMessage => E_NO_SUCH_MESSAGE,
            ServiceError::BadReaction => E_OTHER,
        },
    }
}

/// Apply `request` from `user` at `now_ms`:
/// - `Post`, `Edit`, `Delete`: the matching `Server` call; `Ok { cursor }` is the new event's cursor.
/// - `Sync`: the user must be a member (`RoomService::sync`); `Ok { cursor }` is the room's head. The events themselves
///   go out as separate frames, not in this response.
/// - `MarkRead`: `Server::mark_read`; `Ok { cursor }` is the room's head, whether or not the marker moved.
/// - `MarkUnread` (task T344): resolve a live target for this member; `Ok.cursor` is their final read position.
/// - `Ping`: `Ok { cursor: 0 }`; it needs no room and never fails.
/// - `ListRooms`: `Ok { cursor }` is how many rooms `listed_rooms` gives for `user`. The names themselves go out as
///   one room-list frame after this response (`request::encode_rooms`), as `Sync`'s events do. It never fails.
/// - `Search` (task T320b): `Ok { cursor }` is how many hits `DurableServer::found` gives for `user`; the hits go out as
///   one hits frame after this response (`request::encode_hits`). A server without a journal has no index and finds
///   nothing. It never fails.
///
/// Any error is `Error { code: error_code(e), detail: "" }`.
pub fn handle(server: &mut Server, user: &str, request: &Request, now_ms: u64) -> Response {
    handle_backend(&mut Backend::Memory(server), user, request, now_ms).unwrap_or_else(|_| refusal(E_OTHER))
}

pub(crate) enum Backend<'a> {
    Memory(&'a mut Server),
    Durable(&'a mut DurableServer),
}

impl Backend<'_> {
    pub(crate) fn server(&self) -> &Server {
        match self {
            Self::Memory(server) => server,
            Self::Durable(server) => server.server(),
        }
    }

    /// What `Search` finds for `user` (task T320b): nothing without a journal.
    pub(crate) fn found(&self, user: &str, query: &str) -> Vec<crewcraft_proto::request::SearchHit> {
        match self {
            Self::Memory(_) => Vec::new(),
            Self::Durable(server) => server.found(user, query),
        }
    }

    fn change<T>(
        &mut self,
        memory: impl FnOnce(&mut Server) -> Result<T, ServerError>,
        durable: impl FnOnce(&mut DurableServer) -> Result<T, DurableError>,
    ) -> Result<T, DurableError> {
        match self {
            Self::Memory(server) => memory(server).map_err(DurableError::Server),
            Self::Durable(server) => durable(server),
        }
    }
}

/// The rooms `ListRooms` lists for `user`: the slugs of the rooms they are a member of (`Server::rooms_of`), sorted,
/// and nothing about anyone else's. At most `request::MAX_ROOMS` (the first by slug); a slug longer than
/// `message::MAX_NAME` bytes, which no request could name, is left out.
pub fn listed_rooms(server: &Server, user: &str) -> Vec<String> {
    server.rooms_of(user).into_iter().map(|room| room.slug).filter(|slug| !slug.is_empty() && slug.len() <= MAX_NAME).take(MAX_ROOMS).collect()
}

fn refusal(code: u16) -> Response {
    Response::Error { code, detail: String::new() }
}

pub(crate) fn handle_backend(backend: &mut Backend<'_>, user: &str, request: &Request, now_ms: u64) -> Result<Response, DurableError> {
    let result = match request {
        Request::Ping => return Ok(Response::Ok { cursor: 0 }),
        Request::ListRooms => return Ok(Response::Ok { cursor: listed_rooms(backend.server(), user).len() as u64 }),
        Request::Search { query } => return Ok(Response::Ok { cursor: backend.found(user, query).len() as u64 }),
        // Current requires a full durable projection and correlated follow frames, supplied by the connection.
        Request::Current { room } => {
            return Ok(match backend.server().room(room) {
                Ok(service) if service.role(user).is_some() => refusal(E_NO_STORAGE),
                _ => refusal(E_NO_SUCH_ROOM),
            });
        }
        // Uploads (task T330b) need a journal; the connection answers them (`connection::Connection::receive_durable`)
        // because their answer carries an id frame. Without a journal there is nowhere to keep files.
        Request::UploadBegin { .. }
        | Request::UploadChunk { .. }
        | Request::UploadFinish { .. }
        | Request::Download { .. }
        | Request::CallStart { .. }
        | Request::CallJoin { .. }
        | Request::CallHeartbeat { .. }
        | Request::CallLeave { .. }
        | Request::ListFiles
        | Request::StorageUse
        | Request::SaveMessage { .. }
        | Request::ListSaved { .. }
        | Request::CallKey { .. }
        | Request::CallSeal { .. }
        | Request::CallOffer { .. }
        | Request::PostFiles { .. }
        | Request::Reply { .. } => {
            return Ok(refusal(E_NO_STORAGE));
        }
        Request::Post { room, text } => backend.change(|s| s.post(room, user, text, now_ms), |s| s.post(room, user, text, now_ms)),
        Request::Edit { room, target, text } => {
            backend.change(|s| s.edit(room, user, *target, text, now_ms), |s| s.edit(room, user, *target, text, now_ms))
        }
        Request::Delete { room, target } => backend.change(|s| s.delete(room, user, *target), |s| s.delete(room, user, *target)),
        Request::React { room, target, reaction, on } => {
            backend.change(|s| s.react(room, user, *target, *reaction, *on, now_ms), |s| s.react(room, user, *target, *reaction, *on, now_ms))
        }
        Request::Pin { room, target, on } => backend.change(|s| s.pin(room, user, *target, *on, now_ms), |s| s.pin(room, user, *target, *on, now_ms)),
        Request::Sync { room, .. } => {
            return Ok(match backend.server().room(room) {
                Ok(service) if service.role(user).is_some() => Response::Ok { cursor: service.head() },
                _ => refusal(E_NO_SUCH_ROOM),
            });
        }
        Request::MarkRead { room, cursor } => backend
            .change(|s| s.mark_read(room, user, *cursor), |s| s.mark_read(room, user, *cursor))
            .and_then(|_| backend.server().room(room).map(|service| service.head()).map_err(|_| DurableError::Server(ServerError::NoSuchRoom))),
        Request::MarkUnread { room, target } => backend.change(|s| s.mark_unread(room, user, *target), |s| s.mark_unread(room, user, *target)),
    };
    match result {
        Ok(cursor) => Ok(Response::Ok { cursor }),
        Err(DurableError::Server(error)) => Ok(refusal(error_code(error))),
        Err(error) => Err(error),
    }
}
