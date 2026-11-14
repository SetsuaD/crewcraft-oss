//! One request from a signed-in user, applied to the server: the server side of `proto::request` (T124) over
//! `server::Server` (T122). Task T128.

use crewcraft_proto::request::{Request, Response};

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
/// Anything else (`AlreadyMember`, `LastOwner`, `BadName`).
pub const E_OTHER: u16 = 99;

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
        },
    }
}

/// Apply `request` from `user` at `now_ms`:
/// - `Post`, `Edit`, `Delete`: the matching `Server` call; `Ok { cursor }` is the new event's cursor.
/// - `Sync`: the user must be a member (`RoomService::sync`); `Ok { cursor }` is the room's head. The events themselves
///   go out as separate frames, not in this response.
/// - `MarkRead`: `Server::mark_read`; `Ok { cursor }` is the room's head, whether or not the marker moved.
/// - `Ping`: `Ok { cursor: 0 }`; it needs no room and never fails.
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

fn refusal(code: u16) -> Response {
    Response::Error { code, detail: String::new() }
}

pub(crate) fn handle_backend(backend: &mut Backend<'_>, user: &str, request: &Request, now_ms: u64) -> Result<Response, DurableError> {
    let result = match request {
        Request::Ping => return Ok(Response::Ok { cursor: 0 }),
        Request::Post { room, text } => backend.change(|s| s.post(room, user, text, now_ms), |s| s.post(room, user, text, now_ms)),
        Request::Edit { room, target, text } => {
            backend.change(|s| s.edit(room, user, *target, text, now_ms), |s| s.edit(room, user, *target, text, now_ms))
        }
        Request::Delete { room, target } => backend.change(|s| s.delete(room, user, *target), |s| s.delete(room, user, *target)),
        Request::Sync { room, .. } => {
            return Ok(match backend.server().room(room) {
                Ok(service) if service.role(user).is_some() => Response::Ok { cursor: service.head() },
                _ => refusal(E_NO_SUCH_ROOM),
            });
        }
        Request::MarkRead { room, cursor } => backend
            .change(|s| s.mark_read(room, user, *cursor), |s| s.mark_read(room, user, *cursor))
            .and_then(|_| backend.server().room(room).map(|service| service.head()).map_err(|_| DurableError::Server(ServerError::NoSuchRoom))),
    };
    match result {
        Ok(cursor) => Ok(Response::Ok { cursor }),
        Err(DurableError::Server(error)) => Ok(refusal(error_code(error))),
        Err(error) => Err(error),
    }
}
