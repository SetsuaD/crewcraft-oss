//! One request from a signed-in user, applied to the server: the server side of `proto::request` (T124) over
//! `server::Server` (T122). Task T128.

use crewcraft_proto::request::{Request, Response};

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
    match request {
        Request::Ping => Response::Ok { cursor: 0 },
        Request::Post { room, text } => match server.post(room, user, text, now_ms) {
            Ok(cursor) => Response::Ok { cursor },
            Err(e) => Response::Error { code: error_code(e), detail: String::new() },
        },
        Request::Edit { room, target, text } => match server.edit(room, user, *target, text, now_ms) {
            Ok(cursor) => Response::Ok { cursor },
            Err(e) => Response::Error { code: error_code(e), detail: String::new() },
        },
        Request::Delete { room, target } => match server.delete(room, user, *target) {
            Ok(cursor) => Response::Ok { cursor },
            Err(e) => Response::Error { code: error_code(e), detail: String::new() },
        },
        Request::Sync { room, cursor: _ } => match server.room(room) {
            Ok(service) if service.role(user).is_some() => Response::Ok { cursor: service.head() },
            _ => Response::Error { code: E_NO_SUCH_ROOM, detail: String::new() },
        },
        Request::MarkRead { room, cursor } => match server.mark_read(room, user, *cursor) {
            Ok(_) => match server.room(room) {
                Ok(service) => Response::Ok { cursor: service.head() },
                Err(_) => Response::Error { code: E_NO_SUCH_ROOM, detail: String::new() },
            },
            Err(e) => Response::Error { code: error_code(e), detail: String::new() },
        },
    }
}
