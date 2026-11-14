//! One signed-in client's connection on the server: bytes in, bytes out. Frames (`proto::frame`, T100) carry requests
//! (`proto::request`, T124); each request is applied with `dispatch::handle` (T128) and answered with exactly one
//! response frame; after a successful `Sync`, the room's events follow as push frames (`proto::push`, T131). Task T135.

use crewcraft_proto::frame::{Decoder, FrameError, encode};
use crewcraft_proto::message::CodecError;
use crewcraft_proto::push::{MAX_MENTIONS, Push, encode_push};
use crewcraft_proto::request::{Request, Response, decode_request, encode_response};

use crate::cursor_log::Since;
use crate::dispatch::handle;
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

/// The push for one room event: `Posted` becomes `Push::Posted` with the event's actor as author and its html and
/// mentions; `Edited { target }` becomes `Push::Edited` with the html and mentions; `Deleted { target }` becomes
/// `Push::Deleted`; `Joined` and `Left` become `Push::Other`. `room` and `cursor` are given. A push carries at most
/// `push::MAX_MENTIONS` mentions, the first ones: a message may mention more members than that, and a push that could
/// not be encoded would close every member's connection on each `Sync` of the room.
pub fn to_push(room: &str, cursor: u64, event: &Event) -> Push {
    match &event.kind {
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
    ///    (`Since::Gap`), no pushes follow: the client sees from the response's head that it must resync.
    ///
    /// Returns everything to send, in that order. On a fatal error, returns only the error: no bytes from this call
    /// are sent and the caller closes the connection.
    pub fn receive(&mut self, server: &mut Server, bytes: &[u8], now_ms: u64) -> Result<Vec<u8>, ConnError> {
        self.decoder.push(bytes);
        let mut out = Vec::new();

        loop {
            let payload = match self.decoder.next_frame() {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => return Err(ConnError::Frame(e)),
            };

            let (id, request) = decode_request(&payload).map_err(ConnError::Request)?;
            let response = handle(server, &self.user, &request, now_ms);
            let resp_bytes = encode_response(id, &response).map_err(ConnError::Request)?;
            let framed_resp = encode(&resp_bytes).map_err(ConnError::Frame)?;
            out.extend_from_slice(&framed_resp);

            // After a successful Sync, append the room's events as push frames.
            if let Request::Sync { room, cursor } = &request
                && matches!(response, Response::Ok { .. })
                && let Ok(service) = server.room(room)
                && let Ok(Since::Events(events)) = service.sync(&self.user, *cursor)
            {
                for (ev_cursor, ev) in events {
                    let push = to_push(room, ev_cursor, &ev);
                    let push_bytes = encode_push(&push).map_err(ConnError::Request)?;
                    let framed_push = encode(&push_bytes).map_err(ConnError::Frame)?;
                    out.extend_from_slice(&framed_push);
                }
            }
        }

        Ok(out)
    }
}
