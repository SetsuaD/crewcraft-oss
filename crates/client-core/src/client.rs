//! The client side of a connection: requests out; replies and pushes in. Frames (`proto::frame`, T100) carry requests
//! (`proto::request`, T124) one way and responses and pushes (`proto::push`, T131) the other. Replies are matched by
//! `requests::Requests` (T129) and pushes go to `inbox::Inbox` (T132). Task T136.

use crewcraft_proto::frame::{Decoder, FrameError};
use crewcraft_proto::message::CodecError;
use crewcraft_proto::push::{Push, decode_push};
use crewcraft_proto::request::{HITS_TAG, ROOMS_TAG, Request, SearchHit, decode_hits, decode_rooms};

use crate::inbox::Inbox;
use crate::notify::{Notify, Settings};
use crate::requests::{Reply, Requests};
use crate::timeline::Apply;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// A response frame, as `Requests::on_reply` matched it (`Done` or `Unknown`).
    Reply(Reply),
    /// A push for a followed room, as `Inbox::on_push` applied it.
    Pushed { room: String, apply: Apply, notify: Notify },
    /// A push for a room not followed (nothing changed).
    Ignored { room: String },
    /// The room list that follows the `Ok` answering `ListRooms` request `id`.
    Rooms { id: u32, rooms: Vec<String> },
    /// The hits that follow the `Ok` answering `Search` request `id` (task T320c).
    Hits { id: u32, hits: Vec<SearchHit> },
}

/// A fatal error: the connection must be closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientError {
    /// The frame layer refused the bytes.
    Frame(FrameError),
    /// A frame is neither a response nor a push, or does not decode: `Truncated` for an empty frame, `BadKind(byte)` when
    /// its first byte is neither a response tag (128, 129), a push tag (64 to 67, or 70 for a message's files), the
    /// room-list tag (131) nor the hits tag (132), otherwise the decoder's error.
    Malformed(CodecError),
}

pub struct Client {
    requests: Requests,
    inbox: Inbox,
    decoder: Decoder,
}

impl Client {
    /// A client for `me`, following no rooms, with these notification settings; request ids start at 1.
    pub fn new(me: &str, settings: Settings) -> Self {
        Self { requests: Requests::new(), inbox: Inbox::new(me, settings), decoder: Decoder::new() }
    }

    /// The bytes to send for `request`: `Requests::send` at `now_ms`, framed (`frame::encode`). Errors as
    /// `Requests::send` (nothing is sent or remembered).
    pub fn send(&mut self, request: Request, now_ms: u64) -> Result<Vec<u8>, CodecError> {
        let (_id, payload) = self.requests.send(request, now_ms)?;
        match crewcraft_proto::frame::encode(&payload) {
            Ok(frame) => Ok(frame),
            Err(_) => Err(CodecError::FieldLength),
        }
    }

    /// Feed received bytes. They are buffered until they form whole frames. Each complete frame, in order, is told apart
    /// by its first byte: a response goes to `Requests::on_reply` (`Reply`; a `Reply::Malformed` is fatal, as
    /// `Malformed` with its error); a push is decoded (`decode_push`) and goes to `Inbox::on_push` at `now_ms` and
    /// `local_minute` (`Pushed`, or `Ignored` for a room not followed); a room list is decoded (`decode_rooms`) and
    /// reported as `Rooms`. Returns the events in order. On a fatal error,
    /// returns only the error.
    pub fn receive(&mut self, bytes: &[u8], now_ms: u64, local_minute: u16) -> Result<Vec<ClientEvent>, ClientError> {
        self.decoder.push(bytes);
        let mut events = Vec::new();

        loop {
            let payload = match self.decoder.next_frame() {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(e) => return Err(ClientError::Frame(e)),
            };

            if payload.is_empty() {
                return Err(ClientError::Malformed(CodecError::Truncated));
            }

            let first = payload[0];

            if (128..=129).contains(&first) {
                let reply = self.requests.on_reply(&payload);
                match reply {
                    Reply::Malformed(e) => return Err(ClientError::Malformed(e)),
                    _ => events.push(ClientEvent::Reply(reply)),
                }
            } else if (64..=67).contains(&first) || first == crewcraft_proto::push::ATTACHED {
                let push = decode_push(&payload).map_err(ClientError::Malformed)?;
                let room = match &push {
                    Push::Posted { room, .. } => room.clone(),
                    Push::Edited { room, .. } => room.clone(),
                    Push::Deleted { room, .. } => room.clone(),
                    Push::Other { room, .. } => room.clone(),
                    Push::Attached { room, .. } => room.clone(),
                };
                match self.inbox.on_push(push, now_ms, local_minute) {
                    Some((apply, notify)) => events.push(ClientEvent::Pushed { room, apply, notify }),
                    None => events.push(ClientEvent::Ignored { room }),
                }
            } else if first == ROOMS_TAG {
                let (id, rooms) = decode_rooms(&payload).map_err(ClientError::Malformed)?;
                events.push(ClientEvent::Rooms { id, rooms });
            } else if first == HITS_TAG {
                let (id, hits) = decode_hits(&payload).map_err(ClientError::Malformed)?;
                events.push(ClientEvent::Hits { id, hits });
            } else {
                return Err(ClientError::Malformed(CodecError::BadKind(first)));
            }
        }

        Ok(events)
    }

    /// Requests whose time is up (as `Requests::expire`).
    pub fn expire(&mut self, now_ms: u64) -> Vec<(u32, Request)> {
        self.requests.expire(now_ms)
    }

    pub fn inbox(&self) -> &Inbox {
        &self.inbox
    }

    /// To follow rooms, send messages from a room view, or apply a snapshot.
    pub fn inbox_mut(&mut self) -> &mut Inbox {
        &mut self.inbox
    }
}
