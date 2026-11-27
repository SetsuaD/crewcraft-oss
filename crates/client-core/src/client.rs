//! The client side of a connection: requests out; replies and pushes in. Frames (`proto::frame`, T100) carry requests
//! (`proto::request`, T124) one way and responses and pushes (`proto::push`, T131) the other. Replies are matched by
//! `requests::Requests` (T129) and pushes go to `inbox::Inbox` (T132). Task T136.

use crewcraft_proto::frame::{Decoder, FrameError};
use crewcraft_proto::message::CodecError;
use crewcraft_proto::push::{Push, decode_push};
use crewcraft_proto::request::{
    ANSWER_TAG, BYTES_TAG, CONTINUED_TAG, FILES_TAG, HITS_TAG, ID_TAG, ListedFile, MEDIA_TAG, ROOMS_TAG, Request, SAVED_TAG, SavedPage, SearchHit, decode_answer,
    decode_bytes, decode_continued, decode_files, decode_hits, decode_id, decode_media, decode_rooms, decode_saved,
};

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
    /// The files frame answering `ListFiles` request `id` (task T331a).
    Files { id: u32, files: Vec<ListedFile> },
    /// A page of the person's saved messages in their current state (T343).
    Saved { id: u32, page: SavedPage },
    /// One bounded current-state page; its framed byte count includes the four-byte length prefix (T345).
    Current { id: u32, page: crewcraft_proto::current::CurrentPage, framed_bytes: usize },
    /// Explicit missing event history, sent after this Sync's other metadata (T345).
    Gap { room: String, head: u64, after: u64, oldest: u64 },
    /// The upload or file id that follows the `Ok` answering an upload request `id` (task T330e).
    Id { id: u32, value: [u8; 16] },
    /// The bytes that follow the `Ok` answering `Download` request `id` (task T330e).
    Bytes { id: u32, data: Vec<u8> },
    /// The media server's address and this device's media credential, after the `Ok` answering `CallStart` or
    /// `CallJoin` request `id` with `FEATURE_MEDIA` (task T360b2). The credential goes into a `CallOffer`.
    Media { id: u32, address: String, credential: Vec<u8> },
    /// The media server's WebRTC answer (SDP) to the offer of `CallOffer` request `id` (task T360b6).
    Answer { id: u32, answer: String },
    /// The room an archive continues in, after the `Ok` answering `Continue` request `id` (task T352).
    Continued { id: u32, room: String },
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
            } else if (64..=67).contains(&first)
                || first == crewcraft_proto::push::ATTACHED
                || first == crewcraft_proto::push::THREADED
                || first == crewcraft_proto::push::REACTED
                || first == crewcraft_proto::push::ARCHIVED
                || first == crewcraft_proto::push::SENT
                || first == crewcraft_proto::push::CALL_LINE
                || first == crewcraft_proto::push::CALL_STATE
                || first == crewcraft_proto::push::CALL_KEYS
                || first == crewcraft_proto::push::CALL_SEALED
                || first == crewcraft_proto::push::PINNED
                || first == crewcraft_proto::push::READ_STATE
                || first == crewcraft_proto::push::GAP
                || first == crewcraft_proto::push::CONTINUED
            {
                let push = decode_push(&payload).map_err(ClientError::Malformed)?;
                if let Push::Gap { room, cursor, after, oldest } = push {
                    self.inbox.on_push(Push::Gap { room: room.clone(), cursor, after, oldest }, now_ms, local_minute);
                    events.push(ClientEvent::Gap { room, head: cursor, after, oldest });
                    continue;
                }
                let room = match &push {
                    Push::Posted { room, .. } => room.clone(),
                    Push::Edited { room, .. } => room.clone(),
                    Push::Deleted { room, .. } => room.clone(),
                    Push::Other { room, .. } => room.clone(),
                    Push::Attached { room, .. } | Push::Threaded { room, .. } | Push::Reacted { room, .. } => room.clone(),
                    Push::Archived { room, .. } | Push::Sent { room, .. } => room.clone(),
                    Push::CallLine { room, .. } | Push::CallState { room, .. } => room.clone(),
                    Push::CallKeys { room, .. } | Push::CallSealed { room, .. } => room.clone(),
                    Push::Pinned { room, .. } => room.clone(),
                    Push::ReadState { room, .. } => room.clone(),
                    Push::Gap { room, .. } => room.clone(),
                    Push::Continued { room, .. } => room.clone(),
                };
                match self.inbox.on_push(push, now_ms, local_minute) {
                    Some((apply, notify)) => events.push(ClientEvent::Pushed { room, apply, notify }),
                    None => events.push(ClientEvent::Ignored { room }),
                }
            } else if first == ROOMS_TAG {
                let (id, rooms) = decode_rooms(&payload).map_err(ClientError::Malformed)?;
                events.push(ClientEvent::Rooms { id, rooms });
            } else if first == FILES_TAG {
                let (id, files) = decode_files(&payload).map_err(ClientError::Malformed)?;
                events.push(ClientEvent::Files { id, files });
            } else if first == HITS_TAG {
                let (id, hits) = decode_hits(&payload).map_err(ClientError::Malformed)?;
                events.push(ClientEvent::Hits { id, hits });
            } else if first == SAVED_TAG {
                let (id, page) = decode_saved(&payload).map_err(ClientError::Malformed)?;
                events.push(ClientEvent::Saved { id, page });
            } else if first == crewcraft_proto::current::CURRENT_TAG {
                let (id, page) = crewcraft_proto::current::decode_page(&payload).map_err(ClientError::Malformed)?;
                events.push(ClientEvent::Current { id, page, framed_bytes: payload.len() + 4 });
            } else if first == ID_TAG {
                let (id, value) = decode_id(&payload).map_err(ClientError::Malformed)?;
                events.push(ClientEvent::Id { id, value });
            } else if first == BYTES_TAG {
                let (id, data) = decode_bytes(&payload).map_err(ClientError::Malformed)?;
                events.push(ClientEvent::Bytes { id, data });
            } else if first == MEDIA_TAG {
                let (id, address, credential) = decode_media(&payload).map_err(ClientError::Malformed)?;
                events.push(ClientEvent::Media { id, address, credential });
            } else if first == CONTINUED_TAG {
                let (id, room) = decode_continued(&payload).map_err(ClientError::Malformed)?;
                events.push(ClientEvent::Continued { id, room });
            } else if first == ANSWER_TAG {
                let (id, answer) = decode_answer(&payload).map_err(ClientError::Malformed)?;
                events.push(ClientEvent::Answer { id, answer });
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
