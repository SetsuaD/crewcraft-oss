//! Synchronous chat over an already verified, enrolled device connection. Task T215.

use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

use crewcraft_client_core::client::{Client, ClientEvent};
use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::requests::Reply as RequestReply;
use crewcraft_client_core::room_view::RoomView;
use crewcraft_client_core::session::{ClientSession, Phase, SessionError};
use crewcraft_proto::frame::{self, ReceivedFrame};
use crewcraft_proto::handshake::Hello;
use crewcraft_proto::message::{CodecError, MAX_NAME};
use crewcraft_proto::request::{FEATURE_LIST_ROOMS, Request, Response};
use crewcraft_proto::signin::{self, Opening, SignIn};
use zeroize::Zeroizing;

const SIGN_IN_REPLY_LIMIT: usize = 1 + signin::TOKEN_LEN;
const WELCOME_LIMIT: usize = 9 + MAX_NAME;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatError {
    Io(io::ErrorKind),
    SignInProtocol,
    SignInRefused,
    HandshakeRefused,
    Session(SessionError),
    Request(CodecError),
    Rejected(u16),
    Closed,
    /// An out-of-order event or a head behind the local cursor requires resync.
    HistoryGap {
        reached: u64,
        head: u64,
    },
    /// The stream stopped or the deadline expired before the advertised head arrived.
    SyncIncomplete {
        reached: u64,
        head: u64,
        reason: io::ErrorKind,
    },
    /// The server did not agree to the feature this request needs (an older server); nothing was sent.
    Unsupported,
    /// The server's room list did not match the count its answer announced; the connection is closed.
    UnexpectedResponse,
}

pub struct ChatSession<S, D> {
    stream: S,
    set_deadline: D,
    frame_timeout: Duration,
    session: ClientSession,
    closed: bool,
    /// The session token the server returned; it resumes this session later (task T240). Wiped on drop.
    token: Zeroizing<String>,
}

impl<S: Read + Write, D: FnMut(&mut S, Instant)> ChatSession<S, D> {
    /// The stream has already authenticated both peers. `set_deadline` must enforce one absolute
    /// cutoff across all I/O for a frame. The same operation deadline covers sign-in and negotiation.
    pub fn connect(
        stream: S,
        set_deadline: D,
        credentials: &SignIn<'_>,
        hello: Hello,
        settings: Settings,
        frame_timeout: Duration,
        deadline: Instant,
    ) -> Result<Self, ChatError> {
        let opening = Opening::SignIn(SignIn { email: credentials.email, password: credentials.password, code: credentials.code });
        Self::open(stream, set_deadline, &opening, credentials.email, hello, settings, frame_timeout, deadline)
    }

    /// As `connect`, but reopening the session `token` belongs to instead of signing in (task T240). A token the server
    /// no longer accepts is `SignInRefused`.
    #[allow(clippy::too_many_arguments)]
    pub fn resume(
        stream: S,
        set_deadline: D,
        email: &str,
        token: &str,
        hello: Hello,
        settings: Settings,
        frame_timeout: Duration,
        deadline: Instant,
    ) -> Result<Self, ChatError> {
        Self::open(stream, set_deadline, &Opening::Resume { token }, email, hello, settings, frame_timeout, deadline)
    }

    /// The session token, for a later `resume`. A secret: keep it as the device record is kept, never in a log.
    pub fn token(&self) -> &str {
        &self.token
    }

    #[allow(clippy::too_many_arguments)]
    fn open(
        stream: S,
        set_deadline: D,
        opening: &Opening<'_>,
        email: &str,
        hello: Hello,
        settings: Settings,
        frame_timeout: Duration,
        deadline: Instant,
    ) -> Result<Self, ChatError> {
        let versions = hello.min_version..=hello.max_version;
        let supported_features = hello.features;
        let client = Client::new(email, settings);
        let mut chat =
            Self { stream, set_deadline, frame_timeout, session: ClientSession::new(hello, client), closed: false, token: Zeroizing::default() };
        chat.token = chat.authenticate(opening, deadline)?;

        let hello = chat.session.start().map_err(ChatError::Session)?;
        chat.write_frame(&hello, deadline)?;
        let reply = chat.read_frame(WELCOME_LIMIT, deadline)?;
        chat.session.receive(reply.as_bytes(), 0, 0).map_err(ChatError::Session)?;
        match chat.session.phase() {
            Phase::Open { version, features } if versions.contains(&version) && features & !supported_features == 0 => Ok(chat),
            _ => Err(ChatError::HandshakeRefused),
        }
    }

    /// Send one post and return only its matched server acknowledgement. A transport failure
    /// after dispatch leaves the result unknown. The runtime does not retry a write.
    pub fn post(&mut self, room: &str, text: &str, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<u64, ChatError> {
        self.request(Request::Post { room: room.to_owned(), text: text.to_owned() }, now_ms, local_minute, deadline)
    }

    pub fn edit(&mut self, room: &str, target: u64, text: &str, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<u64, ChatError> {
        self.request(Request::Edit { room: room.to_owned(), target, text: text.to_owned() }, now_ms, local_minute, deadline)
    }

    pub fn delete(&mut self, room: &str, target: u64, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<u64, ChatError> {
        self.request(Request::Delete { room: room.to_owned(), target }, now_ms, local_minute, deadline)
    }

    /// The features both sides agreed on in the handshake (`handshake::Hello::features`).
    pub fn features(&self) -> u32 {
        match self.session.phase() {
            Phase::Open { features, .. } => features,
            _ => 0,
        }
    }

    /// Whether the server agreed to `ListRooms` (`request::FEATURE_LIST_ROOMS`).
    pub fn lists_rooms(&self) -> bool {
        self.features() & FEATURE_LIST_ROOMS != 0
    }

    /// The rooms the signed-in person is a member of, as the server lists them. `Unsupported`, with nothing sent, when
    /// the server did not agree to `FEATURE_LIST_ROOMS`. The answer announces how many rooms follow; a room list of
    /// another length is `UnexpectedResponse` and closes the session.
    pub fn list_rooms(&mut self, now_ms: u64, deadline: Instant) -> Result<Vec<String>, ChatError> {
        if !self.lists_rooms() {
            return Err(ChatError::Unsupported);
        }
        let (id, count) = match self.exchange(Request::ListRooms, now_ms, 0, deadline)? {
            (id, Response::Ok { cursor }) => (id, cursor),
            (_, Response::Error { code, .. }) => return Err(ChatError::Rejected(code)),
        };
        loop {
            for event in self.receive(now_ms, 0, deadline)? {
                if let ClientEvent::Rooms { id: answered, rooms } = event
                    && answered == id
                {
                    if u64::try_from(rooms.len()).ok() != Some(count) {
                        self.closed = true;
                        return Err(ChatError::UnexpectedResponse);
                    }
                    return Ok(rooms);
                }
            }
        }
    }

    /// A request that needs no room and never fails at the server, to keep an idle connection open.
    pub fn ping(&mut self, now_ms: u64, deadline: Instant) -> Result<(), ChatError> {
        self.request(Request::Ping, now_ms, 0, deadline).map(|_| ())
    }

    /// Follow the room and fetch events after its current cursor. Return the acknowledged head
    /// after the timeline reaches it. A gap or incomplete replay leaves the applied prefix visible.
    pub fn sync(&mut self, room: &str, direct: bool, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<u64, ChatError> {
        if self.closed {
            return Err(ChatError::Closed);
        }
        let inbox = self.session.client_mut().inbox_mut();
        inbox.follow(room, direct);
        let start = inbox.view(room).ok_or(ChatError::Closed)?.cursor();
        let head = self.request(Request::Sync { room: room.to_owned(), cursor: start }, now_ms, local_minute, deadline)?;

        loop {
            let view = self.view(room).ok_or(ChatError::Closed)?;
            let reached = view.cursor();
            if view.needs_resync() || head < start {
                self.closed = true;
                return Err(ChatError::HistoryGap { reached, head });
            }
            if reached >= head {
                return Ok(head);
            }
            match self.receive(now_ms, local_minute, deadline) {
                Err(ChatError::Io(reason)) => return Err(ChatError::SyncIncomplete { reached, head, reason }),
                Err(error) => return Err(error),
                Ok(_) => {}
            }
        }
    }

    pub fn view(&mut self, room: &str) -> Option<&RoomView> {
        self.session.client_mut().inbox().view(room)
    }

    fn authenticate(&mut self, opening: &Opening<'_>, deadline: Instant) -> Result<Zeroizing<String>, ChatError> {
        let request = Zeroizing::new(signin::encode_opening(opening).map_err(|_| ChatError::SignInProtocol)?);
        let framed = Zeroizing::new(frame::encode(&request).map_err(|_| ChatError::SignInProtocol)?);
        self.write_frame(&framed, deadline)?;

        let reply = self.read_frame(SIGN_IN_REPLY_LIMIT, deadline)?;
        match signin::decode_reply(reply.payload()).map_err(|_| ChatError::SignInProtocol)? {
            signin::Reply::Accepted { token } => Ok(Zeroizing::new(token.to_owned())),
            signin::Reply::Refused => Err(ChatError::SignInRefused),
            // An external-sign-in start is only an answer to BeginExternal (task T611a), never to these openings.
            signin::Reply::Ended | signin::Reply::ExternalStart { .. } => Err(ChatError::SignInProtocol),
        }
    }

    fn request(&mut self, request: Request, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<u64, ChatError> {
        match self.exchange(request, now_ms, local_minute, deadline)?.1 {
            Response::Ok { cursor } => Ok(cursor),
            Response::Error { code, .. } => Err(ChatError::Rejected(code)),
        }
    }

    /// Send one request and return its id and matched response.
    fn exchange(&mut self, request: Request, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<(u32, Response), ChatError> {
        if self.closed {
            return Err(ChatError::Closed);
        }
        let frame = self.session.client_mut().send(request, now_ms).map_err(ChatError::Request)?;
        self.write_frame(&frame, deadline)?;

        // There is exactly one request in flight. Client::receive matches its id and ignores old ids.
        loop {
            let events = self.receive(now_ms, local_minute, deadline)?;
            if let Some(ClientEvent::Reply(RequestReply::Done { id, response, .. })) = events.into_iter().next() {
                return Ok((id, response));
            }
        }
    }

    fn receive(&mut self, now_ms: u64, local_minute: u16, deadline: Instant) -> Result<Vec<ClientEvent>, ChatError> {
        let frame = self.read_frame(frame::MAX_FRAME, deadline)?;
        self.session.receive(frame.as_bytes(), now_ms, local_minute).map_err(|error| {
            self.closed = true;
            ChatError::Session(error)
        })
    }

    fn prepare_frame(&mut self, deadline: Instant) -> Result<(), ChatError> {
        let now = Instant::now();
        if deadline <= now || self.frame_timeout.is_zero() {
            self.closed = true;
            return Err(ChatError::Io(io::ErrorKind::TimedOut));
        }
        let cutoff = now.checked_add(self.frame_timeout).map_or(deadline, |frame_deadline| frame_deadline.min(deadline));
        (self.set_deadline)(&mut self.stream, cutoff);
        Ok(())
    }

    fn write_frame(&mut self, frame: &[u8], deadline: Instant) -> Result<(), ChatError> {
        self.prepare_frame(deadline)?;
        self.stream.write_all(frame).and_then(|()| self.stream.flush()).map_err(|error| {
            self.closed = true;
            ChatError::Io(error.kind())
        })
    }

    fn read_frame(&mut self, limit: usize, deadline: Instant) -> Result<ReceivedFrame, ChatError> {
        self.prepare_frame(deadline)?;
        match frame::read_frame(&mut self.stream, limit) {
            Ok(Some(frame)) => Ok(frame),
            result => {
                self.closed = true;
                Err(ChatError::Io(result.err().map_or(io::ErrorKind::UnexpectedEof, |error| error.kind())))
            }
        }
    }
}

/// End the session `token` belongs to (task T240), over a stream whose device that session belongs to: the server
/// revokes it and answers `Ended` whether or not there was one. `set_deadline` bounds each frame as in `connect`.
pub fn end_session<S: Read + Write>(
    stream: &mut S,
    mut set_deadline: impl FnMut(&mut S, Instant),
    token: &str,
    deadline: Instant,
) -> Result<(), ChatError> {
    let request = Zeroizing::new(signin::encode_opening(&Opening::End { token }).map_err(|_| ChatError::SignInProtocol)?);
    let framed = Zeroizing::new(frame::encode(&request).map_err(|_| ChatError::SignInProtocol)?);
    set_deadline(stream, deadline);
    stream.write_all(&framed).and_then(|()| stream.flush()).map_err(|error| ChatError::Io(error.kind()))?;
    set_deadline(stream, deadline);
    let reply = match frame::read_frame(stream, SIGN_IN_REPLY_LIMIT) {
        Ok(Some(reply)) => reply,
        Ok(None) => return Err(ChatError::Io(io::ErrorKind::UnexpectedEof)),
        Err(error) => return Err(ChatError::Io(error.kind())),
    };
    match signin::decode_reply(reply.payload()).map_err(|_| ChatError::SignInProtocol)? {
        signin::Reply::Ended => Ok(()),
        _ => Err(ChatError::SignInProtocol),
    }
}
