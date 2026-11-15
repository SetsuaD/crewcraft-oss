#![allow(clippy::unwrap_used)]

use std::cell::RefCell;
use std::io::{self, Cursor, Read, Write};
use std::rc::Rc;
use std::time::{Duration, Instant};

use crewcraft::chat_session::{ChatError, ChatSession};
use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::room_view::Shown;
use crewcraft_proto::frame::{self, MAX_FRAME};
use crewcraft_proto::handshake::{self, Hello};
use crewcraft_proto::push::{self, Push};
use crewcraft_proto::request::{self, Request, Response};
use crewcraft_proto::signin::{self, SignIn};

#[derive(Default)]
struct Observed {
    written: Vec<u8>,
    deadlines: Vec<Instant>,
}

struct Script {
    input: Cursor<Vec<u8>>,
    observed: Rc<RefCell<Observed>>,
    end: Option<io::ErrorKind>,
}

impl Read for Script {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let len = self.input.read(bytes)?;
        if let (0, Some(kind)) = (len, self.end) {
            return Err(kind.into());
        }
        Ok(len)
    }
}

impl Write for Script {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.observed.borrow_mut().written.extend(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

type TestSession = ChatSession<Script, fn(&mut Script, Instant)>;
const ROOM: &str = "lobby";
const ACCOUNT: &str = "alice@example.org";

fn credentials() -> SignIn<'static> {
    SignIn { email: ACCOUNT, password: "test password", code: "123456" }
}

fn record_deadline(stream: &mut Script, cutoff: Instant) {
    stream.observed.borrow_mut().deadlines.push(cutoff);
}

fn connect(payloads: Vec<Vec<u8>>, end: Option<io::ErrorKind>, deadline: Instant) -> (Result<TestSession, ChatError>, Rc<RefCell<Observed>>) {
    let observed = Rc::new(RefCell::new(Observed::default()));
    let input = payloads.iter().flat_map(|bytes| frame::encode(bytes).unwrap()).collect();
    let stream = Script { input: Cursor::new(input), observed: Rc::clone(&observed), end };
    let hello = Hello { min_version: 1, max_version: 1, features: 0, client: "test client".into() };
    let setter: fn(&mut Script, Instant) = record_deadline;
    let result = ChatSession::connect(stream, setter, &credentials(), hello, Settings::new(ACCOUNT), Duration::from_secs(5), deadline);
    (result, observed)
}

fn opening_replies() -> Vec<Vec<u8>> {
    let token = "A".repeat(signin::TOKEN_LEN);
    vec![
        signin::encode_reply(&signin::Reply::Accepted { token: &token }).unwrap(),
        handshake::encode_reply(&handshake::Reply::Welcome { version: 1, features: 0, server: "test server".into() }).unwrap(),
    ]
}

fn post_event(cursor: u64) -> Vec<u8> {
    push::encode_push(&Push::Posted { room: ROOM.into(), cursor, author: ACCOUNT.into(), html: "a message".into(), mentions: vec![] }).unwrap()
}

fn ok(id: u32, cursor: u64) -> Vec<u8> {
    request::encode_response(id, &Response::Ok { cursor }).unwrap()
}

#[test]
fn post_needs_its_ack_and_sync_replays_from_the_applied_cursor() {
    let mut replies = opening_replies();
    let joined = push::encode_push(&Push::Other { room: ROOM.into(), cursor: 1 }).unwrap();
    replies.extend([ok(99, 900), ok(1, 2), ok(2, 2), joined, post_event(2), ok(3, 2)]);
    let deadline = Instant::now() + Duration::from_secs(10);
    let (result, observed) = connect(replies, None, deadline);
    let mut chat = result.unwrap();
    assert_eq!(chat.post(ROOM, "a message", 0, 0, deadline), Ok(2));
    assert_eq!(chat.sync(ROOM, false, 0, 0, deadline), Ok(2));
    let view = chat.view(ROOM).unwrap();
    assert_eq!(view.cursor(), 2);
    assert!(matches!(view.shown().as_slice(), [Shown::Line(line)] if line.html == "a message" && line.cursor == 2));
    assert_eq!(chat.sync(ROOM, false, 0, 0, deadline), Ok(2));

    let observed = observed.borrow();
    let mut written = observed.written.as_slice();
    let sign_in = frame::read_frame(&mut written, MAX_FRAME).unwrap().unwrap();
    assert_eq!(signin::decode_request(sign_in.payload()).unwrap(), credentials());
    let hello = frame::read_frame(&mut written, MAX_FRAME).unwrap().unwrap();
    assert_eq!(handshake::decode_hello(hello.payload()).unwrap().client, "test client");
    let expected = [
        (1, Request::Post { room: ROOM.into(), text: "a message".into() }),
        (2, Request::Sync { room: ROOM.into(), cursor: 0 }),
        (3, Request::Sync { room: ROOM.into(), cursor: 2 }),
    ];
    for request in expected {
        let sent = frame::read_frame(&mut written, MAX_FRAME).unwrap().unwrap();
        assert_eq!(request::decode_request(sent.payload()).unwrap(), request);
    }
    assert!(written.is_empty());
    assert_eq!(observed.deadlines.len(), 13);
    assert!(observed.deadlines.iter().all(|cutoff| *cutoff <= deadline));
}

#[test]
fn refused_or_malformed_sign_in_never_sends_hello() {
    let deadline = Instant::now() + Duration::from_secs(10);
    let refused = signin::encode_reply(&signin::Reply::Refused).unwrap();
    let mut bad_acceptance = opening_replies().remove(0);
    bad_acceptance.truncate(signin::TOKEN_LEN);
    for (payload, error) in [(refused, ChatError::SignInRefused), (bad_acceptance, ChatError::SignInProtocol)] {
        let (result, observed) = connect(vec![payload], None, deadline);
        assert_eq!(result.err(), Some(error));
        let observed = observed.borrow();
        let mut written = observed.written.as_slice();
        let sign_in = frame::read_frame(&mut written, MAX_FRAME).unwrap().unwrap();
        assert_eq!(signin::decode_request(sign_in.payload()).unwrap(), credentials());
        assert!(written.is_empty());
    }
}

#[test]
fn a_post_without_its_ack_does_not_succeed_and_closes_the_session() {
    let mut replies = opening_replies();
    replies.push(ok(99, 2));
    let deadline = Instant::now() + Duration::from_secs(10);
    let (result, _) = connect(replies, None, deadline);
    let mut chat = result.unwrap();
    assert_eq!(chat.post(ROOM, "message", 0, 0, deadline), Err(ChatError::Io(io::ErrorKind::UnexpectedEof)));
    assert_eq!(chat.post(ROOM, "message", 0, 0, deadline), Err(ChatError::Closed));
}

#[test]
fn an_out_of_order_replay_reports_its_gap_and_keeps_the_applied_prefix() {
    let mut replies = opening_replies();
    replies.extend([ok(1, 3), post_event(1), post_event(3)]);
    let deadline = Instant::now() + Duration::from_secs(10);
    let (result, _) = connect(replies, None, deadline);
    let mut chat = result.unwrap();
    assert_eq!(chat.sync(ROOM, false, 0, 0, deadline), Err(ChatError::HistoryGap { reached: 1, head: 3 }));
    assert_eq!(chat.view(ROOM).unwrap().cursor(), 1);
    assert_eq!(chat.sync(ROOM, false, 0, 0, deadline), Err(ChatError::Closed));
}

#[test]
fn a_head_without_the_full_batch_reports_an_incomplete_sync() {
    let mut replies = opening_replies();
    replies.extend([ok(1, 3), post_event(1)]);
    let deadline = Instant::now() + Duration::from_secs(10);
    let (result, _) = connect(replies, Some(io::ErrorKind::TimedOut), deadline);
    let mut chat = result.unwrap();
    assert_eq!(chat.sync(ROOM, false, 0, 0, deadline), Err(ChatError::SyncIncomplete { reached: 1, head: 3, reason: io::ErrorKind::TimedOut }),);
    assert_eq!(chat.view(ROOM).unwrap().cursor(), 1);
}
