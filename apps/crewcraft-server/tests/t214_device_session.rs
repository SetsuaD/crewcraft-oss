#![allow(clippy::unwrap_used)]

use std::cell::Cell;
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_proto::frame::encode;
use crewcraft_proto::handshake::{self, Hello, ServerSide};
use crewcraft_proto::push::{Push, encode_push};
use crewcraft_proto::request::{Request, Response, encode_request, encode_response};
use crewcraft_proto::signin::{self, SignIn, TOKEN_LEN};
use crewcraft_server::device_session::{AuthError, CommittedSignIn, DeviceAuth, DeviceSessionError, serve};
use crewcraft_server_core::durable::DurableServer;

struct JournalPath(PathBuf);

impl JournalPath {
    fn new(test: &str) -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        Self(std::env::temp_dir().join(format!("crewcraft-t214-{test}-{}-{nonce}", std::process::id())))
    }
}

impl Drop for JournalPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct Script {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Script {
    fn new(input: Vec<u8>) -> Self {
        Self { input: Cursor::new(input), output: Vec::new() }
    }
}

impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for Script {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Auth {
    decision: Result<bool, AuthError>,
    allowed_frames: usize,
    sign_ins: Cell<usize>,
    checks: Cell<usize>,
}

impl Auth {
    fn new(decision: Result<bool, AuthError>, allowed_frames: usize) -> Self {
        Self { decision, allowed_frames, sign_ins: Cell::new(0), checks: Cell::new(0) }
    }
}

impl DeviceAuth for Auth {
    type Session = u64;

    fn sign_in(&self, credentials: SignIn<'_>, now_ms: u64) -> Result<Option<CommittedSignIn<Self::Session>>, AuthError> {
        assert_eq!(credentials.email, "alias@example.org");
        self.sign_ins.set(self.sign_ins.get() + 1);
        self.decision.map(|accepted| accepted.then(|| CommittedSignIn { user: "alice".into(), token: "A".repeat(TOKEN_LEN), session: now_ms }))
    }

    fn with_live_session<T>(&self, session: &Self::Session, now_ms: u64, action: impl FnOnce() -> T) -> Result<Option<T>, AuthError> {
        assert!(*session < now_ms);
        let checks = self.checks.get();
        self.checks.set(checks + 1);
        Ok((checks < self.allowed_frames).then(action))
    }
}

fn run(script: &mut Script, auth: &Auth, rooms: &Mutex<DurableServer>) -> Result<(), DeviceSessionError> {
    let server = ServerSide { min_version: 1, max_version: 1, features: 0, name: "server".into() };
    let mut now_ms = 0;
    serve(
        script,
        auth,
        rooms,
        server,
        |_| Ok(()),
        || {
            now_ms += 1;
            now_ms
        },
    )
}

fn sign_in(password: &str, code: &str) -> Vec<u8> {
    let request = SignIn { email: "alias@example.org", password, code };
    encode(&signin::encode_request(&request).unwrap()).unwrap()
}

fn sign_in_reply(reply: signin::Reply<'_>) -> Vec<u8> {
    encode(&signin::encode_reply(&reply).unwrap()).unwrap()
}

fn hello() -> Vec<u8> {
    let hello = Hello { min_version: 1, max_version: 1, features: 0, client: "client".into() };
    encode(&handshake::encode_hello(&hello).unwrap()).unwrap()
}

fn signed_in_prefix() -> Vec<u8> {
    let mut output = sign_in_reply(signin::Reply::Accepted { token: &"A".repeat(TOKEN_LEN) });
    let welcome = handshake::Reply::Welcome { version: 1, features: 0, server: "server".into() };
    output.extend(encode(&handshake::encode_reply(&welcome).unwrap()).unwrap());
    output
}

fn signed_in_request(request: Request) -> Script {
    let mut input = sign_in("fixture password", "123456");
    input.extend(hello());
    input.extend(encode(&encode_request(1, &request).unwrap()).unwrap());
    Script::new(input)
}

#[test]
fn bad_credentials_produce_one_refusal_and_leave_hello_unread() {
    let journal = JournalPath::new("refused");
    let rooms = Mutex::new(DurableServer::open(&journal.0).unwrap());
    for (password, code) in [("wrong password", "123456"), ("fixture password", "000000")] {
        let auth = Auth::new(Ok(false), 0);
        let mut input = sign_in(password, code);
        let sign_in_end = input.len() as u64;
        input.extend(hello());
        let mut script = Script::new(input);
        run(&mut script, &auth, &rooms).unwrap();
        assert_eq!(script.output, sign_in_reply(signin::Reply::Refused));
        assert_eq!(script.input.position(), sign_in_end);
        assert_eq!(auth.sign_ins.get(), 1);
        assert_eq!(auth.checks.get(), 0);
    }
}

#[test]
fn hello_first_and_auth_errors_close_without_a_reply() {
    let journal = JournalPath::new("closed");
    let rooms = Mutex::new(DurableServer::open(&journal.0).unwrap());
    let auth = Auth::new(Ok(true), 0);
    let mut script = Script::new(hello());
    assert_eq!(run(&mut script, &auth, &rooms), Err(DeviceSessionError::InvalidSignIn));
    assert!(script.output.is_empty());
    assert_eq!(auth.sign_ins.get(), 0);

    for error in [AuthError::Unavailable, AuthError::UnauthorizedDevice] {
        let auth = Auth::new(Err(error), 0);
        let mut script = Script::new(sign_in("fixture password", "123456"));
        assert_eq!(run(&mut script, &auth, &rooms), Err(DeviceSessionError::Auth(error)));
        assert!(script.output.is_empty());
    }
}

#[test]
fn account_authorization_precedes_each_durable_chat_operation() {
    let journal = JournalPath::new("replay");
    let room;
    {
        let mut server = DurableServer::open(&journal.0).unwrap();
        room = server.create_room("alice", "General").unwrap();
        let rooms = Mutex::new(server);
        let post = || Request::Post { room: room.clone(), text: "hello".into() };

        let revoked_after_hello = Auth::new(Ok(true), 1);
        let mut denied = signed_in_request(post());
        assert_eq!(run(&mut denied, &revoked_after_hello, &rooms), Err(DeviceSessionError::SessionEnded));
        assert_eq!(denied.output, signed_in_prefix());
        assert_eq!(revoked_after_hello.checks.get(), 2);

        let auth = Auth::new(Ok(true), 2);
        let mut accepted = signed_in_request(post());
        run(&mut accepted, &auth, &rooms).unwrap();
        let mut expected = signed_in_prefix();
        expected.extend(encode(&encode_response(1, &Response::Ok { cursor: 1 }).unwrap()).unwrap());
        assert_eq!(accepted.output, expected);
        assert_eq!(auth.checks.get(), 2);
    }

    let rooms = Mutex::new(DurableServer::open(&journal.0).unwrap());
    let auth = Auth::new(Ok(true), 2);
    let mut script = signed_in_request(Request::Sync { room: room.clone(), cursor: 0 });
    run(&mut script, &auth, &rooms).unwrap();
    let mut expected = signed_in_prefix();
    expected.extend(encode(&encode_response(1, &Response::Ok { cursor: 1 }).unwrap()).unwrap());
    let push = Push::Posted { room, cursor: 1, author: "alice".into(), html: "hello".into(), mentions: vec![] };
    expected.extend(encode(&encode_push(&push).unwrap()).unwrap());
    assert_eq!(script.output, expected);
}
