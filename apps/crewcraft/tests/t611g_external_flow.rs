//! T611g: the app's external sign-in. The begin request and its answers over a scripted stream, and the whole flow
//! (begin, PKCE and state, the provider URL, the browser, the real loopback redirect, finish) with the server and the
//! browser played by the test.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::{self, Cursor, Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crewcraft::chat_session::{ChatError, ExternalStart, begin_external};
use crewcraft::external_flow::{ExternalServer, FlowError, run};
use crewcraft::lab_client::LabError;
use crewcraft::loopback::{LoopbackError, parse_query};
use crewcraft_proto::frame;
use crewcraft_proto::signin::{Reply, encode_reply};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const NONCE: &str = "__________________________________________8";

/// A stream that reads a scripted answer and keeps what was written.
struct Scripted {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for Scripted {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn answering(reply: &Reply<'_>) -> Scripted {
    Scripted { input: Cursor::new(frame::encode(&encode_reply(reply).unwrap()).unwrap()), output: Vec::new() }
}

fn start() -> ExternalStart {
    ExternalStart {
        issuer: "https://id.example.org/".into(),
        client_id: "chat".into(),
        authorization_endpoint: "https://id.example.org/authorize/".into(),
        nonce: Zeroizing::new(NONCE.into()),
    }
}

#[test]
fn begin_sends_one_frame_and_reads_the_start_or_a_refusal() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = answering(&Reply::ExternalStart {
        issuer: "https://id.example.org/",
        client_id: "chat",
        authorization_endpoint: "https://id.example.org/authorize/",
        nonce: NONCE,
    });
    let got = begin_external(&mut stream, |_, _| {}, deadline).unwrap().unwrap();
    assert_eq!(got, start());
    assert_eq!(stream.output, frame::encode(&[37]).unwrap());
    assert!(!format!("{got:?}").contains(NONCE), "Debug hides the nonce");

    let mut refused = answering(&Reply::Refused);
    assert_eq!(begin_external(&mut refused, |_, _| {}, deadline).unwrap(), None);
    let mut odd = answering(&Reply::Ended);
    assert!(matches!(begin_external(&mut odd, |_, _| {}, deadline), Err(ChatError::SignInProtocol)));
    let mut silent = Scripted { input: Cursor::new(Vec::new()), output: Vec::new() };
    assert!(matches!(begin_external(&mut silent, |_, _| {}, deadline), Err(ChatError::Io(_))));
}

/// The server, played by the test: it remembers what `finish` was given.
struct FakeServer {
    start: Option<ExternalStart>,
    finished: Mutex<Option<(String, String, String)>>,
    refuse_finish: bool,
}

impl ExternalServer for FakeServer {
    type Session = &'static str;
    fn begin(&self) -> Result<Option<ExternalStart>, LabError> {
        Ok(self.start.clone())
    }
    fn finish(&self, code: &str, verifier: &str, redirect_uri: &str) -> Result<&'static str, LabError> {
        *self.finished.lock().unwrap() = Some((code.into(), verifier.into(), redirect_uri.into()));
        if self.refuse_finish { Err(LabError::Usage) } else { Ok("signed in") }
    }
}

fn server() -> FakeServer {
    FakeServer { start: Some(start()), finished: Mutex::new(None), refuse_finish: false }
}

fn counter() -> impl FnMut() -> [u8; 32] {
    let mut n = 0u8;
    move || {
        n += 1;
        [n; 32]
    }
}

/// The browser, played by the test: it reads the URL the app opened and, if `answer`, sends the provider's redirect.
fn browser(seen: &Mutex<Vec<(String, String)>>, answer: bool) -> impl FnOnce(&str) -> io::Result<()> + '_ {
    move |url: &str| {
        let (endpoint, query) = url.split_once('?').unwrap();
        assert_eq!(endpoint, "https://id.example.org/authorize/");
        let params = parse_query(query);
        *seen.lock().unwrap() = params.clone();
        if answer {
            let get = |k: &str| params.iter().find(|(name, _)| name == k).unwrap().1.clone();
            let redirect = get("redirect_uri");
            let (authority, path) = redirect.trim_start_matches("http://").split_once('/').unwrap();
            let target = format!("/{path}?code=provider-code&state={}", get("state"));
            std::thread::spawn({
                let authority = authority.to_owned();
                move || {
                    let mut stream = TcpStream::connect(&authority).unwrap();
                    stream.write_all(format!("GET {target} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes()).unwrap();
                    let mut answer = String::new();
                    let _ = stream.read_to_string(&mut answer);
                }
            });
        }
        Ok(())
    }
}

#[test]
fn the_whole_flow_carries_the_right_values() {
    let server = server();
    let seen = Mutex::new(Vec::new());
    let session = run(&server, counter(), browser(&seen, true), Duration::from_secs(10)).unwrap();
    assert_eq!(session, "signed in");
    let params = seen.lock().unwrap().clone();
    let get = |k: &str| params.iter().find(|(name, _)| name == k).map(|(_, v)| v.clone()).unwrap();
    assert_eq!((get("response_type").as_str(), get("client_id").as_str(), get("nonce").as_str()), ("code", "chat", NONCE));
    assert_eq!(get("code_challenge_method"), "S256");
    assert!(get("redirect_uri").starts_with("http://127.0.0.1:"));
    let (code, verifier, redirect) = server.finished.lock().unwrap().clone().unwrap();
    assert_eq!(code, "provider-code");
    assert_eq!(redirect, get("redirect_uri"), "the same redirect URI goes to the finish");
    assert_eq!(URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())), get("code_challenge"), "the verifier matches the challenge");
    assert_ne!(get("state"), verifier, "state and verifier come from separate random draws");
}

#[test]
fn each_failure_is_named() {
    let no_provider = FakeServer { start: None, ..server() };
    assert!(matches!(run(&no_provider, counter(), |_: &str| Ok(()), Duration::from_secs(1)), Err(FlowError::NotOffered)));
    let seen = Mutex::new(Vec::new());
    let broken = run(&server(), counter(), |_: &str| Err(io::Error::new(io::ErrorKind::NotFound, "no browser")), Duration::from_secs(1));
    assert!(matches!(broken, Err(FlowError::Browser(io::ErrorKind::NotFound))));
    let started = Instant::now();
    assert!(matches!(
        run(&server(), counter(), browser(&seen, false), Duration::from_millis(400)),
        Err(FlowError::Loopback(LoopbackError::TimedOut))
    ));
    assert!(started.elapsed() < Duration::from_secs(5));
    let refusing = FakeServer { refuse_finish: true, ..server() };
    assert!(matches!(run(&refusing, counter(), browser(&seen, true), Duration::from_secs(10)), Err(FlowError::Server(_))));
}
