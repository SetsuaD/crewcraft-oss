//! Two enrolled devices, each behind its own connection worker, talk through an in-test loopback chat server: the
//! real admission verifier and the real server-side chat session, with test-only accounts and certificates.
#![allow(clippy::unwrap_used, clippy::panic, clippy::unreachable)]

use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::signed_in::Credentials;
use crewcraft::worker::{Event, Problem, Worker, WorkerConfig};
use crewcraft_admission::{Admission, Class, admit, server_config};
use crewcraft_client_core::room_view::Shown;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_pki::{Authority, Claims, Status};
use crewcraft_proto::frame;
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::signin;
use crewcraft_server_core::room::Role;
use crewcraft_server_core::server::Server;
use crewcraft_server_core::session::Session;
use crewcraft_totp::Totp;
use crewcraft_ui_model::Command;
use rcgen::{CertificateParams, KeyPair};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{RootCertStore, ServerConfig};

const WAIT: Duration = Duration::from_secs(10);
const IDLE: Duration = Duration::from_secs(30);
const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";
const PASSWORD: &str = "synthetic password";

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn code_at(person: &str, unix_seconds: u64) -> String {
    let secret = vec![if person == ALICE { 17 } else { 23 }; 20];
    Totp::with_defaults(secret).unwrap().generate(unix_seconds)
}

fn code(person: &str) -> String {
    code_at(person, now_ms() / 1000)
}

/// The fixture server accepts the current code and the one before it, so a step boundary between the client
/// reading its code and the server checking it does not fail the test.
fn code_ok(person: &str, code: &str) -> bool {
    let now = now_ms() / 1000;
    code == code_at(person, now) || code == code_at(person, now.saturating_sub(30))
}

/// Admits exactly the device certificates the fixture authority issued.
struct Devices(Mutex<Authority>);

impl std::fmt::Debug for Devices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Devices(..)")
    }
}

impl Devices {
    fn person(&self, certificate: &[u8]) -> Option<String> {
        match self.0.lock().ok()?.status(certificate, now_ms()) {
            Ok(Status::Good(info)) => Some(info.person),
            _ => None,
        }
    }
}

impl Admission for Devices {
    fn device_ok(&self, certificate: &[u8]) -> bool {
        self.person(certificate).is_some()
    }

    fn bootstrap_key_live(&self, _: &[u8; 32]) -> bool {
        false
    }
}

struct Lab {
    devices: Arc<Devices>,
    config: Arc<ServerConfig>,
    rooms: Arc<Mutex<Server>>,
    root: Vec<u8>,
    room: String,
    alice: Arc<dyn ResolvesClientCert>,
    bob: Arc<dyn ResolvesClientCert>,
}

fn device(issuer: &mut Authority, person: &str, device_id: u64) -> Arc<dyn ResolvesClientCert> {
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
    let issued = issuer.issue_device(csr.der(), &Claims { person, device_id }, now_ms()).unwrap();
    let chain = issued.chain.into_iter().map(CertificateDer::from).collect();
    let key = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
    Arc::new(SingleCertAndKey::from(CertifiedKey::from_der(chain, key, &rustls::crypto::ring::default_provider()).unwrap()))
}

fn lab() -> Lab {
    let root = Authority::create_root("Lab Root", now_ms()).unwrap();
    let mut issuer = root.create_issuing("Lab Issuing", now_ms()).unwrap();
    let alice = device(&mut issuer, ALICE, 1);
    let bob = device(&mut issuer, BOB, 2);
    let identity = issuer.server_certificate("localhost", now_ms()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root.certificate().to_vec())).unwrap();
    let devices = Arc::new(Devices(Mutex::new(issuer)));
    let chain = identity.chain.into_iter().map(CertificateDer::from).collect();
    let config = server_config((chain, PrivatePkcs8KeyDer::from(identity.key_pkcs8).into()), roots, devices.clone()).unwrap();
    let mut rooms = Server::new();
    let room = rooms.create_room(ALICE, "General").unwrap();
    rooms.add_member(&room, ALICE, BOB, Role::Member).unwrap();
    Lab { devices, config, rooms: Arc::new(Mutex::new(rooms)), root: root.certificate().to_vec(), room, alice, bob }
}

/// A loopback chat server. `stop` closes the listener and every open connection, as a server going away would.
struct ChatServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    connections: Arc<Mutex<Vec<TcpStream>>>,
    accept: Option<JoinHandle<()>>,
    /// The person whose connection just ended, once per connection.
    ended: Receiver<String>,
}

impl ChatServer {
    fn start(lab: &Lab, address: &str) -> Self {
        let listener = TcpListener::bind(address).unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let (ended_sender, ended) = mpsc::channel();
        let (flag, open, devices, config, rooms) = (stop.clone(), connections.clone(), lab.devices.clone(), lab.config.clone(), lab.rooms.clone());
        let accept = thread::spawn(move || {
            for tcp in listener.incoming() {
                if flag.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(tcp) = tcp else { continue };
                open.lock().unwrap().push(tcp.try_clone().unwrap());
                let (devices, config, rooms, ended) = (devices.clone(), config.clone(), rooms.clone(), ended_sender.clone());
                thread::spawn(move || serve(tcp, &devices, config, &rooms, &ended));
            }
        });
        Self { address, stop, connections, accept: Some(accept), ended }
    }

    fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(accept) = self.accept.take() {
            accept.join().unwrap();
        }
        for connection in self.connections.lock().unwrap().drain(..) {
            let _ = connection.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for ChatServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// One connection: admission, then a sign-in checked against the fixture accounts, then the server-core session.
fn serve(tcp: TcpStream, devices: &Devices, config: Arc<ServerConfig>, rooms: &Mutex<Server>, ended: &Sender<String>) {
    let Ok(admitted) = admit(tcp, config, WAIT, devices, (now_ms() / 1000) as i64) else { return };
    let Some(person) = devices.person(admitted.certificate()).filter(|_| admitted.class == Class::Device) else { return };
    let mut stream = admitted.stream;
    stream.sock.set_read_timeout(Some(IDLE)).unwrap();
    stream.sock.set_write_timeout(Some(WAIT)).unwrap();
    let mut run = || -> Option<()> {
        let first = frame::read_frame(&mut stream, frame::MAX_FRAME).ok()??;
        let request = signin::decode_request(first.payload()).ok()?;
        let accepted = request.email == person && request.password == PASSWORD && code_ok(&person, request.code);
        let token = "A".repeat(signin::TOKEN_LEN);
        let reply = if accepted { signin::Reply::Accepted { token: &token } } else { signin::Reply::Refused };
        stream.write_all(&frame::encode(&signin::encode_reply(&reply).ok()?).ok()?).ok()?;
        stream.flush().ok()?;
        if !accepted {
            return None;
        }
        let mut session = Session::new(&person, ServerSide { min_version: 1, max_version: 1, features: 0, name: "test server".into() });
        loop {
            let request = frame::read_frame(&mut stream, frame::MAX_FRAME).ok()??;
            let reply = session.receive(&mut rooms.lock().unwrap(), request.as_bytes(), now_ms()).ok()?;
            if !reply.is_empty() {
                stream.write_all(&reply).ok()?;
                stream.flush().ok()?;
            }
        }
    };
    let _ = run();
    let _ = ended.send(person);
}

fn fast() -> WorkerConfig {
    WorkerConfig { poll_interval: Duration::from_millis(100), first_retry: Duration::from_millis(100), max_retry: Duration::from_millis(400) }
}

fn worker(lab: &Lab, server: &ChatServer, device: &Arc<dyn ResolvesClientCert>) -> (Worker, Receiver<Event>) {
    let endpoint = ServerEndpoint::new(&server.address.to_string(), "localhost", RootFingerprint::from_der(&lab.root), &lab.root).unwrap();
    Worker::start(endpoint, device.clone(), fast(), || {}).unwrap()
}

fn credentials(person: &str) -> Credentials {
    Credentials::new(person, PASSWORD, &code(person)).unwrap()
}

/// Wait for the first event `wanted` accepts, skipping others. Panics after `WAIT` or when the worker is gone.
fn expect(events: &Receiver<Event>, what: &str, wanted: impl Fn(&Event) -> bool) -> Event {
    let deadline = Instant::now() + WAIT;
    loop {
        match events.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(event) if wanted(&event) => return event,
            Ok(_) => {}
            Err(error) => panic!("no {what} event: {error:?}"),
        }
    }
}

fn has_line(shown: &[Shown], author: &str, html: &str) -> bool {
    shown.iter().any(|entry| matches!(entry, Shown::Line(line) if line.author == author && line.html == html))
}

#[test]
fn a_post_through_one_worker_reaches_the_other_workers_snapshot() {
    let lab = lab();
    let server = ChatServer::start(&lab, "127.0.0.1:0");
    let room = lab.room.clone();
    let (alice, alice_events) = worker(&lab, &server, &lab.alice);
    let (bob, bob_events) = worker(&lab, &server, &lab.bob);

    // Commands before sign-in are reported, not lost silently.
    bob.send(Command::Post { room: room.clone(), text: "too early".into() });
    let early = expect(&bob_events, "post failure", |event| matches!(event, Event::PostFailed { .. }));
    assert_eq!(early, Event::PostFailed { room: room.clone(), text: "too early".into(), problem: Problem::NotSignedIn });

    // A wrong password is refused with no detail.
    bob.sign_in(Credentials::new(BOB, "not the password", &code(BOB)).unwrap());
    expect(&bob_events, "connected", |event| *event == Event::Connected);
    expect(&bob_events, "refusal", |event| *event == Event::Failed(Problem::SignInRefused));
    assert!(Problem::SignInRefused.to_string().contains("not accepted"));

    bob.sign_in(credentials(BOB));
    expect(&bob_events, "signed in", |event| matches!(event, Event::SignedIn { .. }));
    bob.send(Command::Sync { room: room.clone() });
    let opened = expect(&bob_events, "first snapshot", |event| matches!(event, Event::Room { .. }));
    assert_eq!(opened, Event::Room { room: room.clone(), shown: Vec::new() });

    alice.sign_in(credentials(ALICE));
    let signed_in = expect(&alice_events, "signed in", |event| matches!(event, Event::SignedIn { .. }));
    assert_eq!(signed_in, Event::SignedIn { email: ALICE.into(), rooms: Vec::new() });
    alice.send(Command::Post { room: room.clone(), text: "Hello from Alice".into() });
    let posted = expect(&alice_events, "acknowledgement", |event| matches!(event, Event::Posted { .. }));
    let Event::Posted { cursor, .. } = posted else { unreachable!() };
    assert!(cursor > 0);

    // Bob's worker keeps syncing the open room and delivers a snapshot with Alice's message.
    let delivered = expect(
        &bob_events,
        "snapshot with the post",
        |event| matches!(event, Event::Room { shown, .. } if has_line(shown, ALICE, "Hello from Alice")),
    );
    let Event::Room { room: delivered_room, shown } = delivered else { unreachable!() };
    assert_eq!(delivered_room, room);
    assert!(matches!(&shown[..], [Shown::Line(line)] if line.cursor == cursor && !line.edited));

    // Alice follows the room without having it open, so Bob's reply counts as unread for her; her own post did not.
    bob.send(Command::Post { room: room.clone(), text: "Hello from Bob".into() });
    expect(&bob_events, "acknowledgement", |event| matches!(event, Event::Posted { .. }));
    expect(&alice_events, "unread count", |event| *event == Event::Unread { room: room.clone(), count: 1 });
    alice.send(Command::Sync { room: room.clone() });
    let both = expect(&alice_events, "snapshot", |event| matches!(event, Event::Room { .. }));
    let Event::Room { shown, .. } = both else { unreachable!() };
    assert!(has_line(&shown, ALICE, "Hello from Alice") && has_line(&shown, BOB, "Hello from Bob"));
    expect(&alice_events, "unread reset", |event| *event == Event::Unread { room: room.clone(), count: 0 });

    // A room the person is not in is refused by the server without ending the session.
    bob.send(Command::Sync { room: "no-such-room".into() });
    expect(&bob_events, "refusal", |event| matches!(event, Event::Failed(Problem::Refused(_))));
    bob.send(Command::Post { room: room.clone(), text: "still here".into() });
    expect(&bob_events, "acknowledgement", |event| matches!(event, Event::Posted { .. }));
}

#[test]
fn dropping_a_worker_closes_its_connection_and_ends_its_thread() {
    let lab = lab();
    let server = ChatServer::start(&lab, "127.0.0.1:0");
    let (alice, events) = worker(&lab, &server, &lab.alice);
    alice.sign_in(credentials(ALICE));
    expect(&events, "signed in", |event| matches!(event, Event::SignedIn { .. }));
    alice.send(Command::Sync { room: lab.room.clone() });
    expect(&events, "snapshot", |event| matches!(event, Event::Room { .. }));

    let started = Instant::now();
    drop(alice);
    assert!(started.elapsed() < Duration::from_secs(2), "drop took {:?}", started.elapsed());
    assert_eq!(server.ended.recv_timeout(WAIT).unwrap(), ALICE, "the server saw the connection close");
    // The thread owned the event sender; the channel closes once the thread has ended.
    let deadline = Instant::now() + WAIT;
    loop {
        match events.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(_) => {}
            Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => panic!("the worker thread is still running"),
        }
    }

    // A worker that never signed in stops as promptly.
    let (idle, idle_events) = worker(&lab, &server, &lab.bob);
    let started = Instant::now();
    drop(idle);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(idle_events.recv_timeout(WAIT), Err(RecvTimeoutError::Disconnected));
}

#[test]
fn a_server_that_goes_away_produces_a_failure_and_the_worker_finds_it_again() {
    let lab = lab();
    let mut server = ChatServer::start(&lab, "127.0.0.1:0");
    let address = server.address;
    let room = lab.room.clone();
    let (alice, events) = worker(&lab, &server, &lab.alice);
    alice.sign_in(credentials(ALICE));
    expect(&events, "signed in", |event| matches!(event, Event::SignedIn { .. }));
    alice.send(Command::Post { room: room.clone(), text: "before".into() });
    alice.send(Command::Sync { room: room.clone() });
    expect(&events, "snapshot", |event| matches!(event, Event::Room { shown, .. } if has_line(shown, ALICE, "before")));

    server.stop();
    let failed = expect(&events, "failure", |event| matches!(event, Event::Failed(_)));
    assert!(matches!(failed, Event::Failed(Problem::Lost(_) | Problem::Protocol)), "{failed:?}");
    alice.send(Command::Post { room: room.clone(), text: "while away".into() });
    let refused = expect(&events, "post failure", |event| matches!(event, Event::PostFailed { .. }));
    assert_eq!(refused, Event::PostFailed { room: room.clone(), text: "while away".into(), problem: Problem::NotSignedIn });

    // The server comes back at the same address: the worker's backoff finds it and, holding a resume ticket (T240),
    // tries to resume. This test server cannot resume a session (it closes the connection, as a server older than
    // T240 does), so the worker reports SessionEnded and Connected, and a sign-in with a fresh code restores the open
    // room.
    let _back = ChatServer::start(&lab, &address.to_string());
    expect(&events, "session ended", |event| *event == Event::SessionEnded);
    expect(&events, "reconnected", |event| *event == Event::Connected);
    alice.sign_in(credentials(ALICE));
    let signed_in = expect(&events, "signed in", |event| matches!(event, Event::SignedIn { .. }));
    assert_eq!(signed_in, Event::SignedIn { email: ALICE.into(), rooms: vec![room.clone()] });
    expect(&events, "snapshot", |event| matches!(event, Event::Room { shown, .. } if has_line(shown, ALICE, "before")));

    let started = Instant::now();
    drop(alice);
    assert!(started.elapsed() < Duration::from_secs(2));
}
