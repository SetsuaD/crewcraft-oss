//! A person's rooms: the `ListRooms` request and the room list that answers it, the server listing only the caller's
//! memberships, and the connection worker reporting them at sign-in. Task T233.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::Write;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::signed_in::Credentials;
use crewcraft::worker::{Event, Worker, WorkerConfig};
use crewcraft_admission::{Admission, Class, admit, server_config};
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_pki::{Authority, Claims, Status};
use crewcraft_proto::frame::{self, Decoder};
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::message::{CodecError, MAX_NAME};
use crewcraft_proto::request::{
    FEATURE_LIST_ROOMS, MAX_ROOMS, ROOMS_TAG, Request, Response, decode_request, decode_response, decode_rooms, encode_request, encode_response,
    encode_rooms,
};
use crewcraft_proto::signin;
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::dispatch::{handle, listed_rooms};
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
const CAROL: &str = "carol@example.org";
const PASSWORD: &str = "synthetic password";

// --- The codec ---

#[test]
fn list_rooms_and_the_room_list_round_trip() {
    let bytes = encode_request(9, &Request::ListRooms).unwrap();
    assert_eq!(bytes, [8, 0, 0, 0, 9]);
    assert_eq!(decode_request(&bytes).unwrap(), (9, Request::ListRooms));
    assert_eq!(decode_request(&[8, 0, 0]), Err(CodecError::Truncated));
    assert_eq!(decode_request(&[8, 0, 0, 0, 9, 0]), Err(CodecError::TrailingBytes));

    let rooms = vec!["general".to_owned(), "projects".to_owned()];
    let bytes = encode_rooms(9, &rooms).unwrap();
    let mut expected = vec![ROOMS_TAG, 0, 0, 0, 9, 0, 2, 0, 7];
    expected.extend_from_slice(b"general");
    expected.extend_from_slice(&[0, 8]);
    expected.extend_from_slice(b"projects");
    assert_eq!(bytes, expected);
    assert_eq!(decode_rooms(&bytes).unwrap(), (9, rooms));

    let bytes = encode_rooms(1, &[]).unwrap();
    assert_eq!(bytes, [ROOMS_TAG, 0, 0, 0, 1, 0, 0]);
    assert_eq!(decode_rooms(&bytes).unwrap(), (1, Vec::new()));

    // The largest list fits one frame.
    let most: Vec<String> = (0..MAX_ROOMS).map(|index| format!("{index:0>width$}", width = MAX_NAME)).collect();
    let bytes = encode_rooms(2, &most).unwrap();
    assert!(frame::encode(&bytes).is_ok());
    assert_eq!(decode_rooms(&bytes).unwrap(), (2, most));

    // The existing tag spaces are unchanged: 7 is not a request, 130 and 131 are not responses, and a response is not
    // a room list.
    assert_eq!(ROOMS_TAG, 131);
    assert_eq!(decode_request(&[7, 0, 0, 0, 1]), Err(CodecError::BadKind(7)));
    assert_eq!(decode_response(&[130, 0, 0, 0, 1]), Err(CodecError::BadKind(130)));
    assert_eq!(decode_response(&[ROOMS_TAG, 0, 0, 0, 1, 0, 0]), Err(CodecError::BadKind(ROOMS_TAG)));
    assert_eq!(decode_rooms(&encode_response(1, &Response::Ok { cursor: 0 }).unwrap()), Err(CodecError::BadKind(128)));
    assert_eq!(FEATURE_LIST_ROOMS.count_ones(), 1);
}

#[test]
fn oversized_or_malformed_room_lists_are_refused() {
    let too_many: Vec<String> = (0..=MAX_ROOMS).map(|index| format!("room-{index}")).collect();
    assert_eq!(encode_rooms(1, &too_many), Err(CodecError::FieldLength));
    for bad in [String::new(), "a".repeat(MAX_NAME + 1)] {
        assert_eq!(encode_rooms(1, &["general".to_owned(), bad]), Err(CodecError::FieldLength));
    }

    // A count above the limit is refused before any room is read.
    let count = (MAX_ROOMS as u16 + 1).to_be_bytes();
    assert_eq!(decode_rooms(&[ROOMS_TAG, 0, 0, 0, 1, count[0], count[1]]), Err(CodecError::FieldLength));
    assert_eq!(decode_rooms(&[ROOMS_TAG, 0, 0, 0, 1, 0xff, 0xff]), Err(CodecError::FieldLength));
    // An empty or too-long name is refused by its length.
    assert_eq!(decode_rooms(&[ROOMS_TAG, 0, 0, 0, 1, 0, 1, 0, 0]), Err(CodecError::FieldLength));
    let long = (MAX_NAME as u16 + 1).to_be_bytes();
    assert_eq!(decode_rooms(&[ROOMS_TAG, 0, 0, 0, 1, 0, 1, long[0], long[1]]), Err(CodecError::FieldLength));
    assert_eq!(decode_rooms(&[ROOMS_TAG, 0, 0, 0, 1, 0, 1, 0, 1, 0xff]), Err(CodecError::BadUtf8));

    let bytes = encode_rooms(3, &["general".to_owned(), "projects".to_owned()]).unwrap();
    for end in 0..bytes.len() {
        assert_eq!(decode_rooms(&bytes[..end]), Err(CodecError::Truncated), "{end}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert_eq!(decode_rooms(&extra), Err(CodecError::TrailingBytes));
}

// --- The server ---

/// `ListRooms` through `dispatch::handle` and through a connection: the count, then the names.
fn listed(server: &mut Server, user: &str) -> Vec<String> {
    let rooms = listed_rooms(server, user);
    assert_eq!(handle(server, user, &Request::ListRooms, 0), Response::Ok { cursor: rooms.len() as u64 });
    let mut connection = Connection::new(user);
    let request = frame::encode(&encode_request(5, &Request::ListRooms).unwrap()).unwrap();
    let out = connection.receive(server, &request, 0).unwrap();
    let mut decoder = Decoder::new();
    decoder.push(&out);
    let answer = decoder.next_frame().unwrap().unwrap();
    assert_eq!(decode_response(&answer).unwrap(), (5, Response::Ok { cursor: rooms.len() as u64 }));
    let list = decoder.next_frame().unwrap().unwrap();
    assert_eq!(decode_rooms(&list).unwrap(), (5, rooms.clone()));
    assert_eq!(decoder.next_frame().unwrap(), None);
    rooms
}

#[test]
fn the_server_lists_only_the_callers_rooms() {
    let mut server = Server::new();
    let general = server.create_room(BOB, "General").unwrap();
    let projects = server.create_room(BOB, "Projects").unwrap();
    let private = server.create_room(BOB, "Private").unwrap();
    let carols = server.create_room(CAROL, "Carol Room").unwrap();
    server.add_member(&projects, BOB, ALICE, Role::Member).unwrap();
    server.add_member(&general, BOB, ALICE, Role::Guest).unwrap();

    assert_eq!(listed(&mut server, ALICE), vec![general.clone(), projects.clone()]);
    let mut bobs = vec![general.clone(), private.clone(), projects.clone()];
    bobs.sort();
    assert_eq!(listed(&mut server, BOB), bobs);
    assert_eq!(listed(&mut server, CAROL), vec![carols]);
    assert_eq!(listed(&mut server, "nobody@example.org"), Vec::<String>::new());

    server.remove_member(&projects, BOB, ALICE).unwrap();
    assert_eq!(listed(&mut server, ALICE), vec![general]);
}

#[test]
fn a_person_in_more_rooms_than_one_list_holds_gets_the_first_by_name() {
    let mut server = Server::new();
    for index in 0..=MAX_ROOMS {
        server.create_room(ALICE, &format!("Room {index:04}")).unwrap();
    }
    let rooms = listed(&mut server, ALICE);
    assert_eq!(rooms.len(), MAX_ROOMS);
    assert_eq!(rooms.first().map(String::as_str), Some("room-0000"));
    assert!(!rooms.contains(&format!("room-{MAX_ROOMS:04}")));
}

// --- The connection worker ---

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn code_at(person: &str, unix_seconds: u64) -> String {
    let secret = vec![if person == ALICE { 29 } else { 31 }; 20];
    Totp::with_defaults(secret).unwrap().generate(unix_seconds)
}

fn code_ok(person: &str, code: &str) -> bool {
    let now = now_ms() / 1000;
    code == code_at(person, now) || code == code_at(person, now.saturating_sub(30))
}

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

fn device(issuer: &mut Authority, person: &str, device_id: u64) -> Arc<dyn ResolvesClientCert> {
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
    let issued = issuer.issue_device(csr.der(), &Claims { person, device_id }, now_ms()).unwrap();
    let chain = issued.chain.into_iter().map(CertificateDer::from).collect();
    let key = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
    Arc::new(SingleCertAndKey::from(CertifiedKey::from_der(chain, key, &rustls::crypto::ring::default_provider()).unwrap()))
}

struct Lab {
    devices: Arc<Devices>,
    config: Arc<ServerConfig>,
    rooms: Arc<Mutex<Server>>,
    root: Vec<u8>,
    alice: Arc<dyn ResolvesClientCert>,
    general: String,
    projects: String,
}

/// Bob owns three rooms and adds Alice to two of them; he has already posted in one.
fn lab() -> Lab {
    let root = Authority::create_root("Lab Root", now_ms()).unwrap();
    let mut issuer = root.create_issuing("Lab Issuing", now_ms()).unwrap();
    let alice = device(&mut issuer, ALICE, 1);
    let identity = issuer.server_certificate("localhost", now_ms()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root.certificate().to_vec())).unwrap();
    let devices = Arc::new(Devices(Mutex::new(issuer)));
    let chain = identity.chain.into_iter().map(CertificateDer::from).collect();
    let config = server_config((chain, PrivatePkcs8KeyDer::from(identity.key_pkcs8).into()), roots, devices.clone()).unwrap();
    let mut rooms = Server::new();
    let general = rooms.create_room(BOB, "General").unwrap();
    let projects = rooms.create_room(BOB, "Projects").unwrap();
    rooms.create_room(BOB, "Private").unwrap();
    rooms.add_member(&general, BOB, ALICE, Role::Member).unwrap();
    rooms.add_member(&projects, BOB, ALICE, Role::Member).unwrap();
    rooms.post(&projects, BOB, "Welcome to projects", now_ms()).unwrap();
    Lab { devices, config, rooms: Arc::new(Mutex::new(rooms)), root: root.certificate().to_vec(), alice, general, projects }
}

struct ChatServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    connections: Arc<Mutex<Vec<TcpStream>>>,
    accept: Option<JoinHandle<()>>,
}

impl ChatServer {
    /// A loopback chat server agreeing to `features` in the handshake.
    fn start(lab: &Lab, features: u32) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let (flag, open, devices, config, rooms) = (stop.clone(), connections.clone(), lab.devices.clone(), lab.config.clone(), lab.rooms.clone());
        let accept = thread::spawn(move || {
            for tcp in listener.incoming() {
                if flag.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(tcp) = tcp else { continue };
                open.lock().unwrap().push(tcp.try_clone().unwrap());
                let (devices, config, rooms) = (devices.clone(), config.clone(), rooms.clone());
                thread::spawn(move || serve(tcp, &devices, config, &rooms, features));
            }
        });
        Self { address, stop, connections, accept: Some(accept) }
    }
}

impl Drop for ChatServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        for connection in self.connections.lock().unwrap().drain(..) {
            let _ = connection.shutdown(Shutdown::Both);
        }
    }
}

fn serve(tcp: TcpStream, devices: &Devices, config: Arc<ServerConfig>, rooms: &Mutex<Server>, features: u32) {
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
        let mut session = Session::new(&person, ServerSide { min_version: 1, max_version: 1, features, name: "test server".into() });
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
}

fn worker(lab: &Lab, server: &ChatServer) -> (Worker, Receiver<Event>) {
    let endpoint = ServerEndpoint::new(&server.address.to_string(), "localhost", RootFingerprint::from_der(&lab.root), &lab.root).unwrap();
    let config =
        WorkerConfig { poll_interval: Duration::from_millis(100), first_retry: Duration::from_millis(100), max_retry: Duration::from_millis(400) };
    Worker::start(endpoint, lab.alice.clone(), config, || {}).unwrap()
}

fn credentials() -> Credentials {
    Credentials::new(ALICE, PASSWORD, &code_at(ALICE, now_ms() / 1000)).unwrap()
}

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

#[test]
fn a_person_added_to_two_rooms_sees_both_at_sign_in_with_unread_counts() {
    let lab = lab();
    let server = ChatServer::start(&lab, FEATURE_LIST_ROOMS);
    let (alice, events) = worker(&lab, &server);

    // A room opened before sign-in that the person is not in does not survive the server's list.
    alice.send(Command::Sync { room: "not-a-member".into() });
    alice.sign_in(credentials());
    let signed_in = expect(&events, "signed in", |event| matches!(event, Event::SignedIn { .. }));
    let mut rooms = vec![lab.general.clone(), lab.projects.clone()];
    rooms.sort();
    assert_eq!(signed_in, Event::SignedIn { email: ALICE.into(), rooms });

    // Both rooms are followed: Bob's earlier post counts as unread in one, the other has none (in either order).
    let mut counts = Vec::new();
    while counts.len() < 2 {
        let Event::Unread { room, count } = expect(&events, "unread count", |event| matches!(event, Event::Unread { .. })) else { continue };
        counts.push((room, count));
    }
    counts.sort();
    let mut wanted = vec![(lab.general.clone(), 0), (lab.projects.clone(), 1)];
    wanted.sort();
    assert_eq!(counts, wanted);

    // The session carries on as before.
    alice.send(Command::Post { room: lab.general.clone(), text: "Hello from Alice".into() });
    expect(&events, "acknowledgement", |event| matches!(event, Event::Posted { room, .. } if *room == lab.general));
}

#[test]
fn a_server_that_does_not_list_rooms_still_signs_in() {
    let lab = lab();
    let server = ChatServer::start(&lab, 0);
    let (alice, events) = worker(&lab, &server);
    alice.sign_in(credentials());
    let signed_in = expect(&events, "signed in", |event| matches!(event, Event::SignedIn { .. }));
    assert_eq!(signed_in, Event::SignedIn { email: ALICE.into(), rooms: Vec::new() });
    alice.send(Command::Post { room: lab.projects.clone(), text: "Hello from Alice".into() });
    expect(&events, "acknowledgement", |event| matches!(event, Event::Posted { room, .. } if *room == lab.projects));
}
