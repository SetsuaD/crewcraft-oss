//! T343: shared room pins and personal saved messages through the enrolled device's normal signed-in session.
//! The restart test also ages the events out of the retained log, so a historical pin and the saved list must come
//! from current durable state instead of depending on seeing the original pin or message event again. A timeline
//! gap stays explicit while its current pin and the saved list remain accessible on the signed-in connection.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::chat_session::{ChatError, ChatSession};
use crewcraft::enroll_client::{EnrollmentRequest, FirstTotpCode};
use crewcraft::lab_client::LabError;
use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::signed_in::{Credentials, SignedInSession};
use crewcraft_bootstrap::Environment;
use crewcraft_client_core::inbox::Inbox;
use crewcraft_client_core::notify::Settings;
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_proto::handshake::{self, Hello, ServerSide};
use crewcraft_proto::push::{Push, decode_push, encode_push};
use crewcraft_proto::request::{FEATURE_LIST_ROOMS, FEATURE_PINS_SAVED, MAX_SAVED_PAGE, Request, Response, encode_request, encode_response};
use crewcraft_proto::signin::{self, SignIn};
use crewcraft_server::lab_bootstrap::bootstrap_handler;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::dispatch::{E_NO_SUCH_MESSAGE, E_NO_SUCH_ROOM, E_NOT_ALLOWED};
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::journal::{Journal, MAX_RECORD};
use crewcraft_server_core::op::{Op, encode_op};
use crewcraft_server_core::room::Role;
use crewcraft_server_core::server::ROOM_LOG_CAPACITY;
use crewcraft_tls::client_config;
use crewcraft_totp::Totp;
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use rustls::RootCertStore;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

const WAIT: Duration = Duration::from_secs(10);
const STEP_MS: u64 = 30_000;
const PASSWORD: &str = "synthetic saved messages password";
const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";
const GUEST: &str = "guest@example.org";

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("crewcraft-t343-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct TestEnvironment {
    clock: Arc<AtomicU64>,
    secrets: VecDeque<[u8; 20]>,
}

impl Environment for TestEnvironment {
    fn now_ms(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn totp_secret(&mut self) -> Option<[u8; 20]> {
        self.secrets.pop_front()
    }
}

struct Running {
    address: SocketAddr,
    clock: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Running {
    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap().unwrap();
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn start(state: LabInstallation, now_ms: u64, secrets: Vec<[u8; 20]>) -> Running {
    let options = LabOptions {
        address: "127.0.0.1:0".parse().unwrap(),
        capacity: NonZeroUsize::new(8).unwrap(),
        timeouts: Timeouts { handshake: WAIT, sign_in: WAIT, signed_in_frame: WAIT, bootstrap: WAIT },
        protocol: ServerSide {
            min_version: 1,
            max_version: 1,
            features: FEATURE_LIST_ROOMS | FEATURE_PINS_SAVED,
            name: "saved messages test".into(),
        },
    };
    let clock = Arc::new(AtomicU64::new(wall_ms()));
    let server_clock = clock.clone();
    let server = LabRuntime::bind(state, options, move || server_clock.load(Ordering::SeqCst)).unwrap();
    let address = server.local_addr().unwrap();
    clock.store(now_ms, Ordering::SeqCst);
    let environment = TestEnvironment { clock: clock.clone(), secrets: VecDeque::from(secrets) };
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let thread = thread::spawn(move || server.serve(&shutdown, |accounts, issuer| Ok(bootstrap_handler(accounts, issuer, environment))));
    Running { address, clock, stop, thread: Some(thread) }
}

struct Person {
    email: &'static str,
    secret: [u8; 20],
    invitation: EnrollmentCode,
}

impl Person {
    fn code_at(&self, now_ms: u64) -> String {
        Totp::with_defaults(self.secret.to_vec()).unwrap().generate(now_ms / 1000)
    }

    fn enroll(&self, endpoint: &ServerEndpoint, now_ms: u64) -> Arc<dyn ResolvesClientCert> {
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
        let spki = key.subject_public_key_info();
        let request = EnrollmentRequest { device_name: "Synthetic Device", csr: csr.der().as_ref(), password: PASSWORD, expected_spki: &spki };
        let chain =
            endpoint.open_bootstrap(&self.invitation, WAIT).unwrap().enroll(request, |_, _| FirstTotpCode::parse(self.code_at(now_ms))).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(endpoint.root_der().to_vec())).unwrap();
        let identity = (vec![chain.leaf, chain.issuer], PrivatePkcs8KeyDer::from(key.serialize_der()).into());
        client_config(roots, Some(identity)).unwrap().client_auth_cert_resolver.clone()
    }
}

struct Fixture {
    directory: Scratch,
    fingerprint: RootFingerprint,
    root_der: Vec<u8>,
    room: String,
    private_room: String,
    people: [Person; 3],
    devices: Vec<Arc<dyn ResolvesClientCert>>,
}

impl Fixture {
    fn new() -> (Self, Running) {
        let directory = Scratch::new();
        let setup_time = wall_ms();
        let mut state = LabInstallation::initialize(&directory.0.join("server"), setup_time).unwrap();
        let fingerprint = state.issuer.root_fingerprint();
        let root_der = state.issuer.root_certificate().to_vec();
        let people = [
            Person { email: ALICE, secret: [17; 20], invitation: EnrollmentCode::from_bytes([1; 20]) },
            Person { email: BOB, secret: [19; 20], invitation: EnrollmentCode::from_bytes([2; 20]) },
            Person { email: GUEST, secret: [23; 20], invitation: EnrollmentCode::from_bytes([3; 20]) },
        ];
        for person in &people {
            let invite =
                Invite { email: person.email.into(), bootstrap_pub: person.invitation.bootstrap_public_key(), expires_ms: setup_time + 600_000 };
            state.accounts.issue_invite(invite, setup_time).unwrap();
        }
        let room = state.rooms.create_room(ALICE, "Project").unwrap();
        state.rooms.add_member(&room, ALICE, BOB, Role::Member).unwrap();
        state.rooms.add_member(&room, ALICE, GUEST, Role::Guest).unwrap();
        let private_room = state.rooms.create_room(GUEST, "Private").unwrap();
        let running = start(state, setup_time, people.iter().map(|person| person.secret).collect());
        let mut fixture = Self { directory, fingerprint, root_der, room, private_room, people, devices: Vec::new() };
        let endpoint = fixture.endpoint(&running);
        fixture.devices = fixture.people.iter().map(|person| person.enroll(&endpoint, setup_time)).collect();
        running.clock.fetch_add(STEP_MS, Ordering::SeqCst);
        (fixture, running)
    }

    fn endpoint(&self, running: &Running) -> ServerEndpoint {
        ServerEndpoint::new(&running.address.to_string(), "localhost", RootFingerprint::from_der(&self.root_der), &self.root_der).unwrap()
    }

    fn sign_in(&self, running: &Running, person: usize) -> SignedInSession {
        let person_info = &self.people[person];
        let code = person_info.code_at(running.clock.load(Ordering::SeqCst));
        let credentials = Credentials::new(person_info.email, PASSWORD, &code).unwrap();
        self.endpoint(running).sign_in(self.devices[person].clone(), &credentials).unwrap()
    }

    fn reopen(&self) -> LabInstallation {
        LabInstallation::open(&self.directory.0.join("server"), self.fingerprint, wall_ms()).unwrap()
    }
}

/// A deterministic already-authenticated transport, following the ChatSession test harness. Reads supply exactly
/// the scripted protocol frames. The matching reply ids ensure each real request has completed before its result.
struct PinScript {
    input: Cursor<Vec<u8>>,
}

impl Read for PinScript {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.input.read(bytes)
    }
}

impl Write for PinScript {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_second_sync_at_the_same_head_consumes_its_own_pin_snapshot() {
    let room = "project";
    let token = "A".repeat(signin::TOKEN_LEN);
    let pinned = |html: &str| Push::Pinned { room: room.into(), cursor: 1, target: 1, author: ALICE.into(), html: html.into(), edited: false };
    // The fake peer deliberately distinguishes same-head snapshots. The test observes each one immediately on
    // returning from sync, without allowing a later request to drain an unread trailing frame and mask the bug.
    let replies = [
        signin::encode_reply(&signin::Reply::Accepted { token: &token }).unwrap(),
        handshake::encode_reply(&handshake::Reply::Welcome { version: 1, features: FEATURE_PINS_SAVED, server: "pin snapshot test".into() }).unwrap(),
        encode_response(1, &Response::Ok { cursor: 1 }).unwrap(),
        encode_push(&Push::Posted { room: room.into(), cursor: 1, author: ALICE.into(), html: "a plan".into(), mentions: Vec::new() }).unwrap(),
        encode_push(&pinned("first snapshot")).unwrap(),
        encode_response(2, &Response::Ok { cursor: 1 }).unwrap(),
        encode_push(&pinned("second snapshot")).unwrap(),
        encode_response(3, &Response::Ok { cursor: 0 }).unwrap(),
    ];
    let bytes = replies.iter().flat_map(|reply| encode(reply).unwrap()).collect();
    let stream = PinScript { input: Cursor::new(bytes) };
    let hello = Hello { min_version: 1, max_version: 1, features: FEATURE_PINS_SAVED, client: "pin snapshot client".into() };
    let credentials = SignIn { email: ALICE, password: PASSWORD, code: "123456" };
    let deadline = Instant::now() + WAIT;
    let mut session = ChatSession::connect(stream, |_, _| {}, &credentials, hello, Settings::new(ALICE), WAIT, deadline).unwrap();

    assert_eq!(session.sync(room, false, 0, 0, deadline), Ok(1));
    let view = session.view(room).unwrap();
    assert_eq!(view.pin_revision(), Some(1), "the first snapshot is already cached");
    assert_eq!(view.pinned_message().unwrap().html, "first snapshot");
    assert_eq!(session.sync(room, false, 0, 0, deadline), Ok(1));
    assert_eq!(session.view(room).unwrap().pinned_message().unwrap().html, "second snapshot");
    assert_eq!(session.ping(0, deadline), Ok(()), "the stream is aligned for the following operation");
}

#[test]
fn pin_metadata_accepts_empty_live_bodies_and_ignores_older_snapshots_after_a_clear() {
    let mut inbox = Inbox::new(ALICE, Settings::new(ALICE));
    inbox.follow("project", false);
    let pinned = |cursor, target| Push::Pinned { room: "project".into(), cursor, target, author: ALICE.into(), html: String::new(), edited: false };
    let push = pinned(10, 3);
    assert_eq!(decode_push(&encode_push(&push).unwrap()).unwrap(), push, "an empty body can belong to a live message");
    inbox.on_push(push, 0, 0).unwrap();
    let view = inbox.view("project").unwrap();
    assert_eq!(view.cursor(), 0, "pin metadata must not skip any unseen timeline events");
    assert_eq!(view.pinned(), Some(3));
    inbox.on_push(pinned(9, 2), 0, 0).unwrap();
    assert_eq!(inbox.view("project").unwrap().pinned(), Some(3));
    inbox
        .on_push(Push::Pinned { room: "project".into(), cursor: 11, target: 0, author: String::new(), html: String::new(), edited: false }, 0, 0)
        .unwrap();
    assert!(inbox.view("project").unwrap().pinned().is_none());
    inbox.on_push(pinned(10, 3), 0, 0).unwrap();
    assert!(inbox.view("project").unwrap().pinned().is_none(), "an older snapshot cannot restore a deleted or unpinned message");
}

#[test]
fn clients_without_the_feature_receive_only_the_pushes_they_already_understand() {
    let directory = Scratch::new();
    let mut server = DurableServer::open(&directory.0.join("rooms")).unwrap();
    let room = server.create_room(ALICE, "Project").unwrap();
    let target = server.post(&room, ALICE, "a shared plan", wall_ms()).unwrap();
    server.pin(&room, ALICE, target, true, wall_ms()).unwrap();
    let request = encode(&encode_request(1, &Request::Sync { room: room.clone(), cursor: 0 }).unwrap()).unwrap();
    let bytes = Connection::new(ALICE).receive_durable(&mut server, &request, wall_ms()).unwrap();
    let mut decoder = Decoder::new();
    decoder.push(&bytes);
    let mut frames = Vec::new();
    while let Some(frame) = decoder.next_frame().unwrap() {
        frames.push(frame);
    }
    let pushes = frames.iter().skip(1).map(|frame| decode_push(frame).unwrap()).collect::<Vec<_>>();
    assert!(pushes.iter().any(|push| matches!(push, Push::Posted { cursor, .. } if *cursor == target)));
    assert!(!pushes.iter().any(|push| matches!(push, Push::Pinned { .. })));
}

#[test]
fn pins_replace_stale_unpins_preserve_the_latest_and_deleting_clears_it() {
    let (fixture, running) = Fixture::new();
    let mut alice = fixture.sign_in(&running, 0);
    let mut bob = fixture.sign_in(&running, 1);
    let mut guest = fixture.sign_in(&running, 2);
    let room = &fixture.room;
    let first = alice.post(room, "first plan").unwrap();
    let second = alice.post(room, "second plan").unwrap();
    alice.pin(room, first, true).unwrap();
    bob.sync(room).unwrap();
    assert_eq!(bob.pinned(room).unwrap().target, first);
    bob.pin(room, second, true).unwrap();
    alice.delete(room, first).unwrap();
    alice.pin(room, first, false).unwrap();
    alice.sync(room).unwrap();
    assert_eq!(alice.pinned(room).unwrap().target, second, "a stale unpin may not clear a replacement");
    let head = bob.sync(room).unwrap().0;
    assert_eq!(bob.pinned(room).unwrap().target, second);
    assert_eq!(bob.sync(room).unwrap().0, head, "metadata also accompanies a sync at the same head");
    assert_eq!(bob.pinned(room).unwrap().target, second);
    assert_eq!(guest.pin(room, second, true), Err(LabError::Chat(ChatError::Rejected(E_NOT_ALLOWED))));
    assert_eq!(bob.pin(&fixture.private_room, second, true), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_ROOM))));
    assert_eq!(alice.pin(room, first, true), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_MESSAGE))));
    alice.delete(room, second).unwrap();
    bob.sync(room).unwrap();
    assert!(bob.pinned(room).is_none(), "deleting the currently pinned message clears its snapshot");
    let bob_ticket = bob.resume_ticket().unwrap();
    let now = running.clock.load(Ordering::SeqCst);
    drop((alice, bob, guest));
    running.stop();
    let reopened = fixture.reopen();
    let running = start(reopened, now, Vec::new());
    let mut bob = fixture.endpoint(&running).resume(fixture.devices[1].clone(), &bob_ticket).unwrap();
    bob.sync(room).unwrap();
    assert!(bob.pinned(room).is_none(), "the deletion remains effective after journal replay");
    drop(bob);
    running.stop();
}

#[test]
fn saved_messages_are_personal_follow_edits_and_deletes_and_require_current_membership() {
    let (fixture, running) = Fixture::new();
    let mut alice = fixture.sign_in(&running, 0);
    let mut bob = fixture.sign_in(&running, 1);
    let mut guest = fixture.sign_in(&running, 2);
    let room = &fixture.room;
    let target = alice.post(room, "original plan").unwrap();
    bob.save_message(room, target, true).unwrap();
    bob.save_message(room, target, true).unwrap();
    assert_eq!(bob.saved_messages().unwrap().len(), 1, "saving twice is idempotent");
    assert!(alice.saved_messages().unwrap().is_empty(), "another person's save is private");
    assert!(guest.saved_messages().unwrap().is_empty());
    guest.save_message(room, target, true).unwrap();
    assert_eq!(guest.saved_messages().unwrap().len(), 1, "a guest may save a message they can read");
    alice.edit(room, target, "revised plan").unwrap();
    let saved = bob.saved_messages().unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!((&saved[0].room, saved[0].cursor, saved[0].author.as_str()), (room, target, ALICE));
    assert!(saved[0].edited);
    assert!(saved[0].html.contains("revised plan"));
    assert!(!saved[0].html.contains("original plan"));
    assert_eq!(bob.save_message(&fixture.private_room, target, true), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_ROOM))));
    let deleted = alice.post(room, "discarded plan").unwrap();
    bob.save_message(room, deleted, true).unwrap();
    alice.delete(room, deleted).unwrap();
    assert_eq!(bob.saved_messages().unwrap().len(), 1, "deleted bodies disappear from saved messages");
    assert_eq!(bob.save_message(room, deleted, true), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_MESSAGE))));
    guest.save_message(room, target, false).unwrap();
    assert!(guest.saved_messages().unwrap().is_empty());
    let bob_ticket = bob.resume_ticket().unwrap();
    let now = running.clock.load(Ordering::SeqCst);
    drop((alice, bob, guest));
    running.stop();
    let mut state = fixture.reopen();
    state.rooms.remove_member(room, ALICE, BOB).unwrap();
    drop(state);
    let running = start(fixture.reopen(), now, Vec::new());
    let mut bob = fixture.endpoint(&running).resume(fixture.devices[1].clone(), &bob_ticket).unwrap();
    assert!(bob.saved_messages().unwrap().is_empty(), "a retained save cannot disclose a room after membership is removed");
    assert_eq!(bob.sync(room), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_ROOM))));
    assert_eq!(bob.pin(room, target, true), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_ROOM))));
    assert_eq!(bob.save_message(room, target, true), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_ROOM))));
    drop(bob);
    running.stop();
    let mut state = fixture.reopen();
    assert!(state.accounts.revoke_session(bob_ticket.token()).unwrap());
    let running = start(state, now, Vec::new());
    assert_eq!(fixture.endpoint(&running).resume(fixture.devices[1].clone(), &bob_ticket).err(), Some(LabError::Chat(ChatError::SignInRefused)));
    running.stop();
}

/// Add semantically valid membership records as bounded fixture history. The production operation codec creates
/// each payload, and the production journal reader checks every length and digest before the installation replays
/// it. One fixture write avoids thousands of filesystem syncs while moving old events beyond ROOM_LOG_CAPACITY.
fn age_out_retained_events(path: &Path, room: &str) -> u64 {
    let (_, before) = Journal::open(path).unwrap();
    let mut bytes = Vec::new();
    let pairs = ROOM_LOG_CAPACITY / 2 + 1;
    for _ in 0..pairs {
        let operations = [
            Op::AddMember { slug: room.into(), actor: ALICE.into(), user: "visitor@example.org".into(), role: Role::Guest },
            Op::RemoveMember { slug: room.into(), actor: ALICE.into(), user: "visitor@example.org".into() },
        ];
        for operation in operations {
            let payload = encode_op(&operation).unwrap();
            assert!(payload.len() <= MAX_RECORD);
            bytes.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
            bytes.extend_from_slice(&payload);
            bytes.extend_from_slice(&Sha256::digest(&payload));
        }
    }
    let mut file = OpenOptions::new().append(true).open(path).unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_data().unwrap();
    drop(file);
    let size = fs::metadata(path).unwrap().len();
    let (_, after) = Journal::open(path).unwrap();
    assert_eq!(after.len(), before.len() + pairs * 2, "every fixture record passes the actual journal reader");
    assert_eq!(fs::metadata(path).unwrap().len(), size, "no recovery truncation occurred");
    (pairs * 2) as u64
}

#[test]
fn pins_and_all_saved_pages_survive_restart_after_the_original_events_age_out() {
    let (fixture, running) = Fixture::new();
    let mut alice = fixture.sign_in(&running, 0);
    let mut bob = fixture.sign_in(&running, 1);
    let room = &fixture.room;
    let target = alice.post(room, "retained plan").unwrap();
    alice.pin(room, target, true).unwrap();
    bob.save_message(room, target, true).unwrap();
    alice.edit(room, target, "current retained plan").unwrap();
    let mut expected = vec![target];
    for index in 0..MAX_SAVED_PAGE + 1 {
        running.clock.fetch_add(1_000, Ordering::SeqCst);
        let cursor = alice.post(room, &format!("saved detail {index}")).unwrap();
        bob.save_message(room, cursor, true).unwrap();
        expected.push(cursor);
    }
    let saved = bob.saved_messages().unwrap();
    assert_eq!(saved.iter().map(|item| item.cursor).collect::<Vec<_>>(), expected, "the client follows every saved page");
    let alice_ticket = alice.resume_ticket().unwrap();
    let bob_ticket = bob.resume_ticket().unwrap();
    let old_head = alice.sync(room).unwrap().0;
    let now = running.clock.load(Ordering::SeqCst);
    drop((alice, bob));
    running.stop();

    let added = age_out_retained_events(&fixture.directory.0.join("server/rooms.journal"), room);
    let state = fixture.reopen();
    assert_eq!(state.rooms.server().room(room).unwrap().head(), old_head + added);
    assert!(added > ROOM_LOG_CAPACITY as u64);
    let running = start(state, now, Vec::new());
    let endpoint = fixture.endpoint(&running);
    let mut alice = endpoint.resume(fixture.devices[0].clone(), &alice_ticket).unwrap();
    let mut bob = endpoint.resume(fixture.devices[1].clone(), &bob_ticket).unwrap();
    let head = old_head + added;
    assert!(matches!(bob.sync(room), Err(LabError::Chat(ChatError::HistoryGap { head: actual, .. })) if actual == head));
    let pinned = bob.pinned(room).unwrap();
    assert_eq!(pinned.target, target);
    assert_eq!(pinned.author, ALICE);
    assert!(pinned.edited);
    assert!(pinned.html.contains("current retained plan"));
    assert!(matches!(bob.sync(room), Err(LabError::Chat(ChatError::HistoryGap { head: actual, .. })) if actual == head));
    assert_eq!(bob.pinned(room).unwrap().target, target);
    let saved = bob.saved_messages().unwrap();
    assert_eq!(saved.iter().map(|item| item.cursor).collect::<Vec<_>>(), expected);
    assert!(saved[0].edited);
    assert!(saved[0].html.contains("current retained plan"));
    assert!(alice.saved_messages().unwrap().is_empty());
    alice.edit(room, target, "revised after the history was evicted").unwrap();
    assert!(bob.saved_messages().unwrap()[0].html.contains("revised after the history was evicted"));
    assert!(matches!(bob.sync(room), Err(LabError::Chat(ChatError::HistoryGap { .. }))));
    assert!(bob.pinned(room).unwrap().html.contains("revised after the history was evicted"));
    alice.delete(room, target).unwrap();
    let saved = bob.saved_messages().unwrap();
    assert_eq!(saved.len(), expected.len() - 1);
    assert!(!saved.iter().any(|item| item.cursor == target));
    assert!(matches!(bob.sync(room), Err(LabError::Chat(ChatError::HistoryGap { .. }))));
    assert!(bob.pinned(room).is_none(), "deleting an evicted historical target clears its pin too");
    let replacement = alice.post(room, "new plan after restart").unwrap();
    alice.pin(room, replacement, true).unwrap();
    assert!(matches!(bob.sync(room), Err(LabError::Chat(ChatError::HistoryGap { .. }))));
    assert_eq!(bob.pinned(room).unwrap().target, replacement);
    alice.delete(room, replacement).unwrap();
    assert!(matches!(bob.sync(room), Err(LabError::Chat(ChatError::HistoryGap { .. }))));
    assert!(bob.pinned(room).is_none());
    drop((alice, bob));
    running.stop();
}
