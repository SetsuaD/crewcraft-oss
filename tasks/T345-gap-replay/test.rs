//! T345: recover a bounded current room after missing event history, with an honest persistent gap notice.
//! Fixtures come from CrewCraft's own T343/T344 integration tests. The network case uses real enrollment, TOTP,
//! certificates, storage and sessions. Its authentication setup may exceed one second (testing standard F5).
#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::chat_session::{ChatError, ChatSession};
use crewcraft::enroll_client::{EnrollmentRequest, FirstTotpCode};
use crewcraft::lab_client::LabError;
use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::signed_in::{Credentials, SignedInSession};
use crewcraft::worker::{Event, Worker, WorkerConfig};
use crewcraft_bootstrap::Environment;
use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::room_view::Shown;
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::current::{CurrentPage, CurrentRecord, MAX_CURRENT_MESSAGES, encode_page};
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_proto::handshake::{self, Hello, ServerSide};
use crewcraft_proto::push::{AttachedFile, Push, encode_push};
use crewcraft_proto::request::{
    FEATURE_ARCHIVE, FEATURE_CALLS, FEATURE_FILES, FEATURE_GAP_REPLAY, FEATURE_LIST_ROOMS, FEATURE_PINS_SAVED, FEATURE_REACTIONS, FEATURE_READ_STATE,
    FEATURE_THREADS, Request, Response, decode_request, encode_response,
};
use crewcraft_proto::signin::{self, SignIn};
use crewcraft_server::lab_bootstrap::bootstrap_handler;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use crewcraft_server_core::dispatch::{E_NO_SUCH_MESSAGE, E_NO_SUCH_ROOM};
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::journal::{Journal, MAX_RECORD};
use crewcraft_server_core::op::{Op, encode_op};
use crewcraft_server_core::room::Role;
use crewcraft_server_core::server::ROOM_LOG_CAPACITY;
use crewcraft_tls::client_config;
use crewcraft_totp::Totp;
use crewcraft_ui_model::Command;
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use rustls::RootCertStore;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

const WAIT: Duration = Duration::from_secs(10);
const STEP_MS: u64 = 30_000;
const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";
const PASSWORD: &str = "synthetic current room password";
const FEATURES: u32 = FEATURE_LIST_ROOMS
    | FEATURE_FILES
    | FEATURE_THREADS
    | FEATURE_REACTIONS
    | FEATURE_ARCHIVE
    | FEATURE_PINS_SAVED
    | FEATURE_READ_STATE
    | FEATURE_GAP_REPLAY;

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn clock_now(clock: &AtomicU64) -> u64 {
    wall_ms().max(clock.load(Ordering::SeqCst))
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("crewcraft-t345-{}-{nonce}", std::process::id()));
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
        clock_now(&self.clock)
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
    fn advance(&self, milliseconds: u64) {
        self.clock.store(clock_now(&self.clock).saturating_add(milliseconds), Ordering::SeqCst);
    }

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
        protocol: ServerSide { min_version: 1, max_version: 1, features: FEATURES, name: "current room test".into() },
    };
    let clock = Arc::new(AtomicU64::new(wall_ms()));
    let server_clock = clock.clone();
    let server = LabRuntime::bind(state, options, move || clock_now(&server_clock)).unwrap();
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

    fn enroll(&self, endpoint: &ServerEndpoint, clock: &AtomicU64) -> Arc<dyn ResolvesClientCert> {
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
        let spki = key.subject_public_key_info();
        let request = EnrollmentRequest { device_name: "Replay Test Device", csr: csr.der().as_ref(), password: PASSWORD, expected_spki: &spki };
        let chain = endpoint
            .open_bootstrap(&self.invitation, WAIT)
            .unwrap()
            .enroll(request, |_, _| FirstTotpCode::parse(self.code_at(clock_now(clock))))
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(endpoint.root_der().to_vec())).unwrap();
        let identity = (vec![chain.leaf, chain.issuer], PrivatePkcs8KeyDer::from(key.serialize_der()).into());
        client_config(roots, Some(identity)).unwrap().client_auth_cert_resolver.clone()
    }
}

struct Fixture {
    directory: Scratch,
    fingerprint: [u8; 32],
    root_der: Vec<u8>,
    room: String,
    people: [Person; 2],
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
        ];
        for person in &people {
            state
                .accounts
                .issue_invite(
                    Invite { email: person.email.into(), bootstrap_pub: person.invitation.bootstrap_public_key(), expires_ms: setup_time + 600_000 },
                    setup_time,
                )
                .unwrap();
        }
        let room = state.rooms.create_room(ALICE, "Project").unwrap();
        state.rooms.add_member(&room, ALICE, BOB, Role::Member).unwrap();
        let running = start(state, setup_time, people.iter().map(|person| person.secret).collect());
        let mut fixture = Self { directory, fingerprint, root_der, room, people, devices: Vec::new() };
        let endpoint = fixture.endpoint(&running);
        fixture.devices = fixture.people.iter().map(|person| person.enroll(&endpoint, &running.clock)).collect();
        running.advance(STEP_MS);
        (fixture, running)
    }

    fn endpoint(&self, running: &Running) -> ServerEndpoint {
        ServerEndpoint::new(&running.address.to_string(), "localhost", RootFingerprint::from_der(&self.root_der), &self.root_der).unwrap()
    }

    fn sign_in(&self, running: &Running, person: usize) -> SignedInSession {
        let person_info = &self.people[person];
        let code = person_info.code_at(clock_now(&running.clock));
        let credentials = Credentials::new(person_info.email, PASSWORD, &code).unwrap();
        self.endpoint(running).sign_in(self.devices[person].clone(), &credentials).unwrap()
    }

    fn reopen(&self) -> LabInstallation {
        LabInstallation::open(&self.directory.0.join("server"), self.fingerprint, wall_ms()).unwrap()
    }
}

/// A bounded fixture sequence using the production operation codec and journal reader, with one filesystem sync.
fn age_out_retained_events(path: &Path, room: &str) -> u64 {
    let (_, before) = Journal::open(path).unwrap();
    let mut bytes = Vec::new();
    let pairs = ROOM_LOG_CAPACITY / 2 + 1;
    for _ in 0..pairs {
        for operation in [
            Op::AddMember { slug: room.into(), actor: ALICE.into(), user: "visitor@example.org".into(), role: Role::Guest },
            Op::RemoveMember { slug: room.into(), actor: ALICE.into(), user: "visitor@example.org".into() },
        ] {
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
    assert_eq!(after.len(), before.len() + pairs * 2);
    assert_eq!(fs::metadata(path).unwrap().len(), size, "no fixture record was rejected or truncated");
    (pairs * 2) as u64
}

#[test]
fn an_enrolled_reconnect_recovers_current_window_and_metadata_then_resumes_incremental_sync() {
    let (fixture, running) = Fixture::new();
    let mut alice = fixture.sign_in(&running, 0);
    let mut bob = fixture.sign_in(&running, 1);
    let room = &fixture.room;
    let outside = alice.post(room, "an early pinned plan").unwrap();
    alice.pin(room, outside, true).unwrap();
    bob.save_message(room, outside, true).unwrap();
    let mut fillers = Vec::new();
    for index in 0..MAX_CURRENT_MESSAGES + 2 {
        running.advance(1_000);
        fillers.push(alice.post(room, &format!("current detail {index}")).unwrap());
    }
    let edited = *fillers.last().unwrap();
    alice.edit(room, edited, "the current revised detail").unwrap();
    let deleted = alice.post(room, "a recent message that must never return").unwrap();
    alice.delete(room, deleted).unwrap();
    alice.edit(room, outside, "the current pinned plan outside the window").unwrap();
    let reply = alice.reply(room, outside, "a reply whose true parent is outside the window").unwrap();
    let path = fixture.directory.0.join("attachment.txt");
    fs::write(&path, b"synthetic attachment bytes").unwrap();
    let upload = alice.upload(room, &path, &mut |_, _| {}).unwrap();
    let with_file = alice.post_files(room, "a current attached file", vec![upload.file]).unwrap();
    bob.react(room, with_file, 1, true).unwrap();
    let old_head = bob.sync(room).unwrap().0;
    assert!(bob.gap_notice(room).is_none(), "inside-tail sync remains ordinary incremental sync");
    bob.mark_read(room, old_head).unwrap();
    bob.mark_unread(room, reply).unwrap();
    bob.sync(room).unwrap();
    let read_before = bob.read_state(room).unwrap();
    let alice_ticket = alice.resume_ticket().unwrap();
    let bob_ticket = bob.resume_ticket().unwrap();
    let now = clock_now(&running.clock);
    drop((alice, bob));
    running.stop();
    let added = age_out_retained_events(&fixture.directory.0.join("server/rooms.journal"), room);
    let running = start(fixture.reopen(), now, Vec::new());
    let endpoint = fixture.endpoint(&running);
    let mut alice = endpoint.resume(fixture.devices[0].clone(), &alice_ticket).unwrap();
    let mut bob = endpoint.resume(fixture.devices[1].clone(), &bob_ticket).unwrap();
    let (head, shown) = bob.sync(room).unwrap();
    assert_eq!(head, old_head + added);
    let lines = shown
        .iter()
        .filter_map(|entry| match entry {
            Shown::Line(line) => Some(line),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), MAX_CURRENT_MESSAGES);
    assert!(!lines.iter().any(|line| line.cursor == outside || line.cursor == deleted));
    assert!(lines.iter().any(|line| line.cursor == edited && line.edited && line.html.contains("current revised detail")));
    assert_eq!(bob.parents(room).get(&reply), Some(&outside), "the real parent relation survives an omitted parent");
    assert_eq!(bob.attachments(room).get(&with_file).unwrap()[0].file, upload.file);
    assert!(
        bob.reactions(room)
            .iter()
            .any(|(at, reactions)| *at == with_file && reactions.iter().any(|(code, people)| *code == 1 && people.iter().any(|who| who == BOB)))
    );
    let notice = bob.gap_notice(room).unwrap();
    assert!(notice.recovered && notice.older);
    assert!(notice.oldest > notice.after + 1);
    let epoch = bob.recovery_epoch(room);
    assert!(epoch > 0);
    let pinned = bob.pinned(room).unwrap();
    assert_eq!(pinned.target, outside);
    assert!(pinned.html.contains("current pinned plan outside the window"));
    let saved = bob.saved_messages().unwrap();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].cursor, outside);
    assert!(saved[0].html.contains("current pinned plan outside the window"));
    let read = bob.read_state(room).unwrap();
    assert_eq!((read.position, read.revision, read.unread), (read_before.position, read_before.revision, read_before.unread));
    let next = alice.post(room, "an incremental message after recovery").unwrap();
    let (next_head, shown) = bob.sync(room).unwrap();
    assert_eq!(next_head, next);
    assert!(shown.iter().any(|entry| matches!(entry, Shown::Line(line) if line.cursor == next && line.html.contains("incremental message"))));
    assert_eq!(bob.recovery_epoch(room), epoch, "ordinary incremental sync starts no new recovery");
    assert!(bob.gap_notice(room).unwrap().recovered, "the history warning survives a successful follow-up sync");

    // A fresh worker must publish the recovered replacement and empty sidecars, so the real window can clear its
    // previous metadata. It uses another authenticated connection on Bob's registered device.
    bob.react(room, with_file, 1, false).unwrap();
    let config =
        WorkerConfig { poll_interval: Duration::from_millis(50), first_retry: Duration::from_millis(50), max_retry: Duration::from_millis(200) };
    let (worker, events) = Worker::start(fixture.endpoint(&running), fixture.devices[1].clone(), config, || {}).unwrap();
    running.advance(STEP_MS);
    let code = fixture.people[1].code_at(clock_now(&running.clock));
    assert!(worker.sign_in(Credentials::new(BOB, PASSWORD, &code).unwrap()));
    let deadline = Instant::now() + WAIT;
    let (mut connected, mut signed_in, mut recovered, mut gap, mut window, mut files, mut empty_reactions) =
        (false, false, false, false, false, false, false);
    let mut observed = Vec::new();
    while !(connected && signed_in && recovered && gap && window && files && empty_reactions) {
        let received = events.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        assert!(received.is_ok(), "worker recovery incomplete: {received:?}; observed {observed:?}");
        let event = received.unwrap();
        observed.push(format!("{event:?}"));
        assert!(!matches!(&event, Event::Failed(_)), "worker recovery failed: {event:?}; observed {observed:?}");
        match event {
            Event::Connected => connected = true,
            Event::SignedIn { .. } => {
                signed_in = true;
                assert!(worker.send(Command::Sync { room: room.clone() }));
            }
            Event::Recovered { room: reported } if reported == *room => recovered = true,
            Event::Gap { room: reported, notice } if reported == *room && notice.recovered && notice.older => gap = true,
            Event::Room { room: reported, shown } if reported == *room => {
                assert_eq!(shown.iter().filter(|entry| matches!(entry, Shown::Line(_))).count(), MAX_CURRENT_MESSAGES);
                window = true;
            }
            Event::Attachments { room: reported, files: current } if reported == *room => {
                assert_eq!(current.len(), 1);
                assert_eq!(current[0].0, with_file);
                assert_eq!(current[0].1[0].file, upload.file);
                files = true;
            }
            Event::Reactions { room: reported, reactions } if reported == *room && reactions.is_empty() => empty_reactions = true,
            _ => {}
        }
    }
    drop(worker);
    // Recovered live messages remain actionable even when their original events have left the retained tail.
    // The original top-level pin is deliberately outside both that tail and the fifty-message window.
    let old_parent_reply = bob.reply(room, outside, "a new reply to the recovered old plan").unwrap();
    let (_, shown) = bob.sync(room).unwrap();
    assert_eq!(bob.parents(room).get(&old_parent_reply), Some(&outside));
    assert!(
        shown.iter().any(|entry| matches!(entry, Shown::Line(line) if line.cursor == old_parent_reply && line.html.contains("recovered old plan")))
    );
    let now = clock_now(&running.clock);
    drop((alice, bob));
    running.stop();
    let mut state = fixture.reopen();
    state.rooms.remove_member(room, ALICE, BOB).unwrap();
    drop(state);
    let running = start(fixture.reopen(), now, Vec::new());
    let mut alice = fixture.endpoint(&running).resume(fixture.devices[0].clone(), &alice_ticket).unwrap();
    let (_, shown) = alice.sync(room).unwrap();
    assert_eq!(alice.parents(room).get(&old_parent_reply), Some(&outside), "old-parent replies replay through the normal durable journal");
    assert!(
        shown.iter().any(|entry| matches!(entry, Shown::Line(line) if line.cursor == old_parent_reply && line.html.contains("recovered old plan")))
    );
    assert!(!alice.reactions(room).iter().any(|(target, _)| *target == with_file), "the old-target reaction removal also survives replay");
    let mut bob = fixture.endpoint(&running).resume(fixture.devices[1].clone(), &bob_ticket).unwrap();
    assert_eq!(bob.react(room, with_file, 1, true), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_ROOM))));
    assert_eq!(bob.reply(room, outside, "must not be accepted"), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_MESSAGE))));
    assert_eq!(bob.sync(room), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_ROOM))));
    assert!(bob.saved_messages().unwrap().is_empty());
    drop((alice, bob));
    running.stop();
}

const SCRIPT_ROOM: &str = "project";
const SCRIPT_HEAD: u64 = 10_004;
const SCRIPT_FEATURES: u32 = FEATURE_FILES | FEATURE_THREADS | FEATURE_REACTIONS | FEATURE_PINS_SAVED | FEATURE_READ_STATE | FEATURE_GAP_REPLAY;

/// The established ChatSession transport seam, with production framing, sign-in and negotiation codecs. This
/// peer supplies deterministic hostile sequences that a legitimate server does not produce. Capturing requests
/// proves recovery asks once and resumes at the captured event head rather than the newest visible message.
struct ReplayScript {
    input: Cursor<Vec<u8>>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Read for ReplayScript {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.input.read(bytes)
    }
}

impl Write for ReplayScript {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.written.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

type ScriptChat = ChatSession<ReplayScript, fn(&mut ReplayScript, Instant)>;

struct ScriptedSession {
    chat: ScriptChat,
    written: Arc<Mutex<Vec<u8>>>,
    deadline: Instant,
}

impl ScriptedSession {
    fn new(replies: Vec<Vec<u8>>) -> Self {
        Self::with_features(replies, SCRIPT_FEATURES)
    }

    fn with_features(replies: Vec<Vec<u8>>, features: u32) -> Self {
        let bytes = replies.iter().flat_map(|reply| encode(reply).unwrap()).collect();
        let written = Arc::new(Mutex::new(Vec::new()));
        let stream = ReplayScript { input: Cursor::new(bytes), written: written.clone() };
        let hello = Hello { min_version: 1, max_version: 1, features, client: "current recovery client".into() };
        let credentials = SignIn { email: ALICE, password: PASSWORD, code: "123456" };
        let deadline = Instant::now() + WAIT;
        let set_deadline: fn(&mut ReplayScript, Instant) = |_, _| {};
        let mut chat = ChatSession::connect(stream, set_deadline, &credentials, hello, Settings::new(ALICE), WAIT, deadline).unwrap();
        assert_eq!(chat.sync(SCRIPT_ROOM, false, 0, 0, deadline), Ok(3));
        let view = chat.view(SCRIPT_ROOM).unwrap();
        assert_eq!(view.cursor(), 3);
        if features & FEATURE_FILES != 0 {
            assert!(view.attachments().contains_key(&1));
        }
        if features & FEATURE_THREADS != 0 {
            assert!(view.parents().contains_key(&2));
        }
        if features & FEATURE_REACTIONS != 0 {
            assert!(view.reactions().contains_key(&1));
        }
        Self { chat, written, deadline }
    }

    fn requests(&self) -> Vec<Request> {
        let mut decoder = Decoder::new();
        decoder.push(&self.written.lock().unwrap());
        let mut frames = Vec::new();
        while let Some(frame) = decoder.next_frame().unwrap() {
            frames.push(frame);
        }
        assert_eq!(decoder.buffered(), 0);
        // The opening sign-in and Hello precede request ids and use different protocol-phase decoders.
        frames.iter().skip(2).map(|frame| decode_request(frame).unwrap().1).collect()
    }
}

fn script_file(current: bool) -> AttachedFile {
    AttachedFile {
        file: [if current { 8 } else { 7 }; 16],
        name: String::from(if current { "current.txt" } else { "old.txt" }),
        size: 4,
        image: None,
    }
}

fn script_metadata(replies: &mut Vec<Vec<u8>>, head: u64, features: u32) {
    if features & FEATURE_CALLS != 0 {
        replies.push(
            encode_push(&Push::CallState {
                room: SCRIPT_ROOM.into(),
                cursor: 0,
                call: 9,
                video: true,
                started_by: BOB.into(),
                started_ms: 42,
                participants: vec![ALICE.into(), BOB.into()],
            })
            .unwrap(),
        );
    }
    if features & FEATURE_PINS_SAVED != 0 {
        replies.push(
            encode_push(&Push::Pinned {
                room: SCRIPT_ROOM.into(),
                cursor: head,
                target: if head == 3 { 1 } else { 10 },
                author: BOB.into(),
                html: if head == 3 { "cached plan" } else { "current recovered body" }.into(),
                edited: head != 3,
            })
            .unwrap(),
        );
    }
    if features & FEATURE_READ_STATE != 0 {
        replies.push(
            encode_push(&Push::ReadState { room: SCRIPT_ROOM.into(), cursor: head, position: 3, revision: 1, unread: u64::from(head != 3) }).unwrap(),
        );
    }
}

fn script_gap(replies: &mut Vec<Vec<u8>>, head: u64, after: u64, oldest: u64) {
    replies.push(encode_push(&Push::Gap { room: SCRIPT_ROOM.into(), cursor: head, after, oldest }).unwrap());
}

fn script_prefix() -> Vec<Vec<u8>> {
    script_prefix_with_features(SCRIPT_FEATURES)
}

fn script_prefix_with_features(features: u32) -> Vec<Vec<u8>> {
    let token = "A".repeat(signin::TOKEN_LEN);
    let mut replies = vec![
        signin::encode_reply(&signin::Reply::Accepted { token: &token }).unwrap(),
        handshake::encode_reply(&handshake::Reply::Welcome { version: 1, features, server: "current recovery peer".into() }).unwrap(),
        encode_response(1, &Response::Ok { cursor: 3 }).unwrap(),
        encode_push(&Push::Posted { room: SCRIPT_ROOM.into(), cursor: 1, author: BOB.into(), html: "cached plan".into(), mentions: Vec::new() })
            .unwrap(),
    ];
    if features & FEATURE_FILES != 0 {
        replies.push(encode_push(&Push::Attached { room: SCRIPT_ROOM.into(), cursor: 1, files: vec![script_file(false)] }).unwrap());
    }
    replies.push(
        encode_push(&Push::Posted {
            room: SCRIPT_ROOM.into(),
            cursor: 2,
            author: BOB.into(),
            html: "cached deleted message".into(),
            mentions: Vec::new(),
        })
        .unwrap(),
    );
    if features & FEATURE_THREADS != 0 {
        replies.push(encode_push(&Push::Threaded { room: SCRIPT_ROOM.into(), cursor: 2, parent: 1 }).unwrap());
    }
    let last = if features & FEATURE_REACTIONS != 0 {
        Push::Reacted { room: SCRIPT_ROOM.into(), cursor: 3, target: 1, author: ALICE.into(), reaction: 1, on: true }
    } else {
        Push::Other { room: SCRIPT_ROOM.into(), cursor: 3 }
    };
    replies.push(encode_push(&last).unwrap());
    script_metadata(&mut replies, 3, features);
    replies.push(encode_response(2, &Response::Ok { cursor: SCRIPT_HEAD }).unwrap());
    script_metadata(&mut replies, SCRIPT_HEAD, features);
    script_gap(&mut replies, SCRIPT_HEAD, 3, 5);
    replies.push(encode_response(3, &Response::Ok { cursor: SCRIPT_HEAD }).unwrap());
    replies
}

fn script_message(cursor: u64) -> CurrentRecord {
    CurrentRecord::Message { cursor, author: BOB.into(), html: "current recovered body".into(), edited: true, parent: None, sent_ms: None }
}

fn script_page(index: u32, last: bool, records: Vec<CurrentRecord>) -> CurrentPage {
    CurrentPage { room: SCRIPT_ROOM.into(), head: SCRIPT_HEAD, index, last, older: false, archived: false, records }
}

fn script_complete_capture(replies: &mut Vec<Vec<u8>>) {
    replies.push(encode_page(3, &script_page(0, false, vec![script_message(10)])).unwrap());
    replies.push(encode_page(3, &script_page(1, true, vec![CurrentRecord::File { cursor: 10, index: 0, file: script_file(true) }])).unwrap());
}

#[test]
fn a_complete_multipage_capture_replaces_cached_state_and_syncs_from_the_captured_head() {
    for features in [SCRIPT_FEATURES, FEATURE_GAP_REPLAY | FEATURE_CALLS, FEATURE_GAP_REPLAY | FEATURE_FILES] {
        let tail_files = features == (FEATURE_GAP_REPLAY | FEATURE_FILES);
        let needs_barrier = features & (FEATURE_PINS_SAVED | FEATURE_READ_STATE) == 0;
        let final_head = SCRIPT_HEAD + u64::from(tail_files);
        let tail_file = AttachedFile { file: [9; 16], name: "after-capture.txt".into(), size: 5, image: None };
        let mut replies = script_prefix_with_features(features);
        script_complete_capture(&mut replies);
        // A matched Ping after the terminal page establishes the capture boundary before installation.
        replies.push(encode_response(4, &Response::Ok { cursor: 0 }).unwrap());
        replies.push(encode_response(5, &Response::Ok { cursor: final_head }).unwrap());
        if tail_files {
            replies.push(
                encode_push(&Push::Posted {
                    room: SCRIPT_ROOM.into(),
                    cursor: final_head,
                    author: BOB.into(),
                    html: "a post-capture attached message".into(),
                    mentions: Vec::new(),
                })
                .unwrap(),
            );
            replies.push(encode_push(&Push::Attached { room: SCRIPT_ROOM.into(), cursor: final_head, files: vec![tail_file.clone()] }).unwrap());
        }
        script_metadata(&mut replies, final_head, features);
        // Without pin/read metadata the recovery operation needs Ping6 to drain either the equal-head CallState
        // or an attachment after Posted reached the newer head. Pin/read completes without that extra request.
        replies.push(encode_response(6, &Response::Ok { cursor: 0 }).unwrap());
        if needs_barrier {
            replies.push(encode_response(7, &Response::Ok { cursor: 0 }).unwrap());
        }
        let mut session = ScriptedSession::with_features(replies, features);
        assert_eq!(session.chat.sync(SCRIPT_ROOM, false, 0, 0, session.deadline), Ok(final_head));
        let requests = session.requests();
        assert_eq!(requests.len(), if needs_barrier { 6 } else { 5 });
        assert_eq!(requests.iter().filter(|request| matches!(request, Request::Current { .. })).count(), 1);
        assert!(matches!(&requests[3], Request::Ping));
        assert!(matches!(&requests[4], Request::Sync { room, cursor } if room == SCRIPT_ROOM && *cursor == SCRIPT_HEAD));
        if needs_barrier {
            assert!(matches!(&requests[5], Request::Ping));
        }
        let view = session.chat.view(SCRIPT_ROOM).unwrap();
        assert_eq!(view.cursor(), final_head, "the captured event head includes any subsequent timeline events");
        let shown = view.shown();
        assert_eq!(shown.len(), if tail_files { 2 } else { 1 });
        assert!(matches!(&shown[0], Shown::Line(line) if line.cursor == 10 && line.edited && line.html == "current recovered body"));
        assert_eq!(view.attachments().len(), if tail_files { 2 } else { 1 });
        assert_eq!(view.attachments().get(&10), Some(&vec![script_file(true)]));
        if tail_files {
            assert_eq!(
                view.attachments().get(&final_head),
                Some(&vec![tail_file]),
                "the post-capture attachment is present immediately when sync returns"
            );
        }
        assert!(view.parents().is_empty() && view.reactions().is_empty());
        assert_eq!(view.recovery_epoch(), 1);
        assert!(view.gap_notice().is_some_and(|notice| notice.recovered && !notice.older && notice.after == 3));
        if features & FEATURE_PINS_SAVED != 0 {
            assert_eq!(view.pinned_message().unwrap().html, "current recovered body");
        }
        if features & FEATURE_READ_STATE != 0 {
            assert_eq!(view.read_state().unwrap().head, SCRIPT_HEAD);
        }
        if features & FEATURE_CALLS != 0 {
            let call = view.call().unwrap();
            assert_eq!(call.call, 9, "the cleared open-call cache was restored before sync returned");
            assert!(call.video);
            assert_eq!(call.participants, vec![ALICE.to_owned(), BOB.to_owned()]);
        }
        assert_eq!(session.chat.ping(0, session.deadline), Ok(()), "the stream is aligned for the next operation");
    }
}

#[test]
fn interrupted_or_inconsistent_current_pages_preserve_the_cached_view_and_explicit_gap() {
    let valid_next = script_page(1, true, vec![script_message(11)]);
    let mut wrong_room = valid_next.clone();
    wrong_room.room = "another-room".into();
    let mut wrong_head = valid_next.clone();
    wrong_head.head += 1;
    let mut skipped_index = valid_next.clone();
    skipped_index.index = 2;
    let mut repeated_index = valid_next.clone();
    repeated_index.index = 0;
    let mut changed_flags = valid_next.clone();
    changed_flags.older = true;
    let cases = [
        ("interrupted after the first page", false, None),
        ("wrong room", false, Some(encode_page(3, &wrong_room).unwrap())),
        ("wrong head", false, Some(encode_page(3, &wrong_head).unwrap())),
        ("skipped index", false, Some(encode_page(3, &skipped_index).unwrap())),
        ("repeated index", false, Some(encode_page(3, &repeated_index).unwrap())),
        ("changed flags", false, Some(encode_page(3, &changed_flags).unwrap())),
        ("descending message cursor", false, Some(encode_page(3, &script_page(1, true, vec![script_message(9)])).unwrap())),
        ("duplicate message cursor", false, Some(encode_page(3, &script_page(1, true, vec![script_message(10)])).unwrap())),
        ("wrong request id", false, Some(encode_page(99, &valid_next).unwrap())),
        ("duplicate page after last", true, Some(encode_page(3, &script_page(0, true, vec![script_message(10)])).unwrap())),
    ];
    for (label, ends_capture, continuation) in cases {
        let mut replies = script_prefix();
        replies.push(encode_page(3, &script_page(0, ends_capture, vec![script_message(10)])).unwrap());
        replies.extend(continuation);
        if ends_capture {
            // If the generic response reader silently drops the extra page, this valid Ping answer would let
            // the staged replacement commit. It must instead be refused before any visible installation.
            replies.push(encode_response(4, &Response::Ok { cursor: 0 }).unwrap());
        }
        let mut session = ScriptedSession::new(replies);
        let before = session.chat.view(SCRIPT_ROOM).unwrap();
        let shown = before.shown();
        let files = before.attachments().clone();
        let parents = before.parents().clone();
        let reactions = before.reactions().clone();
        assert!(session.chat.sync(SCRIPT_ROOM, false, 0, 0, session.deadline).is_err(), "{label}");
        let after = session.chat.view(SCRIPT_ROOM).unwrap();
        assert_eq!(after.cursor(), 3, "{label}");
        assert_eq!(after.shown(), shown, "{label}");
        assert_eq!(after.attachments(), &files, "{label}");
        assert_eq!(after.parents(), &parents, "{label}");
        assert_eq!(after.reactions(), &reactions, "{label}");
        assert_eq!(after.recovery_epoch(), 0, "{label}");
        assert!(after.gap_notice().is_some_and(|notice| !notice.recovered && notice.after == 3 && notice.head == SCRIPT_HEAD), "{label}");
        let requests = session.requests();
        assert_eq!(requests.iter().filter(|request| matches!(request, Request::Current { .. })).count(), 1, "{label}");
        assert_eq!(
            requests.iter().filter(|request| matches!(request, Request::Sync { .. })).count(),
            2,
            "no fresh sync follows a refused capture: {label}"
        );
        assert_eq!(requests.len(), if ends_capture { 4 } else { 3 }, "{label}");
    }
}

#[test]
fn a_second_gap_after_install_keeps_the_completed_capture_and_does_not_recurse() {
    let mut replies = script_prefix();
    script_complete_capture(&mut replies);
    replies.push(encode_response(4, &Response::Ok { cursor: 0 }).unwrap());
    let later_head = SCRIPT_HEAD + 10_001;
    replies.push(encode_response(5, &Response::Ok { cursor: later_head }).unwrap());
    script_metadata(&mut replies, later_head, SCRIPT_FEATURES);
    script_gap(&mut replies, later_head, SCRIPT_HEAD, SCRIPT_HEAD + 2);
    let mut session = ScriptedSession::new(replies);
    assert_eq!(session.chat.sync(SCRIPT_ROOM, false, 0, 0, session.deadline), Err(ChatError::HistoryGap { reached: SCRIPT_HEAD, head: later_head }));
    let view = session.chat.view(SCRIPT_ROOM).unwrap();
    assert_eq!(view.cursor(), SCRIPT_HEAD);
    assert!(view.shown().iter().any(|entry| matches!(entry, Shown::Line(line) if line.cursor == 10 && line.html == "current recovered body")));
    assert_eq!(view.recovery_epoch(), 1, "a completed replacement remains usable when its final sync fails");
    assert!(view.gap_notice().is_some_and(|notice| notice.recovered && notice.head == later_head));
    let requests = session.requests();
    assert_eq!(
        requests.iter().filter(|request| matches!(request, Request::Current { .. })).count(),
        1,
        "a single sync cannot start unbounded recovery attempts"
    );
    assert!(matches!(&requests[3], Request::Ping));
    assert_eq!(requests.len(), 5);
}
