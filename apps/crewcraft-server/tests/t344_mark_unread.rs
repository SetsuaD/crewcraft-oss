//! T344: a person's read position is shared by distinct devices, and explicit unread positions survive restart.
//! Synthetic fixture provenance: CrewCraft's own T343 enrolled-device fixture. First devices use network bootstrap
//! and TOTP confirmation. The second device uses the existing AccountStore activation transaction for an existing
//! person, with a separate issuer-signed key and certificate; both devices then use normal TLS and TOTP sign-in.
//! This authentication compatibility evidence includes real Argon2, certificate issuance, enrollment and network
//! setup, so an integration case may exceed one second (testing standard F5).
#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::chat_session::ChatError;
use crewcraft::enroll_client::{EnrollmentRequest, FirstTotpCode};
use crewcraft::lab_client::LabError;
use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::signed_in::{Credentials, SignedInSession};
use crewcraft::worker::{Event, Worker, WorkerConfig};
use crewcraft_bootstrap::Environment;
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_pki::Claims;
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::request::{FEATURE_LIST_ROOMS, FEATURE_READ_STATE};
use crewcraft_server::lab_bootstrap::bootstrap_handler;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use crewcraft_server_core::account_store::Activation;
use crewcraft_server_core::dispatch::{E_NO_SUCH_MESSAGE, E_NO_SUCH_ROOM};
use crewcraft_server_core::import::{Bundle, BundleMessage, BundleRoom, RoomKind};
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::room::Role;
use crewcraft_tls::client_config;
use crewcraft_totp::Totp;
use crewcraft_ui_model::Command;
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use rustls::RootCertStore;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

const WAIT: Duration = Duration::from_secs(10);
const STEP_MS: u64 = 30_000;
const PASSWORD: &str = "synthetic read position password";
const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";

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
        let path = std::env::temp_dir().join(format!("crewcraft-t344-{}-{nonce}", std::process::id()));
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
        protocol: ServerSide { min_version: 1, max_version: 1, features: FEATURE_LIST_ROOMS | FEATURE_READ_STATE, name: "read position test".into() },
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
    fn totp(&self) -> Totp {
        Totp::with_defaults(self.secret.to_vec()).unwrap()
    }

    fn code_at(&self, now_ms: u64) -> String {
        self.totp().generate(now_ms / 1000)
    }

    fn enroll(&self, endpoint: &ServerEndpoint, clock: &AtomicU64) -> Arc<dyn ResolvesClientCert> {
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
        let spki = key.subject_public_key_info();
        let request = EnrollmentRequest { device_name: "Primary Device", csr: csr.der().as_ref(), password: PASSWORD, expected_spki: &spki };
        let chain = endpoint
            .open_bootstrap(&self.invitation, WAIT)
            .unwrap()
            .enroll(request, |_, _| FirstTotpCode::parse(self.code_at(clock_now(clock))))
            .unwrap();
        device_resolver(endpoint.root_der(), vec![chain.leaf, chain.issuer], key)
    }
}

fn device_resolver(root_der: &[u8], chain: Vec<CertificateDer<'static>>, key: KeyPair) -> Arc<dyn ResolvesClientCert> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root_der.to_vec())).unwrap();
    let identity = (chain, PrivatePkcs8KeyDer::from(key.serialize_der()).into());
    client_config(roots, Some(identity)).unwrap().client_auth_cert_resolver.clone()
}

struct Fixture {
    directory: Scratch,
    fingerprint: [u8; 32],
    root_der: Vec<u8>,
    room: String,
    private_room: String,
    own_room: String,
    archive_room: String,
    non_message: u64,
    people: [Person; 2],
    // Alice's primary device, Bob's device, and Alice's distinct secondary device.
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
            let invite =
                Invite { email: person.email.into(), bootstrap_pub: person.invitation.bootstrap_public_key(), expires_ms: setup_time + 600_000 };
            state.accounts.issue_invite(invite, setup_time).unwrap();
        }
        let room = state.rooms.create_room(ALICE, "Project").unwrap();
        let non_message = state.rooms.add_member(&room, ALICE, BOB, Role::Member).unwrap();
        let private_room = state.rooms.create_room(BOB, "Private").unwrap();
        let own_room = state.rooms.create_room(ALICE, "Own messages").unwrap();
        let archive = Bundle {
            source: "fixture".into(),
            rooms: vec![BundleRoom { key: "archive".into(), kind: RoomKind::Group, name: "Archive".into(), members: vec![ALICE.into(), BOB.into()] }],
            messages: vec![BundleMessage {
                room: "archive".into(),
                key: "message".into(),
                author: BOB.into(),
                sent_ms: setup_time,
                text: "archived message".into(),
                reply_to: None,
                edited_ms: None,
                deleted: false,
                files: Vec::new(),
            }],
        };
        let first = start(state, setup_time, people.iter().map(|person| person.secret).collect());
        let mut fixture = Self {
            directory,
            fingerprint,
            root_der,
            room,
            private_room,
            own_room,
            archive_room: String::new(),
            non_message,
            people,
            devices: Vec::new(),
        };
        let endpoint = fixture.endpoint(&first);
        fixture.devices.push(fixture.people[0].enroll(&endpoint, &first.clock));
        fixture.devices.push(fixture.people[1].enroll(&endpoint, &first.clock));
        first.stop();

        // The password bootstrap enrolls a person's first device. Register a real second key with the existing
        // activation transaction, then exercise both independent credentials through the normal network sign-in.
        let LabInstallation { ownership, issuer, mut accounts, mut rooms } = fixture.reopen();
        assert!(rooms.import(&archive, &|email| accounts.person(email).is_some(), false).unwrap().refusals.is_empty());
        fixture.archive_room = rooms.server().rooms_of(ALICE).into_iter().find(|room| room.name == "Archive").unwrap().slug;
        let (root_der, mut authority) = issuer.into_parts();
        let code = EnrollmentCode::from_bytes([3; 20]);
        let registration_time = wall_ms().saturating_add(STEP_MS);
        let bootstrap_pub = code.bootstrap_public_key();
        accounts.issue_invite(Invite { email: ALICE.into(), bootstrap_pub, expires_ms: registration_time + 600_000 }, registration_time).unwrap();
        let (email, device_id) = accounts.preview_activation(&bootstrap_pub, registration_time).unwrap();
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
        let issued = authority.issue_device(csr.der(), &Claims { person: &email, device_id }, wall_ms()).unwrap();
        let totp = fixture.people[0].totp();
        let confirmation = totp.generate(registration_time / 1000);
        let counter = totp.verify(&confirmation, registration_time / 1000, 0, None).unwrap();
        accounts
            .activate(
                Activation {
                    bootstrap_pub,
                    device_name: "Secondary Device",
                    certificate: &issued.certificate,
                    spki_sha256: issued.key_id,
                    counter,
                    first_device: None,
                    expected_device_id: Some(device_id),
                },
                registration_time,
            )
            .unwrap();
        let alice_devices = accounts.devices_of(ALICE);
        assert_eq!(alice_devices.len(), 2);
        assert_ne!(alice_devices[0].id, alice_devices[1].id);
        fixture.devices.push(device_resolver(&root_der, issued.chain.into_iter().map(CertificateDer::from).collect(), key));
        drop((authority, accounts, rooms, ownership));
        let running = start(fixture.reopen(), registration_time, Vec::new());
        (fixture, running)
    }

    fn endpoint(&self, running: &Running) -> ServerEndpoint {
        ServerEndpoint::new(&running.address.to_string(), "localhost", RootFingerprint::from_der(&self.root_der), &self.root_der).unwrap()
    }

    fn sign_in(&self, running: &Running, device: usize) -> SignedInSession {
        running.advance(STEP_MS);
        let person = &self.people[if device == 2 { 0 } else { device }];
        let code = person.code_at(clock_now(&running.clock));
        let credentials = Credentials::new(person.email, PASSWORD, &code).unwrap();
        self.endpoint(running).sign_in(self.devices[device].clone(), &credentials).unwrap()
    }

    fn reopen(&self) -> LabInstallation {
        LabInstallation::open(&self.directory.0.join("server"), self.fingerprint, wall_ms()).unwrap()
    }
}

#[test]
fn a_chosen_unread_position_is_shared_by_distinct_devices_and_survives_restart() {
    let (fixture, running) = Fixture::new();
    let mut alice = fixture.sign_in(&running, 0);
    let mut bob = fixture.sign_in(&running, 1);
    let mut alice_other_device = fixture.sign_in(&running, 2);
    let room = &fixture.room;
    bob.post(room, "earlier message").unwrap();
    alice.post(room, "my earlier reply").unwrap();
    let chosen = bob.post(room, "read this again").unwrap();
    bob.post(room, "another incoming message").unwrap();
    let head = alice.post(room, "my newest reply").unwrap();
    alice.mark_read(room, head).unwrap();
    bob.mark_read(room, head).unwrap();
    alice.sync(room).unwrap();
    bob.sync(room).unwrap();
    let original = alice.read_state(room).unwrap();
    let bob_original = bob.read_state(room).unwrap();
    assert_eq!(original.unread, 0);
    assert_eq!(alice.mark_unread(room, chosen).unwrap(), chosen - 1);
    alice.sync(room).unwrap();
    let marked = alice.read_state(room).unwrap();
    assert_eq!(marked.position, chosen - 1);
    assert_eq!(marked.head, head, "a personal read change adds no room event");
    assert!(marked.revision > original.revision);
    assert_eq!(marked.unread, 2, "incoming messages after the chosen point count, own replies do not");
    alice_other_device.sync(room).unwrap();
    assert_eq!(alice_other_device.read_state(room).unwrap(), marked);
    bob.sync(room).unwrap();
    assert_eq!(bob.read_state(room).unwrap(), bob_original, "another person's cursor is unchanged");
    let primary_ticket = alice.resume_ticket().unwrap();
    let secondary_ticket = alice_other_device.resume_ticket().unwrap();
    let now = clock_now(&running.clock);
    drop((alice, bob, alice_other_device));
    running.stop();
    let running = start(fixture.reopen(), now, Vec::new());
    let endpoint = fixture.endpoint(&running);
    let mut alice = endpoint.resume(fixture.devices[0].clone(), &primary_ticket).unwrap();
    let mut alice_other_device = endpoint.resume(fixture.devices[2].clone(), &secondary_ticket).unwrap();
    alice.sync(room).unwrap();
    alice_other_device.sync(room).unwrap();
    assert_eq!(alice.read_state(room).unwrap(), marked);
    assert_eq!(alice_other_device.read_state(room).unwrap(), marked);
    alice.mark_read(room, head).unwrap();
    alice_other_device.sync(room).unwrap();
    let read = alice_other_device.read_state(room).unwrap();
    assert_eq!(read.position, head);
    assert_eq!(read.unread, 0);
    assert!(read.revision > marked.revision);
    drop((alice, alice_other_device));
    running.stop();
}

#[test]
fn default_unread_chooses_the_newest_other_author_and_only_self_is_a_no_op() {
    let (fixture, running) = Fixture::new();
    let mut alice = fixture.sign_in(&running, 0);
    let mut bob = fixture.sign_in(&running, 1);
    let room = &fixture.room;
    let earlier = bob.post(room, "earlier incoming").unwrap();
    let newest_other = bob.post(room, "newest incoming").unwrap();
    let head = alice.post(room, "newer own reply").unwrap();
    alice.mark_read(room, head).unwrap();
    alice.mark_unread(room, earlier).unwrap();
    assert_eq!(alice.mark_unread(room, 0).unwrap(), newest_other - 1, "the default is an exact chosen position and may move forward");
    alice.sync(room).unwrap();
    assert_eq!(alice.read_state(room).unwrap().unread, 1);
    let own_room = &fixture.own_room;
    alice.sync(own_room).unwrap();
    let empty = alice.read_state(own_room).unwrap();
    alice.mark_unread(own_room, 0).unwrap();
    alice.sync(own_room).unwrap();
    assert_eq!(alice.read_state(own_room).unwrap(), empty);
    let own = alice.post(own_room, "only my own message").unwrap();
    alice.mark_read(own_room, own).unwrap();
    alice.sync(own_room).unwrap();
    let read = alice.read_state(own_room).unwrap();
    alice.mark_unread(own_room, 0).unwrap();
    alice.sync(own_room).unwrap();
    assert_eq!(alice.read_state(own_room).unwrap(), read, "only-self default preserves both position and revision");
    drop((alice, bob));
    running.stop();
}

#[test]
fn unread_targets_must_be_live_and_readable_and_archived_rooms_never_count() {
    let (fixture, running) = Fixture::new();
    let mut alice = fixture.sign_in(&running, 0);
    let mut bob = fixture.sign_in(&running, 1);
    let room = &fixture.room;
    let live = bob.post(room, "a visible message").unwrap();
    let deleted = bob.post(room, "a removed message").unwrap();
    bob.delete(room, deleted).unwrap();
    alice.mark_read(room, bob.sync(room).unwrap().0).unwrap();
    alice.sync(room).unwrap();
    let before = alice.read_state(room).unwrap();
    for target in [fixture.non_message, deleted, u64::MAX] {
        assert_eq!(alice.mark_unread(room, target), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_MESSAGE))));
    }
    for target in [0, live, u64::MAX] {
        assert_eq!(alice.mark_unread(&fixture.private_room, target), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_ROOM))));
    }
    alice.sync(room).unwrap();
    assert_eq!(alice.read_state(room).unwrap(), before, "refused targets cannot change a person's cursor");
    let (_, archive) = alice.sync(&fixture.archive_room).unwrap();
    let target = archive
        .iter()
        .find_map(|entry| match entry {
            crewcraft_client_core::room_view::Shown::Line(line) => Some(line.cursor),
            _ => None,
        })
        .unwrap();
    alice.mark_unread(&fixture.archive_room, target).unwrap();
    alice.sync(&fixture.archive_room).unwrap();
    assert_eq!(alice.read_state(&fixture.archive_room).unwrap().unread, 0);
    let ticket = bob.resume_ticket().unwrap();
    let now = clock_now(&running.clock);
    drop((alice, bob));
    running.stop();
    let mut state = fixture.reopen();
    state.rooms.remove_member(room, ALICE, BOB).unwrap();
    drop(state);
    let running = start(fixture.reopen(), now, Vec::new());
    let mut bob = fixture.endpoint(&running).resume(fixture.devices[1].clone(), &ticket).unwrap();
    assert_eq!(bob.mark_unread(room, live), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_ROOM))));
    assert_eq!(bob.sync(room), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_ROOM))));
    assert!(bob.read_state(room).is_none(), "lost membership yields no personal metadata for that room");
    drop(bob);
    running.stop();
}

fn wait_for_event(events: &Receiver<Event>, phase: &str, want: impl Fn(&Event) -> bool) -> Event {
    let deadline = Instant::now() + WAIT;
    let mut observed = VecDeque::new();
    loop {
        let received = events.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        assert!(received.is_ok(), "worker did not complete {phase}: {received:?}; earlier events: {observed:?}");
        let event = received.unwrap();
        if want(&event) {
            return event;
        }
        assert!(
            !matches!(event, Event::Failed(_) | Event::Disconnected | Event::SessionEnded),
            "worker failed during {phase}: {event:?}; earlier events: {observed:?}"
        );
        observed.push_back(format!("{event:?}"));
        if observed.len() > 16 {
            observed.pop_front();
        }
    }
}

#[test]
fn an_open_worker_observes_another_devices_rewind_until_a_deliberate_read() {
    let (fixture, running) = Fixture::new();
    let mut alice = fixture.sign_in(&running, 0);
    let mut bob = fixture.sign_in(&running, 1);
    let room = &fixture.room;
    let target = bob.post(room, "remember this incoming message").unwrap();
    let head = bob.post(room, "another incoming message").unwrap();
    alice.mark_read(room, head).unwrap();
    let config =
        WorkerConfig { poll_interval: Duration::from_millis(50), first_retry: Duration::from_millis(50), max_retry: Duration::from_millis(200) };
    let (worker, events) = Worker::start(fixture.endpoint(&running), fixture.devices[2].clone(), config, || {}).unwrap();
    running.advance(STEP_MS);
    let code = fixture.people[0].code_at(clock_now(&running.clock));
    assert!(worker.sign_in(Credentials::new(ALICE, PASSWORD, &code).unwrap()));
    wait_for_event(&events, "secondary device connection", |event| matches!(event, Event::Connected));
    wait_for_event(&events, "secondary device sign-in", |event| matches!(event, Event::SignedIn { .. }));
    assert!(worker.send(Command::Sync { room: room.clone() }));
    wait_for_event(&events, "initial open-room snapshot", |event| matches!(event, Event::Room { room: reported, .. } if reported == room));

    alice.mark_unread(room, target).unwrap();
    // No new command is sent to the worker here: its normal background poll must observe the other device's change.
    wait_for_event(
        &events,
        "background unread count after remote rewind",
        |event| matches!(event, Event::Unread { room: reported, count } if reported == room && *count > 0),
    );
    wait_for_event(
        &events,
        "background read state after remote rewind",
        |event| matches!(event, Event::ReadState { room: reported, state } if reported == room && state.position == target - 1 && state.unread > 0),
    );
    // A forced observation cycle supplies a completion barrier. Refreshing an already-open room must preserve the
    // remote unread position, as ordinary background polling does.
    assert!(worker.send(Command::Sync { room: room.clone() }));
    wait_for_event(&events, "passive refresh completion", |event| matches!(event, Event::Room { room: reported, .. } if reported == room));
    alice.sync(room).unwrap();
    let pending = alice.read_state(room).unwrap();
    assert_eq!(pending.position, target - 1);
    assert!(pending.unread > 0);
    assert!(worker.send(Command::Read { room: room.clone() }));
    wait_for_event(
        &events,
        "deliberate read completion",
        |event| matches!(event, Event::ReadState { room: reported, state } if reported == room && state.position == head && state.unread == 0),
    );
    alice.sync(room).unwrap();
    let read = alice.read_state(room).unwrap();
    assert_eq!(read.unread, 0);
    assert!(read.revision > pending.revision);
    drop(worker);
    drop((alice, bob));
    running.stop();
}
