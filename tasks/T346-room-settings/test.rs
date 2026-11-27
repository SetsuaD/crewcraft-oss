//! T346: a person's own room settings (pinned, muted, hidden) are shared by their distinct devices, change nothing
//! for anyone else, survive restart, and leave a hidden room a real membership.
//! Synthetic fixture provenance: CrewCraft's own T344 enrolled-device fixture, itself from T343. First devices use network bootstrap
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
use crewcraft_proto::request::{FEATURE_LIST_ROOMS, FEATURE_ROOM_SETTINGS, FEATURE_SEARCH};
use crewcraft_proto::room_settings::{RoomSetting, RoomSettings};
use crewcraft_server::lab_bootstrap::bootstrap_handler;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use crewcraft_server_core::account_store::Activation;
use crewcraft_server_core::dispatch::E_NO_SUCH_ROOM;
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
const PASSWORD: &str = "synthetic room settings password";
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
        let path = std::env::temp_dir().join(format!("crewcraft-t346-{}-{nonce}", std::process::id()));
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
        protocol: ServerSide {
            min_version: 1,
            max_version: 1,
            features: FEATURE_LIST_ROOMS | FEATURE_SEARCH | FEATURE_ROOM_SETTINGS,
            name: "room settings test".into(),
        },
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
    archive_room: String,
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
        state.rooms.add_member(&room, ALICE, BOB, Role::Member).unwrap();
        let private_room = state.rooms.create_room(BOB, "Private").unwrap();
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
        let mut fixture = Self { directory, fingerprint, root_der, room, private_room, archive_room: String::new(), people, devices: Vec::new() };
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

fn settings_of(session: &mut SignedInSession, room: &str) -> crewcraft_client_core::room_view::RoomSettingsState {
    session.sync(room).unwrap();
    session.room_settings(room).unwrap()
}

#[test]
fn a_persons_room_settings_are_shared_by_their_devices_change_nothing_for_others_and_survive_restart() {
    let (fixture, running) = Fixture::new();
    let mut alice = fixture.sign_in(&running, 0);
    let mut bob = fixture.sign_in(&running, 1);
    let mut alice_other_device = fixture.sign_in(&running, 2);
    let room = &fixture.room;
    let untouched = settings_of(&mut alice, room);
    assert_eq!(untouched.settings, RoomSettings::default());
    let bob_before = settings_of(&mut bob, room);

    let pinned = alice.set_room_setting(room, RoomSetting::Pinned, true).unwrap();
    assert!(pinned > untouched.revision);
    assert_eq!(alice.set_room_setting(room, RoomSetting::Pinned, true).unwrap(), pinned, "a setting already on changes nothing");
    let muted = alice.set_room_setting(room, RoomSetting::Muted, true).unwrap();
    let hidden = alice.set_room_setting(room, RoomSetting::Hidden, true).unwrap();
    assert!(pinned < muted && muted < hidden);
    let all_on = RoomSettings { pinned: true, muted: true, hidden: true };
    let stored = settings_of(&mut alice, room);
    assert_eq!((stored.settings, stored.revision), (all_on, hidden));
    assert_eq!(stored.head, untouched.head, "a personal setting adds no room event");

    // Alice's other device sees the same settings, by Sync and by the list it reads at sign-in.
    let seen = settings_of(&mut alice_other_device, room);
    assert_eq!((seen.settings, seen.revision), (all_on, hidden));
    let listed = alice_other_device.list_room_settings().unwrap().unwrap();
    let row = listed.iter().find(|row| &row.room == room).unwrap();
    assert_eq!((row.settings, row.revision), (all_on, hidden));
    assert!(listed.iter().filter(|row| &row.room != room).all(|row| row.settings == RoomSettings::default()));

    // Bob shares the room, and nothing about it changed for him.
    let bob_after = settings_of(&mut bob, room);
    assert_eq!(bob_after.settings, bob_before.settings);
    assert_eq!(bob_after.revision, bob_before.revision);
    let bob_row = bob.list_room_settings().unwrap().unwrap().into_iter().find(|row| &row.room == room).unwrap();
    assert_eq!(bob_row.settings, RoomSettings::default());

    // Turning one setting off on the second device reaches the first.
    let unpinned = alice_other_device.set_room_setting(room, RoomSetting::Pinned, false).unwrap();
    assert!(unpinned > hidden);
    let after = settings_of(&mut alice, room);
    assert_eq!((after.settings, after.revision), (RoomSettings { pinned: false, ..all_on }, unpinned));

    let primary_ticket = alice.resume_ticket().unwrap();
    let bob_ticket = bob.resume_ticket().unwrap();
    let now = clock_now(&running.clock);
    drop((alice, bob, alice_other_device));
    running.stop();
    let running = start(fixture.reopen(), now, Vec::new());
    let endpoint = fixture.endpoint(&running);
    let mut alice = endpoint.resume(fixture.devices[0].clone(), &primary_ticket).unwrap();
    let mut bob = endpoint.resume(fixture.devices[1].clone(), &bob_ticket).unwrap();
    let reopened = settings_of(&mut alice, room);
    assert_eq!((reopened.settings, reopened.revision), (after.settings, after.revision), "the journal keeps the settings");
    assert_eq!(settings_of(&mut bob, room).settings, RoomSettings::default());
    drop((alice, bob));
    running.stop();
}

#[test]
fn a_hidden_room_stays_a_membership_that_search_finds_and_a_new_message_does_not_unhide_it() {
    let (fixture, running) = Fixture::new();
    let mut alice = fixture.sign_in(&running, 0);
    let mut bob = fixture.sign_in(&running, 1);
    let room = &fixture.room;
    let hidden = alice.set_room_setting(room, RoomSetting::Hidden, true).unwrap();
    let posted = bob.post(room, "the zebra quarterly is ready").unwrap();
    assert!(alice.list_rooms().unwrap().unwrap().contains(room), "a hidden room is still listed as a membership");
    let hits = alice.search("zebra").unwrap().unwrap();
    assert!(hits.iter().any(|hit| &hit.room == room && hit.cursor == posted), "search still finds the hidden room's messages");
    let (_, shown) = alice.sync(room).unwrap();
    assert!(shown.iter().any(|entry| matches!(entry, crewcraft_client_core::room_view::Shown::Line(line) if line.cursor == posted)));
    let state = alice.room_settings(room).unwrap();
    assert!(state.settings.hidden, "a new message does not unhide the room");
    assert_eq!(state.revision, hidden);
    assert!(state.head >= posted);

    // Settings belong to members: a room the person is not in refuses them and reveals nothing.
    for setting in [RoomSetting::Pinned, RoomSetting::Muted, RoomSetting::Hidden] {
        assert_eq!(alice.set_room_setting(&fixture.private_room, setting, true), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_ROOM))));
    }
    assert!(!alice.list_room_settings().unwrap().unwrap().iter().any(|row| row.room == fixture.private_room));
    assert_eq!(settings_of(&mut bob, &fixture.private_room).settings, RoomSettings::default());
    // An archive room never accepts writes, but its member may still pin, mute or hide it for themselves.
    alice.set_room_setting(&fixture.archive_room, RoomSetting::Pinned, true).unwrap();
    assert!(settings_of(&mut alice, &fixture.archive_room).settings.pinned);
    assert!(!settings_of(&mut bob, &fixture.archive_room).settings.pinned);
    drop((alice, bob));
    running.stop();
}

fn wait_for_event(events: &Receiver<Event>, phase: &str, want: impl Fn(&Event) -> bool) -> (Event, Vec<String>) {
    let deadline = Instant::now() + WAIT;
    let mut observed = Vec::new();
    loop {
        let received = events.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        assert!(received.is_ok(), "worker did not complete {phase}: {received:?}; earlier events: {observed:?}");
        let event = received.unwrap();
        if want(&event) {
            return (event, observed);
        }
        assert!(
            !matches!(event, Event::Failed(_) | Event::Disconnected | Event::SessionEnded),
            "worker failed during {phase}: {event:?}; earlier events: {observed:?}"
        );
        observed.push(format!("{event:?}"));
    }
}

#[test]
fn a_worker_reports_settings_before_sign_in_completes_and_follows_another_devices_change() {
    let (fixture, running) = Fixture::new();
    let mut alice = fixture.sign_in(&running, 0);
    let room = &fixture.room;
    alice.set_room_setting(room, RoomSetting::Muted, true).unwrap();
    let config =
        WorkerConfig { poll_interval: Duration::from_millis(50), first_retry: Duration::from_millis(50), max_retry: Duration::from_millis(200) };
    let (worker, events) = Worker::start(fixture.endpoint(&running), fixture.devices[2].clone(), config, || {}).unwrap();
    running.advance(STEP_MS);
    let code = fixture.people[0].code_at(clock_now(&running.clock));
    assert!(worker.sign_in(Credentials::new(ALICE, PASSWORD, &code).unwrap()));
    wait_for_event(&events, "secondary device connection", |event| matches!(event, Event::Connected));
    let (_, before_sign_in) = wait_for_event(&events, "secondary device sign-in", |event| matches!(event, Event::SignedIn { .. }));
    let muted = format!("{:?}", Event::RoomSettings { room: room.clone(), settings: RoomSettings { muted: true, ..RoomSettings::default() } });
    assert!(before_sign_in.contains(&muted), "settings arrive before the room list is shown: {before_sign_in:?}");

    alice.set_room_setting(room, RoomSetting::Pinned, true).unwrap();
    // No command is sent to the worker: its background poll must observe the other device's change.
    wait_for_event(
        &events,
        "background settings after a remote pin",
        |event| matches!(event, Event::RoomSettings { room: reported, settings } if reported == room && settings.pinned && settings.muted),
    );
    assert!(worker.send(Command::SetRoomSetting { room: room.clone(), setting: RoomSetting::Muted, on: false }));
    wait_for_event(
        &events,
        "confirmed unmute",
        |event| matches!(event, Event::RoomSettings { room: reported, settings } if reported == room && settings.pinned && !settings.muted),
    );
    assert!(!settings_of(&mut alice, room).settings.muted);
    drop(worker);
    drop(alice);
    running.stop();
}
