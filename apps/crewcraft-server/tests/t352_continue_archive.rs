//! T352: an archived conversation continues as an active one. Real parts: the network server with its journal, people
//! enrolled through the bootstrap with TOTP confirmation, and the app's signed-in sessions. Synthetic fixture
//! provenance: CrewCraft's own T344 enrolled-device fixture, with bundles written here. Real Argon2, certificate
//! issuance, enrollment and network setup make each case take more than a second (testing standard F5).
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft::chat_session::ChatError;
use crewcraft::enroll_client::{EnrollmentRequest, FirstTotpCode};
use crewcraft::lab_client::LabError;
use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::signed_in::{Credentials, ResumeTicket, SignedInSession};
use crewcraft_bootstrap::Environment;
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::request::{FEATURE_ARCHIVE, FEATURE_CONTINUE, FEATURE_LIST_ROOMS};
use crewcraft_server::lab_bootstrap::bootstrap_handler;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use crewcraft_server_core::dispatch::{E_NO_SUCH_ROOM, E_NOT_ALLOWED};
use crewcraft_server_core::import::{Bundle, BundleMessage, BundleRoom, RoomKind};
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::room::Role;
use crewcraft_tls::client_config;
use crewcraft_totp::Totp;
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use rustls::RootCertStore;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

const WAIT: Duration = Duration::from_secs(10);
const STEP_MS: u64 = 30_000;
const PASSWORD: &str = "synthetic continuation password";
const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";
const CY: &str = "cy@example.org";
/// Never invited: no account, now or later.
const DEE: &str = "dee@example.org";

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
        let path = std::env::temp_dir().join(format!("crewcraft-t352-{}-{nonce}", std::process::id()));
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
    let features = FEATURE_LIST_ROOMS | FEATURE_ARCHIVE | FEATURE_CONTINUE;
    let options = LabOptions {
        address: "127.0.0.1:0".parse().unwrap(),
        capacity: NonZeroUsize::new(8).unwrap(),
        timeouts: Timeouts { handshake: WAIT, sign_in: WAIT, signed_in_frame: WAIT, bootstrap: WAIT },
        protocol: ServerSide { min_version: 1, max_version: 1, features, name: "continuation test".into() },
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
        let request = EnrollmentRequest { device_name: "Device", csr: csr.der().as_ref(), password: PASSWORD, expected_spki: &spki };
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

/// A message by `author` in bundle room `room`.
fn message(room: &str, key: &str, author: &str, text: &str) -> BundleMessage {
    BundleMessage {
        room: room.into(),
        key: key.into(),
        author: author.into(),
        sent_ms: 1_709_647_629_123,
        text: text.into(),
        reply_to: None,
        edited_ms: None,
        deleted: false,
        files: Vec::new(),
    }
}

fn bundle(source: &str, key: &str, kind: RoomKind, name: &str, members: &[&str], author: &str) -> Bundle {
    Bundle {
        source: source.into(),
        rooms: vec![BundleRoom { key: key.into(), kind, name: name.into(), members: members.iter().map(|m| (*m).to_owned()).collect() }],
        messages: vec![message(key, "m1", author, "from the old system")],
    }
}

/// Three enrolled people (Alice, Bob, Cy) and their archives: two one-to-one conversations between Alice and Bob from
/// two sources; a group conversation with Alice, Bob and Dee (who has no account), written by Dee; a one-to-one
/// conversation between Alice and Dee; and an ordinary room Alice and Bob are in.
struct Fixture {
    directory: Scratch,
    fingerprint: [u8; 32],
    root_der: Vec<u8>,
    people: [Person; 3],
    devices: Vec<Arc<dyn ResolvesClientCert>>,
    direct: String,
    direct_again: String,
    group: String,
    half_linked: String,
    project: String,
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
            Person { email: CY, secret: [23; 20], invitation: EnrollmentCode::from_bytes([3; 20]) },
        ];
        for person in &people {
            let invite =
                Invite { email: person.email.into(), bootstrap_pub: person.invitation.bootstrap_public_key(), expires_ms: setup_time + 600_000 };
            state.accounts.issue_invite(invite, setup_time).unwrap();
        }
        let first = start(state, setup_time, people.iter().map(|person| person.secret).collect());
        let mut fixture = Self {
            directory,
            fingerprint,
            root_der,
            people,
            devices: Vec::new(),
            direct: String::new(),
            direct_again: String::new(),
            group: String::new(),
            half_linked: String::new(),
            project: String::new(),
        };
        let endpoint = fixture.endpoint(&first);
        for index in 0..3 {
            let device = fixture.people[index].enroll(&endpoint, &first.clock);
            fixture.devices.push(device);
        }
        first.stop();

        // The import links only people who have accounts now (deferred author linking).
        let LabInstallation { ownership, issuer, accounts, mut rooms } = fixture.reopen();
        let has_account = |email: &str| accounts.person(email).is_some();
        let bundles = [
            bundle("teams", "chat-1", RoomKind::Direct, "", &[ALICE, BOB], BOB),
            bundle("other", "dm-9", RoomKind::Direct, "", &[ALICE, BOB], ALICE),
            bundle("teams", "team-1", RoomKind::Group, "Old team", &[ALICE, BOB, DEE], DEE),
            bundle("teams", "chat-2", RoomKind::Direct, "", &[ALICE, DEE], DEE),
        ];
        let reports: Vec<_> = bundles.iter().map(|bundle| rooms.import(bundle, &has_account, false).unwrap()).collect();
        assert!(reports.iter().all(|report| report.ok()), "{reports:?}");
        assert!(reports[2].people_skipped.values().any(|skipped| skipped.contains(DEE)));
        fixture.direct = rooms.archive_room("teams", "chat-1").unwrap().to_owned();
        fixture.direct_again = rooms.archive_room("other", "dm-9").unwrap().to_owned();
        fixture.group = rooms.archive_room("teams", "team-1").unwrap().to_owned();
        fixture.half_linked = rooms.archive_room("teams", "chat-2").unwrap().to_owned();
        fixture.project = rooms.create_room(ALICE, "Project").unwrap();
        rooms.add_member(&fixture.project, ALICE, BOB, Role::Member).unwrap();
        drop((ownership, issuer, accounts, rooms));
        let running = start(fixture.reopen(), wall_ms().saturating_add(STEP_MS), Vec::new());
        (fixture, running)
    }

    fn endpoint(&self, running: &Running) -> ServerEndpoint {
        ServerEndpoint::new(&running.address.to_string(), "localhost", RootFingerprint::from_der(&self.root_der), &self.root_der).unwrap()
    }

    fn sign_in(&self, running: &Running, person: usize) -> SignedInSession {
        running.advance(STEP_MS);
        let code = self.people[person].code_at(clock_now(&running.clock));
        let credentials = Credentials::new(self.people[person].email, PASSWORD, &code).unwrap();
        self.endpoint(running).sign_in(self.devices[person].clone(), &credentials).unwrap()
    }

    fn resume(&self, running: &Running, person: usize, ticket: &ResumeTicket) -> SignedInSession {
        self.endpoint(running).resume(self.devices[person].clone(), ticket).unwrap()
    }

    fn reopen(&self) -> LabInstallation {
        LabInstallation::open(&self.directory.0.join("server"), self.fingerprint, wall_ms()).unwrap()
    }

    /// The members of `room` on the stopped server.
    fn members(&self, room: &str) -> BTreeSet<String> {
        let state = self.reopen();
        state.rooms.server().room(room).unwrap().members().into_iter().map(|(member, _)| member).collect()
    }
}

fn people(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

/// The archives `room`'s lines link back to.
fn linked_archives(session: &mut SignedInSession, room: &str) -> BTreeSet<String> {
    session.sync(room).unwrap();
    session.continued_lines(room).into_iter().map(|(_, archive, _)| archive).collect()
}

#[test]
fn an_archived_one_to_one_conversation_continues_in_the_pairs_only_direct_message() {
    let (fixture, running) = Fixture::new();
    let mut alice = fixture.sign_in(&running, 0);
    let mut bob = fixture.sign_in(&running, 1);
    assert!(alice.continues());
    let rooms_before = bob.list_rooms().unwrap().unwrap();

    let direct = alice.continue_archive(&fixture.direct).unwrap();
    assert_ne!(direct, fixture.direct, "an archive stays read-only; the conversation continues elsewhere");
    assert_eq!(bob.continue_archive(&fixture.direct).unwrap(), direct, "either person reaches the same direct message");
    assert_eq!(
        alice.continue_archive(&fixture.direct_again).unwrap(),
        direct,
        "another archived conversation between the same two people never makes a second direct message"
    );
    let rooms_after = bob.list_rooms().unwrap().unwrap();
    assert_eq!(rooms_after.len(), rooms_before.len() + 1, "exactly one new room for Bob");
    assert!(rooms_after.contains(&direct));

    // It is an active conversation, and it links back to both archives.
    alice.post(&direct, "picking this up again").unwrap();
    let (_, shown) = bob.sync(&direct).unwrap();
    assert!(shown.iter().any(|row| matches!(row, crewcraft_client_core::room_view::Shown::Line(line) if line.html.contains("picking this up"))));
    assert_eq!(linked_archives(&mut bob, &direct), people(&[fixture.direct.as_str(), fixture.direct_again.as_str()]));

    let ticket = alice.resume_ticket().unwrap();
    let now = clock_now(&running.clock);
    drop((alice, bob));
    running.stop();
    assert_eq!(fixture.members(&direct), people(&[ALICE, BOB]));

    // After a restart, continuing again still answers the same room, and adds no second line.
    let running = start(fixture.reopen(), now, Vec::new());
    let mut alice = fixture.resume(&running, 0, &ticket);
    assert_eq!(alice.continue_archive(&fixture.direct).unwrap(), direct);
    alice.sync(&direct).unwrap();
    assert_eq!(alice.continued_lines(&direct).len(), 2);
    drop(alice);
    running.stop();
}

#[test]
fn any_other_archive_continues_in_one_new_room_with_exactly_its_linked_people() {
    let (fixture, running) = Fixture::new();
    let mut alice = fixture.sign_in(&running, 0);
    let mut bob = fixture.sign_in(&running, 1);

    let group = alice.continue_archive(&fixture.group).unwrap();
    assert_ne!(group, fixture.group);
    assert_eq!(bob.continue_archive(&fixture.group).unwrap(), group, "continuing twice answers the same room");
    assert_eq!(alice.continue_archive(&fixture.group).unwrap(), group);
    assert_eq!(linked_archives(&mut bob, &group), people(&[fixture.group.as_str()]), "one line, pointing at the archive");
    let lines = bob.continued_lines(&group);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].2.contains("Old team"), "the server's line names the archive: {:?}", lines[0].2);

    // A one-to-one conversation with someone who has no account is not a direct message either.
    let half = alice.continue_archive(&fixture.half_linked).unwrap();
    assert_ne!(half, fixture.half_linked);
    assert_ne!(half, group);

    let ticket = bob.resume_ticket().unwrap();
    let now = clock_now(&running.clock);
    drop((alice, bob));
    running.stop();
    assert_eq!(fixture.members(&group), people(&[ALICE, BOB]), "Dee, who wrote there but has no account, is never added");
    assert_eq!(fixture.members(&half), people(&[ALICE]));

    // A later, larger export links Cy to the archive; Cy may then continue it, into the same room.
    let LabInstallation { ownership, issuer, accounts, mut rooms } = fixture.reopen();
    let later = bundle("teams", "team-1", RoomKind::Group, "Old team", &[ALICE, BOB, CY, DEE], DEE);
    let has_account = |email: &str| accounts.person(email).is_some();
    assert!(rooms.import(&later, &has_account, false).unwrap().ok());
    drop((ownership, issuer, accounts, rooms));
    let running = start(fixture.reopen(), now, Vec::new());
    let mut cy = fixture.sign_in(&running, 2);
    assert_eq!(cy.continue_archive(&fixture.group).unwrap(), group);
    let mut bob = fixture.resume(&running, 1, &ticket);
    assert_eq!(bob.continue_archive(&fixture.group).unwrap(), group);
    drop((cy, bob));
    running.stop();
    assert_eq!(fixture.members(&group), people(&[ALICE, BOB, CY]));
}

#[test]
fn only_someone_who_can_read_an_archive_may_continue_it() {
    let (fixture, running) = Fixture::new();
    let mut cy = fixture.sign_in(&running, 2);
    let mut alice = fixture.sign_in(&running, 0);
    for archive in [&fixture.direct, &fixture.group] {
        assert_eq!(cy.continue_archive(archive), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_ROOM))), "Cy is not in {archive}");
    }
    assert_eq!(cy.continue_archive("no-such-room"), Err(LabError::Chat(ChatError::Rejected(E_NO_SUCH_ROOM))));
    assert_eq!(alice.continue_archive(&fixture.project), Err(LabError::Chat(ChatError::Rejected(E_NOT_ALLOWED))), "only an archive continues");
    let rooms = cy.list_rooms().unwrap().unwrap();
    assert!(rooms.is_empty(), "a refused continuation makes nothing: {rooms:?}");
    drop((cy, alice));
    running.stop();
    let state = fixture.reopen();
    assert!(state.rooms.continued_in(&fixture.direct).is_none() && state.rooms.continued_in(&fixture.group).is_none());
}
