//! T370b2: meeting lines reach the app. A meeting's system lines show among a room's history lines, and an open
//! calendar reads its week again when another person's change arrives as a line, with no command from the window.
//! Real parts: the network server with its journal, people enrolled through the bootstrap with TOTP confirmation, the
//! app's signed-in session and its connection worker. Synthetic fixture provenance: CrewCraft's own T344 enrolled-device
//! fixture. Real Argon2, certificate issuance and enrollment make the case take more than a second (testing standard F5).
#![allow(clippy::unwrap_used, clippy::panic)]

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

use crewcraft::enroll_client::{EnrollmentRequest, FirstTotpCode};
use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::signed_in::{Credentials, MeetingSave, SignedInSession};
use crewcraft::worker::{Event, Worker, WorkerConfig};
use crewcraft_bootstrap::Environment;
use crewcraft_client_core::calendar::work_week_at;
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::request::{FEATURE_LIST_ROOMS, FEATURE_MEETINGS};
use crewcraft_server::lab_bootstrap::bootstrap_handler;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
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
const PASSWORD: &str = "synthetic meeting line password";
const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn clock_now(clock: &AtomicU64) -> u64 {
    wall_ms().max(clock.load(Ordering::SeqCst))
}

struct Scratch(PathBuf);

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
    let features = FEATURE_LIST_ROOMS | FEATURE_MEETINGS;
    let options = LabOptions {
        address: "127.0.0.1:0".parse().unwrap(),
        capacity: NonZeroUsize::new(8).unwrap(),
        timeouts: Timeouts { handshake: WAIT, sign_in: WAIT, signed_in_frame: WAIT, bootstrap: WAIT },
        protocol: ServerSide { min_version: 1, max_version: 1, features, name: "meeting line test".into() },
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

fn endpoint(running: &Running, root_der: &[u8]) -> ServerEndpoint {
    ServerEndpoint::new(&running.address.to_string(), "localhost", RootFingerprint::from_der(root_der), root_der).unwrap()
}

fn wait_for(events: &Receiver<Event>, phase: &str, want: impl Fn(&Event) -> bool) -> Event {
    let deadline = Instant::now() + WAIT;
    let mut seen = VecDeque::new();
    loop {
        let received = events.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        let Ok(event) = received else { panic!("no {phase}: {received:?}; earlier: {seen:?}") };
        if want(&event) {
            return event;
        }
        assert!(!matches!(event, Event::Disconnected | Event::SessionEnded), "{phase}: {event:?}");
        seen.push_back(format!("{event:?}"));
        if seen.len() > 16 {
            seen.pop_front();
        }
    }
}

/// A history-lines event for `room` with a line that contains `what`.
fn has_line(event: &Event, room: &str, what: &str) -> bool {
    matches!(event, Event::Calls { room: of, lines, .. } if of == room && lines.iter().any(|(_, text)| text.contains(what)))
}

fn has_title(event: &Event, title: &str) -> bool {
    matches!(event, Event::Meetings { meetings, .. } if meetings.iter().any(|meeting| meeting.title == title))
}

#[test]
fn meeting_lines_show_in_the_room_and_an_open_calendar_follows_another_persons_change() {
    let directory = Scratch(std::env::temp_dir().join(format!("crewcraft-t370b2-{}-{}", std::process::id(), wall_ms())));
    fs::create_dir(&directory.0).unwrap();
    let setup_time = wall_ms();
    let mut state = LabInstallation::initialize(&directory.0.join("server"), setup_time).unwrap();
    let fingerprint = state.issuer.root_fingerprint();
    let root_der = state.issuer.root_certificate().to_vec();
    let people = [
        Person { email: ALICE, secret: [17; 20], invitation: EnrollmentCode::from_bytes([1; 20]) },
        Person { email: BOB, secret: [19; 20], invitation: EnrollmentCode::from_bytes([2; 20]) },
    ];
    for person in &people {
        let invite = Invite { email: person.email.into(), bootstrap_pub: person.invitation.bootstrap_public_key(), expires_ms: setup_time + 600_000 };
        state.accounts.issue_invite(invite, setup_time).unwrap();
    }
    let room = state.rooms.create_room(ALICE, "Project").unwrap();
    state.rooms.add_member(&room, ALICE, BOB, Role::Member).unwrap();
    let running = start(state, setup_time, people.iter().map(|person| person.secret).collect());
    let devices: Vec<_> = people.iter().map(|person| person.enroll(&endpoint(&running, &root_der), &running.clock)).collect();
    running.stop();
    let state = LabInstallation::open(&directory.0.join("server"), fingerprint, wall_ms()).unwrap();
    let running = start(state, wall_ms() + STEP_MS, Vec::new());

    // Alice schedules a meeting next week (this week may already be over: the work week ends on Saturday).
    running.advance(STEP_MS);
    let code = people[0].code_at(clock_now(&running.clock));
    let credentials = Credentials::new(ALICE, PASSWORD, &code).unwrap();
    let mut alice: SignedInSession = endpoint(&running, &root_der).sign_in(devices[0].clone(), &credentials).unwrap();
    let (next_monday, _) = work_week_at(wall_ms(), 0, 1).unwrap();
    let save = |meeting, version, title: &str| MeetingSave {
        room: room.clone(),
        meeting,
        version,
        start_ms: next_monday + 10 * 60 * 60 * 1000,
        duration: 30,
        title: title.into(),
        agenda: String::new(),
    };
    let scheduled = alice.meeting_save(save(0, 0, "Weekly review")).unwrap();

    // Bob's app: the room's history holds the scheduled line, and his calendar shows next week's meeting.
    let config =
        WorkerConfig { poll_interval: Duration::from_millis(50), first_retry: Duration::from_millis(50), max_retry: Duration::from_millis(200) };
    let (worker, events) = Worker::start(endpoint(&running, &root_der), devices[1].clone(), config, || {}).unwrap();
    running.advance(STEP_MS);
    let code = people[1].code_at(clock_now(&running.clock));
    assert!(worker.sign_in(Credentials::new(BOB, PASSWORD, &code).unwrap()));
    wait_for(&events, "sign-in", |event| matches!(event, Event::SignedIn { .. }));
    assert!(worker.send(Command::Sync { room: room.clone() }));
    wait_for(&events, "the scheduled line", |event| has_line(event, &room, "scheduled a meeting"));
    assert!(worker.send(Command::ListMeetings { weeks: 1 }));
    wait_for(&events, "the week with the meeting", |event| has_title(event, "Weekly review"));

    // Alice edits it on her device. Bob's window sends nothing: his worker's poll sees the line and reads the week again.
    alice.meeting_save(save(scheduled.id, scheduled.version, "Weekly sync")).unwrap();
    wait_for(&events, "the edited line", |event| has_line(event, &room, "edited the meeting"));
    wait_for(&events, "the week after another person's edit", |event| has_title(event, "Weekly sync"));
    drop(worker);
    drop(alice);
    running.stop();
}
