//! T310: the whole beta flow with real parts. A network server (a configured name, the bind used by `serve`) and
//! two complete desktop-app stacks (controller, enrollment thread, saved device, connection worker): both people
//! enroll from invitation codes, set up their authenticator, sign in with TOTP, and exchange messages in a room.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::app::{Controller, Join, Wake};
use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::worker::WorkerConfig;
use crewcraft_bootstrap::Environment;
use crewcraft_client_core::room_view::Shown;
use crewcraft_desktop_ui::{Action, Update};
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::handshake::ServerSide;
use crewcraft_server::lab_bootstrap::bootstrap_handler;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use crewcraft_server::server_name::ServerName;
use crewcraft_server_core::activation::ISSUER;
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::room::Role;
use crewcraft_totp::Totp;
use crewcraft_ui_model::Command;
use zeroize::Zeroizing;

const WAIT: Duration = Duration::from_secs(10);
const STEP_MS: u64 = 30_000;
const SERVER_NAME: &str = "chat.example.org";
const PASSWORD: &str = "synthetic system test password";
const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("crewcraft-t310-{}-{}", std::process::id(), wall_ms()));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The server's clock and the TOTP secrets it hands out, so codes can be computed without waiting on wall time.
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

struct Person {
    email: &'static str,
    secret: [u8; 20],
    invitation: EnrollmentCode,
}

impl Person {
    fn totp(&self) -> Totp {
        Totp::with_defaults(self.secret.to_vec()).unwrap()
    }

    fn code_at(&self, now_ms: u64) -> Zeroizing<String> {
        Zeroizing::new(self.totp().generate(now_ms / 1000))
    }
}

struct Running {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn poll_until(controller: &mut Controller, what: &str, want: impl Fn(&Update) -> bool) -> Vec<Update> {
    let deadline = Instant::now() + WAIT;
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        let updates = controller.poll();
        let found = updates.iter().any(&want);
        seen.extend(updates);
        if found {
            return seen;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("timed out waiting for {what}; saw {seen:?}");
}

fn shows_text(update: &Update, room: &str, text: &str) -> bool {
    matches!(update, Update::Snapshot { room: shown_room, shown } if shown_room == room
        && shown.iter().any(|entry| matches!(entry, Shown::Line(line) if line.html.contains(text))))
}

/// Enroll one person through the whole app stack and return their controller at the sign-in screen.
fn enroll(person: &Person, data: PathBuf, join: Join, clock: &AtomicU64) -> Controller {
    let wake: Wake = Arc::new(|| {});
    let quick =
        WorkerConfig { poll_interval: Duration::from_millis(50), first_retry: Duration::from_millis(50), max_retry: Duration::from_millis(400) };
    let (mut controller, updates) = Controller::start(Some(data), join, wake, quick);
    assert_eq!(updates, vec![Update::NeedsEnrollment]);
    let link = Zeroizing::new("crewcraft://enroll (resolved by the test's join)".to_owned());
    assert!(controller.act(Action::Enroll { link, password: Zeroizing::new(PASSWORD.to_owned()) }).is_empty());
    let seen = poll_until(&mut controller, "the authenticator setup", |update| matches!(update, Update::AuthenticatorSetup { .. }));
    assert_eq!(seen.last(), Some(&Update::AuthenticatorSetup { otpauth_uri: person.totp().otpauth_uri(ISSUER, person.email) }));
    let code = person.code_at(clock.load(Ordering::SeqCst));
    assert!(controller.act(Action::ConfirmAuthenticator { code }).is_empty());
    let seen = poll_until(&mut controller, "enrollment", |update| matches!(update, Update::Enrolled { .. }));
    assert!(!seen.iter().any(|update| matches!(update, Update::Failed(_))), "{seen:?}");
    controller
}

fn sign_in(controller: &mut Controller, person: &Person, clock: &AtomicU64) -> Vec<String> {
    let code = person.code_at(clock.load(Ordering::SeqCst));
    let action = Action::SignIn { email: person.email.to_owned(), password: Zeroizing::new(PASSWORD.to_owned()), code };
    assert!(controller.act(action).is_empty());
    let seen = poll_until(controller, "sign-in", |update| matches!(update, Update::SignedIn { .. }));
    match seen.last() {
        Some(Update::SignedIn { email, rooms }) => {
            assert_eq!(email, person.email);
            rooms.clone()
        }
        other => panic!("expected SignedIn, got {other:?}"),
    }
}

#[test]
fn two_people_enroll_sign_in_and_chat_through_the_desktop_app_stack() {
    let scratch = Scratch::new();
    let setup_time = wall_ms();
    let mut state = LabInstallation::initialize(&scratch.0.join("server"), setup_time).unwrap();
    let root_der = state.issuer.root_certificate().to_vec();
    let alice = Person { email: ALICE, secret: [41; 20], invitation: EnrollmentCode::from_bytes([3; 20]) };
    let bob = Person { email: BOB, secret: [43; 20], invitation: EnrollmentCode::from_bytes([4; 20]) };
    for person in [&alice, &bob] {
        let invite = Invite { email: person.email.into(), bootstrap_pub: person.invitation.bootstrap_public_key(), expires_ms: setup_time + 600_000 };
        state.accounts.issue_invite(invite, setup_time).unwrap();
    }
    let room = state.rooms.create_room(ALICE, "General").unwrap();
    assert_eq!(state.rooms.add_member(&room, ALICE, BOB, Role::Member), Ok(1));

    // The network bind `serve` uses, with the server certificate signed for a real-looking name.
    let options = LabOptions {
        address: "127.0.0.1:0".parse().unwrap(),
        capacity: NonZeroUsize::new(8).unwrap(),
        timeouts: Timeouts { handshake: WAIT, sign_in: WAIT, signed_in_frame: WAIT, bootstrap: WAIT },
        protocol: ServerSide { min_version: 1, max_version: 1, features: 0, name: "system test server".into() },
    };
    let clock = Arc::new(AtomicU64::new(setup_time));
    let server_clock = clock.clone();
    let name = ServerName::parse(SERVER_NAME).unwrap();
    let server = LabRuntime::bind_network(state, options, &name, move || server_clock.load(Ordering::SeqCst)).unwrap();
    let address = server.local_addr().unwrap();
    let environment = TestEnvironment { clock: clock.clone(), secrets: VecDeque::from([alice.secret, bob.secret]) };
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let thread = thread::spawn(move || server.serve(&shutdown, |accounts, issuer| Ok(bootstrap_handler(accounts, issuer, environment))));
    let running = Running { address, stop, thread: Some(thread) };

    let join_for = |person: &Person| -> Join {
        let (address, root, code) = (running.address.to_string(), root_der.clone(), person.invitation.clone());
        Box::new(move |_link: &str| {
            let endpoint =
                ServerEndpoint::new(&address, SERVER_NAME, RootFingerprint::from_der(&root), &root).map_err(|error| format!("{error:?}"))?;
            Ok((endpoint, code.clone()))
        })
    };
    let mut alice_app = enroll(&alice, scratch.0.join("alice"), join_for(&alice), &clock);
    let mut bob_app = enroll(&bob, scratch.0.join("bob"), join_for(&bob), &clock);

    // A later authenticator step, so the sign-in codes are fresh.
    clock.fetch_add(STEP_MS, Ordering::SeqCst);
    let _ = sign_in(&mut alice_app, &alice, &clock);
    let _ = sign_in(&mut bob_app, &bob, &clock);
    for app in [&mut alice_app, &mut bob_app] {
        assert!(app.act(Action::Room(Command::Sync { room: room.clone() })).is_empty());
    }

    assert!(alice_app.act(Action::Room(Command::Post { room: room.clone(), text: "hello from the system test".into() })).is_empty());
    poll_until(&mut bob_app, "Alice's message on Bob's screen", |update| shows_text(update, &room, "hello from the system test"));
    assert!(bob_app.act(Action::Room(Command::Post { room: room.clone(), text: "and back again".into() })).is_empty());
    poll_until(&mut alice_app, "Bob's reply on Alice's screen", |update| shows_text(update, &room, "and back again"));

    // Signing out keeps the enrollment: a fresh controller on Alice's data folder goes straight to sign-in.
    assert_eq!(alice_app.act(Action::SignOut), vec![Update::SignedOut]);
    drop(alice_app);
    let wake: Wake = Arc::new(|| {});
    let (_again, updates) = Controller::start(Some(scratch.0.join("alice")), join_for(&alice), wake, WorkerConfig::default());
    // ... and fills in the email Alice last signed in with (T312).
    assert_eq!(updates, vec![Update::Enrolled { server: running.address.to_string() }, Update::LastEmail(ALICE.to_owned())]);
    drop(bob_app);
    drop(running);
}
