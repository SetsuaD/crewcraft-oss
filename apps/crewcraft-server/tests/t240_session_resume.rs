//! T240: a signed-in device resumes its session without a new authenticator code, for up to 12 hours from the sign-in:
//! after the connection is lost (here, the server restarts), and after the app is closed and opened again, however
//! long it sat idle. The ticket is kept owner-only next to the device record and works only from that device; signing
//! out ends the session on the server; past 12 hours the app says the session ended and asks for a code. Real parts:
//! the network server, and the whole desktop-app stack (controller, worker, saved device).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::app::{Controller, Join, PROFILE, Wake};
use crewcraft::chat_session::ChatError;
use crewcraft::device_store::DeviceStore;
use crewcraft::key_vault::MemoryVault;
use crewcraft::lab_client::LabError;
use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::signed_in::ResumeTicket;
use crewcraft::ticket_file::{TICKET_FILE, TicketFile};
use crewcraft::worker::{TicketKeeper, WorkerConfig};
use crewcraft_bootstrap::Environment;
use crewcraft_client_core::room_view::Shown;
use crewcraft_desktop_ui::{Action, Update};
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::message::CodecError;
use crewcraft_proto::signin::{self, Opening, Reply, SignIn, TOKEN_LEN};
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
const HOUR_MS: u64 = 60 * 60 * 1000;
const SERVER_NAME: &str = "chat.example.org";
const PASSWORD: &str = "synthetic resume test password";
const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("crewcraft-t240-{}-{}", std::process::id(), wall_ms()));
        fs::create_dir_all(&path).unwrap();
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

/// Serve `state` on `address` with the network bind `serve` uses, its clock and TOTP secrets from the test.
fn start(state: LabInstallation, address: &str, clock: &Arc<AtomicU64>, secrets: Vec<[u8; 20]>) -> Running {
    let options = LabOptions {
        address: address.parse().unwrap(),
        capacity: NonZeroUsize::new(8).unwrap(),
        timeouts: Timeouts { handshake: WAIT, sign_in: WAIT, signed_in_frame: WAIT, bootstrap: WAIT },
        protocol: ServerSide { min_version: 1, max_version: 1, features: 0, name: "resume test server".into() },
    };
    let server_clock = clock.clone();
    let name = ServerName::parse(SERVER_NAME).unwrap();
    let server = LabRuntime::bind_network(state, options, &name, move || server_clock.load(Ordering::SeqCst)).unwrap();
    let address = server.local_addr().unwrap();
    let environment = TestEnvironment { clock: clock.clone(), secrets: VecDeque::from(secrets) };
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let thread = thread::spawn(move || server.serve(&shutdown, |accounts, issuer| Ok(bootstrap_handler(accounts, issuer, environment))));
    Running { address, stop, thread: Some(thread) }
}

fn quick() -> WorkerConfig {
    WorkerConfig { poll_interval: Duration::from_millis(50), first_retry: Duration::from_millis(50), max_retry: Duration::from_millis(400) }
}

fn no_wake() -> Wake {
    Arc::new(|| {})
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

fn enroll(person: &Person, data: PathBuf, vault: &MemoryVault, join: Join, clock: &AtomicU64) -> Controller {
    let (mut controller, updates) = Controller::start_with_vault(Some(data), vault.opener(), join, no_wake(), quick());
    assert_eq!(updates, vec![Update::NeedsEnrollment]);
    let link = Zeroizing::new("crewcraft://enroll (resolved by the test's join)".to_owned());
    assert!(controller.act(Action::Enroll { link, password: Zeroizing::new(PASSWORD.to_owned()) }).is_empty());
    let seen = poll_until(&mut controller, "the authenticator setup", |update| matches!(update, Update::AuthenticatorSetup { .. }));
    assert_eq!(seen.last(), Some(&Update::AuthenticatorSetup { otpauth_uri: person.totp().otpauth_uri(ISSUER, person.email) }));
    assert!(controller.act(Action::ConfirmAuthenticator { code: person.code_at(clock.load(Ordering::SeqCst)) }).is_empty());
    poll_until(&mut controller, "enrollment", |update| matches!(update, Update::Enrolled { .. }));
    controller
}

fn sign_in(controller: &mut Controller, person: &Person, clock: &AtomicU64) {
    let action = Action::SignIn {
        email: person.email.to_owned(),
        password: Zeroizing::new(PASSWORD.to_owned()),
        code: person.code_at(clock.load(Ordering::SeqCst)),
    };
    assert!(controller.act(action).is_empty());
    poll_until(controller, "sign-in", |update| matches!(update, Update::SignedIn { .. }));
}

/// Wait until `path` exists (`true`) or is gone (`false`): the worker writes and deletes the ticket on its own thread.
fn wait_for_file(path: &Path, present: bool) {
    let deadline = Instant::now() + WAIT;
    while path.exists() != present {
        assert!(Instant::now() < deadline, "{} did not {}", path.display(), if present { "appear" } else { "go away" });
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_device_resumes_its_session_without_a_new_code_for_twelve_hours() {
    let scratch = Scratch::new();
    let setup_time = wall_ms();
    let server_dir = scratch.0.join("server");
    let mut state = LabInstallation::initialize(&server_dir, setup_time).unwrap();
    let pin = state.issuer.root_fingerprint();
    let root_der = state.issuer.root_certificate().to_vec();
    let alice = Person { email: ALICE, secret: [51; 20], invitation: EnrollmentCode::from_bytes([5; 20]) };
    let bob = Person { email: BOB, secret: [53; 20], invitation: EnrollmentCode::from_bytes([6; 20]) };
    for person in [&alice, &bob] {
        let invite = Invite { email: person.email.into(), bootstrap_pub: person.invitation.bootstrap_public_key(), expires_ms: setup_time + 600_000 };
        state.accounts.issue_invite(invite, setup_time).unwrap();
    }
    let room = state.rooms.create_room(ALICE, "General").unwrap();
    assert_eq!(state.rooms.add_member(&room, ALICE, BOB, Role::Member), Ok(1));
    let clock = Arc::new(AtomicU64::new(setup_time));
    let mut running = start(state, "127.0.0.1:0", &clock, vec![alice.secret, bob.secret]);
    let address = running.address;

    let endpoint = || ServerEndpoint::new(&address.to_string(), SERVER_NAME, RootFingerprint::from_der(&root_der), &root_der).unwrap();
    let join_for = |person: &Person| -> Join {
        let (address, root, code) = (address.to_string(), root_der.clone(), person.invitation.clone());
        Box::new(move |_link: &str| {
            let endpoint =
                ServerEndpoint::new(&address, SERVER_NAME, RootFingerprint::from_der(&root), &root).map_err(|error| format!("{error:?}"))?;
            Ok((endpoint, code.clone()))
        })
    };
    let (alice_dir, bob_dir) = (scratch.0.join("alice"), scratch.0.join("bob"));
    let (alice_vault, bob_vault) = (MemoryVault::new(), MemoryVault::new());
    let mut alice_app = enroll(&alice, alice_dir.clone(), &alice_vault, join_for(&alice), &clock);
    let mut bob_app = enroll(&bob, bob_dir.clone(), &bob_vault, join_for(&bob), &clock);
    clock.fetch_add(STEP_MS, Ordering::SeqCst);
    sign_in(&mut alice_app, &alice, &clock);
    sign_in(&mut bob_app, &bob, &clock);

    // The ticket is kept next to the device record, owner-only, and holds neither the password nor the code.
    let ticket_path = alice_dir.join(TICKET_FILE);
    wait_for_file(&ticket_path, true);
    let text = fs::read_to_string(&ticket_path).unwrap();
    assert!(
        text.starts_with(&format!("{ALICE}\n")) && !text.contains(PASSWORD) && !text.contains(alice.code_at(clock.load(Ordering::SeqCst)).as_str())
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&ticket_path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // 1. The server restarts: both apps lose the connection, stay signed in on screen, and resume on their own.
    drop(running);
    let seen = poll_until(&mut alice_app, "the lost connection", |update| matches!(update, Update::Failed(_)));
    assert!(!seen.contains(&Update::SignedOut), "{seen:?}");
    // The restarted server signs its own certificate at its clock's time, and the app checks it against real time, so
    // the server starts at the wall clock's time (the test's clock is a step ahead) and then goes on from where it was.
    let test_time = clock.swap(wall_ms(), Ordering::SeqCst);
    let state = LabInstallation::open(&server_dir, pin, clock.load(Ordering::SeqCst)).unwrap();
    running = start(state, &address.to_string(), &clock, Vec::new());
    clock.store(test_time, Ordering::SeqCst);
    for app in [&mut alice_app, &mut bob_app] {
        let seen = poll_until(app, "the resumed session", |update| matches!(update, Update::SignedIn { .. }));
        assert!(!seen.contains(&Update::SignedOut), "{seen:?}");
        assert!(app.act(Action::Room(Command::Sync { room: room.clone() })).is_empty());
    }
    assert!(alice_app.act(Action::Room(Command::Post { room: room.clone(), text: "after the restart".into() })).is_empty());
    poll_until(&mut bob_app, "Alice's message after the restart", |update| shows_text(update, &room, "after the restart"));

    // 2. The app is closed and opened two hours later (well past the 30-minute idle limit): it resumes at once.
    drop(alice_app);
    clock.fetch_add(2 * HOUR_MS, Ordering::SeqCst);
    let (mut alice_app, updates) = Controller::start_with_vault(Some(alice_dir.clone()), alice_vault.opener(), join_for(&alice), no_wake(), quick());
    assert_eq!(updates, vec![Update::Enrolled { server: address.to_string() }, Update::LastEmail(ALICE.to_owned())]);
    let seen = poll_until(&mut alice_app, "the session resumed at start", |update| matches!(update, Update::SignedIn { .. }));
    assert!(!seen.iter().any(|update| matches!(update, Update::Failed(_))), "{seen:?}");

    // 3. The ticket works only from the device it belongs to.
    let ticket: ResumeTicket = TicketFile::new(&alice_dir).load().unwrap();
    let alice_device = DeviceStore::open_sealed(&alice_dir, Arc::new(alice_vault.clone())).unwrap().load(PROFILE).unwrap();
    let bob_device = DeviceStore::open_sealed(&bob_dir, Arc::new(bob_vault.clone())).unwrap().load(PROFILE).unwrap();
    assert!(matches!(endpoint().resume(bob_device.identity().unwrap(), &ticket), Err(LabError::Chat(ChatError::SignInRefused))));
    assert!(endpoint().resume(alice_device.identity().unwrap(), &ticket).is_ok());

    // 4. Signing out ends the session on the server and forgets the ticket.
    assert_eq!(alice_app.act(Action::SignOut), vec![Update::SignedOut]);
    wait_for_file(&ticket_path, false);
    assert!(matches!(endpoint().resume(alice_device.identity().unwrap(), &ticket), Err(LabError::Chat(ChatError::SignInRefused))));

    // 5. Past 12 hours from the sign-in the ticket no longer works: the app says so, asks for a code, and forgets it.
    clock.fetch_add(STEP_MS, Ordering::SeqCst);
    sign_in(&mut alice_app, &alice, &clock);
    wait_for_file(&ticket_path, true);
    drop(alice_app);
    clock.fetch_add(13 * HOUR_MS, Ordering::SeqCst);
    let (mut alice_app, _) = Controller::start_with_vault(Some(alice_dir.clone()), alice_vault.opener(), join_for(&alice), no_wake(), quick());
    let seen = poll_until(&mut alice_app, "the ended session", |update| matches!(update, Update::Failed(_)));
    assert!(seen.contains(&Update::SignedOut), "{seen:?}");
    assert!(seen.contains(&Update::Failed("Your session has ended. Sign in again with a new code.".to_owned())), "{seen:?}");
    wait_for_file(&ticket_path, false);
    // ... and a new sign-in with a code still works.
    sign_in(&mut alice_app, &alice, &clock);

    drop(alice_app);
    drop(bob_app);
    drop(running);
}

#[test]
fn the_resume_and_end_requests_are_checked_on_the_wire() {
    let token = format!("{}A", "a".repeat(TOKEN_LEN - 1));
    for opening in [Opening::Resume { token: &token }, Opening::End { token: &token }] {
        let bytes = signin::encode_opening(&opening).unwrap();
        assert_eq!(bytes.len(), 1 + TOKEN_LEN);
        assert_eq!(signin::decode_opening(&bytes).unwrap(), opening);
        assert!(!format!("{opening:?}").contains(&token), "Debug hides the token");
        assert_eq!(signin::decode_opening(&bytes[..TOKEN_LEN]), Err(CodecError::Truncated));
        assert_eq!(signin::decode_opening(&[bytes.as_slice(), b"x"].concat()), Err(CodecError::TrailingBytes));
        // A plain sign-in decoder still refuses them.
        assert_eq!(signin::decode_request(&bytes), Err(CodecError::BadKind(bytes[0])));
    }
    assert_eq!(signin::encode_opening(&Opening::Resume { token: "short" }), Err(CodecError::FieldLength));
    let bad_ending = format!("{}B", "a".repeat(TOKEN_LEN - 1));
    assert!(signin::encode_opening(&Opening::End { token: &bad_ending }).is_err());
    let sign_in = SignIn { email: ALICE, password: PASSWORD, code: "123456" };
    let bytes = signin::encode_opening(&Opening::SignIn(SignIn { email: ALICE, password: PASSWORD, code: "123456" })).unwrap();
    assert_eq!(bytes, signin::encode_request(&sign_in).unwrap());
    assert_eq!(signin::decode_opening(&bytes).unwrap(), Opening::SignIn(sign_in));
    assert_eq!(signin::encode_reply(&Reply::Ended).unwrap(), [165]);
    assert_eq!(signin::decode_reply(&[165]), Ok(Reply::Ended));
    assert_eq!(signin::decode_reply(&[165, 0]), Err(CodecError::TrailingBytes));
    assert!(ResumeTicket::new(ALICE, &token).is_some());
    assert!(ResumeTicket::new(ALICE, "short").is_none() && ResumeTicket::new("", &token).is_none());
    assert_eq!(format!("{:?}", ResumeTicket::new(ALICE, &token).unwrap()), "ResumeTicket { .. }");
}
