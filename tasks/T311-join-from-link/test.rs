//! T311: the desktop app joins from a real invitation link, off the window's thread. The server prints the link
//! `first-run` would print; the app parses it, fetches the root certificate against its fingerprint and enrolls.
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

use crewcraft::app::{Controller, Wake, join_from_link};
use crewcraft::key_vault::MemoryVault;
use crewcraft::worker::WorkerConfig;
use crewcraft_bootstrap::Environment;
use crewcraft_desktop_ui::{Action, Update};
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_enroll::{EnrollmentCode, InvitationLink};
use crewcraft_proto::handshake::ServerSide;
use crewcraft_server::lab_bootstrap::bootstrap_handler;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use crewcraft_server::server_name::ServerName;
use crewcraft_server_core::invites::Invite;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const WAIT: Duration = Duration::from_secs(10);
const PERSON: &str = "carol@example.org";

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct FixedEnvironment {
    clock: Arc<AtomicU64>,
    secrets: VecDeque<[u8; 20]>,
}

impl Environment for FixedEnvironment {
    fn now_ms(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn totp_secret(&mut self) -> Option<[u8; 20]> {
        self.secrets.pop_front()
    }
}

struct Running {
    address: SocketAddr,
    root_sha256: [u8; 32],
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

/// A network-bound server named `localhost` with one live invitation.
fn start(dir: &std::path::Path, invitation: &EnrollmentCode) -> Running {
    let now = wall_ms();
    let mut state = LabInstallation::initialize(dir, now).unwrap();
    let root_sha256: [u8; 32] = Sha256::digest(state.issuer.root_certificate()).into();
    let invite = Invite { email: PERSON.into(), bootstrap_pub: invitation.bootstrap_public_key(), expires_ms: now + 600_000 };
    state.accounts.issue_invite(invite, now).unwrap();
    let options = LabOptions {
        address: "127.0.0.1:0".parse().unwrap(),
        capacity: NonZeroUsize::new(4).unwrap(),
        timeouts: Timeouts { handshake: WAIT, sign_in: WAIT, signed_in_frame: WAIT, bootstrap: WAIT },
        protocol: ServerSide { min_version: 1, max_version: 1, features: 0, name: "join test server".into() },
    };
    let clock = Arc::new(AtomicU64::new(now));
    let server_clock = clock.clone();
    let server =
        LabRuntime::bind_network(state, options, &ServerName::parse("localhost").unwrap(), move || server_clock.load(Ordering::SeqCst)).unwrap();
    let address = server.local_addr().unwrap();
    let environment = FixedEnvironment { clock, secrets: VecDeque::from([[47; 20]]) };
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let thread = thread::spawn(move || server.serve(&shutdown, |accounts, issuer| Ok(bootstrap_handler(accounts, issuer, environment))));
    Running { address, root_sha256, stop, thread: Some(thread) }
}

fn poll_until(controller: &mut Controller, want: impl Fn(&Update) -> bool) -> Vec<Update> {
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
    panic!("timed out; saw {seen:?}");
}

fn enroll_from(link: &str, data: PathBuf) -> (Controller, Vec<Update>) {
    let wake: Wake = Arc::new(|| {});
    let (mut controller, updates) =
        Controller::start_with_vault(Some(data), MemoryVault::new().opener(), join_from_link(WAIT), wake, WorkerConfig::default());
    assert_eq!(updates, vec![Update::NeedsEnrollment]);
    let action = Action::Enroll { link: Zeroizing::new(link.to_owned()), password: Zeroizing::new("synthetic join test password".to_owned()) };
    assert!(controller.act(action).is_empty(), "joining must not block the window");
    let seen = poll_until(&mut controller, |update| matches!(update, Update::AuthenticatorSetup { .. } | Update::Failed(_)));
    (controller, seen)
}

#[test]
fn a_real_link_reaches_the_authenticator_step_and_bad_links_are_explained() {
    let scratch = Scratch(std::env::temp_dir().join(format!("crewcraft-t311-{}-{}", std::process::id(), wall_ms())));
    fs::create_dir_all(&scratch.0).unwrap();
    let invitation = EnrollmentCode::from_bytes([5; 20]);
    let server = start(&scratch.0.join("server"), &invitation);
    let public = format!("localhost:{}", server.address.port());

    // The link the server prints, with surrounding whitespace as a paste might carry.
    let link = InvitationLink::new(&public, invitation.clone(), RootFingerprint::from_bytes(server.root_sha256)).unwrap().to_string();
    let (_controller, seen) = enroll_from(&format!("  {link}\n"), scratch.0.join("good"));
    assert!(matches!(seen.last(), Some(Update::AuthenticatorSetup { .. })), "{seen:?}");

    // The same server and code, but a fingerprint the server cannot match: refused before any enrollment byte.
    let mut wrong = server.root_sha256;
    wrong[0] ^= 1;
    let forged = InvitationLink::new(&public, invitation.clone(), RootFingerprint::from_bytes(wrong)).unwrap().to_string();
    let (_controller, seen) = enroll_from(&forged, scratch.0.join("forged"));
    assert_eq!(seen.first(), Some(&Update::NeedsEnrollment));
    assert!(matches!(seen.last(), Some(Update::Failed(text)) if text.contains("did not prove")), "{seen:?}");

    // Not a link at all.
    let (_controller, seen) = enroll_from("hello there", scratch.0.join("text"));
    assert!(matches!(seen.last(), Some(Update::Failed(text)) if text.contains("not a CrewCraft invitation link")), "{seen:?}");

    // Nothing listens here: reported as unreachable, within the timeout.
    let closed = format!("localhost:{}", { std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port() });
    let gone = InvitationLink::new(&closed, invitation, RootFingerprint::from_bytes(server.root_sha256)).unwrap().to_string();
    let (_controller, seen) = enroll_from(&gone, scratch.0.join("gone"));
    assert!(matches!(seen.last(), Some(Update::Failed(text)) if text.contains("could not be reached")), "{seen:?}");
}
