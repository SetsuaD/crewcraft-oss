//! T350d2 end to end: a Teams-style bundle imported into a real server shows in Alice's app as an archive room, with
//! each imported message's original time; posting into it is refused. Real parts: the network server with its
//! journal, and the whole desktop-app stack; sign-in goes through the test's provider and browser.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crewcraft::app::{Controller, Join, Wake};
use crewcraft::key_vault::MemoryVault;
use crewcraft::loopback::parse_query;
use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::worker::{Browser, WorkerConfig};
use crewcraft_bootstrap::{Environment, ExternalEnrollment};
use crewcraft_client_core::room_view::Shown;
use crewcraft_desktop_ui::{Action, Update};
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_oidc::{Key, parse_jwks};
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::request::{FEATURE_ARCHIVE, FEATURE_FILES, FEATURE_LIST_ROOMS, FEATURE_REACTIONS, FEATURE_SEARCH, FEATURE_THREADS};
use crewcraft_server::external_signin::{ExternalSignIn, Provider};
use crewcraft_server::lab_bootstrap::bootstrap_handler_with;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use crewcraft_server::server_name::ServerName;
use crewcraft_server_core::import::{Bundle, BundleMessage, BundleRoom, RoomKind};
use crewcraft_server_core::invites::Invite;
use crewcraft_ui_model::Command;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::json;
use zeroize::Zeroizing;

const WAIT: Duration = Duration::from_secs(10);
const SERVER_NAME: &str = "chat.example.org";
const ISSUER: &str = "https://id.example.org/application/o/chat/";
const CLIENT: &str = "chat-client";
const ALICE: &str = "alice@example.org";
const CODE: &str = "provider-code";
/// 2024-03-05 14:07:09 UTC.
const SENT: u64 = 1_709_647_629_123;

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("crewcraft-t350d2-e2e-{}-{}", std::process::id(), wall_ms()));
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

/// What the test's browser saw in the last authorization URL, and who the provider says signed in.
#[derive(Default)]
struct Seen {
    nonce: String,
    challenge: String,
    /// The `sub` and `email` the next ID token carries.
    person: (String, String),
    exchanges: usize,
}

/// A provider whose ID tokens are signed here, for the nonce and PKCE challenge the browser last saw.
struct FakeProvider {
    pair: EcdsaKeyPair,
    rng: SystemRandom,
    seen: Arc<Mutex<Seen>>,
}

impl Provider for FakeProvider {
    fn issuer(&self) -> &str {
        ISSUER
    }
    fn client_id(&self) -> &str {
        CLIENT
    }
    fn authorization_endpoint(&self) -> Result<String, String> {
        Ok("https://id.example.org/authorize/".into())
    }
    fn keys(&self, _: bool) -> Result<Vec<Key>, String> {
        let point = self.pair.public_key().as_ref();
        let doc = json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "x": URL_SAFE_NO_PAD.encode(&point[1..33]), "y": URL_SAFE_NO_PAD.encode(&point[33..65])}]});
        Ok(parse_jwks(doc.to_string().as_bytes()).unwrap())
    }
    fn exchange(&self, code: &str, verifier: &str, redirect_uri: &str) -> Result<String, String> {
        let mut seen = self.seen.lock().unwrap();
        seen.exchanges += 1;
        // The provider's own PKCE check: the verifier must hash to the challenge the browser carried.
        let hashed = URL_SAFE_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()));
        if code != CODE || hashed != seen.challenge || !redirect_uri.starts_with("http://127.0.0.1:") {
            return Err("invalid_grant".into());
        }
        let now = wall_ms() / 1000;
        let claims = json!({
            "iss": ISSUER, "aud": CLIENT, "sub": seen.person.0, "email": seen.person.1, "exp": now + 600, "iat": now,
            "amr": ["pwd", "mfa"], "nonce": seen.nonce,
        });
        let header = URL_SAFE_NO_PAD.encode(json!({"alg": "ES256", "kid": "k1"}).to_string());
        let signed = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
        let signature = self.pair.sign(&self.rng, signed.as_bytes()).unwrap();
        Ok(format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref())))
    }
}

/// The browser: note the nonce and challenge, then send the provider's redirect with `CODE` to the app's loopback.
fn browser(seen: &Arc<Mutex<Seen>>) -> Browser {
    let seen = seen.clone();
    Arc::new(move |url: &str| {
        let (endpoint, query) = url.split_once('?').unwrap();
        assert_eq!(endpoint, "https://id.example.org/authorize/");
        let params = parse_query(query);
        let get = |k: &str| params.iter().find(|(name, _)| name == k).unwrap().1.clone();
        {
            let mut seen = seen.lock().unwrap();
            seen.nonce = get("nonce");
            seen.challenge = get("code_challenge");
        }
        let redirect = get("redirect_uri");
        let (authority, path) = redirect.trim_start_matches("http://").split_once('/').unwrap();
        let (authority, target) = (authority.to_owned(), format!("/{path}?code={CODE}&state={}", get("state")));
        thread::spawn(move || {
            let mut stream = TcpStream::connect(&authority).unwrap();
            stream.write_all(format!("GET {target} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes()).unwrap();
            let mut answer = String::new();
            let _ = stream.read_to_string(&mut answer);
        });
        Ok(())
    })
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

/// Serve `state` with sign-in and enrollment through `external`.
fn start(state: LabInstallation, clock: &Arc<AtomicU64>, secrets: Vec<[u8; 20]>, external: Arc<ExternalSignIn>) -> Running {
    let options = LabOptions {
        address: "127.0.0.1:0".parse().unwrap(),
        capacity: NonZeroUsize::new(8).unwrap(),
        timeouts: Timeouts { handshake: WAIT, sign_in: WAIT, signed_in_frame: WAIT, bootstrap: WAIT },
        protocol: ServerSide {
            min_version: 1,
            max_version: 1,
            features: FEATURE_LIST_ROOMS | FEATURE_SEARCH | FEATURE_FILES | FEATURE_THREADS | FEATURE_REACTIONS | FEATURE_ARCHIVE,
            name: "archive test server".into(),
        },
    };
    let server_clock = clock.clone();
    let name = ServerName::parse(SERVER_NAME).unwrap();
    let server =
        LabRuntime::bind_network(state, options, &name, move || server_clock.load(Ordering::SeqCst)).unwrap().with_external(external.clone());
    let address = server.local_addr().unwrap();
    let environment = TestEnvironment { clock: clock.clone(), secrets: VecDeque::from(secrets) };
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let enrollment: Arc<dyn ExternalEnrollment> = external;
    let thread = thread::spawn(move || {
        server.serve(&shutdown, move |accounts, issuer| Ok(bootstrap_handler_with(accounts, issuer, environment, Some(enrollment))))
    });
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

const BOB: &str = "bob@example.org";

/// Enroll and sign in `email` (whose provider subject is `subject`) with a fresh app in `dir`.
fn signed_in(dir: PathBuf, join: Join, seen: &Arc<Mutex<Seen>>, email: &str, subject: &str, vault: &MemoryVault) -> Controller {
    seen.lock().unwrap().person = (subject.into(), email.into());
    let (mut app, _) = Controller::start_with_vault(Some(dir), vault.opener(), join, no_wake(), quick());
    app.set_browser(browser(seen));
    assert!(app.act(Action::EnrollExternal { link: Zeroizing::new("crewcraft://enroll (the test's join)".into()) }).is_empty());
    poll_until(&mut app, "enrollment", |update| matches!(update, Update::Enrolled { .. }));
    assert!(app.act(Action::SignInExternal { email: email.into() }).is_empty());
    poll_until(&mut app, "sign-in", |update| matches!(update, Update::SignedIn { .. }));
    app
}

/// The cursor of the message whose HTML contains `text`, from the snapshots in `updates`.
fn cursor_of(updates: &[Update], text: &str) -> Option<u64> {
    updates.iter().rev().find_map(|update| match update {
        Update::Snapshot { shown, .. } => shown.iter().find_map(|row| match row {
            Shown::Line(line) if line.html.contains(text) => Some(line.cursor),
            _ => None,
        }),
        _ => None,
    })
}

#[test]
fn an_imported_room_reaches_the_app_as_an_archive() {
    let scratch = Scratch::new();
    let setup_time = wall_ms();
    let server_dir = scratch.0.join("server");
    let mut state = LabInstallation::initialize(&server_dir, setup_time).unwrap();
    let root_der = state.issuer.root_certificate().to_vec();
    let codes = [EnrollmentCode::from_bytes([5; 20]), EnrollmentCode::from_bytes([6; 20])];
    for (email, code) in [ALICE, BOB].iter().zip(&codes) {
        let invite = Invite { email: (*email).into(), bootstrap_pub: code.bootstrap_public_key(), expires_ms: setup_time + 600_000 };
        state.accounts.issue_invite(invite, setup_time).unwrap();
    }
    let room = state.rooms.create_room(ALICE, "General").unwrap();
    state.rooms.add_member(&room, ALICE, BOB, crewcraft_server_core::room::Role::Member).unwrap();
    // Last year's conversation, imported as an archive room.
    let message = |key: &str, minute: u64, text: &str| BundleMessage {
        room: "c1".into(),
        key: key.into(),
        author: BOB.into(),
        sent_ms: SENT + minute * 60_000,
        text: text.into(),
        reply_to: None,
        edited_ms: None,
        deleted: false,
        files: Vec::new(),
    };
    let bundle = Bundle {
        source: "teams".into(),
        rooms: vec![BundleRoom { key: "c1".into(), kind: RoomKind::Group, name: "Old team".into(), members: vec![ALICE.into(), BOB.into()] }],
        messages: vec![message("m1", 0, "the plan from last year"), message("m2", 1, "and the budget")],
    };
    let imported = state.rooms.import(&bundle, &|_| true, false).unwrap();
    assert!(imported.ok(), "{:?}", imported.refusals);
    let archive = state.rooms.archive_room("teams", "c1").unwrap().to_owned();

    let seen = Arc::new(Mutex::new(Seen::default()));
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let provider = Arc::new(FakeProvider { pair, rng, seen: seen.clone() });
    let external = Arc::new(ExternalSignIn::new(provider, None, true));
    let clock = Arc::new(AtomicU64::new(setup_time));
    let running = start(state, &clock, vec![[51; 20], [53; 20]], external);
    let address = running.address.to_string();
    let join_for = |code: &EnrollmentCode| -> Join {
        let (address, root, code) = (address.clone(), root_der.clone(), code.clone());
        Box::new(move |_link: &str| {
            let endpoint =
                ServerEndpoint::new(&address, SERVER_NAME, RootFingerprint::from_der(&root), &root).map_err(|error| format!("{error:?}"))?;
            Ok((endpoint, code.clone()))
        })
    };
    let (alice_vault, bob_vault) = (MemoryVault::new(), MemoryVault::new());
    let mut alice = signed_in(scratch.0.join("alice"), join_for(&codes[0]), &seen, ALICE, "sub-alice", &alice_vault);
    let mut bob = signed_in(scratch.0.join("bob"), join_for(&codes[1]), &seen, BOB, "sub-bob", &bob_vault);

    let _ = &mut bob;
    assert!(alice.act(Action::Room(Command::Sync { room: archive.clone() })).is_empty());
    let updates = poll_until(&mut alice, "the archive", |update| matches!(update, Update::Archive { times, .. } if times.len() == 2));
    // The last archive update, the one with both times: an earlier sync may have carried only the first.
    let times = updates
        .iter()
        .rev()
        .find_map(|update| match update {
            Update::Archive { room, times } if *room == archive && times.len() == 2 => Some(times.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(times.iter().map(|(_, ms)| *ms).collect::<Vec<_>>(), vec![SENT, SENT + 60_000]);
    let updates = poll_until(&mut alice, "the messages", |update| cursor_of(std::slice::from_ref(update), "budget").is_some());
    assert!(cursor_of(&updates, "the plan").is_some());

    // The archive takes no messages.
    assert!(alice.act(Action::Room(Command::Post { room: archive.clone(), text: "too late".into() })).is_empty());
    poll_until(&mut alice, "the refused post", |update| matches!(update, Update::Failed(text) if text.contains("was not sent")));
    drop(alice);
    drop(bob);
    drop(running);
}
