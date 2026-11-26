//! T611j end to end: while signed in, the server asks the external authorizer again when the person's record is due
//! (docs/AUTHORIZER.md, the T600 rules), and a `deny` ends the session at the next request: the app is signed out, the
//! session cannot be resumed, and signing in again is refused. Between checks, requests do not ask. Real parts as in
//! T611i: the network server and the whole desktop-app stack; the provider, the browser, the authorizer and the server's
//! clock are the test's.
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
use crewcraft_authz::{Answer, Capabilities};
use crewcraft_bootstrap::{Environment, ExternalEnrollment};
use crewcraft_client_core::room_view::Shown;
use crewcraft_desktop_ui::{Action, Update};
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_oidc::Identity;
use crewcraft_oidc::{Key, parse_jwks};
use crewcraft_proto::handshake::ServerSide;
use crewcraft_server::external_signin::{Authorizer, ExternalSignIn, Provider};
use crewcraft_server::lab_bootstrap::bootstrap_handler_with;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use crewcraft_server::server_name::ServerName;
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

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("crewcraft-t611j-e2e-{}-{}", std::process::id(), wall_ms()));
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
    /// The server's clock: the tokens' times follow it.
    clock: Arc<AtomicU64>,
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
        let now = self.clock.load(Ordering::SeqCst) / 1000;
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
        protocol: ServerSide { min_version: 1, max_version: 1, features: 0, name: "external sign-in test server".into() },
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

/// An authorizer whose answer the test sets; it records each purpose it was asked for.
struct FakeAuthorizer {
    answer: Mutex<Answer>,
    asked: Mutex<Vec<String>>,
}

impl Authorizer for FakeAuthorizer {
    fn ask(&self, identity: &Identity, purpose: &str) -> Answer {
        assert_eq!((identity.issuer.as_str(), identity.subject.as_str()), (ISSUER, "sub-alice"));
        self.asked.lock().unwrap().push(purpose.to_owned());
        self.answer.lock().unwrap().clone()
    }
}

fn allow(revision: u64) -> Answer {
    Answer::Allow { capabilities: Capabilities::from_names(["use"]), revision, recheck_after_secs: None }
}

fn post_and_see(app: &mut Controller, room: &str, text: &str) {
    assert!(app.act(Action::Room(Command::Post { room: room.to_owned(), text: text.to_owned() })).is_empty());
    poll_until(app, text, |update| {
        matches!(update, Update::Snapshot { room: shown, shown: lines } if shown == room
            && lines.iter().any(|line| matches!(line, Shown::Line(line) if line.html.contains(text))))
    });
}

#[test]
fn a_deny_ends_the_session_at_the_next_request_after_the_recheck_is_due() {
    let scratch = Scratch::new();
    let setup_time = wall_ms();
    let server_dir = scratch.0.join("server");
    let mut state = LabInstallation::initialize(&server_dir, setup_time).unwrap();
    let pin = state.issuer.root_fingerprint();
    let root_der = state.issuer.root_certificate().to_vec();
    let code = EnrollmentCode::from_bytes([5; 20]);
    let invite = Invite { email: ALICE.into(), bootstrap_pub: code.bootstrap_public_key(), expires_ms: setup_time + 600_000 };
    state.accounts.issue_invite(invite, setup_time).unwrap();
    let room = state.rooms.create_room(ALICE, "General").unwrap();

    let clock = Arc::new(AtomicU64::new(setup_time));
    let seen = Arc::new(Mutex::new(Seen { person: ("sub-alice".into(), ALICE.into()), ..Seen::default() }));
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let provider = Arc::new(FakeProvider { pair, rng, seen: seen.clone(), clock: clock.clone() });
    let authorizer = Arc::new(FakeAuthorizer { answer: Mutex::new(allow(1)), asked: Mutex::new(Vec::new()) });
    let as_authorizer: Arc<dyn Authorizer> = authorizer.clone();
    let external = Arc::new(ExternalSignIn::new(provider, Some(as_authorizer), true));
    let running = start(state, &clock, vec![[51; 20]], external);
    let address = running.address.to_string();
    let join: Join = {
        let (address, root) = (address.clone(), root_der.clone());
        Box::new(move |_link: &str| {
            let endpoint =
                ServerEndpoint::new(&address, SERVER_NAME, RootFingerprint::from_der(&root), &root).map_err(|error| format!("{error:?}"))?;
            Ok((endpoint, code.clone()))
        })
    };

    let vault = MemoryVault::new();
    let (mut app, _) = Controller::start_with_vault(Some(scratch.0.join("alice")), vault.opener(), join, no_wake(), quick());
    app.set_browser(browser(&seen));
    assert!(app.act(Action::EnrollExternal { link: Zeroizing::new("crewcraft://enroll (the test's join)".into()) }).is_empty());
    poll_until(&mut app, "enrollment", |update| matches!(update, Update::Enrolled { .. }));
    assert!(app.act(Action::SignInExternal { email: ALICE.into() }).is_empty());
    poll_until(&mut app, "sign-in", |update| matches!(update, Update::SignedIn { .. }));
    assert!(app.act(Action::Room(Command::Sync { room: room.clone() })).is_empty());
    post_and_see(&mut app, &room, "first message");
    assert_eq!(*authorizer.asked.lock().unwrap(), vec!["sign-in".to_owned(), "sign-in".to_owned()], "enrollment and sign-in asked");

    // Within the ten minutes after a good answer, requests use the stored record and do not ask.
    clock.fetch_add(5 * 60 * 1000, Ordering::SeqCst);
    post_and_see(&mut app, &room, "five minutes later");
    assert_eq!(authorizer.asked.lock().unwrap().len(), 2);

    // The authorizer now denies. Once the recheck is due, the next request asks, and the session ends.
    *authorizer.answer.lock().unwrap() = Answer::Deny { revision: 2 };
    clock.fetch_add(6 * 60 * 1000, Ordering::SeqCst);
    assert!(app.act(Action::Room(Command::Post { room: room.clone(), text: "after the deny".into() })).is_empty());
    let updates = poll_until(&mut app, "the end of the session", |update| *update == Update::SignedOut);
    assert!(updates.iter().any(|update| matches!(update, Update::Failed(text) if text.contains("session has ended"))), "{updates:?}");
    assert_eq!(authorizer.asked.lock().unwrap().last().map(String::as_str), Some("recheck"));

    // Signing in again is refused while the authorizer denies.
    assert!(app.act(Action::SignInExternal { email: ALICE.into() }).is_empty());
    poll_until(&mut app, "the refused sign-in", |update| matches!(update, Update::Failed(text) if text.contains("did not accept")));

    // The denial is stored.
    drop(app);
    drop(running);
    let state = LabInstallation::open(&server_dir, pin, clock.load(Ordering::SeqCst)).unwrap();
    let record = state.accounts.authorization(ALICE).cloned().unwrap();
    assert_eq!(record.denied_revision, Some(2));
}
