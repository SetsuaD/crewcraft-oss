//! Wire enrollment, mTLS chat and full lab-state reopen with two synthetic people.
#![allow(clippy::unwrap_used)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::bootstrap_transport::{BootstrapEndpoint, BootstrapTransportError};
use crewcraft::chat_session::{ChatError, ChatSession};
use crewcraft::enroll_client::{EnrollmentError, EnrollmentRequest, ExchangeProblem, FirstTotpCode};
use crewcraft::lab_client::LabError;
use crewcraft_bootstrap::Environment;
use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::frame;
use crewcraft_proto::handshake::{Hello, ServerSide};
use crewcraft_proto::signin::{SignIn, encode_request};
use crewcraft_server::lab_bootstrap::bootstrap_handler;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use crewcraft_server_core::account_store::AccountStore;
use crewcraft_server_core::activation::ISSUER;
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::room::Role;
use crewcraft_tls::{DeadlineSocket, client_config, connect};
use crewcraft_totp::Totp;
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const WAIT: Duration = Duration::from_secs(10);
const STEP_MS: u64 = 30_000;
const PASSWORD: &str = "synthetic durable lab password";
const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";
const ALICE_SECRET: [u8; 20] = [31; 20];
const BOB_SECRET: [u8; 20] = [37; 20];
const DELETED_BODY: &str = "synthetic message for the redaction test";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = elapsed_since_epoch().as_nanos();
        let path = std::env::temp_dir().join(format!("crewcraft-t225-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn elapsed_since_epoch() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

fn wall_ms() -> u64 {
    elapsed_since_epoch().as_millis() as u64
}

fn cutoff() -> Instant {
    Instant::now() + WAIT
}

fn roots(root_der: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root_der)).unwrap();
    roots
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

    fn invite(&self, store: &mut AccountStore, now_ms: u64) {
        let invite = Invite { email: self.email.into(), bootstrap_pub: self.invitation.bootstrap_public_key(), expires_ms: now_ms + 300_000 };
        store.issue_invite(invite, now_ms).unwrap();
    }

    fn enroll(&self, endpoint: &BootstrapEndpoint, trusted: RootCertStore, now_ms: u64) -> Arc<ClientConfig> {
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
        let expected_spki = key.subject_public_key_info();
        let request = || EnrollmentRequest {
            device_name: "Synthetic Test Device",
            csr: csr.der().as_ref(),
            password: PASSWORD,
            expected_spki: &expected_spki,
        };
        let chain = endpoint
            .open(&self.invitation, WAIT)
            .unwrap()
            .enroll(request(), |setup, _| {
                assert!(setup.protected_uri() == self.totp().otpauth_uri(ISSUER, self.email));
                FirstTotpCode::parse(self.code_at(now_ms))
            })
            .unwrap();
        self.assert_consumed(endpoint, request());
        let identity = (vec![chain.leaf, chain.issuer], PrivatePkcs8KeyDer::from(key.serialize_der()).into());
        client_config(trusted, Some(identity)).unwrap()
    }

    fn assert_consumed(&self, endpoint: &BootstrapEndpoint, request: EnrollmentRequest<'_>) {
        match endpoint.open(&self.invitation, WAIT) {
            Err(error) => assert_eq!(error, BootstrapTransportError::Connection(LabError::Handshake)),
            Ok(connection) => {
                // A client can finish writing its handshake before the server checks its invitation key.
                // If it gets that far, expect a bare close without any bootstrap application response.
                let error = connection.enroll(request, |_, _| None).unwrap_err();
                assert!(matches!(
                    error,
                    EnrollmentError::Setup(ExchangeProblem::Io(
                        io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe
                    ))
                ));
            }
        }
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

struct Running {
    address: SocketAddr,
    clock: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<()>>>,
}

impl Running {
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

fn start(state: LabInstallation, initial_auth_time: u64) -> Running {
    let options = LabOptions {
        address: "127.0.0.1:0".parse().unwrap(),
        capacity: NonZeroUsize::new(4).unwrap(),
        timeouts: Timeouts { handshake: WAIT, sign_in: WAIT, signed_in_frame: WAIT, bootstrap: WAIT },
        protocol: ServerSide { min_version: 1, max_version: 1, features: 0, name: "test server".into() },
    };
    // Sign the TLS server certificate at wall time. Control TOTP and rate limiting only after binding.
    let clock = Arc::new(AtomicU64::new(wall_ms()));
    let server_clock = clock.clone();
    let server = LabRuntime::bind(state, options, move || server_clock.load(Ordering::SeqCst)).unwrap();
    let address = server.local_addr().unwrap();
    clock.store(initial_auth_time, Ordering::SeqCst);
    let environment = TestEnvironment { clock: clock.clone(), secrets: VecDeque::from([ALICE_SECRET, BOB_SECRET]) };
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let thread = thread::spawn(move || server.serve(&shutdown, |accounts, issuer| Ok(bootstrap_handler(accounts, issuer, environment))));
    Running { address, clock, stop, thread: Some(thread) }
}

type ClientStream = StreamOwned<ClientConnection, DeadlineSocket>;

struct ObserveReads<'a> {
    stream: ClientStream,
    capture: &'a RefCell<Option<Vec<u8>>>,
}

impl Read for ObserveReads<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.stream.read(buf)?;
        if let Some(received) = self.capture.borrow_mut().as_mut() {
            received.extend_from_slice(&buf[..read]);
        }
        Ok(read)
    }
}

impl Write for ObserveReads<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn dial(address: SocketAddr, config: Arc<ClientConfig>) -> ClientStream {
    let socket = TcpStream::connect_timeout(&address, WAIT).unwrap();
    let tls = connect(socket, config, ServerName::try_from("localhost").unwrap()).unwrap();
    StreamOwned::new(tls.conn, DeadlineSocket::new(tls.sock, cutoff()))
}

fn set_deadline(stream: &mut ClientStream, deadline: Instant) {
    stream.sock.set_deadline(deadline);
}

fn chat<S: Read + Write, D: FnMut(&mut S, Instant)>(stream: S, deadline: D, person: &Person, code: &str) -> Result<ChatSession<S, D>, ChatError> {
    let request = SignIn { email: person.email, password: PASSWORD, code };
    let hello = Hello { min_version: 1, max_version: 1, features: 0, client: "test client".into() };
    ChatSession::connect(stream, deadline, &request, hello, Settings::new(person.email), WAIT, cutoff())
}

fn assert_dark(mut stream: ClientStream, email: &str, code: &str) {
    let request = SignIn { email, password: PASSWORD, code };
    let bytes = frame::encode(&encode_request(&request).unwrap()).unwrap();
    let _ = stream.write_all(&bytes);
    let _ = stream.flush();
    let mut byte = [0];
    match stream.read(&mut byte) {
        Ok(read) => assert_eq!(read, 0),
        Err(error) => assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe
        )),
    }
}

fn line(cursor: u64, author: &str, text: &str) -> Shown {
    Shown::Line(Line { cursor, author: author.into(), html: text.into(), edited: false })
}

#[test]
fn both_clients_enroll_and_chat_then_reopen_every_server_store_and_replay() {
    let directory = TestDirectory::new();
    let state_path = directory.0.join("state");
    let setup_time = wall_ms();
    let mut state = LabInstallation::initialize(&state_path, setup_time).unwrap();
    let pin = state.issuer.root_fingerprint();
    let root_der = state.issuer.root_certificate().to_vec();
    let trusted = roots(&root_der);
    let alice = Person { email: ALICE, secret: ALICE_SECRET, invitation: EnrollmentCode::from_bytes([1; 20]) };
    let bob = Person { email: BOB, secret: BOB_SECRET, invitation: EnrollmentCode::from_bytes([2; 20]) };
    alice.invite(&mut state.accounts, setup_time);
    bob.invite(&mut state.accounts, setup_time);
    let room = state.rooms.create_room(ALICE, "General").unwrap();
    assert_eq!(state.rooms.add_member(&room, ALICE, BOB, Role::Member), Ok(1));

    let first = start(state, setup_time);
    let endpoint = BootstrapEndpoint::new(&first.address.to_string(), "localhost", RootFingerprint::from_der(&root_der), &root_der).unwrap();
    let alice_config = alice.enroll(&endpoint, trusted.clone(), setup_time);
    let bob_config = bob.enroll(&endpoint, trusted.clone(), setup_time);

    // Pick a synthetic sign-in time with distinct adjacent codes so the replay assertion cannot hit a collision.
    let first_sign_in = (1..=8)
        .map(|offset| setup_time + offset * STEP_MS)
        .find(|&at| {
            let bob_code = bob.code_at(at);
            alice.code_at(at) != alice.code_at(at - STEP_MS) && bob_code != bob.code_at(at - STEP_MS) && bob_code != bob.code_at(at + STEP_MS)
        })
        .unwrap();
    first.clock.store(first_sign_in, Ordering::SeqCst);
    let mut client_a = chat(dial(first.address, alice_config.clone()), set_deadline, &alice, &alice.code_at(first_sign_in)).unwrap();
    let mut client_b = chat(dial(first.address, bob_config.clone()), set_deadline, &bob, &bob.code_at(first_sign_in)).unwrap();

    let expected = [line(2, ALICE, "Hello from Alice"), line(3, BOB, "Hello from Bob")];
    assert_eq!(client_a.post(&room, "Hello from Alice", first_sign_in, 0, cutoff()), Ok(2));
    assert_eq!(client_b.sync(&room, false, first_sign_in, 0, cutoff()), Ok(2));
    assert_eq!(client_b.view(&room).unwrap().shown().as_slice(), &expected[..1]);
    assert_eq!(client_b.post(&room, "Hello from Bob", first_sign_in, 0, cutoff()), Ok(3));
    assert_eq!(client_a.sync(&room, false, first_sign_in, 0, cutoff()), Ok(3));
    assert_eq!(client_a.view(&room).unwrap().shown(), expected);
    let deleted = client_a.post(&room, DELETED_BODY, first_sign_in, 0, cutoff()).unwrap();
    assert_eq!(deleted, 4);
    assert_eq!(client_b.sync(&room, false, first_sign_in, 0, cutoff()), Ok(deleted));
    assert_eq!(client_b.view(&room).unwrap().shown().last(), Some(&line(deleted, ALICE, DELETED_BODY)));
    drop(client_a);
    drop(client_b);
    first.stop();

    let mut state = LabInstallation::open(&state_path, pin, wall_ms()).unwrap();
    assert_eq!(state.accounts.session_hashes().len(), 2);
    assert_eq!(state.accounts.person(ALICE).unwrap().last_totp_counter, first_sign_in / STEP_MS);
    assert_eq!(state.accounts.person(BOB).unwrap().last_totp_counter, first_sign_in / STEP_MS);
    assert!(!state.accounts.is_invite_pending(&alice.invitation.bootstrap_public_key(), first_sign_in));
    assert!(!state.accounts.is_invite_pending(&bob.invitation.bootstrap_public_key(), first_sign_in));
    let devices = state.accounts.devices_of(ALICE);
    assert_eq!(devices.len(), 1);
    assert_eq!(state.accounts.devices_of(BOB).len(), 1);
    assert_eq!(state.rooms.delete(&room, ALICE, deleted), Ok(5));
    assert!(state.accounts.revoke_device(ALICE, devices[0].id).unwrap());
    drop(state);

    let reopened = LabInstallation::open(&state_path, pin, wall_ms()).unwrap();
    let second = start(reopened, first_sign_in);
    assert_dark(dial(second.address, client_config(trusted, None).unwrap()), BOB, &bob.code_at(first_sign_in));
    assert_dark(dial(second.address, alice_config), ALICE, &alice.code_at(first_sign_in));
    let used_code = bob.code_at(first_sign_in);
    assert!(matches!(chat(dial(second.address, bob_config.clone()), set_deadline, &bob, &used_code), Err(ChatError::SignInRefused)));
    let fresh = first_sign_in + 2 * STEP_MS;
    second.clock.store(fresh, Ordering::SeqCst);
    let received = RefCell::new(None);
    let stream = ObserveReads { stream: dial(second.address, bob_config), capture: &received };
    let mut replay = chat(stream, |probe, deadline| set_deadline(&mut probe.stream, deadline), &bob, &bob.code_at(fresh)).unwrap();
    // Start observing after sign-in so the probe retains only room-sync application bytes.
    *received.borrow_mut() = Some(Vec::new());
    assert_eq!(replay.sync(&room, false, fresh, 0, cutoff()), Ok(5));
    let room_view = replay.view(&room).unwrap();
    assert_eq!(room_view.cursor(), 5);
    assert_eq!(room_view.shown(), expected);
    drop(replay);
    let wire = received.into_inner().unwrap();
    assert!(!wire.is_empty());
    assert!(!wire.windows(DELETED_BODY.len()).any(|part| part == DELETED_BODY.as_bytes()));
    second.stop();
}
