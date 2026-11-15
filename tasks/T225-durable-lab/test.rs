//! Real mTLS chat and full lab-state reopen. Synthetic devices are activated directly in the account store.
#![allow(clippy::unwrap_used)]

use std::cell::RefCell;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::chat_session::{ChatError, ChatSession};
use crewcraft_accounts::password;
use crewcraft_accounts::throttle::Throttle;
use crewcraft_admission::Admission;
use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_pki::{Authority, Claims};
use crewcraft_proto::frame;
use crewcraft_proto::handshake::{Hello, ServerSide};
use crewcraft_proto::signin::{SignIn, encode_request};
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_server::{LabOptions, LabServer, Timeouts};
use crewcraft_server::stored_device_auth::StoredDeviceAuth;
use crewcraft_server_core::account_store::{AccountStore, Activation, FirstDevice};
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::room::Role;
use crewcraft_tls::{DeadlineSocket, Identity, client_config, connect};
use crewcraft_totp::Totp;
use rcgen::{CertificateParams, KeyPair};
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

fn identity(chain: Vec<Vec<u8>>, key: Vec<u8>) -> Identity {
    (chain.into_iter().map(CertificateDer::from).collect(), PrivatePkcs8KeyDer::from(key).into())
}

fn roots(root_der: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root_der)).unwrap();
    roots
}

struct Person {
    email: &'static str,
    secret: [u8; 20],
    invitation: [u8; 32],
}

impl Person {
    fn totp(&self) -> Totp {
        Totp::with_defaults(self.secret.to_vec()).unwrap()
    }

    fn code_at(&self, now_ms: u64) -> String {
        self.totp().generate(now_ms / 1000)
    }

    fn activate(&self, store: &mut AccountStore, issuer: &mut Authority, trusted: RootCertStore, phc: &str, now_ms: u64) -> (u64, Arc<ClientConfig>) {
        let invite = Invite { email: self.email.into(), bootstrap_pub: self.invitation, expires_ms: now_ms + 300_000 };
        store.issue_invite(invite, now_ms).unwrap();
        let (person, device_id) = store.preview_activation(&self.invitation, now_ms).unwrap();
        assert_eq!(person, self.email);
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
        let issued = issuer.issue_device(csr.der(), &Claims { person: &person, device_id }, now_ms).unwrap();
        let setup_code = self.code_at(now_ms);
        let counter = self.totp().verify(&setup_code, now_ms / 1000, 0, None).unwrap();
        let activation = Activation {
            bootstrap_pub: self.invitation,
            device_name: "Synthetic Test Device",
            certificate: &issued.certificate,
            spki_sha256: issued.key_id,
            counter,
            first_device: Some(FirstDevice { password_phc: Some(phc), totp_secret: &self.secret }),
            expected_device_id: Some(device_id),
        };
        assert_eq!(store.activate(activation, now_ms).unwrap(), device_id);
        assert!(!store.is_invite_pending(&self.invitation, now_ms));
        let config = client_config(trusted, Some(identity(issued.chain, key.serialize_der()))).unwrap();
        (device_id, config)
    }
}

#[derive(Debug)]
struct StoreAdmission {
    accounts: Arc<Mutex<AccountStore>>,
    now: Arc<AtomicU64>,
}

impl Admission for StoreAdmission {
    fn device_ok(&self, leaf_der: &[u8]) -> bool {
        self.accounts.lock().is_ok_and(|mut store| store.admit(leaf_der, self.now.load(Ordering::SeqCst)).is_ok())
    }

    fn bootstrap_key_live(&self, key: &[u8; 32]) -> bool {
        self.accounts.lock().is_ok_and(|store| store.is_invite_pending(key, self.now.load(Ordering::SeqCst)))
    }
}

struct Running {
    address: SocketAddr,
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

fn start(state: LabInstallation, now: Arc<AtomicU64>) -> Running {
    let LabInstallation { ownership, issuer, accounts, rooms } = state;
    let (root_der, issuer) = issuer.into_parts();
    start_parts(ownership, root_der, issuer, accounts, rooms, now)
}

fn start_parts(
    ownership: crewcraft_server::lab_state::LabState,
    root_der: Vec<u8>,
    issuer: Authority,
    accounts: AccountStore,
    rooms: crewcraft_server_core::durable::DurableServer,
    now: Arc<AtomicU64>,
) -> Running {
    let server_cert = issuer.server_certificate("localhost", wall_ms()).unwrap();
    let accounts = Arc::new(Mutex::new(accounts));
    let throttle = Arc::new(Mutex::new(Throttle::new()));
    let admission = Arc::new(StoreAdmission { accounts: accounts.clone(), now: now.clone() });
    let options = LabOptions {
        address: "127.0.0.1:0".parse().unwrap(),
        capacity: NonZeroUsize::new(4).unwrap(),
        timeouts: Timeouts { handshake: WAIT, sign_in: WAIT, signed_in_frame: WAIT, bootstrap: WAIT },
        protocol: ServerSide { min_version: 1, max_version: 1, features: 0, name: "test server".into() },
    };
    let server = LabServer::bind(options, identity(server_cert.chain, server_cert.key_pkcs8), roots(&root_der), admission, rooms).unwrap();
    let address = server.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let thread = thread::spawn(move || {
        let result = server.serve(
            &shutdown,
            move || now.load(Ordering::SeqCst),
            move |leaf, at| StoredDeviceAuth::bind(accounts.clone(), throttle.clone(), leaf, at),
            |_, _| {},
        );
        drop(issuer);
        drop(ownership);
        result
    });
    Running { address, stop, thread: Some(thread) }
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
fn both_clients_chat_then_reopen_every_server_store_and_replay() {
    let directory = TestDirectory::new();
    let state_path = directory.0.join("state");
    let setup_time = wall_ms();
    let state = LabInstallation::initialize(&state_path, setup_time).unwrap();
    let pin = state.issuer.root_fingerprint();
    let LabInstallation { ownership, issuer, mut accounts, mut rooms } = state;
    let (root_der, mut issuer) = issuer.into_parts();
    let trusted = roots(&root_der);
    let alice = Person { email: ALICE, secret: ALICE_SECRET, invitation: [1; 32] };
    let bob = Person { email: BOB, secret: BOB_SECRET, invitation: [2; 32] };
    let phc = password::hash(PASSWORD).unwrap();
    let (alice_id, alice_config) = alice.activate(&mut accounts, &mut issuer, trusted.clone(), &phc, setup_time);
    let (_, bob_config) = bob.activate(&mut accounts, &mut issuer, trusted.clone(), &phc, setup_time);
    let room = rooms.create_room(ALICE, "General").unwrap();
    assert_eq!(rooms.add_member(&room, ALICE, BOB, Role::Member), Ok(1));

    // Pick a synthetic sign-in time with distinct adjacent codes so the replay assertion cannot hit a collision.
    let first_sign_in = (1..=8)
        .map(|offset| setup_time + offset * STEP_MS)
        .find(|&at| {
            let bob_code = bob.code_at(at);
            alice.code_at(at) != alice.code_at(at - STEP_MS) && bob_code != bob.code_at(at - STEP_MS) && bob_code != bob.code_at(at + STEP_MS)
        })
        .unwrap();
    let clock = Arc::new(AtomicU64::new(first_sign_in));
    let first = start_parts(ownership, root_der, issuer, accounts, rooms, clock.clone());
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
    assert_eq!(state.rooms.delete(&room, ALICE, deleted), Ok(5));
    assert!(state.accounts.revoke_device(ALICE, alice_id).unwrap());
    drop(state);

    let reopened = LabInstallation::open(&state_path, pin, wall_ms()).unwrap();
    let second = start(reopened, clock.clone());
    assert_dark(dial(second.address, client_config(trusted, None).unwrap()), BOB, &bob.code_at(first_sign_in));
    assert_dark(dial(second.address, alice_config), ALICE, &alice.code_at(first_sign_in));
    let used_code = bob.code_at(first_sign_in);
    assert!(matches!(chat(dial(second.address, bob_config.clone()), set_deadline, &bob, &used_code), Err(ChatError::SignInRefused)));
    let fresh = first_sign_in + 2 * STEP_MS;
    clock.store(fresh, Ordering::SeqCst);
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
