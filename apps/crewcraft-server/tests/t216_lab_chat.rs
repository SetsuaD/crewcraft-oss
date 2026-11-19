//! Synthetic interoperability test. The listener and journal restart while test-only PKI and accounts stay in memory.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::chat_session::{ChatError, ChatSession};
use crewcraft_accounts::password;
use crewcraft_accounts::sessions::Sessions;
use crewcraft_accounts::sign_in::{Credentials, OwnAccount, verify_own};
use crewcraft_accounts::totp_guard::TotpGuard;
use crewcraft_admission::{Admission, Class, admit, server_config};
use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_pki::{Authority, Claims, Issued, LeafInfo, Status};
use crewcraft_proto::frame;
use crewcraft_proto::handshake::{Hello, ServerSide};
use crewcraft_proto::signin::{SignIn, encode_request};
use crewcraft_server::device_session::{AuthError, CommittedSignIn, DeviceAuth, serve};
use crewcraft_server::listener::Listener;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::room::Role;
use crewcraft_tls::{DeadlineSocket, Identity, client_config, connect};
use crewcraft_totp::Totp;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConnection, RootCertStore, StreamOwned};

const WAIT: Duration = Duration::from_secs(10);
const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";
const ALICE_SECRET: [u8; 20] = [17; 20];
const BOB_SECRET: [u8; 20] = [23; 20];
const PASSWORD: &str = "synthetic lab password";

struct Fixture {
    issuer: Mutex<Authority>,
    accounts: Mutex<FixtureAccounts>,
    now_ms: AtomicU64,
}

struct FixtureAccounts {
    password_hash: String,
    totp: TotpGuard,
    sessions: Sessions,
    token_sequence: u64,
}

impl std::fmt::Debug for Fixture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fixture(..)")
    }
}

fn current_time() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

fn device_leaf(issuer: &Authority, certificate: &[u8], now_ms: u64) -> Option<LeafInfo> {
    match issuer.status(certificate, now_ms) {
        Ok(Status::Good(info)) => Some(info),
        _ => None,
    }
}

impl Fixture {
    fn now(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }

    fn device(&self, certificate: &[u8]) -> Option<LeafInfo> {
        let issuer = self.issuer.lock().ok()?;
        device_leaf(&issuer, certificate, self.now())
    }
}

impl Admission for Fixture {
    fn device_ok(&self, certificate: &[u8]) -> bool {
        self.device(certificate).is_some()
    }

    fn bootstrap_key_live(&self, _: &[u8; 32]) -> bool {
        false
    }
}

struct ConnectionAuth<'a> {
    fixture: &'a Fixture,
    certificate: Vec<u8>,
    leaf: LeafInfo,
}

impl DeviceAuth for ConnectionAuth<'_> {
    type Session = String;

    fn sign_in(&self, input: SignIn<'_>, now_ms: u64) -> Result<Option<CommittedSignIn<Self::Session>>, AuthError> {
        let issuer = self.fixture.issuer.lock().map_err(|_| AuthError::Unavailable)?;
        let Some(leaf) = device_leaf(&issuer, &self.certificate, now_ms).filter(|leaf| *leaf == self.leaf) else {
            return Err(AuthError::UnauthorizedDevice);
        };
        let mut accounts = self.fixture.accounts.lock().map_err(|_| AuthError::Unavailable)?;
        let (totp, last_totp_counter) = accounts.totp.credential(&leaf.person).ok_or(AuthError::UnauthorizedDevice)?;
        let account = OwnAccount { email: &leaf.person, password_hash: &accounts.password_hash, totp, last_totp_counter };
        let credentials = Credentials { email: input.email, password: input.password, code: input.code };
        let Some(verified) = verify_own(Some(&leaf.person), Some(&account), credentials, now_ms / 1000) else {
            return Ok(None);
        };
        accounts.totp.record_counter(&leaf.person, verified.accepted_counter).map_err(|_| AuthError::Unavailable)?;

        // Deterministic tokens are suitable for these tests only. Production session issuance is a separate adapter.
        accounts.token_sequence += 1;
        let mut token_bytes = [0u8; 32];
        token_bytes[..8].copy_from_slice(&accounts.token_sequence.to_be_bytes());
        let token = accounts.sessions.create(token_bytes, &leaf.person, &leaf.device_id.to_string(), now_ms);
        Ok(Some(CommittedSignIn { user: leaf.person, token: token.clone(), session: token }))
    }

    fn with_live_session<T>(&self, token: &Self::Session, now_ms: u64, action: impl FnOnce() -> T) -> Result<Option<T>, AuthError> {
        let issuer = self.fixture.issuer.lock().map_err(|_| AuthError::Unavailable)?;
        let Some(leaf) = device_leaf(&issuer, &self.certificate, now_ms).filter(|leaf| *leaf == self.leaf) else {
            return Ok(None);
        };
        let mut accounts = self.fixture.accounts.lock().map_err(|_| AuthError::Unavailable)?;
        Ok(accounts.sessions.validate_for(token, &leaf.person, &leaf.device_id.to_string(), now_ms).map(|_| action()))
    }
}

fn identity(chain: &[Vec<u8>], key: Vec<u8>) -> Identity {
    (chain.iter().cloned().map(CertificateDer::from).collect(), PrivatePkcs8KeyDer::from(key).into())
}

fn device(issuer: &mut Authority, person: &str, device_id: u64, now_ms: u64) -> (KeyPair, Issued) {
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
    let issued = issuer.issue_device(csr.der(), &Claims { person, device_id }, now_ms).unwrap();
    (key, issued)
}

struct Lab {
    roots: RootCertStore,
    fixture: Arc<Fixture>,
    alice: Arc<rustls::ClientConfig>,
    bob: Arc<rustls::ClientConfig>,
}

fn setup() -> Lab {
    let now_ms = current_time().as_millis() as u64;
    let root = Authority::create_root("Lab Root", now_ms).unwrap();
    let mut issuer = root.create_issuing("Lab Issuing", now_ms).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root.certificate().to_vec())).unwrap();

    let (alice_key, alice_cert) = device(&mut issuer, ALICE, 1, now_ms);
    let (bob_key, bob_cert) = device(&mut issuer, BOB, 2, now_ms);
    let alice = client_config(roots.clone(), Some(identity(&alice_cert.chain, alice_key.serialize_der()))).unwrap();
    let bob = client_config(roots.clone(), Some(identity(&bob_cert.chain, bob_key.serialize_der()))).unwrap();

    let mut totp = TotpGuard::new();
    assert!(totp.enroll(ALICE, ALICE_SECRET));
    assert!(totp.enroll(BOB, BOB_SECRET));
    let password_hash = password::hash_with_salt(PASSWORD, b"lab-fixture-salt").unwrap();
    let accounts = FixtureAccounts { password_hash, totp, sessions: Sessions::new(), token_sequence: 0 };
    let fixture = Arc::new(Fixture { issuer: Mutex::new(issuer), accounts: Mutex::new(accounts), now_ms: AtomicU64::new(now_ms) });
    Lab { roots, fixture, alice, bob }
}

struct Running {
    address: SocketAddr,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<()>>>,
    admission_failures: Receiver<()>,
}

impl Running {
    fn stop(mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap().unwrap();
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn start(lab: &Lab, rooms: DurableServer) -> Running {
    let fixture = Arc::clone(&lab.fixture);
    let wall_ms = current_time().as_millis() as u64;
    let identity_record = fixture.issuer.lock().unwrap().server_certificate("localhost", wall_ms).unwrap();
    let config = server_config(identity(&identity_record.chain, identity_record.key_pkcs8), lab.roots.clone(), fixture.clone()).unwrap();
    let rooms = Mutex::new(rooms);
    let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), NonZeroUsize::new(4).unwrap()).unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&shutdown);
    let (rejected, admission_failures) = mpsc::channel();

    let worker = thread::spawn(move || {
        listener.serve(&stop, move |tcp| {
            let now_seconds = (fixture.now() / 1000) as i64;
            let Ok(admitted) = admit(tcp, Arc::clone(&config), WAIT, &*fixture, now_seconds) else {
                let _ = rejected.send(());
                return;
            };
            if admitted.class != Class::Device || admitted.recheck(&*fixture, now_seconds).is_err() {
                return;
            }
            let certificate = admitted.certificate().to_vec();
            let Some(leaf) = fixture.device(&certificate) else {
                return;
            };
            let auth = ConnectionAuth { fixture: &fixture, certificate, leaf };
            let mut stream = StreamOwned::new(admitted.stream.conn, DeadlineSocket::new(admitted.stream.sock, cutoff()));
            let server_side = ServerSide { min_version: 1, max_version: 1, features: 0, name: "lab server".into() };
            // Dropping a test client can end with EOF instead of a close-notify. Assertions below use client replies.
            let _ = serve(
                &mut stream,
                &auth,
                &rooms,
                server_side,
                |stream| {
                    stream.sock.set_deadline(cutoff());
                    Ok(())
                },
                || fixture.now(),
            );
        })
    });

    Running { address, shutdown, worker: Some(worker), admission_failures }
}

type ClientStream = StreamOwned<ClientConnection, DeadlineSocket>;
type SetDeadline = fn(&mut ClientStream, Instant);

fn cutoff() -> Instant {
    Instant::now() + WAIT
}

fn dial(address: SocketAddr, config: Arc<rustls::ClientConfig>) -> ClientStream {
    let tcp = TcpStream::connect_timeout(&address, WAIT).unwrap();
    let stream = connect(tcp, config, ServerName::try_from("localhost").unwrap()).unwrap();
    StreamOwned::new(stream.conn, DeadlineSocket::new(stream.sock, cutoff()))
}

fn set_client_deadline(stream: &mut ClientStream, deadline: Instant) {
    stream.sock.set_deadline(deadline);
}

fn chat(
    server: &Running,
    config: Arc<rustls::ClientConfig>,
    email: &str,
    secret: [u8; 20],
    lab: &Lab,
) -> Result<ChatSession<ClientStream, SetDeadline>, ChatError> {
    let code = Totp::with_defaults(secret.to_vec()).unwrap().generate(lab.fixture.now() / 1000);
    let request = SignIn { email, password: PASSWORD, code: &code };
    let hello = Hello { min_version: 1, max_version: 1, features: 0, client: "lab client".into() };
    ChatSession::connect(dial(server.address, config), set_client_deadline as SetDeadline, &request, hello, Settings::new(email), WAIT, cutoff())
}

fn assert_certless_is_dark(server: &Running, lab: &Lab) {
    let mut client = dial(server.address, client_config(lab.roots.clone(), None).unwrap());
    let sign_in = SignIn { email: ALICE, password: PASSWORD, code: "000001" };
    let bytes = frame::encode(&encode_request(&sign_in).unwrap()).unwrap();
    let _ = client.write_all(&bytes);
    let _ = client.flush();
    let mut byte = [0];
    match client.read(&mut byte) {
        Ok(read) => assert_eq!(read, 0),
        Err(error) => assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe
        )),
    }
    server.admission_failures.recv_timeout(WAIT).unwrap();
}

struct JournalFile(PathBuf);

impl JournalFile {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("crewcraft-t216-{}-{}.journal", std::process::id(), current_time().as_nanos())))
    }

    fn open(&self) -> DurableServer {
        DurableServer::open(&self.0).unwrap()
    }
}

impl Drop for JournalFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn message(cursor: u64, author: &str, html: &str) -> Shown {
    Shown::Line(Line { cursor, author: author.into(), html: html.into(), edited: false })
}

#[test]
fn two_certified_clients_exchange_and_replay_messages_over_a_restarted_lab_listener() {
    let journal = JournalFile::new();
    let lab = setup();
    let mut rooms = journal.open();
    let room = rooms.create_room(ALICE, "General").unwrap();
    assert_eq!(rooms.add_member(&room, ALICE, BOB, Role::Member), Ok(1));
    let first = start(&lab, rooms);
    assert_certless_is_dark(&first, &lab);
    assert!(matches!(chat(&first, lab.alice.clone(), BOB, BOB_SECRET, &lab), Err(ChatError::SignInRefused)));

    let mut alice = chat(&first, lab.alice.clone(), ALICE, ALICE_SECRET, &lab).unwrap();
    let mut bob = chat(&first, lab.bob.clone(), BOB, BOB_SECRET, &lab).unwrap();
    let first_message = message(2, ALICE, "Hello from Alice");
    let second_message = message(3, BOB, "Hello from Bob");
    let now_ms = lab.fixture.now();

    assert_eq!(alice.post(&room, "Hello from Alice", now_ms, 0, cutoff()), Ok(2));
    assert_eq!(bob.sync(&room, false, now_ms, 0, cutoff()), Ok(2));
    assert_eq!(bob.view(&room).unwrap().shown().as_slice(), std::slice::from_ref(&first_message));
    assert_eq!(bob.post(&room, "Hello from Bob", now_ms, 0, cutoff()), Ok(3));
    assert_eq!(alice.sync(&room, false, now_ms, 0, cutoff()), Ok(3));
    let expected = [first_message, second_message];
    assert_eq!(alice.view(&room).unwrap().shown(), expected);
    drop(alice);
    drop(bob);
    first.stop();

    // Advance the fixture clock so reconnecting uses a new code rather than replaying the accepted counter.
    lab.fixture.now_ms.fetch_add(60_000, Ordering::SeqCst);
    let second = start(&lab, journal.open());
    let mut replay = chat(&second, lab.bob.clone(), BOB, BOB_SECRET, &lab).unwrap();
    assert_eq!(replay.sync(&room, false, lab.fixture.now(), 0, cutoff()), Ok(3));
    assert_eq!(replay.view(&room).unwrap().shown(), expected);
    drop(replay);
    second.stop();
}
