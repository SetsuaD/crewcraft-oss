//! The client fetches the server's root certificate from an invitation's fingerprint alone, and enrolls with it.
//! Task T232.
#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;
use std::fs;
use std::io;
use std::net::{SocketAddr, TcpListener};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::enroll_client::{EnrollmentRequest, FirstTotpCode};
use crewcraft::lab_client::LabError;
use crewcraft::server_endpoint::{MAX_PRESENTED_CERT, ServerEndpoint, fetch_root};
use crewcraft_bootstrap::Environment;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_enroll::{EnrollmentCode, InvitationLink};
use crewcraft_pki::Authority;
use crewcraft_proto::handshake::ServerSide;
use crewcraft_server::lab_bootstrap::bootstrap_handler;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{BootstrapStream, LabOptions, Timeouts};
use crewcraft_server::server_install;
use crewcraft_server::server_name::ServerName;
use crewcraft_server_core::invites::Invite;
use crewcraft_totp::Totp;
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};

const WAIT: Duration = Duration::from_secs(10);
const PASSWORD: &str = "synthetic root fetch password";
const EMAIL: &str = "pilot@example.org";
const NAME: &str = "chat.example.org";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("crewcraft-t232-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// A TOTP secret drawn for this run, so no secret is written in the test.
fn totp_secret() -> [u8; 20] {
    let mut secret = [0u8; 20];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = (wall_ms() as u8).wrapping_add(index as u8).wrapping_mul(31) | 1;
    }
    secret
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
    /// Every connection that reached the enrollment handler.
    enrollments: Arc<Mutex<usize>>,
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

fn options() -> LabOptions {
    LabOptions {
        address: "127.0.0.1:0".parse().unwrap(),
        capacity: NonZeroUsize::new(4).unwrap(),
        timeouts: Timeouts { handshake: WAIT, sign_in: WAIT, signed_in_frame: WAIT, bootstrap: WAIT },
        protocol: ServerSide { min_version: 1, max_version: 1, features: 0, name: "test server".into() },
    }
}

/// The real network server with one pending invitation, signed for `name`. Returns it and its root.
fn start(directory: &TestDirectory, name: &str, invitation: &EnrollmentCode, secret: [u8; 20], now_ms: u64) -> (Running, Vec<u8>) {
    let mut state = LabInstallation::initialize(&directory.0.join("state"), now_ms).unwrap();
    let root_der = state.issuer.root_certificate().to_vec();
    let invite = Invite { email: EMAIL.into(), bootstrap_pub: invitation.bootstrap_public_key(), expires_ms: now_ms + 300_000 };
    state.accounts.issue_invite(invite, now_ms).unwrap();
    let clock = Arc::new(AtomicU64::new(now_ms));
    let server_clock = clock.clone();
    let name = ServerName::parse(name).unwrap();
    let server = LabRuntime::bind_network(state, options(), &name, move || server_clock.load(Ordering::SeqCst)).unwrap();
    let address = server.local_addr().unwrap();
    let environment = TestEnvironment { clock, secrets: VecDeque::from([secret]) };
    let enrollments = Arc::new(Mutex::new(0));
    let seen = enrollments.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let thread = thread::spawn(move || {
        server.serve(&shutdown, move |accounts, issuer| {
            let inner = bootstrap_handler(accounts, issuer, environment);
            Ok(move |key: [u8; 32], stream: &mut BootstrapStream| {
                *seen.lock().unwrap() += 1;
                inner(key, stream);
            })
        })
    });
    (Running { address, enrollments, stop, thread: Some(thread) }, root_der)
}

/// A server that presents exactly `chain` (leaf first) for `key`, answering one connection.
fn presenting(chain: Vec<Vec<u8>>, key: Vec<u8>, client_root: &[u8]) -> (SocketAddr, JoinHandle<()>) {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(client_root.to_vec())).unwrap();
    let identity = (chain.into_iter().map(CertificateDer::from).collect(), PrivatePkcs8KeyDer::from(key).into());
    let config = crewcraft_tls::server_config(identity, roots).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let thread = thread::spawn(move || {
        if let Ok((tcp, _)) = listener.accept() {
            // The fetching client presents no certificate, so this handshake never completes.
            assert!(crewcraft_tls::accept(tcp, config, WAIT).is_err());
        }
    });
    (address, thread)
}

#[test]
fn the_pinned_root_is_fetched_and_the_endpoint_built_from_it_enrolls() {
    let directory = TestDirectory::new();
    let invitation = EnrollmentCode::from_bytes([5; 20]);
    let secret = totp_secret();
    let now = wall_ms();
    let (server, root_der) = start(&directory, NAME, &invitation, secret, now);
    let address = server.address.to_string();
    let pin = RootFingerprint::from_der(&root_der);

    let started = Instant::now();
    let fetched = fetch_root(&address, NAME, pin, WAIT).unwrap();
    assert_eq!(fetched, root_der);
    assert!(started.elapsed() < WAIT);
    // Fetching sent no application bytes: nothing reached the enrollment handler.
    assert_eq!(*server.enrollments.lock().unwrap(), 0);

    let endpoint = ServerEndpoint::new(&address, NAME, pin, &fetched).unwrap();
    assert_eq!(ServerEndpoint::fetch(&address, NAME, pin, WAIT).unwrap().root_der(), &root_der[..]);
    enroll(&endpoint, &invitation, secret, now);
    assert_eq!(*server.enrollments.lock().unwrap(), 1);
}

fn enroll(endpoint: &ServerEndpoint, invitation: &EnrollmentCode, secret: [u8; 20], now: u64) {
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
    let expected_spki = key.subject_public_key_info();
    let request =
        EnrollmentRequest { device_name: "Synthetic Test Device", csr: csr.der().as_ref(), password: PASSWORD, expected_spki: &expected_spki };
    let code = Totp::with_defaults(secret.to_vec()).unwrap().generate(now / 1000);
    let chain = endpoint.open_bootstrap(invitation, WAIT).unwrap().enroll(request, |_, _| FirstTotpCode::parse(code)).unwrap();
    assert!(!chain.leaf.is_empty() && !chain.issuer.is_empty());
}

#[test]
fn the_link_the_server_prints_is_all_a_client_needs() {
    let directory = TestDirectory::new();
    let invitation = EnrollmentCode::from_bytes([9; 20]);
    let secret = totp_secret();
    let now = wall_ms();
    let (server, root_der) = start(&directory, "127.0.0.1", &invitation, secret, now);
    let pin_bytes: [u8; 32] = Sha256::digest(&root_der).into();
    let text = server_install::enrollment_link(&format!("127.0.0.1:{}", server.address.port()), &invitation.to_display(), &pin_bytes);
    let link = InvitationLink::parse(&text).unwrap();
    let endpoint = ServerEndpoint::from_invitation(&link, WAIT).unwrap();
    assert_eq!(endpoint.root_der(), &root_der[..]);
    assert_eq!(endpoint.server_name(), "127.0.0.1");
    enroll(&endpoint, link.code(), secret, now);
    assert_eq!(*server.enrollments.lock().unwrap(), 1);
}

#[test]
fn a_wrong_pin_a_wrong_name_or_a_bad_address_is_refused() {
    let directory = TestDirectory::new();
    let invitation = EnrollmentCode::from_bytes([6; 20]);
    let (server, root_der) = start(&directory, NAME, &invitation, totp_secret(), wall_ms());
    let address = server.address.to_string();
    let pin = RootFingerprint::from_der(&root_der);

    let mut other = root_der.clone();
    let last = other.len() - 1;
    other[last] ^= 1;
    assert_eq!(fetch_root(&address, NAME, RootFingerprint::from_der(&other), WAIT), Err(LabError::Trust));
    assert_eq!(fetch_root(&address, "other.example.org", pin, WAIT), Err(LabError::Trust));
    assert_eq!(fetch_root(&address, "", pin, WAIT), Err(LabError::Trust));
    assert_eq!(fetch_root("chat.example.org", NAME, pin, WAIT), Err(LabError::Address));
    assert_eq!(fetch_root("0.0.0.0:443", NAME, pin, WAIT), Err(LabError::Address));
    assert!(ServerEndpoint::fetch(&address, "other.example.org", pin, WAIT).is_err());
    assert_eq!(*server.enrollments.lock().unwrap(), 0);
}

#[test]
fn a_chain_without_the_root_or_that_does_not_verify_is_refused() {
    let now = wall_ms();
    let root = Authority::create_root("Synthetic Root", now).unwrap();
    let issuing = root.create_issuing("Synthetic Issuing", now).unwrap();
    let pin = RootFingerprint::from_der(root.certificate());

    // The chain the server certificate comes with: leaf and issuing authority, no root.
    let identity = issuing.server_certificate(NAME, now).unwrap();
    let (address, thread) = presenting(identity.chain.clone(), identity.key_pkcs8.clone(), root.certificate());
    assert_eq!(fetch_root(&address.to_string(), NAME, pin, WAIT), Err(LabError::Trust));
    thread.join().unwrap();

    // With the root appended the same server is accepted: the control for the cases below.
    let mut full = identity.chain.clone();
    full.push(root.certificate().to_vec());
    let (address, thread) = presenting(full, identity.key_pkcs8.clone(), root.certificate());
    assert_eq!(fetch_root(&address.to_string(), NAME, pin, WAIT).unwrap(), root.certificate());
    thread.join().unwrap();

    // The pinned root at the end of a chain from another authority: the fingerprint matches, the chain does not.
    let stranger_root = Authority::create_root("Other Root", now).unwrap();
    let stranger = stranger_root.create_issuing("Other Issuing", now).unwrap().server_certificate(NAME, now).unwrap();
    let mut forged = stranger.chain.clone();
    forged.push(root.certificate().to_vec());
    let (address, thread) = presenting(forged, stranger.key_pkcs8, root.certificate());
    assert_eq!(fetch_root(&address.to_string(), NAME, pin, WAIT), Err(LabError::Trust));
    thread.join().unwrap();

    // An oversized certificate in the chain, even one that matches its own pin.
    let oversized = vec![0x30; MAX_PRESENTED_CERT + 1];
    let mut padded = identity.chain.clone();
    padded.push(oversized.clone());
    let (address, thread) = presenting(padded, identity.key_pkcs8.clone(), root.certificate());
    assert_eq!(fetch_root(&address.to_string(), NAME, RootFingerprint::from_der(&oversized), WAIT), Err(LabError::Trust));
    thread.join().unwrap();

    // A leaf alone, pinned by its own fingerprint, is not a chain to a root.
    let (address, thread) = presenting(vec![identity.chain[0].clone()], identity.key_pkcs8, root.certificate());
    assert_eq!(fetch_root(&address.to_string(), NAME, RootFingerprint::from_der(&identity.chain[0]), WAIT), Err(LabError::Trust));
    thread.join().unwrap();
}
