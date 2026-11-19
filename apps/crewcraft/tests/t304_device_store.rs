//! An enrolled device is saved to disk, survives the process object that enrolled it, and signs in again from the
//! reloaded record. The server here is a scripted loopback peer behind the real admission verifier.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft::device::{NewDevice, StoredDevice};
use crewcraft::device_store::{DeviceStore, MAX_RECORD, StoreError};
use crewcraft::enroll_client::FirstTotpCode;
use crewcraft::enrollment::{Enrollment, EnrollmentEvent};
use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::signed_in::Credentials;
use crewcraft_admission::{Admission, Admitted, Class, admit, server_config};
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_pki::{Authority, Claims};
use crewcraft_proto::bootstrap::{self, BootstrapRequest, BootstrapResponse};
use crewcraft_proto::request::{self, Request, Response};
use crewcraft_proto::{frame, handshake, signin};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};

const WAIT: Duration = Duration::from_secs(5);
const USER: &str = "reader@example.org";
const PASSWORD: &str = "fixture password";
const DEVICE_NAME: &str = "Test Desktop";

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// A private scratch directory, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!("crewcraft-t304-{tag}-{}-{}", std::process::id(), now_ms()));
        Self(path)
    }

    fn store(&self) -> PathBuf {
        self.0.join("devices")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug)]
struct Devices {
    invitation: [u8; 32],
    leaf: Mutex<Option<Vec<u8>>>,
}

impl Admission for Devices {
    fn device_ok(&self, leaf: &[u8]) -> bool {
        self.leaf.lock().unwrap().as_deref() == Some(leaf)
    }

    fn bootstrap_key_live(&self, public_key: &[u8; 32]) -> bool {
        self.invitation == *public_key && self.leaf.lock().unwrap().is_none()
    }
}

struct Server {
    root: Vec<u8>,
    devices: Arc<Devices>,
    config: Arc<ServerConfig>,
    issuer: Option<Authority>,
    code: EnrollmentCode,
}

impl Server {
    fn new(code_byte: u8) -> Self {
        let root = Authority::create_root("Test Root", now_ms()).unwrap();
        let issuer = root.create_issuing("Test Issuer", now_ms()).unwrap();
        let identity = issuer.server_certificate("localhost", now_ms()).unwrap();
        let code = EnrollmentCode::from_bytes([code_byte; 20]);
        let devices = Arc::new(Devices { invitation: code.bootstrap_public_key(), leaf: Mutex::new(None) });
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(root.certificate())).unwrap();
        let chain = identity.chain.into_iter().map(CertificateDer::from).collect();
        let key = PrivatePkcs8KeyDer::from(identity.key_pkcs8).into();
        let config = server_config((chain, key), roots, devices.clone()).unwrap();
        Self { root: root.certificate().to_vec(), devices, config, issuer: Some(issuer), code }
    }

    fn endpoint(&self, address: &str) -> ServerEndpoint {
        ServerEndpoint::new(address, "localhost", RootFingerprint::from_der(&self.root), &self.root).unwrap()
    }

    fn serve(&self, listener: TcpListener, script: impl FnOnce(Admitted) + Send + 'static) -> JoinHandle<()> {
        let (config, devices) = (self.config.clone(), self.devices.clone());
        thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let peer = admit(socket, config, WAIT, &*devices, (now_ms() / 1000) as i64).unwrap();
            peer.stream.sock.set_read_timeout(Some(WAIT)).unwrap();
            peer.stream.sock.set_write_timeout(Some(WAIT)).unwrap();
            script(peer);
        })
    }

    /// Enroll a fresh device through the bootstrap wire and return its record.
    fn enroll(&mut self) -> StoredDevice {
        let (address, server) = self.enrollment_peer();
        let device = NewDevice::generate()
            .unwrap()
            .enroll(&self.endpoint(&address), &self.code, WAIT, DEVICE_NAME, PASSWORD, |_, _| FirstTotpCode::parse("123456".into()))
            .unwrap();
        server.join().unwrap();
        device
    }

    /// A one-shot peer that runs the server side of enrollment and expects the first code `123456`.
    fn enrollment_peer(&mut self) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let mut issuer = self.issuer.take().unwrap();
        let devices = self.devices.clone();
        let server = self.serve(listener, move |mut peer| {
            assert_eq!(peer.class, Class::Bootstrap(devices.invitation));
            let redeem = read(&mut peer.stream);
            let (id, BootstrapRequest::Redeem { device_name, csr, password }) = bootstrap::decode_bootstrap_request(redeem.payload()).unwrap() else {
                panic!("expected Redeem");
            };
            assert_eq!((device_name.as_str(), password.as_str()), (DEVICE_NAME, PASSWORD));
            let uri = setup_uri();
            send(&mut peer.stream, &bootstrap::encode_bootstrap_response(id, &BootstrapResponse::Setup { totp_uri: uri }).unwrap());
            let confirm = read(&mut peer.stream);
            let (id, confirm) = bootstrap::decode_bootstrap_request(confirm.payload()).unwrap();
            assert_eq!(confirm, BootstrapRequest::ConfirmTotp { code: "123456".into() });
            let issued = issuer.issue_device(&csr, &Claims { person: USER, device_id: 1 }, now_ms()).unwrap();
            *devices.leaf.lock().unwrap() = Some(issued.certificate.clone());
            let activated = BootstrapResponse::Activated { certificate: issued.certificate, issuer_certificate: issuer.certificate().to_vec() };
            send(&mut peer.stream, &bootstrap::encode_bootstrap_response(id, &activated).unwrap());
            closed(&mut peer.stream);
        });
        (address, server)
    }
}

/// The authenticator setup link the scripted server sends, built at run time from a fixed test secret.
fn setup_uri() -> String {
    crewcraft_totp::Totp::with_defaults(vec![7; 20]).unwrap().otpauth_uri("CrewCraft", USER)
}

fn read(stream: &mut impl Read) -> frame::ReceivedFrame {
    frame::read_frame(stream, frame::MAX_FRAME).unwrap().unwrap()
}

fn send(stream: &mut impl Write, payload: &[u8]) {
    stream.write_all(&frame::encode(payload).unwrap()).unwrap();
    stream.flush().unwrap();
}

fn closed(stream: &mut impl Read) {
    let mut byte = [0];
    match stream.read(&mut byte) {
        Ok(count) => assert_eq!(count, 0),
        Err(error) => assert!(matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset)),
    }
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    names
}

#[test]
fn an_enrolled_device_signs_in_again_from_its_reloaded_record() {
    let scratch = Scratch::new("reload");
    let mut server = Server::new(0x23);
    let enrolled = server.enroll();
    let leaf = enrolled.certificate().to_vec();
    let debug = format!("{enrolled:?}");
    assert!(debug.contains("StoredDevice") && debug.contains("localhost") && debug.len() < 400, "{debug}");

    // The enrolling process object is gone after this block; only the file remains.
    {
        let store = DeviceStore::open(&scratch.store()).unwrap();
        store.save("work", &enrolled).unwrap();
        drop(enrolled);
        assert_eq!(store.profiles().unwrap(), ["work"]);
        assert_eq!(entries(&scratch.store()), ["work.device"]);
    }

    let reloaded = DeviceStore::open(&scratch.store()).unwrap().load("work").unwrap();
    assert_eq!(reloaded.certificate(), leaf.as_slice());
    let address = reloaded.endpoint().address().to_owned();
    assert_eq!(reloaded.endpoint().server_name(), "localhost");
    assert_eq!(RootFingerprint::from_der(&server.root), reloaded.endpoint().fingerprint());

    // The server comes back at the same address; the reloaded device signs in and posts.
    let listener = TcpListener::bind(&address).unwrap();
    let script = server.serve(listener, move |mut peer| {
        assert_eq!(peer.class, Class::Device);
        assert_eq!(peer.certificate(), leaf.as_slice());
        let request = read(&mut peer.stream);
        let request = signin::decode_request(request.payload()).unwrap();
        assert_eq!((request.email, request.password, request.code), (USER, PASSWORD, "234567"));
        let token = "A".repeat(signin::TOKEN_LEN);
        send(&mut peer.stream, &signin::encode_reply(&signin::Reply::Accepted { token: &token }).unwrap());
        let hello = read(&mut peer.stream);
        assert_eq!(handshake::decode_hello(hello.payload()).unwrap().client, "crewcraft");
        let welcome = handshake::Reply::Welcome { version: 1, features: 0, server: "test server".into() };
        send(&mut peer.stream, &handshake::encode_reply(&welcome).unwrap());
        let post = read(&mut peer.stream);
        let (id, post) = request::decode_request(post.payload()).unwrap();
        assert_eq!(post, Request::Post { room: "lobby".into(), text: "back again".into() });
        send(&mut peer.stream, &request::encode_response(id, &Response::Ok { cursor: 9 }).unwrap());
        closed(&mut peer.stream);
    });
    let credentials = Credentials::new(USER, PASSWORD, "234567").unwrap();
    assert_eq!(format!("{credentials:?}"), "Credentials { .. }");
    let mut session = reloaded.sign_in(&credentials).unwrap();
    assert_eq!(session.post("lobby", "back again"), Ok(9));
    drop(session);
    script.join().unwrap();
}

#[test]
fn saving_again_replaces_the_record_in_one_step() {
    let scratch = Scratch::new("replace");
    let store = DeviceStore::open(&scratch.store()).unwrap();
    let first = Server::new(0x31).enroll();
    let second = Server::new(0x32).enroll();
    assert_ne!(first.certificate(), second.certificate());

    store.save("work", &first).unwrap();
    store.save("work", &second).unwrap();
    assert_eq!(store.load("work").unwrap().certificate(), second.certificate());
    assert_eq!(entries(&scratch.store()), ["work.device"], "no temporary file is left behind");

    // A save interrupted before its rename leaves only a temporary file, which is never read as a record.
    fs::write(scratch.store().join(".work.1.2.3.tmp"), b"partial").unwrap();
    assert_eq!(store.load("work").unwrap().certificate(), second.certificate());
    assert_eq!(store.profiles().unwrap(), ["work"]);

    store.save("home", &first).unwrap();
    assert_eq!(store.profiles().unwrap(), ["home", "work"]);
    assert_eq!(store.remove("home"), Ok(true));
    assert_eq!(store.remove("home"), Ok(false));
    assert_eq!(store.load("home").err(), Some(StoreError::NotFound));
    for bad in ["", "Work", "../work", "a/b", "-work", "work.device"] {
        assert_eq!(store.save(bad, &first), Err(StoreError::InvalidName), "{bad}");
        assert_eq!(store.load(bad).err(), Some(StoreError::InvalidName), "{bad}");
    }
}

#[cfg(unix)]
#[test]
fn unix_records_are_owner_only_and_looser_ones_are_refused() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let scratch = Scratch::new("modes");
    fs::create_dir_all(scratch.store()).unwrap();
    fs::set_permissions(scratch.store(), fs::Permissions::from_mode(0o755)).unwrap();
    let store = DeviceStore::open(&scratch.store()).unwrap();
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&scratch.store()), 0o700, "open makes the directory owner-only");

    store.save("work", &Server::new(0x41).enroll()).unwrap();
    let file = store.path("work").unwrap();
    assert_eq!(mode(&file), 0o600);
    assert!(store.load("work").is_ok());

    for loose in [0o640, 0o604, 0o660, 0o666] {
        fs::set_permissions(&file, fs::Permissions::from_mode(loose)).unwrap();
        assert_eq!(store.load("work").err(), Some(StoreError::Permissions), "{loose:o}");
    }
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(store.load("work").is_ok());

    fs::set_permissions(scratch.store(), fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(store.load("work").err(), Some(StoreError::Permissions), "a group-readable directory");
    fs::set_permissions(scratch.store(), fs::Permissions::from_mode(0o700)).unwrap();

    // A symbolic link in place of the record is refused even when it points at a good record.
    let elsewhere = scratch.0.join("elsewhere.device");
    fs::copy(&file, &elsewhere).unwrap();
    fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&elsewhere, store.path("linked").unwrap()).unwrap();
    assert_eq!(store.load("linked").err(), Some(StoreError::Permissions));
}

/// The record's fields as the format documents them: magic line, seven length-prefixed fields, SHA-256 trailer.
fn fields(record: &[u8]) -> Vec<(usize, usize)> {
    let mut at = b"crewcraft device v1\n".len();
    let mut out = Vec::new();
    for _ in 0..7 {
        let size = u32::from_be_bytes(record[at..at + 4].try_into().unwrap()) as usize;
        out.push((at + 4, size));
        at += 4 + size;
    }
    assert_eq!(at + 32, record.len());
    out
}

fn reseal(record: &mut Vec<u8>) {
    let body = record.len() - 32;
    let digest = Sha256::digest(&record[..body]);
    record.truncate(body);
    record.extend_from_slice(&digest);
}

#[test]
fn corrupt_truncated_mismatched_or_oversized_records_are_refused() {
    let scratch = Scratch::new("corrupt");
    let store = DeviceStore::open(&scratch.store()).unwrap();
    let mine = Server::new(0x51).enroll();
    let other = Server::new(0x52).enroll();
    store.save("other", &other).unwrap();
    let other_record = fs::read(store.path("other").unwrap()).unwrap();
    store.save("work", &mine).unwrap();
    let file = store.path("work").unwrap();
    let good = fs::read(&file).unwrap();
    assert!(good.len() < MAX_RECORD);

    // Overwriting in place keeps the owner-only mode, so only the content is under test.
    let refused = |bytes: &[u8]| {
        fs::write(&file, bytes).unwrap();
        store.load("work").err()
    };
    let mut flipped = good.clone();
    flipped[good.len() / 2] ^= 0x01;
    assert_eq!(refused(&flipped), Some(StoreError::Corrupt), "one changed bit");
    assert_eq!(refused(&good[..good.len() - 1]), Some(StoreError::Corrupt), "truncated");
    assert_eq!(refused(&good[..10]), Some(StoreError::Corrupt), "a few bytes");
    assert_eq!(refused(b""), Some(StoreError::Corrupt), "empty");

    // A well-formed record whose key belongs to another device: the checksum is right, the parts do not fit.
    let (key_at, key_size) = fields(&good)[6];
    let (other_key_at, other_key_size) = fields(&other_record)[6];
    let mut swapped = good[..key_at - 4].to_vec();
    swapped.extend_from_slice(&other_record[other_key_at - 4..other_key_at + other_key_size]);
    swapped.extend_from_slice(&good[key_at + key_size..]);
    reseal(&mut swapped);
    assert_eq!(refused(&swapped), Some(StoreError::Corrupt), "another device's key");

    // A root that does not match the stored fingerprint.
    let (root_at, _) = fields(&good)[3];
    let mut wrong_root = good.clone();
    wrong_root[root_at + 20] ^= 0x01;
    reseal(&mut wrong_root);
    assert_eq!(refused(&wrong_root), Some(StoreError::Corrupt), "root and fingerprint disagree");

    let mut oversized = good.clone();
    oversized.resize(MAX_RECORD + 1, 0);
    assert_eq!(refused(&oversized), Some(StoreError::TooLarge));
    assert_eq!(refused(&vec![0; 4 * MAX_RECORD]), Some(StoreError::TooLarge));

    assert!(refused(&good).is_none(), "the original record still loads");
    assert_eq!(store.load("missing").err(), Some(StoreError::NotFound));
}

#[test]
fn enrollment_runs_on_its_own_thread_and_waits_for_the_first_code() {
    let scratch = Scratch::new("thread");
    let mut server = Server::new(0x61);
    let (address, peer) = server.enrollment_peer();
    let endpoint = server.endpoint(&address);
    let (enrollment, events) = Enrollment::start(endpoint, server.code.clone(), DEVICE_NAME, PASSWORD, || {}).unwrap();
    let EnrollmentEvent::AuthenticatorSetup(setup) = events.recv_timeout(WAIT).unwrap() else { panic!("expected the setup step") };
    assert_eq!(setup.otpauth_uri(), setup_uri());
    assert_eq!(format!("{setup:?}"), "AuthenticatorSetup(..)");
    assert!(!enrollment.confirm("12345"), "five digits are not a code");
    assert!(enrollment.confirm("123456"));
    let EnrollmentEvent::Enrolled(device) = events.recv_timeout(WAIT).unwrap() else { panic!("expected the record") };
    peer.join().unwrap();
    let store = DeviceStore::open(&scratch.store()).unwrap();
    store.save("work", &device).unwrap();
    assert_eq!(store.load("work").unwrap().certificate(), device.certificate());
}
