//! T403: a device key that lives in a hardware key store (the Android Keystore on a phone; `MemoryKeys` here). The
//! key is made inside the store, signs the enrollment request and every TLS client handshake there, and the saved
//! record only names it.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::app::{Controller, Join, PROFILE, Wake, no_key_store, store_problem};
use crewcraft::device::{DeviceError, NewDevice};
use crewcraft::device_store::{DeviceStore, StoreError};
use crewcraft::hardware_key::{
    HardwareKey, HardwareKeyError, HardwareKeys, KeyLocation, MemoryKeys, RequestSigner, TlsSigningKey, new_alias, p256_point, valid_alias,
};
use crewcraft::key_vault::MemoryVault;
use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::signed_in::Credentials;
use crewcraft::worker::WorkerConfig;
use crewcraft_admission::{Admission, Admitted, admit, server_config};
use crewcraft_desktop_ui::{Action, Update};
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_pki::{Authority, Claims};
use crewcraft_proto::bootstrap::{self, BootstrapRequest, BootstrapResponse};
use crewcraft_proto::frame;
use rustls::SignatureScheme;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::SigningKey;
use rustls::{RootCertStore, ServerConfig};
use zeroize::Zeroizing;

const WAIT: Duration = Duration::from_secs(5);
const USER: &str = "phone@example.org";
const PASSWORD: &str = "fixture password";

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        Self(std::env::temp_dir().join(format!("crewcraft-t403-{tag}-{}-{}", std::process::id(), now_ms())))
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

/// A scripted server that enrolls one device (expecting the first code `123456`), then can admit that device again.
struct Server {
    root: Vec<u8>,
    address: String,
    code: EnrollmentCode,
    config: Arc<ServerConfig>,
    devices: Arc<Devices>,
    script: Option<JoinHandle<()>>,
}

impl Server {
    fn start() -> Self {
        let root = Authority::create_root("Test Root", now_ms()).unwrap();
        let mut issuer = root.create_issuing("Test Issuer", now_ms()).unwrap();
        let identity = issuer.server_certificate("localhost", now_ms()).unwrap();
        let code = EnrollmentCode::from_bytes([0x43; 20]);
        let devices = Arc::new(Devices { invitation: code.bootstrap_public_key(), leaf: Mutex::new(None) });
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(root.certificate())).unwrap();
        let chain = identity.chain.into_iter().map(CertificateDer::from).collect();
        let key = PrivatePkcs8KeyDer::from(identity.key_pkcs8).into();
        let config: Arc<ServerConfig> = server_config((chain, key), roots, devices.clone()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (script_config, script_devices) = (config.clone(), devices.clone());
        let script = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut peer: Admitted = admit(socket, script_config, WAIT, &*script_devices, (now_ms() / 1000) as i64).unwrap();
            peer.stream.sock.set_read_timeout(Some(WAIT)).unwrap();
            let (id, BootstrapRequest::Redeem { csr, .. }) = bootstrap::decode_bootstrap_request(read(&mut peer.stream).payload()).unwrap() else {
                panic!("expected Redeem");
            };
            send(&mut peer.stream, &bootstrap::encode_bootstrap_response(id, &BootstrapResponse::Setup { totp_uri: setup_uri() }).unwrap());
            let (id, _confirm) = bootstrap::decode_bootstrap_request(read(&mut peer.stream).payload()).unwrap();
            // Issuing checks the request's signature, which the key store made.
            let issued = issuer.issue_device(&csr, &Claims { person: USER, device_id: 1 }, now_ms()).unwrap();
            *script_devices.leaf.lock().unwrap() = Some(issued.certificate.clone());
            let activated = BootstrapResponse::Activated { certificate: issued.certificate, issuer_certificate: issuer.certificate().to_vec() };
            send(&mut peer.stream, &bootstrap::encode_bootstrap_response(id, &activated).unwrap());
            let mut byte = [0];
            let _ = peer.stream.read(&mut byte);
        });
        Self { root: root.certificate().to_vec(), address, code, config, devices, script: Some(script) }
    }

    fn endpoint(&self, address: &str) -> ServerEndpoint {
        ServerEndpoint::new(address, "localhost", RootFingerprint::from_der(&self.root), &self.root).unwrap()
    }

    /// A `Join` that ignores the link text and returns this server's endpoint and invitation code.
    fn join(&self) -> Join {
        let (address, root, code) = (self.address.clone(), self.root.clone(), self.code.clone());
        Box::new(move |_link: &str| {
            let endpoint = ServerEndpoint::new(&address, "localhost", RootFingerprint::from_der(&root), &root).map_err(|_| "endpoint".to_owned())?;
            Ok((endpoint, code.clone()))
        })
    }

    /// Admit one device connection on a new port, returning that port's address and the presented certificate.
    fn admit_once(&self) -> (String, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (config, devices) = (self.config.clone(), self.devices.clone());
        let handle = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let peer = admit(socket, config, WAIT, &*devices, (now_ms() / 1000) as i64).unwrap();
            peer.certificate().to_vec()
        });
        (address, handle)
    }
}

fn setup_uri() -> String {
    crewcraft_totp::Totp::with_defaults(vec![9; 20]).unwrap().otpauth_uri("CrewCraft", USER)
}

fn read(stream: &mut impl Read) -> frame::ReceivedFrame {
    frame::read_frame(stream, frame::MAX_FRAME).unwrap().unwrap()
}

fn send(stream: &mut impl Write, payload: &[u8]) {
    stream.write_all(&frame::encode(payload).unwrap()).unwrap();
    stream.flush().unwrap();
}

fn no_wake() -> Wake {
    Arc::new(|| {})
}

fn refused_join() -> Join {
    Box::new(|_link: &str| Err("That is not a CrewCraft invitation link.".to_owned()))
}

fn quick() -> WorkerConfig {
    WorkerConfig { poll_interval: Duration::from_millis(50), first_retry: Duration::from_millis(50), max_retry: Duration::from_millis(200) }
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

fn enroll_action() -> Action {
    Action::Enroll { link: Zeroizing::new("crewcraft://enroll?ignored".to_owned()), password: Zeroizing::new(PASSWORD.to_owned()) }
}

fn phone(dir: &Path, keys: &MemoryKeys, join: Join) -> (Controller, Vec<Update>) {
    Controller::start_with_hardware_keys(Some(dir.to_path_buf()), Arc::new(keys.clone()), join, no_wake(), quick())
}

/// Enroll the phone in `dir` against a new scripted server and return that server. A phone that is already enrolled
/// starts at sign-in and enrolls again.
fn enroll(dir: &Path, keys: &MemoryKeys) -> Server {
    let mut server = Server::start();
    let (mut controller, updates) = phone(dir, keys, server.join());
    assert!(matches!(updates.first(), Some(Update::NeedsEnrollment | Update::Enrolled { .. })), "{updates:?}");
    assert!(controller.act(enroll_action()).is_empty());
    poll_until(&mut controller, |update| matches!(update, Update::AuthenticatorSetup { .. }));
    assert!(controller.act(Action::ConfirmAuthenticator { code: Zeroizing::new("123456".to_owned()) }).is_empty());
    let seen = poll_until(&mut controller, |update| matches!(update, Update::Enrolled { .. }));
    assert!(!seen.iter().any(|update| matches!(update, Update::Failed(_))), "{seen:?}");
    server.script.take().unwrap().join().unwrap();
    server
}

/// The 32-byte private scalar inside a P-256 PKCS#8 key (the OCTET STRING after the version).
fn private_scalar(pkcs8: &[u8]) -> Vec<u8> {
    let at = pkcs8.windows(2).position(|pair| pair == [0x04, 0x20]).unwrap();
    pkcs8[at + 2..at + 34].to_vec()
}

#[test]
fn the_key_is_made_in_the_key_store_and_the_record_only_names_it() {
    let scratch = Scratch::new("record");
    let keys = MemoryKeys::new();
    let (_, updates) = phone(&scratch.0, &keys, refused_join());
    assert_eq!(updates, vec![Update::NeedsEnrollment]);
    let server = enroll(&scratch.0, &keys);

    let aliases = keys.aliases();
    assert_eq!(aliases.len(), 1);
    let alias = &aliases[0];
    assert!(alias.starts_with("crewcraft-default-") && valid_alias(alias), "{alias}");
    assert!(keys.signatures() >= 1, "the certificate request was signed by the key store");

    let record = fs::read(scratch.0.join("default.device")).unwrap();
    assert!(record.starts_with(b"crewcraft device v3\n"));
    assert!(record.windows(alias.len()).any(|window| window == alias.as_bytes()));
    let pkcs8 = keys.private_key_for_test(alias).unwrap();
    assert!(!record.windows(pkcs8.len()).any(|window| window == pkcs8.as_slice()));
    let scalar = private_scalar(&pkcs8);
    assert!(!record.windows(scalar.len()).any(|window| window == scalar.as_slice()), "the record holds no private key");
    // Nothing else in the folder holds it either.
    for entry in fs::read_dir(&scratch.0).unwrap() {
        let bytes = fs::read(entry.unwrap().path()).unwrap();
        assert!(!bytes.windows(scalar.len()).any(|window| window == scalar.as_slice()));
    }

    // A restart goes straight to sign-in with the same key.
    let (_restarted, updates) = phone(&scratch.0, &keys, refused_join());
    assert_eq!(updates, vec![Update::Enrolled { server: server.address.clone() }]);
    let device = DeviceStore::open_hardware(&scratch.0, Arc::new(keys.clone())).unwrap().load(PROFILE).unwrap();
    assert_eq!(device.hardware_alias(), Some(alias.as_str()));
    assert!(!format!("{device:?}").contains(alias.as_str()));
}

#[test]
fn the_key_store_signs_the_tls_handshake() {
    let scratch = Scratch::new("tls");
    let keys = MemoryKeys::new();
    let server = enroll(&scratch.0, &keys);
    let device = DeviceStore::open_hardware(&scratch.0, Arc::new(keys.clone())).unwrap().load(PROFILE).unwrap();

    let before = keys.signatures();
    let (address, admitted) = server.admit_once();
    let identity = device.identity().unwrap();
    let endpoint = server.endpoint(&address);
    // The scripted server ends after the handshake, so the sign-in itself fails; the handshake is what is tested.
    let credentials = Credentials::new(USER, PASSWORD, "123456").unwrap();
    let _ = endpoint.sign_in(identity, &credentials);
    assert_eq!(admitted.join().unwrap(), device.certificate(), "the server admitted the enrolled device");
    assert!(keys.signatures() > before, "the handshake was signed by the key store");

    // A key store that will not sign: no handshake completes.
    keys.set_refuse_signing(true);
    let (address, admitted) = server.admit_once();
    let _ = server.endpoint(&address).sign_in(device.identity().unwrap(), &credentials);
    assert!(admitted.join().is_err(), "no handshake without a signature");
}

#[test]
fn a_missing_or_unreachable_key_store_is_a_clear_error() {
    let scratch = Scratch::new("missing");
    let keys = MemoryKeys::new();
    enroll(&scratch.0, &keys);
    let store = DeviceStore::open_hardware(&scratch.0, Arc::new(keys.clone())).unwrap();

    keys.set_unavailable(true);
    assert_eq!(store.load(PROFILE).unwrap_err(), StoreError::KeyStoreUnavailable);
    assert_eq!(store.check_key_store(PROFILE), Err(StoreError::KeyStoreUnavailable));
    let fresh = Scratch::new("fresh");
    let (_controller, updates) = phone(&fresh.0, &keys, refused_join());
    assert_eq!(updates, vec![Update::NeedsEnrollment, Update::Failed(no_key_store(&fresh.0))]);
    keys.set_unavailable(false);
    assert_eq!(store.check_key_store(PROFILE), Ok(()));

    let alias = keys.aliases().remove(0);
    assert!(keys.delete(&alias).unwrap());
    assert_eq!(store.load(PROFILE).unwrap_err(), StoreError::KeyMissing);
    let (_controller, updates) = phone(&scratch.0, &keys, refused_join());
    assert_eq!(updates, vec![Update::NeedsEnrollment, Update::Failed(store_problem(StoreError::KeyMissing))]);
}

#[test]
fn records_do_not_cross_between_kinds_of_store() {
    let phone_dir = Scratch::new("phone");
    let keys = MemoryKeys::new();
    enroll(&phone_dir.0, &keys);
    // A desktop store, plain or sealed, will not take a record whose key is in a hardware key store.
    assert_eq!(DeviceStore::open(&phone_dir.0).unwrap().load(PROFILE).unwrap_err(), StoreError::KeyKind);
    assert_eq!(DeviceStore::open_sealed(&phone_dir.0, Arc::new(MemoryVault::new())).unwrap().load(PROFILE).unwrap_err(), StoreError::KeyKind);

    // A hardware store will not take a record that holds its key, nor save a software-key device.
    let desktop_dir = Scratch::new("desktop");
    let mut server = Server::start();
    let vault = MemoryVault::new();
    let (mut controller, _) = Controller::start_with_vault(Some(desktop_dir.0.clone()), vault.opener(), server.join(), no_wake(), quick());
    assert!(controller.act(enroll_action()).is_empty());
    poll_until(&mut controller, |update| matches!(update, Update::AuthenticatorSetup { .. }));
    assert!(controller.act(Action::ConfirmAuthenticator { code: Zeroizing::new("123456".to_owned()) }).is_empty());
    poll_until(&mut controller, |update| matches!(update, Update::Enrolled { .. }));
    server.script.take().unwrap().join().unwrap();
    let software = DeviceStore::open_sealed(&desktop_dir.0, Arc::new(vault)).unwrap().load(PROFILE).unwrap();
    assert_eq!(software.hardware_alias(), None);
    let hardware_store = DeviceStore::open_hardware(&desktop_dir.0, Arc::new(keys.clone())).unwrap();
    assert_eq!(hardware_store.load(PROFILE).unwrap_err(), StoreError::KeyKind);
    assert_eq!(hardware_store.save("other", &software).unwrap_err(), StoreError::KeyKind);
    assert_eq!(store_problem(StoreError::KeyKind), "The saved enrollment was made for a different kind of key store. Enroll this device again.");
}

#[test]
fn a_failed_enrollment_or_a_removed_profile_leaves_no_key_behind() {
    // Nothing listens at this address, so enrollment fails after the key was made.
    let server = Server::start();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string();
    let scratch = Scratch::new("failed");
    let keys = MemoryKeys::new();
    let endpoint = server.endpoint(&closed);
    let code = server.code.clone();
    let join: Join = Box::new(move |_link: &str| Ok((endpoint.clone(), code.clone())));
    let (mut controller, _) = phone(&scratch.0, &keys, join);
    assert!(controller.act(enroll_action()).is_empty());
    poll_until(&mut controller, |update| matches!(update, Update::Failed(_)));
    assert!(keys.aliases().is_empty(), "the unused key was deleted");

    // A key store that will not sign the certificate request: no device, and no key left.
    keys.set_refuse_signing(true);
    let store: Arc<dyn HardwareKeys> = Arc::new(keys.clone());
    assert_eq!(NewDevice::generate_in(store.clone(), "crewcraft-default-test").unwrap_err(), DeviceError::Generate);
    assert!(keys.aliases().is_empty());
    assert_eq!(NewDevice::generate_in(store, "Not A Valid Alias").unwrap_err(), DeviceError::Generate);
    keys.set_refuse_signing(false);

    // Enrolling again replaces the old key; removing the profile deletes the key.
    let enrolled = Scratch::new("again");
    enroll(&enrolled.0, &keys);
    let first = keys.aliases();
    enroll(&enrolled.0, &keys);
    let second = keys.aliases();
    assert_eq!(second.len(), 1);
    assert_ne!(first, second, "the replaced record's key was deleted");
    let store = DeviceStore::open_hardware(&enrolled.0, Arc::new(keys.clone())).unwrap();
    assert!(store.remove(PROFILE).unwrap());
    assert!(keys.aliases().is_empty());
    assert!(!store.remove(PROFILE).unwrap());
}

/// A key store that answers with a public key that is not P-256.
struct WrongKey;

impl HardwareKey for WrongKey {
    fn alias(&self) -> &str {
        "crewcraft-default-wrong"
    }

    fn public_key(&self) -> &[u8] {
        &[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]
    }

    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, HardwareKeyError> {
        Err(HardwareKeyError::SignFailed)
    }

    fn location(&self) -> KeyLocation {
        KeyLocation::Unknown
    }
}

#[test]
fn only_p256_keys_and_the_p256_scheme_are_used() {
    assert!(RequestSigner::new(Arc::new(WrongKey)).is_err());
    assert!(TlsSigningKey::new(Arc::new(WrongKey)).is_err());

    let keys = MemoryKeys::new();
    let key = keys.generate("crewcraft-default-scheme").unwrap();
    assert_eq!(key.location(), KeyLocation::Software);
    assert_eq!(p256_point(key.public_key()).map(<[u8]>::len), Some(65));
    let tls = TlsSigningKey::new(key.clone()).unwrap();
    assert!(tls.choose_scheme(&[SignatureScheme::ED25519, SignatureScheme::RSA_PSS_SHA256]).is_none());
    let signer = tls.choose_scheme(&[SignatureScheme::RSA_PSS_SHA256, SignatureScheme::ECDSA_NISTP256_SHA256]).unwrap();
    assert_eq!(signer.scheme(), SignatureScheme::ECDSA_NISTP256_SHA256);
    assert!(signer.sign(b"transcript").is_ok());
    assert_eq!(tls.public_key().unwrap().as_ref(), key.public_key());

    let first = new_alias(PROFILE);
    assert!(first.starts_with("crewcraft-default-") && first.len() == "crewcraft-default-".len() + 16 && valid_alias(&first));
    assert_ne!(first, new_alias(PROFILE));
    assert!(!valid_alias("") && !valid_alias("Upper") && !valid_alias(&"a".repeat(65)) && !valid_alias("dot.dot"));

    keys.set_unavailable(true);
    assert!(matches!(keys.open("crewcraft-default-scheme"), Err(HardwareKeyError::Unavailable)));
    keys.set_unavailable(false);
    assert!(matches!(keys.open("crewcraft-default-none"), Err(HardwareKeyError::NotFound)));
}
