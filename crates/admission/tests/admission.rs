//! The admission verifier in real mutual TLS over loopback, with certificates from the W1 authority and from rcgen.
//! Every socket has a deadline. Synthetic names only (example.org), no real keys. A refused peer must receive no
//! application byte and no TLS alert, and a peer admitted at the handshake but refused by the recheck must receive nothing.

// The helpers here are test code too, but clippy's `allow-unwrap-in-tests` only covers `#[test]` bodies.
#![allow(clippy::unwrap_used)]

use std::collections::HashSet;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft_admission::{Admission, AdmitError, Class, Refusal, admit, server_config};
use crewcraft_pki::{Authority, Claims, Issued, Status};
use crewcraft_tls::{client_config, connect};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ED25519, PublicKeyData,
    date_time_ymd,
};
use rustls::client::ResolvesClientCert;
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::sign::CertifiedKey;
use rustls::{RootCertStore, SignatureScheme};

const IO: Duration = Duration::from_secs(3);

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn now_s() -> i64 {
    (now_ms() / 1000) as i64
}

/// The server's answers, backed by the real W1 authority plus a registry and an invitation list.
#[derive(Debug)]
struct Fake {
    authority: Mutex<Authority>,
    registered: Mutex<HashSet<[u8; 32]>>,
    invitations: Mutex<HashSet<[u8; 32]>>,
    /// Answer yes to every device: used only to show that the verifier's own EKU check is what refuses a certificate.
    trust_any_device: bool,
}

impl Admission for Fake {
    fn device_ok(&self, certificate: &[u8]) -> bool {
        if self.trust_any_device {
            return true;
        }
        match self.authority.lock().unwrap().status(certificate, now_ms()) {
            Ok(Status::Good(info)) => self.registered.lock().unwrap().contains(&info.key_id),
            _ => false,
        }
    }

    fn bootstrap_key_live(&self, public_key: &[u8; 32]) -> bool {
        self.invitations.lock().unwrap().contains(public_key)
    }
}

struct Lab {
    fake: Arc<Fake>,
    root_cert: Vec<u8>,
    server_chain: Vec<Vec<u8>>,
    server_key: Vec<u8>,
}

fn roots(der: &[u8]) -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.add(CertificateDer::from(der.to_vec())).unwrap();
    store
}

fn certs(chain: &[Vec<u8>]) -> Vec<CertificateDer<'static>> {
    chain.iter().map(|c| CertificateDer::from(c.clone())).collect()
}

fn lab() -> Lab {
    let root = Authority::create_root("Test Root", now_ms()).unwrap();
    let issuing = root.create_issuing("Test Issuing", now_ms()).unwrap();
    let server = issuing.server_certificate("localhost", now_ms()).unwrap();
    let fake = Arc::new(Fake {
        authority: Mutex::new(issuing),
        registered: Mutex::new(HashSet::new()),
        invitations: Mutex::new(HashSet::new()),
        trust_any_device: false,
    });
    Lab { fake, root_cert: root.certificate().to_vec(), server_chain: server.chain.clone(), server_key: server.key_pkcs8 }
}

/// An enrolled device: issued by the authority and registered.
fn enrolled(lab: &Lab, person: &str, id: u64) -> (KeyPair, Issued) {
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
    let issued = lab.fake.authority.lock().unwrap().issue_device(csr.der(), &Claims { person, device_id: id }, now_ms()).unwrap();
    lab.fake.registered.lock().unwrap().insert(issued.key_id);
    (key, issued)
}

/// A bootstrap certificate: self-signed Ed25519, valid for the given dates (default rcgen dates are valid now).
fn bootstrap(params: CertificateParams) -> (KeyPair, Vec<u8>, [u8; 32]) {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let public: [u8; 32] = key.der_bytes().try_into().unwrap();
    (key, cert.der().to_vec(), public)
}

fn plain_bootstrap() -> (KeyPair, Vec<u8>, [u8; 32]) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, "bootstrap");
    bootstrap(params)
}

#[derive(Debug)]
enum Outcome {
    Refused(AdmitError),
    /// Admitted at the handshake, refused by the recheck before any application I/O.
    RecheckFailed(Class, Refusal),
    Served(Class),
}

/// One connection. After the handshake the thread waits for `go` (so a test can change state between handshake and use),
/// rechecks, and only then reads "ping" and answers "pong".
struct Server {
    addr: SocketAddr,
    go: Sender<()>,
    handle: JoinHandle<Outcome>,
}

fn serve(lab: &Lab, device_roots: RootCertStore, identity: (Vec<Vec<u8>>, Vec<u8>), fake: Arc<Fake>) -> Server {
    let identity = (certs(&identity.0), PrivateKeyDer::from(PrivatePkcs8KeyDer::from(identity.1)));
    let config = server_config(identity, device_roots, fake.clone()).unwrap();
    let _ = lab;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (go, wait): (Sender<()>, Receiver<()>) = channel();
    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut admitted = match admit(tcp, config, IO, &*fake, now_s()) {
            Ok(admitted) => admitted,
            Err(e) => return Outcome::Refused(e),
        };
        let class = admitted.class;
        let _ = wait.recv_timeout(IO);
        if let Err(refusal) = admitted.recheck(&*fake, now_s()) {
            return Outcome::RecheckFailed(class, refusal);
        }
        admitted.stream.sock.set_read_timeout(Some(IO)).unwrap();
        let mut ping = [0u8; 4];
        admitted.stream.read_exact(&mut ping).unwrap();
        admitted.stream.write_all(b"pong").unwrap();
        admitted.stream.flush().unwrap();
        Outcome::Served(class)
    });
    Server { addr, go, handle }
}

fn standard(lab: &Lab) -> Server {
    serve(lab, roots(&lab.root_cert), (lab.server_chain.clone(), lab.server_key.clone()), lab.fake.clone())
}

fn tcp(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(IO)).unwrap();
    s.set_write_timeout(Some(IO)).unwrap();
    s
}

fn client(lab: &Lab, identity: Option<(Vec<Vec<u8>>, Vec<u8>)>) -> Arc<rustls::ClientConfig> {
    let identity = identity.map(|(chain, key)| (certs(&chain), PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key))));
    client_config(roots(&lab.root_cert), identity).unwrap()
}

/// Ping and wait for pong, as an admitted client does.
fn exchange(addr: SocketAddr, config: Arc<rustls::ClientConfig>, server_go: &Sender<()>) -> std::io::Result<[u8; 4]> {
    let mut stream = connect(tcp(addr), config, ServerName::try_from("localhost").unwrap()).unwrap();
    stream.write_all(b"ping")?;
    stream.flush()?;
    server_go.send(()).unwrap();
    let mut pong = [0u8; 4];
    stream.read_exact(&mut pong)?;
    Ok(pong)
}

/// A refused client: what it read (must be nothing) and how the connection ended (a bare close, never a TLS alert).
fn refused_client(addr: SocketAddr, config: Arc<rustls::ClientConfig>, server_go: &Sender<()>) {
    let mut stream = connect(tcp(addr), config, ServerName::try_from("localhost").unwrap()).unwrap();
    let _ = stream.write_all(b"ping");
    let _ = stream.flush();
    let _ = server_go.send(());
    let mut plain = Vec::new();
    let error = stream.read_to_end(&mut plain).err().map(|e| e.kind());
    assert!(plain.is_empty(), "application bytes reached a refused client: {plain:?}");
    assert!(
        matches!(error, Some(ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe)),
        "a refused client saw {error:?} instead of a bare close"
    );
}

fn chain_and_key(key: &KeyPair, issued: &Issued) -> (Vec<Vec<u8>>, Vec<u8>) {
    (issued.chain.clone(), key.serialize_der())
}

#[test]
fn an_enrolled_device_is_admitted_and_exchanges_bytes() {
    let lab = lab();
    let (key, issued) = enrolled(&lab, "alice@example.org", 1);
    let server = standard(&lab);
    let config = client(&lab, Some(chain_and_key(&key, &issued)));
    assert_eq!(&exchange(server.addr, config, &server.go).unwrap(), b"pong");
    assert!(matches!(server.handle.join().unwrap(), Outcome::Served(Class::Device)));
}

#[test]
fn a_valid_but_unregistered_device_is_refused() {
    let lab = lab();
    let (key, issued) = enrolled(&lab, "alice@example.org", 1);
    lab.fake.registered.lock().unwrap().clear();
    let server = standard(&lab);
    refused_client(server.addr, client(&lab, Some(chain_and_key(&key, &issued))), &server.go);
    assert!(matches!(server.handle.join().unwrap(), Outcome::Refused(AdmitError::Tls(_))));
}

#[test]
fn a_revoked_device_is_refused_at_the_handshake() {
    let lab = lab();
    let (key, issued) = enrolled(&lab, "alice@example.org", 1);
    assert!(lab.fake.authority.lock().unwrap().revoke(&issued.serial));
    let server = standard(&lab);
    refused_client(server.addr, client(&lab, Some(chain_and_key(&key, &issued))), &server.go);
    assert!(matches!(server.handle.join().unwrap(), Outcome::Refused(AdmitError::Tls(_))));
}

#[test]
fn a_device_revoked_after_the_handshake_is_refused_before_any_application_io() {
    let lab = lab();
    let (key, issued) = enrolled(&lab, "alice@example.org", 1);
    let server = standard(&lab);
    let config = client(&lab, Some(chain_and_key(&key, &issued)));
    // Revoke between the handshake and the first application byte: the server's recheck runs after `go`.
    let fake = lab.fake.clone();
    let serial = issued.serial.clone();
    let go = server.go.clone();
    let revoker = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        assert!(fake.authority.lock().unwrap().revoke(&serial));
        go.send(()).unwrap();
    });
    let mut stream = connect(tcp(server.addr), config, ServerName::try_from("localhost").unwrap()).unwrap();
    let _ = stream.write_all(b"ping");
    let mut plain = Vec::new();
    let _ = stream.read_to_end(&mut plain);
    revoker.join().unwrap();
    assert!(plain.is_empty(), "application bytes reached a revoked device: {plain:?}");
    assert!(matches!(server.handle.join().unwrap(), Outcome::RecheckFailed(Class::Device, Refusal::DeviceNotAdmitted)));
}

/// A CA made by rcgen, to build leaves the W1 authority would never issue.
struct PlainCa {
    der: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
}

fn plain_ca() -> PlainCa {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, "Plain CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = params.self_signed(&key).unwrap();
    PlainCa { der: cert.der().to_vec(), issuer: Issuer::new(params, key) }
}

fn leaf(ca: &PlainCa, names: Vec<String>, usage: Vec<ExtendedKeyUsagePurpose>) -> (Vec<Vec<u8>>, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(names).unwrap();
    params.extended_key_usages = usage;
    let cert = params.signed_by(&key, &ca.issuer).unwrap();
    (vec![cert.der().to_vec()], key.serialize_der())
}

/// A server and a client both trusting `plain_ca`, with the device-side answer forced to yes.
fn plain_world(client_usage: Vec<ExtendedKeyUsagePurpose>) -> (Server, Arc<rustls::ClientConfig>) {
    let lab = lab();
    let ca = plain_ca();
    let fake = Arc::new(Fake {
        authority: Mutex::new(Authority::create_root("Unused", now_ms()).unwrap()),
        registered: Mutex::new(HashSet::new()),
        invitations: Mutex::new(HashSet::new()),
        trust_any_device: true,
    });
    let server_identity = leaf(&ca, vec!["localhost".into()], vec![ExtendedKeyUsagePurpose::ServerAuth]);
    let server = serve(&lab, roots(&ca.der), server_identity, fake);
    let client_identity = leaf(&ca, Vec::new(), client_usage);
    let config =
        client_config(roots(&ca.der), Some((certs(&client_identity.0), PrivateKeyDer::from(PrivatePkcs8KeyDer::from(client_identity.1))))).unwrap();
    (server, config)
}

#[test]
fn a_leaf_with_no_extended_key_usage_is_refused_even_when_the_server_says_yes() {
    let (server, config) = plain_world(Vec::new());
    refused_client(server.addr, config, &server.go);
    assert!(matches!(server.handle.join().unwrap(), Outcome::Refused(AdmitError::Tls(_))));
}

#[test]
fn a_leaf_with_server_auth_only_is_refused() {
    let (server, config) = plain_world(vec![ExtendedKeyUsagePurpose::ServerAuth]);
    refused_client(server.addr, config, &server.go);
    assert!(matches!(server.handle.join().unwrap(), Outcome::Refused(AdmitError::Tls(_))));
}

#[test]
fn a_client_auth_leaf_from_an_unknown_authority_is_refused_even_when_the_server_says_yes() {
    // The server's answer is yes for every device, the leaf is perfect, but it chains to an authority the server never trusted.
    let lab = lab();
    let ca = plain_ca();
    let stranger = plain_ca();
    let fake = Arc::new(Fake {
        authority: Mutex::new(Authority::create_root("Unused", now_ms()).unwrap()),
        registered: Mutex::new(HashSet::new()),
        invitations: Mutex::new(HashSet::new()),
        trust_any_device: true,
    });
    let server_identity = leaf(&ca, vec!["localhost".into()], vec![ExtendedKeyUsagePurpose::ServerAuth]);
    let server = serve(&lab, roots(&ca.der), server_identity, fake);
    let client_identity = leaf(&stranger, Vec::new(), vec![ExtendedKeyUsagePurpose::ClientAuth]);
    let config =
        client_config(roots(&ca.der), Some((certs(&client_identity.0), PrivateKeyDer::from(PrivatePkcs8KeyDer::from(client_identity.1))))).unwrap();
    refused_client(server.addr, config, &server.go);
    assert!(matches!(server.handle.join().unwrap(), Outcome::Refused(AdmitError::Tls(_))));
}

#[test]
fn control_a_leaf_with_client_auth_passes_the_same_world() {
    // Proves the two refusals above are about the extended key usage and nothing else in this setup.
    let (server, config) = plain_world(vec![ExtendedKeyUsagePurpose::ClientAuth]);
    assert_eq!(&exchange(server.addr, config, &server.go).unwrap(), b"pong");
    assert!(matches!(server.handle.join().unwrap(), Outcome::Served(Class::Device)));
}

#[test]
fn a_live_bootstrap_key_is_admitted_as_enrollment_only() {
    let lab = lab();
    let (key, cert, public) = plain_bootstrap();
    lab.fake.invitations.lock().unwrap().insert(public);
    let server = standard(&lab);
    let config = client(&lab, Some((vec![cert], key.serialize_der())));
    assert_eq!(&exchange(server.addr, config, &server.go).unwrap(), b"pong");
    assert!(matches!(server.handle.join().unwrap(), Outcome::Served(Class::Bootstrap(k)) if k == public));
}

#[test]
fn an_unknown_bootstrap_key_is_refused() {
    let lab = lab();
    let (key, cert, _) = plain_bootstrap();
    let server = standard(&lab);
    refused_client(server.addr, client(&lab, Some((vec![cert], key.serialize_der()))), &server.go);
    assert!(matches!(server.handle.join().unwrap(), Outcome::Refused(AdmitError::Tls(_))));
}

#[test]
fn a_consumed_bootstrap_key_is_refused() {
    let lab = lab();
    let (key, cert, public) = plain_bootstrap();
    lab.fake.invitations.lock().unwrap().insert(public);
    lab.fake.invitations.lock().unwrap().remove(&public); // redeemed
    let server = standard(&lab);
    refused_client(server.addr, client(&lab, Some((vec![cert], key.serialize_der()))), &server.go);
    assert!(matches!(server.handle.join().unwrap(), Outcome::Refused(AdmitError::Tls(_))));
}

#[test]
fn an_invitation_consumed_after_the_handshake_fails_closed() {
    let lab = lab();
    let (key, cert, public) = plain_bootstrap();
    lab.fake.invitations.lock().unwrap().insert(public);
    let server = standard(&lab);
    let config = client(&lab, Some((vec![cert], key.serialize_der())));
    let fake = lab.fake.clone();
    let go = server.go.clone();
    let consumer = thread::spawn(move || {
        thread::sleep(Duration::from_millis(150));
        fake.invitations.lock().unwrap().remove(&public);
        go.send(()).unwrap();
    });
    let mut stream = connect(tcp(server.addr), config, ServerName::try_from("localhost").unwrap()).unwrap();
    let _ = stream.write_all(b"ping");
    let mut plain = Vec::new();
    let _ = stream.read_to_end(&mut plain);
    consumer.join().unwrap();
    assert!(plain.is_empty(), "application bytes reached a consumed invitation: {plain:?}");
    assert!(matches!(server.handle.join().unwrap(), Outcome::RecheckFailed(Class::Bootstrap(_), Refusal::BootstrapNotLive)));
}

#[test]
fn an_expired_bootstrap_certificate_is_refused_even_for_a_live_key() {
    let lab = lab();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2020, 1, 2);
    let (key, cert, public) = bootstrap(params);
    lab.fake.invitations.lock().unwrap().insert(public);
    let server = standard(&lab);
    refused_client(server.addr, client(&lab, Some((vec![cert], key.serialize_der()))), &server.go);
    assert!(matches!(server.handle.join().unwrap(), Outcome::Refused(AdmitError::Tls(_))));
}

#[test]
fn a_bootstrap_key_that_is_not_ed25519_is_refused() {
    let lab = lab();
    // A self-signed P-256 certificate whose public key bytes are, absurdly, registered as an invitation key.
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(Vec::<String>::new()).unwrap().self_signed(&key).unwrap();
    let mut fake_key = [0u8; 32];
    fake_key.copy_from_slice(&key.der_bytes()[1..33]);
    lab.fake.invitations.lock().unwrap().insert(fake_key);
    let server = standard(&lab);
    refused_client(server.addr, client(&lab, Some((vec![cert.der().to_vec()], key.serialize_der()))), &server.go);
    assert!(matches!(server.handle.join().unwrap(), Outcome::Refused(AdmitError::Tls(_))));
}

#[test]
fn a_certificate_that_looks_self_signed_but_was_signed_by_another_key_is_refused() {
    let lab = lab();
    // The holder of a live invitation key K makes a certificate for K whose issuer name equals its subject name, but signs
    // it with a different key J. It is not self-signed, so it is no bootstrap certificate; it chains to nothing either.
    let k = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let j = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut subject = CertificateParams::new(Vec::<String>::new()).unwrap();
    subject.distinguished_name.push(DnType::CommonName, "bootstrap");
    let mut issuer_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    issuer_params.distinguished_name.push(DnType::CommonName, "bootstrap");
    issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = subject.signed_by(&k, &Issuer::new(issuer_params, j)).unwrap();
    let public: [u8; 32] = k.der_bytes().try_into().unwrap();
    lab.fake.invitations.lock().unwrap().insert(public);
    let server = standard(&lab);
    refused_client(server.addr, client(&lab, Some((vec![cert.der().to_vec()], k.serialize_der()))), &server.go);
    assert!(matches!(server.handle.join().unwrap(), Outcome::Refused(AdmitError::Tls(_))));
}

/// Always offers one certificate with whatever key it was given, without checking they belong together.
#[derive(Debug)]
struct Impostor(Arc<CertifiedKey>);

impl ResolvesClientCert for Impostor {
    fn resolve(&self, _hints: &[&[u8]], _schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[test]
fn a_copy_of_a_live_invitation_certificate_without_its_private_key_is_refused() {
    let lab = lab();
    let (_victim_key, victim_cert, public) = plain_bootstrap();
    lab.fake.invitations.lock().unwrap().insert(public);
    // The attacker saw the certificate (it is not secret) and signs the handshake with a key of their own.
    let attacker = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let signer = ring::sign::any_supported_type(&PrivateKeyDer::from(PrivatePkcs8KeyDer::from(attacker.serialize_der()))).unwrap();
    let certified = Arc::new(CertifiedKey::new(vec![CertificateDer::from(victim_cert)], signer));
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots(&lab.root_cert))
        .with_client_cert_resolver(Arc::new(Impostor(certified)));
    let server = standard(&lab);
    refused_client(server.addr, Arc::new(config), &server.go);
    assert!(matches!(server.handle.join().unwrap(), Outcome::Refused(AdmitError::Tls(_))));
}

#[test]
fn a_client_with_no_certificate_and_a_foreign_certificate_get_nothing() {
    let lab = lab();
    let server = standard(&lab);
    refused_client(server.addr, client(&lab, None), &server.go);
    assert!(matches!(server.handle.join().unwrap(), Outcome::Refused(AdmitError::Tls(_))));

    // A device certificate from another authority, with a registered-looking identity.
    let foreign = self::lab();
    let (key, issued) = enrolled(&foreign, "mallory@example.org", 1);
    let server = standard(&lab);
    refused_client(server.addr, client(&lab, Some(chain_and_key(&key, &issued))), &server.go);
    assert!(matches!(server.handle.join().unwrap(), Outcome::Refused(AdmitError::Tls(_))));
}
