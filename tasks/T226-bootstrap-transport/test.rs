#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::bootstrap_transport::{BootstrapEndpoint, BootstrapTransportError, MAX_CONFIRMATION_WINDOW};
use crewcraft::enroll_client::{EnrollmentError, EnrollmentRequest, FirstTotpCode};
use crewcraft::lab_client::LabError;
use crewcraft_admission::{Admission, AdmitError, Admitted, Class, admit, server_config};
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_pki::{Authority, Claims, ServerIdentity};
use crewcraft_proto::bootstrap::{self, BootstrapRequest, BootstrapResponse};
use crewcraft_proto::frame;
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use x509_parser::prelude::{FromDer, X509Certificate};

const NAME: &str = "localhost";
const IO: Duration = Duration::from_secs(5);
const PASSWORD: &str = "fixture password";
fn test_uri() -> String {
    crewcraft_totp::Totp::with_defaults(vec![7; 20]).unwrap().otpauth_uri("CrewCraft Lab", "pilot@example.org")
}

#[derive(Debug)]
struct Invite([u8; 32]);

impl Admission for Invite {
    fn device_ok(&self, _: &[u8]) -> bool {
        false
    }

    fn bootstrap_key_live(&self, public_key: &[u8; 32]) -> bool {
        self.0 == *public_key
    }
}

struct Fixture {
    root: Vec<u8>,
    server: ServerIdentity,
    issuer: Authority,
    code: EnrollmentCode,
}

impl Fixture {
    fn new() -> Self {
        let root = Authority::create_root("Test Root", now_ms()).unwrap();
        let issuer = root.create_issuing("Test Issuer", now_ms()).unwrap();
        let server = issuer.server_certificate(NAME, now_ms()).unwrap();
        let code = EnrollmentCode::from_bytes([0xa1; 20]);
        Self { root: root.certificate().to_vec(), server, issuer, code }
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn serve(
    root: &[u8],
    server: ServerIdentity,
    expected: [u8; 32],
    script: impl FnOnce(Result<Admitted, AdmitError>) + Send + 'static,
) -> (SocketAddr, JoinHandle<()>) {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root)).unwrap();
    let admission = Arc::new(Invite(expected));
    let chain = server.chain.into_iter().map(CertificateDer::from).collect();
    let key = PrivatePkcs8KeyDer::from(server.key_pkcs8).into();
    let config = server_config((chain, key), roots, admission.clone()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        script(admit(socket, config, IO, &*admission, (now_ms() / 1000) as i64));
    });
    (address, handle)
}

fn accepted(peer: Result<Admitted, AdmitError>, key: [u8; 32]) -> Admitted {
    let peer = peer.unwrap();
    assert_eq!(peer.class, Class::Bootstrap(key));
    peer.stream.sock.set_read_timeout(Some(IO)).unwrap();
    peer.stream.sock.set_write_timeout(Some(IO)).unwrap();
    peer
}

fn read_request(stream: &mut impl Read) -> (u32, BootstrapRequest) {
    let next = frame::read_frame(stream, frame::MAX_FRAME).unwrap().unwrap();
    bootstrap::decode_bootstrap_request(next.payload()).unwrap()
}

fn respond(stream: &mut impl Write, id: u32, reply: &BootstrapResponse) {
    let payload = bootstrap::encode_bootstrap_response(id, reply).unwrap();
    stream.write_all(&frame::encode(&payload).unwrap()).unwrap();
    stream.flush().unwrap();
}

#[test]
fn refuses_external_addresses_wrong_root_and_unbounded_windows() {
    let fixture = Fixture::new();
    let root = &fixture.root;
    let pin = RootFingerprint::from_der(root);
    assert_eq!(BootstrapEndpoint::new("192.0.2.1:4242", NAME, pin, root).err(), Some(BootstrapTransportError::Endpoint(LabError::Address)),);
    assert_eq!(BootstrapEndpoint::new("127.0.0.1:0", NAME, pin, root).err(), Some(BootstrapTransportError::Endpoint(LabError::Address)));
    let wrong_pin = RootFingerprint::from_der(b"different certificate");
    assert_eq!(BootstrapEndpoint::new("127.0.0.1:4242", NAME, wrong_pin, root).err(), Some(BootstrapTransportError::Endpoint(LabError::Trust)));
    let endpoint = BootstrapEndpoint::new("127.0.0.1:4242", NAME, pin, root).unwrap();
    for window in [Duration::ZERO, MAX_CONFIRMATION_WINDOW + Duration::from_millis(1)] {
        assert_eq!(endpoint.open(&fixture.code, window).err(), Some(BootstrapTransportError::ConfirmationWindow));
    }
}

#[test]
fn a_server_with_the_wrong_name_does_not_get_a_bootstrap_connection() {
    let fixture = Fixture::new();
    let (address, handle) = serve(&fixture.root, fixture.server, fixture.code.bootstrap_public_key(), |peer| assert!(peer.is_err()));
    let root = &fixture.root;
    let endpoint = BootstrapEndpoint::new(&address.to_string(), "wrong.example.org", RootFingerprint::from_der(root), root).unwrap();
    assert_eq!(endpoint.open(&fixture.code, IO).err(), Some(BootstrapTransportError::Connection(LabError::Handshake)));
    handle.join().unwrap();
}

#[test]
fn derives_the_admitted_identity_and_enrolls_using_the_original_root() {
    let mut fixture = Fixture::new();
    let device = KeyPair::generate().unwrap();
    let params = CertificateParams::default();
    let csr = params.serialize_request(&device).unwrap();
    let issued = fixture.issuer.issue_device(csr.der(), &Claims { person: "reader@example.org", device_id: 1 }, now_ms()).unwrap();
    let expected_leaf = issued.certificate.clone();
    let issuer_certificate = fixture.issuer.certificate().to_vec();
    let expected = fixture.code.bootstrap_public_key();
    let (address, handle) = serve(&fixture.root, fixture.server, expected, move |peer| {
        let mut peer = accepted(peer, expected);
        let (rest, bootstrap_cert) = X509Certificate::from_der(&peer.certificate).unwrap();
        assert!(rest.is_empty());
        let validity = bootstrap_cert.validity();
        assert_eq!(validity.not_after.timestamp() - validity.not_before.timestamp(), 210);
        assert!(bootstrap_cert.verify_signature(None).is_ok());
        let (id, request) = read_request(&mut peer.stream);
        assert_eq!(id, 1);
        assert!(matches!(request, BootstrapRequest::Redeem { password, .. } if password == PASSWORD));
        respond(&mut peer.stream, id, &BootstrapResponse::Setup { totp_uri: test_uri() });
        let (id, request) = read_request(&mut peer.stream);
        assert_eq!(id, 2);
        assert!(matches!(request, BootstrapRequest::ConfirmTotp { code } if code == "287082"));
        respond(&mut peer.stream, id, &BootstrapResponse::Activated { certificate: issued.certificate, issuer_certificate });
    });
    let root = &fixture.root;
    let endpoint = BootstrapEndpoint::new(&address.to_string(), NAME, RootFingerprint::from_der(root), root).unwrap();
    let connection = endpoint.open(&fixture.code, IO).unwrap();
    let spki = device.subject_public_key_info();
    let request = EnrollmentRequest { device_name: "Test Device", csr: csr.der(), password: PASSWORD, expected_spki: &spki };
    let chain = connection
        .enroll(request, |setup, deadline| {
            assert_eq!(setup.protected_uri(), test_uri());
            assert!(Instant::now() < deadline);
            FirstTotpCode::parse("287082".into())
        })
        .unwrap();
    assert_eq!(chain.leaf.as_ref(), expected_leaf);
    handle.join().unwrap();
}

#[test]
fn discards_a_confirmation_returned_after_the_shared_cutoff() {
    let fixture = Fixture::new();
    let expected = fixture.code.bootstrap_public_key();
    let (address, handle) = serve(&fixture.root, fixture.server, expected, move |peer| {
        let mut peer = accepted(peer, expected);
        let (id, _) = read_request(&mut peer.stream);
        respond(&mut peer.stream, id, &BootstrapResponse::Setup { totp_uri: test_uri() });
        let mut bytes = [0];
        assert!(!matches!(peer.stream.read(&mut bytes), Ok(1)));
    });
    let root = &fixture.root;
    let endpoint = BootstrapEndpoint::new(&address.to_string(), NAME, RootFingerprint::from_der(root), root).unwrap();
    let connection = endpoint.open(&fixture.code, Duration::from_secs(1)).unwrap();
    let request = EnrollmentRequest { device_name: "Test Device", csr: b"fixture", password: PASSWORD, expected_spki: b"fixture" };
    let result = connection.enroll(request, |_, deadline| {
        thread::sleep(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(20));
        FirstTotpCode::parse("287082".into())
    });
    assert_eq!(result.err(), Some(EnrollmentError::PromptCancelled));
    handle.join().unwrap();
}
