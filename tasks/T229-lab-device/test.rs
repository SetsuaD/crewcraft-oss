#![allow(clippy::unwrap_used)]

use std::io::{self, Cursor, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft::bootstrap_transport::BootstrapEndpoint;
use crewcraft::enroll_client::{CertificateProblem, EnrollmentError, FirstTotpCode};
use crewcraft::lab_device::{LabDeviceError, LabDeviceKey};
use crewcraft_admission::{Admission, Admitted, Class, admit, server_config};
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_pki::{Authority, Claims};
use crewcraft_proto::bootstrap::{self, BootstrapRequest, BootstrapResponse};
use crewcraft_proto::frame;
use crewcraft_proto::handshake;
use crewcraft_proto::request::{self, Request, Response};
use crewcraft_proto::signin;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig};

const WAIT: Duration = Duration::from_secs(5);
const USER: &str = "reader@example.org";
const PASSWORD: &str = "fixture password";
fn test_setup() -> String {
    crewcraft_totp::Totp::with_defaults(vec![7; 20]).unwrap().otpauth_uri("CrewCraft Lab", "pilot@example.org")
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

struct Fixture {
    issuer: Authority,
    root: Vec<u8>,
    code: EnrollmentCode,
    devices: Arc<Devices>,
    config: Arc<ServerConfig>,
}

impl Fixture {
    fn new() -> Self {
        let root = Authority::create_root("Test Root", now_ms()).unwrap();
        let issuer = root.create_issuing("Test Issuer", now_ms()).unwrap();
        let server = issuer.server_certificate("localhost", now_ms()).unwrap();
        let code = EnrollmentCode::from_bytes([0x23; 20]);
        let devices = Arc::new(Devices { invitation: code.bootstrap_public_key(), leaf: Mutex::new(None) });
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(root.certificate())).unwrap();
        let chain = server.chain.into_iter().map(CertificateDer::from).collect();
        let key = PrivatePkcs8KeyDer::from(server.key_pkcs8).into();
        let config = server_config((chain, key), roots, devices.clone()).unwrap();
        Self { issuer, root: root.certificate().to_vec(), code, devices, config }
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn serve(listener: TcpListener, config: Arc<ServerConfig>, devices: Arc<Devices>, script: impl FnOnce(Admitted) + Send + 'static) -> JoinHandle<()> {
    thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        let peer = admit(socket, config, WAIT, &*devices, (now_ms() / 1000) as i64).unwrap();
        peer.stream.sock.set_read_timeout(Some(WAIT)).unwrap();
        peer.stream.sock.set_write_timeout(Some(WAIT)).unwrap();
        script(peer);
    })
}

fn read(stream: &mut impl Read) -> frame::ReceivedFrame {
    frame::read_frame(stream, frame::MAX_FRAME).unwrap().unwrap()
}

fn send(stream: &mut impl Write, payload: &[u8]) {
    stream.write_all(&frame::encode(payload).unwrap()).unwrap();
    stream.flush().unwrap();
}

fn client_closed(stream: &mut impl Read) {
    let mut byte = [0];
    match stream.read(&mut byte) {
        Ok(count) => assert_eq!(count, 0),
        Err(error) => assert!(matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset)),
    }
}

fn enroll_peer(mut peer: Admitted, mut issuer: Authority, devices: Arc<Devices>, wrong_key: bool) {
    assert_eq!(peer.class, Class::Bootstrap(devices.invitation));
    let request = read(&mut peer.stream);
    let (id, request) = bootstrap::decode_bootstrap_request(request.payload()).unwrap();
    assert_eq!(id, 1);
    let BootstrapRequest::Redeem { device_name, csr, password } = request else {
        assert!(matches!(request, BootstrapRequest::Redeem { .. }));
        return;
    };
    assert_eq!((device_name.as_str(), password.as_str()), ("Test Lab", PASSWORD));
    send(&mut peer.stream, &bootstrap::encode_bootstrap_response(id, &BootstrapResponse::Setup { totp_uri: test_setup() }).unwrap());

    let request = read(&mut peer.stream);
    let (id, confirm) = bootstrap::decode_bootstrap_request(request.payload()).unwrap();
    assert_eq!(id, 2);
    assert_eq!(confirm, BootstrapRequest::ConfirmTotp { code: "123456".into() });
    let csr = if wrong_key { CertificateParams::default().serialize_request(&KeyPair::generate().unwrap()).unwrap().der().to_vec() } else { csr };
    let issued = issuer.issue_device(&csr, &Claims { person: USER, device_id: 1 }, now_ms()).unwrap();
    *devices.leaf.lock().unwrap() = Some(issued.certificate.clone());
    let response = BootstrapResponse::Activated { certificate: issued.certificate, issuer_certificate: issuer.certificate().to_vec() };
    send(&mut peer.stream, &bootstrap::encode_bootstrap_response(id, &response).unwrap());
    client_closed(&mut peer.stream);
}

#[test]
fn one_ephemeral_device_enrolls_and_reconnects_after_server_restarts() {
    let Fixture { issuer, root, code, devices, config } = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let enrolled = devices.clone();
    let server = serve(listener, config.clone(), devices.clone(), |peer| enroll_peer(peer, issuer, enrolled, false));
    let endpoint = BootstrapEndpoint::new(&address.to_string(), "localhost", RootFingerprint::from_der(&root), &root).unwrap();
    let key = LabDeviceKey::generate().unwrap();
    let device = key
        .enroll(&endpoint, &code, WAIT, "Test Lab", PASSWORD, |setup, _| {
            assert_eq!(setup.protected_uri(), test_setup());
            FirstTotpCode::parse("123456".into())
        })
        .unwrap();
    server.join().unwrap();

    for (passcode, cursor) in [("234567", 1), ("345678", 2)] {
        let listener = TcpListener::bind(address).unwrap();
        let expected_leaf = devices.leaf.lock().unwrap().clone().unwrap();
        let server = serve(listener, config.clone(), devices.clone(), move |mut peer| {
            assert_eq!(peer.class, Class::Device);
            assert_eq!(peer.certificate(), expected_leaf.as_slice());
            let sign_in = read(&mut peer.stream);
            let sign_in = signin::decode_request(sign_in.payload()).unwrap();
            assert_eq!((sign_in.email, sign_in.password, sign_in.code), (USER, PASSWORD, passcode));
            let token = "A".repeat(signin::TOKEN_LEN);
            send(&mut peer.stream, &signin::encode_reply(&signin::Reply::Accepted { token: &token }).unwrap());
            let hello = read(&mut peer.stream);
            assert_eq!(handshake::decode_hello(hello.payload()).unwrap().client, "crewcraft-lab");
            let welcome = handshake::Reply::Welcome { version: 1, features: 0, server: "test server".into() };
            send(&mut peer.stream, &handshake::encode_reply(&welcome).unwrap());
            let post = read(&mut peer.stream);
            let (id, post) = request::decode_request(post.payload()).unwrap();
            assert_eq!(post, Request::Post { room: "lobby".into(), text: "a message".into() });
            send(&mut peer.stream, &request::encode_response(id, &Response::Ok { cursor }).unwrap());
            client_closed(&mut peer.stream);
        });
        let mut input = Cursor::new(format!("{USER}\n{PASSWORD}\n{passcode}\n").into_bytes());
        let mut session = device.open_session(&mut input).unwrap();
        assert_eq!(session.post("lobby", "a message"), Ok(cursor));
        drop(session);
        server.join().unwrap();
    }
}

#[test]
fn refuses_an_activation_certificate_for_a_different_key() {
    let Fixture { issuer, root, code, devices, config } = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let enrolled = devices.clone();
    let server = serve(listener, config, devices, |peer| enroll_peer(peer, issuer, enrolled, true));
    let endpoint = BootstrapEndpoint::new(&address.to_string(), "localhost", RootFingerprint::from_der(&root), &root).unwrap();
    let result = LabDeviceKey::generate().unwrap().enroll(&endpoint, &code, WAIT, "Test Lab", PASSWORD, |_, _| FirstTotpCode::parse("123456".into()));
    assert_eq!(result.err(), Some(LabDeviceError::Enrollment(EnrollmentError::ActivatedCertificateRejected(CertificateProblem::WrongDeviceKey))));
    server.join().unwrap();
}
