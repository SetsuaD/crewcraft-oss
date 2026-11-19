//! T309: the desktop app's controller, driven without a window against a scripted server.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::app::{Controller, Join, PROFILE, Wake, enrollment_problem, worker_update};
use crewcraft::device::DeviceError;
use crewcraft::device_store::DeviceStore;
use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::worker::{Event, Problem, WorkerConfig};
use crewcraft_admission::{Admission, Admitted, admit, server_config};
use crewcraft_desktop_ui::{Action, Update};
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_pki::{Authority, Claims};
use crewcraft_proto::bootstrap::{self, BootstrapRequest, BootstrapResponse};
use crewcraft_proto::frame;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{RootCertStore, ServerConfig};
use zeroize::Zeroizing;

const WAIT: Duration = Duration::from_secs(5);
const USER: &str = "reader@example.org";
const PASSWORD: &str = "fixture password";

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        Self(std::env::temp_dir().join(format!("crewcraft-t309-{tag}-{}-{}", std::process::id(), now_ms())))
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

/// A one-shot scripted server that enrolls one device, expecting the first code `123456`.
struct Server {
    root: Vec<u8>,
    address: String,
    code: EnrollmentCode,
    script: Option<JoinHandle<()>>,
}

impl Server {
    fn start() -> Self {
        let root = Authority::create_root("Test Root", now_ms()).unwrap();
        let mut issuer = root.create_issuing("Test Issuer", now_ms()).unwrap();
        let identity = issuer.server_certificate("localhost", now_ms()).unwrap();
        let code = EnrollmentCode::from_bytes([0x31; 20]);
        let devices = Arc::new(Devices { invitation: code.bootstrap_public_key(), leaf: Mutex::new(None) });
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(root.certificate())).unwrap();
        let chain = identity.chain.into_iter().map(CertificateDer::from).collect();
        let key = PrivatePkcs8KeyDer::from(identity.key_pkcs8).into();
        let config: Arc<ServerConfig> = server_config((chain, key), roots, devices.clone()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let script = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let mut peer: Admitted = admit(socket, config, WAIT, &*devices, (now_ms() / 1000) as i64).unwrap();
            peer.stream.sock.set_read_timeout(Some(WAIT)).unwrap();
            let redeem = read(&mut peer.stream);
            let (id, BootstrapRequest::Redeem { csr, password, .. }) = bootstrap::decode_bootstrap_request(redeem.payload()).unwrap() else {
                panic!("expected Redeem");
            };
            assert_eq!(password.as_str(), PASSWORD);
            send(&mut peer.stream, &bootstrap::encode_bootstrap_response(id, &BootstrapResponse::Setup { totp_uri: setup_uri() }).unwrap());
            let (id, confirm) = bootstrap::decode_bootstrap_request(read(&mut peer.stream).payload()).unwrap();
            assert_eq!(confirm, BootstrapRequest::ConfirmTotp { code: "123456".into() });
            let issued = issuer.issue_device(&csr, &Claims { person: USER, device_id: 1 }, now_ms()).unwrap();
            *devices.leaf.lock().unwrap() = Some(issued.certificate.clone());
            let activated = BootstrapResponse::Activated { certificate: issued.certificate, issuer_certificate: issuer.certificate().to_vec() };
            send(&mut peer.stream, &bootstrap::encode_bootstrap_response(id, &activated).unwrap());
            let mut byte = [0];
            let _ = peer.stream.read(&mut byte);
        });
        Self { root: root.certificate().to_vec(), address, code, script: Some(script) }
    }

    /// A `Join` that ignores the link text and returns this server's endpoint and invitation code.
    fn join(&self) -> Join {
        let (address, root, code) = (self.address.clone(), self.root.clone(), self.code.clone());
        Box::new(move |_link: &str| {
            let endpoint = ServerEndpoint::new(&address, "localhost", RootFingerprint::from_der(&root), &root).map_err(|_| "endpoint".to_owned())?;
            Ok((endpoint, code.clone()))
        })
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

/// Poll until an update matching `want` arrives, returning everything seen up to it.
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

#[test]
fn first_start_asks_for_enrollment_and_a_bad_link_is_explained() {
    let scratch = Scratch::new("first");
    let (mut controller, updates) = Controller::start(Some(scratch.0.clone()), refused_join(), no_wake(), quick());
    assert_eq!(updates, vec![Update::NeedsEnrollment]);
    assert_eq!(controller.act(enroll_action()), vec![Update::NeedsEnrollment, Update::Failed("That is not a CrewCraft invitation link.".to_owned())]);
    assert_eq!(controller.act(Action::ConfirmAuthenticator { code: Zeroizing::new("123456".to_owned()) }), vec![Update::NeedsEnrollment]);
    assert!(matches!(
        controller
            .act(Action::SignIn { email: USER.to_owned(), password: Zeroizing::new(PASSWORD.to_owned()), code: Zeroizing::new("12".to_owned()) })
            .as_slice(),
        [Update::Failed(_)]
    ));
    assert_eq!(controller.act(Action::SignOut), vec![Update::SignedOut]);
}

#[test]
fn no_data_folder_still_starts_and_says_why_nothing_is_saved() {
    let (_controller, updates) = Controller::start(None, refused_join(), no_wake(), quick());
    assert_eq!(updates.first(), Some(&Update::NeedsEnrollment));
    assert!(matches!(updates.get(1), Some(Update::Failed(text)) if text.contains("cannot save")));
}

#[test]
fn enrolls_saves_the_device_and_a_restart_goes_straight_to_sign_in() {
    let scratch = Scratch::new("enroll");
    let mut server = Server::start();
    let (mut controller, updates) = Controller::start(Some(scratch.0.clone()), server.join(), no_wake(), quick());
    assert_eq!(updates, vec![Update::NeedsEnrollment]);
    assert!(controller.act(enroll_action()).is_empty());

    let seen = poll_until(&mut controller, |update| matches!(update, Update::AuthenticatorSetup { .. }));
    assert_eq!(seen.last(), Some(&Update::AuthenticatorSetup { otpauth_uri: setup_uri() }));
    assert_eq!(
        controller.act(Action::ConfirmAuthenticator { code: Zeroizing::new("12345".to_owned()) }),
        vec![Update::Failed("Type the six-digit code your authenticator shows now.".to_owned())]
    );
    assert!(controller.act(Action::ConfirmAuthenticator { code: Zeroizing::new(" 123456 ".to_owned()) }).is_empty());

    let seen = poll_until(&mut controller, |update| matches!(update, Update::Enrolled { .. }));
    assert_eq!(seen.last(), Some(&Update::Enrolled { server: server.address.clone() }));
    assert!(!seen.iter().any(|update| matches!(update, Update::Failed(_))), "{seen:?}");
    server.script.take().unwrap().join().unwrap();
    assert_eq!(DeviceStore::open(&scratch.0).unwrap().profiles().unwrap(), [PROFILE]);
    drop(controller);

    let (_restarted, updates) = Controller::start(Some(scratch.0.clone()), refused_join(), no_wake(), quick());
    assert_eq!(updates, vec![Update::Enrolled { server: server.address.clone() }]);
}

#[test]
fn worker_events_become_window_updates() {
    assert!(worker_update(Event::Connected).is_empty());
    assert!(worker_update(Event::Posted { room: "lobby".into(), cursor: 3 }).is_empty());
    assert_eq!(
        worker_update(Event::SignedIn { email: USER.into(), rooms: vec!["lobby".into()] }),
        vec![Update::SignedIn { email: USER.into(), rooms: vec!["lobby".into()] }]
    );
    assert_eq!(
        worker_update(Event::Room { room: "lobby".into(), shown: Vec::new() }),
        vec![Update::Snapshot { room: "lobby".into(), shown: Vec::new() }]
    );
    assert_eq!(worker_update(Event::Unread { room: "lobby".into(), count: 4 }), vec![Update::Unread { room: "lobby".into(), unread: 4 }]);
    assert_eq!(worker_update(Event::Failed(Problem::SignInRefused)), vec![Update::Failed(Problem::SignInRefused.to_string())]);
    let lost = worker_update(Event::Disconnected);
    assert_eq!(lost.first(), Some(&Update::SignedOut));
    assert!(matches!(lost.get(1), Some(Update::Failed(text)) if text.contains("Sign in again")));
    assert!(!enrollment_problem(DeviceError::Invalid).is_empty());
}
