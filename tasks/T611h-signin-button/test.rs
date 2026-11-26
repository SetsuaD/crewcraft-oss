//! T611h: the connection worker's external sign-in against an in-test server that speaks the real sign-in openings
//! over real mutual TLS (begin, then finish on a second connection), with the browser played by the test: the session
//! it opens chats like any other, and cancel, a closing worker, a browser that cannot open, a server that offers no
//! provider and a refused finish each end in their own named problem.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crewcraft::loopback::parse_query;
use crewcraft::server_endpoint::ServerEndpoint;
use crewcraft::signed_in::ResumeTicket;
use crewcraft::worker::{Browser, Event, Problem, TicketKeeper, Worker, WorkerConfig};
use crewcraft_admission::{Admission, Class, admit, server_config};
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_pki::{Authority, Claims, Status};
use crewcraft_proto::frame;
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::signin::{self, Opening, Reply};
use crewcraft_server_core::server::Server;
use crewcraft_server_core::session::Session;
use crewcraft_ui_model::Command;
use rcgen::{CertificateParams, KeyPair};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};

const WAIT: Duration = Duration::from_secs(10);
const ALICE: &str = "alice@example.org";
const NONCE: &str = "__________________________________________8";
const CODE: &str = "provider-code";

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// Admits exactly the device certificates the fixture authority issued.
struct Devices(Mutex<Authority>);

impl std::fmt::Debug for Devices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Devices(..)")
    }
}

impl Devices {
    fn person(&self, certificate: &[u8]) -> Option<String> {
        match self.0.lock().ok()?.status(certificate, now_ms()) {
            Ok(Status::Good(info)) => Some(info.person),
            _ => None,
        }
    }
}

impl Admission for Devices {
    fn device_ok(&self, certificate: &[u8]) -> bool {
        self.person(certificate).is_some()
    }

    fn bootstrap_key_live(&self, _: &[u8; 32]) -> bool {
        false
    }
}

/// What the scripted server does, and what it saw.
#[derive(Default)]
struct Script {
    /// Refuse `BeginExternal`, as a server with no identity provider does.
    no_provider: bool,
    /// Refuse `FinishExternal`, as a server does for a person not bound to this device.
    refuse_finish: bool,
    begins: AtomicUsize,
    /// What each `FinishExternal` carried: code, verifier, redirect URI.
    finishes: Mutex<Vec<(String, String, String)>>,
}

struct Lab {
    devices: Arc<Devices>,
    config: Arc<ServerConfig>,
    rooms: Arc<Mutex<Server>>,
    root: Vec<u8>,
    room: String,
    alice: Arc<dyn ResolvesClientCert>,
}

fn lab() -> Lab {
    let root = Authority::create_root("Lab Root", now_ms()).unwrap();
    let mut issuer = root.create_issuing("Lab Issuing", now_ms()).unwrap();
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
    let issued = issuer.issue_device(csr.der(), &Claims { person: ALICE, device_id: 1 }, now_ms()).unwrap();
    let chain = issued.chain.into_iter().map(CertificateDer::from).collect();
    let device_key = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
    let alice: Arc<dyn ResolvesClientCert> =
        Arc::new(SingleCertAndKey::from(CertifiedKey::from_der(chain, device_key, &rustls::crypto::ring::default_provider()).unwrap()));
    let identity = issuer.server_certificate("localhost", now_ms()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root.certificate().to_vec())).unwrap();
    let devices = Arc::new(Devices(Mutex::new(issuer)));
    let chain = identity.chain.into_iter().map(CertificateDer::from).collect();
    let config = server_config((chain, PrivatePkcs8KeyDer::from(identity.key_pkcs8).into()), roots, devices.clone()).unwrap();
    let mut rooms = Server::new();
    let room = rooms.create_room(ALICE, "General").unwrap();
    Lab { devices, config, rooms: Arc::new(Mutex::new(rooms)), root: root.certificate().to_vec(), room, alice }
}

/// A loopback server speaking the sign-in openings, then the server-core chat session.
struct ScriptedServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    connections: Arc<Mutex<Vec<TcpStream>>>,
    accept: Option<JoinHandle<()>>,
}

impl ScriptedServer {
    fn start(lab: &Lab, script: &Arc<Script>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let connections = Arc::new(Mutex::new(Vec::new()));
        let (flag, open, devices, config, rooms, script) =
            (stop.clone(), connections.clone(), lab.devices.clone(), lab.config.clone(), lab.rooms.clone(), script.clone());
        let accept = thread::spawn(move || {
            for tcp in listener.incoming() {
                if flag.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(tcp) = tcp else { continue };
                open.lock().unwrap().push(tcp.try_clone().unwrap());
                let (devices, config, rooms, script) = (devices.clone(), config.clone(), rooms.clone(), script.clone());
                thread::spawn(move || serve(tcp, &devices, config, &rooms, &script));
            }
        });
        Self { address, stop, connections, accept: Some(accept) }
    }
}

impl Drop for ScriptedServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(accept) = self.accept.take() {
            accept.join().unwrap();
        }
        for connection in self.connections.lock().unwrap().drain(..) {
            let _ = connection.shutdown(Shutdown::Both);
        }
    }
}

fn serve(tcp: TcpStream, devices: &Devices, config: Arc<ServerConfig>, rooms: &Mutex<Server>, script: &Script) {
    let Ok(admitted) = admit(tcp, config, WAIT, devices, (now_ms() / 1000) as i64) else { return };
    let Some(person) = devices.person(admitted.certificate()).filter(|_| admitted.class == Class::Device) else { return };
    let mut stream = admitted.stream;
    stream.sock.set_read_timeout(Some(WAIT)).unwrap();
    stream.sock.set_write_timeout(Some(WAIT)).unwrap();
    let mut run = || -> Option<()> {
        let first = frame::read_frame(&mut stream, frame::MAX_FRAME).ok()??;
        let token = "A".repeat(signin::TOKEN_LEN);
        let (reply, chat) = match signin::decode_opening(first.payload()).ok()? {
            Opening::BeginExternal => {
                script.begins.fetch_add(1, Ordering::SeqCst);
                if script.no_provider {
                    (Reply::Refused, false)
                } else {
                    let reply = Reply::ExternalStart {
                        issuer: "https://id.example.org/",
                        client_id: "chat",
                        authorization_endpoint: "https://id.example.org/authorize/",
                        nonce: NONCE,
                    };
                    (reply, false)
                }
            }
            Opening::FinishExternal { code, verifier, redirect_uri } => {
                script.finishes.lock().unwrap().push((code.into(), verifier.into(), redirect_uri.into()));
                if script.refuse_finish || code != CODE { (Reply::Refused, false) } else { (Reply::Accepted { token: &token }, true) }
            }
            _ => (Reply::Refused, false),
        };
        stream.write_all(&frame::encode(&signin::encode_reply(&reply).ok()?).ok()?).ok()?;
        stream.flush().ok()?;
        if !chat {
            return None;
        }
        let mut session = Session::new(&person, ServerSide { min_version: 1, max_version: 1, features: 0, name: "test server".into() });
        loop {
            let request = frame::read_frame(&mut stream, frame::MAX_FRAME).ok()??;
            let reply = session.receive(&mut rooms.lock().unwrap(), request.as_bytes(), now_ms()).ok()?;
            if !reply.is_empty() {
                stream.write_all(&reply).ok()?;
                stream.flush().ok()?;
            }
        }
    };
    let _ = run();
}

/// Keeps the ticket in memory, so the test can see that an external sign-in's session is kept like any other.
#[derive(Default, Clone)]
struct Kept(Arc<Mutex<Option<String>>>);

impl TicketKeeper for Kept {
    fn load(&self) -> Option<ResumeTicket> {
        None
    }
    fn save(&self, ticket: &ResumeTicket) {
        *self.0.lock().unwrap() = Some(ticket.email().to_owned());
    }
    fn clear(&self) {
        *self.0.lock().unwrap() = None;
    }
}

/// The URLs the browser was asked to open.
type Opened = Arc<Mutex<Vec<String>>>;

/// A browser that records the URL and, if `answer`, sends the provider's redirect with `CODE` and the URL's state.
fn browser(opened: &Opened, answer: bool) -> Browser {
    let opened = opened.clone();
    Arc::new(move |url: &str| {
        opened.lock().unwrap().push(url.to_owned());
        if answer {
            let params = parse_query(url.split_once('?').unwrap().1);
            let get = |k: &str| params.iter().find(|(name, _)| name == k).unwrap().1.clone();
            let redirect = get("redirect_uri");
            let (authority, path) = redirect.trim_start_matches("http://").split_once('/').unwrap();
            let (authority, target) = (authority.to_owned(), format!("/{path}?code={CODE}&state={}", get("state")));
            thread::spawn(move || {
                let mut stream = TcpStream::connect(&authority).unwrap();
                stream.write_all(format!("GET {target} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes()).unwrap();
                let mut answer = String::new();
                let _ = stream.read_to_string(&mut answer);
            });
        }
        Ok(())
    })
}

fn fast() -> WorkerConfig {
    WorkerConfig { poll_interval: Duration::from_millis(100), first_retry: Duration::from_millis(100), max_retry: Duration::from_millis(400) }
}

fn worker(lab: &Lab, server: &ScriptedServer, keeper: Kept, browser: Browser) -> (Worker, Receiver<Event>) {
    let endpoint = ServerEndpoint::new(&server.address.to_string(), "localhost", RootFingerprint::from_der(&lab.root), &lab.root).unwrap();
    Worker::start_with_browser(endpoint, lab.alice.clone(), fast(), Box::new(keeper), browser, || {}).unwrap()
}

/// Wait for the first event `wanted` accepts, skipping others. Panics after `WAIT` or when the worker is gone.
fn expect(events: &Receiver<Event>, what: &str, wanted: impl Fn(&Event) -> bool) -> Event {
    let deadline = Instant::now() + WAIT;
    loop {
        match events.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(event) if wanted(&event) => return event,
            Ok(_) => {}
            Err(error) => panic!("no {what} event: {error:?}"),
        }
    }
}

#[test]
fn an_external_sign_in_opens_a_session_that_chats_and_is_kept() {
    let lab = lab();
    let script = Arc::new(Script::default());
    let server = ScriptedServer::start(&lab, &script);
    let opened = Opened::default();
    let kept = Kept::default();
    let (alice, events) = worker(&lab, &server, kept.clone(), browser(&opened, true));

    assert!(alice.sign_in_external(ALICE));
    expect(&events, "the browser page", |event| *event == Event::WaitingForBrowser);
    let signed_in = expect(&events, "signed in", |event| matches!(event, Event::SignedIn { .. }));
    assert_eq!(signed_in, Event::SignedIn { email: ALICE.into(), rooms: Vec::new() });
    assert_eq!(kept.0.lock().unwrap().as_deref(), Some(ALICE), "the session's resume ticket is kept");

    // The browser was sent to the provider with this sign-in's values, and the finish carried the matching verifier.
    let url = opened.lock().unwrap()[0].clone();
    let (endpoint, query) = url.split_once('?').unwrap();
    assert_eq!(endpoint, "https://id.example.org/authorize/");
    let params = parse_query(query);
    let get = |k: &str| params.iter().find(|(name, _)| name == k).map(|(_, v)| v.clone()).unwrap();
    assert_eq!((get("client_id").as_str(), get("nonce").as_str()), ("chat", NONCE));
    let finishes = script.finishes.lock().unwrap().clone();
    let [(code, verifier, redirect)] = finishes.as_slice() else { panic!("one finish expected, got {}", finishes.len()) };
    assert_eq!(code, CODE);
    assert_eq!(redirect, &get("redirect_uri"));
    assert_eq!(URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())), get("code_challenge"));

    // The session is an ordinary one.
    alice.send(Command::Post { room: lab.room.clone(), text: "Hello from the organization sign-in".into() });
    expect(&events, "acknowledgement", |event| matches!(event, Event::Posted { .. }));
}

#[test]
fn cancel_ends_the_wait_and_nothing_is_finished() {
    let lab = lab();
    let script = Arc::new(Script::default());
    let server = ScriptedServer::start(&lab, &script);
    let opened = Opened::default();
    let (alice, events) = worker(&lab, &server, Kept::default(), browser(&opened, false));

    alice.sign_in_external(ALICE);
    expect(&events, "the browser page", |event| *event == Event::WaitingForBrowser);
    let asked = Instant::now();
    alice.cancel_sign_in();
    expect(&events, "the cancel", |event| *event == Event::Failed(Problem::Cancelled));
    assert!(asked.elapsed() < Duration::from_secs(2), "the wait ends at once, not at the five-minute timeout");
    assert!(script.finishes.lock().unwrap().is_empty());

    // A cancel before the next sign-in does not cancel it.
    alice.cancel_sign_in();
    alice.sign_in_external(ALICE);
    expect(&events, "the browser page again", |event| *event == Event::WaitingForBrowser);
    assert_eq!(script.begins.load(Ordering::SeqCst), 2);
}

#[test]
fn dropping_the_worker_while_it_waits_for_the_browser_returns_at_once() {
    let lab = lab();
    let script = Arc::new(Script::default());
    let server = ScriptedServer::start(&lab, &script);
    let (alice, events) = worker(&lab, &server, Kept::default(), browser(&Opened::default(), false));
    alice.sign_in_external(ALICE);
    expect(&events, "the browser page", |event| *event == Event::WaitingForBrowser);
    let dropped = Instant::now();
    drop(alice);
    assert!(dropped.elapsed() < Duration::from_secs(2));
}

#[test]
fn each_failure_is_its_own_problem() {
    let lab = lab();

    let script = Arc::new(Script { no_provider: true, ..Script::default() });
    let server = ScriptedServer::start(&lab, &script);
    let opened = Opened::default();
    let (alice, events) = worker(&lab, &server, Kept::default(), browser(&opened, true));
    alice.sign_in_external(ALICE);
    expect(&events, "no provider", |event| *event == Event::Failed(Problem::ExternalNotOffered));
    assert!(opened.lock().unwrap().is_empty(), "no browser without a provider");
    drop((alice, server));

    let script = Arc::new(Script { refuse_finish: true, ..Script::default() });
    let server = ScriptedServer::start(&lab, &script);
    let kept = Kept::default();
    let (alice, events) = worker(&lab, &server, kept.clone(), browser(&Opened::default(), true));
    alice.sign_in_external(ALICE);
    expect(&events, "refused finish", |event| *event == Event::Failed(Problem::ExternalRefused));
    assert!(kept.0.lock().unwrap().is_none());
    assert!(Problem::ExternalRefused.to_string().contains("did not accept"));
    drop((alice, server));

    let script = Arc::new(Script::default());
    let server = ScriptedServer::start(&lab, &script);
    let broken: Browser = Arc::new(|_: &str| Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no browser")));
    let (alice, events) = worker(&lab, &server, Kept::default(), broken);
    alice.sign_in_external(ALICE);
    expect(&events, "no browser", |event| *event == Event::Failed(Problem::Browser));
    assert!(script.finishes.lock().unwrap().is_empty());
    for problem in [Problem::ExternalNotOffered, Problem::Browser, Problem::NoRedirect, Problem::BrowserTimedOut, Problem::ProviderRefused, Problem::Cancelled] {
        assert!(!problem.to_string().is_empty());
    }
}
