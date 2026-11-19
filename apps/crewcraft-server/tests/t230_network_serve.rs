//! A network server: any listen address, a certificate for the configured name, the real peer address. Task T230.
#![allow(clippy::unwrap_used)]

use std::collections::VecDeque;
use std::fs;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::bootstrap_transport::BootstrapEndpoint;
use crewcraft::chat_session::ChatSession;
use crewcraft::enroll_client::{EnrollmentRequest, FirstTotpCode};
use crewcraft_bootstrap::Environment;
use crewcraft_client_core::notify::Settings;
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::frame;
use crewcraft_proto::handshake::{Hello, ServerSide};
use crewcraft_proto::signin::{SignIn, encode_request};
use crewcraft_server::lab_bootstrap::{bootstrap_handler, source_key};
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{BootstrapStream, LabOptions, Timeouts};
use crewcraft_server::listener::Listener;
use crewcraft_server::server_name::ServerName;
use crewcraft_server_core::invites::Invite;
use crewcraft_tls::{DeadlineSocket, client_config, connect};
use crewcraft_totp::Totp;
use rcgen::{CertificateParams, KeyPair, PublicKeyData};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

const WAIT: Duration = Duration::from_secs(10);
const STEP_MS: u64 = 30_000;
const PASSWORD: &str = "synthetic network serve password";
const EMAIL: &str = "pilot@example.org";
const TOTP_SECRET: [u8; 20] = [41; 20];
const NAME: &str = "chat.example.org";

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("crewcraft-t230-{}-{nonce}", std::process::id()));
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

fn cutoff() -> Instant {
    Instant::now() + WAIT
}

fn options(address: &str) -> LabOptions {
    LabOptions {
        address: address.parse().unwrap(),
        capacity: NonZeroUsize::new(4).unwrap(),
        timeouts: Timeouts { handshake: WAIT, sign_in: WAIT, signed_in_frame: WAIT, bootstrap: WAIT },
        protocol: ServerSide { min_version: 1, max_version: 1, features: 0, name: "test server".into() },
    }
}

fn totp() -> Totp {
    Totp::with_defaults(TOTP_SECRET.to_vec()).unwrap()
}

fn code_at(now_ms: u64) -> String {
    totp().generate(now_ms / 1000)
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
    clock: Arc<AtomicU64>,
    peers: Arc<Mutex<Vec<IpAddr>>>,
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

/// Serve through the network path, recording the peer address each bootstrap connection is given.
fn start(state: LabInstallation, address: &str, name: &ServerName) -> Running {
    let clock = Arc::new(AtomicU64::new(wall_ms()));
    let server_clock = clock.clone();
    let server = LabRuntime::bind_network(state, options(address), name, move || server_clock.load(Ordering::SeqCst)).unwrap();
    let address = server.local_addr().unwrap();
    let environment = TestEnvironment { clock: clock.clone(), secrets: VecDeque::from([TOTP_SECRET]) };
    let peers = Arc::new(Mutex::new(Vec::new()));
    let seen = peers.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let thread = thread::spawn(move || {
        server.serve(&shutdown, move |accounts, issuer| {
            let inner = bootstrap_handler(accounts, issuer, environment);
            Ok(move |key: [u8; 32], stream: &mut BootstrapStream| {
                seen.lock().unwrap().push(stream.peer_ip());
                inner(key, stream);
            })
        })
    });
    Running { address, clock, peers, stop, thread: Some(thread) }
}

fn installation(directory: &TestDirectory, invitation: &EnrollmentCode, now_ms: u64) -> (LabInstallation, Vec<u8>) {
    let mut state = LabInstallation::initialize(&directory.0.join("state"), now_ms).unwrap();
    let root_der = state.issuer.root_certificate().to_vec();
    let invite = Invite { email: EMAIL.into(), bootstrap_pub: invitation.bootstrap_public_key(), expires_ms: now_ms + 300_000 };
    state.accounts.issue_invite(invite, now_ms).unwrap();
    (state, root_der)
}

fn roots(root_der: &[u8]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root_der)).unwrap();
    roots
}

fn endpoint(address: SocketAddr, name: &str, root_der: &[u8]) -> BootstrapEndpoint {
    BootstrapEndpoint::new(&address.to_string(), name, RootFingerprint::from_der(root_der), root_der).unwrap()
}

/// Enroll through the endpoint and return a client configuration holding the issued device certificate.
fn enroll(endpoint: &BootstrapEndpoint, invitation: &EnrollmentCode, root_der: &[u8], now_ms: u64) -> Arc<ClientConfig> {
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
    let expected_spki = key.subject_public_key_info();
    let request =
        EnrollmentRequest { device_name: "Synthetic Test Device", csr: csr.der().as_ref(), password: PASSWORD, expected_spki: &expected_spki };
    let chain = endpoint.open(invitation, WAIT).unwrap().enroll(request, |_, _| FirstTotpCode::parse(code_at(now_ms))).unwrap();
    let identity = (vec![chain.leaf, chain.issuer], PrivatePkcs8KeyDer::from(key.serialize_der()).into());
    client_config(roots(root_der), Some(identity)).unwrap()
}

type ClientStream = StreamOwned<ClientConnection, DeadlineSocket>;

fn dial(address: SocketAddr, config: Arc<ClientConfig>, name: &str) -> ClientStream {
    let socket = TcpStream::connect_timeout(&address, WAIT).unwrap();
    let tls = connect(socket, config, rustls::pki_types::ServerName::try_from(name.to_owned()).unwrap()).unwrap();
    StreamOwned::new(tls.conn, DeadlineSocket::new(tls.sock, cutoff()))
}

fn handshake(stream: &mut ClientStream) -> io::Result<()> {
    while stream.conn.is_handshaking() {
        stream.conn.complete_io(&mut stream.sock)?;
    }
    Ok(())
}

fn served_names(stream: &ClientStream) -> (Vec<String>, Vec<Vec<u8>>) {
    let leaf = &stream.conn.peer_certificates().unwrap()[0];
    let (_, certificate) = X509Certificate::from_der(leaf.as_ref()).unwrap();
    let extension = certificate.subject_alternative_name().unwrap().unwrap();
    let names = &extension.value.general_names;
    let dns = names.iter().filter_map(|name| if let GeneralName::DNSName(dns) = name { Some(dns.to_string()) } else { None }).collect();
    let ips = names.iter().filter_map(|name| if let GeneralName::IPAddress(ip) = name { Some(ip.to_vec()) } else { None }).collect();
    (dns, ips)
}

/// No application byte reaches a client the server did not admit.
fn assert_dark(mut stream: ClientStream, code: &str) {
    let request = SignIn { email: EMAIL, password: PASSWORD, code };
    let bytes = frame::encode(&encode_request(&request).unwrap()).unwrap();
    let _ = stream.write_all(&bytes);
    let _ = stream.flush();
    let mut byte = [0];
    match stream.read(&mut byte) {
        Ok(read) => assert_eq!(read, 0),
        Err(error) => assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::InvalidData
        )),
    }
}

#[test]
fn the_network_path_binds_any_address_and_the_lab_path_still_refuses_it() {
    let capacity = NonZeroUsize::new(1).unwrap();
    for address in ["0.0.0.0:0", "192.0.2.10:0", "[2001:db8::10]:0"] {
        let refused = Listener::bind(address.parse().unwrap(), capacity).err().unwrap();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
    }
    let listener = Listener::bind_network("0.0.0.0:0".parse().unwrap(), capacity).unwrap();
    let bound = listener.local_addr().unwrap();
    assert!(bound.ip().is_unspecified());
    assert_ne!(bound.port(), 0);
    // Every interface includes loopback.
    TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, bound.port())), WAIT).unwrap();
    drop(listener);

    let directory = TestDirectory::new();
    let now = wall_ms();
    let lab = LabInstallation::initialize(&directory.0.join("lab"), now).unwrap();
    let refused = LabRuntime::bind(lab, options("0.0.0.0:0"), move || now).err().unwrap();
    assert_eq!(refused.kind(), io::ErrorKind::InvalidInput);
    let network = LabInstallation::initialize(&directory.0.join("network"), now).unwrap();
    let runtime = LabRuntime::bind_network(network, options("0.0.0.0:0"), &ServerName::parse(NAME).unwrap(), move || now).unwrap();
    assert!(runtime.local_addr().unwrap().ip().is_unspecified());
}

#[test]
fn server_names_are_dns_names_or_addresses() {
    assert_eq!(ServerName::parse("Chat.Example.ORG").unwrap(), ServerName::Dns(NAME.into()));
    assert_eq!(ServerName::parse("localhost").unwrap().certificate_name(), "localhost");
    assert_eq!(ServerName::parse("chat-1.example.org").unwrap().with_port(7443), "chat-1.example.org:7443");
    assert_eq!(ServerName::parse("192.0.2.10").unwrap(), ServerName::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))));
    assert_eq!(ServerName::parse("192.0.2.10").unwrap().with_port(7443), "192.0.2.10:7443");
    let v6 = ServerName::parse("2001:DB8::1").unwrap();
    assert_eq!(v6, ServerName::parse("[2001:db8::1]").unwrap());
    assert_eq!(v6.certificate_name(), "2001:db8::1");
    assert_eq!(v6.with_port(7443), "[2001:db8::1]:7443");
    assert_eq!(ServerName::parse("::ffff:192.0.2.10").unwrap(), ServerName::parse("192.0.2.10").unwrap());
    let longest_label = "a".repeat(63);
    assert!(ServerName::parse(&format!("{longest_label}.example.org")).is_ok());

    let too_long_label = format!("{}.example.org", "a".repeat(64));
    let too_long_name = format!("{}.example.org", vec!["a".repeat(60); 5].join("."));
    for refused in [
        "",
        ".",
        "example.org.",
        ".example.org",
        "chat..example.org",
        "-chat.example.org",
        "chat-.example.org",
        "*.example.org",
        "chat_1.example.org",
        "chat example.org",
        "ch\u{e4}t.example.org",
        "chat.example.org:7443",
        "192.0.2",
        "0.0.0.0",
        "::",
        "[::]",
        "[192.0.2.10]",
        "224.0.0.1", // multicast, not a host; sanitize-scan: allow
        "ff02::1",
        "255.255.255.255", // broadcast, not a host; sanitize-scan: allow
        too_long_label.as_str(),
        too_long_name.as_str(),
    ] {
        assert!(ServerName::parse(refused).is_err(), "{refused:?} was accepted");
    }
}

#[test]
fn enrollment_limits_count_the_real_source_address() {
    let v4 = |text: &str| source_key(text.parse().unwrap());
    assert_eq!(v4("192.0.2.7"), "192.0.2.7");
    assert_eq!(v4("::ffff:192.0.2.7"), "192.0.2.7");
    assert_ne!(v4("192.0.2.7"), v4("192.0.2.8"));
    // A host is usually given a whole IPv6 /64, so its addresses share one bucket.
    assert_eq!(v4("2001:db8:1:2:3:4:5:6"), v4("2001:db8:1:2::9"));
    assert_ne!(v4("2001:db8:1:2::9"), v4("2001:db8:1:3::9"));
}

#[test]
fn a_client_pinned_to_the_configured_name_enrolls_and_signs_in_and_others_get_nothing() {
    let directory = TestDirectory::new();
    let invitation = EnrollmentCode::from_bytes([3; 20]);
    let setup_time = wall_ms();
    let (mut state, root_der) = installation(&directory, &invitation, setup_time);
    let room = state.rooms.create_room(EMAIL, "General").unwrap();
    let name = ServerName::parse(NAME).unwrap();
    let server = start(state, "127.0.0.1:0", &name);
    server.clock.store(setup_time, Ordering::SeqCst);

    // A client that expects another name refuses the server before it sends anything.
    assert!(endpoint(server.address, "other.example.org", &root_der).open(&invitation, WAIT).is_err());
    let config = enroll(&endpoint(server.address, NAME, &root_der), &invitation, &root_der, setup_time);
    assert_eq!(*server.peers.lock().unwrap(), vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);

    let mut stream = dial(server.address, config.clone(), NAME);
    handshake(&mut stream).unwrap();
    assert_eq!(served_names(&stream), (vec![NAME.to_owned()], vec![]));
    drop(stream);
    let mut wrong_name = dial(server.address, config.clone(), "other.example.org");
    assert!(handshake(&mut wrong_name).is_err());

    let sign_in_at = setup_time + 2 * STEP_MS;
    server.clock.store(sign_in_at, Ordering::SeqCst);
    let code = code_at(sign_in_at);
    let request = SignIn { email: EMAIL, password: PASSWORD, code: &code };
    let hello = Hello { min_version: 1, max_version: 1, features: 0, client: "test client".into() };
    let set_deadline = |stream: &mut ClientStream, deadline: Instant| stream.sock.set_deadline(deadline);
    let mut chat =
        ChatSession::connect(dial(server.address, config, NAME), set_deadline, &request, hello, Settings::new(EMAIL), WAIT, cutoff()).unwrap();
    assert!(chat.post(&room, "Hello over the network path", sign_in_at, 0, cutoff()).is_ok());
    drop(chat);

    assert_dark(dial(server.address, client_config(roots(&root_der), None).unwrap(), NAME), &code);
    // Only the one enrollment reached the bootstrap handler.
    assert_eq!(server.peers.lock().unwrap().len(), 1);
}

#[test]
fn an_address_name_is_certified_and_an_ipv6_peer_is_seen_as_itself() {
    let directory = TestDirectory::new();
    let invitation = EnrollmentCode::from_bytes([4; 20]);
    let setup_time = wall_ms();
    let (state, root_der) = installation(&directory, &invitation, setup_time);
    // The address of the old fixed peer label would be wrong here, so this shows the socket's address is used.
    if let Err(error) = std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) {
        eprintln!("skipped: this system has no IPv6 loopback ({error})");
        return;
    }
    let name = ServerName::parse("::1").unwrap();
    let server = start(state, "[::1]:0", &name);
    server.clock.store(setup_time, Ordering::SeqCst);
    let config = enroll(&endpoint(server.address, "::1", &root_der), &invitation, &root_der, setup_time);
    assert_eq!(*server.peers.lock().unwrap(), vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]);

    let mut stream = dial(server.address, config, "::1");
    handshake(&mut stream).unwrap();
    assert_eq!(served_names(&stream), (vec![], vec![Ipv6Addr::LOCALHOST.octets().to_vec()]));
}
