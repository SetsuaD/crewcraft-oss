#![allow(clippy::unwrap_used)]

use std::io::{Cursor, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crewcraft::lab_client::{LabCommand, LabEndpoint, LabError, LabOutcome};
use crewcraft_client_core::room_view::Shown;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::frame::{self, MAX_FRAME, ReceivedFrame};
use crewcraft_proto::handshake;
use crewcraft_proto::push::{self, Push};
use crewcraft_proto::request::{self, Request, Response};
use crewcraft_proto::signin;
use crewcraft_tls::{Accepted, Identity, accept, server_config};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use rustls::{RootCertStore, ServerConfig, ServerConnection};

const TIMEOUT: Duration = Duration::from_secs(5);
const NAME: &str = "localhost";
const USER: &str = "alice@example.org";
const PASSWORD: &str = "  test password  ";
const ROOM: &str = "lobby";

struct Fixture {
    root: CertificateDer<'static>,
    server: Identity,
    device: Arc<dyn ResolvesClientCert>,
}

fn fixture() -> Fixture {
    let ca_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root = params.self_signed(&ca_key).unwrap().der().clone();
    let issuer = Issuer::new(params, ca_key);
    let server = issue(&issuer, vec![NAME.to_owned()], ExtendedKeyUsagePurpose::ServerAuth);
    let (chain, private_key) = issue(&issuer, Vec::new(), ExtendedKeyUsagePurpose::ClientAuth);
    let device = CertifiedKey::from_der(chain, private_key, &rustls::crypto::ring::default_provider()).unwrap();
    Fixture { root, server, device: Arc::new(SingleCertAndKey::from(device)) }
}

fn issue(issuer: &Issuer<'static, KeyPair>, names: Vec<String>, usage: ExtendedKeyUsagePurpose) -> Identity {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(names).unwrap();
    params.extended_key_usages = vec![usage];
    let leaf = params.signed_by(&key, issuer).unwrap().der().clone();
    (vec![leaf], PrivatePkcs8KeyDer::from(key.serialize_der()).into())
}

fn serve(root: CertificateDer<'static>, server: Identity, script: impl FnOnce(Option<Accepted>) + Send + 'static) -> (SocketAddr, JoinHandle<()>) {
    let mut roots = RootCertStore::empty();
    roots.add(root).unwrap();
    let config = server_config(server, roots).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        script(accept(socket, config, TIMEOUT).ok());
    });
    (address, handle)
}

fn read(stream: &mut impl Read) -> ReceivedFrame {
    frame::read_frame(stream, MAX_FRAME).unwrap().unwrap()
}

fn send(stream: &mut impl Write, payload: &[u8]) {
    stream.write_all(&frame::encode(payload).unwrap()).unwrap();
    stream.flush().unwrap();
}

fn open(accepted: Option<Accepted>) -> Accepted {
    let mut accepted = accepted.unwrap();
    accepted.stream.sock.set_read_timeout(Some(TIMEOUT)).unwrap();
    accepted.stream.sock.set_write_timeout(Some(TIMEOUT)).unwrap();
    let signed_in = read(&mut accepted.stream);
    let sign_in = signin::decode_request(signed_in.payload()).unwrap();
    assert_eq!((sign_in.email, sign_in.password, sign_in.code), (USER, PASSWORD, "123456"));
    let token = "A".repeat(signin::TOKEN_LEN);
    send(&mut accepted.stream, &signin::encode_reply(&signin::Reply::Accepted { token: &token }).unwrap());
    let hello = read(&mut accepted.stream);
    assert_eq!(handshake::decode_hello(hello.payload()).unwrap().client, "crewcraft-lab");
    let reply = handshake::Reply::Welcome { version: 1, features: 0, server: "test server".into() };
    send(&mut accepted.stream, &handshake::encode_reply(&reply).unwrap());
    accepted
}

#[test]
fn only_public_command_arguments_and_loopback_endpoints_are_accepted() {
    let fixture = fixture();
    let root = fixture.root.as_ref();
    let fingerprint = RootFingerprint::from_der(root);
    assert!(LabCommand::parse(&["sign-in"]).is_ok());
    assert!(LabCommand::parse(&["post", ROOM]).is_ok());
    assert!(LabCommand::parse(&["sync", ROOM]).is_ok());
    assert_eq!(LabCommand::parse(&["post", ROOM, "another argument"]).err(), Some(LabError::Usage));
    assert_eq!(LabEndpoint::new("192.0.2.1:4242", NAME, fingerprint, root).err(), Some(LabError::Address));
    assert_eq!(LabEndpoint::new("localhost:4242", NAME, fingerprint, root).err(), Some(LabError::Address));
    let mismatch = RootFingerprint::from_der(b"another root");
    assert_eq!(LabEndpoint::new("127.0.0.1:4242", NAME, mismatch, root).err(), Some(LabError::Trust));
}

#[test]
fn a_wrong_server_name_never_reads_protected_input() {
    let fixture = fixture();
    let (address, handle) = serve(fixture.root.clone(), fixture.server, |accepted| assert!(accepted.is_none()));
    let root = fixture.root.as_ref();
    let endpoint = LabEndpoint::new(&address.to_string(), "wrong.example.org", RootFingerprint::from_der(root), root).unwrap();
    let mut input = Cursor::new(b"unread");
    assert_eq!(endpoint.run(fixture.device, LabCommand::SignIn, &mut input).err(), Some(LabError::Handshake));
    assert_eq!(input.position(), 0);
    handle.join().unwrap();
}

#[test]
fn a_verified_peer_that_does_not_request_a_device_never_reads_protected_input() {
    let fixture = fixture();
    let (chain, key) = fixture.server;
    let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(TIMEOUT)).unwrap();
        socket.set_write_timeout(Some(TIMEOUT)).unwrap();
        ServerConnection::new(Arc::new(config)).unwrap().complete_io(&mut socket).unwrap();
    });
    let root = fixture.root.as_ref();
    let endpoint = LabEndpoint::new(&address.to_string(), NAME, RootFingerprint::from_der(root), root).unwrap();
    let mut input = Cursor::new(b"unread");
    assert_eq!(endpoint.run(fixture.device, LabCommand::SignIn, &mut input).err(), Some(LabError::Device));
    assert_eq!(input.position(), 0);
    handle.join().unwrap();
}

#[test]
fn rejects_an_incomplete_or_malformed_record_without_sending_a_sign_in() {
    for code in ["12345\n", "1234567\n", "123456", "123\r456\n", "123456\nextra\n"] {
        let fixture = fixture();
        let (address, handle) = serve(fixture.root.clone(), fixture.server, |accepted| {
            let mut accepted = accepted.unwrap();
            accepted.stream.sock.set_read_timeout(Some(TIMEOUT)).unwrap();
            let mut byte = [0];
            assert!(!matches!(accepted.stream.read(&mut byte), Ok(1)));
        });
        let root = fixture.root.as_ref();
        let endpoint = LabEndpoint::new(&address.to_string(), NAME, RootFingerprint::from_der(root), root).unwrap();
        let mut input = Cursor::new(format!("{USER}\n{PASSWORD}\n{code}").into_bytes());
        assert_eq!(endpoint.run(fixture.device, LabCommand::SignIn, &mut input).err(), Some(LabError::Input));
        handle.join().unwrap();
    }
}

#[test]
fn signs_in_then_posts_or_syncs_over_verified_tls() {
    for words in [vec!["sign-in"], vec!["post", ROOM], vec!["sync", ROOM]] {
        let fixture = fixture();
        let operation = words[0];
        let (address, handle) = serve(fixture.root.clone(), fixture.server, move |accepted| {
            let mut accepted = open(accepted);
            if operation == "sign-in" {
                return;
            }
            let frame = read(&mut accepted.stream);
            let (id, message) = request::decode_request(frame.payload()).unwrap();
            let expected = if operation == "post" {
                Request::Post { room: ROOM.into(), text: " a message ".into() }
            } else {
                Request::Sync { room: ROOM.into(), cursor: 0 }
            };
            assert_eq!(message, expected);
            send(&mut accepted.stream, &request::encode_response(id, &Response::Ok { cursor: 1 }).unwrap());
            if operation == "sync" {
                let push = Push::Posted { room: ROOM.into(), cursor: 1, author: USER.into(), html: "a message".into(), mentions: vec![] };
                send(&mut accepted.stream, &push::encode_push(&push).unwrap());
            }
        });
        let root = fixture.root.as_ref();
        let endpoint = LabEndpoint::new(&address.to_string(), NAME, RootFingerprint::from_der(root), root).unwrap();
        let extra = if operation == "post" { " a message \r\n" } else { "" };
        let mut input = Cursor::new(format!("{USER}\r\n{PASSWORD}\r\n123456\r\n{extra}").into_bytes());
        let outcome = endpoint.run(fixture.device, LabCommand::parse(&words).unwrap(), &mut input).unwrap();
        match operation {
            "sign-in" => assert!(matches!(outcome, LabOutcome::SignedIn)),
            "post" => assert!(matches!(outcome, LabOutcome::Posted { cursor: 1 })),
            _ => assert!(matches!(outcome, LabOutcome::Synced { head: 1, lines } if
                matches!(lines.as_slice(), [Shown::Line(line)] if line.html == "a message"))),
        }
        handle.join().unwrap();
    }
}

#[test]
fn one_sign_in_can_post_and_sync_on_the_same_connection() {
    let fixture = fixture();
    let (address, handle) = serve(fixture.root.clone(), fixture.server, |accepted| {
        let mut accepted = open(accepted);

        let post = read(&mut accepted.stream);
        let expected = Request::Post { room: ROOM.into(), text: "a message".into() };
        assert_eq!(request::decode_request(post.payload()).unwrap(), (1, expected));
        send(&mut accepted.stream, &request::encode_response(1, &Response::Ok { cursor: 1 }).unwrap());

        let sync = read(&mut accepted.stream);
        let expected = Request::Sync { room: ROOM.into(), cursor: 0 };
        assert_eq!(request::decode_request(sync.payload()).unwrap(), (2, expected));
        send(&mut accepted.stream, &request::encode_response(2, &Response::Ok { cursor: 1 }).unwrap());
        let push = Push::Posted { room: ROOM.into(), cursor: 1, author: USER.into(), html: "a message".into(), mentions: vec![] };
        send(&mut accepted.stream, &push::encode_push(&push).unwrap());
    });
    let root = fixture.root.as_ref();
    let endpoint = LabEndpoint::new(&address.to_string(), NAME, RootFingerprint::from_der(root), root).unwrap();
    let mut input = Cursor::new(format!("{USER}\n{PASSWORD}\n123456\n").into_bytes());
    let mut session = endpoint.open_authenticated(fixture.device, &mut input).unwrap();
    assert_eq!(session.post(ROOM, "a message"), Ok(1));
    let (head, lines) = session.sync(ROOM).unwrap();
    assert_eq!(head, 1);
    assert!(matches!(lines.as_slice(), [Shown::Line(line)] if line.html == "a message"));
    handle.join().unwrap();
}
