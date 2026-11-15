//! A real mutual-TLS exchange over the loopback interface, with a synthetic certificate authority made by rcgen.
//! Every socket has a deadline, so a regression fails the test instead of hanging it. No real names, hosts or keys.

// The helper functions here are test code too, but clippy's `allow-unwrap-in-tests` only covers `#[test]` bodies.
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crewcraft_tls::{Accepted, DeadlineSocket, Identity, TlsError, accept, client_config, connect, server_config};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::{RootCertStore, StreamOwned};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};

const HANDSHAKE: Duration = Duration::from_secs(3);
const IO: Duration = Duration::from_secs(3);

struct Ca {
    der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
}

fn ca(name: &str) -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = params.self_signed(&key).unwrap();
    Ca { der: cert.der().clone(), issuer: Issuer::new(params, key) }
}

fn identity(params: CertificateParams, key: KeyPair, signer: Option<&Ca>) -> Identity {
    let cert = match signer {
        Some(ca) => params.signed_by(&key, &ca.issuer).unwrap(),
        None => params.self_signed(&key).unwrap(),
    };
    (vec![cert.der().clone()], PrivatePkcs8KeyDer::from(key.serialize_der()).into())
}

fn server_identity(ca: &Ca) -> Identity {
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    identity(params, KeyPair::generate().unwrap(), Some(ca))
}

fn client_identity(common_name: &str, signer: Option<&Ca>) -> Identity {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, common_name);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    identity(params, KeyPair::generate().unwrap(), signer)
}

fn roots(ca: &Ca) -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.add(ca.der.clone()).unwrap();
    store
}

/// A one-connection server on an ephemeral loopback port. `join` gives the handshake outcome and, on success, what
/// the client sent after it.
struct Server {
    addr: std::net::SocketAddr,
    handle: JoinHandle<Result<(Accepted, Vec<u8>), TlsError>>,
}

fn serve(ca: &Ca, deadline: Duration) -> Server {
    let config = server_config(server_identity(ca), roots(ca)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut accepted = accept(tcp, config, deadline)?;
        accepted.stream.sock.set_read_timeout(Some(IO)).unwrap();
        accepted.stream.sock.set_write_timeout(Some(IO)).unwrap();
        let mut ping = [0u8; 4];
        accepted.stream.read_exact(&mut ping).unwrap();
        accepted.stream.write_all(b"pong").unwrap();
        accepted.stream.flush().unwrap();
        Ok((accepted, ping.to_vec()))
    });
    Server { addr, handle }
}

fn tcp(addr: std::net::SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(IO)).unwrap();
    s.set_write_timeout(Some(IO)).unwrap();
    s
}

/// What a rejected client gets: its application bytes, and the error that ended the read (if any).
fn read_all_from_client(addr: std::net::SocketAddr, config: Arc<rustls::ClientConfig>) -> (Vec<u8>, Option<std::io::ErrorKind>) {
    let mut stream = connect(tcp(addr), config, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut plain = Vec::new();
    let error = stream.read_to_end(&mut plain).err().map(|e| e.kind());
    (plain, error)
}

/// A rejected client must not see a TLS alert (rustls reports one as `InvalidData`): the connection just ends.
fn assert_dark(plain: &[u8], error: Option<std::io::ErrorKind>) {
    use std::io::ErrorKind::*;
    assert!(plain.is_empty(), "application bytes reached a rejected client: {plain:?}");
    assert!(
        matches!(error, Some(UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe)),
        "a rejected client saw {error:?} instead of a bare close"
    );
}

#[test]
fn an_enrolled_client_completes_mutual_tls_and_exchanges_bytes() {
    let ca = ca("Test CA");
    let server = serve(&ca, HANDSHAKE);
    let client_id = client_identity("alice device", Some(&ca));
    let leaf = client_id.0[0].as_ref().to_vec();
    let config = client_config(roots(&ca), Some(client_id)).unwrap();
    let stream = connect(tcp(server.addr), config, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut stream = StreamOwned::new(stream.conn, DeadlineSocket::new(stream.sock, Instant::now() + HANDSHAKE));
    stream.write_all(b"ping").unwrap();
    stream.sock.set_deadline(Instant::now() + IO);
    let mut pong = [0u8; 4];
    stream.read_exact(&mut pong).unwrap();
    assert_eq!(&pong, b"pong");
    let (accepted, ping) = server.handle.join().unwrap().unwrap();
    assert_eq!(ping, b"ping");
    // The server learns exactly which certificate the client presented.
    assert_eq!(accepted.client_certificate, leaf);
}

#[test]
fn fragmented_reads_share_one_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = tcp(listener.local_addr().unwrap());
    let (socket, _) = listener.accept().unwrap();
    let start = Instant::now();
    let mut stream = DeadlineSocket::new(socket, start + Duration::from_millis(700));
    peer.write_all(b"a").unwrap();
    let writer = thread::spawn(move || {
        thread::sleep((start + Duration::from_millis(400)).saturating_duration_since(Instant::now()));
        peer.write_all(b"b").unwrap();
        thread::sleep((start + Duration::from_millis(950)).saturating_duration_since(Instant::now()));
        peer.write_all(b"c").unwrap();
    });

    // Each gap is shorter than the initial timeout. Resetting that timeout on each read would allow the full frame.
    let mut frame = [0; 3];
    let result = stream.read_exact(&mut frame);
    writer.join().unwrap();
    let error = result.unwrap_err();
    assert!(matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock), "{error:?}");
}

#[test]
fn reset_reopens_io_for_the_next_frame() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = tcp(listener.local_addr().unwrap());
    let (socket, _) = listener.accept().unwrap();
    let mut stream = DeadlineSocket::new(socket, Instant::now());
    peer.write_all(b"ping").unwrap();
    let mut frame = [0; 4];
    assert_eq!(stream.read(&mut frame).unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(stream.write(b"late").unwrap_err().kind(), std::io::ErrorKind::TimedOut);

    stream.set_deadline(Instant::now() + IO);
    stream.read_exact(&mut frame).unwrap();
    assert_eq!(&frame, b"ping");
    stream.write_all(b"pong").unwrap();
    peer.read_exact(&mut frame).unwrap();
    assert_eq!(&frame, b"pong");
}

#[test]
fn a_client_with_no_certificate_gets_no_application_bytes_and_no_alert() {
    let ca = ca("Test CA");
    let server = serve(&ca, HANDSHAKE);
    let config = client_config(roots(&ca), None).unwrap();
    let (plain, error) = read_all_from_client(server.addr, config);
    assert_dark(&plain, error);
    assert!(matches!(server.handle.join().unwrap(), Err(TlsError::Handshake(_))));
}

#[test]
fn a_certificate_from_another_authority_gets_nothing() {
    let ca = ca("Test CA");
    let other = self::ca("Other CA");
    let server = serve(&ca, HANDSHAKE);
    let config = client_config(roots(&ca), Some(client_identity("mallory", Some(&other)))).unwrap();
    let (plain, error) = read_all_from_client(server.addr, config);
    assert_dark(&plain, error);
    assert!(matches!(server.handle.join().unwrap(), Err(TlsError::Handshake(_))));
}

#[test]
fn a_self_signed_certificate_gets_nothing() {
    let ca = ca("Test CA");
    let server = serve(&ca, HANDSHAKE);
    let config = client_config(roots(&ca), Some(client_identity("mallory", None))).unwrap();
    let (plain, error) = read_all_from_client(server.addr, config);
    assert_dark(&plain, error);
    assert!(matches!(server.handle.join().unwrap(), Err(TlsError::Handshake(_))));
}

#[test]
fn a_plain_http_request_gets_zero_bytes() {
    let ca = ca("Test CA");
    let server = serve(&ca, HANDSHAKE);
    let mut raw = tcp(server.addr);
    raw.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
    let mut received = Vec::new();
    let _ = raw.read_to_end(&mut received);
    assert!(received.is_empty(), "the server answered a non-TLS client: {received:?}");
    assert!(matches!(server.handle.join().unwrap(), Err(TlsError::Handshake(_))));
}

#[test]
fn a_client_that_says_nothing_is_cut_at_the_deadline() {
    let ca = ca("Test CA");
    let started = Instant::now();
    let server = serve(&ca, Duration::from_millis(300));
    let silent = tcp(server.addr);
    let outcome = server.handle.join().unwrap();
    assert!(matches!(outcome, Err(TlsError::Timeout)), "{outcome:?}");
    assert!(started.elapsed() < Duration::from_secs(3), "took {:?}", started.elapsed());
    drop(silent);
}

#[test]
fn a_server_certificate_from_the_wrong_authority_is_refused_by_the_client() {
    let ca = ca("Test CA");
    let other = self::ca("Other CA");
    let server = serve(&ca, HANDSHAKE);
    // The client trusts a different authority than the one that signed the server's certificate.
    let config = client_config(roots(&other), Some(client_identity("alice device", Some(&ca)))).unwrap();
    let mut stream = connect(tcp(server.addr), config, ServerName::try_from("localhost").unwrap()).unwrap();
    let outcome = stream.write_all(b"ping").and_then(|()| stream.flush());
    assert!(outcome.is_err(), "the client talked to an untrusted server");
    assert!(server.handle.join().unwrap().is_err());
}

#[test]
fn a_certificate_for_the_wrong_server_name_is_refused_by_the_client() {
    let ca = ca("Test CA");
    let server = serve(&ca, HANDSHAKE);
    let config = client_config(roots(&ca), Some(client_identity("alice device", Some(&ca)))).unwrap();
    let mut stream = connect(tcp(server.addr), config, ServerName::try_from("other.example.org").unwrap()).unwrap();
    let outcome = stream.write_all(b"ping").and_then(|()| stream.flush());
    assert!(outcome.is_err(), "the client talked to the wrong server name");
    assert!(server.handle.join().unwrap().is_err());
}
