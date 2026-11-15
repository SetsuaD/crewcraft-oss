//! A certificate this authority issues works in real mutual TLS with `crewcraft-tls`, over loopback with bounded I/O.

// The helpers here are test code too, but clippy's `allow-unwrap-in-tests` only covers `#[test]` bodies.
#![allow(clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft_pki::{Authority, Claims, Issued, LeafInfo, Status};
use crewcraft_tls::{Accepted, TlsError, accept, client_config, connect, server_config};
use rcgen::{CertificateParams, KeyPair};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};

const IO: Duration = Duration::from_secs(3);
const DAY_MS: u64 = 86_400_000;

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn chain(der: &[Vec<u8>]) -> Vec<CertificateDer<'static>> {
    der.iter().map(|c| CertificateDer::from(c.clone())).collect()
}

fn roots(root: &Authority) -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.add(CertificateDer::from(root.certificate().to_vec())).unwrap();
    store
}

struct Lab {
    root: Authority,
    issuing: Authority,
}

fn lab() -> Lab {
    let root = Authority::create_root("Test Root", now_ms()).unwrap();
    let issuing = root.create_issuing("Test Issuing", now_ms()).unwrap();
    Lab { root, issuing }
}

/// A device: its key, and a certificate issued at `at_ms` (so a test can issue one that has already expired).
fn device(lab: &mut Lab, person: &str, id: u64, at_ms: u64) -> (KeyPair, Issued) {
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
    let issued = lab.issuing.issue_device(csr.der(), &Claims { person, device_id: id }, at_ms).unwrap();
    (key, issued)
}

fn serve(lab: &Lab) -> (SocketAddr, JoinHandle<Result<Accepted, TlsError>>) {
    let server = lab.issuing.server_certificate("localhost", now_ms()).unwrap();
    let identity = (chain(&server.chain), PrivatePkcs8KeyDer::from(server.key_pkcs8).into());
    let config = server_config(identity, roots(&lab.root)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut accepted = accept(tcp, config, IO)?;
        accepted.stream.sock.set_read_timeout(Some(IO)).unwrap();
        let mut ping = [0u8; 4];
        accepted.stream.read_exact(&mut ping).unwrap();
        accepted.stream.write_all(b"pong").unwrap();
        accepted.stream.flush().unwrap();
        Ok(accepted)
    });
    (addr, handle)
}

fn dial(addr: SocketAddr, lab: &Lab, key: &KeyPair, issued: &Issued) -> std::io::Result<[u8; 4]> {
    let identity = (chain(&issued.chain), PrivatePkcs8KeyDer::from(key.serialize_der()).into());
    let config = client_config(roots(&lab.root), Some(identity)).unwrap();
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(IO)).unwrap();
    tcp.set_write_timeout(Some(IO)).unwrap();
    let mut stream = connect(tcp, config, ServerName::try_from("localhost").unwrap()).unwrap();
    stream.write_all(b"ping")?;
    let mut pong = [0u8; 4];
    stream.read_exact(&mut pong)?;
    Ok(pong)
}

#[test]
fn an_issued_device_certificate_completes_mutual_tls_and_is_known_on_reconnect() {
    let mut lab = lab();
    let (key, issued) = device(&mut lab, "alice@example.org", 1, now_ms());
    let (addr, server) = serve(&lab);
    assert_eq!(&dial(addr, &lab, &key, &issued).unwrap(), b"pong");
    let accepted = server.join().unwrap().unwrap();

    // The handshake gave the server the exact leaf; the authority says whose it is.
    assert_eq!(accepted.client_certificate, issued.certificate);
    let expected = LeafInfo { person: "alice@example.org".into(), device_id: 1, key_id: issued.key_id };
    assert_eq!(lab.issuing.status(&accepted.client_certificate, now_ms()).unwrap(), Status::Good(expected));

    // Revoked later: the TLS layer has no revocation list yet (a named boundary), so the server's re-check on
    // reconnect is what refuses the device.
    assert!(lab.issuing.revoke(&issued.serial));
    assert_eq!(lab.issuing.status(&accepted.client_certificate, now_ms()).unwrap(), Status::Revoked);
}

#[test]
fn a_renewed_certificate_works_and_keeps_the_device_identity() {
    let mut lab = lab();
    let (key, first) = device(&mut lab, "alice@example.org", 1, now_ms());
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
    let second = lab.issuing.renew(&first.certificate, csr.der(), now_ms()).unwrap();
    let (addr, server) = serve(&lab);
    assert_eq!(&dial(addr, &lab, &key, &second).unwrap(), b"pong");
    let accepted = server.join().unwrap().unwrap();
    let Status::Good(info) = lab.issuing.status(&accepted.client_certificate, now_ms()).unwrap() else { panic!("not good") };
    assert_eq!(info.key_id, first.key_id);
    assert_eq!(info.device_id, 1);
}

#[test]
fn an_expired_device_certificate_fails_the_handshake() {
    let mut lab = lab();
    // Issued 200 days ago: its 90 days are over.
    let (key, expired) = device(&mut lab, "alice@example.org", 1, now_ms() - 200 * DAY_MS);
    let (addr, server) = serve(&lab);
    assert!(dial(addr, &lab, &key, &expired).is_err());
    assert!(matches!(server.join().unwrap(), Err(TlsError::Handshake(_))));
}

#[test]
fn a_device_certificate_from_another_authority_fails_the_handshake() {
    let lab = lab();
    let mut foreign = self::lab();
    let (key, issued) = device(&mut foreign, "mallory@example.org", 1, now_ms());
    let (addr, server) = serve(&lab);
    assert!(dial(addr, &lab, &key, &issued).is_err());
    assert!(matches!(server.join().unwrap(), Err(TlsError::Handshake(_))));
    // Not issued here, so the ledger does not know it either.
    assert_eq!(lab.issuing.status(&issued.certificate, now_ms()).unwrap(), Status::Unknown);
}

#[test]
fn a_server_certificate_is_not_accepted_as_a_client_certificate() {
    let lab = lab();
    // The server's own certificate has serverAuth only: presented by a client, the handshake must fail.
    let server_identity = lab.issuing.server_certificate("localhost", now_ms()).unwrap();
    let key = KeyPair::try_from(server_identity.key_pkcs8.clone()).unwrap();
    let issued = Issued {
        certificate: server_identity.chain[0].clone(),
        chain: server_identity.chain.clone(),
        serial: Vec::new(),
        key_id: [0; 32],
        not_before: 0,
        not_after: 0,
    };
    let (addr, server) = serve(&lab);
    assert!(dial(addr, &lab, &key, &issued).is_err());
    assert!(matches!(server.join().unwrap(), Err(TlsError::Handshake(_))));
}
