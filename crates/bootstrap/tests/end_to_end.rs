//! The whole first-device path over real mutual TLS on loopback: a bootstrap handshake with the invitation key, Redeem,
//! Setup, ConfirmTotp, Activated, and then a reconnect as an enrolled device with the issued chain. The server side uses
//! `crewcraft-admission` for who may connect and `crewcraft-bootstrap` for what a bootstrap peer may do. Every socket has
//! a deadline. The fixture memory store stands in for durable storage; nothing here is a runnable server.

#![allow(clippy::unwrap_used)]

mod common;

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use common::*;
use crewcraft_admission::{Admission, Class, admit, server_config};
use crewcraft_bootstrap::{BootstrapConnection, Enroller};
use crewcraft_pki::Status;
use crewcraft_proto::bootstrap::{BootstrapResponse, decode_bootstrap_response};
use crewcraft_proto::frame::Decoder;
use crewcraft_tls::{client_config, connect};
use rcgen::CertificateParams;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

const IO: Duration = Duration::from_secs(3);

type Shared = Arc<Mutex<Enroller<MemoryStore>>>;

/// What the listener tells `admit`: live state read from the same enroller the bootstrap handler writes.
#[derive(Debug)]
struct Live(Shared);

impl Admission for Live {
    fn device_ok(&self, certificate: &[u8]) -> bool {
        let enroller = self.0.lock().unwrap();
        match enroller.authority().status(certificate, now_ms()) {
            Ok(Status::Good(info)) => enroller.activation().devices().list(&info.person).iter().any(|d| d.fingerprint == info.key_id && !d.revoked),
            _ => false,
        }
    }

    fn bootstrap_key_live(&self, public_key: &[u8; 32]) -> bool {
        self.0.lock().unwrap().activation().is_pending(public_key, now_ms())
    }
}

fn roots(der: &[u8]) -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.add(CertificateDer::from(der.to_vec())).unwrap();
    store
}

struct Lab {
    shared: Shared,
    addr: SocketAddr,
    root_cert: Vec<u8>,
    bootstrap_cert: Vec<u8>,
    bootstrap_key: Vec<u8>,
    secret: [u8; 20],
    server: JoinHandle<Vec<String>>,
}

/// A listener that handles `connections` connections in turn and reports what each one was.
fn lab(connections: usize) -> Lab {
    let w = world();
    let bootstrap_cert = {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, "bootstrap");
        params.self_signed(&w.bootstrap_key).unwrap().der().to_vec()
    };
    let bootstrap_key = w.bootstrap_key.serialize_der();
    let (root_cert, secret) = (w.root_cert.clone(), w.secret);
    let server_identity = w.enroller.authority().server_certificate("localhost", now_ms()).unwrap();
    let shared: Shared = Arc::new(Mutex::new(w.enroller));
    let identity = (
        server_identity.chain.iter().map(|c| CertificateDer::from(c.clone())).collect(),
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(server_identity.key_pkcs8.clone())),
    );
    let live = Arc::new(Live(shared.clone()));
    let config = server_config(identity, roots(&root_cert), live.clone()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let key = w.key;
    let server_shared = shared.clone();
    let server = thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..connections {
            let (tcp, _) = listener.accept().unwrap();
            let Ok(mut admitted) = admit(tcp, config.clone(), IO, &*live, (now_ms() / 1000) as i64) else {
                seen.push("refused".to_string());
                continue;
            };
            admitted.stream.sock.set_read_timeout(Some(IO)).unwrap();
            match admitted.class {
                Class::Bootstrap(bootstrap_pub) => {
                    assert_eq!(bootstrap_pub, key);
                    seen.push("bootstrap".to_string());
                    let mut conn = BootstrapConnection::new(bootstrap_pub, "127.0.0.1");
                    let mut buf = [0u8; 4096];
                    // A bootstrap peer gets nothing but the two enrollment calls; anything else ends the connection.
                    while let Ok(n) = admitted.stream.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        let out = conn.receive(&mut server_shared.lock().unwrap(), &buf[..n]);
                        if !out.bytes.is_empty() {
                            admitted.stream.write_all(&out.bytes).unwrap();
                            admitted.stream.flush().unwrap();
                        }
                        if !out.open {
                            break;
                        }
                    }
                }
                Class::Device => {
                    // Recheck before any application I/O, as the listener must.
                    if admitted.recheck(&*live, (now_ms() / 1000) as i64).is_err() {
                        seen.push("device-recheck-failed".to_string());
                        continue;
                    }
                    seen.push("device".to_string());
                    let mut ping = [0u8; 4];
                    admitted.stream.read_exact(&mut ping).unwrap();
                    admitted.stream.write_all(b"pong").unwrap();
                    admitted.stream.flush().unwrap();
                }
            }
        }
        seen
    });
    Lab { shared, addr, root_cert, bootstrap_cert, bootstrap_key, secret, server }
}

fn tcp(addr: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(IO)).unwrap();
    s.set_write_timeout(Some(IO)).unwrap();
    s
}

type Client = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn dial(lab: &Lab, chain: Vec<Vec<u8>>, key: Vec<u8>) -> Client {
    let identity = (chain.into_iter().map(CertificateDer::from).collect(), PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key)));
    let config = client_config(roots(&lab.root_cert), Some(identity)).unwrap();
    connect(tcp(lab.addr), config, ServerName::try_from("localhost").unwrap()).unwrap()
}

/// Read until one whole response frame has arrived.
fn read_response(stream: &mut Client) -> (u32, BootstrapResponse) {
    let mut decoder = Decoder::new();
    let mut buf = [0u8; 4096];
    loop {
        if let Some(payload) = decoder.next_frame().unwrap() {
            return decode_bootstrap_response(&payload).unwrap();
        }
        let n = stream.read(&mut buf).unwrap();
        assert!(n > 0, "the server closed before a whole reply");
        decoder.push(&buf[..n]);
    }
}

/// A refused client: no plaintext and a bare close (never a TLS alert).
fn assert_dark(mut stream: Client) {
    let _ = stream.write_all(b"ping");
    let _ = stream.flush();
    let mut plain = Vec::new();
    let error = stream.read_to_end(&mut plain).err().map(|e| e.kind());
    assert!(plain.is_empty(), "application bytes reached a refused client: {plain:?}");
    assert!(
        matches!(error, Some(ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe)),
        "a refused client saw {error:?} instead of a bare close"
    );
}

#[test]
fn a_first_device_enrolls_over_mutual_tls_and_reconnects_with_the_issued_chain() {
    let lab = lab(3);
    let (device_key, csr) = device_csr();

    // 1. The bootstrap handshake with the invitation key, then Redeem. The reply is Setup and carries no certificate.
    let mut bootstrap = dial(&lab, vec![lab.bootstrap_cert.clone()], lab.bootstrap_key.clone());
    bootstrap.write_all(&redeem_frame(1, "laptop", &csr, PASSWORD)).unwrap();
    let (id, setup) = read_response(&mut bootstrap);
    assert_eq!(id, 1);
    let BootstrapResponse::Setup { totp_uri } = setup else { panic!("not Setup") };
    assert!(totp_uri.starts_with("otpauth://totp/"));
    assert!(lab.shared.lock().unwrap().services().committed.is_empty(), "nothing is committed before the code");

    // 2. Confirm on the same connection. Only now does the device get its chain.
    let code = code_at(lab.secret, lab.shared.lock().unwrap().services().clock_ms);
    bootstrap.write_all(&confirm_frame(2, &code)).unwrap();
    let (id, activated) = read_response(&mut bootstrap);
    assert_eq!(id, 2);
    let BootstrapResponse::Activated { certificate, issuer_certificate } = activated else { panic!("not Activated") };
    {
        let enroller = lab.shared.lock().unwrap();
        let committed = &enroller.services().committed;
        assert_eq!(committed.len(), 1);
        assert_eq!(committed[0].chain, vec![certificate.clone(), issuer_certificate.clone()]);
        assert_eq!(enroller.activation().devices().list(EMAIL).len(), 1);
    }

    // 3. Reconnect as an enrolled device with exactly the chain the server issued and the key that signed the request.
    let mut device = dial(&lab, vec![certificate.clone(), issuer_certificate], device_key.serialize_der());
    device.write_all(b"ping").unwrap();
    let mut pong = [0u8; 4];
    device.read_exact(&mut pong).unwrap();
    assert_eq!(&pong, b"pong");

    // 4. The invitation is used up: the bootstrap certificate no longer gets in, and a client with no certificate never did.
    assert_dark(dial(&lab, vec![lab.bootstrap_cert.clone()], lab.bootstrap_key.clone()));
    let seen = lab.server.join().unwrap();
    assert_eq!(seen, ["bootstrap", "device", "refused"]);
}

#[test]
fn a_bootstrap_peer_that_sends_anything_else_is_cut_off_without_a_reply() {
    let lab = lab(1);
    let (_key, _csr) = device_csr();
    let mut bootstrap = dial(&lab, vec![lab.bootstrap_cert.clone()], lab.bootstrap_key.clone());
    // An ordinary chat-protocol frame (a Ping request, tag 5 in the request codec) on a bootstrap connection.
    let ping = crewcraft_proto::request::encode_request(1, &crewcraft_proto::request::Request::Ping).unwrap();
    bootstrap.write_all(&crewcraft_proto::frame::encode(&ping).unwrap()).unwrap();
    let mut plain = Vec::new();
    let error = bootstrap.read_to_end(&mut plain).err().map(|e| e.kind());
    assert!(plain.is_empty(), "the server answered a chat request on a bootstrap connection: {plain:?}");
    assert!(
        matches!(error, Some(ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe)),
        "{error:?}"
    );
    assert_eq!(lab.server.join().unwrap(), ["bootstrap"]);
    // Nothing was staged by it.
    assert_eq!(lab.shared.lock().unwrap().activation().pending_count(), 0);
}
