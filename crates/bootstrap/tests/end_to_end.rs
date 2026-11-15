//! The whole first-device path over real mutual TLS on loopback, with the durable store behind it and a RESTART in the
//! middle: a bootstrap handshake with the invitation key, Redeem, Setup, ConfirmTotp, Activated; the server process is
//! stopped and its journal reopened; then the device reconnects with exactly the issued chain and is admitted from the
//! reloaded store alone. Every socket has a deadline. No listener command exists; this is a test harness only.

#![allow(clippy::unwrap_used)]

mod common;

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use common::*;
use crewcraft_accounts::password;
use crewcraft_admission::{Class, admit, server_config};
use crewcraft_bootstrap::{BootstrapConnection, DurableAdmission, Enroller, StoreServices, receive_shared};
use crewcraft_proto::bootstrap::{BootstrapResponse, decode_bootstrap_response};
use crewcraft_proto::frame::Decoder;
use crewcraft_server_core::account_journal::AccountJournal;
use crewcraft_server_core::account_store::AccountStore;
use crewcraft_tls::{client_config, connect};
use rcgen::CertificateParams;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

const IO: Duration = Duration::from_secs(3);

type Shared = Arc<Mutex<Enroller<StoreServices<AccountJournal, TestEnv>>>>;

fn roots(der: &[u8]) -> RootCertStore {
    let mut store = RootCertStore::empty();
    store.add(CertificateDer::from(der.to_vec())).unwrap();
    store
}

/// The server's certificate and key as bytes, so the same identity serves before and after the restart.
struct Identity {
    chain: Vec<Vec<u8>>,
    key: Vec<u8>,
}

/// A listener that handles `connections` connections in turn and reports what each one was.
fn listen(
    shared: Shared,
    identity: &Identity,
    root_cert: &[u8],
    bootstrap_key: [u8; 32],
    connections: usize,
) -> (SocketAddr, JoinHandle<Vec<String>>) {
    let live = {
        let enroller = shared.lock().unwrap();
        Arc::new(DurableAdmission::new(enroller.services().shared(), Arc::new(real_now_ms), enroller.poison_flag()))
    };
    let id = (
        identity.chain.iter().map(|c| CertificateDer::from(c.clone())).collect(),
        PrivateKeyDer::from(PrivatePkcs8KeyDer::from(identity.key.clone())),
    );
    let config = server_config(id, roots(root_cert), live.clone()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..connections {
            let (tcp, _) = listener.accept().unwrap();
            let now = (real_now_ms() / 1000) as i64;
            let Ok(mut admitted) = admit(tcp, config.clone(), IO, &*live, now) else {
                seen.push("refused".to_string());
                continue;
            };
            admitted.stream.sock.set_read_timeout(Some(IO)).unwrap();
            match admitted.class {
                Class::Bootstrap(key) => {
                    assert_eq!(key, bootstrap_key);
                    seen.push("bootstrap".to_string());
                    let mut conn = BootstrapConnection::new(key, "127.0.0.1");
                    let mut buf = [0u8; 4096];
                    // A bootstrap peer gets nothing but the two enrollment calls; anything else ends the connection.
                    while let Ok(n) = admitted.stream.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        // The lock is taken for each short step only; the password is hashed with no lock held.
                        let out = receive_shared(&mut conn, &shared, &|p| password::hash(p).ok(), &buf[..n]);
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
                    if admitted.recheck(&*live, now).is_err() {
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
    (addr, handle)
}

type Client = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

fn dial(addr: SocketAddr, root_cert: &[u8], chain: Vec<Vec<u8>>, key: Vec<u8>) -> Client {
    let identity = (chain.into_iter().map(CertificateDer::from).collect(), PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key)));
    let config = client_config(roots(root_cert), Some(identity)).unwrap();
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_read_timeout(Some(IO)).unwrap();
    tcp.set_write_timeout(Some(IO)).unwrap();
    connect(tcp, config, ServerName::try_from("localhost").unwrap()).unwrap()
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
fn a_first_device_enrolls_survives_a_restart_and_reconnects_with_the_issued_chain() {
    let path = std::env::temp_dir().join(format!("crewcraft-bootstrap-e2e-{}.journal", std::process::id()));
    let _ = fs::remove_file(&path);
    let p = parts();
    let bootstrap_cert = CertificateParams::new(Vec::<String>::new()).unwrap().self_signed(&p.bootstrap_key).unwrap().der().to_vec();
    let bootstrap_key = p.bootstrap_key.serialize_der();
    let (root_cert, key, secret) = (p.root_cert.clone(), p.key, p.secret);
    let w = world_over(AccountStore::create(&path, service_key()).unwrap(), p, real_now_ms(), true);
    let clock = w.now();
    let server = w.enroller.authority().server_certificate("localhost", clock).unwrap();
    let identity = Identity { chain: server.chain.clone(), key: server.key_pkcs8.clone() };
    let shared: Shared = Arc::new(Mutex::new(w.enroller));
    let (device_key, csr) = device_csr();

    // 1. Bootstrap handshake with the invitation key, then Redeem. The reply is Setup and carries no certificate.
    let (addr, first) = listen(shared.clone(), &identity, &root_cert, key, 2);
    let mut bootstrap = dial(addr, &root_cert, vec![bootstrap_cert.clone()], bootstrap_key.clone());
    bootstrap.write_all(&redeem_frame(1, "laptop", &csr, PASSWORD)).unwrap();
    let (id, setup) = read_response(&mut bootstrap);
    assert_eq!(id, 1);
    let BootstrapResponse::Setup { totp_uri } = setup else { panic!("not Setup") };
    assert!(totp_uri.starts_with("otpauth://totp/"));
    assert!(shared.lock().unwrap().services().store().person(EMAIL).is_none(), "nothing is durable before the code");

    // 2. Confirm on the same connection. Only now does the device get its chain.
    let code = code_at(secret, clock);
    bootstrap.write_all(&confirm_frame(2, &code)).unwrap();
    let (id, activated) = read_response(&mut bootstrap);
    assert_eq!(id, 2);
    let BootstrapResponse::Activated { certificate, issuer_certificate } = activated else { panic!("not Activated") };
    drop(bootstrap);
    // The consumed invitation no longer gets in, even before any restart.
    assert_dark(dial(addr, &root_cert, vec![bootstrap_cert.clone()], bootstrap_key.clone()));
    assert_eq!(first.join().unwrap(), ["bootstrap", "refused"]);

    // 3. The process stops. A new one opens the same journal with the same service key and nothing else.
    let enroller = Arc::try_unwrap(shared).unwrap().into_inner().unwrap();
    let (authority, services) = enroller.into_parts();
    let (store, env) = services.into_parts();
    drop(store);
    let reopened = StoreServices::new(AccountStore::open(&path, service_key()).unwrap(), env);
    let shared: Shared = Arc::new(Mutex::new(Enroller::new(authority, reopened)));
    assert_eq!(shared.lock().unwrap().services().store().device_certificate(1).unwrap(), certificate.as_slice());

    // 4. The device reconnects with exactly the issued chain and the key that signed the request, and is admitted from the
    //    reloaded store. A client with the old bootstrap certificate is still refused.
    let (addr, second) = listen(shared, &identity, &root_cert, key, 2);
    let mut device = dial(addr, &root_cert, vec![certificate, issuer_certificate], device_key.serialize_der());
    device.write_all(b"ping").unwrap();
    let mut pong = [0u8; 4];
    device.read_exact(&mut pong).unwrap();
    assert_eq!(&pong, b"pong");
    assert_dark(dial(addr, &root_cert, vec![bootstrap_cert], bootstrap_key));
    assert_eq!(second.join().unwrap(), ["device", "refused"]);
}

#[test]
fn a_bootstrap_peer_that_sends_anything_else_is_cut_off_without_a_reply() {
    let path = std::env::temp_dir().join(format!("crewcraft-bootstrap-e2e-cut-{}.journal", std::process::id()));
    let _ = fs::remove_file(&path);
    let p = parts();
    let bootstrap_cert = CertificateParams::new(Vec::<String>::new()).unwrap().self_signed(&p.bootstrap_key).unwrap().der().to_vec();
    let bootstrap_key = p.bootstrap_key.serialize_der();
    let (root_cert, key) = (p.root_cert.clone(), p.key);
    let w = world_over(AccountStore::create(&path, service_key()).unwrap(), p, real_now_ms(), true);
    let server = w.enroller.authority().server_certificate("localhost", w.now()).unwrap();
    let identity = Identity { chain: server.chain.clone(), key: server.key_pkcs8.clone() };
    let shared: Shared = Arc::new(Mutex::new(w.enroller));
    let (addr, handle) = listen(shared.clone(), &identity, &root_cert, key, 1);
    let mut bootstrap = dial(addr, &root_cert, vec![bootstrap_cert], bootstrap_key);
    // An ordinary chat-protocol frame (a Ping request) on a bootstrap connection.
    let ping = crewcraft_proto::request::encode_request(1, &crewcraft_proto::request::Request::Ping).unwrap();
    bootstrap.write_all(&crewcraft_proto::frame::encode(&ping).unwrap()).unwrap();
    let mut plain = Vec::new();
    let error = bootstrap.read_to_end(&mut plain).err().map(|e| e.kind());
    assert!(plain.is_empty(), "the server answered a chat request on a bootstrap connection: {plain:?}");
    assert!(
        matches!(error, Some(ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe)),
        "{error:?}"
    );
    assert_eq!(handle.join().unwrap(), ["bootstrap"]);
    assert_eq!(shared.lock().unwrap().staged_count(), 0);
}
