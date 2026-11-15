#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft_admission::Admission;
use crewcraft_pki::{Authority, Claims};
use crewcraft_proto::bootstrap::{self, BootstrapRequest, BootstrapResponse};
use crewcraft_proto::frame;
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::signin::{self, Reply, SignIn};
use crewcraft_server::device_session::{AuthError, CommittedSignIn, DeviceAuth};
use crewcraft_server::lab_server::{LabOptions, LabServer, Timeouts};
use crewcraft_server_core::durable::DurableServer;
use crewcraft_tls::{DeadlineSocket, Identity, client_config, connect};
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519, PublicKeyData};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const WAIT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct KnownPeers {
    device: Vec<u8>,
    bootstrap_key: [u8; 32],
}

impl Admission for KnownPeers {
    fn device_ok(&self, certificate: &[u8]) -> bool {
        self.device == certificate
    }

    fn bootstrap_key_live(&self, key: &[u8; 32]) -> bool {
        self.bootstrap_key == *key
    }
}

struct RejectCredentials;

impl DeviceAuth for RejectCredentials {
    type Session = ();

    fn sign_in(&self, _credentials: SignIn<'_>, _now_ms: u64) -> Result<Option<CommittedSignIn<Self::Session>>, AuthError> {
        Ok(None)
    }

    fn with_live_session<T>(&self, _session: &Self::Session, _now_ms: u64, _action: impl FnOnce() -> T) -> Result<Option<T>, AuthError> {
        Ok(None)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Routed {
    Device(Vec<u8>),
    Bootstrap([u8; 32]),
}

fn elapsed_since_epoch() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

fn now_ms() -> u64 {
    elapsed_since_epoch().as_millis() as u64
}

fn identity(chain: Vec<Vec<u8>>, key: Vec<u8>) -> Identity {
    (chain.into_iter().map(CertificateDer::from).collect(), PrivatePkcs8KeyDer::from(key).into())
}

fn dial(address: SocketAddr, config: Arc<ClientConfig>) -> StreamOwned<ClientConnection, DeadlineSocket> {
    let tcp = TcpStream::connect_timeout(&address, WAIT).unwrap();
    let stream = connect(tcp, config, ServerName::try_from("localhost").unwrap()).unwrap();
    StreamOwned::new(stream.conn, DeadlineSocket::new(stream.sock, Instant::now() + WAIT))
}

fn assert_no_app_bytes(mut stream: impl Read + Write, payload: &[u8]) {
    let _ = stream.write_all(&frame::encode(payload).unwrap());
    let _ = stream.flush();
    let mut byte = [0; 1];
    match stream.read(&mut byte) {
        Ok(n) => assert_eq!(n, 0),
        Err(error) => assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe
        )),
    }
}

struct JournalPath(PathBuf);

impl Drop for JournalPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct Run {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<io::Result<()>>>,
}

impl Drop for Run {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn verified_classes_route_to_different_handlers_and_refusals_never_fall_back() {
    let now = now_ms();
    let root = Authority::create_root("Test Root", now).unwrap();
    let mut issuer = root.create_issuing("Test Issuing", now).unwrap();
    let server_id = issuer.server_certificate("localhost", now).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root.certificate().to_vec())).unwrap();

    let device_key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&device_key).unwrap();
    let device = issuer.issue_device(csr.der(), &Claims { person: "reader@example.org", device_id: 1 }, now).unwrap();
    let client = client_config(roots.clone(), Some(identity(device.chain, device_key.serialize_der()))).unwrap();

    let bootstrap_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let raw_key: [u8; 32] = bootstrap_key.der_bytes().try_into().unwrap();
    let bootstrap_leaf = CertificateParams::new(Vec::<String>::new()).unwrap().self_signed(&bootstrap_key).unwrap();
    let bootstrap_client = client_config(roots.clone(), Some(identity(vec![bootstrap_leaf.der().to_vec()], bootstrap_key.serialize_der()))).unwrap();
    let no_certificate = client_config(roots.clone(), None).unwrap();

    let name = format!("crewcraft-t219-{}-{}.journal", std::process::id(), elapsed_since_epoch().as_nanos());
    let journal = JournalPath(std::env::temp_dir().join(name));
    let options = LabOptions {
        address: "127.0.0.1:0".parse().unwrap(),
        capacity: NonZeroUsize::new(4).unwrap(),
        timeouts: Timeouts { handshake: WAIT, sign_in: WAIT, signed_in_frame: WAIT, bootstrap: WAIT },
        protocol: ServerSide { min_version: 1, max_version: 1, features: 0, name: "test server".into() },
    };
    let known = Arc::new(KnownPeers { device: device.certificate.clone(), bootstrap_key: raw_key });
    let rooms = DurableServer::open(&journal.0).unwrap();
    let server = LabServer::bind(options, identity(server_id.chain, server_id.key_pkcs8), roots, known, rooms).unwrap();
    let address = server.local_addr().unwrap();
    let (routed, routes) = mpsc::channel();
    let device_routed = routed.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let shutdown = stop.clone();
    let worker = thread::spawn(move || {
        server.serve(
            &shutdown,
            now_ms,
            move |certificate, _| {
                let _ = device_routed.send(Routed::Device(certificate.to_vec()));
                Ok(RejectCredentials)
            },
            move |key, stream| {
                let _ = routed.send(Routed::Bootstrap(key));
                if let Ok(Some(request)) = frame::read_frame(stream, 64)
                    && let Ok((id, BootstrapRequest::ConfirmTotp { .. })) = bootstrap::decode_bootstrap_request(request.payload())
                {
                    let reply = bootstrap::encode_bootstrap_response(id, &BootstrapResponse::Error { code: 123 }).unwrap();
                    stream.write_all(&frame::encode(&reply).unwrap()).unwrap();
                    stream.flush().unwrap();
                }
            },
        )
    });
    let mut run = Run { stop, worker: Some(worker) };

    let sign_in = signin::encode_request(&SignIn { email: "reader@example.org", password: "test password", code: "123456" }).unwrap();
    assert_no_app_bytes(dial(address, no_certificate), &sign_in);
    assert!(matches!(routes.try_recv(), Err(mpsc::TryRecvError::Empty)));

    let mut enrolled = dial(address, client.clone());
    enrolled.write_all(&frame::encode(&sign_in).unwrap()).unwrap();
    let reply = frame::read_frame(&mut enrolled, 64).unwrap().unwrap();
    assert_eq!(signin::decode_reply(reply.payload()), Ok(Reply::Refused));
    assert_eq!(routes.recv_timeout(WAIT).unwrap(), Routed::Device(device.certificate.clone()));
    drop(enrolled);

    let request = bootstrap::encode_bootstrap_request(1, &BootstrapRequest::ConfirmTotp { code: "123456".into() }).unwrap();
    assert_no_app_bytes(dial(address, client), &request);
    assert_eq!(routes.recv_timeout(WAIT).unwrap(), Routed::Device(device.certificate));
    assert!(matches!(routes.try_recv(), Err(mpsc::TryRecvError::Empty)));

    let mut enrolling = dial(address, bootstrap_client);
    enrolling.write_all(&frame::encode(&request).unwrap()).unwrap();
    let reply = frame::read_frame(&mut enrolling, 64).unwrap().unwrap();
    assert_eq!(bootstrap::decode_bootstrap_response(reply.payload()), Ok((1, BootstrapResponse::Error { code: 123 })));
    assert_eq!(routes.recv_timeout(WAIT).unwrap(), Routed::Bootstrap(raw_key));
    drop(enrolling);
    run.stop.store(true, Ordering::Release);
    run.worker.take().unwrap().join().unwrap().unwrap();
}
