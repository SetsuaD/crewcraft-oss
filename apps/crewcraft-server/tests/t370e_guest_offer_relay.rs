//! T370e: an admitted visitor's offer through the real media link and a loopback mTLS control stub. The test
//! generates a disposable link CA and server state. It uses socket and channel barriers for both revocation races.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft_media_auth::{Issuer, Verifier};
use crewcraft_pki::{Authority, LINK_LIFETIME_SECS, ServerIdentity};
use crewcraft_proto::frame::{encode, read_frame};
use crewcraft_proto::guest::{GuestDecision, GuestMeetingChange, GuestMeetingDraft, GuestReply, GuestState};
use crewcraft_proto::media_control::{ControlMessage, MAX_CONTROL_MESSAGE, REFUSED_CREDENTIAL, decode_control, encode_control};
use crewcraft_server::device_session::RelayRefusal;
use crewcraft_server::media_link::{MediaLink, MediaRelayHandle};
use crewcraft_server_core::calls::HEARTBEAT_TIMEOUT_MS;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::guests::{GuestEntrance, GuestProof, MIN_LINK_MS};
use crewcraft_server_core::media::MediaIssuer;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

const HOST: &str = "host@example.org";
const MEDIA: &str = "media.example.org";
const PEER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const WAIT: Duration = Duration::from_secs(10);
const OFFER: &str = "fixture guest offer";
const ANSWER: &str = "fixture media answer";
const REFUSED: RelayRefusal = RelayRefusal::Refused(REFUSED_CREDENTIAL);

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("crewcraft-t370e-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct RelayFixture {
    relay: MediaRelayHandle,
    rooms: Arc<Mutex<DurableServer>>,
    stopped: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
    tls: Arc<ServerConfig>,
    address: SocketAddr,
    listener: Option<TcpListener>,
    public_key: [u8; 32],
    now: u64,
    clock: Arc<AtomicU64>,
    expires_at: u64,
    proof: GuestProof,
    call: u64,
    room: String,
    _scratch: Scratch,
}

fn identity(cert: ServerIdentity) -> crewcraft_tls::Identity {
    (cert.chain.into_iter().map(CertificateDer::from).collect(), PrivatePkcs8KeyDer::from(cert.key_pkcs8).into())
}

impl RelayFixture {
    fn new() -> Self {
        let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap();
        let ca = Authority::create_root("Fixture link CA", now).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(ca.certificate().to_vec())).unwrap();
        let server = identity(ca.server_certificate_for(MEDIA, now, LINK_LIFETIME_SECS).unwrap());
        let client = identity(ca.client_certificate("Fixture chat server", now, LINK_LIFETIME_SECS).unwrap());
        let tls = crewcraft_tls::server_config(server, roots.clone()).unwrap();
        let client_tls = crewcraft_tls::client_config(roots, Some(client)).unwrap();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let link = MediaLink::new(address, ServerName::try_from(MEDIA).unwrap(), client_tls);
        let relay = link.relay();

        let scratch = Scratch::new();
        let mut rooms = DurableServer::open(&scratch.0.join("rooms")).unwrap();
        let issuer = Issuer::from_pkcs8(&Issuer::generate().unwrap()).unwrap();
        let public_key = issuer.public_key();
        rooms.set_media(MediaIssuer::new(issuer, MEDIA, "media.example.org:3478"));
        let room = rooms.create_room(HOST, "Guest offer fixture").unwrap();
        let expires_at = now + HEARTBEAT_TIMEOUT_MS + 2;
        let draft = GuestMeetingDraft {
            room: room.clone(),
            start_ms: now,
            duration: 30,
            title: "Guest offer fixture".into(),
            agenda: String::new(),
            host_name: "Fixture host".into(),
            expires_ms: expires_at,
            lobby: true,
            confirm_direct: false,
        };
        let GuestReply::Created { lobby, code } = rooms.guest_meeting_save(HOST, &GuestMeetingChange::Create(draft), expires_at - MIN_LINK_MS).unwrap() else {
            panic!("expected a new guest meeting");
        };
        let proof = rooms.guest_entrance(|| now).knock(PEER, &code.0, "Fixture visitor").unwrap().proof;
        let waiting = rooms.guest_lobby(HOST, lobby.meeting, now).unwrap();
        rooms.guest_lobby_decide(HOST, lobby.meeting, proof.guest, waiting.revision, GuestDecision::Admit, now).unwrap();
        let (_, call) = rooms.join_meeting(HOST, lobby.meeting, now).unwrap();
        let rooms = Arc::new(Mutex::new(rooms));
        let stopped = Arc::new(AtomicBool::new(false));
        let clock = Arc::new(AtomicU64::new(now));
        let task = {
            let rooms = rooms.clone();
            let stopped = stopped.clone();
            let clock = clock.clone();
            thread::spawn(move || link.run(&|| stopped.load(Ordering::Acquire), &rooms, &|| clock.load(Ordering::Acquire)))
        };
        Self { relay, rooms, stopped, task: Some(task), tls, address, listener: Some(listener), public_key, now, clock, expires_at, proof, call, room, _scratch: scratch }
    }

    fn offer(&self) -> Receiver<Result<String, RelayRefusal>> {
        let (send, receive) = mpsc::channel();
        let relay = self.relay.clone();
        let proof = self.proof.clone();
        thread::spawn(move || {
            let _ = send.send(relay.join_guest(PEER, &proof, OFFER));
        });
        receive
    }

    fn accept_tcp(&mut self) -> TcpStream {
        let listener = self.listener.take().unwrap();
        let (send, receive) = mpsc::channel();
        let task = thread::spawn(move || {
            let _ = send.send(listener.accept().map(|(tcp, _)| tcp));
        });
        let accepted = receive.recv_timeout(WAIT);
        if accepted.is_err() {
            // Wake the accept thread even if a broken relay never connected.
            let _ = TcpStream::connect_timeout(&self.address, WAIT);
        }
        task.join().unwrap();
        accepted.unwrap().unwrap()
    }

    fn accept_tls(&self, tcp: TcpStream) -> StreamOwned<ServerConnection, TcpStream> {
        let stream = crewcraft_tls::accept(tcp, self.tls.clone(), WAIT).unwrap().stream;
        stream.sock.set_read_timeout(Some(WAIT)).unwrap();
        stream.sock.set_write_timeout(Some(WAIT)).unwrap();
        stream
    }

    fn remove(&self) {
        let mut rooms = self.rooms.lock().unwrap();
        let lobby = rooms.guest_lobby(HOST, self.proof.meeting, self.now).unwrap();
        rooms.guest_lobby_decide(HOST, lobby.meeting, self.proof.guest, lobby.revision, GuestDecision::Remove, self.now).unwrap();
        assert_eq!(rooms.guest_entrance(|| self.now).status(PEER, &self.proof).unwrap().state, GuestState::Removed);
    }

    fn close_link(&self) {
        let mut rooms = self.rooms.lock().unwrap();
        let lobby = rooms.guest_lobby(HOST, self.proof.meeting, self.now).unwrap();
        rooms.guest_link_close(HOST, lobby.meeting, lobby.revision, self.now).unwrap();
    }

    fn expire_link(&self) {
        // Keep the host present at the expiry boundary to isolate the link deadline.
        self.rooms.lock().unwrap().call_heartbeat(&self.room, HOST, self.call, self.expires_at - HEARTBEAT_TIMEOUT_MS).unwrap();
        self.clock.store(self.expires_at, Ordering::Release);
    }

    fn expire_host(&self) {
        self.clock.store(self.now + HEARTBEAT_TIMEOUT_MS + 1, Ordering::Release);
    }

    fn expect_join(&self, control: &mut impl Read) -> u64 {
        let ControlMessage::Join { seq, call, credential, offer } = receive_control(control) else {
            panic!("expected a guest join");
        };
        let grant = Verifier::new(self.public_key, MEDIA).verify(&credential, self.now).unwrap();
        assert_eq!(call, self.call);
        assert_eq!((grant.call, grant.room.as_str(), grant.device), (call, self.room.as_str(), self.proof.guest));
        assert_eq!(grant.person, format!("guest:{}", self.proof.guest));
        assert_eq!(offer, OFFER);
        seq
    }

    fn expect_drop(&self, control: &mut (impl Read + Write)) {
        let ControlMessage::DropPerson { seq, call, person } = receive_control(control) else {
            panic!("expected a revocation control message");
        };
        assert_eq!(call, self.call);
        assert_eq!(person, format!("guest:{}", self.proof.guest));
        send_control(control, &ControlMessage::Ack { seq });
    }
}

impl Drop for RelayFixture {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

fn receive_control(stream: &mut impl Read) -> ControlMessage {
    let frame = read_frame(stream, MAX_CONTROL_MESSAGE).unwrap().unwrap();
    decode_control(frame.payload()).unwrap()
}

fn send_control(stream: &mut impl Write, message: &ControlMessage) {
    stream.write_all(&encode(&encode_control(message).unwrap()).unwrap()).unwrap();
    stream.flush().unwrap();
}

#[test]
fn admitted_guest_gets_the_answer_but_removal_during_exchange_withholds_it() {
    let mut fixture = RelayFixture::new();
    let admitted = fixture.offer();
    let tcp = fixture.accept_tcp();
    let mut control = fixture.accept_tls(tcp);
    let seq = fixture.expect_join(&mut control);
    send_control(&mut control, &ControlMessage::JoinAnswer { seq, answer: ANSWER.into() });
    assert_eq!(admitted.recv_timeout(WAIT).unwrap(), Ok(ANSWER.into()));

    let in_flight = fixture.offer();
    let seq = fixture.expect_join(&mut control);
    // The relay has dispatched this offer. Commit removal before the media peer answers it.
    fixture.remove();
    send_control(&mut control, &ControlMessage::JoinAnswer { seq, answer: ANSWER.into() });
    assert_eq!(in_flight.recv_timeout(WAIT).unwrap(), Err(REFUSED));
    fixture.expect_drop(&mut control);
}

#[test]
fn removal_during_the_control_handshake_never_dispatches_a_guest_join() {
    let mut fixture = RelayFixture::new();
    let queued = fixture.offer();
    let tcp = fixture.accept_tcp();
    // The relay has started TLS, but the media peer has not answered its ClientHello.
    tcp.set_read_timeout(Some(WAIT)).unwrap();
    assert_eq!(tcp.peek(&mut [0]).unwrap(), 1);
    fixture.remove();
    let mut control = fixture.accept_tls(tcp);
    assert_eq!(queued.recv_timeout(WAIT).unwrap(), Err(REFUSED));
    // The first frame must be the removal event itself. A premature join would arrive before it.
    fixture.expect_drop(&mut control);
}

#[test]
fn closure_link_expiry_and_call_expiry_during_exchange_each_withhold_the_answer() {
    let invalidate: [fn(&RelayFixture); 3] = [RelayFixture::close_link, RelayFixture::expire_link, RelayFixture::expire_host];
    for invalidate in invalidate {
        let mut fixture = RelayFixture::new();
        let pending = fixture.offer();
        let tcp = fixture.accept_tcp();
        let mut control = fixture.accept_tls(tcp);
        let seq = fixture.expect_join(&mut control);
        invalidate(&fixture);
        send_control(&mut control, &ControlMessage::JoinAnswer { seq, answer: ANSWER.into() });
        assert_eq!(pending.recv_timeout(WAIT).unwrap(), Err(REFUSED));
    }
}
