//! T360b6: a participant's WebRTC offer reaches the media server through the chat server (docs/CALLS.md
//! "Admission"). Two people on their own device connections (real loopback TCP, the chat server's session code, the
//! client-core `Client`) get media credentials when they start and join a call, send their offers with them, and get
//! the media server's answers back: the chat server relays each over its mutual-TLS control link. Their str0m clients
//! then connect to the media server over real UDP and A's frames reach B. An offer with a used or forged credential is
//! refused by the media server; a non-member's offer is refused by the chat server and never reaches the media server.
//! A credential that has expired when it arrives is refused by the media server too: Bo's second device runs its chat
//! server connection on a clock set back past the credential's lifetime, so no test waits out the 60 seconds.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft_client_core::client::{Client, ClientEvent};
use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::requests::Reply;
use crewcraft_media::{config, intake, serve};
use crewcraft_media_auth::{Issuer, LIFETIME_MS};
use crewcraft_media_server::control::{ControlListener, tls_config};
use crewcraft_proto::frame::{encode, read_frame};
use crewcraft_proto::handshake::{self, Hello, ServerSide};
use crewcraft_proto::request::{FEATURE_CALLS, FEATURE_MEDIA, Request, Response};
use crewcraft_proto::signin::{self, SignIn, TOKEN_LEN};
use crewcraft_server::device_session::{AuthError, CommittedSignIn, DeviceAuth, MediaRelay, RelayRefusal, serve_with_media};
use crewcraft_server::media_link;
use crewcraft_server_core::dispatch::{E_NO_SUCH_ROOM, E_NOT_ALLOWED};
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::room::Role;
use str0m::change::SdpAnswer;
use str0m::format::Codec;
use str0m::media::{Direction, MediaKind, Mid};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc};

const MEDIA: &str = "media.example.org";
const ANA: &str = "ana@example.org";
const BO: &str = "bo@example.org";
const CY: &str = "cy@example.org";
const WAIT: Duration = Duration::from_secs(10);

fn now_ms() -> u64 {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("crewcraft-t360b6-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(dir.join("chat")).unwrap();
        std::fs::create_dir_all(dir.join("media")).unwrap();
        Scratch(dir)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The transport has verified this device; signing in always succeeds (the sign-in itself is tested elsewhere).
struct Device {
    user: &'static str,
    device: u64,
}

impl DeviceAuth for Device {
    type Session = ();

    fn sign_in(&self, _credentials: SignIn<'_>, _now_ms: u64) -> Result<Option<CommittedSignIn<()>>, AuthError> {
        Ok(Some(CommittedSignIn { user: self.user.to_owned(), token: "A".repeat(TOKEN_LEN), session: () }))
    }

    fn with_live_session<T>(&self, _session: &(), _now_ms: u64, action: impl FnOnce() -> T) -> Result<Option<T>, AuthError> {
        Ok(Some(action()))
    }

    fn device(&self) -> Option<u64> {
        Some(self.device)
    }
}

/// The chat server's relay, counting the offers that reach it.
struct Counting {
    relay: media_link::MediaRelayHandle,
    count: AtomicUsize,
}

impl MediaRelay for Counting {
    fn join(&self, call: u64, credential: &[u8], offer: &str) -> Result<String, RelayRefusal> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.relay.join(call, credential, offer)
    }
}

/// One person's device connection to the chat server, through client-core.
struct Person {
    stream: TcpStream,
    client: Client,
}

impl Person {
    fn connect(address: SocketAddr, user: &str) -> Person {
        let mut stream = TcpStream::connect(address).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        stream
            .write_all(&encode(&signin::encode_request(&SignIn { email: user, password: "fixture password", code: "123456" }).unwrap()).unwrap())
            .unwrap();
        read_frame(&mut stream, 4096).unwrap().unwrap();
        let hello = Hello { min_version: 1, max_version: 1, features: FEATURE_CALLS | FEATURE_MEDIA, client: "test".into() };
        stream.write_all(&encode(&handshake::encode_hello(&hello).unwrap()).unwrap()).unwrap();
        let welcome = read_frame(&mut stream, 4096).unwrap().unwrap();
        match handshake::decode_reply(welcome.payload()).unwrap() {
            handshake::Reply::Welcome { features, .. } => assert_eq!(features & FEATURE_MEDIA, FEATURE_MEDIA),
            other => panic!("{other:?}"),
        }
        Person { stream, client: Client::new(user, Settings::default()) }
    }

    /// Send `request`; return its answer and the frame that follows it, if any.
    fn ask(&mut self, request: Request) -> (Response, Option<ClientEvent>) {
        let bytes = self.client.send(request, now_ms()).unwrap();
        self.stream.write_all(&bytes).unwrap();
        let mut response = None;
        let until = Instant::now() + WAIT;
        while Instant::now() < until {
            let frame = read_frame(&mut self.stream, 1 << 20).unwrap().unwrap();
            for event in self.client.receive(frame.as_bytes(), now_ms(), 0).unwrap() {
                match event {
                    ClientEvent::Reply(Reply::Done { response: answered, .. }) => {
                        if !matches!(answered, Response::Ok { .. }) {
                            return (answered, None);
                        }
                        response = Some(answered);
                    }
                    follow @ (ClientEvent::Media { .. } | ClientEvent::Answer { .. }) => return (response.take().unwrap(), Some(follow)),
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        panic!("no answer in time");
    }
}

/// A str0m client on its own loopback UDP socket.
struct Peer {
    socket: UdpSocket,
    address: SocketAddr,
    rtc: Rtc,
    mic: Mid,
    events: Vec<Event>,
}

impl Peer {
    fn new() -> (Peer, String, str0m::change::SdpPendingOffer) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let address = socket.local_addr().unwrap();
        let mut rtc = Rtc::builder().set_crypto_provider(Arc::new(crewcraft_media_crypto::provider())).build(Instant::now());
        rtc.add_local_candidate(Candidate::host(address, "udp").unwrap());
        let mut change = rtc.sdp_api();
        let mic = change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
        change.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
        let (offer, pending) = change.apply().unwrap();
        (Peer { socket, address, rtc, mic, events: Vec::new() }, offer.to_sdp_string(), pending)
    }

    fn turn(&mut self) {
        loop {
            match self.rtc.poll_output().unwrap() {
                Output::Timeout(_) => break,
                Output::Transmit(sent) => {
                    let _ = self.socket.send_to(&sent.contents, sent.destination);
                }
                Output::Event(event) => self.events.push(event),
            }
        }
        let mut buffer = [0u8; 2048];
        while let Ok((len, source)) = self.socket.recv_from(&mut buffer) {
            let contents = buffer[..len].try_into().unwrap();
            self.rtc
                .handle_input(Input::Receive(Instant::now(), Receive { proto: Protocol::Udp, source, destination: self.address, contents }))
                .unwrap();
        }
        self.rtc.handle_input(Input::Timeout(Instant::now())).unwrap();
    }

    fn received(&self) -> Vec<Vec<u8>> {
        self.events.iter().filter_map(|event| if let Event::MediaData(data) = event { Some(data.data.to_vec()) } else { None }).collect()
    }
}

fn drive(a: &mut Peer, b: &mut Peer, time: Duration, done: impl Fn(&Peer, &Peer) -> bool) {
    let until = Instant::now() + time;
    while Instant::now() < until && !done(a, b) {
        a.turn();
        b.turn();
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn offers_go_through_the_chat_server_and_answers_come_back() {
    let files = Scratch::new();
    let (chat, media) = (files.0.join("chat"), files.0.join("media"));
    media_link::issue_link(&chat, &media, MEDIA, now_ms()).unwrap();
    let media_key = Issuer::generate().unwrap();
    files.write("chat/media.key", &media_key);
    let public = Issuer::from_pkcs8(&media_key).unwrap().public_key();
    files.write("media/chat-server.key", format!("{}\n", hex(&public)).as_bytes());

    // The media server: UDP for media, the control listener for the chat server.
    let settings = format!(
        "[media]\nserver-name = \"{MEDIA}\"\nlisten = \"127.0.0.1:0\"\nchat-server-key = \"chat-server.key\"\n\n[control]\nlisten = \"127.0.0.1:0\"\ncertificate = \"media.pem\"\nkey = \"media-key.pem\"\nchat-server-ca = \"chat-ca.pem\"\n"
    );
    let media_config = config::load(&files.write("media/media.toml", settings.as_bytes())).unwrap();
    let control = media_config.settings.control.clone().unwrap();
    let (socket, server) = serve::bind(&media_config).unwrap();
    let media_address = socket.local_addr().unwrap();
    let (handle, mut requests) = intake::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let listener = ControlListener::start(control.listen, tls_config(&media, &control).unwrap(), handle, stop.clone()).unwrap();
    let flag = stop.clone();
    let serving = std::thread::spawn(move || serve::run(&socket, server, &mut requests, &flag).map_err(|e| e.to_string()));

    // The chat server: its room store, the link with its relay, and device connections served on loopback TCP.
    let chat_settings = format!(
        "[media]\nserver-name = \"{MEDIA}\"\naddress = \"{media_address}\"\ncontrol = \"{}\"\nkey = \"media.key\"\nca-bundle = \"media-ca.pem\"\nclient-certificate = \"media-client.pem\"\nclient-key = \"media-client-key.pem\"\n",
        listener.local_addr()
    );
    files.write("chat/media.toml", chat_settings.as_bytes());
    let (issuer, link) = media_link::load(&chat).unwrap().unwrap();
    let relay = Arc::new(Counting { relay: link.relay(), count: AtomicUsize::new(0) });
    let rooms = Arc::new(Mutex::new(DurableServer::open(&chat.join("rooms.journal")).unwrap()));
    let room = {
        let mut rooms = rooms.lock().unwrap();
        rooms.set_media(issuer);
        let room = rooms.create_room(ANA, "Project").unwrap();
        rooms.add_member(&room, ANA, BO, Role::Member).unwrap();
        room
    };
    let chat_stop = Arc::new(AtomicBool::new(false));
    let linking = {
        let (rooms, chat_stop) = (rooms.clone(), chat_stop.clone());
        std::thread::spawn(move || link.run(&|| chat_stop.load(Ordering::Acquire), &rooms, &now_ms))
    };
    let devices = TcpListener::bind("127.0.0.1:0").unwrap();
    let devices_address = devices.local_addr().unwrap();
    // How far behind the real clock the chat server's clock runs for Bo's second device (device 4).
    let behind = Arc::new(AtomicU64::new(0));
    let accepting = {
        let (rooms, relay, behind) = (rooms.clone(), relay.clone(), behind.clone());
        std::thread::spawn(move || {
            for (user, device) in [(ANA, 1), (BO, 2), (CY, 3), (BO, 4)] {
                let (mut stream, _) = devices.accept().unwrap();
                let (rooms, relay) = (rooms.clone(), relay.clone());
                let behind = if device == 4 { behind.clone() } else { Arc::new(AtomicU64::new(0)) };
                std::thread::spawn(move || {
                    let side = ServerSide { min_version: 1, max_version: 1, features: FEATURE_CALLS | FEATURE_MEDIA, name: "chat".into() };
                    let relay: &dyn MediaRelay = &*relay;
                    let clock = || now_ms().saturating_sub(behind.load(Ordering::SeqCst));
                    let _ = serve_with_media(&mut stream, &Device { user, device }, &rooms, Some(relay), side, |_| Ok(()), clock);
                });
            }
        })
    };
    let mut ana = Person::connect(devices_address, ANA);
    let mut bo = Person::connect(devices_address, BO);
    let mut cy = Person::connect(devices_address, CY);
    let mut bo_second = Person::connect(devices_address, BO);
    accepting.join().unwrap();

    // Ana starts a call and Bo joins: each gets a credential.
    let credential_of = |follow: Option<ClientEvent>| match follow {
        Some(ClientEvent::Media { address, credential, .. }) => {
            assert_eq!(address, media_address.to_string());
            credential
        }
        other => panic!("no media frame: {other:?}"),
    };
    let (started, follow) = ana.ask(Request::CallStart { room: room.clone(), video: false });
    let Response::Ok { cursor: call } = started else { panic!("{started:?}") };
    let ana_credential = credential_of(follow);
    let (joined, follow) = bo.ask(Request::CallJoin { room: room.clone(), call });
    assert_eq!(joined, Response::Ok { cursor: call });
    let bo_credential = credential_of(follow);

    // Each sends an offer with its credential through the chat server and gets the media server's answer back.
    let mut peers = Vec::new();
    for (person, credential) in [(&mut ana, &ana_credential), (&mut bo, &bo_credential)] {
        let (mut peer, offer, pending) = Peer::new();
        let (answered, follow) = person.ask(Request::CallOffer { room: room.clone(), call, credential: credential.clone(), offer });
        assert_eq!(answered, Response::Ok { cursor: call });
        let Some(ClientEvent::Answer { answer, .. }) = follow else { panic!("no answer frame: {follow:?}") };
        peer.rtc.sdp_api().accept_answer(pending, SdpAnswer::from_sdp_string(&answer).unwrap()).unwrap();
        peers.push(peer);
    }
    assert_eq!(relay.count.load(Ordering::SeqCst), 2, "both offers were relayed");
    let mut b = peers.pop().unwrap();
    let mut a = peers.pop().unwrap();
    drive(&mut a, &mut b, WAIT, |a, b| a.rtc.is_connected() && b.rtc.is_connected());
    assert!(a.rtc.is_connected() && b.rtc.is_connected(), "the peers did not connect to the media server");

    // A's frames reach B, byte for byte.
    let pt = a.rtc.codec_config().find(|params| params.spec().codec == Codec::Opus).unwrap().pt();
    let mut sent = Vec::new();
    for n in 0..25u32 {
        let frame = format!("ana opaque frame {n:04}").into_bytes();
        a.rtc.writer(a.mic).unwrap().write(pt, Instant::now(), Duration::from_millis(20 * u64::from(n)).into(), frame.clone()).unwrap();
        sent.push(frame);
        drive(&mut a, &mut b, Duration::from_millis(20), |_, _| false);
    }
    drive(&mut a, &mut b, Duration::from_millis(500), |_, _| false);
    let at_b = b.received();
    assert!(at_b.len() >= 20 && at_b.iter().all(|frame| sent.contains(frame)), "only {} of Ana's frames reached Bo", at_b.len());

    // A used credential (Ana's, again) and a forged one are refused by the media server.
    let (_, offer, _) = Peer::new();
    let (refused, _) = bo.ask(Request::CallOffer { room: room.clone(), call, credential: ana_credential, offer: offer.clone() });
    assert!(matches!(refused, Response::Error { code, .. } if code == E_NOT_ALLOWED), "{refused:?}");
    let forged = Issuer::from_pkcs8(&Issuer::generate().unwrap()).unwrap().issue(call, &room, BO, 2, MEDIA, now_ms()).unwrap();
    let (refused, _) = bo.ask(Request::CallOffer { room: room.clone(), call, credential: forged, offer: offer.clone() });
    assert!(matches!(refused, Response::Error { code, .. } if code == E_NOT_ALLOWED), "{refused:?}");
    assert_eq!(relay.count.load(Ordering::SeqCst), 4);

    // Cy is not a member: the chat server refuses the offer and it never reaches the media server.
    let (refused, _) = cy.ask(Request::CallOffer { room: room.clone(), call, credential: bo_credential, offer });
    assert!(matches!(refused, Response::Error { code, .. } if code == E_NO_SUCH_ROOM), "{refused:?}");
    assert_eq!(relay.count.load(Ordering::SeqCst), 4, "a non-member's offer reached the relay");

    // Bo's second device joins while the chat server's clock for it runs a second more than a credential's lifetime
    // behind: the credential it gets has already expired. The chat server relays the offer (Bo is in the call) and the
    // media server, on the real clock, refuses it.
    behind.store(LIFETIME_MS + 1_000, Ordering::SeqCst);
    let (joined, follow) = bo_second.ask(Request::CallJoin { room: room.clone(), call });
    assert_eq!(joined, Response::Ok { cursor: call });
    let expired = credential_of(follow);
    let (_, offer, _) = Peer::new();
    let (refused, _) = bo_second.ask(Request::CallOffer { room: room.clone(), call, credential: expired, offer });
    assert!(matches!(refused, Response::Error { code, .. } if code == E_NOT_ALLOWED), "{refused:?}");
    assert_eq!(relay.count.load(Ordering::SeqCst), 5, "the expired credential's offer reached the media server");
    // The control: the same device, the same join and offer, with the clock put right, is answered.
    behind.store(0, Ordering::SeqCst);
    let (joined, follow) = bo_second.ask(Request::CallJoin { room: room.clone(), call });
    assert_eq!(joined, Response::Ok { cursor: call });
    let fresh = credential_of(follow);
    let (_, offer, _) = Peer::new();
    let (answered, follow) = bo_second.ask(Request::CallOffer { room: room.clone(), call, credential: fresh, offer });
    assert_eq!(answered, Response::Ok { cursor: call });
    assert!(matches!(follow, Some(ClientEvent::Answer { .. })), "no answer frame: {follow:?}");
    assert_eq!(relay.count.load(Ordering::SeqCst), 6);

    drop((ana, bo, cy, bo_second));
    chat_stop.store(true, Ordering::Release);
    linking.join().unwrap();
    stop.store(true, Ordering::Release);
    assert_eq!(serving.join().unwrap(), Ok(()));
    listener.join();
}
