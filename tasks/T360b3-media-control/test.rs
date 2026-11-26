//! T360b3: the chat server's control connection to the media server (docs/CALLS.md "Admission: removed means
//! removed"), end to end. A media server runs on loopback (UDP for media, mutual TLS for control) and a chat server's
//! room store runs beside its media link; two str0m clients get credentials from the chat server, join the media
//! server and connect over real UDP. Removing one from the room closes their media session at once; the end of the
//! call closes everyone; a client certificate from another CA cannot drop anyone. `media.toml` on both sides is read
//! strictly, and the chat server makes its media key at the first start.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft_media::{config, intake, serve};
use crewcraft_media_auth::Issuer;
use crewcraft_media_server::control::{ControlListener, tls_config};
use crewcraft_proto::frame::{Decoder, encode, read_frame};
use crewcraft_proto::media_control::{ControlMessage, MAX_CONTROL_MESSAGE, encode_control};
use crewcraft_proto::request::{FEATURE_CALLS, FEATURE_MEDIA, MEDIA_TAG, Request, Response, decode_media, decode_response, encode_request};
use crewcraft_server::media_link;
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::room::Role;
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
use std::io::Write;
use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::media::{Direction, MediaKind};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc};

const MEDIA: &str = "media.example.org";
const ANA: &str = "ana@example.org";
const BO: &str = "bo@example.org";

fn now_ms() -> u64 {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh directory for one test's files, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("crewcraft-t360b3-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(dir.join("media")).unwrap();
        std::fs::create_dir_all(dir.join("chat")).unwrap();
        Scratch(dir)
    }

    fn write(&self, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        path
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A test CA: its certificate (PEM) and what signs with it.
struct Ca {
    pem: String,
    issuer: rcgen::Issuer<'static, KeyPair>,
}

fn ca(name: &str) -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let pem = params.self_signed(&key).unwrap().pem();
    Ca { pem, issuer: rcgen::Issuer::new(params, key) }
}

/// A certificate (PEM) and key (PEM) from `ca`, for `names`, used for `usage`.
fn leaf(ca: &Ca, names: Vec<String>, usage: ExtendedKeyUsagePurpose) -> (String, String) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(names).unwrap();
    params.extended_key_usages = vec![usage];
    (params.signed_by(&key, &ca.issuer).unwrap().pem(), key.serialize_pem())
}

/// A str0m client on its own loopback UDP socket.
struct Client {
    socket: UdpSocket,
    address: SocketAddr,
    rtc: Rtc,
    events: Vec<Event>,
}

impl Client {
    fn new() -> (Client, String, SdpPendingOffer) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let address = socket.local_addr().unwrap();
        let mut rtc = Rtc::builder().set_crypto_provider(Arc::new(crewcraft_media_crypto::provider())).build(Instant::now());
        rtc.add_local_candidate(Candidate::host(address, "udp").unwrap());
        let mut change = rtc.sdp_api();
        change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
        change.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
        let (offer, pending) = change.apply().unwrap();
        (Client { socket, address, rtc, events: Vec::new() }, offer.to_sdp_string(), pending)
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
            let receive = Receive { proto: Protocol::Udp, source, destination: self.address, contents };
            self.rtc.handle_input(Input::Receive(Instant::now(), receive)).unwrap();
        }
        self.rtc.handle_input(Input::Timeout(Instant::now())).unwrap();
    }

    fn closed(&self) -> bool {
        self.events.iter().any(|event| matches!(event, Event::Closed))
    }
}

/// Run both clients for `time` of real time, or until `done` holds.
fn drive(a: &mut Client, b: &mut Client, time: Duration, done: impl Fn(&Client, &Client) -> bool) {
    let until = Instant::now() + time;
    while Instant::now() < until && !done(a, b) {
        a.turn();
        b.turn();
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Send `request` for `user` on `device` to the chat server and return the answer and the media frame after it.
fn ask(rooms: &Mutex<DurableServer>, user: &str, device: u64, request: Request) -> (Response, Option<(String, Vec<u8>)>) {
    let mut connection = Connection::with_features(user, FEATURE_CALLS | FEATURE_MEDIA).with_device(Some(device));
    let bytes = encode(&encode_request(1, &request).unwrap()).unwrap();
    let out = connection.receive_durable(&mut rooms.lock().unwrap(), &bytes, now_ms()).unwrap();
    let mut decoder = Decoder::new();
    decoder.push(&out);
    let (_, response) = decode_response(&decoder.next_frame().unwrap().unwrap()).unwrap();
    let mut media = None;
    while let Some(frame) = decoder.next_frame().unwrap() {
        if frame.first() == Some(&MEDIA_TAG) {
            let (_, address, credential) = decode_media(&frame).unwrap();
            media = Some((address, credential));
        }
    }
    (response, media)
}

#[test]
fn removal_and_the_end_of_a_call_reach_the_media_server_over_mutual_tls() {
    let files = Scratch::new("link");
    let media_ca = ca("Media CA");
    let chat_ca = ca("Chat CA");
    let (media_cert, media_key) = leaf(&media_ca, vec![MEDIA.to_owned()], ExtendedKeyUsagePurpose::ServerAuth);
    let (chat_cert, chat_key) = leaf(&chat_ca, Vec::new(), ExtendedKeyUsagePurpose::ClientAuth);

    // The chat server's media key, and its public half on the media server.
    let chat_media_key = Issuer::generate().unwrap();
    files.write("chat/media.key", &chat_media_key, 0o600);
    let public = Issuer::from_pkcs8(&chat_media_key).unwrap().public_key();
    files.write("media/chat-server.key", format!("{}\n", hex(&public)).as_bytes(), 0o600);

    // The media server: UDP for media, mutual TLS for control, each on a port the system picks.
    files.write("media/media.pem", media_cert.as_bytes(), 0o644);
    files.write("media/media-key.pem", media_key.as_bytes(), 0o600);
    files.write("media/chat-ca.pem", chat_ca.pem.as_bytes(), 0o644);
    let settings = format!(
        "[media]\nserver-name = \"{MEDIA}\"\nlisten = \"127.0.0.1:0\"\nchat-server-key = \"chat-server.key\"\n\n[control]\nlisten = \"127.0.0.1:0\"\ncertificate = \"media.pem\"\nkey = \"media-key.pem\"\nchat-server-ca = \"chat-ca.pem\"\n"
    );
    let media_toml = files.write("media/media.toml", settings.as_bytes(), 0o644);
    let media_config = config::load(&media_toml).unwrap();
    let control = media_config.settings.control.clone().unwrap();
    let (socket, server) = serve::bind(&media_config).unwrap();
    let media_address = socket.local_addr().unwrap();
    let (handle, mut requests) = intake::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let listener = ControlListener::start(control.listen, tls_config(&files.path("media"), &control).unwrap(), handle.clone(), stop.clone()).unwrap();
    let control_address = listener.local_addr();
    let flag = stop.clone();
    let serving = std::thread::spawn(move || serve::run(&socket, server, &mut requests, &flag).map_err(|e| e.to_string()));

    // The chat server: its media.toml, its room store and the link beside it.
    files.write("chat/media-ca.pem", media_ca.pem.as_bytes(), 0o644);
    files.write("chat/media-client.pem", chat_cert.as_bytes(), 0o644);
    files.write("chat/media-client-key.pem", chat_key.as_bytes(), 0o600);
    let chat_settings = format!(
        "[media]\nserver-name = \"{MEDIA}\"\naddress = \"{media_address}\"\ncontrol = \"{control_address}\"\nkey = \"media.key\"\nca-bundle = \"media-ca.pem\"\nclient-certificate = \"media-client.pem\"\nclient-key = \"media-client-key.pem\"\n"
    );
    files.write("chat/media.toml", chat_settings.as_bytes(), 0o644);
    let (issuer, link) = media_link::load(&files.path("chat")).unwrap().expect("media.toml is there");
    let rooms = Arc::new(Mutex::new(DurableServer::open(&files.path("chat/rooms.journal")).unwrap()));
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

    // Ana starts a call and Bo joins: each gets a credential for the media server, which admits them.
    let (started, ana_media) = ask(&rooms, ANA, 1, Request::CallStart { room: room.clone(), video: false });
    let Response::Ok { cursor: call } = started else { panic!("{started:?}") };
    let (joined, bo_media) = ask(&rooms, BO, 2, Request::CallJoin { room: room.clone(), call });
    assert_eq!(joined, Response::Ok { cursor: call });
    let mut clients = Vec::new();
    for media in [ana_media, bo_media] {
        let (address, credential) = media.expect("a credential follows the answer");
        assert_eq!(address, media_address.to_string(), "clients are told the media server's address");
        let (mut client, offer, pending) = Client::new();
        let joined = handle.join(call, &credential, &offer).unwrap();
        client.rtc.sdp_api().accept_answer(pending, SdpAnswer::from_sdp_string(&joined.answer).unwrap()).unwrap();
        clients.push(client);
    }
    let mut bo = clients.pop().unwrap();
    let mut ana = clients.pop().unwrap();
    drive(&mut ana, &mut bo, Duration::from_secs(10), |a, b| a.rtc.is_connected() && b.rtc.is_connected());
    assert!(ana.rtc.is_connected() && bo.rtc.is_connected(), "the clients did not connect");

    // Someone holding a certificate from another CA cannot tell the media server anything.
    let stranger = ca("Stranger CA");
    let (stranger_cert, stranger_key) = leaf(&stranger, Vec::new(), ExtendedKeyUsagePurpose::ClientAuth);
    let roots = crewcraft_tls::pem::roots(media_ca.pem.as_bytes()).unwrap();
    let identity = crewcraft_tls::pem::identity(stranger_cert.as_bytes(), stranger_key.as_bytes()).unwrap();
    let tls = crewcraft_tls::client_config(roots, Some(identity)).unwrap();
    let tcp = TcpStream::connect(control_address).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut forged = crewcraft_tls::connect(tcp, tls, MEDIA.try_into().unwrap()).unwrap();
    let drop_ana = encode_control(&ControlMessage::DropPerson { seq: 1, call, person: ANA.to_owned() }).unwrap();
    let refused = forged.write_all(&encode(&drop_ana).unwrap()).and_then(|()| forged.flush()).and_then(|()| read_frame(&mut forged, MAX_CONTROL_MESSAGE));
    assert!(!matches!(refused, Ok(Some(_))), "the media server answered a stranger");
    drive(&mut ana, &mut bo, Duration::from_millis(500), |_, _| false);
    assert!(!ana.closed() && !bo.closed(), "a stranger dropped someone");

    // Bo is removed from the room: the chat server tells the media server over the control connection, at once.
    let removed_at = Instant::now();
    rooms.lock().unwrap().remove_member(&room, ANA, BO).unwrap();
    drive(&mut ana, &mut bo, Duration::from_secs(5), |_, b| b.closed());
    assert!(bo.closed(), "Bo's media session was not closed after his removal");
    assert!(removed_at.elapsed() < Duration::from_secs(3), "dropping Bo took {:?}", removed_at.elapsed());
    assert!(!ana.closed(), "Ana stays in the call");

    // Ana leaves, the last one: the call ends and the media server closes everyone left.
    rooms.lock().unwrap().call_leave(&room, ANA, call, now_ms()).unwrap();
    drive(&mut ana, &mut bo, Duration::from_secs(5), |a, _| a.closed());
    assert!(ana.closed(), "the end of the call did not close Ana's media session");

    chat_stop.store(true, Ordering::Release);
    linking.join().unwrap();
    stop.store(true, Ordering::Release);
    assert_eq!(serving.join().unwrap(), Ok(()));
    listener.join();
}

#[test]
fn the_chat_servers_media_toml_is_strict_and_makes_its_key() {
    let good = "[media]\nserver-name = \"media.example.org\"\naddress = \"203.0.113.10:3478\"\ncontrol = \"203.0.113.10:7443\"\nkey = \"media.key\"\nca-bundle = \"media-ca.pem\"\nclient-certificate = \"media-client.pem\"\nclient-key = \"media-client-key.pem\"\n";
    let settings = media_link::parse(good).unwrap();
    assert_eq!(settings.server_name, MEDIA);
    assert_eq!(settings.control, "203.0.113.10:7443".parse().unwrap());
    assert!(media_link::parse(&format!("{good}colour = \"blue\"\n")).is_err(), "an unknown key");
    assert!(media_link::parse(&good.replace("203.0.113.10:7443", "0.0.0.0:7443")).is_err(), "no control address");
    assert!(media_link::parse(&good.replace("media-ca.pem", "../media-ca.pem")).is_err(), "a path for a file");
    assert!(media_link::parse(&good.replace("media.example.org", "Media")).is_err(), "a bad server name");
    assert!(media_link::parse(&good.replace("key = \"media.key\"\n", "")).is_err(), "no key");

    // No media.toml: no media server, and that is not an error.
    let files = Scratch::new("strict");
    assert!(media_link::load(&files.path("chat")).unwrap().is_none());

    // The first start makes the media key, owner-only, with its public half beside it; the next start reads it.
    let ca = ca("Media CA");
    let (cert, key) = leaf(&ca, Vec::new(), ExtendedKeyUsagePurpose::ClientAuth);
    files.write("chat/media.toml", good.as_bytes(), 0o644);
    files.write("chat/media-ca.pem", ca.pem.as_bytes(), 0o644);
    files.write("chat/media-client.pem", cert.as_bytes(), 0o644);
    files.write("chat/media-client-key.pem", key.as_bytes(), 0o600);
    let (first, _) = media_link::load(&files.path("chat")).unwrap().unwrap();
    let public = std::fs::read_to_string(files.path("chat/media.key.pub")).unwrap();
    assert_eq!(public, format!("{}\n", hex(&first.public_key())), "media.key.pub is what the media server trusts");
    let (again, _) = media_link::load(&files.path("chat")).unwrap().unwrap();
    assert_eq!(again.public_key(), first.public_key(), "the key is kept");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(files.path("chat/media.key")).unwrap().permissions().mode() & 0o077, 0, "made owner-only");
        std::fs::set_permissions(files.path("chat/media-client-key.pem"), std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(media_link::load(&files.path("chat")).is_err(), "a client key others can read is refused");
    }
}

#[test]
fn the_binary_refuses_bad_settings() {
    let binary = Path::new(env!("CARGO_BIN_EXE_crewcraft-media-server"));
    let usage = Command::new(binary).output().unwrap();
    assert_eq!(usage.status.code(), Some(2), "no settings file is a usage error");

    let files = Scratch::new("binary");
    let settings = "[media]\nserver-name = \"media.example.org\"\nlisten = \"127.0.0.1:0\"\nchat-server-key = \"chat-server.key\"\ncolour = \"blue\"\n";
    let path = files.write("media/media.toml", settings.as_bytes(), 0o644);
    let refused = Command::new(binary).arg(&path).output().unwrap();
    assert_eq!(refused.status.code(), Some(1));
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(message.contains("colour"), "the error names the bad key: {message}");
}
