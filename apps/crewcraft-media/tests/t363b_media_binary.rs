//! T363b: the media server's binary parts (docs/CALLS.md): `media.toml` and the chat server's key are read strictly,
//! the serving loop runs on a real loopback UDP socket, two str0m clients join through the in-process intake and A1's
//! audio reaches A2 over real UDP; stopping the loop closes every session (each client is told) and returns, after
//! which the intake answers that the server has stopped.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft_media::config::{self, Settings};
use crewcraft_media::{JoinError, intake, serve};
use crewcraft_media_auth::Issuer;
use crewcraft_strict_toml::Error as TomlError;
use str0m::change::SdpAnswer;
use str0m::format::Codec;
use str0m::media::{Direction, MediaKind, Mid};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc};

const MEDIA: &str = "media.example.org";
const CALL: u64 = 7;

/// A fresh directory for one test's files, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("crewcraft-t363b-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn write(&self, name: &str, text: &str, mode: u32) -> PathBuf {
        let path = self.0.join(name);
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = mode;
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_ms() -> u64 {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

const SETTINGS: &str = "[media]\nserver-name = \"media.example.org\"\nlisten = \"127.0.0.1:0\"\nchat-server-key = \"chat-server.key\"\nmax-call-size = 8\n";

/// A str0m client on its own loopback UDP socket.
struct Client {
    socket: UdpSocket,
    address: SocketAddr,
    rtc: Rtc,
    mic: Mid,
    events: Vec<Event>,
}

impl Client {
    /// A client and its offer: one audio section it sends, two it only receives.
    fn new() -> (Client, String, str0m::change::SdpPendingOffer) {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let address = socket.local_addr().unwrap();
        let mut rtc = Rtc::builder().set_crypto_provider(Arc::new(crewcraft_media_crypto::provider())).build(Instant::now());
        rtc.add_local_candidate(Candidate::host(address, "udp").unwrap());
        let mut change = rtc.sdp_api();
        let mic = change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
        change.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
        change.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
        let (offer, pending) = change.apply().unwrap();
        (Client { socket, address, rtc, mic, events: Vec::new() }, offer.to_sdp_string(), pending)
    }

    /// Send what the session has, take in what arrived, and move its clock.
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

    fn received(&self) -> Vec<Vec<u8>> {
        self.events.iter().filter_map(|event| if let Event::MediaData(data) = event { Some(data.data.to_vec()) } else { None }).collect()
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

#[test]
fn forwards_over_real_udp_and_shuts_down_cleanly() {
    let issuer = Issuer::from_pkcs8(&Issuer::generate().unwrap()).unwrap();
    let scratch = Scratch::new("serve");
    let path = scratch.write("media.toml", SETTINGS, 0o644);
    scratch.write("chat-server.key", &format!("{}\n", hex(&issuer.public_key())), 0o600);

    let config = config::load(&path).unwrap();
    let (socket, server) = serve::bind(&config).unwrap();
    let server_address = socket.local_addr().unwrap();
    assert_eq!(server.address(), server_address, "with no public-address the bound address is the candidate");
    assert!(server_address.ip().is_loopback() && server_address.port() != 0);

    let (handle, mut requests) = intake::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let (done, finished) = mpsc::channel();
    let flag = stop.clone();
    let serving = std::thread::spawn(move || {
        let result = serve::run(&socket, server, &mut requests, &flag);
        let _ = done.send(result.map_err(|e| e.to_string()));
    });

    // Both join through the intake, each with its own credential.
    let mut clients = Vec::new();
    for (n, person) in [(1u64, "ana@example.org"), (2, "ben@example.org")] {
        let (mut client, offer, pending) = Client::new();
        let credential = issuer.issue(CALL, "general", person, n, MEDIA, now_ms()).unwrap();
        let joined = handle.join(CALL, &credential, &offer).unwrap();
        client.rtc.sdp_api().accept_answer(pending, SdpAnswer::from_sdp_string(&joined.answer).unwrap()).unwrap();
        clients.push(client);
    }
    let mut a2 = clients.pop().unwrap();
    let mut a1 = clients.pop().unwrap();
    let (a1, a2) = (&mut a1, &mut a2);
    drive(a1, a2, Duration::from_secs(10), |a, b| a.rtc.is_connected() && b.rtc.is_connected());
    assert!(a1.rtc.is_connected() && a2.rtc.is_connected(), "the clients did not connect over UDP");
    drive(a1, a2, Duration::from_millis(200), |_, _| false);

    // A1 talks for a second: one frame every 20 ms, over real UDP through the server.
    let pt = a1.rtc.codec_config().find(|params| params.spec().codec == Codec::Opus).unwrap().pt();
    let mut sent = Vec::new();
    for n in 0..50u32 {
        let frame = format!("a1 opaque frame {n:04}").into_bytes();
        let time = Duration::from_millis(20 * u64::from(n)).into();
        a1.rtc.writer(a1.mic).unwrap().write(pt, Instant::now(), time, frame.clone()).unwrap();
        sent.push(frame);
        drive(a1, a2, Duration::from_millis(20), |_, _| false);
    }
    drive(a1, a2, Duration::from_millis(500), |_, _| false);
    let at_a2 = a2.received();
    assert!(at_a2.len() >= 45, "only {} of A1's 50 frames reached A2", at_a2.len());
    assert!(at_a2.iter().all(|frame| sent.contains(frame)), "A2 received something A1 did not send");
    assert!(a1.received().is_empty(), "A1 received its own frames");

    // Stop: the loop closes both sessions, says goodbye and returns.
    stop.store(true, Ordering::Release);
    assert_eq!(finished.recv_timeout(Duration::from_secs(5)).unwrap(), Ok(()), "the loop did not stop cleanly");
    serving.join().unwrap();
    drive(a1, a2, Duration::from_secs(2), |a, b| a.closed() && b.closed());
    assert!(a1.closed() && a2.closed(), "a client was not told its session closed");
    // The intake knows the server is gone.
    let (_, offer, _) = Client::new();
    let credential = issuer.issue(CALL, "general", "cleo@example.org", 3, MEDIA, now_ms()).unwrap();
    assert_eq!(handle.join(CALL, &credential, &offer).unwrap_err(), JoinError::Stopped);
}

#[test]
fn settings_and_key_are_read_strictly() {
    let good = config::parse(SETTINGS).unwrap();
    assert_eq!(
        good,
        Settings {
            server_name: MEDIA.to_owned(),
            listen: "127.0.0.1:0".parse().unwrap(),
            public_address: None,
            chat_server_key: "chat-server.key".to_owned(),
            max_call_size: 8,
        }
    );
    let with = |extra: &str| config::parse(&format!("{SETTINGS}{extra}\n"));
    assert!(matches!(with("colour = \"blue\""), Err(TomlError::UnknownKey { .. })));
    assert!(matches!(with("public-address = \"0.0.0.0:3478\""), Err(TomlError::BadValue { .. })), "no candidate");
    let public = config::parse(&SETTINGS.replace("127.0.0.1:0", "0.0.0.0:3478").replace("[media]\n", "[media]\npublic-address = \"203.0.113.10:3478\"\n")).unwrap();
    assert_eq!(public.public_address, Some("203.0.113.10:3478".parse().unwrap()));
    assert!(matches!(config::parse(&SETTINGS.replace("127.0.0.1:0", "0.0.0.0:3478")), Err(TomlError::BadValue { .. })), "unspecified, no public-address");
    assert!(matches!(config::parse(&SETTINGS.replace("= 8", "= 0")), Err(TomlError::BadValue { .. })));
    assert!(matches!(config::parse(&SETTINGS.replace("= 8", "= 65")), Err(TomlError::BadValue { .. })));
    assert!(matches!(config::parse(&SETTINGS.replace("chat-server.key", "../chat-server.key")), Err(TomlError::BadValue { .. })));
    assert!(matches!(config::parse(&SETTINGS.replace("media.example.org", "Media Server")), Err(TomlError::BadValue { .. })));

    let key = [0xa5u8; 32];
    assert_eq!(config::parse_key(&format!("{}\n", hex(&key))), Some(key));
    assert_eq!(config::parse_key(&hex(&key)), Some(key));
    assert_eq!(config::parse_key(&hex(&key[..31])), None, "too short");
    assert_eq!(config::parse_key(&format!("{}zz", hex(&key[..31]))), None, "not hexadecimal");
    assert_eq!(config::parse_key(&format!("{}\n\n", hex(&key))), None, "more than one line");

    // The key file must be owner-only, like the server's other keys (Unix permissions).
    let scratch = Scratch::new("strict");
    let path = scratch.write("media.toml", SETTINGS, 0o644);
    assert!(config::load(&path).is_err(), "a missing key file");
    scratch.write("chat-server.key", &hex(&key), 0o600);
    assert_eq!(config::load(&path).unwrap().trusted_key, key);
    #[cfg(unix)]
    {
        scratch.write("chat-server.key", &hex(&key), 0o640);
        let refused = config::load(&path).unwrap_err().to_string();
        assert!(refused.contains("owner-only"), "{refused}");
    }
}

#[test]
fn the_binary_refuses_bad_settings() {
    let binary = Path::new(env!("CARGO_BIN_EXE_crewcraft-media"));
    let usage = Command::new(binary).output().unwrap();
    assert_eq!(usage.status.code(), Some(2), "no settings file is a usage error");

    let scratch = Scratch::new("binary");
    let path = scratch.write("media.toml", &format!("{SETTINGS}colour = \"blue\"\n"), 0o644);
    let refused = Command::new(binary).arg(&path).output().unwrap();
    assert_eq!(refused.status.code(), Some(1));
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(message.contains("colour"), "the error names the bad key: {message}");
}
