//! T360b5: the media control link's certificates, issued by the chat server (`crewcraft-server media-link-cert`,
//! `media_link::issue_link`) instead of made by hand. The generated files carry the names both `media.toml`s use, the
//! keys are owner-only, the certificates are short-lived, and the pair completes the mutual-TLS link: an event from
//! the chat server reaches the media server's intake. A client certificate from another issue (another link CA) is
//! refused, and running the command again replaces the files.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft_media::config::ControlSettings;
use crewcraft_media::intake::{self, Intake, Request};
use crewcraft_media_server::control::{ControlListener, tls_config};
use crewcraft_proto::frame::{encode, read_frame};
use crewcraft_proto::media_control::{ControlMessage, MAX_CONTROL_MESSAGE, encode_control};
use crewcraft_server::media_link::{self, CHAT_LINK_FILES, MEDIA_LINK_FILES};
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::room::Role;

const MEDIA: &str = "media.example.org";
const ANA: &str = "ana@example.org";
const BO: &str = "bo@example.org";
/// The certificates' life (crewcraft_pki::LINK_LIFETIME_SECS): 30 days.
const THIRTY_DAYS: i64 = 30 * 86_400;

fn now_ms() -> u64 {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

/// A fresh directory with `chat` and `media` inside, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("crewcraft-t360b5-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(dir.join("chat")).unwrap();
        Scratch(dir)
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

fn control_settings() -> ControlSettings {
    ControlSettings {
        listen: "127.0.0.1:0".parse().unwrap(),
        certificate: MEDIA_LINK_FILES[0].to_owned(),
        key: MEDIA_LINK_FILES[1].to_owned(),
        chat_server_ca: MEDIA_LINK_FILES[2].to_owned(),
    }
}

/// Wait up to `wait` until `intake` has a request, and return it.
fn next_request(intake: &mut impl Intake, wait: Duration) -> Option<Request> {
    let until = Instant::now() + wait;
    let mut requests = Vec::new();
    while Instant::now() < until {
        intake.take(&mut requests);
        if let Some(request) = requests.pop() {
            return Some(request);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

#[test]
fn the_issued_pair_completes_the_link_and_another_ca_is_refused() {
    let files = Scratch::new("link");
    let (chat, media) = (files.path("chat"), files.path("media"));
    let issued_at = now_ms();
    let until = media_link::issue_link(&chat, &media, MEDIA, issued_at).unwrap();
    assert_eq!(until, i64::try_from(issued_at / 1000).unwrap() + THIRTY_DAYS, "short-lived: 30 days");
    for (dir, names) in [(&chat, CHAT_LINK_FILES), (&media, MEDIA_LINK_FILES)] {
        for name in names {
            let path = dir.join(name);
            assert!(path.is_file(), "{} was written", path.display());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o077, 0, "{name} is owner-only");
            }
        }
    }

    // The media server's end, from the issued files: the control listener feeds an intake the test reads.
    let stop = Arc::new(AtomicBool::new(false));
    let (handle, mut requests) = intake::channel();
    let control = control_settings();
    let listener = ControlListener::start(control.listen, tls_config(&media, &control).unwrap(), handle, stop.clone()).unwrap();
    let control_address = listener.local_addr();

    // The chat server's end, from its issued files, sends the event of Bo leaving a call.
    let settings = format!(
        "[media]\nserver-name = \"{MEDIA}\"\naddress = \"203.0.113.10:3478\"\ncontrol = \"{control_address}\"\nkey = \"media.key\"\nca-bundle = \"{}\"\nclient-certificate = \"{}\"\nclient-key = \"{}\"\n",
        CHAT_LINK_FILES[0], CHAT_LINK_FILES[1], CHAT_LINK_FILES[2]
    );
    std::fs::write(chat.join("media.toml"), settings).unwrap();
    let (issuer, link) = media_link::load(&chat).unwrap().unwrap();
    let rooms = Arc::new(Mutex::new(DurableServer::open(&chat.join("rooms.journal")).unwrap()));
    let call = {
        let mut rooms = rooms.lock().unwrap();
        rooms.set_media(issuer);
        let room = rooms.create_room(ANA, "Project").unwrap();
        rooms.add_member(&room, ANA, BO, Role::Member).unwrap();
        let call = rooms.call_start(&room, ANA, false, now_ms()).unwrap();
        rooms.call_join(&room, BO, call, now_ms()).unwrap();
        rooms.call_leave(&room, BO, call, now_ms()).unwrap();
        call
    };
    let chat_stop = Arc::new(AtomicBool::new(false));
    let linking = {
        let (rooms, chat_stop) = (rooms.clone(), chat_stop.clone());
        std::thread::spawn(move || link.run(&|| chat_stop.load(Ordering::Acquire), &rooms, &now_ms))
    };
    match next_request(&mut requests, Duration::from_secs(10)) {
        Some(Request::DropPerson { call: dropped, person }) => assert_eq!((dropped, person.as_str()), (call, BO)),
        _ => panic!("the event did not cross the link made of the issued certificates"),
    }
    chat_stop.store(true, Ordering::Release);
    linking.join().unwrap();

    // Another issue makes another link CA: its client certificate is refused by this media server.
    let other = Scratch::new("other");
    media_link::issue_link(&other.path("chat"), &other.path("media"), MEDIA, now_ms()).unwrap();
    let read = |dir: &Path, name: &str| std::fs::read(dir.join(name)).unwrap();
    let roots = crewcraft_tls::pem::roots(&read(&chat, CHAT_LINK_FILES[0])).unwrap();
    let identity =
        crewcraft_tls::pem::identity(&read(&other.path("chat"), CHAT_LINK_FILES[1]), &read(&other.path("chat"), CHAT_LINK_FILES[2])).unwrap();
    let tcp = TcpStream::connect(control_address).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut stranger = crewcraft_tls::connect(tcp, crewcraft_tls::client_config(roots, Some(identity)).unwrap(), MEDIA.try_into().unwrap()).unwrap();
    let message = encode_control(&ControlMessage::EndCall { seq: 1, call }).unwrap();
    let answer =
        stranger.write_all(&encode(&message).unwrap()).and_then(|()| stranger.flush()).and_then(|()| read_frame(&mut stranger, MAX_CONTROL_MESSAGE));
    assert!(!matches!(answer, Ok(Some(_))), "the media server answered a certificate from another link CA");
    assert!(next_request(&mut requests, Duration::from_secs(1)).is_none(), "a certificate from another link CA ended a call");

    // Running it again (rotation) replaces the files with new certificates.
    let before = read(&media, MEDIA_LINK_FILES[0]);
    media_link::issue_link(&chat, &media, MEDIA, now_ms()).unwrap();
    assert_ne!(read(&media, MEDIA_LINK_FILES[0]), before, "rotation replaced the media server's certificate");
    assert!(!media.join(format!("{}.new", MEDIA_LINK_FILES[0])).exists(), "no half-written file is left");

    stop.store(true, Ordering::Release);
    listener.join();
}
