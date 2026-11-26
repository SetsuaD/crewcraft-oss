//! The chat server's media server (docs/CALLS.md "Admission: removed means removed", tasks T360b2 and T360b3):
//! `media.toml` in the data directory, the media key credentials are signed with, and the control connection that
//! tells the media server whom to drop.
//!
//! Owns: reading `media.toml` ([`parse`], [`load`]), the media key (made at the first start, owner-only, with its
//! public half beside it for the media server's `chat-server-key`), and [`MediaLink::run`]: every tick it sweeps the
//! calls (so a stopped heartbeat drops someone without waiting for traffic), takes the core's `MediaEvent`s and sends
//! them over mutual TLS, each until the media server acknowledges it; a broken connection is made again and the
//! unacknowledged events sent again. Called by: `main.rs` (`serve`) and `lab_runtime` (the thread beside the listener).
//!
//! ```toml
//! [media]
//! server-name = "media.example.org"      # what credentials name, and the name on the media server's certificate
//! address = "203.0.113.10:3478"          # what clients are told: the media server's UDP address
//! control = "203.0.113.10:7443"          # the media server's control port
//! key = "media.key"                      # the chat server's media key (Ed25519, PKCS#8), owner-only; made at the
//!                                        # first start, with media.key.pub (64 hex characters) for the media server
//! ca-bundle = "media-ca.pem"             # the only CA the media server's certificate may chain to
//! client-certificate = "media-client.pem" # this server's certificate for the control connection
//! client-key = "media-client-key.pem"    # its key, owner-only
//! ```

use std::collections::VecDeque;
use std::io::{self, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crewcraft_media_auth::Issuer;
use crewcraft_proto::frame::{encode, read_frame};
use crewcraft_proto::media_control::{ControlMessage, MAX_CONTROL_MESSAGE, decode_control, encode_control};
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::media::{MAX_MEDIA_EVENTS, MediaEvent, MediaIssuer};
use crewcraft_strict_toml as toml;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::server_install::{hex, read_file, write_new};

/// The media settings file in the data directory.
pub const MEDIA_FILE: &str = "media.toml";
const MAX_FILE_BYTES: usize = 16 * 1024;
const MAX_KEY_BYTES: u64 = 1024;
const MAX_PEM_BYTES: u64 = 1024 * 1024;
/// How often the link sweeps the calls and sends what is waiting.
const TICK: Duration = Duration::from_millis(50);
/// How long to wait before connecting again after a failure.
const RETRY: Duration = Duration::from_secs(1);
/// How long connecting, sending one event or waiting for its acknowledgement may take.
const PATIENCE: Duration = Duration::from_secs(5);

/// `media.toml`, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaSettings {
    pub server_name: String,
    pub address: SocketAddr,
    pub control: SocketAddr,
    pub key: String,
    pub ca_bundle: String,
    pub client_certificate: String,
    pub client_key: String,
}

fn bad(line: usize, key: &str, reason: &'static str) -> toml::Error {
    toml::Error::BadValue { line, key: key.to_owned(), reason }
}

fn address(section: &toml::Section, key: &str) -> Result<SocketAddr, toml::Error> {
    let (text, line) = section.req_str("media", key)?;
    let address: SocketAddr = text.parse().map_err(|_| bad(line, key, "an IP address and port, such as \"203.0.113.10:3478\""))?;
    if address.ip().is_unspecified() || address.port() == 0 {
        return Err(bad(line, key, "a specific address and port"));
    }
    Ok(address)
}

fn file_name(section: &toml::Section, key: &str) -> Result<String, toml::Error> {
    let (name, line) = section.req_str("media", key)?;
    let plain = !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if plain { Ok(name.to_owned()) } else { Err(bad(line, key, "a plain file name in the data directory")) }
}

/// Read `media.toml`.
pub fn parse(text: &str) -> Result<MediaSettings, toml::Error> {
    let doc = toml::parse(text, MAX_FILE_BYTES)?;
    doc.check_sections(&["media"], &[])?;
    let media = doc.require("media")?;
    media.check_keys("media", &["server-name", "address", "control", "key", "ca-bundle", "client-certificate", "client-key"])?;
    let (server_name, line) = media.req_str("media", "server-name")?;
    let plain_name = !server_name.is_empty()
        && server_name.len() <= crewcraft_media_auth::MAX_NAME
        && server_name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
        && ServerName::try_from(server_name.to_owned()).is_ok();
    if !plain_name {
        return Err(bad(line, "server-name", "a host name: lowercase letters, digits, dots and hyphens"));
    }
    Ok(MediaSettings {
        server_name: server_name.to_owned(),
        address: address(media, "address")?,
        control: address(media, "control")?,
        key: file_name(media, "key")?,
        ca_bundle: file_name(media, "ca-bundle")?,
        client_certificate: file_name(media, "client-certificate")?,
        client_key: file_name(media, "client-key")?,
    })
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read(dir: &Path, name: &str, limit: u64, private: bool) -> io::Result<Vec<u8>> {
    read_file(&dir.join(name), limit, private).map_err(|e| io::Error::new(e.kind(), format!("{MEDIA_FILE}: {name}: {e}")))
}

/// The media key named `name` in `dir`, made (owner-only) with `name.pub` beside it when there is none yet.
fn media_key(dir: &Path, name: &str) -> io::Result<Issuer> {
    let path = dir.join(name);
    if std::fs::symlink_metadata(&path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
        let pkcs8 = Issuer::generate().map_err(|_| io::Error::other("could not make the media key"))?;
        write_new(&path, &pkcs8)?;
        let issuer = Issuer::from_pkcs8(&pkcs8).map_err(|_| io::Error::other("could not use the media key"))?;
        let public = dir.join(format!("{name}.pub"));
        let _ = std::fs::remove_file(&public);
        write_new(&public, format!("{}\n", hex(&issuer.public_key())).as_bytes())?;
        return Ok(issuer);
    }
    let pkcs8 = read(dir, name, MAX_KEY_BYTES, true)?;
    Issuer::from_pkcs8(&pkcs8).map_err(|_| invalid(format!("{MEDIA_FILE}: {name} is not a media key")))
}

/// The media server `media.toml` in `dir` describes, or `None` without the file: the issuer for the room store and
/// the link to run beside the listener. A file that does not check out is an error, not a server without media.
pub fn load(dir: &Path) -> io::Result<Option<(MediaIssuer, MediaLink)>> {
    let path = dir.join(MEDIA_FILE);
    let text = match read_file(&path, MAX_FILE_BYTES as u64, false) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io::Error::new(e.kind(), format!("{MEDIA_FILE}: {e}"))),
        Ok(bytes) => String::from_utf8(bytes).map_err(|_| invalid(format!("{MEDIA_FILE} is not UTF-8")))?,
    };
    let settings = parse(&text).map_err(|e| invalid(format!("{MEDIA_FILE}: {e}")))?;
    let issuer = media_key(dir, &settings.key)?;
    let chain = read(dir, &settings.client_certificate, MAX_PEM_BYTES, false)?;
    let key = read(dir, &settings.client_key, MAX_PEM_BYTES, true)?;
    let ca = read(dir, &settings.ca_bundle, MAX_PEM_BYTES, false)?;
    let identity = crewcraft_tls::pem::identity(&chain, &key)?;
    let tls = crewcraft_tls::client_config(crewcraft_tls::pem::roots(&ca)?, Some(identity)).map_err(|e| invalid(format!("{MEDIA_FILE}: {e}")))?;
    let name = ServerName::try_from(settings.server_name.clone()).map_err(|_| invalid(format!("{MEDIA_FILE}: server-name")))?;
    let issuer = MediaIssuer::new(issuer, &settings.server_name, &settings.address.to_string());
    Ok(Some((issuer, MediaLink { control: settings.control, name, tls })))
}

type Control = StreamOwned<ClientConnection, TcpStream>;

/// The control connection to the media server.
pub struct MediaLink {
    control: SocketAddr,
    name: ServerName<'static>,
    tls: Arc<ClientConfig>,
}

impl MediaLink {
    /// A link to the control port `control`, whose certificate must be for `name` and chain to `tls`'s roots.
    pub fn new(control: SocketAddr, name: ServerName<'static>, tls: Arc<ClientConfig>) -> Self {
        Self { control, name, tls }
    }

    fn connect(&self) -> io::Result<Control> {
        let tcp = TcpStream::connect_timeout(&self.control, PATIENCE)?;
        tcp.set_read_timeout(Some(PATIENCE))?;
        tcp.set_write_timeout(Some(PATIENCE))?;
        tcp.set_nodelay(true)?;
        crewcraft_tls::connect(tcp, self.tls.clone(), self.name.clone()).map_err(|e| io::Error::other(e.to_string()))
    }

    /// Send `event` as message `seq` and wait for its acknowledgement.
    fn send(control: &mut Control, seq: u64, event: &MediaEvent) -> io::Result<()> {
        let message = match event {
            MediaEvent::DropPerson { call, person } => ControlMessage::DropPerson { seq, call: *call, person: person.clone() },
            MediaEvent::EndCall { call } => ControlMessage::EndCall { seq, call: *call },
        };
        let bytes = encode_control(&message).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        control.write_all(&encode(&bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?)?;
        control.flush()?;
        let frame = read_frame(control, MAX_CONTROL_MESSAGE)?.ok_or(io::ErrorKind::UnexpectedEof)?;
        match decode_control(frame.payload()) {
            Ok(ControlMessage::Ack { seq: acked }) if acked == seq => Ok(()),
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }

    /// Run until `stopped`: sweep the calls of `rooms`, take their media events and deliver them, in order.
    pub fn run(&self, stopped: &dyn Fn() -> bool, rooms: &Mutex<DurableServer>, now_ms: &dyn Fn() -> u64) {
        let mut waiting: VecDeque<(u64, MediaEvent)> = VecDeque::new();
        let mut next_seq: u64 = 1;
        let mut control: Option<Control> = None;
        let mut retry_at = Instant::now();
        while !stopped() {
            {
                let Ok(mut rooms) = rooms.lock() else { return };
                // A failed sweep is the journal failing; the listener's own requests report that.
                let _ = rooms.sweep_calls(now_ms());
                for event in rooms.take_media_events() {
                    if waiting.len() >= MAX_MEDIA_EVENTS {
                        waiting.pop_front();
                    }
                    waiting.push_back((next_seq, event));
                    next_seq += 1;
                }
            }
            if !waiting.is_empty() && control.is_none() && Instant::now() >= retry_at {
                match self.connect() {
                    Ok(connected) => control = Some(connected),
                    Err(_) => retry_at = Instant::now() + RETRY,
                }
            }
            if let Some(connected) = control.as_mut() {
                while let Some((seq, event)) = waiting.front() {
                    if Self::send(connected, *seq, event).is_err() {
                        control = None;
                        retry_at = Instant::now() + RETRY;
                        break;
                    }
                    waiting.pop_front();
                }
            }
            std::thread::sleep(TICK);
        }
    }
}
