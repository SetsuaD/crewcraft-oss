//! The chat server's media server (docs/CALLS.md "Admission: removed means removed", tasks T360b2 and T360b3):
//! `media.toml` in the data directory, the media key credentials are signed with, and the control connection that
//! tells the media server whom to drop.
//!
//! Owns: reading `media.toml` ([`parse`], [`load`]), the media key (made at the first start, owner-only, with its
//! public half beside it for the media server's `chat-server-key`), and [`MediaLink::run`]: every tick it sweeps the
//! calls (so a stopped heartbeat drops someone without waiting for traffic), takes the core's `MediaEvent`s and sends
//! them over mutual TLS. A reconnect within this process resends unacknowledged events before dispatching guest
//! offers. A chat server restart still reconstructs removed guests from durable state for open calls.
//! Called by: `main.rs` (`serve`) and `lab_runtime` (the thread beside the listener).
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
//!
//! The certificates can come from the operator (any CA) or from `crewcraft-server media-link-cert` ([`issue_link`],
//! task T360b5), which writes all six files with the names above and in the media server's `media.toml`. It makes a
//! link CA of its own for each issue and throws its key away: the chat server's device CA is not used, because every
//! enrolled device holds a client certificate from it and must not be able to reach the control port. The
//! certificates last `crewcraft_pki::LINK_LIFETIME_SECS` (30 days); rotate by running the command again (it replaces
//! the files), copying the media server's three files across and restarting both servers. Until both have the new
//! files the link refuses to connect and the chat server keeps the events waiting.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crewcraft_media_auth::Issuer;
use crewcraft_proto::frame::{encode, read_frame};
use crewcraft_proto::media_control::{ControlMessage, MAX_CONTROL_MESSAGE, REFUSED_CREDENTIAL, decode_control, encode_control};
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::guests::{GuestEntrance, GuestError, GuestProof};
use crewcraft_server_core::media::{MAX_MEDIA_EVENTS, MediaEvent, MediaIssuer};
use crewcraft_strict_toml as toml;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::device_session::{MediaRelay, RelayRefusal};
use crate::server_install::{hex, read_file, write_new};

/// The files `issue_link` writes into the chat server's data directory: the link CA, its client certificate and key.
pub const CHAT_LINK_FILES: [&str; 3] = ["media-ca.pem", "media-client.pem", "media-client-key.pem"];
/// The files `issue_link` writes for the media server: its certificate chain and key, and the link CA.
pub const MEDIA_LINK_FILES: [&str; 3] = ["media.pem", "media-key.pem", "chat-ca.pem"];

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
/// How long an offer can wait for its answer, including a guest waiting behind pending drops.
const JOIN_WAIT: Duration = PATIENCE.saturating_mul(3);

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
    Ok(Some((issuer, MediaLink::new(settings.control, name, tls))))
}

type Control = StreamOwned<ClientConnection, TcpStream>;

/// The control connection to the media server.
pub struct MediaLink {
    control: SocketAddr,
    name: ServerName<'static>,
    tls: Arc<ClientConfig>,
    /// Participants' offers waiting to be relayed (task T360b6), and the handle that queues them.
    joins: Mutex<Receiver<JoinRequest>>,
    relay: MediaRelayHandle,
}

/// One offer to relay, and where its answer goes.
struct JoinRequest {
    admission: JoinAdmission,
    offer: String,
    reply: Sender<Result<String, RelayRefusal>>,
    deadline: Instant,
}

enum JoinAdmission {
    Staff { call: u64, credential: Vec<u8> },
    Guest { peer: IpAddr, proof: GuestProof },
}

struct AuthorizedJoin {
    call: u64,
    credential: Vec<u8>,
    guest: Option<GuestProof>,
}

struct PendingMedia {
    waiting: VecDeque<(u64, MediaEvent)>,
    next_seq: u64,
    overflowed: bool,
}

impl PendingMedia {
    fn next(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq += 1;
        seq
    }

    fn collect(&mut self, rooms: &mut DurableServer, now: u64) -> bool {
        let swept_guests = rooms.sweep_guest_links(now).is_ok();
        let swept_calls = rooms.sweep_calls(now).is_ok();
        let events = rooms.take_media_events();
        // The room store and the link each bound their queues. A full room-store batch may already have lost a drop.
        self.overflowed |= events.len() >= MAX_MEDIA_EVENTS || self.waiting.len() + events.len() > MAX_MEDIA_EVENTS;
        for event in events {
            if self.waiting.len() >= MAX_MEDIA_EVENTS {
                self.waiting.pop_front();
            }
            let seq = self.next();
            self.waiting.push_back((seq, event));
        }
        swept_guests && swept_calls
    }
}

/// How many offers may wait for the link at once; more wait in their own device connection.
const JOIN_QUEUE: usize = 64;

/// A cloneable way for device connections to relay offers through the link (task T360b6).
#[derive(Clone)]
pub struct MediaRelayHandle {
    joins: SyncSender<JoinRequest>,
}

impl MediaRelay for MediaRelayHandle {
    fn join(&self, call: u64, credential: &[u8], offer: &str) -> Result<String, RelayRefusal> {
        self.submit(JoinAdmission::Staff { call, credential: credential.to_vec() }, offer)
    }
}

impl MediaRelayHandle {
    /// Relay a guest offer from a trusted adapter. The queued request keeps the proof until dispatch,
    /// when the link can check current admission and issue a credential for the current call.
    pub fn join_guest(&self, peer: IpAddr, proof: &GuestProof, offer: &str) -> Result<String, RelayRefusal> {
        self.submit(JoinAdmission::Guest { peer, proof: proof.clone() }, offer)
    }

    fn submit(&self, admission: JoinAdmission, offer: &str) -> Result<String, RelayRefusal> {
        let (reply, answer) = mpsc::channel();
        let request = JoinRequest { admission, offer: offer.to_owned(), reply, deadline: Instant::now() + JOIN_WAIT };
        self.joins.send(request).map_err(|_| RelayRefusal::Unavailable)?;
        answer.recv_timeout(JOIN_WAIT).unwrap_or(Err(RelayRefusal::Unavailable))
    }
}

impl MediaLink {
    /// A link to the control port `control`, whose certificate must be for `name` and chain to `tls`'s roots.
    pub fn new(control: SocketAddr, name: ServerName<'static>, tls: Arc<ClientConfig>) -> Self {
        let (joins, queued) = mpsc::sync_channel(JOIN_QUEUE);
        Self { control, name, tls, joins: Mutex::new(queued), relay: MediaRelayHandle { joins } }
    }

    /// The handle device connections relay offers through (task T360b6).
    pub fn relay(&self) -> MediaRelayHandle {
        self.relay.clone()
    }

    /// Send `message` and read the one message that answers it.
    fn exchange(control: &mut Control, message: &ControlMessage) -> io::Result<ControlMessage> {
        let bytes = encode_control(message).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        control.write_all(&encode(&bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?)?;
        control.flush()?;
        let frame = read_frame(control, MAX_CONTROL_MESSAGE)?.ok_or(io::ErrorKind::UnexpectedEof)?;
        decode_control(frame.payload()).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
    }

    /// A queued guest waits for the link and the media loop's acknowledgements before it is authorized.
    /// Once sent, a join is never retried: its credential admits once.
    fn relay_join(
        control: &mut Option<Control>,
        pending: &mut PendingMedia,
        join: JoinRequest,
        rooms: &Mutex<DurableServer>,
        now_ms: &dyn Fn() -> u64,
    ) -> Option<JoinRequest> {
        let is_guest = matches!(&join.admission, JoinAdmission::Guest { .. });
        if is_guest && (Instant::now() >= join.deadline || pending.overflowed) {
            let _ = join.reply.send(Err(RelayRefusal::Unavailable));
            return None;
        }
        let Some(connected) = control.as_mut() else {
            if is_guest {
                return Some(join);
            }
            let _ = join.reply.send(Err(RelayRefusal::Unavailable));
            return None;
        };
        if is_guest && connected.conn.is_handshaking() && connected.conn.complete_io(&mut connected.sock).is_err() {
            *control = None;
            return Some(join);
        }
        let JoinRequest { admission, offer, reply, deadline } = join;
        let AuthorizedJoin { call, credential, guest } = match admission {
            JoinAdmission::Staff { call, credential } => AuthorizedJoin { call, credential, guest: None },
            JoinAdmission::Guest { peer, proof } => {
                // A drop may have committed while the link waited for this offer, connected, or waited for an ACK.
                // Sample again under the same room lock as authorization. The socket runs without that lock.
                let Ok(mut rooms) = rooms.lock() else {
                    let _ = reply.send(Err(RelayRefusal::Unavailable));
                    return None;
                };
                let now = now_ms();
                if !pending.collect(&mut rooms, now) || pending.overflowed || Instant::now() >= deadline {
                    let _ = reply.send(Err(RelayRefusal::Unavailable));
                    return None;
                }
                if !pending.waiting.is_empty() {
                    return Some(JoinRequest { admission: JoinAdmission::Guest { peer, proof }, offer, reply, deadline });
                }
                match rooms.guest_entrance(|| now).media(peer, &proof) {
                    Ok(media) => AuthorizedJoin { call: media.call, credential: media.credential, guest: Some(proof) },
                    Err(error) => {
                        let refusal = match error {
                            GuestError::MediaUnavailable | GuestError::Durable(_) => RelayRefusal::Unavailable,
                            _ => RelayRefusal::Refused(REFUSED_CREDENTIAL),
                        };
                        let _ = reply.send(Err(refusal));
                        return None;
                    }
                }
            }
        };
        let seq = pending.next();
        let message = ControlMessage::Join { seq, call, credential, offer };
        let answer = match Self::exchange(connected, &message) {
            Ok(ControlMessage::JoinAnswer { seq: answered, answer }) if answered == seq => Ok(answer),
            Ok(ControlMessage::JoinRefused { seq: answered, reason }) if answered == seq => Err(RelayRefusal::Refused(reason)),
            _ => {
                *control = None;
                Err(RelayRefusal::Unavailable)
            }
        };
        match (answer, guest) {
            (Ok(answer), Some(proof)) => {
                // Order delivery of the answer against durable lobby changes without holding the
                // room lock during the network exchange.
                let Ok(mut rooms) = rooms.lock() else {
                    let _ = reply.send(Err(RelayRefusal::Unavailable));
                    return None;
                };
                let now = now_ms();
                let answer = match rooms.sweep_calls(now) {
                    Err(_) => Err(RelayRefusal::Unavailable),
                    Ok(()) if rooms.guest_media_call(&proof, now).is_ok_and(|current| current == call) => Ok(answer),
                    Ok(()) => Err(RelayRefusal::Refused(REFUSED_CREDENTIAL)),
                };
                let _ = reply.send(answer);
            }
            (answer, _) => {
                // The asker may have given up waiting.
                let _ = reply.send(answer);
            }
        }
        None
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
        match Self::exchange(control, &message)? {
            ControlMessage::Ack { seq: acked } if acked == seq => Ok(()),
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }

    /// Run until `stopped`: sweep the calls of `rooms`, take their media events and deliver them, in order, and relay
    /// participants' offers as they come (task T360b6).
    pub fn run(&self, stopped: &dyn Fn() -> bool, rooms: &Mutex<DurableServer>, now_ms: &dyn Fn() -> u64) {
        let Ok(joins) = self.joins.lock() else { return };
        let mut pending = PendingMedia { waiting: VecDeque::new(), next_seq: 1, overflowed: false };
        let mut next_join: Option<JoinRequest> = None;
        let mut deferred_guests = VecDeque::new();
        let mut control: Option<Control> = None;
        let mut retry_at = Instant::now();
        while !stopped() {
            {
                let Ok(mut rooms) = rooms.lock() else { return };
                // A failed sweep is the journal failing; the listener's own requests report that.
                pending.collect(&mut rooms, now_ms());
            }
            let join = next_join.take().or_else(|| deferred_guests.pop_front());
            let staff_offer = join.as_ref().is_some_and(|join| matches!(&join.admission, JoinAdmission::Staff { .. }));
            let needs_ordered_link = !pending.waiting.is_empty() || (join.is_some() && !staff_offer);
            if control.is_none() && needs_ordered_link && Instant::now() >= retry_at {
                match self.connect() {
                    Ok(connected) => control = Some(connected),
                    Err(_) => retry_at = Instant::now() + RETRY,
                }
            }
            if let Some(connected) = control.as_mut() {
                while let Some((seq, event)) = pending.waiting.front() {
                    if stopped() {
                        return;
                    }
                    if Self::send(connected, *seq, event).is_err() {
                        control = None;
                        retry_at = Instant::now() + RETRY;
                        break;
                    }
                    pending.waiting.pop_front();
                }
            }
            if staff_offer && control.is_none() {
                // Preserve the existing staff attempt after an event delivery fails.
                control = self.connect().ok();
            }
            if let Some(join) = join {
                let was_connected = control.is_some();
                let deferred = Self::relay_join(&mut control, &mut pending, join, rooms, now_ms);
                if control.is_none() && was_connected {
                    retry_at = Instant::now() + RETRY;
                }
                if let Some(guest) = deferred {
                    if deferred_guests.len() == JOIN_QUEUE {
                        let _ = guest.reply.send(Err(RelayRefusal::Unavailable));
                    } else {
                        deferred_guests.push_back(guest);
                    }
                }
            }
            // Accept fresh offers even when an earlier guest is waiting for acknowledgements.
            next_join = joins.recv_timeout(TICK).ok();
        }
    }
}

/// `der` as PEM with `label`.
fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = text.as_bytes().chunks(64).filter_map(|line| std::str::from_utf8(line).ok()).collect();
    format!(
        "-----BEGIN {label}-----
{}
-----END {label}-----
",
        lines.join(
            "
"
        )
    )
}

/// Write `bytes` to `dir/name`, owner-only, replacing what is there in one step (a new file, then a rename).
fn replace(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let fresh = dir.join(format!("{name}.new"));
    let _ = std::fs::remove_file(&fresh);
    write_new(&fresh, bytes)?;
    std::fs::rename(&fresh, dir.join(name))
}

/// Issue the media control link's certificates (task T360b5): a new link CA, a server certificate for the media server
/// named `media_name` and a client certificate for this chat server, each good for `crewcraft_pki::LINK_LIFETIME_SECS`
/// from `now_ms`. Writes `CHAT_LINK_FILES` into `data` and `MEDIA_LINK_FILES` into `media_out` (made if missing),
/// owner-only, replacing earlier ones; the link CA's key is never written. Returns when the certificates expire, in
/// Unix seconds.
pub fn issue_link(data: &Path, media_out: &Path, media_name: &str, now_ms: u64) -> io::Result<i64> {
    if ServerName::try_from(media_name.to_owned()).is_err() || media_name.is_empty() {
        return Err(invalid(format!("{media_name} is not a server name")));
    }
    let failed = |_| io::Error::other("could not issue the media link certificates");
    let ca = crewcraft_pki::Authority::create_root("media link CA", now_ms).map_err(failed)?;
    let media = ca.server_certificate_for(media_name, now_ms, crewcraft_pki::LINK_LIFETIME_SECS).map_err(failed)?;
    let chat = ca.client_certificate("chat server", now_ms, crewcraft_pki::LINK_LIFETIME_SECS).map_err(failed)?;
    let chain = |chain: &[Vec<u8>]| chain.iter().map(|der| pem("CERTIFICATE", der)).collect::<String>();
    let ca_pem = pem("CERTIFICATE", ca.certificate());
    std::fs::create_dir_all(media_out)?;
    let [media_ca, client_certificate, client_key] = CHAT_LINK_FILES;
    replace(data, media_ca, ca_pem.as_bytes())?;
    replace(data, client_certificate, chain(&chat.chain).as_bytes())?;
    replace(data, client_key, pem("PRIVATE KEY", &chat.key_pkcs8).as_bytes())?;
    let [certificate, key, chat_ca] = MEDIA_LINK_FILES;
    replace(media_out, certificate, chain(&media.chain).as_bytes())?;
    replace(media_out, key, pem("PRIVATE KEY", &media.key_pkcs8).as_bytes())?;
    replace(media_out, chat_ca, ca_pem.as_bytes())?;
    let seconds = i64::try_from(now_ms / 1000).map_err(|_| invalid("the clock is out of range".to_owned()))?;
    Ok(seconds.saturating_add(crewcraft_pki::LINK_LIFETIME_SECS))
}
