//! T370f: the isolated browser lobby over actual loopback HTTPS. The fixtures make their own lab CA and
//! a journal with synthetic meetings and visitors, and send HTTP without a browser or a deployed service.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use crewcraft_pki::{Authority, ServerIdentity};
use crewcraft_proto::guest::{GuestCode, GuestDecision, GuestLobby, GuestMeetingChange, GuestMeetingDraft, GuestReply, GuestState};
use crewcraft_proto::handshake::ServerSide;
use crewcraft_server::guest_lab::{self, GuestLab};
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::guests::MIN_LINK_MS;
use crewcraft_tls::{DeadlineSocket, Identity};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{Value, json};

const HOST: &str = "localhost";
const OWNER: &str = "host@example.org";
const TITLE: &str = "Planning";
const DISPLAY_HOST: &str = "Fixture host";
const PRIVATE_AGENDA: &str = "Private fixture agenda";
const WAIT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("crewcraft-t370f-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Running {
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl Running {
    fn start(serve: impl FnOnce(&AtomicBool) -> io::Result<()> + Send + 'static) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let task = thread::spawn(move || serve(&shutdown));
        Self { stop, task: Some(task) }
    }

    fn finish(&mut self) -> thread::Result<io::Result<()>> {
        self.stop.store(true, Ordering::Release);
        self.task.take().map_or(Ok(Ok(())), JoinHandle::join)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}

struct LobbyLab {
    running: Running,
    rooms: Arc<Mutex<DurableServer>>,
    addr: SocketAddr,
    tls: Arc<ClientConfig>,
    clock: Arc<AtomicU64>,
    now: u64,
    room: String,
    journal: PathBuf,
    scratch: Scratch,
}

fn wall_ms() -> u64 {
    u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

fn identity(cert: ServerIdentity) -> Identity {
    (cert.chain.into_iter().map(CertificateDer::from).collect(), PrivatePkcs8KeyDer::from(cert.key_pkcs8).into())
}

fn client_tls(root: &[u8]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(root.to_vec())).unwrap();
    crewcraft_tls::client_config(roots, None).unwrap()
}

fn connect(addr: SocketAddr, tls: Arc<ClientConfig>) -> StreamOwned<ClientConnection, DeadlineSocket> {
    let tcp = TcpStream::connect_timeout(&addr, WAIT).unwrap();
    let stream = crewcraft_tls::connect(tcp, tls, HOST.try_into().unwrap()).unwrap();
    StreamOwned::new(stream.conn, DeadlineSocket::new(stream.sock, Instant::now() + WAIT))
}

impl LobbyLab {
    fn start() -> Self {
        let now = wall_ms();
        let scratch = Scratch::new();
        let journal = scratch.0.join("rooms.journal");
        let mut rooms = DurableServer::open(&journal).unwrap();
        let room = rooms.create_room(OWNER, "Fixture room").unwrap();
        let rooms = Arc::new(Mutex::new(rooms));

        let ca = Authority::create_root("Fixture lobby CA", now).unwrap();
        let cert = ca.server_certificate(HOST, now).unwrap();
        let tls = client_tls(ca.certificate());
        let listener = GuestLab::bind((Ipv4Addr::LOCALHOST, 0).into(), HOST, identity(cert)).unwrap();
        let addr = listener.local_addr().unwrap();
        let clock = Arc::new(AtomicU64::new(now));
        let running = Running::start({
            let rooms = rooms.clone();
            let clock = clock.clone();
            move |shutdown| listener.serve(shutdown, rooms, move || clock.load(Ordering::Acquire))
        });
        Self { running, rooms, addr, tls, clock, now, room, journal, scratch }
    }

    fn meeting(&self) -> (GuestLobby, GuestCode) {
        let draft = GuestMeetingDraft {
            room: self.room.clone(),
            start_ms: self.now,
            duration: 30,
            title: TITLE.into(),
            agenda: PRIVATE_AGENDA.into(),
            host_name: DISPLAY_HOST.into(),
            expires_ms: self.now + MIN_LINK_MS,
            lobby: true,
            confirm_direct: false,
        };
        let mut rooms = self.rooms.lock().unwrap();
        let result = rooms.guest_meeting_save(OWNER, &GuestMeetingChange::Create(draft), self.now).unwrap();
        let GuestReply::Created { lobby, code } = result else { panic!("expected creation of a fresh fixture meeting") };
        (lobby, code)
    }

    fn host(&self) -> String {
        format!("{HOST}:{}", self.addr.port())
    }

    fn post_wire(&self, path: &str, body: &str, extra_headers: &str) -> String {
        let host = self.host();
        format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nOrigin: https://{host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra_headers}\r\n{body}",
            body.len()
        )
    }

    fn post(&self, operation: &str, body: &Value, proof: Option<&str>) -> Response {
        let authorization = proof.map_or_else(String::new, |proof| format!("Authorization: Bearer {proof}\r\n"));
        self.exchange(&self.post_wire(&format!("/v1/guest/{operation}"), &body.to_string(), &authorization))
    }

    fn get(&self, path: &str) -> Response {
        self.exchange(&format!("GET {path} HTTP/1.1\r\nHost: {}\r\n\r\n", self.host()))
    }

    fn exchange(&self, request: &str) -> Response {
        let mut tls = connect(self.addr, self.tls.clone());
        tls.write_all(request.as_bytes()).unwrap();
        tls.flush().unwrap();
        let mut bytes = Vec::new();
        let read = (&mut tls).take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut bytes);
        if let Err(error) = read {
            assert!(matches!(error.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted));
        }
        assert!(!bytes.is_empty() && bytes.len() as u64 <= MAX_RESPONSE_BYTES);
        Response::parse(String::from_utf8(bytes).unwrap())
    }

    fn knock(&self, code: &GuestCode, name: &str) -> String {
        let response = self.post("knock", &json!({ "code": code.0, "name": name }), None);
        assert_eq!(response.status, 201);
        let value = response.json();
        assert_eq!(value.as_object().unwrap().len(), 2);
        assert_eq!(value["state"], "waiting");
        let proof = value["proof"].as_str().unwrap();
        let decoded = URL_SAFE_NO_PAD.decode(proof).unwrap();
        assert_eq!(decoded.len(), 48);
        assert!(URL_SAFE_NO_PAD.encode(decoded) == proof, "the proof must have a canonical encoding");
        proof.to_owned()
    }

    fn staff_lobby(&self, meeting: u64) -> GuestLobby {
        self.rooms.lock().unwrap().guest_lobby(OWNER, meeting, self.now).unwrap()
    }
}

struct Response {
    status: u16,
    headers: String,
    body: String,
}

impl Response {
    fn parse(bytes: String) -> Self {
        let (headers, body) = bytes.split_once("\r\n\r\n").unwrap();
        let (line, headers) = headers.split_once("\r\n").unwrap();
        let mut status_line = line.split_whitespace();
        assert_eq!(status_line.next(), Some("HTTP/1.1"));
        let status = status_line.next().unwrap().parse().unwrap();
        let result = Self { status, headers: headers.into(), body: body.into() };
        assert_eq!(result.header("connection"), Some("close"));
        assert_eq!(result.header("cache-control"), Some("no-store"));
        assert_eq!(result.header("set-cookie"), None);
        assert_eq!(result.header("access-control-allow-origin"), None);
        if let Some(length) = result.header("content-length") {
            assert_eq!(length.parse::<usize>().unwrap(), result.body.len());
        }
        result
    }

    fn header(&self, wanted: &str) -> Option<&str> {
        self.headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(wanted).then_some(value.trim())
        })
    }

    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap()
    }
}

fn assert_status(lab: &LobbyLab, proof: &str, state: &str) {
    let response = lab.post("status", &json!({}), Some(proof));
    assert_eq!(response.status, 200);
    assert_eq!(response.json(), json!({ "state": state }));
}

#[test]
fn the_browser_lobby_uses_scoped_proofs_and_replays_the_durable_leave() {
    let mut lab = LobbyLab::start();
    let (meeting, code) = lab.meeting();
    let page = lab.get("/guest/");
    assert_eq!(page.status, 200);
    assert!(page.body.contains("CrewCraft guest lobby lab"));
    let policy = page.header("content-security-policy").unwrap();
    for restriction in ["form-action 'none'", "frame-ancestors 'none'", "base-uri 'none'"] {
        assert!(policy.contains(restriction));
    }
    assert_eq!(page.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(lab.get("/guest/lobby.js").status, 404);

    let lookup = lab.post("lookup", &json!({ "code": code.0 }), None);
    assert_eq!(lookup.status, 200);
    assert_eq!(lookup.json(), json!({ "title": TITLE, "hostName": DISPLAY_HOST }));

    let first = lab.knock(&code, "First visitor");
    let second = lab.knock(&code, "Second visitor");
    assert_status(&lab, &first, "waiting");
    let lobby = lab.staff_lobby(meeting.meeting);
    assert_eq!(lobby.entries.len(), 2);
    let first_id = lobby.entries.iter().find(|guest| guest.name == "First visitor").unwrap().guest;
    let second_id = lobby.entries.iter().find(|guest| guest.name == "Second visitor").unwrap().guest;
    lab.rooms.lock().unwrap().guest_lobby_decide(OWNER, meeting.meeting, first_id, lobby.revision, GuestDecision::Admit, lab.now).unwrap();
    assert_status(&lab, &first, "admitted");
    assert_status(&lab, &second, "waiting");

    let left = lab.post("leave", &json!({}), Some(&first));
    assert_eq!(left.status, 204);
    assert!(left.body.is_empty());
    assert_status(&lab, &first, "removed");
    assert_status(&lab, &second, "waiting");
    let recorded = fs::read(&lab.journal).unwrap();
    assert_eq!(lab.post("leave", &json!({}), Some(&first)).status, 204);
    assert!(fs::read(&lab.journal).unwrap() == recorded, "a repeated leave must not add a journal record");
    assert_eq!(lab.post("leave", &json!({}), Some(&second)).status, 204);
    assert_status(&lab, &second, "declined");

    let proof = URL_SAFE_NO_PAD.decode(first).unwrap();
    let bearer = &proof[16..];
    let recorded = fs::read(&lab.journal).unwrap();
    assert!(!recorded.windows(bearer.len()).any(|part| part == bearer));
    assert!(!recorded.windows(code.0.len()).any(|part| part == code.0.as_bytes()));

    lab.running.finish().unwrap().unwrap();
    drop(lab.rooms);
    let mut reopened = DurableServer::open(&lab.journal).unwrap();
    let replayed = reopened.guest_lobby(OWNER, meeting.meeting, lab.now).unwrap();
    assert_eq!(replayed.entries.iter().find(|guest| guest.guest == first_id).unwrap().state, GuestState::Removed);
    assert_eq!(replayed.entries.iter().find(|guest| guest.guest == second_id).unwrap().state, GuestState::Declined);
}

#[test]
fn the_https_adapter_refuses_invalid_inputs_and_exposes_no_staff_or_media_routes() {
    let lab = LobbyLab::start();
    let (meeting, code) = lab.meeting();
    let (closed, closed_code) = lab.meeting();
    lab.rooms.lock().unwrap().guest_link_close(OWNER, closed.meeting, closed.revision, lab.now).unwrap();
    let proof = lab.knock(&code, "Fixture visitor");
    let mut mismatched = URL_SAFE_NO_PAD.decode(&proof).unwrap();
    mismatched[47] ^= 1;
    let mismatched = URL_SAFE_NO_PAD.encode(mismatched);
    let bad_code = json!({ "code": "?" });
    let refusal = lab.post("lookup", &bad_code, None);
    assert_eq!(refusal.status, 404);
    let unknown = if code.0.starts_with('A') { "B".repeat(24) } else { "A".repeat(24) };
    for response in [
        lab.post("lookup", &json!({ "code": unknown }), None),
        lab.post("lookup", &json!({ "code": closed_code.0 }), None),
        lab.post("status", &json!({}), None),
        lab.post("status", &json!({}), Some(&mismatched)),
        lab.post("leave", &json!({}), Some(&mismatched)),
        lab.post("media", &json!({}), Some(&proof)),
        lab.get("/staff/"),
    ] {
        assert_eq!(response.status, 404);
        assert!(response.body == refusal.body, "404 must have a uniform refusal body");
    }
    assert_status(&lab, &proof, "waiting");

    let valid = lab.post_wire("/v1/guest/lookup", &bad_code.to_string(), "");
    for request in [
        lab.post_wire("/v1/guest/lookup", "{", ""),
        lab.post_wire("/v1/guest/lookup", r#"{"code":"?","code":"?"}"#, ""),
        lab.post_wire("/v1/guest/lookup", r#"{"code":"?","extra":1}"#, ""),
        lab.post_wire("/v1/guest/lookup", &bad_code.to_string(), "Content-Length: 12\r\n"),
    ] {
        assert_eq!(lab.exchange(&request).status, 400);
    }
    for request in [
        valid.replacen("Host: localhost:", "Host: wrong.example.org:", 1),
        valid.replacen("Origin: https://localhost:", "Origin: https://wrong.example.org:", 1),
    ] {
        assert_eq!(lab.exchange(&request).status, 400);
    }
    let oversized = lab.post_wire("/v1/guest/lookup", &json!({ "code": "x".repeat(4096) }).to_string(), "");
    assert_eq!(lab.exchange(&oversized).status, 413);
    let too_many = "X-Fixture: sample\r\n".repeat(32);
    assert_eq!(lab.exchange(&lab.post_wire("/v1/guest/lookup", &bad_code.to_string(), &too_many)).status, 431);

    lab.clock.store(meeting.expires_ms, Ordering::Release);
    for response in [lab.post("lookup", &json!({ "code": code.0 }), None), lab.post("status", &json!({}), Some(&proof))] {
        assert_eq!(response.status, 404);
        assert!(response.body == refusal.body, "expiration must have the same refusal body");
    }
}

#[test]
fn invalid_invites_use_the_direct_peer_budget_after_json_validation() {
    let lab = LobbyLab::start();
    let (_, code) = lab.meeting();
    let path = "/v1/guest/lookup";
    assert_eq!(lab.exchange(&lab.post_wire(path, "{", "")).status, 400);
    assert_eq!(lab.post("lookup", &json!({ "code": 1 }), None).status, 400);

    for index in 1..=30 {
        let forwarded = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, index);
        let headers = format!("X-Forwarded-For: {forwarded}\r\n");
        let request = lab.post_wire(path, r#"{"code":"?"}"#, &headers);
        assert_eq!(lab.exchange(&request).status, 404);
    }
    let exhausted = lab.post("lookup", &json!({ "code": code.0 }), None);
    assert_eq!(exhausted.status, 429);
    assert!(exhausted.header("retry-after").unwrap().parse::<u64>().unwrap() > 0);
}

#[test]
fn guest_configuration_is_opt_in_and_cannot_bind_a_non_loopback_listener() {
    let scratch = Scratch::new();
    assert!(guest_lab::load(&scratch.0).unwrap().is_none());
    fs::write(scratch.0.join(guest_lab::CONFIG_FILE), "[guest-lab]\nlisten = \"0.0.0.0:0\"\nhost = \"localhost\"\n").unwrap();
    let error = guest_lab::load(&scratch.0).err().unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn an_https_guest_and_a_certless_staff_attempt_reach_different_listeners() {
    let lab = LobbyLab::start();
    let installation = LabInstallation::initialize(&lab.scratch.0.join("staff"), lab.now).unwrap();
    let staff_tls = client_tls(installation.issuer.root_certificate());
    let options = LabOptions {
        address: (Ipv4Addr::LOCALHOST, 0).into(),
        capacity: NonZeroUsize::new(2).unwrap(),
        timeouts: Timeouts { handshake: WAIT, sign_in: WAIT, signed_in_frame: WAIT, bootstrap: WAIT },
        protocol: ServerSide { min_version: 1, max_version: 1, features: 0, name: "Fixture staff".into() },
    };
    let now = lab.now;
    let staff = LabRuntime::bind(installation, options, move || now).unwrap();
    let staff_addr = staff.local_addr().unwrap();
    let mut running = Running::start(move |shutdown| staff.serve_enrolled(shutdown));
    assert_eq!(lab.get("/guest/").status, 200);
    let mut tls = connect(staff_addr, staff_tls);
    let request = format!("GET /guest/ HTTP/1.1\r\nHost: {}\r\n\r\n", lab.host());
    let _ = tls.write_all(request.as_bytes()).and_then(|()| tls.flush());
    match tls.read(&mut [0]) {
        Ok(bytes) => assert_eq!(bytes, 0),
        Err(error) => assert!(matches!(
            error.kind(),
            io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::InvalidData
        )),
    }
    running.finish().unwrap().unwrap();
}
