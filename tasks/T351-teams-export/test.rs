//! T351: the Teams exporter (docs/IMPORT.md "Exporting from Teams") against an in-process mock of the Microsoft
//! identity platform and Graph v1.0 on loopback, over TLS with a CA made at run time. Covered: the device code flow
//! with `authorization_pending` and `slow_down` (and an expired or declined code), every page of a list through
//! `@odata.nextLink`, a 429 with `Retry-After` and then success, bounded retries on a server that stays busy, a next
//! page that leaves Graph refused, an expired token renewed once, shared and Graph-hosted attachments (the token never
//! sent to a download address, a size cap, a name no file system can hold), a second run that writes nothing new, the
//! command line, and the round trip: what the exporter writes is read by `import-teams` and imported.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use crewcraft_https::Roots;
use crewcraft_server::export_teams::{DeviceCode, ExportError, ExportOptions, ExportReport, Hooks, sign_in};
use crewcraft_server::import_bundle::read_bundle;
use crewcraft_server::import_teams::read_teams;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::file_store::FileStore;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::crypto::ring;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{Value, json};

const GRAPH: &str = "/graph/v1.0";
const PLAN: &[u8] = b"%PDF-1.7 plan";
const PHOTO: &[u8] = b"\x89PNG photo bytes";

/// How the mock behaves.
#[derive(Clone, Default)]
struct Scenario {
    /// Errors the token endpoint answers, in order, before it gives a token.
    polls: Vec<&'static str>,
    interval: u64,
    /// The first chat list answers 429 with Retry-After: 7.
    throttle: bool,
    /// The chat list always answers 503, without Retry-After.
    busy: bool,
    /// The chat list names a next page outside Graph.
    stray_next: bool,
    /// The first access token is refused (401); the renewed one works.
    expire_first: bool,
}

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    authorization: Option<String>,
    body: String,
}

struct State {
    scenario: Scenario,
    polls: usize,
    throttled: bool,
    log: Vec<Seen>,
}

struct Mock {
    base: String,
    ca_pem: String,
    state: Arc<Mutex<State>>,
}

fn pem(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n", lines.join("\n"))
}

impl Mock {
    fn start(scenario: Scenario) -> Mock {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(DnType::CommonName, "mock graph ca");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = pem(ca.der());
        let issuer = Issuer::new(ca_params, ca_key);
        let key = KeyPair::generate().unwrap();
        let leaf = CertificateParams::new(vec!["localhost".to_owned()]).unwrap().signed_by(&key, &issuer).unwrap();
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))
            .unwrap();
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("https://localhost:{}", listener.local_addr().unwrap().port());
        let state = Arc::new(Mutex::new(State { scenario, polls: 0, throttled: false, log: Vec::new() }));
        let (shared, server_base) = (Arc::clone(&state), base.clone());
        thread::spawn(move || {
            for tcp in listener.incoming() {
                let Ok(tcp) = tcp else { continue };
                tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let Ok(connection) = ServerConnection::new(Arc::clone(&config)) else { continue };
                serve_one(StreamOwned::new(connection, tcp), &shared, &server_base);
            }
        });
        Mock { base, ca_pem, state }
    }

    fn options(&self) -> ExportOptions {
        let mut options = ExportOptions::new("tenant-a", "client-a");
        options.login_url = format!("{}/login", self.base);
        options.graph_url = format!("{}{GRAPH}/", self.base);
        options.roots = Roots::Pem(self.ca_pem.clone().into_bytes());
        options.max_file_bytes = 1024 * 1024;
        options.max_retries = 3;
        options
    }

    fn log(&self) -> Vec<Seen> {
        self.state.lock().unwrap().log.clone()
    }
}

fn serve_one(mut tls: StreamOwned<ServerConnection, std::net::TcpStream>, state: &Mutex<State>, base: &str) {
    let mut request = Vec::new();
    let mut chunk = [0u8; 4096];
    let (head, body) = loop {
        let Ok(n) = tls.read(&mut chunk) else { return };
        if n == 0 {
            return;
        }
        request.extend_from_slice(&chunk[..n]);
        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&request[..end]).into_owned();
            let length = head.to_lowercase().lines().find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap()));
            if request.len() >= end + 4 + length.unwrap_or(0) {
                break (head, String::from_utf8_lossy(&request[end + 4..]).into_owned());
            }
        }
    };
    let mut lines = head.lines();
    let mut first = lines.next().unwrap_or("").split(' ');
    let (method, target) = (first.next().unwrap_or("").to_owned(), first.next().unwrap_or("").to_owned());
    let authorization = lines.find_map(|l| l.strip_prefix("Authorization: ").map(str::to_owned));
    let seen = Seen { method, target, authorization, body };
    let (status, headers, bytes) = {
        let mut state = state.lock().unwrap();
        state.log.push(seen.clone());
        answer(&mut state, &seen, base)
    };
    let mut response = format!("HTTP/1.1 {status} Mock\r\nContent-Length: {}\r\n", bytes.len());
    if !headers.iter().any(|(name, _)| *name == "Content-Type") {
        response.push_str("Content-Type: application/json\r\n");
    }
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    let _ = tls.write_all(response.as_bytes());
    let _ = tls.write_all(&bytes);
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

type Answer = (u16, Vec<(&'static str, String)>, Vec<u8>);

fn json_answer(status: u16, value: Value) -> Answer {
    (status, Vec::new(), serde_json::to_vec(&value).unwrap())
}

fn answer(state: &mut State, seen: &Seen, base: &str) -> Answer {
    match (seen.method.as_str(), seen.target.as_str()) {
        ("POST", "/login/tenant-a/oauth2/v2.0/devicecode") => json_answer(
            200,
            json!({"device_code": "dc-1", "user_code": "WXYZ-1234", "verification_uri": "https://login.example.org/device",
                   "expires_in": 900, "interval": state.scenario.interval, "message": "Open the page and enter the code."}),
        ),
        ("POST", "/login/tenant-a/oauth2/v2.0/token") => {
            if seen.body.contains("grant_type=refresh_token") {
                return json_answer(200, json!({"token_type": "Bearer", "access_token": "at-2", "expires_in": 3600}));
            }
            if let Some(error) = state.scenario.polls.get(state.polls).copied() {
                state.polls += 1;
                return json_answer(400, json!({"error": error, "error_description": "waiting\r\nTrace ID: 0"}));
            }
            json_answer(200, json!({"token_type": "Bearer", "access_token": "at-1", "refresh_token": "rt-1", "expires_in": 3600}))
        }
        ("GET", "/download/plan?tempauth=one-time") => (200, vec![("Content-Type", "application/pdf".to_owned())], PLAN.to_vec()),
        ("GET", target) if target.starts_with(GRAPH) => graph(state, &target[GRAPH.len()..], seen, base),
        _ => json_answer(404, json!({"error": {"code": "NotFound"}})),
    }
}

fn from(id: &str) -> Value {
    json!({"user": {"id": id, "displayName": "someone", "userIdentityType": "aadUser"}, "application": null, "device": null})
}

fn graph(state: &mut State, path: &str, seen: &Seen, base: &str) -> Answer {
    let scenario = state.scenario.clone();
    let token_ok = match seen.authorization.as_deref() {
        Some("Bearer at-2") => true,
        Some("Bearer at-1") => !scenario.expire_first,
        _ => false,
    };
    if !token_ok {
        return json_answer(401, json!({"error": {"code": "InvalidAuthenticationToken"}}));
    }
    let next = |rest: &str| format!("{base}{GRAPH}{rest}");
    match path {
        "/me/chats?$top=50" => {
            if scenario.busy {
                return json_answer(503, json!({"error": {"code": "ServiceUnavailable"}}));
            }
            if scenario.throttle && !state.throttled {
                state.throttled = true;
                return (429, vec![("Retry-After", "7".to_owned())], br#"{"error":{"code":"TooManyRequests"}}"#.to_vec());
            }
            let mut page = json!({"@odata.count": 1, "value": [{"id": "19:chat-ab", "topic": null, "chatType": "oneOnOne"}]});
            if scenario.stray_next {
                page["@odata.nextLink"] = json!(format!("{base}/elsewhere/chats"));
            }
            json_answer(200, page)
        }
        "/chats/19:chat-ab/members" => json_answer(
            200,
            json!({"value": [{"userId": "u-ana", "email": "ana@example.org", "displayName": "Ana"}, {"userId": "u-bo", "email": null}]}),
        ),
        "/chats/19:chat-ab/messages?$top=50" => json_answer(
            200,
            json!({"@odata.nextLink": next("/chats/19:chat-ab/messages?$top=50&$skiptoken=page-2"), "value": [
                {"id": "1001", "messageType": "message", "createdDateTime": "2024-03-05T14:07:09.123Z", "from": from("u-ana"),
                 "body": {"contentType": "html", "content": "<p>Plan for <b>Friday</b></p>"},
                 "attachments": [
                    {"id": "a1", "contentType": "reference", "contentUrl": "https://files.example.org/sites/launch/plan.pdf", "name": "plan.pdf"},
                    {"id": "a2", "contentType": "reference", "contentUrl": "https://files.example.org/sites/launch/huge.iso", "name": "huge.iso"},
                    {"id": "a3", "contentType": "reference", "contentUrl": "https://files.example.org/sites/launch/odd", "name": "what?.txt"},
                    {"id": "card", "contentType": "application/vnd.microsoft.card.adaptive", "content": "{}", "name": null}
                 ]}
            ]}),
        ),
        "/chats/19:chat-ab/messages?$top=50&$skiptoken=page-2" => json_answer(
            200,
            json!({"value": [
                {"id": "1002", "messageType": "message", "createdDateTime": "2024-03-05T15:00:00Z", "from": from("u-bo"),
                 "body": {"contentType": "text", "content": "thanks"},
                 "attachments": [{"id": "img-1", "contentType": "image/png", "name": "photo.png",
                                  "contentUrl": next("/chats/19:chat-ab/messages/1002/hostedContents/img-1/$value")}]},
                {"id": "1003", "messageType": "systemEventMessage", "createdDateTime": "2024-03-05T15:01:00Z", "from": null,
                 "body": {"contentType": "html", "content": "<systemEventMessage/>"}}
            ]}),
        ),
        "/chats/19:chat-ab/messages/1002/hostedContents/img-1/$value" => (200, vec![("Content-Type", "image/png".to_owned())], PHOTO.to_vec()),
        "/me/joinedTeams" => json_answer(200, json!({"value": [{"id": "team-1", "displayName": "Launch"}]})),
        "/teams/team-1/channels" => json_answer(200, json!({"value": [{"id": "19:general", "displayName": "General"}]})),
        "/teams/team-1/channels/19:general/members" => {
            json_answer(200, json!({"value": [{"userId": "u-ana", "email": "ana@example.org"}, {"userId": "u-cy", "email": "cy@example.org"}]}))
        }
        "/teams/team-1/channels/19:general/messages?$expand=replies" => json_answer(
            200,
            json!({"value": [
                {"id": "2001", "messageType": "message", "createdDateTime": "2024-03-07T09:00:00Z", "from": from("u-cy"),
                 "body": {"contentType": "html", "content": "<div>Ship it?</div>"},
                 "replies": [{"id": "2002", "replyToId": "2001", "messageType": "message", "createdDateTime": "2024-03-07T09:05:00Z",
                              "from": from("u-ana"), "body": {"contentType": "text", "content": "Yes"}}]}
            ]}),
        ),
        "/users?$select=id,mail,userPrincipalName,displayName&$top=999" => {
            json_answer(200, json!({"@odata.nextLink": next("/users?$skiptoken=u2"), "value": [{"id": "u-ana", "mail": "ANA@EXAMPLE.ORG"}]}))
        }
        "/users?$skiptoken=u2" => json_answer(200, json!({"value": [{"id": "u-bo", "mail": null, "userPrincipalName": "bo@example.org"}]})),
        shares if shares.starts_with("/shares/u!") && shares.ends_with("/driveItem") => {
            let id = &shares["/shares/u!".len()..shares.len() - "/driveItem".len()];
            let url = String::from_utf8(URL_SAFE_NO_PAD.decode(id).unwrap()).unwrap();
            match url.as_str() {
                "https://files.example.org/sites/launch/plan.pdf" => json_answer(
                    200,
                    json!({"id": "item-1", "name": "plan.pdf", "size": PLAN.len(), "@microsoft.graph.downloadUrl": format!("{base}/download/plan?tempauth=one-time")}),
                ),
                "https://files.example.org/sites/launch/huge.iso" => json_answer(
                    200,
                    json!({"id": "item-2", "name": "huge.iso", "size": 5_000_000_000u64, "@microsoft.graph.downloadUrl": format!("{base}/download/huge")}),
                ),
                _ => json_answer(404, json!({"error": {"code": "itemNotFound"}})),
            }
        }
        _ => json_answer(404, json!({"error": {"code": "NotFound"}})),
    }
}

type Pauses = Arc<Mutex<Vec<u64>>>;

fn recorder() -> (Hooks, Pauses, Arc<Mutex<Vec<DeviceCode>>>) {
    let (pauses, shown) = (Pauses::default(), Arc::new(Mutex::new(Vec::new())));
    let (p, s) = (Arc::clone(&pauses), Arc::clone(&shown));
    let hooks = Hooks {
        show: Box::new(move |code: &DeviceCode| s.lock().unwrap().push(code.clone())),
        pause: Box::new(move |wait: Duration| p.lock().unwrap().push(wait.as_secs())),
        progress: Box::new(|_: &str| {}),
    };
    (hooks, pauses, shown)
}

fn scratch(tag: &str) -> PathBuf {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("crewcraft-t351-{tag}-{}-{now}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn export(mock: &Mock, out: &Path) -> (Result<ExportReport, ExportError>, Vec<u64>) {
    let (hooks, pauses, _) = recorder();
    let result = sign_in(mock.options(), hooks).and_then(|mut session| session.export(out));
    let pauses = pauses.lock().unwrap().clone();
    (result, pauses)
}

fn standard() -> Scenario {
    Scenario { polls: vec!["authorization_pending", "slow_down"], interval: 5, throttle: true, ..Scenario::default() }
}

/// Every file under `dir` with its bytes and modification time.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, (Vec<u8>, SystemTime)> {
    let mut all = BTreeMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(at) = stack.pop() {
        for entry in fs::read_dir(&at).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let modified = fs::metadata(&path).unwrap().modified().unwrap();
                all.insert(path.strip_prefix(dir).unwrap().to_path_buf(), (fs::read(&path).unwrap(), modified));
            }
        }
    }
    all
}

#[test]
fn the_device_code_flow_waits_as_the_identity_platform_says() {
    let mock = Mock::start(Scenario { polls: vec!["authorization_pending", "slow_down"], interval: 5, ..Scenario::default() });
    let (hooks, pauses, shown) = recorder();
    let session = sign_in(mock.options(), hooks).unwrap();
    assert!(!format!("{session:?}").contains("at-1"), "the token never shows in debug output");
    assert_eq!(*pauses.lock().unwrap(), vec![5, 5, 10], "the interval, again while pending, five seconds more after slow_down");
    let shown = shown.lock().unwrap().clone();
    assert_eq!(
        shown,
        vec![DeviceCode {
            user_code: "WXYZ-1234".into(),
            verification_uri: "https://login.example.org/device".into(),
            expires_in: Duration::from_secs(900)
        }]
    );
    let log = mock.log();
    let ask = &log[0];
    assert_eq!((ask.method.as_str(), ask.target.as_str()), ("POST", "/login/tenant-a/oauth2/v2.0/devicecode"));
    assert!(ask.body.starts_with("client_id=client-a&scope=offline_access%20User.ReadBasic.All%20Chat.Read%20Files.Read.All%20"), "{}", ask.body);
    assert!(ask.body.contains("ChannelMessage.Read.All") && !ask.body.contains("Write"), "read-only permissions: {}", ask.body);
    let polls: Vec<&Seen> = log.iter().filter(|seen| seen.target.ends_with("/token")).collect();
    assert_eq!(polls.len(), 3);
    assert_eq!(polls[0].body, "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&client_id=client-a&device_code=dc-1");

    for (error, expected) in [("expired_token", "expired"), ("authorization_declined", "declined"), ("invalid_client", "invalid_client")] {
        let mock = Mock::start(Scenario { polls: vec!["authorization_pending", error], interval: 2, ..Scenario::default() });
        let (hooks, pauses, _) = recorder();
        match sign_in(mock.options(), hooks) {
            Err(ExportError::SignIn(why)) => assert!(why.contains(expected) && !why.contains('\r'), "{error}: {why}"),
            other => panic!("{error}: {other:?}"),
        }
        assert_eq!(*pauses.lock().unwrap(), vec![2, 2]);
    }
    let mut chats_only = mock.options();
    chats_only.chats_only = true;
    assert!(!chats_only.scopes().contains("Channel"), "--chats-only asks for no channel permission");
}

#[test]
fn an_export_pages_waits_out_throttling_and_downloads_attachments() {
    let mock = Mock::start(standard());
    let dir = scratch("export");
    let out = dir.join("export");
    let (report, pauses) = export(&mock, &out);
    let report = report.unwrap();
    assert_eq!(pauses, vec![5, 5, 10, 7], "sign-in, then the 429's Retry-After");
    assert!(report.ok(), "{report:?}");
    assert_eq!((report.conversations_written, report.conversations_skipped, report.messages, report.retries), (2, 0, 5, 1));
    assert_eq!((report.files_downloaded, report.files_present, report.users_written), (2, 0, true));
    let mut skipped: Vec<(&str, &str)> = report.files_not_captured.iter().map(|(_, name, why)| (name.as_str(), why.as_str())).collect();
    skipped.sort();
    assert_eq!(skipped, vec![("huge.iso", "larger than the 1 MiB cap"), ("what?.txt", "the name is not a safe file name")]);
    assert_eq!(fs::read(out.join("files").join("1001").join("plan.pdf")).unwrap(), PLAN);
    assert_eq!(fs::read(out.join("files").join("1002").join("photo.png")).unwrap(), PHOTO);

    // Both pages of the chat are in its file.
    let mut names: Vec<String> = fs::read_dir(out.join("conversations")).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    assert_eq!(names.len(), 2);
    let chat_file = names.iter().find(|name| name.starts_with("chat-")).unwrap();
    let chat: Value = serde_json::from_slice(&fs::read(out.join("conversations").join(chat_file)).unwrap()).unwrap();
    assert_eq!(chat["chat"]["id"], "19:chat-ab");
    let ids: Vec<&str> =
        chat["pages"].as_array().unwrap().iter().flat_map(|p| p["value"].as_array().unwrap()).map(|m| m["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec!["1001", "1002", "1003"]);
    assert!(!names.iter().any(|name| name.ends_with(".partial")));

    // users.json: both /users pages, then the member /users did not list.
    let users: Value = serde_json::from_slice(&fs::read(out.join("users.json")).unwrap()).unwrap();
    let listed: Vec<&str> =
        users.as_array().unwrap().iter().flat_map(|p| p["value"].as_array().unwrap()).map(|u| u["id"].as_str().unwrap()).collect();
    assert_eq!(listed, vec!["u-ana", "u-bo", "u-cy"]);

    // The token went to Graph only; the pre-authenticated download address got none.
    let log = mock.log();
    for seen in &log {
        if seen.target.starts_with(GRAPH) {
            assert_eq!(seen.authorization.as_deref(), Some("Bearer at-1"), "{}", seen.target);
        } else {
            assert_eq!(seen.authorization, None, "{}", seen.target);
        }
    }
    assert!(log.iter().any(|seen| seen.target == "/download/plan?tempauth=one-time"));
    assert!(!log.iter().any(|seen| seen.target.starts_with("/download/huge")), "a file over the cap is not fetched");
}

#[test]
fn a_second_run_resumes_and_writes_nothing_new() {
    let mock = Mock::start(standard());
    let dir = scratch("resume");
    let out = dir.join("export");
    export(&mock, &out).0.unwrap();
    let before = snapshot(&out);
    let first_run = mock.log().len();

    let (again, _) = export(&mock, &out);
    let again = again.unwrap();
    assert_eq!((again.conversations_written, again.conversations_skipped, again.messages), (0, 2, 0));
    assert_eq!((again.files_downloaded, again.files_present, again.users_written), (0, 2, false));
    assert!(again.ok());
    assert_eq!(snapshot(&out), before, "not one file written or touched");
    let second: Vec<String> = mock.log()[first_run..].iter().map(|seen| seen.target.clone()).collect();
    assert!(
        !second.iter().any(|t| t.contains("/messages") || t.contains("/members") || t.starts_with("/download/") || t.contains("/users")),
        "{second:?}"
    );

    // A conversation lost from the directory (an interrupted run) is fetched again, and only it.
    let channel =
        fs::read_dir(out.join("conversations")).unwrap().map(|e| e.unwrap().path()).find(|p| p.to_string_lossy().contains("channel-")).unwrap();
    fs::remove_file(&channel).unwrap();
    let (third, _) = export(&mock, &out);
    let third = third.unwrap();
    assert_eq!((third.conversations_written, third.conversations_skipped, third.messages, third.users_written), (1, 1, 2, true));
    assert!(channel.is_file());
}

#[test]
fn the_export_is_read_by_import_teams_and_imported() {
    let mock = Mock::start(standard());
    let dir = scratch("roundtrip");
    let out = dir.join("export");
    export(&mock, &out).0.unwrap();

    let bundle_dir = dir.join("bundle");
    let read = read_teams(&out, &bundle_dir).unwrap();
    assert_eq!((read.conversations, read.messages, read.system_messages), (2, 4, 1));
    assert_eq!((read.files_captured, read.files_not_captured), (2, 2));
    assert!(read.unmapped_senders.is_empty(), "{:?}", read.unmapped_senders);

    let bundle = read_bundle(&bundle_dir).unwrap();
    let first = bundle.messages.iter().find(|m| m.key == "1001").unwrap();
    assert_eq!((first.author.as_str(), first.text.as_str()), ("ana@example.org", "Plan for Friday"));
    let files: Vec<(&str, bool)> = first.files.iter().map(|f| (f.name.as_str(), f.captured)).collect();
    assert_eq!(files, vec![("plan.pdf", true), ("huge.iso", false), ("what?.txt", false)]);
    let reply = bundle.messages.iter().find(|m| m.key == "2002").unwrap();
    assert_eq!(reply.reply_to.as_deref(), Some("2001"));
    assert_eq!(bundle.messages.iter().find(|m| m.key == "2001").unwrap().author, "cy@example.org", "a member /users did not list");

    let mut server = DurableServer::open(&dir.join("rooms.journal")).unwrap().with_files(FileStore::open(&dir.join("store")).unwrap()).unwrap();
    let imported = server.import(&bundle, &|_| true, false).unwrap();
    assert!(imported.ok(), "{:?}", imported.refusals);
    assert_eq!((imported.rooms_created, imported.messages_added, imported.members_added), (2, 4, 4));
    assert_eq!(server.found("cy@example.org", "Ship").len(), 1);
}

#[test]
fn a_busy_server_is_retried_a_bounded_number_of_times() {
    let mock = Mock::start(Scenario { interval: 5, busy: true, ..Scenario::default() });
    let (result, pauses) = export(&mock, &scratch("busy").join("export"));
    match result {
        Err(ExportError::Status { status: 503, .. }) => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(pauses, vec![5, 1, 2, 4], "sign-in, then doubling backoff for three retries");
    assert_eq!(mock.log().iter().filter(|seen| seen.target.contains("/me/chats")).count(), 4);
}

#[test]
fn a_next_page_outside_graph_is_not_followed() {
    let mock = Mock::start(Scenario { interval: 1, stray_next: true, ..Scenario::default() });
    match export(&mock, &scratch("stray").join("export")).0 {
        Err(ExportError::Graph(why)) => assert!(why.contains("outside"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(!mock.log().iter().any(|seen| seen.target.starts_with("/elsewhere")), "the token never went there");
}

#[test]
fn an_expired_token_is_renewed_once() {
    let mock = Mock::start(Scenario { interval: 1, expire_first: true, ..Scenario::default() });
    let dir = scratch("renew");
    let report = export(&mock, &dir.join("export")).0.unwrap();
    assert_eq!(report.conversations_written, 2);
    let log = mock.log();
    let renewals: Vec<&Seen> = log.iter().filter(|seen| seen.body.contains("grant_type=refresh_token")).collect();
    assert_eq!(renewals.len(), 1);
    assert!(renewals[0].body.contains("refresh_token=rt-1") && renewals[0].body.contains("client_id=client-a"));
    let last = log.iter().rev().find(|seen| seen.target.starts_with(GRAPH)).unwrap();
    assert_eq!(last.authorization.as_deref(), Some("Bearer at-2"));
}

#[test]
fn the_command_exports_and_import_teams_reads_it() {
    let mock = Mock::start(Scenario { interval: 1, ..Scenario::default() });
    let dir = scratch("command");
    let ca = dir.join("ca.pem");
    fs::write(&ca, &mock.ca_pem).unwrap();
    let out = dir.join("export");
    let run = |args: &[&str]| Command::new(env!("CARGO_BIN_EXE_crewcraft-server")).args(args).stdin(Stdio::null()).output().unwrap();
    let (login, graph) = (format!("{}/login", mock.base), format!("{}{GRAPH}", mock.base));
    let exported = run(&[
        "export-teams",
        "--tenant",
        "tenant-a",
        "--client-id",
        "client-a",
        "--out",
        out.to_str().unwrap(),
        "--login-url",
        &login,
        "--graph-url",
        &graph,
        "--ca-file",
        ca.to_str().unwrap(),
        "--max-file-mb",
        "1",
    ]);
    let stdout = String::from_utf8_lossy(&exported.stdout);
    assert!(exported.status.success(), "{stdout}\n{}", String::from_utf8_lossy(&exported.stderr));
    assert!(stdout.contains("open https://login.example.org/device in a browser and enter the code WXYZ-1234"), "{stdout}");
    assert!(stdout.contains("2 conversations written") && !stdout.contains("at-1"), "{stdout}");

    let bundle = dir.join("bundle");
    let read = run(&["import-teams", "--export", out.to_str().unwrap(), "--out", bundle.to_str().unwrap()]);
    assert!(read.status.success(), "{}", String::from_utf8_lossy(&read.stdout));
    assert!(bundle.join("bundle.json").is_file());

    for bad in [
        vec!["export-teams", "--tenant", "tenant-a", "--out", "x"],
        vec!["export-teams", "--tenant", "a", "--client-id", "b", "--out", "x", "--login-url", "http://login.example.org"],
        vec!["export-teams", "--tenant", "a", "--client-id", "b", "--out", "x", "--max-file-mb", "0"],
        vec!["export-teams", "--tenant", "a", "--tenant", "b", "--client-id", "c", "--out", "x"],
    ] {
        assert!(!run(&bad).status.success(), "{bad:?}");
    }
}
