//! T370c through enrolled, password-and-TOTP staff sessions and the in-process guest entrance.
//! The device fixture follows T360b4. MediaServer is driven in process, without browser or guest transport.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft_accounts::password;
use crewcraft_accounts::throttle::Throttle;
use crewcraft_client_core::client::{Client, ClientEvent};
use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::requests::Reply;
use crewcraft_media::{Config, MediaServer};
use crewcraft_media_auth::{Issuer, Verifier};
use crewcraft_pki::{Authority, Claims};
use crewcraft_proto::activity::{ActivityFilter, ActivityKind};
use crewcraft_proto::frame::{Decoder, encode, read_frame};
use crewcraft_proto::guest::{GuestCode, GuestDecision, GuestLobby, GuestMeetingChange, GuestMeetingDraft, GuestReply, GuestState};
use crewcraft_proto::handshake::{self, Hello, ServerSide};
use crewcraft_proto::meeting::MeetingChange;
use crewcraft_proto::push::{GUEST_LOBBY_STATE, Push, decode_push};
use crewcraft_proto::request::{
    FEATURE_CALLS, FEATURE_GUEST_MEETINGS, FEATURE_MEDIA, FEATURE_MEETINGS, Request, Response, decode_response, encode_request,
};
use crewcraft_proto::signin::{self, SignIn};
use crewcraft_server::device_session::serve;
use crewcraft_server::stored_device_auth::StoredDeviceAuth;
use crewcraft_server_core::account_store::{AccountStore, Activation, FirstDevice};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::dispatch::{E_CONFLICT, E_NO_SUCH_CALL, E_NO_SUCH_GUEST, E_NO_SUCH_MEETING, E_NOT_ALLOWED};
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::guests::{GuestEntrance, GuestError, GuestProof};
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::media::{MediaEvent, MediaIssuer};
use crewcraft_server_core::room::Role;
use crewcraft_server_core::seal::ServiceKey;
use crewcraft_totp::Totp;
use rcgen::{CertificateParams, KeyPair};
use str0m::media::{Direction, MediaKind};
use str0m::{Candidate, Rtc};

const CREATED_AT: u64 = 1_800_000_000_000;
const NOW: u64 = CREATED_AT + 30_000;
const EXPIRY: u64 = NOW + 3 * 60 * 60 * 1_000;
const PASSWORD: &str = "synthetic guest meeting password";
const OWNER: &str = "ana@example.org";
const MEMBER: &str = "bo@example.org";
const ROOM_GUEST: &str = "guest-member@example.org";
const OUTSIDE: &str = "other@example.org";
const MEDIA: &str = "media.example.org";
const MEDIA_ADDRESS: &str = "203.0.113.10:3478";
const BASE_FEATURES: u32 = FEATURE_MEETINGS | FEATURE_CALLS;
const FEATURES: u32 = BASE_FEATURES | FEATURE_GUEST_MEETINGS;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("crewcraft-t370c-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Account {
    email: &'static str,
    secret: [u8; 20],
    leaf: Vec<u8>,
}

fn enrolled(path: &Path) -> (Arc<Mutex<AccountStore>>, [Account; 2]) {
    let mut store = AccountStore::create(path, ServiceKey::from_bytes([8; 32])).unwrap();
    let root = Authority::create_root("Fixture Root", CREATED_AT).unwrap();
    let mut issuer = root.create_issuing("Fixture Issuer", CREATED_AT).unwrap();
    let phc = password::hash(PASSWORD).unwrap();
    let people = [(OWNER, 1), (MEMBER, 2)].map(|(email, id)| {
        let bootstrap_pub = [id; 32];
        let secret = [id + 10; 20];
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
        let device_id = u64::from(id);
        let leaf = issuer.issue_device(csr.der().as_ref(), &Claims { person: email, device_id }, CREATED_AT).unwrap();
        store.issue_invite(Invite { email: email.into(), bootstrap_pub, expires_ms: EXPIRY }, CREATED_AT).unwrap();
        let activation = Activation {
            bootstrap_pub,
            device_name: "Fixture device",
            certificate: &leaf.certificate,
            spki_sha256: leaf.key_id,
            counter: CREATED_AT / 30_000,
            first_device: Some(FirstDevice { password_phc: Some(&phc), totp_secret: &secret }),
            expected_device_id: Some(device_id),
        };
        assert_eq!(store.activate(activation, CREATED_AT).unwrap(), device_id);
        Account { email, secret, leaf: leaf.certificate }
    });
    (Arc::new(Mutex::new(store)), people)
}

struct Staff {
    stream: TcpStream,
    client: Client,
    server: Option<JoinHandle<()>>,
}

impl Staff {
    fn connect(person: &Account, accounts: &Arc<Mutex<AccountStore>>, rooms: &Arc<Mutex<DurableServer>>, features: u32) -> Self {
        let auth = StoredDeviceAuth::bind(accounts.clone(), Arc::new(Mutex::new(Throttle::new())), &person.leaf, NOW).unwrap();
        let rooms = rooms.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let side = ServerSide { min_version: 1, max_version: 1, features: FEATURES, name: "Fixture server".into() };
            serve(&mut socket, &auth, &rooms, side, |_| Ok(()), || NOW).unwrap();
        });
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let code = Totp::with_defaults(person.secret.to_vec()).unwrap().generate(NOW / 1_000);
        let sign_in = SignIn { email: person.email, password: PASSWORD, code: &code };
        stream.write_all(&encode(&signin::encode_request(&sign_in).unwrap()).unwrap()).unwrap();
        let reply = read_frame(&mut stream, 4096).unwrap().unwrap();
        assert!(matches!(signin::decode_reply(reply.as_bytes()).unwrap(), signin::Reply::Accepted { .. }));
        let hello = Hello { min_version: 1, max_version: 1, features, client: "Fixture client".into() };
        stream.write_all(&encode(&handshake::encode_hello(&hello).unwrap()).unwrap()).unwrap();
        let reply = read_frame(&mut stream, 4096).unwrap().unwrap();
        assert!(
            matches!(handshake::decode_reply(reply.as_bytes()).unwrap(), handshake::Reply::Welcome { features: negotiated, .. } if negotiated == features)
        );
        Self { stream, client: Client::new(person.email, Settings::default()), server: Some(server) }
    }

    fn ask(&mut self, request: Request) -> (Response, Vec<ClientEvent>, Vec<Push>) {
        for request in [request, Request::Ping] {
            self.stream.write_all(&self.client.send(request, NOW).unwrap()).unwrap();
        }
        let (mut answer, mut events, mut lobby_pushes) = (None, Vec::new(), Vec::new());
        loop {
            let frame = read_frame(&mut self.stream, 1 << 21).unwrap().unwrap();
            if frame.as_bytes().first() == Some(&GUEST_LOBBY_STATE) {
                lobby_pushes.push(decode_push(frame.as_bytes()).unwrap());
            }
            for event in self.client.receive(frame.as_bytes(), NOW, 0).unwrap() {
                match event {
                    ClientEvent::Reply(Reply::Done { request: Request::Ping, .. }) => {
                        return (answer.unwrap(), events, lobby_pushes);
                    }
                    ClientEvent::Reply(Reply::Done { response, .. }) => answer = Some(response),
                    other => events.push(other),
                }
            }
        }
    }

    fn guest(&mut self, request: Request) -> GuestReply {
        let (answer, events, _) = self.ask(request);
        let reply = events.into_iter().find_map(|event| match event {
            ClientEvent::Guest { reply, .. } => Some(reply),
            _ => None,
        });
        let reply = reply.unwrap();
        let cursor = match &reply {
            GuestReply::Created { lobby, .. } => lobby.meeting,
            GuestReply::Lobby(lobby) => lobby.revision,
        };
        assert_eq!(answer, Response::Ok { cursor });
        reply
    }

    fn lobby(&mut self, meeting: u64) -> GuestLobby {
        lobby(self.guest(Request::GuestLobbyList { meeting }))
    }

    fn decide(&mut self, snapshot: &GuestLobby, proof: &GuestProof, decision: GuestDecision) -> GuestLobby {
        lobby(self.guest(Request::GuestLobbyDecide { meeting: snapshot.meeting, guest: proof.guest, revision: snapshot.revision, decision }))
    }
}

impl Drop for Staff {
    fn drop(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

fn lobby(reply: GuestReply) -> GuestLobby {
    let GuestReply::Lobby(lobby) = reply else { panic!("expected lobby snapshot") };
    lobby
}

fn draft(room: &str) -> GuestMeetingDraft {
    GuestMeetingDraft {
        room: room.into(),
        start_ms: NOW,
        duration: 30,
        title: "Planning".into(),
        agenda: "Private notes".into(),
        host_name: "Ana".into(),
        expires_ms: EXPIRY,
        lobby: true,
        confirm_direct: false,
    }
}

fn create(owner: &mut Staff, room: &str) -> (GuestLobby, GuestCode) {
    let GuestReply::Created { lobby, code } = owner.guest(Request::GuestMeetingSave { change: GuestMeetingChange::Create(draft(room)) }) else {
        panic!("expected a newly created guest link");
    };
    (lobby, code)
}

fn refuse(answer: Response, code: u16) {
    assert_eq!(answer, Response::Error { code, detail: String::new() });
}

fn cursor(answer: Response) -> u64 {
    let Response::Ok { cursor } = answer else { panic!("expected success, got {answer:?}") };
    cursor
}

fn peer(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, last))
}

fn offer() -> String {
    let mut rtc = Rtc::builder().set_crypto_provider(Arc::new(crewcraft_media_crypto::provider())).build(Instant::now());
    rtc.add_local_candidate(Candidate::host("198.51.100.100:5000".parse().unwrap(), "udp").unwrap());
    let mut change = rtc.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
    change.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
    change.apply().unwrap().0.to_sdp_string()
}

fn state(lobby: &GuestLobby, proof: &GuestProof) -> GuestState {
    lobby.entries.iter().find(|entry| entry.guest == proof.guest).unwrap().state
}

#[test]
fn enrolled_staff_manage_guests_media_and_a_durable_lobby() {
    let scratch = Scratch::new();
    let path = scratch.0.join("rooms");
    let (accounts, people) = enrolled(&scratch.0.join("accounts"));
    let mut rooms = DurableServer::open(&path).unwrap();
    let room = rooms.create_room(OWNER, "Planning").unwrap();
    rooms.add_member(&room, OWNER, MEMBER, Role::Member).unwrap();
    rooms.add_member(&room, OWNER, ROOM_GUEST, Role::Guest).unwrap();
    let issuer = Issuer::from_pkcs8(&Issuer::generate().unwrap()).unwrap();
    let key = issuer.public_key();
    rooms.set_media(MediaIssuer::new(issuer, MEDIA, MEDIA_ADDRESS));
    let rooms = Arc::new(Mutex::new(rooms));
    let mut owner = Staff::connect(&people[0], &accounts, &rooms, FEATURES);
    let mut old = Staff::connect(&people[1], &accounts, &rooms, BASE_FEATURES);
    owner.client.inbox_mut().follow(&room, false);
    old.client.inbox_mut().follow(&room, false);

    let staff = cursor(
        owner
            .ask(Request::MeetingSave {
                room: room.clone(),
                meeting: 0,
                version: 0,
                start_ms: NOW,
                duration: 30,
                title: "Staff only".into(),
                agenda: String::new(),
            })
            .0,
    );
    refuse(owner.ask(Request::GuestLobbyList { meeting: staff }).0, E_NO_SUCH_GUEST);
    let (meeting, code) = create(&mut owner, &room);
    let id = meeting.meeting;
    assert_eq!(meeting.expires_ms, EXPIRY);
    assert!(meeting.lobby && meeting.entries.is_empty());
    assert!(code.is_valid());
    {
        let mut rooms = rooms.lock().unwrap();
        assert_eq!(rooms.guest_lobby(ROOM_GUEST, id, NOW), Err(GuestError::NotAllowed));
        assert_eq!(rooms.guest_lobby(OUTSIDE, id, NOW), Err(GuestError::NoSuchGuest));
        assert_eq!(rooms.guest_link_close(MEMBER, id, meeting.revision, NOW), Err(GuestError::NotAllowed));
        assert_eq!(rooms.guest_lobby_state(&room, ROOM_GUEST), None);
    }
    refuse(old.ask(Request::GuestLobbyList { meeting: id }).0, E_NOT_ALLOWED);
    refuse(old.ask(Request::MeetingJoin { meeting: id }).0, E_NO_SUCH_MEETING);
    let (answer, events, _) = old.ask(Request::MeetingList { from_ms: NOW, to_ms: NOW + 3_600_000 });
    assert_eq!(answer, Response::Ok { cursor: 1 });
    assert!(
        events.iter().any(|event| matches!(event, ClientEvent::Meetings { page, .. } if page.meetings.len() == 1 && page.meetings[0].id == staff))
    );

    let head = cursor(owner.ask(Request::Sync { room: room.clone(), cursor: 0 }).0);
    let (patient, refused) = {
        let mut rooms = rooms.lock().unwrap();
        let mut entrance = rooms.guest_entrance(|| NOW);
        let preview = entrance.lookup(peer(1), &code.0).unwrap();
        assert_eq!((preview.title.as_str(), preview.host_name.as_str()), ("Planning", "Ana"));
        let patient = entrance.knock(peer(1), &code.0, " Visitor\u{202e} ").unwrap();
        let refused = entrance.knock(peer(2), &code.0, "Second visitor").unwrap();
        assert_eq!(patient.state, GuestState::Waiting);
        assert_eq!(entrance.status(peer(1), &patient.proof).unwrap().name, "Visitor");
        assert!(entrance.media(peer(1), &patient.proof).is_err());
        (patient.proof, refused.proof)
    };
    let (answer, _, pushes) = owner.ask(Request::Sync { room: room.clone(), cursor: head });
    assert_eq!(answer, Response::Ok { cursor: head });
    assert!(matches!(&pushes[..], [Push::GuestLobbyState { waiting: 2, cursor, .. }] if *cursor == head));
    assert_eq!(owner.client.inbox().view(&room).unwrap().guest_lobby_state().unwrap().waiting, 2);
    assert!(old.ask(Request::Sync { room: room.clone(), cursor: 0 }).2.is_empty());

    let ordinary = cursor(owner.ask(Request::MeetingJoin { meeting: staff }).0);
    refuse(owner.ask(Request::MeetingJoin { meeting: id }).0, E_NOT_ALLOWED);
    cursor(owner.ask(Request::CallLeave { room: room.clone(), call: ordinary }).0);
    rooms.lock().unwrap().take_media_events();
    let call = cursor(owner.ask(Request::MeetingJoin { meeting: id }).0);
    assert_ne!(ordinary, call);
    refuse(owner.ask(Request::MeetingJoin { meeting: staff }).0, E_NOT_ALLOWED);
    {
        let mut legacy = Connection::with_features(OWNER, BASE_FEATURES | FEATURE_MEDIA).with_device(Some(3));
        let frame = encode(&encode_request(1, &Request::CallJoin { room: room.clone(), call }).unwrap()).unwrap();
        let answer = legacy.receive_durable(&mut rooms.lock().unwrap(), &frame, NOW).unwrap();
        let mut decoder = Decoder::new();
        decoder.push(&answer);
        let (id, response) = decode_response(&decoder.next_frame().unwrap().unwrap()).unwrap();
        assert_eq!(id, 1);
        refuse(response, E_NO_SUCH_CALL);
        assert!(decoder.next_frame().unwrap().is_none(), "legacy feature mask received a guest call grant");
    }

    let waiting = owner.lobby(id);
    let admitted = owner.decide(&waiting, &patient, GuestDecision::Admit);
    assert_eq!(state(&admitted, &patient), GuestState::Admitted);
    refuse(
        owner.ask(Request::GuestLobbyDecide { meeting: id, guest: refused.guest, revision: waiting.revision, decision: GuestDecision::Decline }).0,
        E_CONFLICT,
    );
    let declined = owner.decide(&admitted, &refused, GuestDecision::Decline);
    assert_eq!(state(&declined, &refused), GuestState::Declined);

    let mut media = MediaServer::new(Config { server_name: MEDIA.into(), trusted_key: key, address: MEDIA_ADDRESS.parse().unwrap() });
    let guest_person = {
        let mut rooms = rooms.lock().unwrap();
        let mut entrance = rooms.guest_entrance(|| NOW);
        let mut wrong = patient.clone();
        wrong.meeting = staff;
        assert!(matches!(entrance.status(peer(3), &wrong), Err(GuestError::NoSuchGuest)));
        wrong = patient.clone();
        wrong.bearer.0[0] ^= 1;
        assert!(matches!(entrance.media(peer(3), &wrong), Err(GuestError::NoSuchGuest)));
        assert!(entrance.media(peer(2), &refused).is_err());
        let grant = entrance.media(peer(1), &patient).unwrap();
        let verified = Verifier::new(key, MEDIA).verify(&grant.credential, NOW).unwrap();
        assert_eq!((verified.call, verified.room.as_str(), verified.person.as_str()), (call, room.as_str(), grant.person.as_str()));
        assert!(grant.person.starts_with("guest:") && grant.label.ends_with("(guest)") && verified.not_after_ms < EXPIRY);
        media.join(call, &grant.credential, &offer(), Instant::now(), NOW).unwrap();
        grant.person
    };
    assert_eq!(media.participants(call).len(), 1);
    let removed = owner.decide(&declined, &patient, GuestDecision::Remove);
    assert_eq!(state(&removed, &patient), GuestState::Removed);
    let drops = rooms.lock().unwrap().take_media_events();
    assert_eq!(drops, vec![MediaEvent::DropPerson { call, person: guest_person.clone() }]);
    assert_eq!(media.drop_person(call, &guest_person), 1);
    assert!(rooms.lock().unwrap().guest_entrance(|| NOW).media(peer(1), &patient).is_err());

    let keep_waiting = rooms.lock().unwrap().guest_entrance(|| NOW).knock(peer(4), &code.0, "Waiting visitor").unwrap().proof;
    let before_toggle = owner.lobby(id);
    let change = |confirm_direct| GuestMeetingChange::SetLobby { meeting: id, revision: before_toggle.revision, lobby: false, confirm_direct };
    assert!(matches!(owner.ask(Request::GuestMeetingSave { change: change(false) }).0, Response::Error { .. }));
    let direct = lobby(owner.guest(Request::GuestMeetingSave { change: change(true) }));
    assert!(!direct.lobby);
    assert_eq!(state(&direct, &keep_waiting), GuestState::Waiting);
    let (direct_guest, direct_person) = {
        let mut rooms = rooms.lock().unwrap();
        let mut entrance = rooms.guest_entrance(|| NOW);
        let joined = entrance.knock(peer(5), &code.0, "Direct visitor").unwrap();
        assert_eq!(joined.state, GuestState::Admitted);
        let grant = entrance.media(peer(5), &joined.proof).unwrap();
        media.join(call, &grant.credential, &offer(), Instant::now(), NOW).unwrap();
        (joined.proof, grant.person)
    };
    let before_close = owner.lobby(id);
    let closed = lobby(owner.guest(Request::GuestLinkClose { meeting: id, revision: before_close.revision }));
    assert!(closed.closed);
    assert_eq!(state(&closed, &keep_waiting), GuestState::Declined);
    assert_eq!(state(&closed, &direct_guest), GuestState::Removed);
    assert_eq!(rooms.lock().unwrap().take_media_events(), vec![MediaEvent::DropPerson { call, person: direct_person.clone() }]);
    assert_eq!(media.drop_person(call, &direct_person), 1);
    assert!(rooms.lock().unwrap().open_call(&room).is_some());
    assert_eq!(cursor(owner.ask(Request::MeetingJoin { meeting: id }).0), call);
    assert!(rooms.lock().unwrap().guest_entrance(|| NOW).media(peer(5), &direct_guest).is_err());
    let (_, events, pushes) = owner.ask(Request::Sync { room: room.clone(), cursor: head });
    assert!(matches!(&pushes[..], [Push::GuestLobbyState { waiting: 0, .. }]));
    assert_eq!(owner.client.inbox().view(&room).unwrap().guest_lobby_state().unwrap().waiting, 0);
    assert!(events.iter().any(|event| matches!(event, ClientEvent::MeetingLine { change: MeetingChange::Lobby, .. })));
    assert!(
        !old.ask(Request::Sync { room: room.clone(), cursor: 0 })
            .1
            .iter()
            .any(|event| { matches!(event, ClientEvent::MeetingLine { change: MeetingChange::Lobby, .. }) })
    );
    cursor(owner.ask(Request::CallLeave { room: room.clone(), call }).0);
    assert_missed_calls(&rooms.lock().unwrap(), ordinary, call);

    let (expiring, expiring_code) = create(&mut owner, &room);
    let expiring_guest = rooms.lock().unwrap().guest_entrance(|| NOW).knock(peer(6), &expiring_code.0, "Late visitor").unwrap();
    assert_eq!(expiring_guest.state, GuestState::Waiting);
    drop(owner);
    drop(old);
    drop(rooms);

    let stored = fs::read(&path).unwrap();
    assert!(!stored.windows(code.0.len()).any(|bytes| bytes == code.0.as_bytes()));
    assert!(!stored.windows(patient.bearer.0.len()).any(|bytes| bytes == patient.bearer.0.as_slice()));
    let mut reopened = DurableServer::open(&path).unwrap();
    assert_eq!(reopened.guest_lobby(OWNER, id, NOW).unwrap(), closed);
    assert_missed_calls(&reopened, ordinary, call);
    assert!(reopened.guest_entrance(|| NOW).lookup(peer(7), &code.0).is_err());
    assert_eq!(reopened.guest_entrance(|| EXPIRY - 1).status(peer(6), &expiring_guest.proof).unwrap().state, GuestState::Waiting);
    assert!(matches!(reopened.guest_entrance(|| EXPIRY).lookup(peer(7), &expiring_code.0), Err(GuestError::LinkClosed)));
    reopened.sweep_guest_links(EXPIRY).unwrap();
    let expired = reopened.guest_lobby(OWNER, expiring.meeting, EXPIRY).unwrap();
    assert!(expired.closed);
    assert_eq!(state(&expired, &expiring_guest.proof), GuestState::Declined);
}

fn assert_missed_calls(rooms: &DurableServer, staff: u64, guest: u64) {
    let missed = rooms.missed_calls(MEMBER);
    assert!(missed.iter().any(|item| item.call == staff));
    assert!(missed.iter().all(|item| item.call != guest));
    let activity = rooms.activity(MEMBER, ActivityFilter::All);
    assert!(activity.items.iter().any(|item| item.kind == ActivityKind::MissedCall && item.target == staff));
    assert!(activity.items.iter().all(|item| item.kind != ActivityKind::MissedCall || item.target != guest));
}
