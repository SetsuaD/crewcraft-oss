//! T370d: the app's ChatSession uses the enrolled-device sign-in service over loopback, sharing a durable room store
//! with the in-process guest entrance. The synthetic device fixture follows T370c. No guest listener is started.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crewcraft::chat_session::{ChatError, ChatSession};
use crewcraft_accounts::password;
use crewcraft_accounts::throttle::Throttle;
use crewcraft_client_core::notify::Settings;
use crewcraft_pki::{Authority, Claims};
use crewcraft_proto::guest::{GuestDecision, GuestMeetingChange, GuestMeetingDraft, GuestReply, GuestState};
use crewcraft_proto::handshake::{Hello, ServerSide};
use crewcraft_proto::request::{FEATURE_GAP_REPLAY, FEATURE_GUEST_MEETINGS, FEATURE_MEETINGS};
use crewcraft_proto::signin::SignIn;
use crewcraft_server::device_session::serve;
use crewcraft_server::stored_device_auth::StoredDeviceAuth;
use crewcraft_server_core::account_store::{AccountStore, Activation, FirstDevice};
use crewcraft_server_core::dispatch::E_CONFLICT;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::guests::GuestEntrance;
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::seal::ServiceKey;
use crewcraft_totp::Totp;
use rcgen::{CertificateParams, KeyPair};

const STAFF: &str = "staff@example.org";
const PASSWORD: &str = "synthetic lobby fixture password";
const CREATED_AT: u64 = 1_800_000_000_000;
const NOW: u64 = CREATED_AT + 30_000;
const WAIT: Duration = Duration::from_secs(5);
const FEATURES: u32 = FEATURE_MEETINGS | FEATURE_GUEST_MEETINGS | FEATURE_GAP_REPLAY;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("crewcraft-t370d-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn enrolled(path: &Path) -> (StoredDeviceAuth, String) {
    let mut accounts = AccountStore::create(path, ServiceKey::from_bytes([8; 32])).unwrap();
    let root = Authority::create_root("Fixture Root", CREATED_AT).unwrap();
    let mut issuer = root.create_issuing("Fixture Issuer", CREATED_AT).unwrap();
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
    let leaf = issuer.issue_device(csr.der().as_ref(), &Claims { person: STAFF, device_id: 1 }, CREATED_AT).unwrap();
    let bootstrap_pub = [1; 32];
    let phc = password::hash(PASSWORD).unwrap();
    let secret = [11; 20];
    accounts.issue_invite(Invite { email: STAFF.into(), bootstrap_pub, expires_ms: NOW + 60_000 }, CREATED_AT).unwrap();
    let activation = Activation {
        bootstrap_pub,
        device_name: "Fixture device",
        certificate: &leaf.certificate,
        spki_sha256: leaf.key_id,
        counter: CREATED_AT / 30_000,
        first_device: Some(FirstDevice { password_phc: Some(&phc), totp_secret: &secret }),
        expected_device_id: Some(1),
    };
    assert_eq!(accounts.activate(activation, CREATED_AT).unwrap(), 1);
    let auth = StoredDeviceAuth::bind(Arc::new(Mutex::new(accounts)), Arc::new(Mutex::new(Throttle::new())), &leaf.certificate, NOW).unwrap();
    let code = Totp::with_defaults(secret.to_vec()).unwrap().generate(NOW / 1_000);
    (auth, code)
}

fn deadline() -> Instant {
    Instant::now() + WAIT
}

fn set_deadline(socket: &mut TcpStream, cutoff: Instant) {
    let timeout = Some(cutoff.saturating_duration_since(Instant::now()).max(Duration::from_millis(1)));
    socket.set_read_timeout(timeout).unwrap();
    socket.set_write_timeout(timeout).unwrap();
}

#[test]
fn staff_session_reads_a_fresh_waiting_count_at_the_same_timeline_head() {
    let scratch = Scratch::new();
    let (auth, code) = enrolled(&scratch.0.join("accounts"));
    let mut rooms = DurableServer::open(&scratch.0.join("rooms")).unwrap();
    let room = rooms.create_room(STAFF, "Planning").unwrap();
    let rooms = Arc::new(Mutex::new(rooms));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let server_rooms = rooms.clone();
    let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let side = ServerSide { min_version: 1, max_version: 1, features: FEATURES, name: "Fixture server".into() };
        serve(&mut socket, &auth, &server_rooms, side, |_| Ok(()), || NOW)
    });
    let hello = Hello { min_version: 1, max_version: 1, features: FEATURES, client: "Fixture client".into() };
    let sign_in = SignIn { email: STAFF, password: PASSWORD, code: &code };
    let mut session = ChatSession::connect(socket, set_deadline, &sign_in, hello, Settings::default(), WAIT, deadline()).unwrap();
    assert!(session.guest_meetings_offered());

    let change = GuestMeetingChange::Create(GuestMeetingDraft {
        room: room.clone(),
        start_ms: NOW,
        duration: 30,
        title: "Planning".into(),
        agenda: String::new(),
        host_name: "Host".into(),
        expires_ms: NOW + 3 * 60 * 60 * 1_000,
        lobby: true,
        confirm_direct: false,
    });
    let GuestReply::Created { lobby: created, code: guest_code } = session.guest_save(change, deadline()).unwrap() else {
        panic!("creation did not return the guest code");
    };
    assert!(guest_code.is_valid());
    assert_eq!(session.guest_list(created.meeting, deadline()).unwrap(), created);
    let head = session.sync(&room, false, NOW, 0, deadline()).unwrap();
    let empty = session.guest_lobby_state(&room).unwrap();
    assert_eq!(empty.waiting, 0);

    let knock = rooms.lock().unwrap().guest_entrance(|| NOW).knock(Ipv4Addr::new(198, 51, 100, 1).into(), &guest_code.0, "Guest").unwrap();
    assert_eq!(knock.state, GuestState::Waiting);
    assert_eq!(session.sync(&room, false, NOW, 0, deadline()).unwrap(), head);
    let waiting = session.guest_lobby_state(&room).unwrap();
    assert_eq!((waiting.head, waiting.waiting), (head, 1));
    assert!(waiting.revision > empty.revision);
    assert_eq!(session.sync(&room, false, NOW, 0, deadline()).unwrap(), head);
    assert_eq!(session.guest_lobby_state(&room), Some(waiting));

    let guest = knock.proof.guest;
    let meeting = created.meeting;
    assert_eq!(session.guest_decide(meeting, guest, created.revision, GuestDecision::Admit, deadline()), Err(ChatError::Rejected(E_CONFLICT)));
    let reloaded = session.guest_list(meeting, deadline()).unwrap();
    assert_eq!(reloaded.entries[0].guest, guest);
    assert_eq!(reloaded.entries[0].state, GuestState::Waiting);
    let admitted = session.guest_decide(meeting, guest, reloaded.revision, GuestDecision::Admit, deadline()).unwrap();
    assert_eq!(admitted.entries[0].state, GuestState::Admitted);
    assert_eq!(session.guest_close(meeting, admitted.revision, deadline()).unwrap().entries[0].state, GuestState::Removed);
    session.sync(&room, false, NOW, 0, deadline()).unwrap();
    assert_eq!(session.guest_lobby_state(&room).unwrap().waiting, 0);

    drop(session);
    server.join().unwrap().unwrap();
}
