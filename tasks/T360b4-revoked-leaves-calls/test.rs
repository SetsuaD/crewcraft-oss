//! T360b4: removed means removed, for withdrawn access too (docs/CALLS.md "Admission"). A person bound to the
//! organization's provider is in a call and admitted to its media; when the external authorizer then refuses them
//! (task T611j's re-check), their session ends and the server takes them out of the call at once, so a `DropPerson`
//! reaches the media server and it drops them. While the authorizer allows them, nothing of the kind happens.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crewcraft_accounts::password;
use crewcraft_accounts::throttle::Throttle;
use crewcraft_authz::{Answer, Capabilities};
use crewcraft_media::{Config, MediaServer};
use crewcraft_media_auth::Issuer;
use crewcraft_oidc::{Identity, Key};
use crewcraft_pki::{Authority, Claims};
use crewcraft_proto::frame::encode;
use crewcraft_proto::handshake::{self, Hello, ServerSide};
use crewcraft_proto::request::{Request, encode_request};
use crewcraft_proto::signin::{self, SignIn};
use crewcraft_server::device_session::{DeviceAuth, DeviceSessionError, serve};
use crewcraft_server::external_signin::{Authorizer, ExternalSignIn, Provider};
use crewcraft_server::stored_device_auth::StoredDeviceAuth;
use crewcraft_server_core::account_store::{AccountStore, Activation, FirstDevice};
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::media::{MediaEvent, MediaIssuer};
use crewcraft_server_core::room::Role;
use crewcraft_server_core::seal::ServiceKey;
use crewcraft_totp::Totp;
use rcgen::{CertificateParams, KeyPair};
use str0m::media::{Direction, MediaKind};
use str0m::{Candidate, Rtc};

const NOW_MS: u64 = 1_800_000_000_000;
const PASSWORD: &str = "synthetic fixture password";
const TOTP_SECRET: [u8; 20] = [3; 20];
const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";
const ISSUER: &str = "https://id.example.org/";
const MEDIA: &str = "media.example.org";
const MEDIA_ADDRESS: &str = "203.0.113.10:3478";

struct Scratch(PathBuf);

impl Scratch {
    fn new(test: &str) -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("crewcraft-t360b4-{test}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// An account store where Alice is enrolled (password and authenticator) on device 1, bound to the provider.
fn alice_enrolled(path: &Path) -> (AccountStore, Vec<u8>) {
    let mut store = AccountStore::create(path, ServiceKey::from_bytes([5; 32])).unwrap();
    let root = Authority::create_root("Test Root", NOW_MS).unwrap();
    let mut issuer = root.create_issuing("Test Issuer", NOW_MS).unwrap();
    let phc = password::hash(PASSWORD).unwrap();
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
    let issued = issuer.issue_device(csr.der().as_ref(), &Claims { person: ALICE, device_id: 1 }, NOW_MS).unwrap();
    store.issue_invite(Invite { email: ALICE.into(), bootstrap_pub: [1; 32], expires_ms: NOW_MS + 300_000 }, NOW_MS).unwrap();
    let activation = Activation {
        bootstrap_pub: [1; 32],
        device_name: "test device",
        certificate: &issued.certificate,
        spki_sha256: issued.key_id,
        counter: NOW_MS / 30_000,
        first_device: Some(FirstDevice { password_phc: Some(&phc), totp_secret: &TOTP_SECRET }),
        expected_device_id: Some(1),
    };
    assert_eq!(store.activate(activation, NOW_MS).unwrap(), 1);
    store.bind_external(ALICE, ISSUER, "sub-alice").unwrap();
    (store, issued.certificate)
}

/// A provider that is never used here (Alice signs in with her password; only the authorizer is asked).
struct NoProvider;

impl Provider for NoProvider {
    fn issuer(&self) -> &str {
        ISSUER
    }
    fn client_id(&self) -> &str {
        "chat"
    }
    fn authorization_endpoint(&self) -> Result<String, String> {
        Err("not used".into())
    }
    fn keys(&self, _refresh: bool) -> Result<Vec<Key>, String> {
        Err("not used".into())
    }
    fn exchange(&self, _code: &str, _verifier: &str, _redirect_uri: &str) -> Result<String, String> {
        Err("not used".into())
    }
}

/// An authorizer that always gives `answer`.
struct Fixed(Answer);

impl Authorizer for Fixed {
    fn ask(&self, identity: &Identity, _purpose: &str) -> Answer {
        assert_eq!(identity.subject, "sub-alice");
        self.0.clone()
    }
}

/// The bytes a client sends: its sign-in, its hello and one request.
struct Script {
    input: Cursor<Vec<u8>>,
}

impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for Script {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn script(signed_in_at: u64) -> Script {
    let code = Totp::with_defaults(TOTP_SECRET.to_vec()).unwrap().generate(signed_in_at / 1000);
    let mut input = encode(&signin::encode_request(&SignIn { email: ALICE, password: PASSWORD, code: &code }).unwrap()).unwrap();
    let hello = Hello { min_version: 1, max_version: 1, features: 0, client: "client".into() };
    input.extend(encode(&handshake::encode_hello(&hello).unwrap()).unwrap());
    input.extend(encode(&encode_request(1, &Request::Ping).unwrap()).unwrap());
    Script { input: Cursor::new(input) }
}

fn offer() -> String {
    let mut rtc = Rtc::builder().set_crypto_provider(Arc::new(crewcraft_media_crypto::provider())).build(Instant::now());
    rtc.add_local_candidate(Candidate::host("198.51.100.1:5000".parse().unwrap(), "udp").unwrap());
    let mut change = rtc.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
    change.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
    change.apply().unwrap().0.to_sdp_string()
}

/// Alice's session, with the authorizer answering `answer`, served over a call Alice and Bob are in and admitted to
/// the media core. Returns how serving ended, the room store, the call and the media core.
fn alice_in_a_call(name: &str, answer: Answer) -> (Result<(), DeviceSessionError>, Mutex<DurableServer>, u64, MediaServer, Scratch) {
    let scratch = Scratch::new(name);
    let (store, leaf) = alice_enrolled(&scratch.0.join("accounts"));
    let external = Arc::new(ExternalSignIn::new(Arc::new(NoProvider), Some(Arc::new(Fixed(answer))), false));
    let auth = StoredDeviceAuth::bind(Arc::new(Mutex::new(store)), Arc::new(Mutex::new(Throttle::new())), &leaf, NOW_MS).unwrap().with_external(external);
    assert_eq!(auth.device(), Some(1));

    let media_key = Issuer::from_pkcs8(&Issuer::generate().unwrap()).unwrap();
    let mut media = MediaServer::new(Config { server_name: MEDIA.to_owned(), trusted_key: media_key.public_key(), address: MEDIA_ADDRESS.parse().unwrap() });
    let mut rooms = DurableServer::open(&scratch.0.join("rooms")).unwrap();
    rooms.set_media(MediaIssuer::new(media_key, MEDIA, MEDIA_ADDRESS));
    let room = rooms.create_room(ALICE, "Project").unwrap();
    rooms.add_member(&room, ALICE, BOB, Role::Member).unwrap();
    let call = rooms.call_start(&room, ALICE, false, NOW_MS).unwrap();
    rooms.call_join(&room, BOB, call, NOW_MS).unwrap();
    for (person, device) in [(ALICE, 1), (BOB, 2)] {
        let credential = rooms.media_credential(&room, person, call, device, NOW_MS).unwrap().unwrap();
        media.join(call, &credential, &offer(), Instant::now(), NOW_MS + 1_000).unwrap();
    }
    assert_eq!(media.participants(call).len(), 2);
    assert!(rooms.take_media_events().is_empty());

    let rooms = Mutex::new(rooms);
    let signed_in_at = NOW_MS + 30_000;
    let mut clock = signed_in_at;
    let server = ServerSide { min_version: 1, max_version: 1, features: 0, name: "server".into() };
    let served = serve(&mut script(signed_in_at), &auth, &rooms, server, |_| Ok(()), || {
        clock += 1;
        clock
    });
    (served, rooms, call, media, scratch)
}

#[test]
fn a_person_the_authorizer_refuses_is_dropped_from_the_call_and_its_media() {
    let (served, rooms, call, mut media, _scratch) = alice_in_a_call("deny", Answer::Deny { revision: 2 });
    assert!(matches!(served, Err(DeviceSessionError::SessionEnded)), "{served:?}");

    // Out of the call at once, and the media server is told: it drops Alice and keeps Bob.
    let mut rooms = rooms.into_inner().unwrap();
    let events = rooms.take_media_events();
    assert_eq!(events, vec![MediaEvent::DropPerson { call, person: ALICE.to_owned() }]);
    let open = rooms.call(call).unwrap();
    assert!(!open.present.contains_key(ALICE) && open.present.contains_key(BOB));
    for event in events {
        if let MediaEvent::DropPerson { call, person } = event {
            assert_eq!(media.drop_person(call, &person), 1);
        }
    }
    assert_eq!(media.participants(call).len(), 1, "only Bob is left in the media");
}

#[test]
fn a_person_the_authorizer_allows_stays_in_the_call() {
    let allow = Answer::Allow { capabilities: Capabilities::from_names(["use"]), revision: 1, recheck_after_secs: None };
    let (served, rooms, call, media, _scratch) = alice_in_a_call("allow", allow);
    assert!(served.is_ok(), "{served:?}");
    let mut rooms = rooms.into_inner().unwrap();
    assert!(rooms.take_media_events().is_empty());
    assert!(rooms.call(call).unwrap().present.contains_key(ALICE));
    assert_eq!(media.participants(call).len(), 2);
}
