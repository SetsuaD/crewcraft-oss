#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, TryLockError};
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_accounts::password;
use crewcraft_accounts::throttle::Throttle;
use crewcraft_pki::{Authority, Claims, DEVICE_LIFETIME_SECS};
use crewcraft_proto::signin::SignIn;
use crewcraft_server::device_session::{AuthError, DeviceAuth};
use crewcraft_server::stored_device_auth::StoredDeviceAuth;
use crewcraft_server_core::account_store::{AccountStore, Activation, FirstDevice};
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::seal::ServiceKey;
use crewcraft_totp::Totp;
use rcgen::{CertificateParams, KeyPair};

const NOW_MS: u64 = 1_800_000_000_000;
const PASSWORD: &str = "synthetic fixture password";
const TOTP_SECRET: [u8; 20] = [3; 20];
const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";

struct AccountPath(PathBuf);

impl AccountPath {
    fn new(test: &str) -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        Self(std::env::temp_dir().join(format!("crewcraft-t223-{test}-{}-{nonce}", std::process::id())))
    }
}

impl Drop for AccountPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn service_key() -> ServiceKey {
    ServiceKey::from_bytes([5; 32])
}

fn activated(path: &Path) -> (AccountStore, [Vec<u8>; 2]) {
    let mut store = AccountStore::create(path, service_key()).unwrap();
    let root = Authority::create_root("Test Root", NOW_MS).unwrap();
    let mut issuer = root.create_issuing("Test Issuer", NOW_MS).unwrap();
    let phc = password::hash(PASSWORD).unwrap();
    let leaves = [(ALICE, 1u8), (BOB, 2u8)].map(|(person, index)| {
        let bootstrap_pub = [index; 32];
        let device_id = u64::from(index);
        let key = KeyPair::generate().unwrap();
        let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap();
        let issued = issuer.issue_device(csr.der().as_ref(), &Claims { person, device_id }, NOW_MS).unwrap();
        store.issue_invite(Invite { email: person.into(), bootstrap_pub, expires_ms: NOW_MS + 300_000 }, NOW_MS).unwrap();
        let activation = Activation {
            bootstrap_pub,
            device_name: "test device",
            certificate: &issued.certificate,
            spki_sha256: issued.key_id,
            counter: NOW_MS / 30_000,
            first_device: Some(FirstDevice { password_phc: Some(&phc), totp_secret: &TOTP_SECRET }),
            expected_device_id: Some(device_id),
        };
        assert_eq!(store.activate(activation, NOW_MS).unwrap(), device_id);
        issued.certificate
    });
    (store, leaves)
}

fn code(now_ms: u64) -> String {
    Totp::with_defaults(TOTP_SECRET.to_vec()).unwrap().generate(now_ms / 1000)
}

fn credentials<'a>(email: &'a str, code: &'a str) -> SignIn<'a> {
    SignIn { email, password: PASSWORD, code }
}

#[test]
fn binds_the_canonical_account_throttles_it_and_holds_authorization_through_the_action() {
    let path = AccountPath::new("sign-in");
    let (store, [alice_leaf, bob_leaf]) = activated(&path.0);
    let store = Arc::new(Mutex::new(store));
    let throttle = Arc::new(Mutex::new(Throttle::new()));
    let alice = StoredDeviceAuth::bind(store.clone(), throttle.clone(), &alice_leaf, NOW_MS).unwrap();
    let bob = StoredDeviceAuth::bind(store.clone(), throttle.clone(), &bob_leaf, NOW_MS).unwrap();
    let fresh = NOW_MS + 30_000;
    let fresh_code = code(fresh);

    assert!(alice.sign_in(credentials(BOB, &fresh_code), fresh).unwrap().is_none());
    assert_eq!(throttle.lock().unwrap().failures(ALICE), 1);
    assert_eq!(throttle.lock().unwrap().failures(BOB), 0);
    assert!(alice.sign_in(credentials(ALICE, &fresh_code), fresh).unwrap().is_none());
    let signed_in = alice.sign_in(credentials("  ALICE@EXAMPLE.ORG  ", &fresh_code), fresh + 1000).unwrap().unwrap();
    assert_eq!(signed_in.user, ALICE);
    assert_eq!(throttle.lock().unwrap().failures(ALICE), 0);

    assert_eq!(bob.with_live_session(&signed_in.session, fresh + 1001, || true).unwrap(), None);
    let held = alice.with_live_session(&signed_in.session, fresh + 1001, || matches!(store.try_lock(), Err(TryLockError::WouldBlock))).unwrap();
    assert_eq!(held, Some(true));
    assert!(store.try_lock().is_ok());
    assert!(alice.sign_in(credentials(ALICE, &fresh_code), fresh + 1001).unwrap().is_none());
}

#[test]
fn committed_hash_and_counter_reopen_and_revocation_precedes_the_next_action() {
    let path = AccountPath::new("restart");
    let (store, [leaf, _]) = activated(&path.0);
    let store = Arc::new(Mutex::new(store));
    let throttle = Arc::new(Mutex::new(Throttle::new()));
    let fresh = NOW_MS + 30_000;
    let fresh_code = code(fresh);
    let auth = StoredDeviceAuth::bind(store.clone(), throttle.clone(), &leaf, NOW_MS).unwrap();
    let signed_in = auth.sign_in(credentials(ALICE, &fresh_code), fresh).unwrap().unwrap();
    drop(auth);
    drop(store);
    assert!(!fs::read(&path.0).unwrap().windows(signed_in.token.len()).any(|bytes| bytes == signed_in.token.as_bytes()));

    let reopened = AccountStore::open(&path.0, service_key()).unwrap();
    assert_eq!(reopened.person(ALICE).unwrap().last_totp_counter, fresh / 30_000);
    let reopened = Arc::new(Mutex::new(reopened));
    let auth = StoredDeviceAuth::bind(reopened.clone(), throttle.clone(), &leaf, fresh + 1).unwrap();
    assert_eq!(auth.with_live_session(&signed_in.session, fresh + 1, || true).unwrap(), Some(true));
    assert!(auth.sign_in(credentials(ALICE, &fresh_code), fresh + 1).unwrap().is_none());

    reopened.lock().unwrap().revoke_device(ALICE, 1).unwrap();
    assert_eq!(auth.with_live_session(&signed_in.session, fresh + 2, || true).unwrap(), None);
    assert!(matches!(StoredDeviceAuth::bind(reopened, throttle, &leaf, fresh + 2), Err(AuthError::UnauthorizedDevice)));
}

#[test]
fn socket_held_across_certificate_expiry_loses_its_session() {
    let path = AccountPath::new("expiry");
    let (store, [leaf, _]) = activated(&path.0);
    let expires_at = NOW_MS + DEVICE_LIFETIME_SECS as u64 * 1000;
    let now = expires_at - 30_000;
    let auth = StoredDeviceAuth::bind(Arc::new(Mutex::new(store)), Arc::new(Mutex::new(Throttle::new())), &leaf, now).unwrap();
    let signed_in = auth.sign_in(credentials(ALICE, &code(now)), now).unwrap().unwrap();
    assert_eq!(auth.with_live_session(&signed_in.session, now + 1, || true).unwrap(), Some(true));
    assert_eq!(auth.with_live_session(&signed_in.session, expires_at + 1000, || true).unwrap(), None);
}
