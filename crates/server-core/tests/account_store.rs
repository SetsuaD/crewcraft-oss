//! The authentication store across restarts (issue #35): one-record activation, no partial writes, fail-closed keys,
//! torn records, TOTP replay and revoked devices. Every test uses its own fresh file under the temp directory and
//! synthetic values only (no real names, keys or codes).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crewcraft_proto::message::CodecError;
use crewcraft_server_core::account_op::{AccountOp, decode_account_op, encode_account_op};
use crewcraft_server_core::account_store::{AccountStore, Activation, AppendLog, FirstDevice, StoreError, fingerprint};
use crewcraft_server_core::devices::DeviceError;
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::journal::{Journal, JournalError};
use crewcraft_server_core::seal::{KeyFileError, SealError, ServiceKey};

const KEY: [u8; 32] = [7; 32];
const OTHER_KEY: [u8; 32] = [9; 32];
const SECRET_A: &[u8] = b"synthetic-totp-AAAAA";
const SECRET_B: &[u8] = b"synthetic-totp-BBBBB";
const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljc2FsdA$c3ludGhldGljLWhhc2gtZm9yLXRlc3RzLW9ubHk";
const DAY: u64 = 24 * 60 * 60 * 1000;
const T0: u64 = 1_800_000_000_000;

fn path(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("crewcraft-account-store-{name}-{}.journal", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

/// A synthetic stand-in for an issued leaf certificate (the store treats it as opaque DER).
fn cert(n: u8) -> &'static [u8] {
    Box::leak(vec![0x30, 0x82, n, n, n, n].into_boxed_slice())
}

fn fp(n: u8) -> [u8; 32] {
    fingerprint(cert(n))
}

fn key() -> ServiceKey {
    ServiceKey::from_bytes(KEY)
}

fn invite(email: &str, n: u8) -> Invite {
    Invite { email: email.to_string(), bootstrap_pub: [n; 32], expires_ms: T0 + 3 * DAY }
}

fn first(n: u8, name: &str, counter: u64, secret: &'static [u8]) -> Activation<'static> {
    let name: &'static str = Box::leak(name.to_string().into_boxed_str());
    Activation {
        bootstrap_pub: [n; 32],
        device_name: name,
        certificate: cert(n),
        spki_sha256: [n.wrapping_add(100); 32],
        counter,
        first_device: Some(FirstDevice { password_phc: Some(PHC), totp_secret: secret }),
    }
}

fn another_device(n: u8, counter: u64) -> Activation<'static> {
    Activation {
        bootstrap_pub: [n; 32],
        device_name: "second device",
        certificate: cert(n),
        spki_sha256: [n.wrapping_add(100); 32],
        counter,
        first_device: None,
    }
}

/// A store with A (device 1) and B (device 2) activated.
fn two_people(p: &Path) -> AccountStore {
    let mut s = AccountStore::open(p, key()).unwrap();
    s.issue_invite(invite("a@example.com", 1), T0).unwrap();
    s.issue_invite(invite("b@example.com", 2), T0).unwrap();
    assert_eq!(s.activate(first(1, "a laptop", 1000, SECRET_A), T0 + 1).unwrap(), 1);
    assert_eq!(s.activate(first(2, "b laptop", 2000, SECRET_B), T0 + 2).unwrap(), 2);
    s
}

#[test]
fn activation_commits_and_reopens_exactly() {
    let p = path("reopen");
    {
        let s = two_people(&p);
        assert!(!s.is_invite_pending(&[1; 32], T0 + 3));
    }
    let mut s = AccountStore::open(&p, key()).unwrap();
    let a = s.person("a@example.com").unwrap();
    assert_eq!(a.password_phc.as_deref(), Some(PHC));
    assert_eq!(a.last_totp_counter, 1000);
    assert_eq!(&s.totp_secret("a@example.com").unwrap()[..], SECRET_A);
    assert_eq!(&s.totp_secret("b@example.com").unwrap()[..], SECRET_B);
    assert_eq!(s.authenticate(&fp(1), T0 + 10).unwrap().id, 1);
    assert_eq!(s.device_certificate(1), Some(cert(1)));
    assert_eq!(s.device_by_key(&[102; 32]), Some(2));
    assert_eq!(s.authenticate(&fp(2), T0 + 10).unwrap().user, "b@example.com");
    // Consumed invitations stay consumed after the restart.
    assert!(!s.is_invite_pending(&[1; 32], T0 + 10));
    assert_eq!(s.activate(first(1, "replay", 1001, SECRET_A), T0 + 10).unwrap_err(), StoreError::NoInvite);
    let _ = fs::remove_file(&p);
}

#[test]
fn a_second_device_joins_the_invited_person_and_needs_a_newer_counter() {
    let p = path("second-device");
    {
        let mut s = two_people(&p);
        s.issue_invite(invite("a@example.com", 3), T0 + 5).unwrap();
        assert_eq!(s.activate(another_device(3, 1000), T0 + 6).unwrap_err(), StoreError::StaleCounter { last: 1000 });
        assert!(s.is_invite_pending(&[3; 32], T0 + 6), "a refused activation leaves the invitation pending");
        assert_eq!(s.activate(another_device(3, 1001), T0 + 6).unwrap(), 3);
    }
    let s = AccountStore::open(&p, key()).unwrap();
    assert_eq!(s.devices_of("a@example.com").len(), 2);
    assert_eq!(s.person("a@example.com").unwrap().last_totp_counter, 1001);
    let _ = fs::remove_file(&p);
}

#[test]
fn a_first_device_activation_for_an_existing_person_is_refused() {
    let p = path("person-exists");
    let mut s = two_people(&p);
    s.issue_invite(invite("a@example.com", 3), T0 + 5).unwrap();
    assert_eq!(s.activate(first(3, "dup", 5000, SECRET_B), T0 + 6).unwrap_err(), StoreError::PersonExists);
    let _ = fs::remove_file(&p);
}

/// Wraps the real journal; while `fail` is set, every append fails having written nothing.
struct FailingLog {
    inner: Journal,
    fail: Rc<Cell<bool>>,
}

impl AppendLog for FailingLog {
    fn append(&mut self, record: &[u8]) -> Result<(), JournalError> {
        if self.fail.get() {
            return Err(JournalError::Io(std::io::ErrorKind::StorageFull));
        }
        self.inner.append(record)
    }
}

#[test]
fn a_failed_write_returns_no_success_and_leaves_no_partial_activation() {
    let p = path("write-failure");
    {
        let mut s = AccountStore::open(&p, key()).unwrap();
        s.issue_invite(invite("a@example.com", 1), T0).unwrap();
    }
    let fail = Rc::new(Cell::new(false));
    {
        let (journal, records) = Journal::open(&p).unwrap();
        let mut s = AccountStore::from_records(FailingLog { inner: journal, fail: Rc::clone(&fail) }, key(), records).unwrap();
        fail.set(true);
        let outcome = s.activate(first(1, "a laptop", 1000, SECRET_A), T0 + 1);
        assert_eq!(outcome.unwrap_err(), StoreError::Journal(JournalError::Io(std::io::ErrorKind::StorageFull)));
        // Nothing reached memory: invitation pending, no person, no device.
        assert!(s.is_invite_pending(&[1; 32], T0 + 1));
        assert!(s.person("a@example.com").is_none());
        assert!(s.devices_of("a@example.com").is_empty());
        // The same activation succeeds once the disk works again.
        fail.set(false);
        assert_eq!(s.activate(first(1, "a laptop", 1000, SECRET_A), T0 + 2).unwrap(), 1);
    }
    let s = AccountStore::open(&p, key()).unwrap();
    assert_eq!(s.devices_of("a@example.com").len(), 1);
    let _ = fs::remove_file(&p);
}

#[test]
fn nothing_failed_is_on_disk_after_a_failed_write() {
    let p = path("write-failure-disk");
    {
        let mut s = AccountStore::open(&p, key()).unwrap();
        s.issue_invite(invite("a@example.com", 1), T0).unwrap();
    }
    let size_before = fs::metadata(&p).unwrap().len();
    {
        let (journal, records) = Journal::open(&p).unwrap();
        let fail = Rc::new(Cell::new(true));
        let mut s = AccountStore::from_records(FailingLog { inner: journal, fail }, key(), records).unwrap();
        assert!(s.activate(first(1, "a laptop", 1000, SECRET_A), T0 + 1).is_err());
    }
    assert_eq!(fs::metadata(&p).unwrap().len(), size_before);
    let s = AccountStore::open(&p, key()).unwrap();
    assert!(s.is_invite_pending(&[1; 32], T0 + 1));
    assert!(s.person("a@example.com").is_none());
    let _ = fs::remove_file(&p);
}

#[test]
fn a_torn_activation_record_rolls_back_to_the_pending_invitation() {
    let p = path("torn");
    {
        let mut s = AccountStore::open(&p, key()).unwrap();
        s.issue_invite(invite("a@example.com", 1), T0).unwrap();
        s.activate(first(1, "a laptop", 1000, SECRET_A), T0 + 1).unwrap();
    }
    // A crash in the middle of writing the activation: cut its frame short.
    let len = fs::metadata(&p).unwrap().len();
    fs::OpenOptions::new().write(true).open(&p).unwrap().set_len(len - 20).unwrap();
    let s = AccountStore::open(&p, key()).unwrap();
    assert!(s.is_invite_pending(&[1; 32], T0 + 2), "the invitation is still usable");
    assert!(s.person("a@example.com").is_none(), "no person without the whole record");
    assert!(s.devices_of("a@example.com").is_empty(), "no device without the whole record");
    let _ = fs::remove_file(&p);
}

#[test]
fn a_wrong_service_key_opens_nothing() {
    let p = path("wrong-key");
    drop(two_people(&p));
    assert_eq!(AccountStore::open(&p, ServiceKey::from_bytes(OTHER_KEY)).unwrap_err(), StoreError::WrongKey);
    // Also for an empty store: the key is pinned by the first record.
    let q = path("wrong-key-empty");
    drop(AccountStore::open(&q, key()).unwrap());
    assert_eq!(AccountStore::open(&q, ServiceKey::from_bytes(OTHER_KEY)).unwrap_err(), StoreError::WrongKey);
    // The right key still opens both.
    assert!(AccountStore::open(&p, key()).is_ok());
    let _ = fs::remove_file(&p);
    let _ = fs::remove_file(&q);
}

#[test]
fn key_files_are_never_created_silently_or_replaced() {
    let dir = std::env::temp_dir().join(format!("crewcraft-key-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("service.key");
    assert_eq!(ServiceKey::load(&file).unwrap_err(), KeyFileError::Missing);
    let made = ServiceKey::provision(&file).unwrap();
    assert_eq!(ServiceKey::provision(&file).unwrap_err(), KeyFileError::Exists);
    assert_eq!(ServiceKey::load(&file).unwrap().id(), made.id());
    fs::write(&file, [1u8; 31]).unwrap();
    assert_eq!(ServiceKey::load(&file).unwrap_err(), KeyFileError::WrongLength);
    fs::write(&file, [1u8; 33]).unwrap();
    assert_eq!(ServiceKey::load(&file).unwrap_err(), KeyFileError::WrongLength);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_sealed_secret_only_opens_with_its_key_and_its_person() {
    let k = key();
    let sealed = k.seal(SECRET_A, b"a@example.com").unwrap();
    assert_eq!(&k.open(&sealed, b"a@example.com").unwrap()[..], SECRET_A);
    assert_eq!(k.open(&sealed, b"b@example.com").unwrap_err(), SealError::Corrupt);
    assert_eq!(ServiceKey::from_bytes(OTHER_KEY).open(&sealed, b"a@example.com").unwrap_err(), SealError::WrongKey);
    let mut flipped = sealed.clone();
    flipped.ciphertext[0] ^= 1;
    assert_eq!(k.open(&flipped, b"a@example.com").unwrap_err(), SealError::Corrupt);
    assert_ne!(k.seal(SECRET_A, b"a@example.com").unwrap().nonce, sealed.nonce, "a fresh nonce per seal");
}

#[test]
fn the_totp_secret_and_password_are_not_in_plaintext_on_disk_or_in_debug() {
    let p = path("at-rest");
    let s = two_people(&p);
    let bytes = fs::read(&p).unwrap();
    for secret in [SECRET_A, SECRET_B] {
        assert!(!bytes.windows(secret.len()).any(|w| w == secret), "a TOTP secret is readable in the store file");
    }
    let debug = format!("{s:?}");
    assert!(!debug.contains("synthetic") && !debug.contains("argon2"), "{debug}");
    drop(s);
    let _ = fs::remove_file(&p);
}

#[test]
fn a_totp_counter_is_used_once_including_across_a_restart() {
    let p = path("counter");
    {
        let mut s = two_people(&p);
        assert_eq!(s.accept_totp("a@example.com", 1000).unwrap_err(), StoreError::StaleCounter { last: 1000 });
        s.accept_totp("a@example.com", 1001).unwrap();
        assert_eq!(s.accept_totp("a@example.com", 1001).unwrap_err(), StoreError::StaleCounter { last: 1001 });
        assert_eq!(s.accept_totp("a@example.com", 999).unwrap_err(), StoreError::StaleCounter { last: 1001 });
        assert_eq!(s.accept_totp("nobody@example.com", 5).unwrap_err(), StoreError::NoSuchPerson);
    }
    let mut s = AccountStore::open(&p, key()).unwrap();
    assert_eq!(s.accept_totp("a@example.com", 1001).unwrap_err(), StoreError::StaleCounter { last: 1001 });
    s.accept_totp("a@example.com", 1002).unwrap();
    // B's counter is its own.
    s.accept_totp("b@example.com", 2001).unwrap();
    let _ = fs::remove_file(&p);
}

#[test]
fn a_revoked_device_stays_revoked_after_a_restart() {
    let p = path("revoked");
    {
        let mut s = two_people(&p);
        assert!(s.revoke_device("a@example.com", 1).unwrap());
        assert!(!s.revoke_device("a@example.com", 1).unwrap(), "already revoked writes nothing");
        assert_eq!(s.revoke_device("a@example.com", 2).unwrap_err(), StoreError::Device(DeviceError::NoSuchDevice), "not A's device");
    }
    let mut s = AccountStore::open(&p, key()).unwrap();
    assert_eq!(s.authenticate(&fp(1), T0 + 10).unwrap_err(), DeviceError::Revoked);
    assert_eq!(s.authenticate(&fp(2), T0 + 10).unwrap().id, 2);
    // The revoked device key can never be enrolled again, even with a new certificate.
    s.issue_invite(invite("a@example.com", 1), T0 + 10).unwrap();
    let mut again = another_device(1, 1001);
    again.certificate = cert(42);
    assert_eq!(s.activate(again, T0 + 11).unwrap_err(), StoreError::KeyInUse);
    // And the revoked certificate itself stays banned under a new key.
    let mut same_cert = another_device(1, 1001);
    same_cert.spki_sha256 = [77; 32];
    assert_eq!(s.activate(same_cert, T0 + 11).unwrap_err(), StoreError::Device(DeviceError::Revoked));
    let _ = fs::remove_file(&p);
}

#[test]
fn expired_and_revoked_invitations_cannot_activate_after_a_restart() {
    let p = path("invites");
    {
        let mut s = AccountStore::open(&p, key()).unwrap();
        s.issue_invite(invite("a@example.com", 1), T0).unwrap();
        s.issue_invite(invite("b@example.com", 2), T0).unwrap();
        assert!(s.revoke_invite(&[2; 32]).unwrap());
        assert!(!s.revoke_invite(&[2; 32]).unwrap());
    }
    let mut s = AccountStore::open(&p, key()).unwrap();
    assert_eq!(s.activate(first(1, "late", 1000, SECRET_A), T0 + 3 * DAY).unwrap_err(), StoreError::NoInvite);
    assert_eq!(s.activate(first(2, "revoked", 1000, SECRET_B), T0 + 1).unwrap_err(), StoreError::NoInvite);
    let _ = fs::remove_file(&p);
}

#[test]
fn replay_is_exact_and_refuses_a_record_that_does_not_apply() {
    // A hand-written journal: a valid store header, then an activation of an invitation that was never issued.
    let p = path("exact");
    drop(AccountStore::open(&p, key()).unwrap());
    let k = key();
    {
        let (mut journal, _) = Journal::open(&p).unwrap();
        let rogue = AccountOp::Activated {
            bootstrap_pub: [5; 32],
            new_person: Some(crewcraft_server_core::account_op::NewPerson { password_phc: None, totp: k.seal(SECRET_A, b"x@example.com").unwrap() }),
            device_id: 1,
            device_name: "rogue".into(),
            certificate: vec![1, 2, 3],
            spki_sha256: [6; 32],
            counter: 1,
            now_ms: T0,
        };
        journal.append(&encode_account_op(&rogue).unwrap()).unwrap();
    }
    match AccountStore::open(&p, key()) {
        Err(StoreError::Corrupt { record: 1, cause }) => assert_eq!(*cause, StoreError::NoInvite),
        other => panic!("{other:?}"),
    }
    let _ = fs::remove_file(&p);
}

#[test]
fn a_store_that_does_not_start_with_its_header_is_refused() {
    let p = path("no-header");
    {
        let (mut journal, _) = Journal::open(&p).unwrap();
        journal.append(&encode_account_op(&AccountOp::TotpAccepted { email: "a@example.com".into(), counter: 1 }).unwrap()).unwrap();
    }
    assert!(matches!(AccountStore::open(&p, key()), Err(StoreError::Corrupt { record: 0, .. })));
    let _ = fs::remove_file(&p);
}

#[test]
fn records_round_trip_and_garbage_is_refused() {
    let k = key();
    let ops = vec![
        AccountOp::Created { format: 1, key_id: k.id() },
        AccountOp::InviteIssued { email: "a@example.com".into(), bootstrap_pub: [1; 32], expires_ms: 9, now_ms: 3 },
        AccountOp::InviteRevoked { bootstrap_pub: [2; 32] },
        AccountOp::Activated {
            bootstrap_pub: [1; 32],
            new_person: Some(crewcraft_server_core::account_op::NewPerson { password_phc: Some(PHC.into()), totp: k.seal(SECRET_A, b"a").unwrap() }),
            device_id: 4,
            device_name: "d".into(),
            certificate: vec![3; 40],
            spki_sha256: [3; 32],
            counter: 77,
            now_ms: 5,
        },
        AccountOp::Activated {
            bootstrap_pub: [1; 32],
            new_person: None,
            device_id: 5,
            device_name: "e".into(),
            certificate: vec![4; 9],
            spki_sha256: [4; 32],
            counter: 78,
            now_ms: 6,
        },
        AccountOp::TotpAccepted { email: "a@example.com".into(), counter: 79 },
        AccountOp::PasswordChanged { email: "a@example.com".into(), phc: PHC.into() },
        AccountOp::DeviceRevoked { email: "a@example.com".into(), device_id: 4 },
    ];
    for op in &ops {
        let bytes = encode_account_op(op).unwrap();
        assert_eq!(&decode_account_op(&bytes).unwrap(), op);
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(decode_account_op(&long).unwrap_err(), CodecError::TrailingBytes);
        assert_eq!(decode_account_op(&bytes[..bytes.len() - 1]).unwrap_err(), CodecError::Truncated);
    }
    assert_eq!(decode_account_op(&[99]).unwrap_err(), CodecError::BadKind(99));
    assert_eq!(decode_account_op(&[]).unwrap_err(), CodecError::Truncated);
}
