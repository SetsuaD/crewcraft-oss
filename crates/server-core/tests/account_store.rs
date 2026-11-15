//! The authentication store across restarts (issue #35): explicit setup, one-record activation, no partial writes,
//! strict journal recovery, fail-closed keys, canonical identity, TOTP replay, revoked devices and device-bound
//! sessions by token hash. Every test uses its own fresh file under the temp directory and synthetic values only.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crewcraft_proto::message::CodecError;
use crewcraft_server_core::account_journal::{AccountJournal, AppendError, OpenError};
use crewcraft_server_core::account_op::{AccountOp, NewPerson, decode_account_op, encode_account_op};
use crewcraft_server_core::account_store::{AccountStore, Activation, AppendLog, FirstDevice, StoreError, fingerprint};
use crewcraft_server_core::devices::DeviceError;
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::seal::{KeyFileError, SealError, ServiceKey};

const KEY: [u8; 32] = [7; 32];
const OTHER_KEY: [u8; 32] = [9; 32];
const SECRET_A: &[u8] = b"synthetic-totp-AAAAA";
const SECRET_B: &[u8] = b"synthetic-totp-BBBBB";
const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljc2FsdA$c3ludGhldGljLWhhc2gtZm9yLXRlc3RzLW9ubHk";
const DAY: u64 = 24 * 60 * 60 * 1000;
const T0: u64 = 1_800_000_000_000;
const A: &str = "a@example.com";
const B: &str = "b@example.com";

fn path(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("crewcraft-account-store-{name}-{}.journal", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

fn key() -> ServiceKey {
    ServiceKey::from_bytes(KEY)
}

/// A synthetic stand-in for an issued leaf certificate (the store treats it as opaque DER).
fn cert(n: u8) -> &'static [u8] {
    Box::leak(vec![0x30, 0x82, n, n, n, n].into_boxed_slice())
}

fn fp(n: u8) -> [u8; 32] {
    fingerprint(cert(n))
}

fn invite(email: &str, n: u8) -> Invite {
    Invite { email: email.to_string(), bootstrap_pub: [n; 32], expires_ms: T0 + 3 * DAY }
}

fn first(n: u8, counter: u64, secret: &'static [u8]) -> Activation<'static> {
    Activation {
        bootstrap_pub: [n; 32],
        device_name: "laptop",
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

/// A new store with A (device 1) and B (device 2) activated.
fn two_people(p: &Path) -> AccountStore {
    let mut s = AccountStore::create(p, key()).unwrap();
    s.issue_invite(invite(A, 1), T0).unwrap();
    s.issue_invite(invite(B, 2), T0).unwrap();
    assert_eq!(s.activate(first(1, 1000, SECRET_A), T0 + 1).unwrap(), 1);
    assert_eq!(s.activate(first(2, 2000, SECRET_B), T0 + 2).unwrap(), 2);
    s
}

fn reopen(p: &Path) -> AccountStore {
    AccountStore::open(p, key()).unwrap()
}

// ---- setup ----

#[test]
fn a_store_is_made_only_by_create() {
    let p = path("setup");
    assert_eq!(AccountStore::open(&p, key()).unwrap_err(), StoreError::NotInitialized, "ordinary start never creates a store");
    assert!(!p.exists());
    fs::write(&p, b"").unwrap();
    assert_eq!(AccountStore::open(&p, key()).unwrap_err(), StoreError::NotInitialized, "an empty file is not a store");
    assert_eq!(AccountStore::create(&p, key()).unwrap_err(), StoreError::Open(OpenError::Exists), "create never replaces a file");
    fs::remove_file(&p).unwrap();
    drop(AccountStore::create(&p, key()).unwrap());
    assert!(AccountStore::open(&p, key()).is_ok());
    let _ = fs::remove_file(&p);
}

// ---- activation ----

#[test]
fn activation_commits_and_reopens_exactly() {
    let p = path("reopen");
    drop(two_people(&p));
    let mut s = reopen(&p);
    let a = s.person(A).unwrap();
    assert_eq!(a.password_phc.as_deref(), Some(PHC));
    assert_eq!(a.last_totp_counter, 1000);
    assert_eq!(&s.totp_secret(A).unwrap()[..], SECRET_A);
    assert_eq!(&s.totp_secret(B).unwrap()[..], SECRET_B);
    assert_eq!(s.authenticate(&fp(1), T0 + 10).unwrap().id, 1);
    assert_eq!(s.device_certificate(1), Some(cert(1)));
    assert_eq!(s.device_by_key(&[102; 32]), Some(2));
    assert_eq!(s.authenticate(&fp(2), T0 + 10).unwrap().user, B);
    assert!(!s.is_invite_pending(&[1; 32], T0 + 10), "a consumed invitation stays consumed");
    assert_eq!(s.activate(first(1, 1001, SECRET_A), T0 + 10).unwrap_err(), StoreError::NoInvite);
    let _ = fs::remove_file(&p);
}

#[test]
fn a_second_device_joins_the_invited_person_and_needs_a_newer_counter() {
    let p = path("second-device");
    {
        let mut s = two_people(&p);
        s.issue_invite(invite(A, 3), T0 + 5).unwrap();
        assert_eq!(s.activate(another_device(3, 1000), T0 + 6).unwrap_err(), StoreError::StaleCounter { last: 1000 });
        assert!(s.is_invite_pending(&[3; 32], T0 + 6), "a refused activation leaves the invitation pending");
        assert_eq!(s.activate(another_device(3, 1001), T0 + 6).unwrap(), 3);
    }
    let s = reopen(&p);
    assert_eq!(s.devices_of(A).len(), 2);
    assert_eq!(s.person(A).unwrap().last_totp_counter, 1001);
    let _ = fs::remove_file(&p);
}

#[test]
fn a_first_device_activation_for_an_existing_person_is_refused() {
    let p = path("person-exists");
    let mut s = two_people(&p);
    s.issue_invite(invite(A, 3), T0 + 5).unwrap();
    assert_eq!(s.activate(first(3, 5000, SECRET_B), T0 + 6).unwrap_err(), StoreError::PersonExists);
    let _ = fs::remove_file(&p);
}

// ---- canonical identity ----

#[test]
fn only_canonical_emails_are_stored() {
    let p = path("canonical");
    let mut s = two_people(&p);
    for bad in ["A@example.com", " a@example.com", "a@Example.com", "a@example.com ", "not-an-email"] {
        assert_eq!(s.issue_invite(invite(bad, 9), T0 + 5).unwrap_err(), StoreError::NotCanonical, "{bad:?}");
    }
    assert!(!s.is_invite_pending(&[9; 32], T0 + 5));
    drop(s);
    // A hand-written record with a non-canonical email refuses the whole open.
    {
        let (mut journal, _) = AccountJournal::open(&p).unwrap();
        let op = AccountOp::InviteIssued { email: "A@example.com".into(), bootstrap_pub: [9; 32], expires_ms: T0 + DAY, now_ms: T0 + 5 };
        journal.append(&encode_account_op(&op).unwrap()).unwrap();
    }
    match AccountStore::open(&p, key()) {
        Err(StoreError::Corrupt { cause, .. }) => assert_eq!(*cause, StoreError::NotCanonical),
        other => panic!("{other:?}"),
    }
    let _ = fs::remove_file(&p);
}

// ---- write failures and writer health ----

/// Wraps the real journal; `mode` 0 = pass through, 1 = fail before writing (NotWritten), 2 = outcome unknown.
struct FailingLog {
    inner: AccountJournal,
    mode: Rc<Cell<u8>>,
}

impl AppendLog for FailingLog {
    fn append(&mut self, record: &[u8]) -> Result<(), AppendError> {
        match self.mode.get() {
            1 => Err(AppendError::NotWritten(std::io::ErrorKind::StorageFull)),
            2 => Err(AppendError::Ambiguous(std::io::ErrorKind::Other)),
            _ => self.inner.append(record),
        }
    }
}

fn failing(p: &Path, mode: &Rc<Cell<u8>>) -> AccountStore<FailingLog> {
    let (journal, records) = AccountJournal::open(p).unwrap();
    AccountStore::from_records(FailingLog { inner: journal, mode: Rc::clone(mode) }, key(), records).unwrap()
}

#[test]
fn a_failed_write_returns_no_success_and_leaves_no_partial_activation() {
    let p = path("write-failure");
    {
        let mut s = AccountStore::create(&p, key()).unwrap();
        s.issue_invite(invite(A, 1), T0).unwrap();
    }
    let size_before = fs::metadata(&p).unwrap().len();
    let mode = Rc::new(Cell::new(1));
    {
        let mut s = failing(&p, &mode);
        let outcome = s.activate(first(1, 1000, SECRET_A), T0 + 1);
        assert_eq!(outcome.unwrap_err(), StoreError::Append(AppendError::NotWritten(std::io::ErrorKind::StorageFull)));
        assert!(s.healthy(), "a failure proved precommit does not poison");
        assert!(s.is_invite_pending(&[1; 32], T0 + 1));
        assert!(s.person(A).is_none());
        assert!(s.devices_of(A).is_empty());
        assert_eq!(fs::metadata(&p).unwrap().len(), size_before, "nothing reached the file");
        // A precommit failure is safe to retry.
        mode.set(0);
        assert_eq!(s.activate(first(1, 1000, SECRET_A), T0 + 2).unwrap(), 1);
    }
    assert_eq!(reopen(&p).devices_of(A).len(), 1);
    let _ = fs::remove_file(&p);
}

#[test]
fn an_ambiguous_write_poisons_writes_admission_and_sessions_until_reopen() {
    let p = path("poison");
    let token = {
        let mut s = two_people(&p);
        s.accept_totp(A, 1001).unwrap();
        s.create_session([5; 32], A, 1, T0 + 10).unwrap()
    };
    let mode = Rc::new(Cell::new(0));
    let mut s = failing(&p, &mode);
    s.issue_invite(invite(B, 3), T0 + 11).unwrap();
    assert!(s.continue_session(&token, &fp(1), T0 + 12).is_some());
    mode.set(2);
    assert!(matches!(s.accept_totp(A, 1002), Err(StoreError::Append(AppendError::Ambiguous(_)))));
    assert!(!s.healthy());
    mode.set(0);
    // Even with a working disk, nothing is written or admitted until the store is reopened.
    assert_eq!(s.accept_totp(A, 1003).unwrap_err(), StoreError::Poisoned);
    assert_eq!(s.authenticate(&fp(1), T0 + 13).unwrap_err(), StoreError::Poisoned);
    assert!(!s.is_invite_pending(&[3; 32], T0 + 13));
    assert!(s.continue_session(&token, &fp(1), T0 + 13).is_none());
    assert_eq!(s.totp_secret(A).unwrap_err(), StoreError::Poisoned);
    assert!(s.person(A).is_none());
    assert_eq!(s.revoke_device(A, 1).unwrap_err(), StoreError::Poisoned);
    assert_eq!(s.activate(another_device(3, 5), T0 + 13).unwrap_err(), StoreError::Poisoned);
    drop(s);
    // Reopening replays what is really on disk.
    let mut s = reopen(&p);
    assert!(s.healthy());
    assert!(s.continue_session(&token, &fp(1), T0 + 14).is_some());
    let _ = fs::remove_file(&p);
}

// ---- strict journal recovery ----

/// Byte offset where the last frame starts.
fn last_frame_start(p: &Path) -> u64 {
    let bytes = fs::read(p).unwrap();
    let mut offset = 0usize;
    let mut last = 0usize;
    while offset < bytes.len() {
        let len = u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        last = offset;
        offset += 4 + len + 32;
    }
    last as u64
}

#[test]
fn a_torn_final_frame_is_recovered_and_rolls_back() {
    let p = path("torn");
    {
        let mut s = AccountStore::create(&p, key()).unwrap();
        s.issue_invite(invite(A, 1), T0).unwrap();
        s.activate(first(1, 1000, SECRET_A), T0 + 1).unwrap();
    }
    // A crash in the middle of writing the activation: its frame is cut short.
    let len = fs::metadata(&p).unwrap().len();
    fs::OpenOptions::new().write(true).open(&p).unwrap().set_len(len - 20).unwrap();
    let mut s = reopen(&p);
    assert!(s.is_invite_pending(&[1; 32], T0 + 2), "the invitation is still usable");
    assert!(s.person(A).is_none(), "no person without the whole record");
    assert!(s.devices_of(A).is_empty(), "no device without the whole record");
    // The torn tail was cut off, so the store keeps working.
    assert_eq!(s.activate(first(1, 1000, SECRET_A), T0 + 3).unwrap(), 1);
    drop(s);
    assert_eq!(reopen(&p).devices_of(A).len(), 1);
    let _ = fs::remove_file(&p);
}

#[test]
fn a_failed_open_changes_nothing_on_disk() {
    let p = path("open-no-mutation");
    drop(two_people(&p));
    let len = fs::metadata(&p).unwrap().len();
    fs::OpenOptions::new().write(true).open(&p).unwrap().set_len(len - 7).unwrap();
    let before = fs::read(&p).unwrap();
    assert_eq!(AccountStore::open(&p, ServiceKey::from_bytes(OTHER_KEY)).unwrap_err(), StoreError::WrongKey);
    assert_eq!(fs::read(&p).unwrap(), before, "a wrong-key open must not cut the torn tail or write anything");
    let _ = fs::remove_file(&p);
}

fn flip_byte(p: &Path, at: u64) {
    let mut bytes = fs::read(p).unwrap();
    bytes[at as usize] ^= 0x01;
    fs::write(p, bytes).unwrap();
}

#[test]
fn a_complete_corrupt_revocation_record_refuses_startup() {
    let p = path("corrupt-revocation");
    {
        let mut s = two_people(&p);
        assert!(s.revoke_device(A, 1).unwrap());
    }
    // The revocation is the last, complete frame; damage one byte of its body.
    flip_byte(&p, last_frame_start(&p) + 6);
    assert_eq!(AccountStore::open(&p, key()).unwrap_err(), StoreError::Open(OpenError::Corrupt { frame: 5 }));
    let _ = fs::remove_file(&p);
}

#[test]
fn a_complete_corrupt_counter_record_refuses_startup() {
    let p = path("corrupt-counter");
    {
        let mut s = two_people(&p);
        s.accept_totp(A, 1001).unwrap();
    }
    flip_byte(&p, fs::metadata(&p).unwrap().len() - 1); // the last byte of its hash
    assert_eq!(AccountStore::open(&p, key()).unwrap_err(), StoreError::Open(OpenError::Corrupt { frame: 5 }));
    let _ = fs::remove_file(&p);
}

#[test]
fn interior_damage_and_oversize_lengths_refuse_startup() {
    let p = path("interior");
    drop(two_people(&p));
    flip_byte(&p, 10); // inside the first record
    assert_eq!(AccountStore::open(&p, key()).unwrap_err(), StoreError::Open(OpenError::Corrupt { frame: 0 }));
    let q = path("oversize");
    drop(two_people(&q));
    let start = last_frame_start(&q);
    let mut bytes = fs::read(&q).unwrap();
    bytes[start as usize] = 0xff; // a length far over MAX_RECORD
    fs::write(&q, bytes).unwrap();
    assert!(matches!(AccountStore::open(&q, key()), Err(StoreError::Open(OpenError::Corrupt { .. }))));
    let _ = fs::remove_file(&p);
    let _ = fs::remove_file(&q);
}

// ---- keys and secrets ----

#[test]
fn a_wrong_service_key_opens_nothing() {
    let p = path("wrong-key");
    drop(two_people(&p));
    assert_eq!(AccountStore::open(&p, ServiceKey::from_bytes(OTHER_KEY)).unwrap_err(), StoreError::WrongKey);
    let q = path("wrong-key-empty");
    drop(AccountStore::create(&q, key()).unwrap());
    assert_eq!(AccountStore::open(&q, ServiceKey::from_bytes(OTHER_KEY)).unwrap_err(), StoreError::WrongKey);
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
    let sealed = k.seal(SECRET_A, A.as_bytes()).unwrap();
    assert_eq!(&k.open(&sealed, A.as_bytes()).unwrap()[..], SECRET_A);
    assert_eq!(k.open(&sealed, B.as_bytes()).unwrap_err(), SealError::Corrupt);
    assert_eq!(ServiceKey::from_bytes(OTHER_KEY).open(&sealed, A.as_bytes()).unwrap_err(), SealError::WrongKey);
    let mut flipped = sealed.clone();
    flipped.ciphertext[0] ^= 1;
    assert_eq!(k.open(&flipped, A.as_bytes()).unwrap_err(), SealError::Corrupt);
    assert_ne!(k.seal(SECRET_A, A.as_bytes()).unwrap().nonce, sealed.nonce, "a fresh nonce per seal");
}

#[test]
fn secrets_and_tokens_are_not_in_plaintext_on_disk_or_in_debug() {
    let p = path("at-rest");
    let mut s = two_people(&p);
    s.accept_totp(A, 1001).unwrap();
    let token = s.create_session([5; 32], A, 1, T0 + 10).unwrap();
    let bytes = fs::read(&p).unwrap();
    for needle in [SECRET_A, SECRET_B, token.as_bytes()] {
        assert!(!bytes.windows(needle.len()).any(|w| w == needle), "a secret or token is readable in the store file");
    }
    assert!(!s.session_hashes().iter().any(|h| h.contains(&token)));
    for debug in [format!("{s:?}"), format!("{:?}", s.person(A).unwrap())] {
        assert!(!debug.contains("synthetic") && !debug.contains("argon2") && !debug.contains(&token), "{debug}");
    }
    drop(s);
    let _ = fs::remove_file(&p);
}

// ---- TOTP replay ----

#[test]
fn a_totp_counter_is_used_once_including_across_a_restart() {
    let p = path("counter");
    {
        let mut s = two_people(&p);
        assert_eq!(s.accept_totp(A, 1000).unwrap_err(), StoreError::StaleCounter { last: 1000 });
        s.accept_totp(A, 1001).unwrap();
        assert_eq!(s.accept_totp(A, 1001).unwrap_err(), StoreError::StaleCounter { last: 1001 });
        assert_eq!(s.accept_totp(A, 999).unwrap_err(), StoreError::StaleCounter { last: 1001 });
        assert_eq!(s.accept_totp("nobody@example.com", 5).unwrap_err(), StoreError::NoSuchPerson);
    }
    let mut s = reopen(&p);
    assert_eq!(s.accept_totp(A, 1001).unwrap_err(), StoreError::StaleCounter { last: 1001 });
    s.accept_totp(A, 1002).unwrap();
    s.accept_totp(B, 2001).unwrap();
    let _ = fs::remove_file(&p);
}

// ---- revocation ----

#[test]
fn a_revoked_device_stays_revoked_after_a_restart() {
    let p = path("revoked");
    {
        let mut s = two_people(&p);
        assert!(s.revoke_device(A, 1).unwrap());
        assert!(!s.revoke_device(A, 1).unwrap(), "already revoked writes nothing");
        assert_eq!(s.revoke_device(A, 2).unwrap_err(), StoreError::Device(DeviceError::NoSuchDevice), "not A's device");
    }
    let mut s = reopen(&p);
    assert_eq!(s.authenticate(&fp(1), T0 + 10).unwrap_err(), StoreError::Device(DeviceError::Revoked));
    assert_eq!(s.authenticate(&fp(2), T0 + 10).unwrap().id, 2);
    s.issue_invite(invite(A, 1), T0 + 10).unwrap();
    let mut again = another_device(1, 1001);
    again.certificate = cert(42);
    assert_eq!(s.activate(again, T0 + 11).unwrap_err(), StoreError::KeyInUse, "a revoked key never returns");
    let mut same_cert = another_device(1, 1001);
    same_cert.spki_sha256 = [77; 32];
    assert_eq!(s.activate(same_cert, T0 + 11).unwrap_err(), StoreError::Device(DeviceError::Revoked), "nor its certificate");
    let _ = fs::remove_file(&p);
}

#[test]
fn expired_and_revoked_invitations_cannot_activate_after_a_restart() {
    let p = path("invites");
    {
        let mut s = AccountStore::create(&p, key()).unwrap();
        s.issue_invite(invite(A, 1), T0).unwrap();
        s.issue_invite(invite(B, 2), T0).unwrap();
        assert!(s.revoke_invite(&[2; 32]).unwrap());
        assert!(!s.revoke_invite(&[2; 32]).unwrap());
    }
    let mut s = reopen(&p);
    assert_eq!(s.activate(first(1, 1000, SECRET_A), T0 + 3 * DAY).unwrap_err(), StoreError::NoInvite);
    assert_eq!(s.activate(first(2, 1000, SECRET_B), T0 + 1).unwrap_err(), StoreError::NoInvite);
    let _ = fs::remove_file(&p);
}

// ---- sessions ----

#[test]
fn sessions_survive_a_restart_by_token_hash_bound_to_device_and_account() {
    let p = path("sessions");
    let (token_a, token_b) = {
        let mut s = two_people(&p);
        s.accept_totp(A, 1001).unwrap();
        let ta = s.create_session([5; 32], A, 1, T0 + 10).unwrap();
        let tb = s.create_session([6; 32], B, 2, T0 + 10).unwrap();
        assert_eq!(s.create_session([7; 32], A, 2, T0 + 10).unwrap_err(), StoreError::Device(DeviceError::NoSuchDevice), "not A's device");
        assert_eq!(s.create_session([5; 32], A, 1, T0 + 10).unwrap_err(), StoreError::Session, "the same token twice");
        (ta, tb)
    };
    let mut s = reopen(&p);
    let session = s.continue_session(&token_a, &fp(1), T0 + 20).unwrap();
    assert_eq!((session.user.as_str(), session.device.as_str()), (A, "1"));
    assert!(s.continue_session(&token_a, &fp(2), T0 + 20).is_none(), "another device cannot carry A's token");
    assert!(s.continue_session(&token_b, &fp(1), T0 + 20).is_none(), "nor A's device B's token");
    assert!(s.continue_session("forged-token", &fp(1), T0 + 20).is_none());
    assert_eq!(s.session_hashes().len(), 2);
    let _ = fs::remove_file(&p);
}

#[test]
fn revoking_a_device_ends_its_sessions_at_once_and_after_a_restart() {
    let p = path("session-revoke-device");
    let (token_a, token_b) = {
        let mut s = two_people(&p);
        let ta = s.create_session([5; 32], A, 1, T0 + 10).unwrap();
        let tb = s.create_session([6; 32], B, 2, T0 + 10).unwrap();
        assert!(s.continue_session(&ta, &fp(1), T0 + 11).is_some());
        assert!(s.revoke_device(A, 1).unwrap());
        assert!(s.continue_session(&ta, &fp(1), T0 + 12).is_none(), "an existing handle is denied immediately");
        assert_eq!(s.session_hashes().len(), 1, "the revoked device's session is deleted, not just blocked");
        assert_eq!(s.create_session([8; 32], A, 1, T0 + 12).unwrap_err(), StoreError::Device(DeviceError::Revoked));
        (ta, tb)
    };
    let mut s = reopen(&p);
    assert_eq!(s.session_hashes().len(), 1, "and it stays deleted after replay");
    assert!(s.continue_session(&token_a, &fp(1), T0 + 13).is_none());
    assert!(s.continue_session(&token_b, &fp(2), T0 + 13).is_some(), "B is untouched");
    let _ = fs::remove_file(&p);
}

#[test]
fn a_revoked_session_stays_revoked_after_a_restart() {
    let p = path("session-revoke");
    let token = {
        let mut s = two_people(&p);
        let t = s.create_session([5; 32], A, 1, T0 + 10).unwrap();
        assert!(s.revoke_session(&t).unwrap());
        assert!(!s.revoke_session(&t).unwrap(), "already ended writes nothing");
        assert!(s.continue_session(&t, &fp(1), T0 + 11).is_none());
        t
    };
    let mut s = reopen(&p);
    assert!(s.continue_session(&token, &fp(1), T0 + 12).is_none());
    assert!(s.session_hashes().is_empty());
    let _ = fs::remove_file(&p);
}

// ---- replay and codec ----

#[test]
fn replay_is_exact_and_refuses_a_record_that_does_not_apply() {
    let p = path("exact");
    drop(AccountStore::create(&p, key()).unwrap());
    let k = key();
    {
        let (mut journal, _) = AccountJournal::open(&p).unwrap();
        let rogue = AccountOp::Activated {
            bootstrap_pub: [5; 32],
            new_person: Some(NewPerson { password_phc: None, totp: k.seal(SECRET_A, b"x@example.com").unwrap() }),
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
        let mut journal = AccountJournal::create(&p).unwrap();
        journal.append(&encode_account_op(&AccountOp::TotpAccepted { email: A.into(), counter: 1 }).unwrap()).unwrap();
    }
    assert!(matches!(AccountStore::open(&p, key()), Err(StoreError::Corrupt { record: 0, .. })));
    let _ = fs::remove_file(&p);
}

#[test]
fn records_round_trip_and_garbage_is_refused() {
    let k = key();
    let ops = vec![
        AccountOp::Created { format: 1, key_id: k.id() },
        AccountOp::InviteIssued { email: A.into(), bootstrap_pub: [1; 32], expires_ms: 9, now_ms: 3 },
        AccountOp::InviteRevoked { bootstrap_pub: [2; 32] },
        AccountOp::Activated {
            bootstrap_pub: [1; 32],
            new_person: Some(NewPerson { password_phc: Some(PHC.into()), totp: k.seal(SECRET_A, b"a").unwrap() }),
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
        AccountOp::TotpAccepted { email: A.into(), counter: 79 },
        AccountOp::PasswordChanged { email: A.into(), phc: PHC.into() },
        AccountOp::DeviceRevoked { email: A.into(), device_id: 4 },
        AccountOp::SessionCreated { token_sha256: [8; 32], email: A.into(), device_id: 5, created_ms: 11 },
        AccountOp::SessionRevoked { token_sha256: [8; 32] },
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
