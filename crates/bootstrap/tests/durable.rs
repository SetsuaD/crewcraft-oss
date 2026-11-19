//! Restart: the account state is on disk, so a new process reads back exactly what was committed, and admission after a
//! restart is answered from that store alone (no certificate-authority ledger, no memory of the old process). Real journal
//! files under the temp directory, synthetic values only.

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use common::*;
use crewcraft_admission::Admission;
use crewcraft_bootstrap::{BootstrapConnection, DurableAdmission, ERR_UNAVAILABLE, Enroller, Services, StoreServices};
use crewcraft_pki::{Claims, key_id_of_certificate};
use crewcraft_proto::bootstrap::BootstrapResponse;
use crewcraft_server_core::account_journal::{AccountJournal, AppendError};
use crewcraft_server_core::account_store::{AccountStore, AppendLog};

fn path(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("crewcraft-bootstrap-{name}-{}.journal", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

fn open(p: &Path) -> AccountStore<AccountJournal> {
    AccountStore::open(p, service_key()).unwrap()
}

fn create(p: &Path) -> AccountStore<AccountJournal> {
    AccountStore::create(p, service_key()).unwrap()
}

fn only(out: &crewcraft_bootstrap::Output) -> BootstrapResponse {
    let mut all = replies(&out.bytes);
    assert_eq!(all.len(), 1, "expected exactly one reply, got {all:?}");
    all.remove(0).1
}

/// Enroll the first device over the real journal at `p`; returns the world (still open) and what the device received.
fn enrolled(p: &Path) -> (World<AccountJournal>, Vec<u8>, Vec<u8>, rcgen::KeyPair) {
    let mut w = world_over(create(p), parts(), real_now_ms(), true);
    let mut conn = connection(&w);
    let (key, csr) = device_csr();
    assert!(matches!(only(&conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD))), BootstrapResponse::Setup { .. }));
    let code = w.code_for(w.secret);
    let out = conn.receive(&mut w.enroller, &confirm_frame(2, &code));
    let BootstrapResponse::Activated { certificate, issuer_certificate } = only(&out) else { panic!("not Activated") };
    (w, certificate, issuer_certificate, key)
}

/// A new process: reopen the journal, keep the authority (its reload is a separate piece of work) and the clock.
fn reopen(w: World<AccountJournal>, p: &Path) -> World<AccountJournal> {
    let (authority, services) = w.enroller.into_parts();
    let (store, env) = services.into_parts();
    drop(store);
    let services = StoreServices::new(open(p), env);
    World { enroller: Enroller::new(authority, services), bootstrap_key: w.bootstrap_key, key: w.key, root_cert: w.root_cert, secret: w.secret }
}

type Shared = Arc<Mutex<Enroller<StoreServices<AccountJournal, TestEnv>>>>;

/// Admission over the SAME durable writer the enroller holds (it never takes the enroller lock), and the enroller itself.
fn admission(w: World<AccountJournal>) -> (DurableAdmission<AccountJournal>, Shared) {
    let admit = admission_of(&w);
    (admit, Arc::new(Mutex::new(w.enroller)))
}

fn admission_of<L: AppendLog + Send + 'static>(w: &World<L>) -> DurableAdmission<L> {
    DurableAdmission::new(w.enroller.services().shared(), Arc::new(real_now_ms), w.enroller.poison_flag())
}

#[test]
fn an_activation_survives_a_restart_and_admission_answers_from_the_reloaded_store() {
    let p = path("restart");
    let (w, certificate, _issuer, _key) = enrolled(&p);
    let (secret, key) = (w.secret, w.key);
    let mut w = reopen(w, &p);

    // Everything the activation wrote is back, exactly. (The guard lives in this block only.)
    let now = w.now();
    let last_counter = {
        let s = w.enroller.services().store();
        let person = s.person(EMAIL).unwrap();
        assert!(person.password_phc.as_deref().is_some_and(|phc| phc.starts_with("$argon2id$")));
        assert_eq!(&s.totp_secret(EMAIL).unwrap()[..], &secret[..]);
        assert_eq!(s.device_certificate(1).unwrap(), certificate.as_slice());
        assert_eq!(s.device_by_key(&key_id_of_certificate(&certificate).unwrap()), Some(1));
        assert!(!s.is_invite_pending(&key, now), "the consumed invitation stays consumed");
        person.last_totp_counter
    };
    assert!(w.enroller.services_mut().store_mut().accept_totp(EMAIL, last_counter).is_err(), "the setup code is spent across the restart");

    // Admission, from the store alone: the exact issued leaf is admitted; nothing else is.
    let other_leaf = {
        // Same key, a different certificate (another serial): not the active leaf, so not admitted.
        let (_k, csr) = device_csr();
        w.enroller.authority().prepare_device(&csr, &Claims { person: EMAIL, device_id: 1 }, w.now()).unwrap().certificate
    };
    let (admit, _shared) = admission(w);
    assert!(admit.device_ok(&certificate), "the issued leaf is admitted after a restart");
    assert!(!admit.device_ok(&other_leaf), "a certificate the store never recorded is not admitted");
    assert!(!admit.device_ok(b"not a certificate"));
    assert!(!admit.bootstrap_key_live(&key), "a consumed invitation is not live after a restart");
}

#[test]
fn only_the_exact_active_leaf_of_a_key_is_admitted() {
    let p = path("exact");
    let (w, certificate, _issuer, key) = enrolled(&p);
    let w = reopen(w, &p);
    // A renewal-shaped certificate for the SAME key: same SPKI, different bytes. It is not the leaf the store holds.
    let csr = csr_for(&key);
    let renewed = w.enroller.authority().prepare_device(&csr, &Claims { person: EMAIL, device_id: 1 }, w.now()).unwrap().certificate;
    assert_ne!(renewed, certificate);
    assert_eq!(key_id_of_certificate(&renewed).unwrap(), key_id_of_certificate(&certificate).unwrap());
    let (admit, _shared) = admission(w);
    assert!(admit.device_ok(&certificate));
    assert!(!admit.device_ok(&renewed), "same key, different leaf: not the exact active leaf");
}

#[test]
fn a_revoked_device_stays_revoked_after_a_restart_and_its_key_stays_taken() {
    let p = path("revoked");
    let (mut w, certificate, _issuer, key) = enrolled(&p);
    assert!(w.enroller.services_mut().store_mut().revoke_device(EMAIL, 1).unwrap());
    let w = reopen(w, &p);
    let spki = key_id_of_certificate(&certificate).unwrap();
    assert!(w.enroller.services().key_registered(&spki), "a revoked key stays registered for good");
    let (admit, shared) = admission(w);
    assert!(!admit.device_ok(&certificate), "revoked before the restart, refused after it");

    // And that key cannot be used to enroll again under a new invitation.
    let now = shared.lock().unwrap().services().now_ms();
    let again = [0x66u8; 32];
    {
        let mut e = shared.lock().unwrap();
        e.services_mut()
            .store_mut()
            .issue_invite(
                crewcraft_server_core::invites::Invite { email: "bob@example.org".into(), bootstrap_pub: again, expires_ms: now + HOUR },
                now,
            )
            .unwrap();
        e.services_mut().env_mut().secrets.push_back([0x55u8; 20]);
    }
    let mut conn = BootstrapConnection::new(again, "192.0.2.50");
    let out = conn.receive(&mut shared.lock().unwrap(), &redeem_frame(1, "laptop", &csr_for(&key), PASSWORD));
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_UNAVAILABLE });
}

#[test]
fn a_consumed_invitation_cannot_be_used_again_after_a_restart() {
    let p = path("consumed");
    let (w, _certificate, _issuer, _key) = enrolled(&p);
    let mut w = reopen(w, &p);
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    let out = conn.receive(&mut w.enroller, &redeem_frame(1, "phone", &csr, PASSWORD));
    assert!(out.bytes.is_empty() && !out.open, "the consumed invitation gets no reply");
}

#[test]
fn an_unfinished_enrollment_is_forgotten_by_a_restart_and_the_invitation_works_again() {
    let p = path("unfinished");
    let mut w = world_over(create(&p), parts(), real_now_ms(), true);
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    assert!(matches!(only(&conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD))), BootstrapResponse::Setup { .. }));
    assert_eq!(w.enroller.staged_count(), 1);
    let mut w = reopen(w, &p);
    assert_eq!(w.enroller.staged_count(), 0, "a staged setup lives only in memory");
    assert!(w.enroller.services().store().is_invite_pending(&w.key, w.now()), "the invitation is still live");
    // The person redoes the setup on a new connection (a new secret) and finishes.
    w.enroller.services_mut().env_mut().secrets.push_back([0x61u8; 20]);
    w.advance(2000);
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    assert!(matches!(only(&conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD))), BootstrapResponse::Setup { .. }));
    let code = w.code_for([0x61u8; 20]);
    assert!(matches!(only(&conn.receive(&mut w.enroller, &confirm_frame(2, &code))), BootstrapResponse::Activated { .. }));
}

#[test]
fn a_failed_save_leaves_nothing_after_a_restart_and_the_enrollment_can_start_again() {
    let (mut w, log) = world();
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    assert!(matches!(only(&conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD))), BootstrapResponse::Setup { .. }));
    log.fail_next(AppendError::Ambiguous(ErrorKind::Other));
    let code = w.code_for(w.secret);
    let out = conn.receive(&mut w.enroller, &confirm_frame(2, &code));
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_UNAVAILABLE });
    assert!(w.enroller.is_poisoned());

    let (mut w, _log) = restart(w, &log);
    assert!(!w.enroller.is_poisoned(), "a rebuilt enroller starts clean");
    assert!(w.enroller.services().store().person(EMAIL).is_none(), "nothing was saved");
    assert!(w.enroller.services().store().is_invite_pending(&w.key, w.now()));
    w.enroller.services_mut().env_mut().secrets.push_back([0x62u8; 20]);
    w.advance(2000);
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    let code = w.code_for([0x62u8; 20]);
    assert!(matches!(only(&conn.receive(&mut w.enroller, &confirm_frame(2, &code))), BootstrapResponse::Activated { .. }));
}

/// A log whose next append writes the record and THEN reports a failure: the case a failed sync can produce.
#[derive(Clone)]
struct LyingLog {
    log: MemLog,
    lie_next: Arc<AtomicBool>,
}

impl AppendLog for LyingLog {
    fn append(&mut self, record: &[u8]) -> Result<(), AppendError> {
        self.log.append(record)?;
        if self.lie_next.swap(false, Ordering::SeqCst) {
            return Err(AppendError::Ambiguous(ErrorKind::Other));
        }
        Ok(())
    }
}

#[test]
fn the_documented_recovery_when_a_save_may_have_succeeded_without_the_client_knowing() {
    let log = MemLog::default();
    let lie = Arc::new(AtomicBool::new(false));
    let lying = LyingLog { log: log.clone(), lie_next: lie.clone() };
    let created = created_record();
    log.0.lock().unwrap().records.push(created.clone());
    let store = AccountStore::from_records(lying, service_key(), vec![created]).unwrap();
    let mut w = world_over(store, parts(), real_now_ms(), true);
    let mut conn = connection(&w);
    let (device_key, csr) = device_csr();
    conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    lie.store(true, Ordering::SeqCst);
    let code = w.code_for(w.secret);
    let out = conn.receive(&mut w.enroller, &confirm_frame(2, &code));

    // The client was told it failed and got no certificate, and the enroller refuses everything from now on.
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_UNAVAILABLE });
    assert!(w.enroller.is_poisoned());
    let mut retry = connection(&w);
    let again = retry.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    assert!(again.bytes.is_empty() && !again.open, "a retry while poisoned gets nothing");

    // But the record DID reach the log. After a restart the activation is there: the invitation is consumed, the device is
    // registered under its key, and nobody holds its leaf.
    let records = log.records();
    let reopened = AccountStore::from_records(MemLog::with_records(records.clone()), service_key(), records).unwrap();
    assert!(reopened.person(EMAIL).is_some());
    assert!(!reopened.is_invite_pending(&w.key, w.now()), "so a retry on a new connection cannot be admitted");
    let leaf = reopened.device_certificate(1).unwrap().to_vec();
    let spki = key_id_of_certificate(&leaf).unwrap();
    assert_eq!(reopened.device_by_key(&spki), Some(1));

    // The recovery: an administrator revokes that device and issues a new invitation, and the person makes a NEW device
    // key. The old key can never enroll again, so reusing it is refused outright.
    let mut admin = reopened;
    assert!(admin.revoke_device(EMAIL, 1).unwrap());
    let now = w.now();
    let new_invite = [0x71u8; 32];
    admin
        .issue_invite(
            crewcraft_server_core::invites::Invite { email: "alice-again@example.org".into(), bootstrap_pub: new_invite, expires_ms: now + HOUR },
            now,
        )
        .unwrap();
    let services = StoreServices::new(admin, env_at(now, &[[0x72u8; 20]]));
    let (authority, _old) = w.enroller.into_parts();
    let mut fresh = Enroller::new(authority, services);
    let mut conn = BootstrapConnection::new(new_invite, "192.0.2.60");
    let reuse = conn.receive(&mut fresh, &redeem_frame(1, "laptop", &csr_for(&device_key), PASSWORD));
    assert_eq!(only(&reuse), BootstrapResponse::Error { code: ERR_UNAVAILABLE }, "the old device key cannot be reused");
}

#[test]
fn a_poisoned_enroller_admits_no_bootstrap_peer() {
    let (mut w, log) = world();
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    log.fail_next(AppendError::Ambiguous(ErrorKind::Other));
    let code = w.code_for(w.secret);
    conn.receive(&mut w.enroller, &confirm_frame(2, &code));
    assert!(w.enroller.is_poisoned());
    let key = w.key;
    // The store poisoned itself too: it reports no invitation as pending, and the enroller refuses on its own account.
    assert!(!w.enroller.services().store().healthy());
    assert!(!w.enroller.services().store().is_invite_pending(&key, w.now()));
    let admit = admission_of(&w);
    assert!(!admit.bootstrap_key_live(&key), "a poisoned enroller must not admit a bootstrap peer");
}

/// Alice's device and Bob's device, both enrolled over the same journal; returns the open world and both leaves.
fn two_devices(p: &Path) -> (World<AccountJournal>, Vec<u8>, Vec<u8>) {
    let (mut w, alice_leaf, _issuer, _key) = enrolled(p);
    let now = w.now() + 5000;
    let bob_boot = [0x71u8; 32];
    w.enroller
        .services_mut()
        .store_mut()
        .issue_invite(
            crewcraft_server_core::invites::Invite { email: "bob@example.org".into(), bootstrap_pub: bob_boot, expires_ms: now + HOUR },
            now,
        )
        .unwrap();
    let bob_secret = [0x72u8; 20];
    w.enroller.services_mut().env_mut().secrets.push_back(bob_secret);
    w.enroller.services_mut().env_mut().clock_ms = now;
    let mut conn = BootstrapConnection::new(bob_boot, "192.0.2.99");
    let (_bk, bob_csr) = device_csr();
    assert!(matches!(only(&conn.receive(&mut w.enroller, &redeem_frame(1, "phone", &bob_csr, PASSWORD))), BootstrapResponse::Setup { .. }));
    let code = code_at(bob_secret, now);
    let BootstrapResponse::Activated { certificate: bob_leaf, .. } = only(&conn.receive(&mut w.enroller, &confirm_frame(2, &code))) else {
        panic!("not Activated")
    };
    assert!(contains(&bob_leaf, b"device-2"));
    (w, alice_leaf, bob_leaf)
}

#[test]
fn several_devices_are_each_admitted_by_their_own_leaf_after_a_restart() {
    let p = path("two-devices");
    let (w, alice_leaf, bob_leaf) = two_devices(&p);
    let (admit, _shared) = admission(reopen(w, &p));
    assert!(admit.device_ok(&alice_leaf), "the first device is admitted by its own leaf");
    assert!(admit.device_ok(&bob_leaf), "the second device is admitted by its own leaf");
}

#[test]
fn revoking_one_device_after_a_restart_leaves_the_others_admitted() {
    let p = path("two-devices-revoked");
    let (w, alice_leaf, bob_leaf) = two_devices(&p);
    let mut w = reopen(w, &p);
    assert!(w.enroller.services_mut().store_mut().revoke_device("bob@example.org", 2).unwrap());
    let (admit, _shared) = admission(reopen(w, &p));
    assert!(admit.device_ok(&alice_leaf), "the first device is still admitted");
    assert!(!admit.device_ok(&bob_leaf), "the second device was revoked, and only it");
}

#[test]
fn a_poisoned_store_admits_no_device_either() {
    let (mut w, log) = world();
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    let code = w.code_for(w.secret);
    let BootstrapResponse::Activated { certificate, .. } = only(&conn.receive(&mut w.enroller, &confirm_frame(2, &code))) else {
        panic!("not Activated")
    };
    let admit = admission_of(&w);
    assert!(admit.device_ok(&certificate), "an enrolled device is admitted while the store is healthy");

    // A later write fails ambiguously, which poisons the whole store.
    let now = w.now();
    w.enroller
        .services_mut()
        .store_mut()
        .issue_invite(
            crewcraft_server_core::invites::Invite { email: "bob@example.org".into(), bootstrap_pub: [0x71; 32], expires_ms: now + HOUR },
            now,
        )
        .unwrap();
    log.fail_next(AppendError::Ambiguous(ErrorKind::Other));
    let _ = w.enroller.services_mut().store_mut().revoke_invite(&[0x71; 32]);
    assert!(!w.enroller.services().store().healthy());
    assert!(!admit.device_ok(&certificate), "nothing is trusted once an earlier write has an unknown outcome");
}

#[test]
fn enrollment_and_admission_share_one_writer_without_taking_each_others_locks() {
    let (mut w, _log) = world();
    let admit = admission_of(&w);
    let store = w.enroller.services().shared();
    // Admission and a direct holder of the store (the sign-in path) see the enroller's writes at once, and the enroller
    // lock is not needed to ask: hold the enroller mutably while admission answers.
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    assert!(admit.bootstrap_key_live(&w.key));
    let code = w.code_for(w.secret);
    let BootstrapResponse::Activated { certificate, .. } = only(&conn.receive(&mut w.enroller, &confirm_frame(2, &code))) else {
        panic!("not Activated")
    };
    assert!(!admit.bootstrap_key_live(&w.key), "consumed by the enroller, seen through the shared store");
    assert!(admit.device_ok(&certificate));
    // The sign-in path signs the device in through the same store, and the enroller sees the new counter.
    let counter = store.lock().unwrap().person(EMAIL).unwrap().last_totp_counter + 1;
    let token = store.lock().unwrap().sign_in([9u8; 32], EMAIL, 1, counter, w.now()).unwrap();
    assert!(!token.is_empty());
    assert_eq!(w.enroller.services().store().person(EMAIL).unwrap().last_totp_counter, counter);
}

#[test]
fn the_enroller_poison_flag_stops_bootstrap_admission_even_when_the_store_is_healthy() {
    let (w, _log) = world();
    let admit = admission_of(&w);
    assert!(admit.bootstrap_key_live(&w.key), "a healthy enroller and a pending invitation: live");
    // The enroller poisons itself for a reason the store cannot see; admission reads the shared flag, not the enroller.
    w.enroller.poison_flag().store(true, Ordering::SeqCst);
    assert!(w.enroller.services().store().healthy() && w.enroller.services().store().is_invite_pending(&w.key, w.now()));
    assert!(!admit.bootstrap_key_live(&w.key), "a poisoned enroller admits no bootstrap peer");
}

#[test]
fn a_mutex_poisoned_by_a_panic_fails_closed_everywhere() {
    let (mut w, _log) = world();
    let admit = admission_of(&w);
    let store = w.enroller.services().shared();
    // Another thread panics while holding the account lock.
    let holder = store.clone();
    let _ = std::thread::spawn(move || {
        let _guard = holder.lock().unwrap();
        panic!("a thread died holding the account lock");
    })
    .join();
    assert!(store.is_poisoned());

    // Nothing is trusted: the questions that gate enrollment answer so that nothing new is staged...
    assert!(w.enroller.services().has_person("nobody@example.org"), "an unreadable store must look like an existing person");
    assert!(w.enroller.services().key_registered(&[9u8; 32]), "an unreadable store must look like a registered key");
    assert!(w.enroller.services().preview(&w.key, w.now()).is_none());
    // ...a Redeem gets no reply, and admission refuses both kinds of peer.
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    let out = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    assert!(out.bytes.is_empty() && !out.open);
    assert!(!admit.bootstrap_key_live(&w.key));
    assert!(!admit.device_ok(b"anything"));
}
