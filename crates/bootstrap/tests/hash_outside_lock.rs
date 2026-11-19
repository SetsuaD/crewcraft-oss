//! The password hash runs with NO lock held: `receive_step` stops at the hash after the limits and the staging, the caller
//! hashes, and `finish_hash` resumes. The throttle-before-hash order of the one-call `receive` is preserved exactly.

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::sync::{Arc, Mutex};

use common::*;
use crewcraft_accounts::password;
use crewcraft_bootstrap::{BootstrapConnection, ERR_RATE_LIMITED, ERR_UNAVAILABLE, Enroller, Output, Progress, StoreServices, receive_shared};
use crewcraft_proto::bootstrap::BootstrapResponse;
use crewcraft_server_core::activation::SOURCE_BURST;

fn only(out: &Output) -> BootstrapResponse {
    let mut all = replies(&out.bytes);
    assert_eq!(all.len(), 1, "expected exactly one reply, got {all:?}");
    all.remove(0).1
}

fn hash(p: &str) -> Option<String> {
    password::hash(p).ok()
}

fn expect_job(progress: Progress) -> (Vec<u8>, crewcraft_bootstrap::HashJob) {
    match progress {
        Progress::NeedsHash { bytes, job } => (bytes, job),
        Progress::Done(out) => panic!("expected NeedsHash, got Done({out:?})"),
    }
}

fn expect_done(progress: Progress) -> Output {
    match progress {
        Progress::Done(out) => out,
        Progress::NeedsHash { .. } => panic!("expected Done, got NeedsHash"),
    }
}

#[test]
fn redeem_stops_at_the_hash_after_the_limits_and_nothing_is_hashed_by_the_handler() {
    let (mut w, log) = world();
    let before = log.len();
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    let (early, job) = expect_job(conn.receive_step(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD)));
    assert!(early.is_empty(), "no Setup before the hash exists");
    assert_eq!(job.password(), PASSWORD);
    assert_eq!(w.enroller.services().env().hash_calls, 0, "the handler did not hash");
    assert_eq!(w.enroller.staged_count(), 1, "the limits were taken and the setup staged");
    assert_eq!(log.len(), before);

    // The caller hashes with no lock, and resumes.
    let phc = hash(job.password());
    let out = expect_done(conn.finish_hash(&mut w.enroller, job, phc.clone()));
    assert!(out.open);
    assert!(matches!(only(&out), BootstrapResponse::Setup { .. }));

    // The PHC that was supplied is the one that is committed.
    let code = w.code_for(w.secret);
    let out = conn.receive(&mut w.enroller, &confirm_frame(2, &code));
    assert!(matches!(only(&out), BootstrapResponse::Activated { .. }));
    let stored = w.enroller.services().store().person(EMAIL).unwrap().password_phc;
    assert_eq!(stored, phc, "the supplied hash is what the store holds");
}

#[test]
fn a_rate_limited_redeem_never_asks_for_a_hash() {
    let (mut w, _log) = world();
    let (_k, csr) = device_csr();
    for n in 0..SOURCE_BURST {
        w.enroller.services_mut().env_mut().secrets.push_back([n as u8 + 1; 20]);
        let mut conn = connection(&w);
        let (_early, job) = expect_job(conn.receive_step(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD)));
        let phc = hash(job.password());
        assert!(matches!(only(&expect_done(conn.finish_hash(&mut w.enroller, job, phc))), BootstrapResponse::Setup { .. }));
    }
    w.enroller.services_mut().env_mut().secrets.push_back([0x77u8; 20]);
    let mut conn = connection(&w);
    let out = expect_done(conn.receive_step(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD)));
    assert!(!out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_RATE_LIMITED }, "limited before any hash was requested");
}

#[test]
fn an_enroller_poisoned_while_the_lock_was_released_closes_the_connection_instead_of_answering() {
    let (mut w, _log) = world();
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    let (_early, job) = expect_job(conn.receive_step(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD)));
    // Meanwhile (no lock held) another connection's commit failed ambiguously.
    w.enroller.poison_flag().store(true, std::sync::atomic::Ordering::SeqCst);
    let phc = hash(job.password());
    let out = expect_done(conn.finish_hash(&mut w.enroller, job, phc));
    assert!(out.bytes.is_empty() && !out.open, "no Setup after the enroller was poisoned");
}

#[test]
fn a_failed_hash_answers_an_error_and_closes() {
    let (mut w, _log) = world();
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    let (_early, job) = expect_job(conn.receive_step(&mut w.enroller, &redeem_frame(7, "laptop", &csr, PASSWORD)));
    let out = expect_done(conn.finish_hash(&mut w.enroller, job, None));
    assert!(!out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_UNAVAILABLE });
    assert_eq!(replies(&out.bytes)[0].0, 7, "the error repeats the Redeem's id");
}

#[test]
fn frames_that_arrive_while_the_hash_is_pending_wait_and_are_handled_on_resume() {
    let (mut w, _log) = world();
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    // A Redeem and a wrong-code Confirm in one chunk: the Confirm must not run before Setup exists.
    let mut chunk = redeem_frame(1, "laptop", &csr, PASSWORD);
    chunk.extend(confirm_frame(2, "000000"));
    let (early, job) = expect_job(conn.receive_step(&mut w.enroller, &chunk));
    assert!(early.is_empty());
    // More bytes while waiting are buffered, not processed, and not answered.
    let waiting = expect_done(conn.receive_step(&mut w.enroller, &confirm_frame(3, "111111")));
    assert!(waiting.bytes.is_empty() && waiting.open);
    let phc = hash(job.password());
    let out = expect_done(conn.finish_hash(&mut w.enroller, job, phc));
    // Setup first, then the two buffered Confirms in order, each a wrong code, connection still open.
    let all = replies(&out.bytes);
    assert_eq!(all.len(), 3, "{all:?}");
    assert!(matches!(all[0].1, BootstrapResponse::Setup { .. }));
    assert_eq!((all[1].0, all[2].0), (2, 3));
    assert!(out.open);
}

#[test]
fn garbage_behind_a_pending_redeem_closes_after_the_setup_is_sent() {
    let (mut w, _log) = world();
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    let mut chunk = redeem_frame(1, "laptop", &csr, PASSWORD);
    chunk.extend(crewcraft_proto::frame::encode(&[1u8, 0, 0, 0, 1]).unwrap());
    let (_early, job) = expect_job(conn.receive_step(&mut w.enroller, &chunk));
    let phc = hash(job.password());
    let out = expect_done(conn.finish_hash(&mut w.enroller, job, phc));
    assert!(matches!(only(&out), BootstrapResponse::Setup { .. }));
    assert!(!out.open, "the bad frame behind it ends the connection");
}

#[test]
fn receive_shared_holds_no_lock_while_the_password_is_hashed() {
    let (w, log) = world();
    let key = w.key;
    let secret = w.secret;
    let clock = w.now();
    let store = w.enroller.services().shared();
    let enroller: Arc<Mutex<Enroller<StoreServices<MemLog, TestEnv>>>> = Arc::new(Mutex::new(w.enroller));
    let mut conn = BootstrapConnection::new(key, SOURCE);
    let (_k, csr) = device_csr();

    let hashed = std::sync::atomic::AtomicUsize::new(0);
    let hasher = |p: &str| {
        hashed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // The enroller and the account store are BOTH free while the password is hashed.
        assert!(enroller.try_lock().is_ok(), "the enroller lock was held across the hash");
        assert!(store.try_lock().is_ok(), "the account store lock was held across the hash");
        hash(p)
    };

    let out = receive_shared(&mut conn, &enroller, &hasher, &redeem_frame(1, "laptop", &csr, PASSWORD));
    assert!(matches!(only(&out), BootstrapResponse::Setup { .. }));
    assert_eq!(hashed.load(std::sync::atomic::Ordering::SeqCst), 1);

    // And the whole enrollment completes through the same loop.
    let before = log.len();
    let code = code_at(secret, clock);
    let out = receive_shared(&mut conn, &enroller, &hasher, &confirm_frame(2, &code));
    assert!(matches!(only(&out), BootstrapResponse::Activated { .. }));
    assert_eq!(log.len(), before + 1);
    assert_eq!(hashed.load(std::sync::atomic::Ordering::SeqCst), 1, "Confirm hashes nothing");
}

#[test]
fn receive_shared_closes_for_a_mutex_poisoned_by_a_panic() {
    let (w, _log) = world();
    let key = w.key;
    let enroller = Arc::new(Mutex::new(w.enroller));
    let holder = enroller.clone();
    let _ = std::thread::spawn(move || {
        let _guard = holder.lock().unwrap();
        panic!("a thread died holding the enroller lock");
    })
    .join();
    let mut conn = BootstrapConnection::new(key, SOURCE);
    let (_k, csr) = device_csr();
    let out = receive_shared(&mut conn, &enroller, &hash, &redeem_frame(1, "laptop", &csr, PASSWORD));
    assert!(out.bytes.is_empty() && !out.open);
}
