//! The handler's copies of the secrets are wiped when they are dropped: the staged TOTP secret, the record handed to the
//! store, and the password waiting for its hash. Wiping a value that the compiler may have copied cannot be proven from
//! outside, so this is best effort and these tests pin the TYPES: a change back to a plain array or `String` stops compiling.

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use common::*;
use crewcraft_bootstrap::{ActivationRecord, CommitFailure, Enroller, Preview, Progress, Services, StoreServices};
use crewcraft_proto::bootstrap::BootstrapResponse;
use zeroize::{ZeroizeOnDrop, Zeroizing};

fn wipes_on_drop<T: ZeroizeOnDrop>(_: &T) {}

/// Services that remember the record the handler handed to the store.
struct Capture {
    inner: StoreServices<MemLog, TestEnv>,
    seen: Vec<ActivationRecord>,
}

impl Services for Capture {
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn new_totp_secret(&mut self) -> Option<[u8; 20]> {
        self.inner.new_totp_secret()
    }
    fn hash_password(&mut self, p: &str) -> Option<String> {
        self.inner.hash_password(p)
    }
    fn preview(&self, k: &[u8; 32], now: u64) -> Option<Preview> {
        self.inner.preview(k, now)
    }
    fn has_person(&self, e: &str) -> bool {
        self.inner.has_person(e)
    }
    fn key_registered(&self, k: &[u8; 32]) -> bool {
        self.inner.key_registered(k)
    }
    fn activate(&mut self, record: &ActivationRecord, now: u64) -> Result<u64, CommitFailure> {
        self.seen.push(record.clone());
        self.inner.activate(record, now)
    }
}

#[test]
fn the_record_given_to_the_store_wipes_its_totp_secret_on_drop_and_still_carries_the_right_one() {
    let (w, _log) = world();
    let (key, secret) = (w.key, w.secret);
    let (authority, services) = w.enroller.into_parts();
    let mut enroller = Enroller::new(authority, Capture { inner: services, seen: Vec::new() });
    let mut conn = crewcraft_bootstrap::BootstrapConnection::new(key, SOURCE);
    let (_k, csr) = device_csr();
    conn.receive(&mut enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    let code = code_at(secret, enroller.services().now_ms());
    let out = conn.receive(&mut enroller, &confirm_frame(2, &code));
    assert!(matches!(replies(&out.bytes)[0].1, BootstrapResponse::Activated { .. }));

    let record = &enroller.services().seen[0];
    wipes_on_drop(&record.totp_secret);
    let kept: &Zeroizing<[u8; 20]> = &record.totp_secret;
    assert_eq!(**kept, secret, "the secret the store seals is the one the person scanned");
    // Debug never shows it.
    assert!(!format!("{record:?}").contains(&format!("{secret:?}")));
}

#[test]
fn the_password_waiting_for_its_hash_is_held_in_a_wiping_buffer_and_never_printed() {
    let (mut w, _log) = world();
    let mut conn = connection(&w);
    let (_k, csr) = device_csr();
    let Progress::NeedsHash { job, .. } = conn.receive_step(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD)) else {
        panic!("no hash job")
    };
    assert_eq!(job.password(), PASSWORD);
    assert!(!format!("{job:?}").contains(PASSWORD), "the job must not print the password");
    drop(job);
}
