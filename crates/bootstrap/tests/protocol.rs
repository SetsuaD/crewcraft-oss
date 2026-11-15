//! The bootstrap handler against the REAL durable account store (over an in-memory append log, so a write can be made to
//! fail): what Redeem and ConfirmTotp release, when, and what closes the connection without a byte. The restart tests
//! with a journal file are in `durable.rs`.

#![allow(clippy::unwrap_used)]

mod common;

use std::io::ErrorKind;

use common::*;
use crewcraft_bootstrap::{
    BootstrapConnection, CommitFailure, ERR_BAD_CODE, ERR_BAD_REQUEST, ERR_PASSWORD, ERR_RATE_LIMITED, ERR_UNAVAILABLE, Enroller, Output, Services,
    StoreServices, classify,
};
use crewcraft_pki::{key_id_of_certificate, serial_of_certificate};
use crewcraft_proto::bootstrap::BootstrapResponse;
use crewcraft_server_core::account_journal::AppendError;
use crewcraft_server_core::account_store::{Activation, AppendLog, FirstDevice, StoreError, fingerprint};
use crewcraft_server_core::activation::{ISSUER, MAX_WRONG_CODES, SOURCE_BURST};
use crewcraft_server_core::invites::Invite;
use rcgen::{KeyPair, PKCS_ED25519};

fn only(out: &Output) -> BootstrapResponse {
    let mut all = replies(&out.bytes);
    assert_eq!(all.len(), 1, "expected exactly one reply, got {all:?}");
    all.remove(0).1
}

fn assert_closed_silently(out: &Output) {
    assert!(out.bytes.is_empty(), "a closing connection wrote {:?}", out.bytes);
    assert!(!out.open);
}

/// A connection that has redeemed and received Setup, ready to confirm.
fn staged() -> (World<MemLog>, MemLog, BootstrapConnection, KeyPair, Vec<u8>) {
    let (mut w, log) = world();
    let mut conn = connection(&w);
    let (key, csr) = device_csr();
    let out = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    assert!(out.open && matches!(only(&out), BootstrapResponse::Setup { .. }));
    (w, log, conn, key, csr)
}

/// The account store, locked. Hold the guard for one statement: two guards at once would deadlock.
fn store<L: AppendLog>(w: &World<L>) -> std::sync::MutexGuard<'_, crewcraft_server_core::account_store::AccountStore<L>> {
    w.enroller.services().store()
}

fn confirm<L: AppendLog>(w: &mut World<L>, conn: &mut BootstrapConnection, id: u32, secret: [u8; 20]) -> Output {
    let code = w.code_for(secret);
    conn.receive(&mut w.enroller, &confirm_frame(id, &code))
}

#[test]
fn redeem_answers_setup_with_the_authenticator_uri_and_nothing_durable() {
    let (mut w, log) = world();
    let before = log.len();
    let mut conn = connection(&w);
    let (_key, csr) = device_csr();
    let out = conn.receive(&mut w.enroller, &redeem_frame(7, "laptop", &csr, PASSWORD));
    assert!(out.open);
    let all = replies(&out.bytes);
    assert_eq!((all.len(), all[0].0), (1, 7), "one reply that repeats the request id");
    let BootstrapResponse::Setup { totp_uri } = &all[0].1 else { panic!("not Setup: {:?}", all[0].1) };
    // Setup carries exactly the authenticator enrollment for the server-drawn secret, and not one byte more.
    let expected = crewcraft_totp::Totp::with_defaults(w.secret.to_vec()).unwrap().otpauth_uri(ISSUER, EMAIL);
    assert_eq!(totp_uri, &expected);
    assert!(out.bytes.len() < 400, "a Setup reply of {} bytes", out.bytes.len());
    assert!(!contains(&out.bytes, w.enroller.authority().certificate()));
    // Nothing is durable yet: not a record, not a person, not a device, and the invitation is still live.
    assert_eq!(log.len(), before, "Redeem must not append");
    assert!(store(&w).person(EMAIL).is_none());
    assert!(store(&w).is_invite_pending(&w.key, w.now()));
    assert_eq!(w.enroller.staged_count(), 1);
}

#[test]
fn confirm_commits_one_record_then_releases_the_chain() {
    let (mut w, log, mut conn, key, csr) = staged();
    let before = log.len();
    let secret = w.secret;
    let out = confirm(&mut w, &mut conn, 2, secret);
    assert!(!out.open, "the connection closes after Activated");
    let BootstrapResponse::Activated { certificate, issuer_certificate } = only(&out) else { panic!("not Activated") };

    // ONE durable record carries the whole activation.
    assert_eq!(log.len(), before + 1, "invitation, person, device, leaf and counter are one record");
    assert_eq!(issuer_certificate, w.enroller.authority().certificate());

    // The store holds exactly what was sent, under the stable key identity and the allocated device id.
    let spki = key_id_of_certificate(&certificate).unwrap();
    assert_eq!(spki, crewcraft_pki::csr_key_id(&csr).unwrap());
    let s = store(&w);
    assert_eq!(s.device_by_key(&spki), Some(1));
    assert_eq!(s.device_certificate(1).unwrap(), certificate.as_slice());
    assert!(contains(&certificate, b"device-1"), "the certificate subject carries the allocated device id");
    let devices = s.devices_of(EMAIL);
    assert_eq!((devices.len(), devices[0].id, devices[0].fingerprint), (1, 1, fingerprint(&certificate)));
    let person = s.person(EMAIL).unwrap();
    assert!(person.password_phc.as_deref().is_some_and(|p| p.starts_with("$argon2id$") && !p.contains(PASSWORD)));
    assert_eq!(&s.totp_secret(EMAIL).unwrap()[..], &secret[..], "the sealed secret opens to the one in Setup");
    assert!(!s.is_invite_pending(&w.key, w.now()), "the invitation is used up");
    assert_ne!(serial_of_certificate(&certificate).unwrap(), 1u64.to_be_bytes(), "ordinal and serial are different things");
    let _ = key;
}

#[test]
fn the_setup_code_is_spent_and_the_next_sign_in_needs_a_later_step() {
    let (mut w, _log, mut conn, _key, _csr) = staged();
    let secret = w.secret;
    assert!(matches!(only(&confirm(&mut w, &mut conn, 2, secret)), BootstrapResponse::Activated { .. }));
    let counter = w.now() / 1000 / 30;
    let last = store(&w).person(EMAIL).unwrap().last_totp_counter;
    assert!((counter.saturating_sub(1)..=counter + 1).contains(&last), "the accepted counter {last} is the confirmation code's");
    // The same counter cannot be used again, an older one cannot, a later one can.
    let mut s = w.enroller.services_mut().store_mut();
    assert!(matches!(s.accept_totp(EMAIL, last), Err(StoreError::StaleCounter { .. })));
    assert!(matches!(s.accept_totp(EMAIL, last - 1), Err(StoreError::StaleCounter { .. })));
    s.accept_totp(EMAIL, last + 1).unwrap();
}

#[test]
fn a_wrong_code_keeps_the_attempt_and_the_right_one_still_works() {
    let (mut w, log, mut conn, _key, _csr) = staged();
    let before = log.len();
    let out = conn.receive(&mut w.enroller, &confirm_frame(2, "000000"));
    assert!(out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_BAD_CODE });
    assert_eq!(log.len(), before, "nothing is committed for a wrong code");
    assert!(store(&w).person(EMAIL).is_none());
    let secret = w.secret;
    assert!(matches!(only(&confirm(&mut w, &mut conn, 3, secret)), BootstrapResponse::Activated { .. }));
}

#[test]
fn too_many_wrong_codes_end_the_attempt_and_even_the_right_code_is_refused() {
    let (mut w, log, mut conn, _key, _csr) = staged();
    let before = log.len();
    for n in 0..MAX_WRONG_CODES {
        // One second between tries: the source bucket (shared by Redeem and Confirm) refills one call a second.
        w.advance(1100);
        let out = conn.receive(&mut w.enroller, &confirm_frame(10 + n, "000000"));
        assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_BAD_CODE }, "wrong code {}", n + 1);
    }
    w.advance(1100);
    let secret = w.secret;
    assert_closed_silently(&confirm(&mut w, &mut conn, 99, secret));
    assert_eq!(log.len(), before);
    assert!(store(&w).is_invite_pending(&w.key, w.now()), "the invitation survives for a fresh attempt");
}

#[test]
fn guessing_codes_from_one_source_runs_into_the_source_limit_first() {
    let (mut w, log, mut conn, _key, _csr) = staged();
    let before = log.len();
    // Redeem used one of the source's five calls; four wrong codes use the rest, and the fifth is limited and ends it.
    for n in 0..4 {
        let out = conn.receive(&mut w.enroller, &confirm_frame(10 + n, "000000"));
        assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_BAD_CODE }, "wrong code {}", n + 1);
    }
    let out = conn.receive(&mut w.enroller, &confirm_frame(20, "000000"));
    assert!(!out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_RATE_LIMITED });
    assert_eq!(log.len(), before);
    assert!(store(&w).is_invite_pending(&w.key, w.now()));
}

#[test]
fn a_second_redeem_replaces_the_attempt() {
    let (mut w, _log) = world();
    w.enroller.services_mut().env_mut().secrets.push_back([0x24u8; 20]);
    let mut conn = connection(&w);
    let (_key, csr) = device_csr();
    let first = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    let second = conn.receive(&mut w.enroller, &redeem_frame(2, "laptop", &csr, PASSWORD));
    let (BootstrapResponse::Setup { totp_uri: a }, BootstrapResponse::Setup { totp_uri: b }) = (only(&first), only(&second)) else {
        panic!("not Setup")
    };
    assert_ne!(a, b, "a replacement draws a new authenticator secret");
    assert_eq!(w.enroller.staged_count(), 1);
    // The first secret no longer works; the second does.
    let old = w.code_for([0x42u8; 20]);
    assert_eq!(only(&conn.receive(&mut w.enroller, &confirm_frame(3, &old))), BootstrapResponse::Error { code: ERR_BAD_CODE });
    let new = w.code_for([0x24u8; 20]);
    assert!(matches!(only(&conn.receive(&mut w.enroller, &confirm_frame(4, &new))), BootstrapResponse::Activated { .. }));
}

#[test]
fn any_other_message_closes_without_a_byte() {
    let (mut w, log) = world();
    let before = log.len();
    // Confirm before Redeem.
    let mut conn = connection(&w);
    assert_closed_silently(&conn.receive(&mut w.enroller, &confirm_frame(1, "123456")));

    // Ordinary chat requests and sign-in style tags cannot even be decoded here: the tags are disjoint.
    for payload in [vec![0u8, 0, 0, 0, 1], vec![1, 0, 0, 0, 1], vec![5, 0, 0, 0, 1, 0, 0], vec![160, 0, 0, 0, 1, 0, 0], vec![255, 0, 0, 0, 1]] {
        let mut conn = connection(&w);
        assert_closed_silently(&conn.receive(&mut w.enroller, &crewcraft_proto::frame::encode(&payload).unwrap()));
    }

    // Trailing bytes inside a frame, a truncated frame, and an oversized frame header.
    let (_key, csr) = device_csr();
    let good = redeem_frame(1, "laptop", &csr, PASSWORD);
    let mut inner = good[4..].to_vec();
    inner.push(0);
    let mut conn = connection(&w);
    assert_closed_silently(&conn.receive(&mut w.enroller, &crewcraft_proto::frame::encode(&inner).unwrap()));
    let mut conn = connection(&w);
    assert_closed_silently(&conn.receive(&mut w.enroller, &crewcraft_proto::frame::encode(&good[4..good.len() - 3]).unwrap()));
    let mut conn = connection(&w);
    assert_closed_silently(&conn.receive(&mut w.enroller, &[0x7f, 0xff, 0xff, 0xff, 1, 2, 3]));

    assert_eq!(w.enroller.staged_count(), 0);
    assert_eq!(log.len(), before);
    assert!(store(&w).is_invite_pending(&w.key, w.now()));
}

#[test]
fn a_closed_connection_stays_closed_and_commits_once() {
    let (mut w, log, mut conn, _key, _csr) = staged();
    let secret = w.secret;
    assert!(!confirm(&mut w, &mut conn, 2, secret).open);
    assert!(conn.is_closed());
    let after = log.len();
    assert_closed_silently(&confirm(&mut w, &mut conn, 3, secret));
    assert_eq!(log.len(), after, "no second commit");
}

#[test]
fn an_ambiguous_write_failure_releases_no_chain_and_poisons_the_enroller() {
    let (mut w, log, mut conn, _key, _csr) = staged();
    let before = log.len();
    // A disk error on the append: the store cannot say whether the record reached the file.
    log.fail_next(AppendError::Ambiguous(ErrorKind::Other));
    let secret = w.secret;
    let out = confirm(&mut w, &mut conn, 2, secret);
    assert!(!out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_UNAVAILABLE });
    assert_eq!(log.len(), before, "the injected failure wrote nothing");
    assert!(!contains(&out.bytes, w.enroller.authority().certificate()), "no chain part was sent");
    assert!(store(&w).person(EMAIL).is_none());
    assert!(store(&w).device_by_key(&[0u8; 32]).is_none());
    // The leaf never left the server: the reply is an error frame and nothing else.
    assert!(out.bytes.len() < 20, "a failed commit answered with {} bytes", out.bytes.len());

    // Whether the activation is durable is unknown, so the enroller fails closed for everyone until it is rebuilt.
    assert!(w.enroller.is_poisoned());
    let mut next = connection(&w);
    let (_k, csr) = device_csr();
    assert_closed_silently(&next.receive(&mut w.enroller, &redeem_frame(1, "phone", &csr, PASSWORD)));
}

#[test]
fn a_proven_precommit_failure_closes_with_an_error_and_changes_nothing() {
    let (mut w, log, mut conn, _key, _csr) = staged();
    let before = log.len();
    // The record is too large to write: the journal says nothing was written, which is proven, not ambiguous.
    log.fail_next(AppendError::TooLarge);
    let secret = w.secret;
    let out = confirm(&mut w, &mut conn, 2, secret);
    assert!(!out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_UNAVAILABLE });
    assert_eq!(log.len(), before);
    assert!(!w.enroller.is_poisoned(), "a proven pre-commit failure does not poison");
    assert!(store(&w).is_invite_pending(&w.key, w.now()), "the invitation is untouched");
    assert!(store(&w).person(EMAIL).is_none());
    // The person starts again on a new connection and the same invitation then works.
    let mut again = connection(&w);
    let (_k, csr) = device_csr();
    w.enroller.services_mut().env_mut().secrets.push_back([0x33u8; 20]);
    w.advance(2000);
    assert!(matches!(only(&again.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD))), BootstrapResponse::Setup { .. }));
    let code = w.code_for([0x33u8; 20]);
    assert!(matches!(only(&again.receive(&mut w.enroller, &confirm_frame(2, &code))), BootstrapResponse::Activated { .. }));
}

#[test]
fn store_errors_are_classified_by_whether_anything_could_have_been_written() {
    use StoreError::*;
    let io = ErrorKind::Other;
    for proven in [NoInvite, PersonExists, KeyInUse, BadField, NotActiveLeaf, StaleCounter { last: 3 }, Append(AppendError::TooLarge)] {
        assert_eq!(classify(&proven), CommitFailure::Refused, "{proven:?}");
    }
    assert_eq!(classify(&DeviceIdMoved { expected: 2, next: 3 }), CommitFailure::OrdinalMoved);
    assert_eq!(classify(&Append(AppendError::NotWritten(io))), CommitFailure::NotWritten);
    for unknown in [Append(AppendError::Ambiguous(io)), Poisoned, WrongKey, NotInitialized] {
        assert_eq!(classify(&unknown), CommitFailure::Ambiguous, "{unknown:?}");
    }
}

/// Services that let another activation slip in between building the certificate and committing it.
struct Racing {
    inner: StoreServices<MemLog, TestEnv>,
    /// How many times to move the device id before letting the real commit through.
    races: u32,
    /// Report an id other than the one the store allocated, after a real commit.
    misreport: bool,
}

impl Services for Racing {
    fn now_ms(&self) -> u64 {
        self.inner.now_ms()
    }
    fn new_totp_secret(&mut self) -> Option<[u8; 20]> {
        self.inner.new_totp_secret()
    }
    fn hash_password(&mut self, p: &str) -> Option<String> {
        self.inner.hash_password(p)
    }
    fn preview(&self, k: &[u8; 32], now: u64) -> Option<crewcraft_bootstrap::Preview> {
        self.inner.preview(k, now)
    }
    fn has_person(&self, e: &str) -> bool {
        self.inner.has_person(e)
    }
    fn key_registered(&self, k: &[u8; 32]) -> bool {
        self.inner.key_registered(k)
    }
    fn activate(&mut self, record: &crewcraft_bootstrap::ActivationRecord, now: u64) -> Result<u64, CommitFailure> {
        if self.races > 0 {
            self.races -= 1;
            // Somebody else's activation takes the id this certificate names.
            let n = u8::try_from(self.races).unwrap() + 50;
            let mut store = self.inner.store_mut();
            let invite = Invite { email: format!("racer{n}@example.org"), bootstrap_pub: [n; 32], expires_ms: now + HOUR };
            store.issue_invite(invite, now).unwrap();
            let cert: &[u8] = &[0x30, 0x82, n, n];
            let first =
                Some(FirstDevice { password_phc: Some("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaA"), totp_secret: b"synthetic-totp-RACER" });
            store
                .activate(
                    Activation {
                        bootstrap_pub: [n; 32],
                        device_name: "racer",
                        certificate: cert,
                        spki_sha256: [n; 32],
                        counter: 1,
                        expected_device_id: None,
                        first_device: first,
                    },
                    now,
                )
                .unwrap();
        }
        let allocated = self.inner.activate(record, now)?;
        Ok(if self.misreport { allocated + 1 } else { allocated })
    }
}

fn racing_world(races: u32) -> (Enroller<Racing>, [u8; 32], [u8; 20], MemLog) {
    let (w, log) = world();
    let (key, secret) = (w.key, w.secret);
    let (authority, services) = w.enroller.into_parts();
    (Enroller::new(authority, Racing { inner: services, races, misreport: false }), key, secret, log)
}

#[test]
fn a_device_id_that_moves_before_the_commit_is_rebuilt_once_and_still_matches() {
    let (mut enroller, key, secret, _log) = racing_world(1);
    let mut conn = BootstrapConnection::new(key, SOURCE);
    let (_k, csr) = device_csr();
    assert!(matches!(only(&conn.receive(&mut enroller, &redeem_frame(1, "laptop", &csr, PASSWORD))), BootstrapResponse::Setup { .. }));
    let code = code_at(secret, enroller.services().now_ms());
    let out = conn.receive(&mut enroller, &confirm_frame(2, &code));
    let BootstrapResponse::Activated { certificate, .. } = only(&out) else { panic!("not Activated") };
    // The racer took id 1, so the certificate was rebuilt for id 2 and the store allocated exactly that.
    assert!(contains(&certificate, b"device-2") && !contains(&certificate, b"device-1"));
    let store = enroller.services().inner.store();
    assert_eq!(store.devices_of(EMAIL)[0].id, 2);
    assert_eq!(store.device_certificate(2).unwrap(), certificate.as_slice());
    assert!(!enroller.is_poisoned());
}

#[test]
fn a_device_id_that_keeps_moving_is_refused_and_nothing_is_written_for_the_person() {
    let (mut enroller, key, secret, _log) = racing_world(2);
    let mut conn = BootstrapConnection::new(key, SOURCE);
    let (_k, csr) = device_csr();
    conn.receive(&mut enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    let code = code_at(secret, enroller.services().now_ms());
    let out = conn.receive(&mut enroller, &confirm_frame(2, &code));
    assert!(!out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_UNAVAILABLE });
    let store = enroller.services().inner.store();
    assert!(store.person(EMAIL).is_none() && store.devices_of(EMAIL).is_empty());
    assert!(store.is_invite_pending(&key, enroller.services().now_ms()), "the invitation is untouched");
    assert!(!enroller.is_poisoned(), "refused before any write, so not poisoned");
}

#[test]
fn a_revoked_or_expired_invitation_closes_before_anything_is_used() {
    let (mut w, log, mut conn, _key, _csr) = staged();
    let before = log.len();
    let key = w.key;
    assert!(w.enroller.services_mut().store_mut().revoke_invite(&key).unwrap());
    let revoked = log.len();
    let secret = w.secret;
    assert_closed_silently(&confirm(&mut w, &mut conn, 2, secret));
    assert_eq!(log.len(), revoked, "no activation after the revoke");
    assert!(before < revoked && !w.enroller.is_poisoned());
    // And Redeem on a new connection is refused the same way.
    let mut fresh = connection(&w);
    let (_k, csr) = device_csr();
    assert_closed_silently(&fresh.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD)));
}

#[test]
fn an_expired_invitation_closes_the_same_way() {
    let (mut w, log, mut conn, _key, _csr) = staged();
    let before = log.len();
    w.advance(2 * HOUR);
    let secret = w.secret;
    assert_closed_silently(&confirm(&mut w, &mut conn, 2, secret));
    assert_eq!(log.len(), before);
}

#[test]
fn a_device_key_that_was_ever_registered_never_enrolls_again() {
    let (mut w, _log, mut conn, key, csr) = staged();
    let secret = w.secret;
    assert!(matches!(only(&confirm(&mut w, &mut conn, 2, secret)), BootstrapResponse::Activated { .. }));
    // Another invitation, for another person, presenting the SAME device key.
    let now = w.now();
    let bob_key = [0x77u8; 32];
    w.enroller
        .services_mut()
        .store_mut()
        .issue_invite(Invite { email: "bob@example.org".into(), bootstrap_pub: bob_key, expires_ms: now + HOUR }, now)
        .unwrap();
    w.enroller.services_mut().env_mut().secrets.push_back([0x55u8; 20]);
    w.advance(2000);
    let mut bob = BootstrapConnection::new(bob_key, "192.0.2.77");
    let out = bob.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr_for(&key), PASSWORD));
    assert!(!out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_UNAVAILABLE });
    assert_eq!(w.enroller.staged_count(), 0);
    let _ = csr;
}

#[test]
fn a_person_who_already_has_an_account_is_not_enrolled_here() {
    let (mut w, _log, mut conn, _key, _csr) = staged();
    let secret = w.secret;
    assert!(matches!(only(&confirm(&mut w, &mut conn, 2, secret)), BootstrapResponse::Activated { .. }));
    let now = w.now();
    let again = [0x66u8; 32];
    w.enroller.services_mut().store_mut().issue_invite(Invite { email: EMAIL.into(), bootstrap_pub: again, expires_ms: now + HOUR }, now).unwrap();
    w.enroller.services_mut().env_mut().secrets.push_back([0x56u8; 20]);
    w.advance(2000);
    let mut conn = BootstrapConnection::new(again, "192.0.2.88");
    let (_k, csr) = device_csr();
    let out = conn.receive(&mut w.enroller, &redeem_frame(1, "second", &csr, PASSWORD));
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_UNAVAILABLE });
    assert!(!out.open);
}

#[test]
fn limits_apply_before_any_password_hashing() {
    let (mut w, _log) = world();
    let (_key, csr) = device_csr();
    for n in 0..SOURCE_BURST {
        w.enroller.services_mut().env_mut().secrets.push_back([n as u8 + 1; 20]);
        let mut conn = connection(&w);
        let out = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
        assert!(matches!(only(&out), BootstrapResponse::Setup { .. }), "call {}", n + 1);
    }
    assert_eq!(w.enroller.services().env().hash_calls, SOURCE_BURST as usize);
    // The next call from the same source is limited and costs no Argon2 work.
    w.enroller.services_mut().env_mut().secrets.push_back([0x77u8; 20]);
    let mut conn = connection(&w);
    let out = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    assert!(!out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_RATE_LIMITED });
    assert_eq!(w.enroller.services().env().hash_calls, SOURCE_BURST as usize, "a limited call must not be hashed");
}

#[test]
fn a_weak_password_or_a_bad_name_is_refused_before_anything_is_staged() {
    let (mut w, _log) = world();
    let mut conn = connection(&w);
    let (_key, csr) = device_csr();
    let out = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, "short"));
    assert!(out.open, "the person may try another password on this connection");
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_PASSWORD });
    let out = conn.receive(&mut w.enroller, &redeem_frame(2, "   ", &csr, PASSWORD));
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_BAD_REQUEST });
    assert_eq!(w.enroller.staged_count(), 0);
    assert_eq!(w.enroller.services().env().hash_calls, 0);
    let out = conn.receive(&mut w.enroller, &redeem_frame(3, "laptop", &csr, PASSWORD));
    assert!(matches!(only(&out), BootstrapResponse::Setup { .. }));
}

#[test]
fn a_bad_signing_request_is_refused_and_closes() {
    let ed = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let mut damaged = device_csr().1;
    let last = damaged.len() - 1;
    damaged[last] ^= 0xff;
    for csr in [b"not a request".to_vec(), damaged, csr_for(&ed)] {
        let (mut w, _log) = world();
        let mut conn = connection(&w);
        let out = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
        assert!(!out.open);
        assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_BAD_REQUEST });
        assert_eq!(w.enroller.staged_count(), 0);
        assert_eq!(w.enroller.services().env().hash_calls, 0);
    }
}

#[test]
fn an_invitation_that_is_not_live_gets_no_reply() {
    let (mut w, _log) = world();
    let mut conn = BootstrapConnection::new([9u8; 32], SOURCE);
    let (_key, csr) = device_csr();
    assert_closed_silently(&conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD)));
    assert_eq!(w.enroller.staged_count(), 0);
}

#[test]
fn a_failed_random_source_closes_with_an_error_and_stages_nothing() {
    let (mut w, _log) = world();
    w.enroller.services_mut().env_mut().secrets.clear();
    let mut conn = connection(&w);
    let (_key, csr) = device_csr();
    let out = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    assert!(!out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_UNAVAILABLE });
    assert_eq!(w.enroller.staged_count(), 0);
}

#[test]
fn nothing_printed_shows_the_password_hash_or_the_authenticator_secret() {
    let (mut w, log, mut conn, _key, _csr) = staged();
    let secret = w.secret;
    confirm(&mut w, &mut conn, 2, secret);
    let printed = format!("{conn:?} {:?} {:?}", w.enroller, w.enroller.services());
    assert!(!printed.contains("argon2") && !printed.contains(&format!("{secret:?}")), "{printed}");
    // And the journal holds neither the password nor the secret in the clear.
    for record in log.records() {
        assert!(!contains(&record, PASSWORD.as_bytes()), "the password is in the journal");
        assert!(!contains(&record, &secret), "the TOTP secret is in the journal in the clear");
    }
}

#[test]
fn a_stale_attempt_from_another_connection_cannot_confirm() {
    let (mut w, log) = world();
    w.enroller.services_mut().env_mut().secrets.push_back([0x24u8; 20]);
    let (_k1, csr1) = device_csr();
    let (_k2, csr2) = device_csr();
    let mut stale = BootstrapConnection::new(w.key, "192.0.2.1");
    let mut current = BootstrapConnection::new(w.key, "192.0.2.2");
    assert!(matches!(only(&stale.receive(&mut w.enroller, &redeem_frame(1, "old", &csr1, PASSWORD))), BootstrapResponse::Setup { .. }));
    assert!(matches!(only(&current.receive(&mut w.enroller, &redeem_frame(1, "new", &csr2, PASSWORD))), BootstrapResponse::Setup { .. }));
    let before = log.len();
    // The replaced attempt must not be able to use the new attempt's secret, even with its correct code.
    let code = w.code_for([0x24u8; 20]);
    assert_closed_silently(&stale.receive(&mut w.enroller, &confirm_frame(2, &code)));
    assert_eq!(log.len(), before, "a stale attempt committed something");
    // The current attempt is unaffected and finishes with its own device.
    assert!(matches!(only(&current.receive(&mut w.enroller, &confirm_frame(2, &code))), BootstrapResponse::Activated { .. }));
    assert_eq!(store(&w).devices_of(EMAIL)[0].name, "new");
}

#[test]
fn an_allocated_id_that_differs_from_the_certificate_poisons_and_releases_nothing() {
    let (mut enroller, key, secret, _log) = racing_world(0);
    enroller.services_mut().misreport = true;
    let mut conn = BootstrapConnection::new(key, SOURCE);
    let (_k, csr) = device_csr();
    conn.receive(&mut enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    let code = code_at(secret, enroller.services().now_ms());
    let out = conn.receive(&mut enroller, &confirm_frame(2, &code));
    // The store says it allocated an id the certificate does not name: the identity would be split, so nothing is released.
    assert!(!out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_UNAVAILABLE });
    assert!(enroller.is_poisoned());
    let leaf = enroller.services().inner.store().device_certificate(1).unwrap().to_vec();
    assert!(!contains(&out.bytes, &leaf), "the leaf was sent although the ids disagree");
}

#[test]
fn a_write_the_journal_promises_it_did_not_make_can_be_retried_on_the_same_connection() {
    let (mut w, log, mut conn, _key, _csr) = staged();
    let before = log.len();
    // NotWritten: the file is exactly as before, so nothing happened and the same request may be sent again.
    log.fail_next(AppendError::NotWritten(ErrorKind::Other));
    let secret = w.secret;
    let out = confirm(&mut w, &mut conn, 2, secret);
    assert!(out.open, "a retryable failure keeps the connection staged");
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_UNAVAILABLE });
    assert_eq!(log.len(), before);
    assert!(!w.enroller.is_poisoned());
    assert!(store(&w).is_invite_pending(&w.key, w.now()));
    assert!(store(&w).person(EMAIL).is_none());
    // The client sends ConfirmTotp again; the same attempt now succeeds, and it commits exactly one record.
    w.advance(1100);
    let out = confirm(&mut w, &mut conn, 3, secret);
    assert!(matches!(only(&out), BootstrapResponse::Activated { .. }));
    assert_eq!(log.len(), before + 1);
}
