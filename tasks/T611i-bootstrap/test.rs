//! T611i: enrolling through the server's identity provider on the bootstrap connection, against the REAL durable account
//! store and a provider played by the test: `RedeemExternal` answers `ExternalStart` with nothing durable,
//! `ConfirmExternal` commits the person, the device and the binding as ONE record and only then sends the leaf, the
//! token's email must be the invitation's, every refusal leaves the invitation live, a server has exactly one way in,
//! and the provider is called with no lock held.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use common::*;
use crewcraft_bootstrap::{
    ERR_EXTERNAL_REFUSED, ERR_UNAVAILABLE, ERR_WRONG_PATH, EnrollmentStart, ExternalEnrollment, Output, VerifiedIdentity, receive_shared,
};
use crewcraft_proto::bootstrap::{BootstrapRequest, BootstrapResponse};

const ISSUER: &str = "https://id.example.org/";
const NONCE: &str = "__________________________________________8";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const REDIRECT: &str = "http://127.0.0.1:5/callback";

/// The provider, played by the test.
struct FakeProvider {
    begin_fails: bool,
    /// What `verify` answers.
    identity: Mutex<Option<VerifiedIdentity>>,
    begins: AtomicUsize,
    /// What each `verify` was given: bootstrap key, code, verifier, redirect URI.
    verified: Mutex<Vec<([u8; 32], String, String, String)>>,
    /// The enroller, when the test drives it through `receive_shared`: `verify` checks its lock is free.
    shared: OnceLock<Arc<Mutex<Rig<MemLog>>>>,
    lock_was_free: AtomicBool,
}

impl FakeProvider {
    fn new(email: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            begin_fails: false,
            identity: Mutex::new(Some(VerifiedIdentity { issuer: ISSUER.into(), subject: "sub-alice".into(), email: email.map(str::to_owned) })),
            begins: AtomicUsize::new(0),
            verified: Mutex::new(Vec::new()),
            shared: OnceLock::new(),
            lock_was_free: AtomicBool::new(false),
        })
    }
}

impl ExternalEnrollment for FakeProvider {
    fn begin(&self, _: &[u8; 32], _: u64) -> Option<EnrollmentStart> {
        self.begins.fetch_add(1, Ordering::SeqCst);
        (!self.begin_fails).then(|| EnrollmentStart {
            issuer: ISSUER.into(),
            client_id: "chat".into(),
            authorization_endpoint: "https://id.example.org/authorize/".into(),
            nonce: NONCE.into(),
        })
    }

    fn verify(&self, key: &[u8; 32], code: &str, verifier: &str, redirect_uri: &str, _: u64) -> Option<VerifiedIdentity> {
        if let Some(shared) = self.shared.get() {
            self.lock_was_free.store(shared.try_lock().is_ok(), Ordering::SeqCst);
        }
        self.verified.lock().unwrap().push((*key, code.into(), verifier.into(), redirect_uri.into()));
        self.identity.lock().unwrap().clone()
    }
}

fn external_world(provider: &Arc<FakeProvider>) -> (World<MemLog>, MemLog) {
    let (w, log) = world();
    let World { enroller, bootstrap_key, key, root_cert, secret } = w;
    let enroller = enroller.with_external(provider.clone());
    assert!(enroller.enrolls_externally());
    (World { enroller, bootstrap_key, key, root_cert, secret }, log)
}

fn redeem_external(id: u32, csr: &[u8]) -> Vec<u8> {
    frame_of(id, &BootstrapRequest::RedeemExternal { device_name: "laptop".into(), csr: csr.to_vec() })
}

fn confirm_external(id: u32) -> Vec<u8> {
    frame_of(id, &BootstrapRequest::ConfirmExternal { code: "the-code".into(), verifier: VERIFIER.into(), redirect_uri: REDIRECT.into() })
}

fn only(out: &Output) -> BootstrapResponse {
    let mut all = replies(&out.bytes);
    assert_eq!(all.len(), 1, "expected exactly one reply, got {all:?}");
    all.remove(0).1
}

fn closed_with(out: &Output, code: u16) {
    assert!(!out.open);
    assert_eq!(only(out), BootstrapResponse::Error { code });
}

#[test]
fn an_enrollment_through_the_provider_commits_one_record_then_sends_the_leaf() {
    let provider = FakeProvider::new(Some(EMAIL));
    let (mut w, log) = external_world(&provider);
    let before = log.len();
    let mut conn = connection(&w);
    let (_key, csr) = device_csr();

    let out = conn.receive(&mut w.enroller, &redeem_external(3, &csr));
    assert!(out.open);
    let all = replies(&out.bytes);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, 3, "the reply repeats the request id");
    let BootstrapResponse::ExternalStart { issuer, client_id, nonce, .. } = &all[0].1 else { panic!("not ExternalStart: {:?}", all[0].1) };
    assert_eq!((issuer.as_str(), client_id.as_str(), nonce.as_str()), (ISSUER, "chat", NONCE));
    assert_eq!(log.len(), before, "RedeemExternal writes nothing");
    assert!(w.enroller.services().store().is_invite_pending(&w.key, w.now()));
    assert_eq!(w.enroller.staged_count(), 1);

    let out = conn.receive(&mut w.enroller, &confirm_external(4));
    assert!(!out.open, "the connection closes after Activated");
    let BootstrapResponse::Activated { certificate, .. } = only(&out) else { panic!("not Activated") };
    assert_eq!(log.len(), before + 1, "invitation, person, device and binding are one record");
    let verified = provider.verified.lock().unwrap().clone();
    assert_eq!(verified, vec![(w.key, "the-code".to_owned(), VERIFIER.to_owned(), REDIRECT.to_owned())]);

    let s = w.enroller.services().store();
    assert_eq!(s.person(EMAIL).unwrap().password_phc, None, "no CrewCraft password");
    assert_eq!(s.person_for_external(ISSUER, "sub-alice"), Some(EMAIL));
    let spki = crewcraft_pki::key_id_of_certificate(&certificate).unwrap();
    assert_eq!(s.device_by_key(&spki), Some(1));
    assert_eq!(s.device_certificate(1).unwrap(), certificate.as_slice());
    assert!(!s.is_invite_pending(&w.key, w.now()));
    // The sealed authenticator secret is one no one was shown.
    assert_eq!(&s.totp_secret(EMAIL).unwrap()[..], &w.secret[..]);
    drop(s);
    assert_eq!(w.enroller.staged_count(), 0);
}

#[test]
fn the_tokens_email_must_be_the_invitations() {
    for (claimed, accepted) in [(Some("Alice@Example.org"), true), (Some("mallory@example.org"), false), (None, false)] {
        let provider = FakeProvider::new(claimed);
        let (mut w, log) = external_world(&provider);
        let mut conn = connection(&w);
        let (_key, csr) = device_csr();
        conn.receive(&mut w.enroller, &redeem_external(1, &csr));
        let before = log.len();
        let out = conn.receive(&mut w.enroller, &confirm_external(2));
        if accepted {
            assert!(matches!(only(&out), BootstrapResponse::Activated { .. }), "{claimed:?}");
            continue;
        }
        closed_with(&out, ERR_EXTERNAL_REFUSED);
        assert_eq!(log.len(), before, "{claimed:?}: nothing durable");
        assert!(w.enroller.services().store().is_invite_pending(&w.key, w.now()), "the invitation stays live");
        assert!(w.enroller.services().store().person(EMAIL).is_none());
        assert_eq!(w.enroller.staged_count(), 0, "the spent attempt is gone");
        // A new connection can start again (with a fresh secret for the new attempt).
        w.enroller.services_mut().env_mut().secrets.push_back([0x43; 20]);
        let mut again = connection(&w);
        assert!(matches!(only(&again.receive(&mut w.enroller, &redeem_external(1, &csr))), BootstrapResponse::ExternalStart { .. }));
    }
}

#[test]
fn a_provider_refusal_or_outage_leaves_nothing_durable() {
    let provider = FakeProvider::new(Some(EMAIL));
    *provider.identity.lock().unwrap() = None;
    let (mut w, log) = external_world(&provider);
    let mut conn = connection(&w);
    let (_key, csr) = device_csr();
    conn.receive(&mut w.enroller, &redeem_external(1, &csr));
    let before = log.len();
    closed_with(&conn.receive(&mut w.enroller, &confirm_external(2)), ERR_EXTERNAL_REFUSED);
    assert_eq!(log.len(), before);
    assert!(w.enroller.services().store().is_invite_pending(&w.key, w.now()));

    let down = Arc::new(FakeProvider { begin_fails: true, ..Arc::try_unwrap(FakeProvider::new(Some(EMAIL))).ok().unwrap() });
    let (mut w, log) = external_world(&down);
    let before = log.len();
    let mut conn = connection(&w);
    closed_with(&conn.receive(&mut w.enroller, &redeem_external(1, &csr)), ERR_UNAVAILABLE);
    assert_eq!((log.len(), w.enroller.staged_count()), (before, 0));
}

#[test]
fn a_server_has_exactly_one_way_in() {
    let provider = FakeProvider::new(Some(EMAIL));
    let (mut w, _log) = external_world(&provider);
    let (_key, csr) = device_csr();
    let mut conn = connection(&w);
    closed_with(&conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD)), ERR_WRONG_PATH);
    assert_eq!(provider.begins.load(Ordering::SeqCst), 0);

    let (mut plain, _log) = world();
    let mut conn = connection(&plain);
    closed_with(&conn.receive(&mut plain.enroller, &redeem_external(1, &csr)), ERR_WRONG_PATH);
}

#[test]
fn out_of_order_requests_close_without_a_reply() {
    let provider = FakeProvider::new(Some(EMAIL));
    let (mut w, _log) = external_world(&provider);
    let (_key, csr) = device_csr();
    // A confirmation before anything is staged.
    let mut conn = connection(&w);
    let out = conn.receive(&mut w.enroller, &confirm_external(1));
    assert!(out.bytes.is_empty() && !out.open);
    // An authenticator code on an external enrollment.
    let mut conn = connection(&w);
    conn.receive(&mut w.enroller, &redeem_external(1, &csr));
    let out = conn.receive(&mut w.enroller, &confirm_frame(2, "123456"));
    assert!(out.bytes.is_empty() && !out.open);
    assert!(provider.verified.lock().unwrap().is_empty());
}

#[test]
fn the_shared_listener_calls_the_provider_with_no_lock_held() {
    let provider = FakeProvider::new(Some(EMAIL));
    let (w, log) = external_world(&provider);
    let key = w.key;
    let shared: Arc<Mutex<Rig<MemLog>>> = Arc::new(Mutex::new(w.enroller));
    assert!(provider.shared.set(shared.clone()).is_ok());
    let mut conn = crewcraft_bootstrap::BootstrapConnection::new(key, SOURCE);
    let (_key, csr) = device_csr();
    let hasher = |_: &str| -> Option<String> { panic!("no password is hashed") };

    let out = receive_shared(&mut conn, &shared, &hasher, &redeem_external(1, &csr));
    assert!(out.open && matches!(only(&out), BootstrapResponse::ExternalStart { .. }));
    let before = log.len();
    let out = receive_shared(&mut conn, &shared, &hasher, &confirm_external(2));
    assert!(matches!(only(&out), BootstrapResponse::Activated { .. }));
    assert!(provider.lock_was_free.load(Ordering::SeqCst), "verify ran while the enroller was unlocked");
    assert_eq!(log.len(), before + 1);
}
