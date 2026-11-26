//! T611e: the server's external sign-in (SECURITY-DESIGN.md section 9) against a real account store and a fake
//! provider that issues real ES256 ID tokens signed in the test: nonce per device and once only, loopback redirects,
//! the token checks, the identity bound to this device's person, the authorizer's decision stored before anything is
//! granted, one key refresh for an unknown key, and the authorizer's answer format.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crewcraft_authz::{Answer, Capabilities};
use crewcraft_oidc::{Identity, Key, parse_jwks};
use crewcraft_server::external_signin::{
    Authorizer, ExternalSignIn, PENDING_MS, Provider, Redirect, Refusal, authorize_request, is_loopback, parse_answer,
};
use crewcraft_server_core::account_store::{AccountStore, Activation, FirstDevice};
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::seal::ServiceKey;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::json;

const ISSUER: &str = "https://id.example.org/application/o/chat/";
const CLIENT: &str = "chat-client";
const A: &str = "a@example.com";
const B: &str = "b@example.com";
const T0: u64 = 1_800_000_000_000;
const REDIRECT: &str = "http://127.0.0.1:51234/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn store(name: &str) -> (AccountStore, PathBuf) {
    let p = std::env::temp_dir().join(format!("crewcraft-t611e-{name}-{}.journal", std::process::id()));
    let _ = fs::remove_file(&p);
    let mut s = AccountStore::create(&p, ServiceKey::from_bytes([7; 32])).unwrap();
    for (email, n) in [(A, 1u8), (B, 2u8)] {
        s.issue_invite(Invite { email: email.into(), bootstrap_pub: [n; 32], expires_ms: T0 + 86_400_000 }, T0).unwrap();
        s.activate(
            Activation {
                bootstrap_pub: [n; 32],
                device_name: "laptop",
                certificate: Box::leak(vec![0x30, 0x82, n, n].into_boxed_slice()),
                spki_sha256: [n + 100; 32],
                counter: 1000,
                first_device: Some(FirstDevice { password_phc: None, totp_secret: b"synthetic-totp-AAAAA" }),
                expected_device_id: None,
            },
            T0,
        )
        .unwrap();
    }
    s.bind_external(A, ISSUER, "sub-a").unwrap();
    s.bind_external(B, ISSUER, "sub-b").unwrap();
    (s, p)
}

/// A provider whose tokens are signed here. `claims` are adjusted per test; the nonce is filled in from `begin`.
struct FakeProvider {
    pair: EcdsaKeyPair,
    rng: SystemRandom,
    kid: Mutex<String>,
    claims: Mutex<serde_json::Value>,
    nonce: Mutex<String>,
    exchange_fails: Mutex<bool>,
    refreshes: AtomicUsize,
    published_kid: Mutex<String>,
}

impl FakeProvider {
    fn new() -> Arc<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        Arc::new(Self {
            pair,
            rng,
            kid: Mutex::new("k1".into()),
            claims: Mutex::new(
                json!({"iss": ISSUER, "aud": CLIENT, "sub": "sub-a", "exp": T0 / 1000 + 300, "iat": T0 / 1000, "amr": ["pwd", "mfa"]}),
            ),
            nonce: Mutex::new(String::new()),
            exchange_fails: Mutex::new(false),
            refreshes: AtomicUsize::new(0),
            published_kid: Mutex::new("k1".into()),
        })
    }

    fn jwks(&self, kid: &str) -> Vec<Key> {
        let point = self.pair.public_key().as_ref();
        let doc = json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": kid, "x": URL_SAFE_NO_PAD.encode(&point[1..33]), "y": URL_SAFE_NO_PAD.encode(&point[33..65])}]});
        parse_jwks(doc.to_string().as_bytes()).unwrap()
    }
}

impl Provider for FakeProvider {
    fn issuer(&self) -> &str {
        ISSUER
    }
    fn client_id(&self) -> &str {
        CLIENT
    }
    fn authorization_endpoint(&self) -> Result<String, String> {
        Ok("https://id.example.org/authorize/".into())
    }
    fn keys(&self, refresh: bool) -> Result<Vec<Key>, String> {
        if refresh {
            self.refreshes.fetch_add(1, Ordering::SeqCst);
            // A refresh sees the key the provider publishes now.
            return Ok(self.jwks(&self.published_kid.lock().unwrap()));
        }
        Ok(self.jwks("k1"))
    }
    fn exchange(&self, code: &str, verifier: &str, redirect_uri: &str) -> Result<String, String> {
        if *self.exchange_fails.lock().unwrap() || code != "good-code" || verifier != VERIFIER || redirect_uri != REDIRECT {
            return Err("invalid_grant".into());
        }
        let mut claims = self.claims.lock().unwrap().clone();
        if claims.get("nonce").is_none() {
            claims["nonce"] = json!(self.nonce.lock().unwrap().clone());
        }
        let header = URL_SAFE_NO_PAD.encode(json!({"alg": "ES256", "kid": self.kid.lock().unwrap().clone()}).to_string());
        let signed = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
        let signature = self.pair.sign(&self.rng, signed.as_bytes()).unwrap();
        Ok(format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref())))
    }
}

struct FakeAuthorizer(Mutex<Answer>, AtomicUsize);

impl Authorizer for FakeAuthorizer {
    fn ask(&self, identity: &Identity, purpose: &str) -> Answer {
        assert_eq!((identity.issuer.as_str(), purpose), (ISSUER, "sign-in"));
        self.1.fetch_add(1, Ordering::SeqCst);
        self.0.lock().unwrap().clone()
    }
}

fn allow(names: &[&str], revision: u64) -> Answer {
    Answer::Allow { capabilities: Capabilities::from_names(names.iter().copied()), revision, recheck_after_secs: None }
}

/// Fresh bytes for each session token (production draws them from the OS); a repeated token is refused by the store.
static NEXT: AtomicUsize = AtomicUsize::new(1);

fn fresh() -> [u8; 32] {
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
    bytes
}

/// Begin on `device`, then finish on `finish_device` as `user`.
fn run(ext: &ExternalSignIn, provider: &FakeProvider, s: &mut AccountStore, user: &str, device: u64, finish_device: u64) -> Result<String, Refusal> {
    let start = ext.begin(device, [device as u8; 32], T0).unwrap();
    assert_eq!((start.issuer.as_str(), start.client_id.as_str()), (ISSUER, CLIENT));
    *provider.nonce.lock().unwrap() = start.nonce.clone();
    ext.finish(s, user, finish_device, Redirect { code: "good-code", verifier: VERIFIER, redirect_uri: REDIRECT }, fresh(), T0 + 1000)
}

#[test]
fn a_good_sign_in_gives_a_session_and_the_nonce_works_once() {
    let (mut s, p) = store("good");
    let provider = FakeProvider::new();
    let ext = ExternalSignIn::new(provider.clone(), None, true);
    let token = run(&ext, &provider, &mut s, A, 1, 1).unwrap();
    assert_eq!(token.len(), 43);
    // The nonce was used: the same finish again is refused.
    assert_eq!(
        ext.finish(&mut s, A, 1, Redirect { code: "good-code", verifier: VERIFIER, redirect_uri: REDIRECT }, [9; 32], T0 + 2000),
        Err(Refusal::NoPendingSignIn)
    );
    // A begin on another device does not serve this one, and an old begin expires.
    ext.begin(2, [2; 32], T0).unwrap();
    assert_eq!(
        ext.finish(&mut s, A, 1, Redirect { code: "good-code", verifier: VERIFIER, redirect_uri: REDIRECT }, [9; 32], T0 + 2000),
        Err(Refusal::NoPendingSignIn)
    );
    let start = ext.begin(1, [1; 32], T0).unwrap();
    *provider.nonce.lock().unwrap() = start.nonce;
    assert_eq!(
        ext.finish(&mut s, A, 1, Redirect { code: "good-code", verifier: VERIFIER, redirect_uri: REDIRECT }, [9; 32], T0 + PENDING_MS),
        Err(Refusal::NoPendingSignIn)
    );
    fs::remove_file(&p).unwrap();
}

#[test]
fn every_check_refuses_on_its_own() {
    let (mut s, p) = store("refusals");
    let provider = FakeProvider::new();
    let ext = ExternalSignIn::new(provider.clone(), None, true);
    // A redirect that is not loopback.
    let start = ext.begin(1, [1; 32], T0).unwrap();
    *provider.nonce.lock().unwrap() = start.nonce;
    assert_eq!(
        ext.finish(&mut s, A, 1, Redirect { code: "good-code", verifier: VERIFIER, redirect_uri: "https://evil.example.org/cb" }, [9; 32], T0),
        Err(Refusal::NotLoopback)
    );
    // The provider refuses the code.
    *provider.exchange_fails.lock().unwrap() = true;
    assert!(matches!(run(&ext, &provider, &mut s, A, 1, 1), Err(Refusal::Provider(_))));
    *provider.exchange_fails.lock().unwrap() = false;
    // A token for another nonce (a replay from another sign-in).
    provider.claims.lock().unwrap()["nonce"] = json!("n-from-elsewhere");
    assert!(matches!(run(&ext, &provider, &mut s, A, 1, 1), Err(Refusal::Token(crewcraft_oidc::Error::Claim("nonce")))));
    provider.claims.lock().unwrap().as_object_mut().unwrap().remove("nonce");
    // Password only, while a second factor is required.
    provider.claims.lock().unwrap()["amr"] = json!(["pwd"]);
    assert!(matches!(run(&ext, &provider, &mut s, A, 1, 1), Err(Refusal::Token(crewcraft_oidc::Error::MfaRequired))));
    provider.claims.lock().unwrap()["amr"] = json!(["pwd", "mfa"]);
    // B's provider identity on A's device, and an identity bound to nobody.
    provider.claims.lock().unwrap()["sub"] = json!("sub-b");
    assert_eq!(run(&ext, &provider, &mut s, A, 1, 1), Err(Refusal::NotThisPerson));
    provider.claims.lock().unwrap()["sub"] = json!("sub-nobody");
    assert_eq!(run(&ext, &provider, &mut s, A, 1, 1), Err(Refusal::NotThisPerson));
    fs::remove_file(&p).unwrap();
}

#[test]
fn the_authorizer_decides_and_its_decision_is_stored_first() {
    let (mut s, p) = store("authz");
    let provider = FakeProvider::new();
    let authorizer = Arc::new(FakeAuthorizer(Mutex::new(allow(&["use", "moderate"], 4)), AtomicUsize::new(0)));
    let ext = ExternalSignIn::new(provider.clone(), Some(authorizer.clone()), true);
    assert!(run(&ext, &provider, &mut s, A, 1, 1).is_ok());
    assert_eq!(s.authorization(A).unwrap().grant.as_ref().unwrap().revision, 4);

    *authorizer.0.lock().unwrap() = Answer::Deny { revision: 5 };
    assert!(matches!(run(&ext, &provider, &mut s, A, 1, 1), Err(Refusal::NotAuthorized(_))));
    assert_eq!(s.authorization(A).unwrap().denied_revision, Some(5), "the denial is stored");
    *authorizer.0.lock().unwrap() = allow(&["use"], 5);
    assert!(matches!(run(&ext, &provider, &mut s, A, 1, 1), Err(Refusal::NotAuthorized(_))), "a stale allow cannot lift it");
    *authorizer.0.lock().unwrap() = Answer::NoAnswer;
    assert!(matches!(run(&ext, &provider, &mut s, A, 1, 1), Err(Refusal::NotAuthorized(_))), "no grace at sign-in");
    *authorizer.0.lock().unwrap() = allow(&["moderate"], 9);
    assert!(matches!(run(&ext, &provider, &mut s, A, 1, 1), Err(Refusal::NotAuthorized(_))), "nothing without use");
    *authorizer.0.lock().unwrap() = allow(&["use"], 10);
    assert!(run(&ext, &provider, &mut s, A, 1, 1).is_ok(), "a newer allow lifts the denial");
    assert_eq!(authorizer.1.load(Ordering::SeqCst), 6);
    fs::remove_file(&p).unwrap();
}

#[test]
fn an_unknown_key_is_fetched_again_once() {
    let (mut s, p) = store("keys");
    let provider = FakeProvider::new();
    let ext = ExternalSignIn::new(provider.clone(), None, true);
    // The provider rotated to k2: the cached set has only k1, so the server fetches again and then verifies.
    *provider.kid.lock().unwrap() = "k2".into();
    *provider.published_kid.lock().unwrap() = "k2".into();
    assert!(run(&ext, &provider, &mut s, A, 1, 1).is_ok());
    assert_eq!(provider.refreshes.load(Ordering::SeqCst), 1);
    // Within a minute, another unknown key does not fetch again.
    *provider.kid.lock().unwrap() = "k3".into();
    assert!(matches!(run(&ext, &provider, &mut s, A, 1, 1), Err(Refusal::Token(crewcraft_oidc::Error::UnknownKey))));
    assert_eq!(provider.refreshes.load(Ordering::SeqCst), 1);
    fs::remove_file(&p).unwrap();
}

#[test]
fn loopback_redirects_and_authorizer_answers_are_read_strictly() {
    for good in ["http://127.0.0.1:51234/callback", "http://[::1]:8080/callback", "http://127.0.0.1:1"] {
        assert!(is_loopback(good), "{good}");
    }
    for bad in [
        "https://127.0.0.1:1/cb",
        "http://localhost:1/cb",
        "http://127.0.0.1/cb",
        "http://127.0.0.1:0/cb",
        "http://127.0.0.1:1@example.org/",
        "http://127.0.0.2:1/cb",
    ] {
        assert!(!is_loopback(bad), "{bad}");
    }
    let body = br#"{"api":1,"decision":"allow","capabilities":["use","moderate","fly"],"revision":1042,"recheck_after_seconds":300}"#;
    assert_eq!(
        parse_answer(200, body),
        Answer::Allow { capabilities: Capabilities::from_names(["use", "moderate"]), revision: 1042, recheck_after_secs: Some(300) }
    );
    assert_eq!(parse_answer(200, br#"{"api":1,"decision":"deny","revision":7}"#), Answer::Deny { revision: 7 });
    for (status, body) in [
        (500, &br#"{"api":1,"decision":"deny","revision":7}"#[..]),
        (200, br#"{"api":2,"decision":"allow","capabilities":["use"],"revision":1}"#),
        (200, br#"{"api":1,"decision":"maybe","revision":1}"#),
        (200, br#"{"api":1,"decision":"allow","revision":1}"#),
        (200, br#"{"api":1,"decision":"allow","capabilities":["use"],"revision":-1}"#),
        (200, br#"{"api":1,"decision":"allow","capabilities":["use"],"revision":1,"recheck_after_seconds":"soon"}"#),
        (200, b"<html>"),
    ] {
        assert_eq!(parse_answer(status, body), Answer::NoAnswer, "{status} {}", String::from_utf8_lossy(body));
    }
    let identity = Identity { issuer: ISSUER.into(), subject: "sub-a".into(), email: Some(A.into()), email_verified: true, name: None, amr: vec![] };
    let request: serde_json::Value = serde_json::from_slice(&authorize_request(&identity, "recheck")).unwrap();
    assert_eq!(request, json!({"api": 1, "purpose": "recheck", "identity": {"issuer": ISSUER, "subject": "sub-a", "email": A}}));
}
