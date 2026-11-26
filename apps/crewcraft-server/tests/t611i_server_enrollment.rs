//! T611i: the server's side of enrolling through its identity provider (SECURITY-DESIGN.md section 9): nonces keyed by
//! the invitation's bootstrap key, used once and kept apart from device sign-ins, the same token checks, the
//! authorizer's fresh `allow` with `use`, nothing stored, and the bootstrap connection's view of it
//! (`crewcraft_bootstrap::ExternalEnrollment`). The provider issues real ES256 ID tokens signed in the test.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crewcraft_authz::{Answer, Capabilities};
use crewcraft_bootstrap::ExternalEnrollment;
use crewcraft_oidc::{Identity, Key, parse_jwks};
use crewcraft_server::external_signin::{Authorizer, ExternalSignIn, PENDING_MS, Provider, Redirect, Refusal};
use crewcraft_server_core::account_store::AccountStore;
use crewcraft_server_core::seal::ServiceKey;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::json;

const ISSUER: &str = "https://id.example.org/application/o/chat/";
const CLIENT: &str = "chat-client";
const T0: u64 = 1_800_000_000_000;
const REDIRECT: &str = "http://127.0.0.1:51234/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const INVITATION: [u8; 32] = [9; 32];
const OTHER_INVITATION: [u8; 32] = [8; 32];

/// A provider whose tokens are signed here; the nonce is the one the test last began with.
struct FakeProvider {
    pair: EcdsaKeyPair,
    rng: SystemRandom,
    nonce: Mutex<String>,
}

impl FakeProvider {
    fn new() -> Arc<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        Arc::new(Self { pair, rng, nonce: Mutex::new(String::new()) })
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
    fn keys(&self, _: bool) -> Result<Vec<Key>, String> {
        let point = self.pair.public_key().as_ref();
        let doc = json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "x": URL_SAFE_NO_PAD.encode(&point[1..33]), "y": URL_SAFE_NO_PAD.encode(&point[33..65])}]});
        Ok(parse_jwks(doc.to_string().as_bytes()).unwrap())
    }
    fn exchange(&self, code: &str, verifier: &str, redirect_uri: &str) -> Result<String, String> {
        if code != "good-code" || verifier != VERIFIER || redirect_uri != REDIRECT {
            return Err("invalid_grant".into());
        }
        let claims = json!({
            "iss": ISSUER, "aud": CLIENT, "sub": "sub-new", "email": "new@example.org", "exp": T0 / 1000 + 300, "iat": T0 / 1000,
            "amr": ["pwd", "mfa"], "nonce": self.nonce.lock().unwrap().clone(),
        });
        let header = URL_SAFE_NO_PAD.encode(json!({"alg": "ES256", "kid": "k1"}).to_string());
        let signed = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
        let signature = self.pair.sign(&self.rng, signed.as_bytes()).unwrap();
        Ok(format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref())))
    }
}

struct FakeAuthorizer(Answer);

impl Authorizer for FakeAuthorizer {
    fn ask(&self, identity: &Identity, purpose: &str) -> Answer {
        assert_eq!((identity.subject.as_str(), purpose), ("sub-new", "sign-in"));
        self.0.clone()
    }
}

/// Begin an enrollment for `invitation` and tell the provider its nonce.
fn begin(ext: &ExternalSignIn, provider: &FakeProvider, invitation: [u8; 32], at: u64) {
    let start = ext.begin_enrollment(invitation, [invitation[0]; 32], at).unwrap();
    assert_eq!((start.issuer.as_str(), start.client_id.as_str()), (ISSUER, CLIENT));
    *provider.nonce.lock().unwrap() = start.nonce;
}

fn verify(ext: &ExternalSignIn, invitation: [u8; 32], redirect: &str, at: u64) -> Result<Identity, Refusal> {
    ext.verify_enrollment(invitation, "good-code", VERIFIER, redirect, at)
}

#[test]
fn an_enrollment_is_verified_once_and_apart_from_device_sign_ins() {
    let provider = FakeProvider::new();
    let ext = ExternalSignIn::new(provider.clone(), None, true);
    begin(&ext, &provider, INVITATION, T0);
    let identity = verify(&ext, INVITATION, REDIRECT, T0 + 1000).unwrap();
    assert_eq!((identity.issuer.as_str(), identity.subject.as_str(), identity.email.as_deref()), (ISSUER, "sub-new", Some("new@example.org")));
    assert_eq!(verify(&ext, INVITATION, REDIRECT, T0 + 2000).unwrap_err(), Refusal::NoPendingSignIn, "used once");

    // Another invitation's nonce, or a device's, does not finish this one.
    begin(&ext, &provider, OTHER_INVITATION, T0);
    assert_eq!(verify(&ext, INVITATION, REDIRECT, T0 + 1000).unwrap_err(), Refusal::NoPendingSignIn);
    let device = ext.begin(9, [1; 32], T0).unwrap();
    *provider.nonce.lock().unwrap() = device.nonce;
    assert_eq!(verify(&ext, INVITATION, REDIRECT, T0 + 1000).unwrap_err(), Refusal::NoPendingSignIn);
    // And an enrollment's nonce does not finish a device sign-in.
    begin(&ext, &provider, INVITATION, T0);
    let path = std::env::temp_dir().join(format!("crewcraft-t611i-server-{}.journal", std::process::id()));
    let _ = fs::remove_file(&path);
    let mut store = AccountStore::create(&path, ServiceKey::from_bytes([7; 32])).unwrap();
    let mut device_bytes = [0; 32];
    device_bytes[0] = 77;
    assert_eq!(
        ext.finish(
            &mut store,
            "new@example.org",
            1,
            Redirect { code: "good-code", verifier: VERIFIER, redirect_uri: REDIRECT },
            device_bytes,
            T0 + 1000
        )
        .unwrap_err(),
        Refusal::NoPendingSignIn
    );
    assert!(verify(&ext, INVITATION, REDIRECT, T0 + 1000).is_ok(), "the enrollment's nonce was still there");
    fs::remove_file(&path).unwrap();
}

#[test]
fn the_sign_in_checks_apply_to_an_enrollment() {
    let provider = FakeProvider::new();
    let ext = ExternalSignIn::new(provider.clone(), None, true);
    begin(&ext, &provider, INVITATION, T0);
    assert_eq!(verify(&ext, INVITATION, "https://evil.example.org/callback", T0 + 1000).unwrap_err(), Refusal::NotLoopback);
    begin(&ext, &provider, INVITATION, T0);
    assert_eq!(verify(&ext, INVITATION, REDIRECT, T0 + PENDING_MS).unwrap_err(), Refusal::NoPendingSignIn, "expired");
    begin(&ext, &provider, INVITATION, T0);
    assert!(matches!(ext.verify_enrollment(INVITATION, "bad-code", VERIFIER, REDIRECT, T0 + 1000), Err(Refusal::Provider(_))));
    // A nonce the token does not carry.
    begin(&ext, &provider, INVITATION, T0);
    *provider.nonce.lock().unwrap() = "another-nonce".into();
    assert!(matches!(verify(&ext, INVITATION, REDIRECT, T0 + 1000), Err(Refusal::Token(_))));
}

#[test]
fn the_authorizer_must_allow_use_and_nothing_is_stored() {
    let deny = Answer::Deny { revision: 3 };
    let no_use = Answer::Allow { capabilities: Capabilities::from_names(["moderate"]), revision: 3, recheck_after_secs: None };
    let allow = Answer::Allow { capabilities: Capabilities::from_names(["use"]), revision: 3, recheck_after_secs: None };
    for (answer, ok) in [(deny, false), (no_use, false), (Answer::NoAnswer, false), (allow, true)] {
        let provider = FakeProvider::new();
        let authorizer: Arc<dyn Authorizer> = Arc::new(FakeAuthorizer(answer.clone()));
        let ext = ExternalSignIn::new(provider.clone(), Some(authorizer), true);
        begin(&ext, &provider, INVITATION, T0);
        let result = verify(&ext, INVITATION, REDIRECT, T0 + 1000);
        assert_eq!(result.is_ok(), ok, "{answer:?}: {result:?}");
        if !ok {
            assert!(matches!(result, Err(Refusal::NotAuthorized(_))));
        }
    }
}

#[test]
fn the_bootstrap_connection_sees_the_same_through_its_trait() {
    let provider = FakeProvider::new();
    let ext = ExternalSignIn::new(provider.clone(), None, true);
    let start = ExternalEnrollment::begin(&ext, &INVITATION, T0).unwrap();
    assert_eq!((start.issuer.as_str(), start.client_id.as_str()), (ISSUER, CLIENT));
    assert_eq!(start.nonce.len(), 43);
    assert!(!format!("{start:?}").contains(&start.nonce), "Debug hides the nonce");
    *provider.nonce.lock().unwrap() = start.nonce.clone();
    let identity = ExternalEnrollment::verify(&ext, &INVITATION, "good-code", VERIFIER, REDIRECT, T0 + 1000).unwrap();
    assert_eq!((identity.subject.as_str(), identity.email.as_deref()), ("sub-new", Some("new@example.org")));
    assert!(ExternalEnrollment::verify(&ext, &INVITATION, "good-code", VERIFIER, REDIRECT, T0 + 1000).is_none(), "used once");
    // Two begins draw two different nonces.
    let again = ExternalEnrollment::begin(&ext, &INVITATION, T0).unwrap();
    assert_ne!(again.nonce, start.nonce);
}
