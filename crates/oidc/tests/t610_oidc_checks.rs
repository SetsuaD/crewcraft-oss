//! T610: the OpenID Connect checks without a network: discovery, PKCE, the authorization URL, the provider's keys and
//! ID tokens. RS256 and ES256 signatures are checked against the published examples of RFC 7515 (appendices A.2 and
//! A.3; public values only), and ES256 ID tokens are signed here with a key made at run time.
#![allow(clippy::unwrap_used, clippy::panic)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crewcraft_oidc::{
    Error, Expected, Key, LEEWAY_SECS, MAX_DOCUMENT_BYTES, Request, authorization_url, parse_discovery, parse_jwks, pkce, random_value,
    verify_id_token, verify_signature,
};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde_json::json;

// RFC 7515 A.2 (RS256) and A.3 (ES256): public key members and the example JWS, exactly as published (the JWS
// as its three parts, one per line).
const RFC_RSA_N: &str = include_str!("fixtures/rfc7515_a2_n.txt");
const RFC_RS256_JWS: &str = include_str!("fixtures/rfc7515_a2_jws.txt");
const RFC_EC_X: &str = include_str!("fixtures/rfc7515_a3_x.txt");
const RFC_EC_Y: &str = include_str!("fixtures/rfc7515_a3_y.txt");
const RFC_ES256_JWS: &str = include_str!("fixtures/rfc7515_a3_jws.txt");

const ISSUER: &str = "https://id.example.org/application/o/chat/";
const CLIENT: &str = "chat-client";
const NOW: u64 = 1_800_000_000;

/// A fixture JWS is kept as its three parts on three lines (so the file is not a literal token); join them.
fn jws(fixture: &str) -> String {
    fixture.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(".")
}

fn rfc_keys() -> Vec<Key> {
    let jwks = json!({"keys": [
        {"kty": "RSA", "n": RFC_RSA_N.trim(), "e": "AQAB"},
        {"kty": "EC", "crv": "P-256", "x": RFC_EC_X.trim(), "y": RFC_EC_Y.trim()},
    ]});
    parse_jwks(jwks.to_string().as_bytes()).unwrap()
}

#[test]
fn the_rfc_examples_verify_and_any_change_is_caught() {
    let keys = rfc_keys();
    for jws in [jws(RFC_RS256_JWS), jws(RFC_ES256_JWS)] {
        let payload = verify_signature(&jws, &keys).unwrap();
        assert!(String::from_utf8(payload).unwrap().contains("\"iss\":\"joe\""));
        // One changed character in the payload breaks the signature.
        let mut parts: Vec<String> = jws.split('.').map(str::to_owned).collect();
        let first = parts[1].remove(0);
        parts[1].insert(0, if first == 'e' { 'f' } else { 'e' });
        assert!(matches!(verify_signature(&parts.join("."), &keys), Err(Error::BadSignature | Error::Malformed(_))));
    }
    // An RS256 token with only an EC key on offer: no key matches.
    let only_ec: Vec<Key> = keys.iter().filter(|k| matches!(k, Key::P256 { .. })).cloned().collect();
    assert_eq!(verify_signature(&jws(RFC_RS256_JWS), &only_ec), Err(Error::UnknownKey));
}

fn header(alg: &str, kid: Option<&str>) -> String {
    let mut h = json!({"alg": alg, "typ": "JWT"});
    if let Some(kid) = kid {
        h["kid"] = json!(kid);
    }
    URL_SAFE_NO_PAD.encode(h.to_string())
}

#[test]
fn none_and_shared_secret_algorithms_are_refused() {
    let keys = rfc_keys();
    let payload = URL_SAFE_NO_PAD.encode(r#"{"iss":"x"}"#);
    for alg in ["none", "HS256", "RS512", ""] {
        let token = format!("{}.{payload}.{}", header(alg, None), URL_SAFE_NO_PAD.encode(b"sig"));
        assert!(matches!(verify_signature(&token, &keys), Err(Error::Algorithm(_))), "{alg}");
    }
    assert!(matches!(verify_signature("a.b", &keys), Err(Error::Malformed(_))));
    assert!(matches!(verify_signature(&"a".repeat(MAX_DOCUMENT_BYTES + 1), &keys), Err(Error::TooLarge)));
}

/// A provider key made at run time, its JWKS, and a signer for tokens.
struct TestProvider {
    pair: EcdsaKeyPair,
    rng: SystemRandom,
}

impl TestProvider {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        Self { pair, rng }
    }

    fn jwks(&self, kid: &str) -> Vec<Key> {
        let point = self.pair.public_key().as_ref();
        let jwks = json!({"keys": [
            {"kty": "RSA", "use": "enc", "n": "AQAB", "e": "AQAB"},
            {"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"},
            {"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "x": URL_SAFE_NO_PAD.encode(&point[1..33]), "y": URL_SAFE_NO_PAD.encode(&point[33..65])},
        ]});
        let keys = parse_jwks(jwks.to_string().as_bytes()).unwrap();
        assert_eq!(keys.len(), 1, "the encryption key and the P-384 key are skipped");
        keys
    }

    fn token(&self, kid: &str, claims: &serde_json::Value) -> String {
        let signed = format!("{}.{}", header("ES256", Some(kid)), URL_SAFE_NO_PAD.encode(claims.to_string()));
        let signature = self.pair.sign(&self.rng, signed.as_bytes()).unwrap();
        format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.as_ref()))
    }
}

fn good_claims() -> serde_json::Value {
    json!({
        "iss": ISSUER, "aud": CLIENT, "sub": "248289761001", "nonce": "n-0S6_WzA2Mj",
        "exp": NOW + 300, "iat": NOW - 5, "email": "ana@example.org", "email_verified": true, "name": "Ana",
        "amr": ["pwd", "mfa"],
    })
}

fn expected(require_mfa: bool) -> Expected<'static> {
    Expected { issuer: ISSUER, client_id: CLIENT, nonce: "n-0S6_WzA2Mj", now: NOW, require_mfa }
}

#[test]
fn a_good_id_token_gives_the_identity() {
    let provider = TestProvider::new();
    let keys = provider.jwks("k1");
    let identity = verify_id_token(&provider.token("k1", &good_claims()), &keys, &expected(true)).unwrap();
    assert_eq!((identity.issuer.as_str(), identity.subject.as_str()), (ISSUER, "248289761001"));
    assert_eq!((identity.email.as_deref(), identity.email_verified, identity.name.as_deref()), (Some("ana@example.org"), true, Some("Ana")));
    assert_eq!(identity.amr, ["pwd", "mfa"]);
    // A token signed by another key, or naming a key the provider does not have, is refused.
    let other = TestProvider::new();
    assert_eq!(verify_id_token(&other.token("k1", &good_claims()), &keys, &expected(true)), Err(Error::BadSignature));
    assert_eq!(verify_id_token(&provider.token("k2", &good_claims()), &keys, &expected(true)), Err(Error::UnknownKey));
}

#[test]
fn every_claim_is_checked() {
    let provider = TestProvider::new();
    let keys = provider.jwks("k1");
    let check = |edit: &dyn Fn(&mut serde_json::Value), want: Error| {
        let mut claims = good_claims();
        edit(&mut claims);
        assert_eq!(verify_id_token(&provider.token("k1", &claims), &keys, &expected(true)), Err(want.clone()), "{want:?}");
    };
    check(&|c| c["iss"] = json!("https://evil.example.org/"), Error::Claim("iss"));
    check(&|c| c["aud"] = json!("someone-else"), Error::Claim("aud"));
    check(&|c| c["aud"] = json!(["someone-else", CLIENT]), Error::Claim("azp"));
    check(&|c| c["azp"] = json!("someone-else"), Error::Claim("azp"));
    check(&|c| c["exp"] = json!(NOW - LEEWAY_SECS), Error::Claim("exp"));
    check(&|c| c["exp"] = json!("tomorrow"), Error::Claim("exp"));
    check(&|c| c["nbf"] = json!(NOW + LEEWAY_SECS + 1), Error::Claim("nbf"));
    check(&|c| c["iat"] = json!(NOW + LEEWAY_SECS + 1), Error::Claim("iat"));
    check(&|c| c["nonce"] = json!("n-replayed"), Error::Claim("nonce"));
    check(&|c| c["sub"] = json!(""), Error::Claim("sub"));
    check(&|c| c["amr"] = json!(["pwd"]), Error::MfaRequired);
    // Inside the leeway, the times pass; several audiences pass when azp names this client.
    for claims in [
        {
            let mut c = good_claims();
            c["exp"] = json!(NOW - LEEWAY_SECS + 1);
            c
        },
        {
            let mut c = good_claims();
            c["aud"] = json!([CLIENT, "api"]);
            c["azp"] = json!(CLIENT);
            c
        },
    ] {
        assert!(verify_id_token(&provider.token("k1", &claims), &keys, &expected(true)).is_ok());
    }
    // Without the second-factor rule, a password-only sign-in passes the token checks (the authorizer still decides).
    let mut password_only = good_claims();
    password_only["amr"] = json!(["pwd"]);
    assert!(verify_id_token(&provider.token("k1", &password_only), &keys, &expected(false)).is_ok());
}

#[test]
fn the_discovery_document_must_name_the_configured_issuer_over_https() {
    let doc = json!({
        "issuer": ISSUER, "authorization_endpoint": "https://id.example.org/authorize/",
        "token_endpoint": "https://id.example.org/token/", "jwks_uri": "https://id.example.org/jwks/",
    });
    let provider = parse_discovery(doc.to_string().as_bytes(), ISSUER).unwrap();
    assert_eq!(provider.jwks_uri, "https://id.example.org/jwks/");
    assert_eq!(parse_discovery(doc.to_string().as_bytes(), "https://id.example.org/"), Err(Error::IssuerMismatch));
    let mut plain = doc.clone();
    plain["token_endpoint"] = json!("http://id.example.org/token/");
    assert_eq!(parse_discovery(plain.to_string().as_bytes(), ISSUER), Err(Error::NotHttps("token_endpoint")));
    let mut missing = doc;
    missing.as_object_mut().unwrap().remove("jwks_uri");
    assert_eq!(parse_discovery(missing.to_string().as_bytes(), ISSUER), Err(Error::Malformed("jwks_uri")));
    assert_eq!(parse_discovery(b"<html>", ISSUER), Err(Error::Malformed("not JSON")));
    assert_eq!(parse_jwks(br#"{"keys": [{"kty": "oct", "k": "AA"}]}"#), Err(Error::Malformed("keys: no RSA or P-256 signing key")));
}

#[test]
fn pkce_matches_rfc_7636_and_the_url_carries_everything() {
    // RFC 7636 appendix B.
    let random = [
        116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141,
        121,
    ];
    let pair = pkce(random);
    assert_eq!(pair.verifier, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    assert_eq!(pair.challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    assert!(!format!("{pair:?}").contains(&pair.verifier), "Debug hides the verifier");
    assert_eq!(random_value([0; 32]).len(), 43);

    let provider = parse_discovery(
        json!({"issuer": ISSUER, "authorization_endpoint": "https://id.example.org/authorize/?tenant=1",
               "token_endpoint": "https://id.example.org/token/", "jwks_uri": "https://id.example.org/jwks/"})
        .to_string()
        .as_bytes(),
        ISSUER,
    )
    .unwrap();
    let url = authorization_url(
        &provider,
        &Request {
            client_id: CLIENT,
            redirect_uri: "http://127.0.0.1:51234/callback",
            state: "st&te",
            nonce: "n-0S6_WzA2Mj",
            code_challenge: &pair.challenge,
        },
    );
    assert!(url.starts_with("https://id.example.org/authorize/?tenant=1&response_type=code&client_id=chat-client&"), "{url}");
    for part in [
        "redirect_uri=http%3A%2F%2F127.0.0.1%3A51234%2Fcallback",
        "scope=openid%20email%20profile",
        "state=st%26te",
        "nonce=n-0S6_WzA2Mj",
        "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge_method=S256",
    ] {
        assert!(url.contains(part), "{part} missing from {url}");
    }
}
