// T009: PKCE S256 (RFC 7636) for the companion-app sign-in. Expected challenges computed with Python's hashlib and
// base64 (urlsafe, padding stripped), independently of the Rust crates the task uses.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_accounts::Error;
use crewcraft_accounts::oidc::{pkce_challenge, verify_pkce};

const V43: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const C43: &str = "ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNA";
const V128: &str = "0123456789-._~ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv";
const C128: &str = "c6oXrdqiWbOlwmm5L5YXyAawt0_neGXXnTePABatxGw";

#[test]
fn challenge_vectors() {
    assert_eq!(V43.len(), 43);
    assert_eq!(V128.len(), 128);
    assert_eq!(pkce_challenge(V43).unwrap(), C43);
    assert_eq!(pkce_challenge(V128).unwrap(), C128);
}

#[test]
fn challenge_is_unpadded_base64url() {
    let c = pkce_challenge(V128).unwrap();
    assert_eq!(c.len(), 43);
    assert!(c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'), "{c}");
}

#[test]
fn verifier_rules() {
    assert_eq!(pkce_challenge(&"a".repeat(42)), Err(Error::BadVerifier));
    assert_eq!(pkce_challenge(&"a".repeat(129)), Err(Error::BadVerifier));
    for bad in ["+", "/", "=", " ", "\u{e9}"] {
        let v = format!("{}{bad}", "a".repeat(42));
        assert_eq!(pkce_challenge(&v), Err(Error::BadVerifier), "{v:?}");
    }
}

#[test]
fn verify_matches_only_the_right_pair() {
    assert!(verify_pkce(V43, C43));
    assert!(verify_pkce(V128, C128));
    assert!(!verify_pkce(V43, C128));
    assert!(!verify_pkce(V43, &C43.to_lowercase()));
    assert!(!verify_pkce(V43, ""));
    assert!(!verify_pkce(&"a".repeat(42), C43)); // invalid verifier never verifies
    assert!(!verify_pkce(V43, &format!("{C43}=")));
}
