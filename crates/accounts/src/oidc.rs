//! The server side of "Sign in with CrewCraft" for companion apps (docs/SECURITY-DESIGN.md section 8).
//!
//! Only PKCE S256 (RFC 7636) is supported: the companion app sends `code_challenge = BASE64URL(SHA-256(verifier))`
//! with the authorize request and the verifier itself with the token request; the server recomputes and compares.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::Error;

/// Shortest and longest code verifier (RFC 7636 section 4.1).
pub const VERIFIER_MIN: usize = 43;
pub const VERIFIER_MAX: usize = 128;

fn is_valid_verifier(verifier: &str) -> bool {
    if !((VERIFIER_MIN..=VERIFIER_MAX).contains(&verifier.len())) {
        return false;
    }

    verifier.bytes().all(|b| {
        matches!(
            b,
            b'A'..=b'Z'
                | b'a'..=b'z'
                | b'0'..=b'9'
                | b'-'
                | b'.'
                | b'_'
                | b'~'
        )
    })
}

/// The S256 challenge for a verifier: base64url without padding of SHA-256 of the verifier's ASCII bytes.
/// `Err(BadVerifier)` unless the verifier is 43 to 128 characters of `A-Z a-z 0-9 - . _ ~`.
pub fn pkce_challenge(verifier: &str) -> Result<String, Error> {
    if !is_valid_verifier(verifier) {
        return Err(Error::BadVerifier);
    }

    let digest = Sha256::digest(verifier.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

/// Does `verifier` produce `challenge`? False for an invalid verifier. Compares in constant time (subtle).
pub fn verify_pkce(verifier: &str, challenge: &str) -> bool {
    match pkce_challenge(verifier) {
        Ok(computed) => computed.as_bytes().ct_eq(challenge.as_bytes()).into(),
        Err(_) => false,
    }
}
