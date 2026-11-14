//! Password hashing: Argon2id (RFC 9106) in the PHC string format, via the RustCrypto `argon2` crate.
//!
//! Parameters are the OWASP minimum for Argon2id: 19 MiB of memory, 2 iterations, 1 lane, a 16-byte random salt and
//! a 32-byte tag. A stored hash with weaker parameters still verifies, and [`needs_rehash`] says to replace it at the
//! next successful sign-in. Passwords are checked against the policy only when they are set, never when verified.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, Salt, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};

use crate::Error;

/// Argon2id memory cost in KiB.
pub const MEMORY_KIB: u32 = 19_456;
/// Argon2id iterations.
pub const ITERATIONS: u32 = 2;
/// Argon2id lanes.
pub const LANES: u32 = 1;
/// Shortest accepted password, in Unicode scalar values (NIST SP 800-63B allows 8; CrewCraft asks for 12).
pub const MIN_CHARS: usize = 12;
/// Longest accepted password, in bytes of UTF-8 (bounds the work an attacker can make the server do).
pub const MAX_BYTES: usize = 1024;

#[allow(clippy::expect_used)]
fn make_params() -> Params {
    // These constants are valid by construction (all > 0, output length is a power of 2 in range).
    Params::new(MEMORY_KIB, ITERATIONS, LANES, Some(32)).expect("valid argon2 parameters")
}

fn hasher() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, make_params())
}

/// Policy for a NEW password: at least [`MIN_CHARS`] characters and at most [`MAX_BYTES`] bytes. Nothing else
/// (no composition rules, NIST SP 800-63B).
pub fn check_policy(password: &str) -> Result<(), Error> {
    if password.chars().count() < MIN_CHARS {
        return Err(Error::PasswordTooShort);
    }
    if password.len() > MAX_BYTES {
        return Err(Error::PasswordTooLong);
    }
    Ok(())
}

/// Hash a new password with a caller-chosen salt (8 to 64 bytes). Checks the policy first. Deterministic, so tests
/// can compare against reference vectors; the server uses [`hash`].
pub fn hash_with_salt(password: &str, salt: &[u8]) -> Result<String, Error> {
    check_policy(password)?;
    let salt_b64 = SaltString::encode_b64(salt).map_err(|_| Error::Hashing)?;
    let salt = Salt::from_b64(salt_b64.as_str()).map_err(|_| Error::Hashing)?;
    let hash = hasher().hash_password(password.as_bytes(), salt).map_err(|_| Error::Hashing)?;
    Ok(hash.to_string())
}

/// Hash a new password with a fresh 16-byte salt from the operating system's random number generator.
pub fn hash(password: &str) -> Result<String, Error> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    hash_with_salt(password, &salt)
}

/// Does `password` match the stored PHC string? `Err(BadHash)` when `phc` is not an Argon2id PHC string.
pub fn verify(password: &str, phc: &str) -> Result<bool, Error> {
    let stored = PasswordHash::new(phc).map_err(|_| Error::BadHash)?;
    if stored.algorithm.as_str() != "argon2id" {
        return Err(Error::BadHash);
    }
    let argon2 = hasher();
    match argon2.verify_password(password.as_bytes(), &stored) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

fn parse_param(params_str: &str, key: &str) -> Option<u32> {
    for part in params_str.split(',') {
        let mut iter = part.splitn(2, '=');
        if iter.next() == Some(key) {
            return iter.next().and_then(|v| v.parse().ok());
        }
    }
    None
}

/// Should this stored hash be replaced? True when it does not parse, is not Argon2id, or any of its memory,
/// iteration or lane costs is below this module's constants.
pub fn needs_rehash(phc: &str) -> bool {
    let stored = match PasswordHash::new(phc) {
        Ok(h) => h,
        Err(_) => return true,
    };
    if stored.algorithm.as_str() != "argon2id" {
        return true;
    }
    let params_str = stored.params.as_str();
    let m = parse_param(params_str, "m").unwrap_or(0);
    let t = parse_param(params_str, "t").unwrap_or(0);
    let p = parse_param(params_str, "p").unwrap_or(0);
    m < MEMORY_KIB || t < ITERATIONS || p < LANES
}
