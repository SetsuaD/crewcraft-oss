//! The Ed25519 `SignatureCheck` over the pinned release keys (REQUIREMENTS 2.21, ROADMAP M5).
//!
//! Owns: turning a list of trusted release public keys into a `SignatureCheck`, and checking a detached signature (64
//! raw bytes, RFC 8032) over the exact manifest bytes with `verify_strict`, which also refuses small-order keys and
//! non-canonical signatures. Holds no private key: release signing happens in the release tooling, never on a server
//! or client.
//! Called by: `open_release` callers (the server's self-update, every client's updater), through `ReleaseKeys`.
//!
//! Several keys may be pinned at once so a release key can be rotated: a release signed by any pinned key is accepted.
//! The implementation is `ed25519-dalek` 2 (pure Rust, BSD-3-Clause), the same crate the enrollment code uses for the
//! bootstrap key, so the workspace has one Ed25519 implementation.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::SignatureCheck;

/// The length of a release public key.
pub const PUBLIC_KEY_BYTES: usize = 32;
/// The length of a detached release signature.
pub const SIGNATURE_BYTES: usize = 64;
/// The most release keys that may be pinned at once (the current key, its successor, and room for an emergency key).
pub const MAX_RELEASE_KEYS: usize = 8;

/// The public halves of CrewCraft's release keys (task T502), as 64 hex characters. A server or app built from this
/// source installs only releases signed by one of them. To replace a key, add its successor here one release before
/// signing with it, then remove the old one (docs/RELEASE.md).
pub const PINNED_RELEASE_KEYS: &[&str] = &[
    // Release key 1, made 2026-11-24.
    "4e80d59df55a73d42cea0e49ab61aeaee0ef784e057aeff873f1035cba32f2bf",
];

/// `PINNED_RELEASE_KEYS` as a `SignatureCheck`.
pub fn pinned_release_keys() -> Result<ReleaseKeys, KeyError> {
    ReleaseKeys::from_hex(PINNED_RELEASE_KEYS)
}

/// Why a list of release keys was refused. The index is the key's position in the list given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// No key was given: nothing could ever be accepted, which is a configuration error, not a policy.
    NoKeys,
    /// More than `MAX_RELEASE_KEYS` keys.
    TooMany,
    /// Not a valid Ed25519 public key (not a point on the curve, or not hex of the right length).
    NotAKey(usize),
    /// A small-order ("weak") key, for which signatures can be forged.
    Weak(usize),
    /// The same key appears twice.
    Duplicate(usize),
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::NoKeys => f.write_str("no release key is pinned"),
            KeyError::TooMany => write!(f, "more than {MAX_RELEASE_KEYS} release keys"),
            KeyError::NotAKey(i) => write!(f, "release key {i} is not an Ed25519 public key"),
            KeyError::Weak(i) => write!(f, "release key {i} is a weak (small-order) key"),
            KeyError::Duplicate(i) => write!(f, "release key {i} is listed twice"),
        }
    }
}

impl std::error::Error for KeyError {}

/// The trusted release keys. Build once from the pinned list and pass to `open_release`.
#[derive(Debug, Clone)]
pub struct ReleaseKeys {
    keys: Vec<VerifyingKey>,
}

impl ReleaseKeys {
    /// Accept 1 to `MAX_RELEASE_KEYS` distinct, valid, non-weak public keys.
    pub fn new(keys: &[[u8; PUBLIC_KEY_BYTES]]) -> Result<Self, KeyError> {
        if keys.is_empty() {
            return Err(KeyError::NoKeys);
        }
        if keys.len() > MAX_RELEASE_KEYS {
            return Err(KeyError::TooMany);
        }
        let mut out: Vec<VerifyingKey> = Vec::with_capacity(keys.len());
        for (i, bytes) in keys.iter().enumerate() {
            let key = VerifyingKey::from_bytes(bytes).map_err(|_| KeyError::NotAKey(i))?;
            if key.is_weak() {
                return Err(KeyError::Weak(i));
            }
            if out.iter().any(|k| k.as_bytes() == key.as_bytes()) {
                return Err(KeyError::Duplicate(i));
            }
            out.push(key);
        }
        Ok(ReleaseKeys { keys: out })
    }

    /// The same, from 64-character lowercase or uppercase hex strings (how keys are pinned in source and config).
    pub fn from_hex(keys: &[&str]) -> Result<Self, KeyError> {
        let mut raw = Vec::with_capacity(keys.len());
        for (i, text) in keys.iter().enumerate() {
            raw.push(parse_hex_key(text).ok_or(KeyError::NotAKey(i))?);
        }
        Self::new(&raw)
    }

    /// How many keys are pinned.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Never true: `new` refuses an empty list. Present for the `len` convention.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl SignatureCheck for ReleaseKeys {
    /// True only for a 64-byte signature that `verify_strict` accepts under one of the pinned keys.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(bytes) = <[u8; SIGNATURE_BYTES]>::try_from(signature) else {
            return false;
        };
        let signature = Signature::from_bytes(&bytes);
        self.keys.iter().any(|key| key.verify_strict(message, &signature).is_ok())
    }
}

/// 64 hex characters to 32 bytes; anything else is `None`.
fn parse_hex_key(text: &str) -> Option<[u8; PUBLIC_KEY_BYTES]> {
    let text = text.as_bytes();
    if text.len() != 2 * PUBLIC_KEY_BYTES {
        return None;
    }
    let (pairs, rest) = text.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let mut out = [0u8; PUBLIC_KEY_BYTES];
    for (byte, [hi, lo]) in out.iter_mut().zip(pairs) {
        let hi = (*hi as char).to_digit(16)?;
        let lo = (*lo as char).to_digit(16)?;
        *byte = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}
