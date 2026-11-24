//! T502: the release keys a CrewCraft build trusts are pinned in the source, as valid Ed25519 public keys, and make
//! the check `open_release` uses. No private key appears anywhere.
#![allow(clippy::unwrap_used)]

use crewcraft_update::SignatureCheck;
use crewcraft_update::ed25519::{MAX_RELEASE_KEYS, PINNED_RELEASE_KEYS, ReleaseKeys, pinned_release_keys};

#[test]
fn the_pinned_keys_are_valid_and_distinct() {
    assert!(!PINNED_RELEASE_KEYS.is_empty() && PINNED_RELEASE_KEYS.len() <= MAX_RELEASE_KEYS);
    for key in PINNED_RELEASE_KEYS {
        assert_eq!(key.len(), 64, "{key}");
        assert!(key.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)), "lowercase hex: {key}");
    }
    let pinned = pinned_release_keys().unwrap();
    assert_eq!(pinned.len(), PINNED_RELEASE_KEYS.len());
    assert_eq!(ReleaseKeys::from_hex(PINNED_RELEASE_KEYS).unwrap().len(), pinned.len());
}

#[test]
fn release_key_1_is_pinned() {
    assert!(PINNED_RELEASE_KEYS.contains(&"4e80d59df55a73d42cea0e49ab61aeaee0ef784e057aeff873f1035cba32f2bf"));
}

#[test]
fn a_signature_by_no_pinned_key_is_refused() {
    let pinned = pinned_release_keys().unwrap();
    assert!(!pinned.verify(b"[release]\n", &[0u8; 64]));
    assert!(!pinned.verify(b"[release]\n", &[]));
}
