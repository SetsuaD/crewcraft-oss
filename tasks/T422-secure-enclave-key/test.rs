//! T422: the iOS Keychain hands out a public key as a bare 65-byte point; `p256_spki` wraps it as the
//! SubjectPublicKeyInfo the rest of the client uses, and refuses anything else. On iOS itself (the simulator or a
//! phone, not the build machine) the Keychain key store makes, finds, uses and deletes a key. The whole enrollment
//! flow is T403's test, and the simulator self-test (docs/MOBILE.md) runs it against a real server.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft::hardware_key::{HardwareKeys, MemoryKeys, P256_SPKI_BYTES, p256_point, p256_spki};

#[test]
fn a_bare_point_becomes_a_p256_public_key() {
    let keys = MemoryKeys::new();
    let key = keys.generate("crewcraft-default-t422").unwrap();
    let point = p256_point(key.public_key()).unwrap().to_vec();
    let spki = p256_spki(&point).unwrap();
    assert_eq!(spki.len(), P256_SPKI_BYTES);
    assert_eq!(spki, key.public_key(), "the same SubjectPublicKeyInfo the key store gave");
    assert_eq!(p256_point(&spki), Some(&point[..]));

    let mut compressed = point.clone();
    compressed[0] = 0x02;
    assert_eq!(p256_spki(&compressed), None, "only an uncompressed point");
    assert_eq!(p256_spki(&point[..64]), None);
    assert_eq!(p256_spki(&[point.clone(), vec![0]].concat()), None);
    assert_eq!(p256_spki(&[]), None);
}

#[cfg(target_os = "ios")]
#[test]
fn the_keychain_keeps_a_key_by_alias() {
    use crewcraft::ios_keys::IosKeychain;
    let keys = IosKeychain::new();
    let alias = crewcraft::hardware_key::new_alias("t422");
    let key = keys.generate(&alias).unwrap();
    assert!(p256_point(key.public_key()).is_some());
    let again = keys.open(&alias).unwrap();
    assert_eq!(again.public_key(), key.public_key());
    assert!(!again.sign(b"message").unwrap().is_empty());
    assert!(keys.delete(&alias).unwrap());
    assert!(keys.open(&alias).is_err());
}
