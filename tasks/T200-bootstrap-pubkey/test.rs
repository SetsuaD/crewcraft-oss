#![allow(clippy::unwrap_used)]

use crewcraft_enroll::{EnrollmentCode, bootstrap_public_key};

fn hex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64);
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// RFC 8032 section 7.1, TEST 1: the secret key (seed) and the public key it must give.
#[test]
fn rfc8032_test_1() {
    let seed = hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let public = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    assert_eq!(bootstrap_public_key(&seed), public);
}

/// RFC 8032 section 7.1, TEST 2.
#[test]
fn rfc8032_test_2() {
    let seed = hex32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    let public = hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    assert_eq!(bootstrap_public_key(&seed), public);
}

/// The code's own method is the function applied to the code's HKDF seed, so server and client agree.
#[test]
fn code_method_is_the_function_of_its_seed() {
    let code = EnrollmentCode::from_bytes([7u8; 20]);
    assert_eq!(code.bootstrap_public_key(), bootstrap_public_key(&code.bootstrap_seed()));
    // Deterministic: asking twice gives the same key.
    assert_eq!(code.bootstrap_public_key(), code.bootstrap_public_key());
}

/// Different codes give different keys, and the key is not the seed (it is a public value, the seed is secret).
#[test]
fn different_codes_give_different_keys() {
    let a = EnrollmentCode::from_bytes([1u8; 20]);
    let b = EnrollmentCode::from_bytes([2u8; 20]);
    assert_ne!(a.bootstrap_public_key(), b.bootstrap_public_key());
    assert_ne!(a.bootstrap_public_key(), a.bootstrap_seed());
}
