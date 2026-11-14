// T006: the bootstrap key seed, HKDF-SHA256(ikm = secret, salt = "crewcraft-enroll-v1", info = "bootstrap-ed25519", 32 bytes).
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_enroll::EnrollmentCode;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn seed_for_zero_secret() {
    let seed = EnrollmentCode::from_bytes([0; 20]).bootstrap_seed();
    assert_eq!(hex(&seed), "9b3c34116be905da4db737780182c4b19ad75c8623abc593d5ef1b3b25433ac9");
}

#[test]
fn seed_for_counting_secret() {
    let mut b = [0u8; 20];
    for (i, x) in b.iter_mut().enumerate() {
        *x = i as u8 + 1;
    }
    assert_eq!(hex(&EnrollmentCode::from_bytes(b).bootstrap_seed()), "98d7da217237b322f2b7d4f94aaf73123f104157e6ab90dc904db2f1f4df6d59");
}

#[test]
fn different_secrets_give_different_seeds() {
    let a = EnrollmentCode::from_bytes([1; 20]).bootstrap_seed();
    let b = EnrollmentCode::from_bytes([2; 20]).bootstrap_seed();
    assert_ne!(a, b);
}
