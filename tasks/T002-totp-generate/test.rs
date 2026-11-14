// T002: TOTP generation. Vectors: RFC 4226 appendix D (HOTP) and RFC 6238 appendix B (TOTP, 8 digits).
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_totp::{Algorithm, Totp};

const SHA1_KEY: &[u8] = b"12345678901234567890";
const SHA256_KEY: &[u8] = b"12345678901234567890123456789012";
const SHA512_KEY: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";
const TIMES: [u64; 6] = [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000];

#[test]
fn hotp_matches_rfc4226() {
    let t = Totp::new(SHA1_KEY.to_vec(), Algorithm::Sha1, 6, 30).unwrap();
    let want = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
    for (counter, code) in want.iter().enumerate() {
        assert_eq!(t.generate_at_counter(counter as u64), *code, "counter {counter}");
    }
}

fn check(key: &[u8], alg: Algorithm, want: [&str; 6]) {
    let t = Totp::new(key.to_vec(), alg, 8, 30).unwrap();
    for (time, code) in TIMES.iter().zip(want) {
        assert_eq!(t.generate(*time), code, "{alg:?} at {time}");
    }
}

#[test]
fn totp_sha1_matches_rfc6238() {
    check(SHA1_KEY, Algorithm::Sha1, ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"]);
}

#[test]
fn totp_sha256_matches_rfc6238() {
    check(SHA256_KEY, Algorithm::Sha256, ["46119246", "68084774", "67062674", "91819424", "90698825", "77737706"]);
}

#[test]
fn totp_sha512_matches_rfc6238() {
    check(SHA512_KEY, Algorithm::Sha512, ["90693936", "25091201", "99943326", "93441116", "38618901", "47863826"]);
}

#[test]
fn six_digit_codes_keep_leading_zeros() {
    let t = Totp::new(SHA1_KEY.to_vec(), Algorithm::Sha1, 6, 30).unwrap();
    // RFC 6238 vector 07081804 truncated to 6 digits is 081804.
    assert_eq!(t.generate(1111111109), "081804");
}
