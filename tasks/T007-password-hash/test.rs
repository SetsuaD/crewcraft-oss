// T007: Argon2id password hashing. Expected strings computed with the reference C implementation (argon2-cffi 23.1.0,
// phc-winner-argon2), independently of the Rust crate the task uses.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_accounts::Error;
use crewcraft_accounts::password::{MAX_BYTES, check_policy, hash, hash_with_salt, needs_rehash, verify};

const PW1: &str = "correct horse battery staple";
const H1: &str = "$argon2id$v=19$m=19456,t=2,p=1$Y3Jld2NyYWZ0LXNhbHQwMQ$reWbIjus4zPfBBm9gelZEvvzOp86eq//UI67BZupQc8";
const PW2: &str = "p\u{e4}ssw\u{f6}rd-\u{20ac}-12";
const H2: &str = "$argon2id$v=19$m=19456,t=2,p=1$AAECAwQFBgcICQoLDA0ODw$XxA0hoBDjglqEN5fTI0z046WjFiTiN9mhnWI7r5apSc";
// The same password under weaker parameters (m=8192, t=1): still verifies, but must be rehashed.
const H_WEAK: &str = "$argon2id$v=19$m=8192,t=1,p=1$Y3Jld2NyYWZ0LXNhbHQwMQ$ChVyoyseMrvyQ6S3sldHsRU5aSO3p6LHok9S74ItzTA";

#[test]
fn hash_with_salt_matches_reference_vectors() {
    assert_eq!(hash_with_salt(PW1, b"crewcraft-salt01").unwrap(), H1);
    let salt: Vec<u8> = (0u8..16).collect();
    assert_eq!(hash_with_salt(PW2, &salt).unwrap(), H2);
}

#[test]
fn verify_accepts_right_and_rejects_wrong() {
    assert_eq!(verify(PW1, H1), Ok(true));
    assert_eq!(verify(PW2, H2), Ok(true));
    assert_eq!(verify("correct horse battery stapl", H1), Ok(false));
    assert_eq!(verify(PW1, H2), Ok(false));
    assert_eq!(verify(PW1, H_WEAK), Ok(true)); // old parameters still verify
}

#[test]
fn verify_refuses_anything_but_argon2id() {
    assert_eq!(verify(PW1, "not a hash"), Err(Error::BadHash));
    assert_eq!(verify(PW1, "$2b$12$abcdefghijklmnopqrstuuJ3oXQ8s3q8yQ2n9t3s1rC0C4nX5T6d."), Err(Error::BadHash)); // bcrypt
    let argon2i = H1.replacen("$argon2id$", "$argon2i$", 1);
    assert_eq!(verify(PW1, &argon2i), Err(Error::BadHash));
}

#[test]
fn needs_rehash_flags_weak_or_foreign_hashes() {
    assert!(!needs_rehash(H1));
    assert!(!needs_rehash(H2));
    assert!(needs_rehash(H_WEAK));
    assert!(needs_rehash("not a hash"));
}

#[test]
fn policy_counts_characters_and_caps_bytes() {
    assert_eq!(check_policy("elevenchars"), Err(Error::PasswordTooShort));
    assert_eq!(check_policy("twelve chars"), Ok(()));
    assert_eq!(check_policy("\u{e4}\u{e4}\u{e4}\u{e4}\u{e4}\u{e4}\u{e4}\u{e4}\u{e4}\u{e4}\u{e4}\u{e4}"), Ok(())); // 12 chars, 24 bytes
    assert_eq!(check_policy(&"a".repeat(MAX_BYTES)), Ok(()));
    assert_eq!(check_policy(&"a".repeat(MAX_BYTES + 1)), Err(Error::PasswordTooLong));
    assert_eq!(hash_with_salt("short", b"crewcraft-salt01"), Err(Error::PasswordTooShort));
}

#[test]
fn hash_uses_a_fresh_salt_and_current_parameters() {
    let a = hash(PW1).unwrap();
    let b = hash(PW1).unwrap();
    assert_ne!(a, b);
    for h in [&a, &b] {
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{h}");
        assert_eq!(verify(PW1, h), Ok(true));
        assert!(!needs_rehash(h));
    }
}
