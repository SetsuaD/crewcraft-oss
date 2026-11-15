#![allow(clippy::unwrap_used)]

use crewcraft_accounts::password::MAX_BYTES;
use crewcraft_accounts::sign_in::{Credentials, OwnAccount, VerifiedOwnSignIn, verify_own};
use crewcraft_totp::Totp;

const USER: &str = "reader@example.org";
const OTHER: &str = "other@example.org";
const PASSWORD: &str = "correct horse battery staple";
// The same independently generated Argon2id vectors as T007.
const CURRENT_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$Y3Jld2NyYWZ0LXNhbHQwMQ$reWbIjus4zPfBBm9gelZEvvzOp86eq//UI67BZupQc8";
const OLD_HASH: &str = "$argon2id$v=19$m=8192,t=1,p=1$Y3Jld2NyYWZ0LXNhbHQwMQ$ChVyoyseMrvyQ6S3sldHsRU5aSO3p6LHok9S74ItzTA";
// Six-digit form of RFC 6238 Appendix B's SHA-1 vector at Unix time 59.
const CODE: &str = "287082";
const NOW: u64 = 59;

fn totp() -> Totp {
    Totp::with_defaults(b"12345678901234567890".to_vec()).unwrap()
}

fn attempt<'a>(email: &'a str, password: &'a str, code: &'a str) -> Credentials<'a> {
    Credentials { email, password, code }
}

#[test]
fn verifies_a_normalized_identity_and_requires_the_enrolled_person() {
    let totp = totp();
    let account = OwnAccount { email: USER, password_hash: CURRENT_HASH, totp: &totp, last_totp_counter: None };
    assert_eq!(
        verify_own(Some(USER), Some(&account), attempt(" Reader@EXAMPLE.ORG ", PASSWORD, CODE), NOW),
        Some(VerifiedOwnSignIn { accepted_counter: 1, needs_password_rehash: false })
    );
    for device_email in [None, Some(OTHER)] {
        assert_eq!(verify_own(device_email, Some(&account), attempt(USER, PASSWORD, CODE), NOW), None);
    }
    for entered_email in [OTHER, "bad address"] {
        assert_eq!(verify_own(Some(USER), Some(&account), attempt(entered_email, PASSWORD, CODE), NOW), None);
    }
    assert_eq!(verify_own(Some(USER), None, attempt(USER, PASSWORD, CODE), NOW), None);

    let other_account = OwnAccount { email: OTHER, ..account };
    assert_eq!(verify_own(Some(USER), Some(&other_account), attempt(OTHER, PASSWORD, CODE), NOW), None);
}

#[test]
fn requires_both_factors_and_rejects_a_committed_counter() {
    let totp = totp();
    let mut account = OwnAccount { email: USER, password_hash: CURRENT_HASH, totp: &totp, last_totp_counter: None };

    assert_eq!(verify_own(Some(USER), Some(&account), attempt(USER, "wrong password", CODE), NOW), None);
    assert_eq!(verify_own(Some(USER), Some(&account), attempt(USER, PASSWORD, "invalid"), NOW), None);
    assert_eq!(verify_own(Some(USER), Some(&account), attempt(USER, PASSWORD, "287083"), NOW), None);
    assert_eq!(verify_own(Some(USER), Some(&account), attempt(USER, PASSWORD, CODE), 90), None);

    let accepted = verify_own(Some(USER), Some(&account), attempt(USER, PASSWORD, CODE), 60).unwrap();
    assert_eq!(accepted.accepted_counter, 1);
    account.last_totp_counter = Some(accepted.accepted_counter);
    assert_eq!(verify_own(Some(USER), Some(&account), attempt(USER, PASSWORD, CODE), 60), None);
}

#[test]
fn reports_rehash_only_after_a_successful_sign_in() {
    let totp = totp();
    let account = OwnAccount { email: USER, password_hash: OLD_HASH, totp: &totp, last_totp_counter: None };
    assert_eq!(
        verify_own(Some(USER), Some(&account), attempt(USER, PASSWORD, CODE), NOW),
        Some(VerifiedOwnSignIn { accepted_counter: 1, needs_password_rehash: true })
    );
    assert_eq!(verify_own(Some(USER), Some(&account), attempt(USER, "wrong password", CODE), NOW), None);

    let overlong = "a".repeat(MAX_BYTES + 1);
    assert_eq!(verify_own(Some(USER), Some(&account), attempt(USER, &overlong, CODE), NOW), None);
    let malformed = OwnAccount { password_hash: "invalid hash", ..account };
    assert_eq!(verify_own(Some(USER), Some(&malformed), attempt(USER, PASSWORD, CODE), NOW), None);
}
