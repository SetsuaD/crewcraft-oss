#![allow(clippy::unwrap_used)]

use crewcraft_accounts::totp_guard::{GuardError, SKEW_STEPS, TotpGuard};
use crewcraft_totp::Totp;

const SECRET: [u8; 20] = *b"12345678901234567890";

fn code_at(secret: [u8; 20], t: u64) -> String {
    Totp::with_defaults(secret.to_vec()).unwrap().generate(t)
}

#[test]
fn unknown_person_is_not_enrolled() {
    let mut g = TotpGuard::new();
    assert!(!g.is_enrolled("alice@example.org"));
    assert_eq!(g.verify("alice@example.org", "123456", 59).unwrap_err(), GuardError::NotEnrolled);
    assert_eq!(g.last_counter("alice@example.org"), None);
    assert_eq!(g.otpauth_uri("alice@example.org", "CrewCraft"), None);
    assert!(!g.reset("alice@example.org"));
}

#[test]
fn enroll_once_and_accept_a_current_code() {
    let mut g = TotpGuard::new();
    assert!(g.enroll("alice@example.org", SECRET));
    assert!(g.is_enrolled("alice@example.org"));
    assert_eq!(g.last_counter("alice@example.org"), None);
    // RFC 6238: at T=59 the counter is 1.
    let counter = g.verify("alice@example.org", &code_at(SECRET, 59), 59).unwrap();
    assert_eq!(counter, 1);
    assert_eq!(g.last_counter("alice@example.org"), Some(1));
}

#[test]
fn enrolling_twice_changes_nothing() {
    let mut g = TotpGuard::new();
    assert!(g.enroll("alice@example.org", SECRET));
    assert!(!g.enroll("alice@example.org", [9u8; 20]));
    // The first secret still works; the second one never took.
    assert!(g.verify("alice@example.org", &code_at(SECRET, 59), 59).is_ok());
    assert_eq!(g.verify("alice@example.org", &code_at([9u8; 20], 89), 89).unwrap_err(), GuardError::Rejected);
}

#[test]
fn a_code_works_once() {
    let mut g = TotpGuard::new();
    g.enroll("alice@example.org", SECRET);
    let code = code_at(SECRET, 59);
    assert_eq!(g.verify("alice@example.org", &code, 59), Ok(1));
    // The same code again, even a moment later in the same step, is a replay.
    assert_eq!(g.verify("alice@example.org", &code, 60).unwrap_err(), GuardError::Rejected);
    assert_eq!(g.last_counter("alice@example.org"), Some(1));
}

#[test]
fn credential_read_and_counter_commit_support_split_verification() {
    let mut g = TotpGuard::new();
    let person = "alice@example.org";
    assert!(g.credential(person).is_none());
    assert_eq!(g.record_counter(person, 1), Err(GuardError::NotEnrolled));
    assert!(g.enroll(person, SECRET));

    let (totp, last_used) = g.credential(person).unwrap();
    // The RFC 6238 SHA-1 example at T=59 truncated to six digits.
    let counter = totp.verify("287082", 59, SKEW_STEPS, last_used).unwrap();
    assert_eq!(counter, 1);
    assert_eq!(g.last_counter(person), None);

    assert_eq!(g.record_counter(person, counter), Ok(()));
    assert_eq!(g.record_counter(person, counter), Err(GuardError::Rejected));
    assert_eq!(g.record_counter(person, 0), Err(GuardError::Rejected));
    assert_eq!(g.last_counter(person), Some(1));
    assert_eq!(g.verify(person, "287082", 59), Err(GuardError::Rejected));
}

#[test]
fn activation_enrollment_starts_with_the_confirmed_counter() {
    let mut g = TotpGuard::new();
    let person = "alice@example.org";
    assert!(g.enroll_with_counter(person, SECRET, 1));
    assert!(!g.enroll_with_counter(person, [9; 20], 3));
    assert_eq!(g.last_counter(person), Some(1));
    assert_eq!(g.verify(person, "287082", 59), Err(GuardError::Rejected));
    assert_eq!(g.verify(person, &code_at(SECRET, 89), 89), Ok(2));
}

#[test]
fn an_older_counter_is_rejected_after_a_newer_one() {
    let mut g = TotpGuard::new();
    g.enroll("alice@example.org", SECRET);
    // Accept the code for counter 3 (T=90..119), then the code for counter 2 (still inside the skew window) is refused.
    let three = code_at(SECRET, 100);
    let two = code_at(SECRET, 70);
    assert_eq!(g.verify("alice@example.org", &three, 100), Ok(3));
    assert_eq!(g.verify("alice@example.org", &two, 100).unwrap_err(), GuardError::Rejected);
    // A newer counter than the last accepted one is fine: the code for counter 4 at the same clock (one step ahead).
    let four = code_at(SECRET, 130);
    assert_eq!(g.verify("alice@example.org", &four, 100), Ok(4));
}

#[test]
fn skew_window_is_one_step_either_side() {
    assert_eq!(SKEW_STEPS, 1);
    let mut g = TotpGuard::new();
    g.enroll("alice@example.org", SECRET);
    // Clock says T=100 (counter 3). Counter 1 (two steps behind) is outside the window.
    assert_eq!(g.verify("alice@example.org", &code_at(SECRET, 59), 100).unwrap_err(), GuardError::Rejected);
    // Counter 2 (one behind) is inside it.
    assert_eq!(g.verify("alice@example.org", &code_at(SECRET, 70), 100), Ok(2));
    // Counter 5 (two ahead) is outside the window; counter 4 (one ahead) is inside.
    assert_eq!(g.verify("alice@example.org", &code_at(SECRET, 150), 100).unwrap_err(), GuardError::Rejected);
    assert_eq!(g.verify("alice@example.org", &code_at(SECRET, 130), 100), Ok(4));
}

#[test]
fn wrong_and_malformed_codes_change_nothing() {
    let mut g = TotpGuard::new();
    g.enroll("alice@example.org", SECRET);
    for bad in ["", "12345", "1234567", "abcdef", "12 456"] {
        assert_eq!(g.verify("alice@example.org", bad, 59).unwrap_err(), GuardError::Rejected, "code {bad:?}");
    }
    assert_eq!(g.last_counter("alice@example.org"), None);
    // A rejected attempt did not burn the right code.
    assert_eq!(g.verify("alice@example.org", &code_at(SECRET, 59), 59), Ok(1));
}

#[test]
fn people_are_independent() {
    let mut g = TotpGuard::new();
    g.enroll("alice@example.org", SECRET);
    g.enroll("bob@example.org", [5u8; 20]);
    let a = code_at(SECRET, 59);
    assert_eq!(g.verify("alice@example.org", &a, 59), Ok(1));
    // Bob can still use the same step; alice's code is not bob's.
    assert_eq!(g.verify("bob@example.org", &a, 59).unwrap_err(), GuardError::Rejected);
    assert_eq!(g.verify("bob@example.org", &code_at([5u8; 20], 59), 59), Ok(1));
}

#[test]
fn reset_forgets_the_enrollment() {
    let mut g = TotpGuard::new();
    g.enroll("alice@example.org", SECRET);
    g.verify("alice@example.org", &code_at(SECRET, 59), 59).unwrap();
    assert!(g.reset("alice@example.org"));
    assert!(!g.is_enrolled("alice@example.org"));
    assert_eq!(g.verify("alice@example.org", &code_at(SECRET, 89), 89).unwrap_err(), GuardError::NotEnrolled);
    // Enrolling again starts with no counter used, so the new enrollment accepts a step the old one had burned.
    assert!(g.enroll("alice@example.org", [8u8; 20]));
    assert_eq!(g.last_counter("alice@example.org"), None);
    assert_eq!(g.verify("alice@example.org", &code_at([8u8; 20], 59), 59), Ok(1));
}

#[test]
fn otpauth_uri_names_issuer_and_person_and_keeps_the_secret_out_of_debug() {
    let mut g = TotpGuard::new();
    g.enroll("alice@example.org", SECRET);
    let uri = g.otpauth_uri("alice@example.org", "CrewCraft").unwrap();
    assert!(uri.starts_with("otpauth://totp/"));
    assert!(uri.contains("CrewCraft"));
    assert!(uri.contains("alice%40example.org") || uri.contains("alice@example.org"));
    let (_, query) = uri.split_once('?').unwrap();
    let encoded = query.split('&').find_map(|field| field.strip_prefix("secret=")).unwrap();
    assert!(crewcraft_totp::base32::decode(encoded).unwrap() == SECRET);
    assert_eq!(format!("{g:?}"), "TotpGuard(..)");
}
