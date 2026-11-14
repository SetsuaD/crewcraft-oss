// T003: verification with a skew window and replay protection.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_totp::Totp;

fn totp() -> Totp {
    Totp::with_defaults(b"12345678901234567890".to_vec()).unwrap()
}

#[test]
fn accepts_the_current_code() {
    let t = totp();
    let now = 1_111_111_111;
    assert_eq!(t.verify(&t.generate(now), now, 1, None), Some(t.counter(now)));
}

#[test]
fn accepts_one_step_either_side_with_skew_one() {
    let t = totp();
    let now = 1_111_111_111;
    let c = t.counter(now);
    assert_eq!(t.verify(&t.generate_at_counter(c - 1), now, 1, None), Some(c - 1));
    assert_eq!(t.verify(&t.generate_at_counter(c + 1), now, 1, None), Some(c + 1));
}

#[test]
fn rejects_codes_outside_the_window() {
    let t = totp();
    let now = 1_111_111_111;
    let c = t.counter(now);
    assert_eq!(t.verify(&t.generate_at_counter(c - 2), now, 1, None), None);
    assert_eq!(t.verify(&t.generate_at_counter(c + 2), now, 1, None), None);
    assert_eq!(t.verify(&t.generate_at_counter(c + 1), now, 0, None), None);
}

#[test]
fn rejects_replay_of_a_used_counter() {
    let t = totp();
    let now = 1_111_111_111;
    let c = t.counter(now);
    let code = t.generate(now);
    assert_eq!(t.verify(&code, now, 1, Some(c)), None, "same counter again");
    assert_eq!(t.verify(&t.generate_at_counter(c - 1), now, 1, Some(c)), None, "older counter");
    assert_eq!(t.verify(&code, now, 1, Some(c - 1)), Some(c), "newer than last used is fine");
}

#[test]
fn rejects_malformed_codes() {
    let t = totp();
    let now = 1_111_111_111;
    let code = t.generate(now);
    assert_eq!(t.verify(&code[..5], now, 1, None), None, "too short");
    assert_eq!(t.verify(&format!("{code}0"), now, 1, None), None, "too long");
    assert_eq!(t.verify("12a456", now, 1, None), None, "non-digit");
    assert_eq!(t.verify("", now, 1, None), None, "empty");
}

#[test]
fn window_does_not_underflow_near_epoch() {
    let t = totp();
    assert_eq!(t.verify(&t.generate(5), 5, 2, None), Some(0));
}
