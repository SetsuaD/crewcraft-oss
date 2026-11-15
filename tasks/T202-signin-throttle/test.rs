#![allow(clippy::unwrap_used)]

use crewcraft_accounts::throttle::{BASE_DELAY_MS, Blocked, LOCK_AFTER, LOCK_MS, Throttle};

const K: &str = "alice@example.org";

#[test]
fn constants_are_the_documented_ones() {
    assert_eq!(BASE_DELAY_MS, 1_000);
    assert_eq!(LOCK_AFTER, 10);
    assert_eq!(LOCK_MS, 900_000);
}

#[test]
fn a_fresh_key_may_attempt() {
    let t = Throttle::new();
    assert_eq!(t.check(K, 0), Ok(()));
    assert_eq!(t.check(K, u64::MAX), Ok(()));
    assert_eq!(t.failures(K), 0);
}

#[test]
fn first_failure_waits_one_second() {
    let mut t = Throttle::new();
    t.fail(K, 10_000);
    assert_eq!(t.failures(K), 1);
    assert_eq!(t.check(K, 10_000), Err(Blocked::Wait { retry_after_ms: 1_000 }));
    assert_eq!(t.check(K, 10_999), Err(Blocked::Wait { retry_after_ms: 1 }));
    assert_eq!(t.check(K, 11_000), Ok(()));
    assert_eq!(t.check(K, 99_000), Ok(()));
}

#[test]
fn the_wait_doubles_with_each_consecutive_failure() {
    let mut t = Throttle::new();
    let mut now = 0u64;
    for n in 1..LOCK_AFTER {
        t.fail(K, now);
        let expected = BASE_DELAY_MS << (n - 1);
        assert_eq!(t.failures(K), n);
        assert_eq!(t.check(K, now), Err(Blocked::Wait { retry_after_ms: expected }), "after failure {n}");
        assert_eq!(t.check(K, now + expected - 1), Err(Blocked::Wait { retry_after_ms: 1 }), "after failure {n}");
        assert_eq!(t.check(K, now + expected), Ok(()), "after failure {n}");
        now += expected;
    }
    // The ninth failure waited 256 s.
    assert_eq!(BASE_DELAY_MS << 8, 256_000);
}

#[test]
fn the_tenth_failure_locks_for_fifteen_minutes() {
    let mut t = Throttle::new();
    let mut now = 5_000u64;
    for n in 1..LOCK_AFTER {
        t.fail(K, now);
        now += BASE_DELAY_MS << (n - 1);
    }
    t.fail(K, now); // the tenth
    assert_eq!(t.failures(K), 10);
    assert_eq!(t.check(K, now), Err(Blocked::Locked { retry_after_ms: LOCK_MS }));
    assert_eq!(t.check(K, now + LOCK_MS - 1), Err(Blocked::Locked { retry_after_ms: 1 }));
    assert_eq!(t.check(K, now + LOCK_MS), Ok(()));
    // The expired lock still reports its count until something changes it...
    assert_eq!(t.failures(K), 10);
    // ...and the next failure after the lock starts again from one, with the one-second wait.
    t.fail(K, now + LOCK_MS);
    assert_eq!(t.failures(K), 1);
    assert_eq!(t.check(K, now + LOCK_MS), Err(Blocked::Wait { retry_after_ms: 1_000 }));
}

#[test]
fn a_failure_while_locked_does_not_extend_the_lock() {
    let mut t = Throttle::new();
    let mut now = 0u64;
    for n in 1..LOCK_AFTER {
        t.fail(K, now);
        now += BASE_DELAY_MS << (n - 1);
    }
    t.fail(K, now);
    t.fail(K, now + 60_000);
    t.fail(K, now + 120_000);
    assert_eq!(t.failures(K), 10);
    assert_eq!(t.check(K, now + LOCK_MS - 1), Err(Blocked::Locked { retry_after_ms: 1 }));
    assert_eq!(t.check(K, now + LOCK_MS), Ok(()));
}

#[test]
fn a_failure_made_while_waiting_still_counts_and_restarts_the_wait() {
    let mut t = Throttle::new();
    t.fail(K, 1_000);
    t.fail(K, 1_500); // not allowed yet, but the caller made the attempt
    assert_eq!(t.failures(K), 2);
    assert_eq!(t.check(K, 1_500), Err(Blocked::Wait { retry_after_ms: 2_000 }));
    assert_eq!(t.check(K, 3_500), Ok(()));
}

#[test]
fn success_and_reset_forget_the_failures() {
    let mut t = Throttle::new();
    t.fail(K, 0);
    t.fail(K, 1_000);
    t.succeed(K);
    assert_eq!(t.failures(K), 0);
    assert_eq!(t.check(K, 1_000), Ok(()));

    t.fail(K, 5_000);
    t.fail(K, 7_000);
    assert_eq!(t.failures(K), 2);
    t.reset(K);
    assert_eq!(t.failures(K), 0);
    assert_eq!(t.check(K, 7_000), Ok(()));
}

#[test]
fn an_administrator_reset_lifts_a_live_lock() {
    let mut t = Throttle::new();
    let mut now = 0u64;
    for n in 1..LOCK_AFTER {
        t.fail(K, now);
        now += BASE_DELAY_MS << (n - 1);
    }
    t.fail(K, now);
    assert!(matches!(t.check(K, now + 1), Err(Blocked::Locked { .. })));
    t.reset(K);
    assert_eq!(t.check(K, now + 1), Ok(()));
}

#[test]
fn keys_are_independent_and_unknown_keys_behave_like_known_ones() {
    let mut t = Throttle::new();
    t.fail("alice@example.org", 0);
    t.fail("nobody@example.org", 0); // an address with no account is throttled exactly the same way
    assert_eq!(t.check("alice@example.org", 0), Err(Blocked::Wait { retry_after_ms: 1_000 }));
    assert_eq!(t.check("nobody@example.org", 0), Err(Blocked::Wait { retry_after_ms: 1_000 }));
    assert_eq!(t.check("bob@example.org", 0), Ok(()));
    t.succeed("alice@example.org");
    assert_eq!(t.check("nobody@example.org", 0), Err(Blocked::Wait { retry_after_ms: 1_000 }));
}

#[test]
fn extreme_times_never_overflow() {
    let mut t = Throttle::new();
    t.fail(K, u64::MAX - 10);
    // Blocked-until saturates at u64::MAX: ten milliseconds left, then allowed at that instant. Nothing panics.
    assert_eq!(t.check(K, u64::MAX - 10), Err(Blocked::Wait { retry_after_ms: 10 }));
    assert_eq!(t.check(K, u64::MAX), Ok(()));
}
