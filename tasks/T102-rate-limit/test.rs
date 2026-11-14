// T102: token bucket in milli-tokens with an injected clock, and a per-key limiter.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_server_core::rate_limit::{Limiter, TokenBucket};

#[test]
fn a_new_bucket_is_full_and_empties() {
    let mut b = TokenBucket::new(3, 1, 0);
    assert_eq!(b.available(0), 3);
    assert!(b.try_take(0));
    assert!(b.try_take(0));
    assert!(b.try_take(0));
    assert!(!b.try_take(0));
    assert_eq!(b.available(0), 0);
}

#[test]
fn refills_exactly_by_the_millisecond() {
    let mut b = TokenBucket::new(3, 1, 0);
    for _ in 0..3 {
        assert!(b.try_take(0));
    }
    assert!(!b.try_take(999));
    assert!(b.try_take(1000));
    assert!(!b.try_take(1000));
    assert_eq!(b.available(4000), 3); // capped at capacity
}

#[test]
fn faster_refill_rates() {
    let mut b = TokenBucket::new(10, 4, 0);
    for _ in 0..10 {
        assert!(b.try_take(0));
    }
    assert_eq!(b.available(250), 1);
    assert_eq!(b.available(1000), 4);
    assert!(b.try_take(500));
    assert!(b.try_take(500));
    assert!(!b.try_take(500));
}

#[test]
fn a_clock_going_backwards_refills_nothing() {
    let mut b = TokenBucket::new(1, 1, 10_000);
    assert!(b.try_take(10_000));
    assert!(!b.try_take(5_000));
    assert!(!b.try_take(10_999)); // the bucket's clock stayed at 10_000
    assert!(b.try_take(11_000));
}

#[test]
fn limiter_keys_are_independent_and_full_buckets_are_pruned() {
    let mut l = Limiter::new(2, 1);
    assert!(l.is_empty());
    assert!(l.check(&"ana", 0));
    assert!(l.check(&"ana", 0));
    assert!(!l.check(&"ana", 0));
    assert!(l.check(&"bo", 0));
    assert_eq!(l.len(), 2);
    assert_eq!(l.prune(1_000), 1); // bo is full again; ana has 1 of 2
    assert_eq!(l.len(), 1);
    assert_eq!(l.prune(2_000), 1);
    assert!(l.is_empty());
}
