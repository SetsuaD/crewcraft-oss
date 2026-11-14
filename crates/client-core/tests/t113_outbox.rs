// T113: offline outbox with exponential backoff and a dead state.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_client_core::outbox::{Outbox, State};

const NONE: Vec<u64> = Vec::new();

#[test]
fn new_messages_are_due_at_once_in_order() {
    let mut o = Outbox::new();
    assert_eq!(o.push("a", 100), 1);
    assert_eq!(o.push("b", 100), 2);
    assert_eq!(o.due(100), vec![1, 2]);
    assert_eq!(o.next_try(1), Some(100));
    assert_eq!(o.get(1).unwrap().attempts, 0);
}

#[test]
fn backoff_doubles_caps_and_dies() {
    let mut o = Outbox::new();
    let id = o.push("a", 0);
    let mut now = 0;
    let mut waits = vec![];
    for _ in 0..7 {
        assert!(o.fail(id, now));
        let t = o.next_try(id).unwrap();
        waits.push(t - now);
        now = t;
    }
    assert_eq!(waits, vec![1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000]);
    assert_eq!(o.get(id).unwrap().attempts, 7);
    assert_eq!(o.get(id).unwrap().state, State::Pending);
    assert!(o.fail(id, now)); // the eighth failure
    let e = o.get(id).unwrap();
    assert_eq!((e.attempts, e.state, e.body.as_str()), (8, State::Dead, "a"));
    assert_eq!(o.next_try(id), None);
    assert_eq!(o.due(u64::MAX), NONE);
    assert!(!o.fail(id, now));
    assert_eq!(o.len(), 1); // a dead message stays for the user to see
}

#[test]
fn not_due_before_the_retry_time() {
    let mut o = Outbox::new();
    let a = o.push("a", 0);
    let b = o.push("b", 0);
    assert!(o.fail(a, 0));
    assert_eq!(o.due(999), vec![b]);
    assert_eq!(o.due(1_000), vec![a, b]);
}

#[test]
fn ack_removes_and_ids_are_never_reused() {
    let mut o = Outbox::new();
    let a = o.push("a", 0);
    assert!(o.ack(a));
    assert!(!o.ack(a));
    assert!(o.is_empty());
    assert_eq!(o.push("b", 0), 2);
    assert!(!o.fail(99, 0));
    assert_eq!(o.get(99), None);
    assert_eq!(o.next_try(99), None);
    assert_eq!(o.len(), 1);
}
