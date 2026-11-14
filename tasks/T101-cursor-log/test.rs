// T101: bounded append-only event log with cursors and gap detection.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_server_core::cursor_log::{EventLog, Since};

#[test]
fn cursors_start_at_one_and_grow() {
    let mut l = EventLog::new(10);
    assert_eq!(l.head(), 0);
    assert!(l.is_empty());
    assert_eq!(l.append("a"), 1);
    assert_eq!(l.append("b"), 2);
    assert_eq!(l.head(), 2);
    assert_eq!(l.len(), 2);
}

#[test]
fn since_returns_what_the_client_has_not_seen() {
    let mut l = EventLog::new(10);
    for e in ["a", "b", "c"] {
        l.append(e);
    }
    assert_eq!(l.since(0), Since::Events(vec![(1, "a"), (2, "b"), (3, "c")]));
    assert_eq!(l.since(2), Since::Events(vec![(3, "c")]));
    assert_eq!(l.since(3), Since::Events(vec![]));
    assert_eq!(l.since(99), Since::Events(vec![]));
}

#[test]
fn an_empty_log() {
    let l: EventLog<&str> = EventLog::new(5);
    assert_eq!(l.since(0), Since::Events(vec![]));
}

#[test]
fn dropped_events_are_reported_as_a_gap() {
    let mut l = EventLog::new(3);
    for e in ["a", "b", "c", "d", "e"] {
        l.append(e);
    }
    assert_eq!(l.len(), 3);
    assert_eq!(l.head(), 5);
    assert_eq!(l.since(0), Since::Gap { oldest: 3 });
    assert_eq!(l.since(1), Since::Gap { oldest: 3 });
    assert_eq!(l.since(2), Since::Events(vec![(3, "c"), (4, "d"), (5, "e")]));
    assert_eq!(l.since(4), Since::Events(vec![(5, "e")]));
}

#[test]
fn capacity_zero_keeps_one() {
    let mut l = EventLog::new(0);
    l.append(1);
    l.append(2);
    assert_eq!(l.len(), 1);
    assert_eq!(l.since(1), Since::Events(vec![(2, 2)]));
    assert_eq!(l.since(0), Since::Gap { oldest: 2 });
}
