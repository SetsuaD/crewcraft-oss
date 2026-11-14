// T105: read markers and unread counts.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_server_core::unread::ReadMarkers;

const MSGS: &[(u64, &str)] = &[(1, "ana"), (2, "bo"), (3, "ana"), (4, "cy"), (5, "bo")];

#[test]
fn nothing_read_yet() {
    let r = ReadMarkers::new();
    assert_eq!(r.last_read("ana", "general"), 0);
    assert_eq!(r.unread("ana", "general", MSGS), 3);
    assert_eq!(r.unread("bo", "general", MSGS), 3);
}

#[test]
fn markers_count_from_the_cursor() {
    let mut r = ReadMarkers::new();
    assert!(r.mark_read("ana", "general", 2));
    assert_eq!(r.unread("ana", "general", MSGS), 2);
    assert!(r.mark_read("ana", "general", 5));
    assert_eq!(r.unread("ana", "general", MSGS), 0);
}

#[test]
fn markers_never_move_backwards() {
    let mut r = ReadMarkers::new();
    assert!(r.mark_read("bo", "general", 4));
    assert!(!r.mark_read("bo", "general", 3));
    assert!(!r.mark_read("bo", "general", 4));
    assert_eq!(r.last_read("bo", "general"), 4);
    assert_eq!(r.unread("bo", "general", MSGS), 0); // message 5 is bo's own
}

#[test]
fn rooms_and_users_are_separate() {
    let mut r = ReadMarkers::new();
    r.mark_read("ana", "general", 5);
    assert_eq!(r.last_read("ana", "random"), 0);
    assert_eq!(r.last_read("bo", "general"), 0);
    assert_eq!(r.unread("ana", "random", MSGS), 3);
}

#[test]
fn a_user_and_room_pair_is_not_confused_by_separators() {
    let mut r = ReadMarkers::new();
    r.mark_read("a:b", "c", 3);
    assert_eq!(r.last_read("a", "b:c"), 0);
    assert_eq!(r.last_read("a:b", "c"), 3);
}
