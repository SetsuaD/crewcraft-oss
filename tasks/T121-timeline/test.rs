#![allow(clippy::unwrap_used)]

use crewcraft_client_core::timeline::{Apply, Change, Line, Timeline};

#[test]
fn new_timeline_starts_empty_at_cursor_zero() {
    let tl = Timeline::new();
    assert_eq!(tl.cursor(), 0);
    assert!(tl.lines().is_empty());
}

#[test]
fn apply_posted_appends_line_and_advances_cursor() {
    let mut tl = Timeline::new();
    let result = tl.apply(1, Change::Posted { author: "alice".into(), html: "<p>hi</p>".into() });
    assert_eq!(result, Apply::Applied);
    assert_eq!(tl.cursor(), 1);
    assert_eq!(tl.lines(), &[Line { cursor: 1, author: "alice".into(), html: "<p>hi</p>".into(), edited: false }]);
}

#[test]
fn apply_duplicate_cursor_is_ignored() {
    let mut tl = Timeline::new();
    tl.apply(1, Change::Posted { author: "a".into(), html: "x".into() });

    // Same cursor → duplicate
    let r = tl.apply(1, Change::Posted { author: "b".into(), html: "y".into() });
    assert_eq!(r, Apply::Duplicate);

    // Lower cursor → also duplicate ("at or below the current one")
    let r = tl.apply(0, Change::Posted { author: "c".into(), html: "z".into() });
    assert_eq!(r, Apply::Duplicate);

    // State unchanged
    assert_eq!(tl.cursor(), 1);
    assert_eq!(tl.lines().len(), 1);
}

#[test]
fn apply_gap_triggers_needs_resync() {
    let mut tl = Timeline::new();
    tl.apply(1, Change::Posted { author: "a".into(), html: "x".into() });
    // cursor is 1, so valid next is 2.  3 > 2 → NeedsResync.
    let r = tl.apply(3, Change::Posted { author: "b".into(), html: "y".into() });
    assert_eq!(r, Apply::NeedsResync);
    assert_eq!(tl.cursor(), 1);
    assert_eq!(tl.lines().len(), 1);
}

#[test]
fn apply_edited_replaces_html_and_marks_edited() {
    let mut tl = Timeline::new();
    tl.apply(1, Change::Posted { author: "alice".into(), html: "<p>original</p>".into() });
    let r = tl.apply(2, Change::Edited { target: 1, html: "<p>updated</p>".into() });
    assert_eq!(r, Apply::Applied);
    assert_eq!(tl.cursor(), 2);
    let line = &tl.lines()[0];
    assert_eq!(line.cursor, 1);
    assert_eq!(line.author, "alice");
    assert_eq!(line.html, "<p>updated</p>");
    assert!(line.edited);
}

#[test]
fn apply_edited_missing_target_still_applied_and_changes_nothing() {
    let mut tl = Timeline::new();
    tl.apply(1, Change::Posted { author: "alice".into(), html: "<p>hi</p>".into() });
    // target 99 does not exist
    let r = tl.apply(2, Change::Edited { target: 99, html: "<p>whatever</p>".into() });
    assert_eq!(r, Apply::Applied);
    assert_eq!(tl.cursor(), 2);
    assert_eq!(tl.lines(), &[Line { cursor: 1, author: "alice".into(), html: "<p>hi</p>".into(), edited: false }]);
}

#[test]
fn apply_deleted_removes_target_line() {
    let mut tl = Timeline::new();
    tl.apply(1, Change::Posted { author: "alice".into(), html: "<p>one</p>".into() });
    tl.apply(2, Change::Posted { author: "bob".into(), html: "<p>two</p>".into() });
    let r = tl.apply(3, Change::Deleted { target: 1 });
    assert_eq!(r, Apply::Applied);
    assert_eq!(tl.cursor(), 3);
    assert_eq!(tl.lines(), &[Line { cursor: 2, author: "bob".into(), html: "<p>two</p>".into(), edited: false }]);
}

#[test]
fn apply_deleted_missing_target_still_applied_and_changes_nothing() {
    let mut tl = Timeline::new();
    tl.apply(1, Change::Posted { author: "alice".into(), html: "<p>hi</p>".into() });
    let r = tl.apply(2, Change::Deleted { target: 42 });
    assert_eq!(r, Apply::Applied);
    assert_eq!(tl.cursor(), 2);
    assert_eq!(tl.lines().len(), 1);
}

#[test]
fn apply_other_advances_cursor_but_adds_no_line() {
    let mut tl = Timeline::new();
    let r = tl.apply(1, Change::Other);
    assert_eq!(r, Apply::Applied);
    assert_eq!(tl.cursor(), 1);
    assert!(tl.lines().is_empty());
}

#[test]
fn reset_replaces_view_and_sorts_lines_by_cursor() {
    let mut tl = Timeline::new();
    // Build some prior state so we can verify it is fully replaced.
    tl.apply(1, Change::Posted { author: "old".into(), html: "<p>old</p>".into() });

    // Reset with lines deliberately out of order.
    tl.reset(
        vec![
            Line { cursor: 5, author: "c".into(), html: "c".into(), edited: true },
            Line { cursor: 2, author: "a".into(), html: "a".into(), edited: false },
            Line { cursor: 4, author: "b".into(), html: "b".into(), edited: false },
        ],
        5,
    );

    assert_eq!(tl.cursor(), 5);
    assert_eq!(
        tl.lines(),
        &[
            Line { cursor: 2, author: "a".into(), html: "a".into(), edited: false },
            Line { cursor: 4, author: "b".into(), html: "b".into(), edited: false },
            Line { cursor: 5, author: "c".into(), html: "c".into(), edited: true },
        ]
    );
}

#[test]
fn apply_after_reset_uses_new_cursor_as_start() {
    let mut tl = Timeline::new();
    tl.reset(vec![Line { cursor: 10, author: "x".into(), html: "x".into(), edited: false }], 10);

    // 11 == 10 + 1 → applied
    let r = tl.apply(11, Change::Posted { author: "y".into(), html: "y".into() });
    assert_eq!(r, Apply::Applied);
    assert_eq!(tl.cursor(), 11);

    // 10 ≤ 11 → duplicate
    let r = tl.apply(10, Change::Posted { author: "z".into(), html: "z".into() });
    assert_eq!(r, Apply::Duplicate);

    // 13 > 12 → needs resync
    let r = tl.apply(13, Change::Posted { author: "w".into(), html: "w".into() });
    assert_eq!(r, Apply::NeedsResync);
}

#[test]
fn reset_with_empty_lines_clears_previous_state() {
    let mut tl = Timeline::new();
    tl.apply(1, Change::Posted { author: "a".into(), html: "a".into() });
    tl.apply(2, Change::Posted { author: "b".into(), html: "b".into() });
    assert_eq!(tl.lines().len(), 2);

    tl.reset(vec![], 3);
    assert_eq!(tl.cursor(), 3);
    assert!(tl.lines().is_empty());
}
