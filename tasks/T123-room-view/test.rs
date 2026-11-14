#![allow(clippy::unwrap_used)]

use crewcraft_client_core::room_view::{RoomView, Shown};
use crewcraft_client_core::timeline::{Apply, Change, Line};

#[test]
fn new_view_is_empty_at_cursor_zero() {
    let v = RoomView::new();
    assert_eq!(v.cursor(), 0);
    assert!(v.shown().is_empty());
    assert!(!v.needs_resync());
    assert!(v.due(1_000_000).is_empty());
    assert_eq!(v.body(1), None);
    assert_eq!(v.body(999), None);
}

#[test]
fn send_assigns_sequential_ids_and_is_immediately_due() {
    let mut v = RoomView::new();
    let id1 = v.send("hello", 100);
    let id2 = v.send("world", 200);
    assert_eq!(id1, 1);
    assert_eq!(id2, 2);
    assert_eq!(v.due(200), vec![1, 2]);
    assert_eq!(v.body(1), Some("hello".into()));
    assert_eq!(v.body(2), Some("world".into()));
    let shown = v.shown();
    assert_eq!(
        shown,
        vec![Shown::Pending { id: 1, body: "hello".into(), failed: false }, Shown::Pending { id: 2, body: "world".into(), failed: false },]
    );
}

#[test]
fn shown_orders_timeline_then_acked_by_cursor_then_outbox_by_id() {
    let mut v = RoomView::new();
    // Build timeline at cursors 1, 2, 3
    v.event(1, Change::Posted { author: "a".into(), html: "h1".into() });
    v.event(2, Change::Posted { author: "b".into(), html: "h2".into() });
    v.event(3, Change::Posted { author: "c".into(), html: "h3".into() });
    // Ack a message at cursor 5 (view cursor 3 < 5, still shown)
    let ack_id = v.send("acked", 0);
    assert_eq!(ack_id, 1);
    assert!(v.acked(ack_id, 5));
    // Queue another outbox message
    let ob_id = v.send("outbox", 0);
    assert_eq!(ob_id, 2);

    let shown = v.shown();
    let expected = vec![
        Shown::Line(Line { cursor: 1, author: "a".into(), html: "h1".into(), edited: false }),
        Shown::Line(Line { cursor: 2, author: "b".into(), html: "h2".into(), edited: false }),
        Shown::Line(Line { cursor: 3, author: "c".into(), html: "h3".into(), edited: false }),
        Shown::Pending { id: ack_id, body: "acked".into(), failed: false },
        Shown::Pending { id: ob_id, body: "outbox".into(), failed: false },
    ];
    assert_eq!(shown, expected);
}

#[test]
fn acked_removes_from_outbox_but_still_shown_until_cursor_reaches() {
    let mut v = RoomView::new();
    let id = v.send("msg", 0);
    assert!(v.acked(id, 5));
    // Left the outbox:
    assert_eq!(v.body(id), None);
    assert!(!v.due(1_000_000).contains(&id));
    // Still shown as Pending (not failed):
    assert_eq!(v.shown(), vec![Shown::Pending { id, body: "msg".into(), failed: false }]);
    // Advance cursor to 4 (still < 5): still shown
    v.event(1, Change::Other);
    v.event(2, Change::Other);
    v.event(3, Change::Other);
    v.event(4, Change::Other);
    assert_eq!(v.cursor(), 4);
    assert_eq!(v.shown(), vec![Shown::Pending { id, body: "msg".into(), failed: false }]);
    // Advance to 5 (>= 5): no longer shown; timeline line stands in
    v.event(5, Change::Posted { author: "me".into(), html: "msg".into() });
    assert_eq!(v.cursor(), 5);
    assert_eq!(v.shown(), vec![Shown::Line(Line { cursor: 5, author: "me".into(), html: "msg".into(), edited: false })]);
}

#[test]
fn acked_with_cursor_already_at_or_past_is_never_shown() {
    let mut v = RoomView::new();
    v.event(1, Change::Posted { author: "a".into(), html: "h1".into() });
    v.event(2, Change::Posted { author: "b".into(), html: "h2".into() });
    assert_eq!(v.cursor(), 2);
    let id = v.send("msg", 0);
    // View cursor (2) >= acked cursor (2): never shown
    assert!(v.acked(id, 2));
    let shown = v.shown();
    assert_eq!(shown.len(), 2);
    assert!(shown.iter().all(|s| matches!(s, Shown::Line(_))));
}

#[test]
fn acked_returns_false_for_unknown_id_and_changes_nothing() {
    let mut v = RoomView::new();
    let id = v.send("keep", 0);
    let before = v.shown();
    assert!(!v.acked(999, 5));
    assert_eq!(v.shown(), before);
    assert_eq!(v.cursor(), 0);
    assert_eq!(v.body(id), Some("keep".into()));
}

#[test]
fn event_needs_resync_sets_flag_until_snapshot_clears_it() {
    let mut v = RoomView::new();
    assert!(!v.needs_resync());
    assert_eq!(v.event(1, Change::Other), Apply::Applied);
    assert!(!v.needs_resync());
    // Gap: cursor is 1, event at 3 -> NeedsResync
    assert_eq!(v.event(3, Change::Other), Apply::NeedsResync);
    assert!(v.needs_resync());
    // Snapshot clears the flag
    v.snapshot(vec![], 3);
    assert!(!v.needs_resync());
    assert_eq!(v.cursor(), 3);
}

#[test]
fn send_failed_backoff_schedule_and_dead_after_max_attempts() {
    let mut v = RoomView::new();
    let id = v.send("retry", 0);

    // 1st failure at t=0: next due = 0 + 1000 = 1000
    assert!(v.send_failed(id, 0));
    assert!(!v.due(999).contains(&id));
    assert!(v.due(1000).contains(&id));

    // 2nd failure at t=1000: next due = 1000 + 2000 = 3000
    assert!(v.send_failed(id, 1000));
    assert!(!v.due(2999).contains(&id));
    assert!(v.due(3000).contains(&id));

    // 3rd failure at t=3000: next due = 3000 + 4000 = 7000
    assert!(v.send_failed(id, 3000));
    assert!(!v.due(6999).contains(&id));
    assert!(v.due(7000).contains(&id));

    // 4th failure at t=7000: next due = 7000 + 8000 = 15000
    assert!(v.send_failed(id, 7000));
    // 5th failure at t=15000: next due = 15000 + 16000 = 31000
    assert!(v.send_failed(id, 15000));
    // 6th failure at t=31000: next due = 31000 + 32000 = 63000
    assert!(v.send_failed(id, 31000));
    // 7th failure at t=63000: next due = 63000 + min(64000,60000) = 123000
    assert!(v.send_failed(id, 63000));
    // 8th failure at t=123000: attempts >= 8 -> Dead
    assert!(v.send_failed(id, 123000));

    // Dead: never due again
    assert!(!v.due(u64::MAX).contains(&id));
    // Shown as failed
    assert_eq!(v.shown(), vec![Shown::Pending { id, body: "retry".into(), failed: true }]);
    // send_failed on dead returns false
    assert!(!v.send_failed(id, 200_000));
    // body is still available (it is in the outbox, just dead)
    assert_eq!(v.body(id), Some("retry".into()));
}

#[test]
fn snapshot_keeps_outbox_and_hides_acked_at_or_below_its_cursor() {
    let mut v = RoomView::new();
    v.event(1, Change::Other);
    assert_eq!(v.cursor(), 1);
    let id_acked = v.send("acked_msg", 0); // id 1
    assert!(v.acked(id_acked, 3)); // view cursor 1 < 3, still shown
    let id_outbox = v.send("outbox_msg", 0); // id 2, still in outbox

    // Snapshot at cursor 2: acked(3) > 2, still shown; outbox untouched
    v.snapshot(vec![], 2);
    assert_eq!(v.cursor(), 2);
    assert_eq!(v.body(id_outbox), Some("outbox_msg".into()));
    assert!(v.due(1000).contains(&id_outbox));
    let shown = v.shown();
    assert_eq!(
        shown,
        vec![
            Shown::Pending { id: id_acked, body: "acked_msg".into(), failed: false },
            Shown::Pending { id: id_outbox, body: "outbox_msg".into(), failed: false },
        ]
    );

    // Snapshot at cursor 5: acked(3) <= 5, no longer shown; outbox still there
    v.snapshot(vec![], 5);
    let shown = v.shown();
    assert_eq!(shown, vec![Shown::Pending { id: id_outbox, body: "outbox_msg".into(), failed: false },]);
    assert_eq!(v.body(id_outbox), Some("outbox_msg".into()));
}

#[test]
fn multiple_acked_messages_shown_in_cursor_order() {
    let mut v = RoomView::new();
    v.event(1, Change::Other);
    let id_a = v.send("a", 0); // id 1
    let id_b = v.send("b", 0); // id 2
    let id_c = v.send("c", 0); // id 3
    // Ack at different cursors, out of id order
    assert!(v.acked(id_c, 10));
    assert!(v.acked(id_a, 5));
    assert!(v.acked(id_b, 7));
    // All still shown (view cursor 1 < each acked cursor)
    // Shown by cursor order: 5 (a), 7 (b), 10 (c)
    let shown = v.shown();
    assert_eq!(
        shown,
        vec![
            Shown::Pending { id: id_a, body: "a".into(), failed: false },
            Shown::Pending { id: id_b, body: "b".into(), failed: false },
            Shown::Pending { id: id_c, body: "c".into(), failed: false },
        ]
    );
}

#[test]
fn body_returns_none_for_unknown_id_and_after_ack() {
    let mut v = RoomView::new();
    assert_eq!(v.body(42), None);
    let id = v.send("hello", 0);
    assert_eq!(v.body(id), Some("hello".into()));
    assert!(v.acked(id, 5));
    assert_eq!(v.body(id), None);
}

#[test]
fn duplicate_events_are_ignored() {
    let mut v = RoomView::new();
    assert_eq!(v.event(1, Change::Posted { author: "a".into(), html: "h".into() }), Apply::Applied);
    assert_eq!(v.event(1, Change::Other), Apply::Duplicate);
    assert_eq!(v.event(0, Change::Other), Apply::Duplicate);
    assert_eq!(v.cursor(), 1);
    assert_eq!(v.shown().len(), 1);
}

#[test]
fn send_ids_are_never_reused_even_after_ack() {
    let mut v = RoomView::new();
    let id1 = v.send("first", 0);
    assert_eq!(id1, 1);
    assert!(v.acked(id1, 5));
    let id2 = v.send("second", 0);
    assert_eq!(id2, 2);
    let id3 = v.send("third", 0);
    assert_eq!(id3, 3);
    assert_eq!(v.body(2), Some("second".into()));
    assert_eq!(v.body(3), Some("third".into()));
}

#[test]
fn acked_message_once_reached_stays_hidden_after_an_older_snapshot() {
    let mut v = RoomView::new();
    let id = v.send("msg", 0);
    assert!(v.acked(id, 2));
    v.event(1, Change::Other);
    v.event(2, Change::Posted { author: "me".into(), html: "msg".into() });
    assert!(v.shown().iter().all(|s| matches!(s, Shown::Line(_))));
    v.snapshot(vec![], 1);
    assert!(v.shown().is_empty());
}
