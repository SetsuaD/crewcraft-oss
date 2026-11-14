#![allow(clippy::unwrap_used)]

use crewcraft_client_core::inbox::Inbox;
use crewcraft_client_core::notify::{Level, Notify, Settings};
use crewcraft_client_core::timeline::Apply;
use crewcraft_proto::push::Push;

#[test]
fn new_inbox_starts_empty() {
    let settings = Settings::new("alice");
    let mut inbox = Inbox::new("alice", settings);

    assert!(inbox.rooms().is_empty());
    assert!(inbox.view("general").is_none());
    assert!(inbox.view_mut("general").is_none());
    assert!(inbox.needs_resync().is_empty());
}

#[test]
fn follow_then_unfollow_lifecycle() {
    let settings = Settings::new("alice");
    let mut inbox = Inbox::new("alice", settings);

    // First follow succeeds.
    assert!(inbox.follow("general", false));
    assert!(inbox.view("general").is_some());

    // Second follow returns false (already followed) and nothing changes.
    assert!(!inbox.follow("general", true));

    // Unfollow succeeds.
    assert!(inbox.unfollow("general"));
    assert!(inbox.view("general").is_none());

    // Second unfollow returns false (not followed).
    assert!(!inbox.unfollow("general"));
}

#[test]
fn on_push_unfollowed_room_returns_none() {
    let settings = Settings::new("alice");
    let mut inbox = Inbox::new("alice", settings);

    let push = Push::Posted { room: "general".into(), cursor: 1, author: "bob".into(), html: "hello".into(), mentions: vec![] };

    let result = inbox.on_push(push, 1_000, 600);
    assert!(result.is_none());

    // Nothing changed: still no rooms.
    assert!(inbox.rooms().is_empty());
}

#[test]
fn on_push_posted_applied_notifies_sound() {
    let settings = Settings::new("alice");
    let mut inbox = Inbox::new("alice", settings);
    inbox.follow("general", false);

    let push = Push::Posted { room: "general".into(), cursor: 1, author: "bob".into(), html: "hi".into(), mentions: vec![] };

    let (apply, notify) = inbox.on_push(push, 1_000, 600).unwrap();
    assert_eq!(apply, Apply::Applied);
    // Level::All, not me, no DND, no quiet → Sound.
    assert_eq!(notify, Notify::Sound);
}

#[test]
fn on_push_posted_mention_case_insensitive() {
    let mut settings = Settings::new("alice");
    settings.set_level("general", Level::Mentions);
    let mut inbox = Inbox::new("alice", settings);
    inbox.follow("general", false);

    // "ALICE" matches me="alice" case-insensitively → mentioned = true.
    let push = Push::Posted { room: "general".into(), cursor: 1, author: "bob".into(), html: "@alice look".into(), mentions: vec!["ALICE".into()] };

    let (apply, notify) = inbox.on_push(push, 1_000, 600).unwrap();
    assert_eq!(apply, Apply::Applied);
    // Level::Mentions, mentioned=true → passes filter → Sound.
    assert_eq!(notify, Notify::Sound);
}

#[test]
fn on_push_non_posted_always_none_notify() {
    let settings = Settings::new("alice");
    let mut inbox = Inbox::new("alice", settings);
    inbox.follow("general", false);

    // Edited
    let push = Push::Edited { room: "general".into(), cursor: 1, target: 0, html: "edited".into(), mentions: vec!["alice".into()] };
    let (_, notify) = inbox.on_push(push, 1_000, 600).unwrap();
    assert_eq!(notify, Notify::None);

    // Deleted
    let push = Push::Deleted { room: "general".into(), cursor: 2, target: 1 };
    let (_, notify) = inbox.on_push(push, 1_000, 600).unwrap();
    assert_eq!(notify, Notify::None);

    // Other
    let push = Push::Other { room: "general".into(), cursor: 3 };
    let (_, notify) = inbox.on_push(push, 1_000, 600).unwrap();
    assert_eq!(notify, Notify::None);
}

#[test]
fn on_push_posted_duplicate_no_notify() {
    let settings = Settings::new("alice");
    let mut inbox = Inbox::new("alice", settings);
    inbox.follow("general", false);

    // First push at cursor 1 is Applied.
    let push1 = Push::Posted { room: "general".into(), cursor: 1, author: "bob".into(), html: "first".into(), mentions: vec![] };
    let (apply1, _) = inbox.on_push(push1, 1_000, 600).unwrap();
    assert_eq!(apply1, Apply::Applied);

    // Second push at the same cursor 1 is Duplicate → Notify::None.
    let push2 = Push::Posted { room: "general".into(), cursor: 1, author: "bob".into(), html: "first".into(), mentions: vec![] };
    let (apply2, notify2) = inbox.on_push(push2, 1_000, 600).unwrap();
    assert_eq!(apply2, Apply::Duplicate);
    assert_eq!(notify2, Notify::None);
}

#[test]
fn on_push_posted_needs_resync_no_notify_and_flagged() {
    let settings = Settings::new("alice");
    let mut inbox = Inbox::new("alice", settings);
    inbox.follow("general", false);

    // Cursor starts at 0; pushing cursor 3 > 0+1 → NeedsResync.
    let push = Push::Posted { room: "general".into(), cursor: 3, author: "bob".into(), html: "gap".into(), mentions: vec![] };
    let (apply, notify) = inbox.on_push(push, 1_000, 600).unwrap();
    assert_eq!(apply, Apply::NeedsResync);
    assert_eq!(notify, Notify::None);

    // The room is now flagged as needing resync.
    assert_eq!(inbox.needs_resync(), vec!["general".to_owned()]);
}

#[test]
fn rooms_and_needs_resync_sorted() {
    let settings = Settings::new("alice");
    let mut inbox = Inbox::new("alice", settings);
    inbox.follow("zeta", false);
    inbox.follow("alpha", false);
    inbox.follow("mid", false);

    // rooms() is sorted.
    assert_eq!(inbox.rooms(), vec!["alpha".to_owned(), "mid".to_owned(), "zeta".to_owned()]);

    // Force needs_resync on two rooms (push cursor 5 when cursor is 0).
    for room in ["zeta", "alpha"] {
        let push = Push::Other { room: room.into(), cursor: 5 };
        let (apply, _) = inbox.on_push(push, 1_000, 600).unwrap();
        assert_eq!(apply, Apply::NeedsResync);
    }

    assert_eq!(inbox.needs_resync(), vec!["alpha".to_owned(), "zeta".to_owned()]);
}

#[test]
fn direct_room_with_mentions_level_still_notifies() {
    let mut settings = Settings::new("alice");
    settings.set_level("dm-bob", Level::Mentions);
    let mut inbox = Inbox::new("alice", settings);
    inbox.follow("dm-bob", true); // direct = true

    // No mention of alice, but the room is direct → passes the Mentions filter.
    let push = Push::Posted { room: "dm-bob".into(), cursor: 1, author: "bob".into(), html: "hey".into(), mentions: vec![] };
    let (apply, notify) = inbox.on_push(push, 1_000, 600).unwrap();
    assert_eq!(apply, Apply::Applied);
    // author != me, level=Mentions, mentioned=false but direct=true → Sound.
    assert_eq!(notify, Notify::Sound);
}

#[test]
fn on_push_posted_by_own_author_no_notify() {
    let settings = Settings::new("alice");
    let mut inbox = Inbox::new("alice", settings);
    inbox.follow("general", false);

    let push = Push::Posted { room: "general".into(), cursor: 1, author: "alice".into(), html: "my message".into(), mentions: vec![] };
    let (apply, notify) = inbox.on_push(push, 1_000, 600).unwrap();
    assert_eq!(apply, Apply::Applied);
    // Settings::decide: author == me → Notify::None.
    assert_eq!(notify, Notify::None);
}

#[test]
fn pushes_reach_the_room_view_as_timeline_changes() {
    use crewcraft_client_core::room_view::Shown;
    use crewcraft_client_core::timeline::Line;

    let mut inbox = Inbox::new("alice", Settings::new("alice"));
    inbox.follow("general", false);
    let pushes = vec![
        Push::Posted { room: "general".into(), cursor: 1, author: "bob".into(), html: "one".into(), mentions: vec![] },
        Push::Edited { room: "general".into(), cursor: 2, target: 1, html: "uno".into(), mentions: vec![] },
        Push::Posted { room: "general".into(), cursor: 3, author: "carol".into(), html: "two".into(), mentions: vec![] },
        Push::Deleted { room: "general".into(), cursor: 4, target: 3 },
    ];
    for push in pushes {
        assert_eq!(inbox.on_push(push, 0, 0).unwrap().0, Apply::Applied);
    }
    let view = inbox.view("general").unwrap();
    assert_eq!(view.cursor(), 4);
    assert_eq!(view.shown(), vec![Shown::Line(Line { cursor: 1, author: "bob".into(), html: "uno".into(), edited: true })]);
}
