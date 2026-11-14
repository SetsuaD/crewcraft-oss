#![allow(clippy::unwrap_used)]

use crewcraft_server_core::cursor_log::Since;
use crewcraft_server_core::room::{Role, RoomError};
use crewcraft_server_core::room_service::{EventKind, RoomService, ServiceError};

#[test]
fn new_room_has_zero_head_and_empty_sync() {
    let svc = RoomService::new("alice", 10);
    assert_eq!(svc.head(), 0);

    let sync = svc.sync("alice", 0).unwrap();
    assert_eq!(sync, Since::Events(vec![]));
}

#[test]
fn add_member_appends_joined_event_with_correct_fields() {
    let mut svc = RoomService::new("alice", 10);
    let cursor = svc.add_member("alice", "bob", Role::Member).unwrap();
    assert_eq!(cursor, 1);
    assert_eq!(svc.head(), 1);

    let sync = svc.sync("alice", 0).unwrap();
    let Since::Events(events) = sync else { panic!("expected Events") };
    assert_eq!(events.len(), 1);
    let (c, event) = &events[0];
    assert_eq!(*c, 1);
    assert_eq!(event.actor, "alice");
    assert_eq!(event.kind, EventKind::Joined { user: "bob".to_string(), role: Role::Member });
    assert_eq!(event.html, "");
    assert!(event.mentions.is_empty());
}

#[test]
fn add_member_rejects_non_member_actor_and_forbidden_role_grant() {
    let mut svc = RoomService::new("alice", 10);

    // Non-member actor
    let err = svc.add_member("dave", "bob", Role::Member).unwrap_err();
    assert_eq!(err, ServiceError::Room(RoomError::NotMember));

    // Alice (Owner) adds bob as Member, then bob (Member) tries to add carol
    svc.add_member("alice", "bob", Role::Member).unwrap();
    let err = svc.add_member("bob", "carol", Role::Member).unwrap_err();
    assert_eq!(err, ServiceError::Room(RoomError::Forbidden));

    // Already a member
    let err = svc.add_member("alice", "bob", Role::Member).unwrap_err();
    assert_eq!(err, ServiceError::Room(RoomError::AlreadyMember));
}

#[test]
fn remove_member_appends_left_event_and_rejects_last_owner() {
    let mut svc = RoomService::new("alice", 10);
    svc.add_member("alice", "bob", Role::Member).unwrap();

    let cursor = svc.remove_member("alice", "bob").unwrap();
    assert_eq!(cursor, 2);

    let sync = svc.sync("alice", 1).unwrap();
    let Since::Events(events) = sync else { panic!("expected Events") };
    assert_eq!(events.len(), 1);
    let (c, event) = &events[0];
    assert_eq!(*c, 2);
    assert_eq!(event.actor, "alice");
    assert_eq!(event.kind, EventKind::Left { user: "bob".to_string() });
    assert_eq!(event.html, "");
    assert!(event.mentions.is_empty());

    // Alice is the only Owner; removing herself is LastOwner
    let err = svc.remove_member("alice", "alice").unwrap_err();
    assert_eq!(err, ServiceError::Room(RoomError::LastOwner));
}

#[test]
fn post_success_renders_html_and_filters_mentions_to_members() {
    let mut svc = RoomService::new("alice", 10);
    svc.add_member("alice", "bob", Role::Member).unwrap(); // cursor 1

    let text = "hey @bob @dave @alice";
    let cursor = svc.post("alice", text).unwrap();
    assert_eq!(cursor, 2);

    let sync = svc.sync("alice", 1).unwrap();
    let Since::Events(events) = sync else { panic!("expected Events") };
    assert_eq!(events.len(), 1);
    let (c, event) = &events[0];
    assert_eq!(*c, 2);
    assert_eq!(event.actor, "alice");
    assert_eq!(event.kind, EventKind::Posted);
    // render("hey @bob @dave @alice") – plain text, no special formatting
    assert_eq!(event.html, "hey @bob @dave @alice");
    // mentions → ["bob", "dave", "alice"]
    // keep only room members → ["bob", "alice"]
    // exclude actor "alice" → ["bob"]
    assert_eq!(event.mentions, vec!["bob".to_string()]);
}

#[test]
fn post_rejects_in_documented_order() {
    let mut svc = RoomService::new("alice", 10);
    svc.add_member("alice", "eve", Role::Guest).unwrap(); // cursor 1

    // 1. Non-member → Room(NotMember)
    let err = svc.post("dave", "hello").unwrap_err();
    assert_eq!(err, ServiceError::Room(RoomError::NotMember));

    // 2. Guest (member but cannot post) → NotAllowed
    let err = svc.post("eve", "  ").unwrap_err();
    assert_eq!(err, ServiceError::NotAllowed);

    // 3. Empty text after trimming → EmptyText
    let err = svc.post("alice", "   ").unwrap_err();
    assert_eq!(err, ServiceError::EmptyText);

    // 4. More than 4000 chars after trimming → TooLong
    let long_text = "a".repeat(4001);
    let err = svc.post("alice", &long_text).unwrap_err();
    assert_eq!(err, ServiceError::TooLong);
}

#[test]
fn edit_success_appends_edited_event_with_new_html_and_mentions() {
    let mut svc = RoomService::new("alice", 10);
    svc.add_member("alice", "bob", Role::Member).unwrap(); // cursor 1
    let posted_cursor = svc.post("bob", "first").unwrap(); // cursor 2
    assert_eq!(posted_cursor, 2);

    let cursor = svc.edit("bob", 2, "hello **world** @alice").unwrap();
    assert_eq!(cursor, 3);

    let sync = svc.sync("alice", 2).unwrap();
    let Since::Events(events) = sync else { panic!("expected Events") };
    assert_eq!(events.len(), 1);
    let (c, event) = &events[0];
    assert_eq!(*c, 3);
    assert_eq!(event.actor, "bob");
    assert_eq!(event.kind, EventKind::Edited { target: 2 });
    // render("hello **world** @alice") → "hello <strong>world</strong> @alice"
    assert_eq!(event.html, "hello <strong>world</strong> @alice");
    // mentions → ["alice"]; alice is a member and not the actor → kept
    assert_eq!(event.mentions, vec!["alice".to_string()]);
}

#[test]
fn edit_rejects_in_documented_order() {
    let mut svc = RoomService::new("alice", 10);
    svc.add_member("alice", "bob", Role::Member).unwrap(); // cursor 1
    let posted = svc.post("bob", "hello").unwrap(); // cursor 2

    // 1. Non-member → Room(NotMember)
    let err = svc.edit("dave", posted, "x").unwrap_err();
    assert_eq!(err, ServiceError::Room(RoomError::NotMember));

    // 2. Target not a live Posted event → NoSuchMessage
    let err = svc.edit("bob", 999, "x").unwrap_err();
    assert_eq!(err, ServiceError::NoSuchMessage);

    // 3. Not the author (even an Owner) → NotAllowed
    let err = svc.edit("alice", posted, "x").unwrap_err();
    assert_eq!(err, ServiceError::NotAllowed);

    // 4. Empty text → EmptyText
    let err = svc.edit("bob", posted, "   ").unwrap_err();
    assert_eq!(err, ServiceError::EmptyText);

    // 5. Too long → TooLong
    let long_text = "a".repeat(4001);
    let err = svc.edit("bob", posted, &long_text).unwrap_err();
    assert_eq!(err, ServiceError::TooLong);
}

#[test]
fn delete_success_appends_deleted_event_and_blocks_reuse() {
    let mut svc = RoomService::new("alice", 10);
    svc.add_member("alice", "bob", Role::Member).unwrap(); // cursor 1
    let posted = svc.post("bob", "to be deleted").unwrap(); // cursor 2

    // alice (Owner) may delete
    let cursor = svc.delete("alice", posted).unwrap();
    assert_eq!(cursor, 3);

    let sync = svc.sync("alice", 2).unwrap();
    let Since::Events(events) = sync else { panic!("expected Events") };
    assert_eq!(events.len(), 1);
    let (c, event) = &events[0];
    assert_eq!(*c, 3);
    assert_eq!(event.actor, "alice");
    assert_eq!(event.kind, EventKind::Deleted { target: 2 });
    assert_eq!(event.html, "");
    assert!(event.mentions.is_empty());

    // The target can no longer be edited
    let err = svc.edit("bob", posted, "new text").unwrap_err();
    assert_eq!(err, ServiceError::NoSuchMessage);

    // The target can no longer be deleted
    let err = svc.delete("alice", posted).unwrap_err();
    assert_eq!(err, ServiceError::NoSuchMessage);
}

#[test]
fn delete_rejects_non_author_non_admin_non_owner() {
    let mut svc = RoomService::new("alice", 10);
    svc.add_member("alice", "bob", Role::Member).unwrap(); // cursor 1
    svc.add_member("alice", "carol", Role::Member).unwrap(); // cursor 2
    let posted = svc.post("bob", "my post").unwrap(); // cursor 3

    // carol is a Member (not author, not Admin, not Owner) → NotAllowed
    let err = svc.delete("carol", posted).unwrap_err();
    assert_eq!(err, ServiceError::NotAllowed);

    // bob (the author) may delete
    svc.delete("bob", posted).unwrap();
}

#[test]
fn sync_rejects_non_members_and_returns_events_after_cursor() {
    let mut svc = RoomService::new("alice", 10);
    svc.add_member("alice", "bob", Role::Member).unwrap(); // cursor 1
    svc.post("bob", "hello").unwrap(); // cursor 2

    // Non-member cannot sync
    let err = svc.sync("dave", 0).unwrap_err();
    assert_eq!(err, ServiceError::Room(RoomError::NotMember));

    // Member syncs from 0: gets both events
    let sync = svc.sync("bob", 0).unwrap();
    let Since::Events(events) = sync else { panic!("expected Events") };
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].0, 1);
    assert_eq!(events[1].0, 2);

    // Member syncs from 1: gets only event 2
    let sync = svc.sync("bob", 1).unwrap();
    let Since::Events(events) = sync else { panic!("expected Events") };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, 2);

    // Member syncs at head: empty
    let sync = svc.sync("bob", 2).unwrap();
    assert_eq!(sync, Since::Events(vec![]));
}

#[test]
fn mark_read_and_unread_count_only_others_live_posts() {
    let mut svc = RoomService::new("alice", 10);
    svc.add_member("alice", "bob", Role::Member).unwrap(); // cursor 1
    svc.post("bob", "hi").unwrap(); // cursor 2
    svc.post("alice", "hello").unwrap(); // cursor 3

    // alice: Posted after marker 0, by someone else → bob's post = 1
    assert_eq!(svc.unread("alice").unwrap(), 1);

    // bob: Posted after marker 0, by someone else → alice's post = 1
    assert_eq!(svc.unread("bob").unwrap(), 1);

    // alice marks read to 3
    assert!(svc.mark_read("alice", 3).unwrap());
    assert_eq!(svc.unread("alice").unwrap(), 0);

    // bob posts again → cursor 4
    svc.post("bob", "again").unwrap();
    assert_eq!(svc.unread("alice").unwrap(), 1);

    // marker never moves backwards
    assert!(!svc.mark_read("alice", 1).unwrap());
    assert_eq!(svc.unread("alice").unwrap(), 1);
}

#[test]
fn unread_excludes_deleted_posts_and_non_posted_events() {
    let mut svc = RoomService::new("alice", 10);
    svc.add_member("alice", "bob", Role::Member).unwrap(); // cursor 1 (Joined)
    let posted = svc.post("bob", "will be deleted").unwrap(); // cursor 2 (Posted)
    svc.delete("alice", posted).unwrap(); // cursor 3 (Deleted)

    // alice's unread: bob's only Posted event was deleted → 0
    assert_eq!(svc.unread("alice").unwrap(), 0);
}

#[test]
fn capacity_limits_held_events_and_causes_gap() {
    let mut svc = RoomService::new("alice", 2); // keeps newest 2
    svc.add_member("alice", "bob", Role::Member).unwrap(); // cursor 1
    svc.post("bob", "one").unwrap(); // cursor 2
    svc.post("bob", "two").unwrap(); // cursor 3; cursor 1 evicted

    assert_eq!(svc.head(), 3);

    // cursor 0: 0+1=1 < oldest(2) → Gap
    let sync = svc.sync("alice", 0).unwrap();
    assert_eq!(sync, Since::Gap { oldest: 2 });

    // cursor 1: 1+1=2, not < 2 → events after 1 → [2, 3]
    let sync = svc.sync("alice", 1).unwrap();
    let Since::Events(events) = sync else { panic!("expected Events") };
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].0, 2);
    assert_eq!(events[1].0, 3);
}

#[test]
fn post_trims_text_before_rendering_and_measuring_length() {
    let mut svc = RoomService::new("alice", 10);

    // Leading/trailing whitespace is trimmed before render
    let cursor = svc.post("alice", "  hello world  ").unwrap();
    assert_eq!(cursor, 1);

    let sync = svc.sync("alice", 0).unwrap();
    let Since::Events(events) = sync else { panic!("expected Events") };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].1.html, "hello world");

    // Exactly 4000 chars (== MAX_TEXT_CHARS) is allowed
    let ok_text = "a".repeat(4000);
    let cursor = svc.post("alice", &ok_text).unwrap();
    assert_eq!(cursor, 2);

    // 4001 chars → TooLong
    let bad_text = "a".repeat(4001);
    let err = svc.post("alice", &bad_text).unwrap_err();
    assert_eq!(err, ServiceError::TooLong);
}

#[test]
fn post_mentions_ignore_code_spans_and_non_member_names() {
    let mut svc = RoomService::new("alice", 10);
    svc.add_member("alice", "bob", Role::Member).unwrap(); // cursor 1

    // @bob inside backticks is NOT a mention; @bob outside IS; @dave is not a member
    let text = "see `@bob` then @bob and @dave";
    let cursor = svc.post("alice", text).unwrap();
    assert_eq!(cursor, 2);

    let sync = svc.sync("alice", 1).unwrap();
    let Since::Events(events) = sync else { panic!("expected Events") };
    assert_eq!(events.len(), 1);
    // mentions → ["bob", "dave"] (code-span @bob ignored)
    // filter to members → ["bob"]
    // exclude actor "alice" → ["bob"]
    assert_eq!(events[0].1.mentions, vec!["bob".to_string()]);
}

#[test]
fn edit_and_delete_target_only_posted_events() {
    let mut svc = RoomService::new("alice", 10);
    let joined = svc.add_member("alice", "bob", Role::Member).unwrap(); // cursor 1, Joined by alice
    let posted = svc.post("alice", "hello").unwrap(); // cursor 2
    let edited = svc.edit("alice", posted, "hello again").unwrap(); // cursor 3, Edited by alice

    // A Joined or Edited event is not a message, even for the actor who made it
    assert_eq!(svc.edit("alice", joined, "x").unwrap_err(), ServiceError::NoSuchMessage);
    assert_eq!(svc.delete("alice", joined).unwrap_err(), ServiceError::NoSuchMessage);
    assert_eq!(svc.edit("alice", edited, "x").unwrap_err(), ServiceError::NoSuchMessage);
    assert_eq!(svc.delete("alice", edited).unwrap_err(), ServiceError::NoSuchMessage);
    assert_eq!(svc.head(), 3);
}
