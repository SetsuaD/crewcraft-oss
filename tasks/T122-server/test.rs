#![allow(clippy::unwrap_used)]

use crewcraft_server_core::room::Role;
use crewcraft_server_core::room::RoomError;
use crewcraft_server_core::room_name::NameError;
use crewcraft_server_core::room_service::ServiceError;
use crewcraft_server_core::server::{Server, ServerError};

#[test]
fn test_create_room_slug_and_ownership() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "  General   Chat  ").unwrap();
    assert_eq!(slug, "general-chat");

    // Owner appears in rooms_of with the cleaned name and Owner role.
    let rooms = server.rooms_of("alice");
    assert_eq!(rooms.len(), 1);
    assert_eq!(rooms[0].slug, "general-chat");
    assert_eq!(rooms[0].name, "General Chat");
    assert_eq!(rooms[0].role, Role::Owner);

    // The room is accessible by slug.
    let room = server.room("general-chat").unwrap();
    assert_eq!(room.role("alice"), Some(Role::Owner));
}

#[test]
fn test_create_room_duplicate_slugs_get_incrementing_suffixes() {
    let mut server = Server::new();
    let s1 = server.create_room("alice", "General").unwrap();
    let s2 = server.create_room("bob", "General").unwrap();
    let s3 = server.create_room("carol", "General").unwrap();
    assert_eq!(s1, "general");
    assert_eq!(s2, "general-2");
    assert_eq!(s3, "general-3");

    // Each room is independently accessible.
    assert!(server.room("general").is_ok());
    assert!(server.room("general-2").is_ok());
    assert!(server.room("general-3").is_ok());
}

#[test]
fn test_create_room_rejects_bad_names() {
    let mut server = Server::new();

    // Empty after trimming.
    let err = server.create_room("alice", "   ").unwrap_err();
    assert_eq!(err, ServerError::BadName(NameError::Empty));

    // Control character anywhere.
    let err = server.create_room("alice", "Hello\tWorld").unwrap_err();
    assert_eq!(err, ServerError::BadName(NameError::ControlCharacter));

    // Longer than 64 characters.
    let long = "a".repeat(65);
    let err = server.create_room("alice", &long).unwrap_err();
    assert_eq!(err, ServerError::BadName(NameError::TooLong));
}

#[test]
fn test_room_no_such_room() {
    let server = Server::new();
    let result = server.room("does-not-exist");
    assert!(matches!(result, Err(ServerError::NoSuchRoom)));
}

#[test]
fn test_rooms_of_sorted_by_slug_and_filtered_to_membership() {
    let mut server = Server::new();
    // alice owns "zeta" and "alpha"
    let _ = server.create_room("alice", "Zeta").unwrap();
    let _ = server.create_room("alice", "Alpha").unwrap();
    // bob owns "alpha-2"
    let _ = server.create_room("bob", "Alpha").unwrap(); // slug "alpha-2"

    // alice's rooms sorted by slug: "alpha" < "zeta"
    let alice_rooms = server.rooms_of("alice");
    let alice_slugs: Vec<&str> = alice_rooms.iter().map(|r| r.slug.as_str()).collect();
    assert_eq!(alice_slugs, vec!["alpha", "zeta"]);

    // bob's rooms: only "alpha-2"
    let bob_rooms = server.rooms_of("bob");
    assert_eq!(bob_rooms.len(), 1);
    assert_eq!(bob_rooms[0].slug, "alpha-2");
    assert_eq!(bob_rooms[0].role, Role::Owner);

    // A user in no rooms gets an empty vec.
    assert!(server.rooms_of("dave").is_empty());
}

#[test]
fn test_post_rate_limit_burst_then_refill() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Chat").unwrap();

    // 20 posts succeed (burst of POST_BURST = 20).
    for _ in 0..20 {
        server.post(&slug, "alice", "hi", 0).unwrap();
    }

    // 21st post at the same instant is rate-limited.
    let err = server.post(&slug, "alice", "hi", 0).unwrap_err();
    assert_eq!(err, ServerError::RateLimited);

    // At t=500ms, 2/sec * 500ms = 1 token refilled; one post succeeds.
    server.post(&slug, "alice", "hi", 500).unwrap();

    // Immediately after, tokens are exhausted again.
    let err = server.post(&slug, "alice", "hi", 500).unwrap_err();
    assert_eq!(err, ServerError::RateLimited);
}

#[test]
fn test_post_refused_still_consumes_token() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Chat").unwrap();

    // Consume 19 tokens with valid posts.
    for _ in 0..19 {
        server.post(&slug, "alice", "hi", 0).unwrap();
    }

    // 20th call: token is taken, but RoomService rejects the empty text.
    let err = server.post(&slug, "alice", "   ", 0).unwrap_err();
    assert_eq!(err, ServerError::Service(ServiceError::EmptyText));

    // Token was consumed; the next valid post at the same instant is rate-limited.
    let err = server.post(&slug, "alice", "hi", 0).unwrap_err();
    assert_eq!(err, ServerError::RateLimited);
}

#[test]
fn test_post_no_such_room_checked_before_rate_limit() {
    let mut server = Server::new();
    let _ = server.create_room("alice", "Real").unwrap();

    // Even though the user has no bucket yet, a nonexistent room is NoSuchRoom, not RateLimited.
    let err = server.post("phantom", "alice", "hi", 0).unwrap_err();
    assert_eq!(err, ServerError::NoSuchRoom);
}

#[test]
fn test_post_and_edit_share_bucket() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Chat").unwrap();

    // Post once to get a cursor to edit later.
    let cursor = server.post(&slug, "alice", "hello", 0).unwrap();
    assert_eq!(cursor, 1);

    // Consume remaining 19 tokens.
    for _ in 0..19 {
        server.post(&slug, "alice", "hi", 0).unwrap();
    }

    // Edit at the same instant: bucket is empty → RateLimited.
    let err = server.edit(&slug, "alice", 1, "world", 0).unwrap_err();
    assert_eq!(err, ServerError::RateLimited);
}

#[test]
fn test_heartbeat_and_online_in() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Lounge").unwrap();
    // Add bob as a member.
    server.add_member(&slug, "alice", "bob", Role::Member).unwrap();

    // Both heartbeat at t=0.
    server.heartbeat("alice", 0);
    server.heartbeat("bob", 0);

    // At t=0 both are Online (age 0 < 60_000).
    let online = server.online_in(&slug, "alice", 0).unwrap();
    assert_eq!(online, vec!["alice".to_string(), "bob".to_string()]);

    // At t=60_000 age is exactly 60_000, which is NOT < ONLINE_MS, so neither is Online.
    let online = server.online_in(&slug, "alice", 60_000).unwrap();
    assert!(online.is_empty());
}

#[test]
fn test_online_in_rejects_non_member() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Private").unwrap();
    server.heartbeat("alice", 0);

    // dave is not in the room.
    let err = server.online_in(&slug, "dave", 0).unwrap_err();
    assert_eq!(err, ServerError::Service(ServiceError::Room(RoomError::NotMember)));
}

#[test]
fn test_online_in_no_such_room() {
    let server = Server::new();
    let err = server.online_in("ghost", "alice", 0).unwrap_err();
    assert_eq!(err, ServerError::NoSuchRoom);
}

#[test]
fn test_add_and_remove_member_delegate_to_room_service() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Squad").unwrap();

    // Add bob as Member; cursor should be 1 (first event).
    let c1 = server.add_member(&slug, "alice", "bob", Role::Member).unwrap();
    assert_eq!(c1, 1);

    // Add carol as Guest; cursor 2.
    let c2 = server.add_member(&slug, "alice", "carol", Role::Guest).unwrap();
    assert_eq!(c2, 2);

    // Remove bob; cursor 3.
    let c3 = server.remove_member(&slug, "alice", "bob").unwrap();
    assert_eq!(c3, 3);

    // Bob is gone; carol remains.
    let room = server.room(&slug).unwrap();
    assert_eq!(room.role("bob"), None);
    assert_eq!(room.role("carol"), Some(Role::Guest));

    // NoSuchRoom takes priority.
    let err = server.add_member("nope", "alice", "dave", Role::Member).unwrap_err();
    assert_eq!(err, ServerError::NoSuchRoom);
    let err = server.remove_member("nope", "alice", "dave").unwrap_err();
    assert_eq!(err, ServerError::NoSuchRoom);
}

#[test]
fn test_delete_and_mark_read_delegate() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Log").unwrap();

    // Post a message (cursor 1).
    let cursor = server.post(&slug, "alice", "important", 0).unwrap();
    assert_eq!(cursor, 1);

    // Delete it (cursor 2).
    let dc = server.delete(&slug, "alice", 1).unwrap();
    assert_eq!(dc, 2);

    // Mark read.
    let advanced = server.mark_read(&slug, "alice", 2).unwrap();
    assert!(advanced);

    // NoSuchRoom first.
    let err = server.delete("missing", "alice", 1).unwrap_err();
    assert_eq!(err, ServerError::NoSuchRoom);
    let err = server.mark_read("missing", "alice", 0).unwrap_err();
    assert_eq!(err, ServerError::NoSuchRoom);
}

#[test]
fn test_edit_refused_still_consumes_token() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Edit").unwrap();

    // One valid post.
    let cursor = server.post(&slug, "alice", "original", 0).unwrap();

    // Consume 18 more tokens, leaving one for the edit.
    for _ in 0..18 {
        server.post(&slug, "alice", "x", 0).unwrap();
    }

    // Edit with empty text: the last token is consumed, RoomService rejects.
    let err = server.edit(&slug, "alice", cursor, "  ", 0).unwrap_err();
    assert_eq!(err, ServerError::Service(ServiceError::EmptyText));

    // Now rate-limited for any further action.
    let err = server.post(&slug, "alice", "y", 0).unwrap_err();
    assert_eq!(err, ServerError::RateLimited);
}

#[test]
fn test_rate_limit_is_per_user_across_rooms() {
    let mut server = Server::new();
    let slug_a = server.create_room("alice", "Alpha").unwrap();
    let slug_b = server.create_room("alice", "Beta").unwrap();

    // Alice exhausts her single shared bucket in room A.
    for _ in 0..20 {
        server.post(&slug_a, "alice", "hi", 0).unwrap();
    }

    // Posting in room B at the same instant is also rate-limited.
    let err = server.post(&slug_b, "alice", "hi", 0).unwrap_err();
    assert_eq!(err, ServerError::RateLimited);

    // But a different user in room B can still post (separate bucket).
    // First add bob to room B.
    server.add_member(&slug_b, "alice", "bob", Role::Member).unwrap();
    server.post(&slug_b, "bob", "hello", 0).unwrap();
}

#[test]
fn test_guest_cannot_post() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Forum").unwrap();

    // Add bob as Guest.
    server.add_member(&slug, "alice", "bob", Role::Guest).unwrap();

    // Bob posts: token is consumed, but RoomService rejects (Guest cannot post → NotAllowed).
    let err = server.post(&slug, "bob", "hello", 0).unwrap_err();
    assert_eq!(err, ServerError::Service(ServiceError::NotAllowed));

    // The token was consumed. Consume remaining 19 tokens (all rejected but tokens taken).
    for _ in 0..19 {
        let _ = server.post(&slug, "bob", "x", 0);
    }
    // Now rate-limited.
    let err = server.post(&slug, "bob", "x", 0).unwrap_err();
    assert_eq!(err, ServerError::RateLimited);
}

#[test]
fn rate_limited_edit_leaves_the_room_unchanged() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Chat").unwrap();
    let posted = server.post(&slug, "alice", "hello", 0).unwrap();
    for _ in 0..19 {
        server.post(&slug, "alice", "hi", 0).unwrap();
    }
    let head = server.room(&slug).unwrap().head();
    assert_eq!(server.edit(&slug, "alice", posted, "changed", 0).unwrap_err(), ServerError::RateLimited);
    assert_eq!(server.room(&slug).unwrap().head(), head);
}

#[test]
fn test_non_member_never_reaches_the_rate_limiter() {
    // A room's existence must not leak through the limiter: a non-member is refused as NotMember (the same wire
    // answer as a missing room) every time, and never becomes RateLimited.
    let mut server = Server::new();
    let slug = server.create_room("alice", "Private").unwrap();
    for i in 0..25 {
        let err = server.post(&slug, "mallory", "hi", 0).unwrap_err();
        assert_eq!(err, ServerError::Service(ServiceError::Room(RoomError::NotMember)), "post {i}");
        let err = server.edit(&slug, "mallory", 1, "hi", 0).unwrap_err();
        assert_eq!(err, ServerError::Service(ServiceError::Room(RoomError::NotMember)), "edit {i}");
    }
    // The member's own bucket is untouched.
    assert!(server.post(&slug, "alice", "still fine", 0).is_ok());
}
