#![allow(clippy::unwrap_used)]

use crewcraft_proto::request::{Request, Response};
use crewcraft_server_core::dispatch::{E_BAD_TEXT, E_NO_SUCH_MESSAGE, E_NO_SUCH_ROOM, E_NOT_ALLOWED, E_OTHER, E_RATE_LIMITED, error_code, handle};
use crewcraft_server_core::room::{Role, RoomError};
use crewcraft_server_core::room_service::ServiceError;
use crewcraft_server_core::server::{Server, ServerError};

/// Every `ServerError` variant must map to the documented `u16` code.
#[test]
fn test_error_code_all_variants() {
    assert_eq!(error_code(ServerError::NoSuchRoom), E_NO_SUCH_ROOM);
    assert_eq!(error_code(ServerError::Service(ServiceError::Room(RoomError::NotMember))), E_NO_SUCH_ROOM);
    assert_eq!(error_code(ServerError::RateLimited), E_RATE_LIMITED);
    assert_eq!(error_code(ServerError::Service(ServiceError::NotAllowed)), E_NOT_ALLOWED);
    assert_eq!(error_code(ServerError::Service(ServiceError::Room(RoomError::Forbidden))), E_NOT_ALLOWED);
    assert_eq!(error_code(ServerError::Service(ServiceError::EmptyText)), E_BAD_TEXT);
    assert_eq!(error_code(ServerError::Service(ServiceError::TooLong)), E_BAD_TEXT);
    assert_eq!(error_code(ServerError::Service(ServiceError::NoSuchMessage)), E_NO_SUCH_MESSAGE);
    assert_eq!(error_code(ServerError::Service(ServiceError::Room(RoomError::AlreadyMember))), E_OTHER);
    assert_eq!(error_code(ServerError::Service(ServiceError::Room(RoomError::LastOwner))), E_OTHER);

    // `create_room` can only fail with `BadName`; an empty name is rejected by validation.
    let mut server = Server::new();
    let bad = server.create_room("alice", "").unwrap_err();
    assert_eq!(error_code(bad), E_OTHER);
}

/// `Ping` always succeeds with cursor 0, regardless of room or membership state.
#[test]
fn test_ping_always_succeeds() {
    let mut server = Server::new();
    let resp = handle(&mut server, "nobody", &Request::Ping, 999_999);
    assert_eq!(resp, Response::Ok { cursor: 0 });
}

/// A `Post` to a room that does not exist yields `E_NO_SUCH_ROOM` with empty detail.
#[test]
fn test_post_nonexistent_room() {
    let mut server = Server::new();
    let req = Request::Post { room: "ghost".into(), text: "hello".into() };
    let resp = handle(&mut server, "alice", &req, 0);
    assert_eq!(resp, Response::Error { code: E_NO_SUCH_ROOM, detail: String::new() });
}

/// A `Post` by a non-member is indistinguishable from a missing room: `E_NO_SUCH_ROOM`.
#[test]
fn test_post_non_member_indistinguishable_from_missing_room() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Secret").unwrap();

    let existing = Request::Post { room: slug.clone(), text: "hello".into() };
    let resp = handle(&mut server, "bob", &existing, 0);
    assert_eq!(resp, Response::Error { code: E_NO_SUCH_ROOM, detail: String::new() });

    let missing = Request::Post { room: "nope".into(), text: "hello".into() };
    let resp2 = handle(&mut server, "bob", &missing, 0);
    assert_eq!(resp, resp2);
}

/// A `Post` by a Guest (member but cannot post) yields `E_NOT_ALLOWED`.
#[test]
fn test_post_guest_not_allowed() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Room").unwrap();
    server.add_member(&slug, "alice", "carol", Role::Guest).unwrap();

    let req = Request::Post { room: slug, text: "hi".into() };
    let resp = handle(&mut server, "carol", &req, 0);
    assert_eq!(resp, Response::Error { code: E_NOT_ALLOWED, detail: String::new() });
}

/// `Post` with only-whitespace text is `E_BAD_TEXT`.
#[test]
fn test_post_empty_text() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Room").unwrap();

    let req = Request::Post { room: slug, text: "   \t\n  ".into() };
    let resp = handle(&mut server, "alice", &req, 0);
    assert_eq!(resp, Response::Error { code: E_BAD_TEXT, detail: String::new() });
}

/// `Post` with text exceeding 4000 chars (after trimming) is `E_BAD_TEXT`.
#[test]
fn test_post_too_long_text() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Room").unwrap();

    // 4001 characters is over the limit.
    let long = "a".repeat(4001);
    let req = Request::Post { room: slug, text: long };
    let resp = handle(&mut server, "alice", &req, 0);
    assert_eq!(resp, Response::Error { code: E_BAD_TEXT, detail: String::new() });
}

/// A successful `Post` returns the new event's cursor (1 for the first post in a fresh room).
#[test]
fn test_post_success_returns_cursor() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Room").unwrap();

    let req = Request::Post { room: slug.clone(), text: "hello world".into() };
    let resp = handle(&mut server, "alice", &req, 0);
    assert_eq!(resp, Response::Ok { cursor: 1 });

    // Second post increments.
    let req2 = Request::Post { room: slug, text: "again".into() };
    let resp2 = handle(&mut server, "alice", &req2, 0);
    assert_eq!(resp2, Response::Ok { cursor: 2 });
}

/// After exhausting the burst of 20 tokens at the same timestamp, the next `Post` is `E_RATE_LIMITED`.
#[test]
fn test_post_rate_limited_after_burst() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Room").unwrap();

    // Consume all 20 burst tokens at t=0.
    for _ in 0..20 {
        let req = Request::Post { room: slug.clone(), text: "x".into() };
        let resp = handle(&mut server, "alice", &req, 0);
        assert!(matches!(resp, Response::Ok { cursor: _ }), "expected Ok, got {resp:?}");
    }

    // 21st post at the same instant: bucket is empty.
    let req = Request::Post { room: slug, text: "x".into() };
    let resp = handle(&mut server, "alice", &req, 0);
    assert_eq!(resp, Response::Error { code: E_RATE_LIMITED, detail: String::new() });
}

/// `Edit` of a nonexistent target yields `E_NO_SUCH_MESSAGE`; `Delete` of a nonexistent target likewise.
#[test]
fn test_edit_and_delete_nonexistent_message() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Room").unwrap();

    let edit_req = Request::Edit { room: slug.clone(), target: 999, text: "new text".into() };
    let resp = handle(&mut server, "alice", &edit_req, 0);
    assert_eq!(resp, Response::Error { code: E_NO_SUCH_MESSAGE, detail: String::new() });

    let del_req = Request::Delete { room: slug, target: 999 };
    let resp = handle(&mut server, "alice", &del_req, 0);
    assert_eq!(resp, Response::Error { code: E_NO_SUCH_MESSAGE, detail: String::new() });
}

/// `Edit` by someone who is not the author is `E_NOT_ALLOWED`.
#[test]
fn test_edit_by_non_author_not_allowed() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Room").unwrap();
    server.add_member(&slug, "alice", "bob", Role::Member).unwrap();

    // Alice posts (cursor 2: adding bob was cursor 1).
    let post_req = Request::Post { room: slug.clone(), text: "original".into() };
    assert_eq!(handle(&mut server, "alice", &post_req, 0), Response::Ok { cursor: 2 });

    // Bob tries to edit Alice's message.
    let edit_req = Request::Edit { room: slug, target: 2, text: "tampered".into() };
    let resp = handle(&mut server, "bob", &edit_req, 0);
    assert_eq!(resp, Response::Error { code: E_NOT_ALLOWED, detail: String::new() });
}

/// `Sync` by a non-member is `E_NO_SUCH_ROOM` (same code as a missing room).
#[test]
fn test_sync_non_member_is_no_such_room() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Room").unwrap();

    // Post something so the room has events.
    let post_req = Request::Post { room: slug.clone(), text: "hello".into() };
    let _ = handle(&mut server, "alice", &post_req, 0);

    // Bob is not a member.
    let sync_req = Request::Sync { room: slug, cursor: 0 };
    let resp = handle(&mut server, "bob", &sync_req, 0);
    assert_eq!(resp, Response::Error { code: E_NO_SUCH_ROOM, detail: String::new() });
}

/// `Sync` by a member returns the room's head as the cursor.
#[test]
fn test_sync_success_returns_room_head() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Room").unwrap();
    server.add_member(&slug, "alice", "bob", Role::Member).unwrap();

    // Two posts → head becomes 3 (add_member=1, post=2, post=3).
    let p1 = Request::Post { room: slug.clone(), text: "one".into() };
    let _ = handle(&mut server, "alice", &p1, 0);
    let p2 = Request::Post { room: slug.clone(), text: "two".into() };
    let _ = handle(&mut server, "bob", &p2, 0);

    let sync_req = Request::Sync { room: slug, cursor: 0 };
    let resp = handle(&mut server, "bob", &sync_req, 0);
    assert_eq!(resp, Response::Ok { cursor: 3 });
}

/// `MarkRead` by a non-member is `E_NO_SUCH_ROOM`; by a member it returns the room's head.
#[test]
fn test_mark_read_membership_and_head() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Room").unwrap();
    server.add_member(&slug, "alice", "bob", Role::Member).unwrap();

    // Post one message (cursor 2, since add_member took cursor 1).
    let post_req = Request::Post { room: slug.clone(), text: "hello".into() };
    let _ = handle(&mut server, "alice", &post_req, 0);

    // Non-member: code 1.
    let mr_stranger = Request::MarkRead { room: slug.clone(), cursor: 1 };
    let resp = handle(&mut server, "eve", &mr_stranger, 0);
    assert_eq!(resp, Response::Error { code: E_NO_SUCH_ROOM, detail: String::new() });

    // Member: Ok with room head (2).
    let mr_bob = Request::MarkRead { room: slug, cursor: 2 };
    let resp = handle(&mut server, "bob", &mr_bob, 0);
    assert_eq!(resp, Response::Ok { cursor: 2 });
}

/// Every error response carries an empty `detail` string, preventing leakage of room/user info.
#[test]
fn test_all_error_responses_have_empty_detail() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Room").unwrap();
    server.add_member(&slug, "alice", "bob", Role::Member).unwrap();
    server.add_member(&slug, "alice", "carol", Role::Guest).unwrap();

    let cases: Vec<(&str, Request)> = vec![
        ("alice", Request::Post { room: "missing".into(), text: "hi".into() }),
        ("eve", Request::Sync { room: slug.clone(), cursor: 0 }),
        ("carol", Request::Post { room: slug.clone(), text: "   ".into() }),
        ("carol", Request::Post { room: slug.clone(), text: "a".repeat(5000) }),
        ("alice", Request::Edit { room: slug.clone(), target: 99, text: "x".into() }),
        ("alice", Request::Delete { room: "missing".into(), target: 1 }),
        ("eve", Request::MarkRead { room: slug.clone(), cursor: 0 }),
    ];

    for (user, req) in cases {
        let resp = handle(&mut server, user, &req, 0);
        match resp {
            Response::Error { code: _, detail } => assert!(detail.is_empty()),
            Response::Ok { .. } => panic!("expected an error for user {user}"),
        }
    }
}

/// `Delete` by the author succeeds and returns the new cursor; a second delete of the same
/// target is `E_NO_SUCH_MESSAGE`.
#[test]
fn test_delete_success_then_already_deleted() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Room").unwrap();

    // Post → cursor 1.
    let post_req = Request::Post { room: slug.clone(), text: "to be deleted".into() };
    let resp = handle(&mut server, "alice", &post_req, 0);
    assert_eq!(resp, Response::Ok { cursor: 1 });

    // Delete → cursor 2.
    let del_req = Request::Delete { room: slug.clone(), target: 1 };
    let resp = handle(&mut server, "alice", &del_req, 0);
    assert_eq!(resp, Response::Ok { cursor: 2 });

    // Delete again → NoSuchMessage (code 5).
    let del_req2 = Request::Delete { room: slug, target: 1 };
    let resp = handle(&mut server, "alice", &del_req2, 0);
    assert_eq!(resp, Response::Error { code: E_NO_SUCH_MESSAGE, detail: String::new() });
}

/// `Edit` by the author succeeds and returns the new cursor.
#[test]
fn test_edit_success_returns_cursor() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Room").unwrap();

    // Post → cursor 1.
    let post_req = Request::Post { room: slug.clone(), text: "original".into() };
    let _ = handle(&mut server, "alice", &post_req, 0);

    // Edit cursor 1 → cursor 2.
    let edit_req = Request::Edit { room: slug, target: 1, text: "updated".into() };
    let resp = handle(&mut server, "alice", &edit_req, 0);
    assert_eq!(resp, Response::Ok { cursor: 2 });
}

/// `Post` to a nonexistent room and `Sync` to a nonexistent room both yield the same response,
/// so a user cannot probe which slugs exist.
#[test]
fn test_missing_room_uniform_response() {
    let mut server = Server::new();

    let post = Request::Post { room: "ghost".into(), text: "hi".into() };
    let sync = Request::Sync { room: "ghost".into(), cursor: 0 };
    let mark = Request::MarkRead { room: "ghost".into(), cursor: 0 };
    let edit = Request::Edit { room: "ghost".into(), target: 1, text: "x".into() };
    let del = Request::Delete { room: "ghost".into(), target: 1 };

    let expected = Response::Error { code: E_NO_SUCH_ROOM, detail: String::new() };
    assert_eq!(handle(&mut server, "alice", &post, 0), expected);
    assert_eq!(handle(&mut server, "alice", &sync, 0), expected);
    assert_eq!(handle(&mut server, "alice", &mark, 0), expected);
    assert_eq!(handle(&mut server, "alice", &edit, 0), expected);
    assert_eq!(handle(&mut server, "alice", &del, 0), expected);
}

/// `Edit` is the plain `Server::edit` call: a refused edit has still used a rate-limit token, as for `Post`.
#[test]
fn test_refused_edits_use_rate_limit_tokens() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "Room").unwrap();
    server.add_member(&slug, "alice", "bob", Role::Member).unwrap();
    let post = Request::Post { room: slug.clone(), text: "mine".into() };
    let Response::Ok { cursor } = handle(&mut server, "alice", &post, 0) else { panic!("post failed") };

    for _ in 0..20 {
        let edit = Request::Edit { room: slug.clone(), target: cursor, text: "not yours".into() };
        assert_eq!(handle(&mut server, "bob", &edit, 0), Response::Error { code: E_NOT_ALLOWED, detail: String::new() });
    }
    let bob_post = Request::Post { room: slug, text: "hello".into() };
    assert_eq!(handle(&mut server, "bob", &bob_post, 0), Response::Error { code: E_RATE_LIMITED, detail: String::new() });
}
