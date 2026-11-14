#![allow(clippy::unwrap_used)]

use crewcraft_proto::frame::{FrameError, MAX_FRAME, encode};
use crewcraft_proto::message::CodecError;
use crewcraft_proto::push::{Push, encode_push};
use crewcraft_proto::request::{Request, Response, encode_request, encode_response};
use crewcraft_server_core::connection::{ConnError, Connection, to_push};
use crewcraft_server_core::room::Role;
use crewcraft_server_core::room_service::{Event, EventKind};
use crewcraft_server_core::server::Server;

/// Build a length-prefixed frame whose payload is an encoded request.
fn framed_request(id: u32, request: &Request) -> Vec<u8> {
    let payload = encode_request(id, request).unwrap();
    encode(&payload).unwrap()
}

/// Build a length-prefixed frame whose payload is an Ok response.
fn framed_ok(id: u32, cursor: u64) -> Vec<u8> {
    let payload = encode_response(id, &Response::Ok { cursor }).unwrap();
    encode(&payload).unwrap()
}

// ─── to_push: pure mapping from Event → Push ───────────────────────────────────

#[test]
fn to_push_posted_maps_actor_to_author_and_carries_html_mentions() {
    let event = Event {
        cursor: 5,
        actor: "alice".to_string(),
        kind: EventKind::Posted,
        html: "hello <b>world</b>".to_string(),
        mentions: vec!["bob".to_string(), "carol".to_string()],
    };
    let push = to_push("general", 5, &event);
    assert_eq!(
        push,
        Push::Posted {
            room: "general".to_string(),
            cursor: 5,
            author: "alice".to_string(),
            html: "hello <b>world</b>".to_string(),
            mentions: vec!["bob".to_string(), "carol".to_string()],
        }
    );
}

#[test]
fn to_push_edited_carries_target_html_and_mentions() {
    let event = Event {
        cursor: 7,
        actor: "alice".to_string(),
        kind: EventKind::Edited { target: 3 },
        html: "fixed typo".to_string(),
        mentions: vec!["dave".to_string()],
    };
    let push = to_push("general", 7, &event);
    assert_eq!(
        push,
        Push::Edited { room: "general".to_string(), cursor: 7, target: 3, html: "fixed typo".to_string(), mentions: vec!["dave".to_string()] }
    );
}

#[test]
fn to_push_deleted_carries_target() {
    let event = Event { cursor: 10, actor: "bob".to_string(), kind: EventKind::Deleted { target: 4 }, html: String::new(), mentions: Vec::new() };
    let push = to_push("room-42", 10, &event);
    assert_eq!(push, Push::Deleted { room: "room-42".to_string(), cursor: 10, target: 4 });
}

#[test]
fn to_push_joined_becomes_other() {
    let event = Event {
        cursor: 2,
        actor: "admin".to_string(),
        kind: EventKind::Joined { user: "newbie".to_string(), role: Role::Admin },
        html: String::new(),
        mentions: Vec::new(),
    };
    let push = to_push("general", 2, &event);
    assert_eq!(push, Push::Other { room: "general".to_string(), cursor: 2 });
}

#[test]
fn to_push_left_becomes_other() {
    let event = Event {
        cursor: 3,
        actor: "admin".to_string(),
        kind: EventKind::Left { user: "newbie".to_string() },
        html: String::new(),
        mentions: Vec::new(),
    };
    let push = to_push("general", 3, &event);
    assert_eq!(push, Push::Other { room: "general".to_string(), cursor: 3 });
}

// ─── Connection::receive: frame buffering and request processing ───────────────

#[test]
fn receive_ping_returns_single_ok_zero_frame() {
    let mut conn = Connection::new("alice");
    let mut server = Server::new();
    let frame = framed_request(42, &Request::Ping);
    let out = conn.receive(&mut server, &frame, 1_000).unwrap();
    assert_eq!(out, framed_ok(42, 0));
}

#[test]
fn receive_buffers_bytes_until_a_whole_frame_forms() {
    let mut conn = Connection::new("alice");
    let mut server = Server::new();
    let full = framed_request(1, &Request::Ping);
    // Split after the 4-byte length header and 2 payload bytes (6 of 9 total).
    let split = 6;
    let first_half = &full[..split];
    let second_half = &full[split..];

    // First call: header says 5-byte payload but only 2 bytes present → no frame yet.
    let out1 = conn.receive(&mut server, first_half, 1_000).unwrap();
    assert!(out1.is_empty());

    // Second call: remaining 3 bytes complete the frame → response emitted.
    let out2 = conn.receive(&mut server, second_half, 1_001).unwrap();
    assert_eq!(out2, framed_ok(1, 0));
}

#[test]
fn receive_processes_multiple_frames_in_one_call_in_order() {
    let mut conn = Connection::new("alice");
    let mut server = Server::new();
    let f1 = framed_request(10, &Request::Ping);
    let f2 = framed_request(20, &Request::Ping);
    let combined: Vec<u8> = f1.iter().chain(f2.iter()).copied().collect();

    let out = conn.receive(&mut server, &combined, 1_000).unwrap();
    let expected: Vec<u8> = framed_ok(10, 0).iter().chain(framed_ok(20, 0).iter()).copied().collect();
    assert_eq!(out, expected);
}

// ─── ConnError::Frame ──────────────────────────────────────────────────────────

#[test]
fn receive_returns_frame_error_when_header_announces_oversize() {
    let mut conn = Connection::new("alice");
    let mut server = Server::new();
    // 4-byte big-endian header announcing a payload of MAX_FRAME + 1 bytes.
    let announced = MAX_FRAME + 1;
    let bytes = (announced as u32).to_be_bytes().to_vec();

    let result = conn.receive(&mut server, &bytes, 1_000);
    assert_eq!(result, Err(ConnError::Frame(FrameError::TooLarge(announced))));
}

// ─── ConnError::Request ────────────────────────────────────────────────────────

#[test]
fn receive_returns_request_error_for_unknown_tag() {
    let mut conn = Connection::new("alice");
    let mut server = Server::new();
    // Payload: tag 99 (not 1–6) | u32 id 1
    let payload = vec![99u8, 0, 0, 0, 1];
    let frame = encode(&payload).unwrap();

    let result = conn.receive(&mut server, &frame, 1_000);
    assert_eq!(result, Err(ConnError::Request(CodecError::BadKind(99))));
}

#[test]
fn receive_returns_request_error_for_truncated_fields() {
    let mut conn = Connection::new("alice");
    let mut server = Server::new();
    // Payload: tag 1 (Post) | u32 id 7 | 1 byte (not enough for the 2-byte room length)
    let payload = vec![1u8, 0, 0, 0, 7, 0];
    let frame = encode(&payload).unwrap();

    let result = conn.receive(&mut server, &frame, 1_000);
    assert_eq!(result, Err(ConnError::Request(CodecError::Truncated)));
}

// ─── Fatal error: nothing from the call is sent ───────────────────────────────

#[test]
fn fatal_error_discards_earlier_successful_responses() {
    let mut conn = Connection::new("alice");
    let mut server = Server::new();
    // Frame 1: valid Ping (would produce Ok { cursor: 0 }).
    let good = framed_request(1, &Request::Ping);
    // Frame 2: invalid tag → fatal.
    let bad_payload = vec![99u8, 0, 0, 0, 1];
    let bad = encode(&bad_payload).unwrap();

    let combined: Vec<u8> = good.iter().chain(bad.iter()).copied().collect();
    let result = conn.receive(&mut server, &combined, 1_000);

    // Only the error is returned; the earlier Ok response is NOT included.
    assert_eq!(result, Err(ConnError::Request(CodecError::BadKind(99))));
}

// --- Sync: the response, then the room's events as pushes (added in review) ---

#[test]
fn sync_is_answered_then_followed_by_the_room_events_as_pushes() {
    let mut server = Server::new();
    let slug = server.create_room("alice", "General").unwrap();
    server.add_member(&slug, "alice", "bob", Role::Member).unwrap(); // cursor 1

    // Alice posts through her own connection: the response carries the new cursor.
    let mut alice = Connection::new("alice");
    let out = alice.receive(&mut server, &framed_request(4, &Request::Post { room: slug.clone(), text: "hi @bob".into() }), 0).unwrap();
    assert_eq!(out, framed_ok(4, 2));

    // Bob syncs after cursor 1: Ok with the head, then one push for the post.
    let mut bob = Connection::new("bob");
    let out = bob.receive(&mut server, &framed_request(5, &Request::Sync { room: slug.clone(), cursor: 1 }), 0).unwrap();
    let mut expected = framed_ok(5, 2);
    let push = Push::Posted { room: slug.clone(), cursor: 2, author: "alice".into(), html: "hi @bob".into(), mentions: vec!["bob".into()] };
    expected.extend(encode(&encode_push(&push).unwrap()).unwrap());
    assert_eq!(out, expected);

    // A non-member gets the same answer as for a missing room, and no pushes.
    let mut eve = Connection::new("eve");
    let out = eve.receive(&mut server, &framed_request(6, &Request::Sync { room: slug, cursor: 0 }), 0).unwrap();
    assert_eq!(out, encode(&encode_response(6, &Response::Error { code: 1, detail: String::new() }).unwrap()).unwrap());
}

#[test]
fn to_push_keeps_at_most_max_mentions() {
    use crewcraft_proto::push::MAX_MENTIONS;
    let mentions: Vec<String> = (0..MAX_MENTIONS + 3).map(|i| format!("user{i}")).collect();
    let event = Event { cursor: 9, actor: "alice".to_string(), kind: EventKind::Posted, html: "hi".to_string(), mentions: mentions.clone() };
    let push = to_push("general", 9, &event);
    let Push::Posted { mentions: kept, .. } = &push else { panic!("expected Posted") };
    assert_eq!(kept, &mentions[..MAX_MENTIONS].to_vec());
    assert!(encode_push(&push).is_ok());
}
