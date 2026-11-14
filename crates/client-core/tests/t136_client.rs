#![allow(clippy::unwrap_used)]

use crewcraft_client_core::client::{Client, ClientError, ClientEvent};
use crewcraft_client_core::notify::{Notify, Settings};
use crewcraft_client_core::requests::{Reply, TIMEOUT_MS};
use crewcraft_client_core::timeline::Apply;
use crewcraft_proto::frame::encode as frame_encode;
use crewcraft_proto::message::CodecError;
use crewcraft_proto::push::{Push, encode_push};
use crewcraft_proto::request::{Request, Response, encode_response};

#[test]
fn send_ping_produces_exact_frame() {
    let mut client = Client::new("me", Settings::default());
    let result = client.send(Request::Ping, 0).unwrap();
    // encode_request(1, &Ping) → [6, 0,0,0,1] (5 bytes)
    // frame_encode → 4-byte BE length (5) + payload
    assert_eq!(result, vec![0u8, 0, 0, 5, 6, 0, 0, 0, 1]);
}

#[test]
fn send_post_produces_exact_frame() {
    let mut client = Client::new("me", Settings::default());
    let req = Request::Post { room: "general".into(), text: "hello".into() };
    let result = client.send(req, 0).unwrap();
    // encode_request(1, Post{room:"general", text:"hello"}):
    //   [1, 0,0,0,1, 0,7,'g','e','n','e','r','a','l', 0,5,'h','e','l','l','o']  → 21 bytes
    // frame_encode → [0,0,0,21] + payload
    let expected = vec![
        0u8, 0, 0, 21, // length
        1,  // tag Post
        0, 0, 0, 1, // id = 1
        0, 7, b'g', b'e', b'n', b'e', b'r', b'a', b'l', 0, 5, b'h', b'e', b'l', b'l', b'o',
    ];
    assert_eq!(result, expected);
}

#[test]
fn send_rejects_empty_room_and_preserves_next_id() {
    let mut client = Client::new("me", Settings::default());
    let bad = Request::Post { room: String::new(), text: "hi".into() };
    let err = client.send(bad, 0).unwrap_err();
    assert_eq!(err, CodecError::FieldLength);
    // Nothing was remembered; the next send still starts at id 1.
    let ok = client.send(Request::Ping, 0).unwrap();
    assert_eq!(ok, vec![0u8, 0, 0, 5, 6, 0, 0, 0, 1]);
}

#[test]
fn send_increments_id_for_subsequent_requests() {
    let mut client = Client::new("me", Settings::default());
    let first = client.send(Request::Ping, 0).unwrap();
    let second = client.send(Request::Ping, 0).unwrap();
    // Both are Ping frames: the tag at byte 4, then the id (bytes 5..9).
    assert_eq!(&first[4..9], &[6, 0, 0, 0, 1]);
    assert_eq!(&second[4..9], &[6, 0, 0, 0, 2]);
}

#[test]
fn receive_response_ok_for_in_flight_request() {
    let mut client = Client::new("me", Settings::default());
    client.send(Request::Ping, 0).unwrap(); // id 1
    let payload = encode_response(1, &Response::Ok { cursor: 42 }).unwrap();
    let frame = frame_encode(&payload).unwrap();
    let events = client.receive(&frame, 0, 0).unwrap();
    assert_eq!(events, vec![ClientEvent::Reply(Reply::Done { id: 1, request: Request::Ping, response: Response::Ok { cursor: 42 } })]);
}

#[test]
fn receive_response_ok_for_unknown_id() {
    let mut client = Client::new("me", Settings::default());
    let payload = encode_response(99, &Response::Ok { cursor: 7 }).unwrap();
    let frame = frame_encode(&payload).unwrap();
    let events = client.receive(&frame, 0, 0).unwrap();
    assert_eq!(events, vec![ClientEvent::Reply(Reply::Unknown { id: 99 })]);
}

#[test]
fn receive_push_to_followed_room_emits_pushed() {
    let mut client = Client::new("me", Settings::default());
    client.inbox_mut().follow("general", false);
    // Cursor 1 is the next one for a fresh view; a post by someone else at default settings notifies with sound.
    let push = Push::Posted { room: "general".into(), cursor: 1, author: "alice".into(), html: "hi".into(), mentions: vec![] };
    let payload = encode_push(&push).unwrap();
    let frame = frame_encode(&payload).unwrap();
    let events = client.receive(&frame, 0, 0).unwrap();
    assert_eq!(events, vec![ClientEvent::Pushed { room: "general".into(), apply: Apply::Applied, notify: Notify::Sound }]);
}

#[test]
fn receive_push_to_unfollowed_room_is_ignored() {
    let mut client = Client::new("me", Settings::default());
    let push = Push::Other { room: "strangers".into(), cursor: 1 };
    let payload = encode_push(&push).unwrap();
    let frame = frame_encode(&payload).unwrap();
    let events = client.receive(&frame, 0, 0).unwrap();
    assert_eq!(events, vec![ClientEvent::Ignored { room: "strangers".into() }]);
}

#[test]
fn receive_buffers_incomplete_frame_until_complete() {
    let mut client = Client::new("me", Settings::default());
    let push = Push::Other { room: "room".into(), cursor: 1 };
    let payload = encode_push(&push).unwrap();
    let frame = frame_encode(&payload).unwrap();
    // Feed only the 4-byte length header.
    let head = &frame[..4];
    let body = &frame[4..];
    assert!(client.receive(head, 0, 0).unwrap().is_empty());
    // Feed the remaining payload bytes.
    let events = client.receive(body, 0, 0).unwrap();
    assert_eq!(events, vec![ClientEvent::Ignored { room: "room".into() }]);
}

#[test]
fn receive_multiple_complete_frames_in_order() {
    let mut client = Client::new("me", Settings::default());
    client.send(Request::Ping, 0).unwrap(); // id 1
    let resp = encode_response(1, &Response::Ok { cursor: 1 }).unwrap();
    let resp_frame = frame_encode(&resp).unwrap();
    let push = Push::Other { room: "x".into(), cursor: 2 };
    let push_payload = encode_push(&push).unwrap();
    let push_frame = frame_encode(&push_payload).unwrap();
    let mut all = resp_frame;
    all.extend_from_slice(&push_frame);
    let events = client.receive(&all, 0, 0).unwrap();
    assert_eq!(
        events,
        vec![
            ClientEvent::Reply(Reply::Done { id: 1, request: Request::Ping, response: Response::Ok { cursor: 1 } }),
            ClientEvent::Ignored { room: "x".into() },
        ]
    );
}

#[test]
fn receive_frame_with_bad_tag_is_fatal() {
    let mut client = Client::new("me", Settings::default());
    // Payload starting with byte 99: neither a response tag (128/129) nor a push tag (64–67).
    let bad_payload = vec![99u8, 0, 0, 0, 1];
    let frame = frame_encode(&bad_payload).unwrap();
    let err = client.receive(&frame, 0, 0).unwrap_err();
    assert_eq!(err, ClientError::Malformed(CodecError::BadKind(99)));
}

#[test]
fn receive_zero_length_frame_is_fatal_truncated() {
    let mut client = Client::new("me", Settings::default());
    // A valid frame whose payload is empty (4-byte header announcing 0 bytes).
    let frame = vec![0u8, 0, 0, 0];
    let err = client.receive(&frame, 0, 0).unwrap_err();
    assert_eq!(err, ClientError::Malformed(CodecError::Truncated));
}

#[test]
fn expire_returns_timed_out_requests_sorted_by_time_then_id() {
    let mut client = Client::new("me", Settings::default());
    client.send(Request::Ping, 0).unwrap(); // id 1, sent at 0
    client.send(Request::Ping, 0).unwrap(); // id 2, sent at 0
    // One millisecond short of the timeout: nothing expires.
    assert!(client.expire(TIMEOUT_MS - 1).is_empty());
    // Exactly at the timeout: both expire, same send time so ordered by id.
    let expired = client.expire(TIMEOUT_MS);
    assert_eq!(expired, vec![(1u32, Request::Ping), (2u32, Request::Ping)]);
}

#[test]
fn inbox_starts_with_no_followed_rooms() {
    let client = Client::new("me", Settings::default());
    assert!(client.inbox().rooms().is_empty());
}
