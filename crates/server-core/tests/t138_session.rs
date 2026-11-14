//! Integration tests for `session::Session` (T138).
#![allow(clippy::unwrap_used)]

use crewcraft_proto::frame::{FrameError, encode};
use crewcraft_proto::handshake::{self, Hello, Reply, ServerSide};
use crewcraft_proto::message::CodecError;

use crewcraft_server_core::connection::ConnError;
use crewcraft_server_core::server::Server;
use crewcraft_server_core::session::{Phase, Session, SessionError};

fn server_side() -> ServerSide {
    ServerSide { min_version: 1, max_version: 3, features: 0b1010, name: "crewcraft-server".to_string() }
}

fn new_server() -> Server {
    Server::new()
}

/// Frame a `Hello` payload for sending to the session.
fn framed_hello(hello: &Hello) -> Vec<u8> {
    let payload = handshake::encode_hello(hello).unwrap();
    encode(&payload).unwrap()
}

/// Compute the expected framed bytes for a `Reply`.
fn framed_reply(reply: &Reply) -> Vec<u8> {
    let payload = handshake::encode_reply(reply).unwrap();
    encode(&payload).unwrap()
}

#[test]
fn initial_phase_is_hello() {
    let session = Session::new("alice", server_side());
    assert_eq!(session.phase(), Phase::Hello);
}

#[test]
fn hello_welcome_opens_session_at_negotiated_version_and_features() {
    let mut server = new_server();
    let mut session = Session::new("alice", server_side());

    // Server speaks 1..=3, features 0b1010.
    // Client speaks 1..=2, features 0b1100.
    // negotiate: lo=max(1,1)=1, hi=min(2,3)=2 → Welcome at 2, features=0b1100&0b1010=0b1000.
    let hello = Hello { min_version: 1, max_version: 2, features: 0b1100, client: "test-client".to_string() };
    let input = framed_hello(&hello);

    let out = session.receive(&mut server, &input, 0).unwrap();

    let expected = Reply::Welcome { version: 2, features: 0b1000, server: "crewcraft-server".to_string() };
    assert_eq!(out, framed_reply(&expected));
    assert_eq!(session.phase(), Phase::Open { version: 2, features: 0b1000 });
}

#[test]
fn hello_refuse_closes_session() {
    let mut server = new_server();
    let mut session = Session::new("bob", server_side());

    // Server speaks 1..=3; client speaks 5..=7 → no overlap → Refuse with server's range.
    let hello = Hello { min_version: 5, max_version: 7, features: 0, client: "mismatch".to_string() };
    let input = framed_hello(&hello);

    let out = session.receive(&mut server, &input, 0).unwrap();

    let expected = Reply::Refuse { min_version: 1, max_version: 3 };
    assert_eq!(out, framed_reply(&expected));
    assert_eq!(session.phase(), Phase::Closed);
}

#[test]
fn hello_refuse_ignores_trailing_bytes() {
    let mut server = new_server();
    let mut session = Session::new("bob", server_side());

    // Hello that will be refused (server 1..=3, client 10..=20).
    let hello = Hello { min_version: 10, max_version: 20, features: 0, client: "far".to_string() };
    let mut input = framed_hello(&hello);

    // Append extra bytes that would form another frame if the session were open.
    input.extend_from_slice(&[0u8, 0, 0, 5, 0x06, 0x00, 0x00, 0x00, 0x42]);

    let out = session.receive(&mut server, &input, 0).unwrap();

    // Only the Refuse is sent; the trailing bytes are ignored because the session closed.
    let expected = Reply::Refuse { min_version: 1, max_version: 3 };
    assert_eq!(out, framed_reply(&expected));
    assert_eq!(session.phase(), Phase::Closed);
}

#[test]
fn hello_bad_tag_closes_with_hello_error() {
    let mut server = new_server();
    let mut session = Session::new("carol", server_side());

    // Payload starts with tag 2 (Welcome) instead of tag 1 (Hello).
    let bad_payload = vec![2u8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x03, b's', b'r', b'v'];
    let input = encode(&bad_payload).unwrap();

    let err = session.receive(&mut server, &input, 0).unwrap_err();
    assert_eq!(err, SessionError::Hello(CodecError::BadKind(2)));
    assert_eq!(session.phase(), Phase::Closed);
}

#[test]
fn hello_truncated_fields_closes_with_hello_error() {
    let mut server = new_server();
    let mut session = Session::new("dave", server_side());

    // Tag 1 (Hello), then only 2 bytes for min_version, then EOF (no max_version).
    let bad_payload = vec![1u8, 0x00, 0x01];
    let input = encode(&bad_payload).unwrap();

    let err = session.receive(&mut server, &input, 0).unwrap_err();
    assert_eq!(err, SessionError::Hello(CodecError::Truncated));
    assert_eq!(session.phase(), Phase::Closed);
}

#[test]
fn frame_too_large_in_hello_closes_with_frame_error() {
    let mut server = new_server();
    let mut session = Session::new("erin", server_side());

    // 4-byte header announcing a payload of 1 MiB + 1 (> MAX_FRAME).
    let mut input = Vec::new();
    input.extend_from_slice(&((1u32 << 20) + 1).to_be_bytes());

    let err = session.receive(&mut server, &input, 0).unwrap_err();
    assert_eq!(err, SessionError::Frame(FrameError::TooLarge((1usize << 20) + 1)));
    assert_eq!(session.phase(), Phase::Closed);
}

#[test]
fn closed_phase_rejects_all_receive_calls() {
    let mut server = new_server();
    let mut session = Session::new("frank", server_side());

    // Close the session by sending a frame with an invalid tag.
    let bad_payload = vec![99u8];
    let bad_input = encode(&bad_payload).unwrap();
    let _ = session.receive(&mut server, &bad_input, 0).unwrap_err();
    assert_eq!(session.phase(), Phase::Closed);

    // Every subsequent receive must return Closed, regardless of input.
    let err = session.receive(&mut server, b"anything at all", 100).unwrap_err();
    assert_eq!(err, SessionError::Closed);
}

#[test]
fn partial_bytes_in_hello_stay_in_hello() {
    let mut server = new_server();
    let mut session = Session::new("gina", server_side());

    // Only 2 bytes — not even a complete 4-byte frame header.
    let out = session.receive(&mut server, &[0x00, 0x00], 0).unwrap();
    assert!(out.is_empty());
    assert_eq!(session.phase(), Phase::Hello);
}

#[test]
fn hello_empty_client_name_rejected_with_field_length() {
    let mut server = new_server();
    let mut session = Session::new("hank", server_side());

    // tag=1, min=1, max=1, features=0, client length=0 (violates 1..=MAX_NAME).
    let bad_payload = vec![
        1u8, // tag
        0x00, 0x01, // min_version = 1
        0x00, 0x01, // max_version = 1
        0x00, 0x00, 0x00, 0x00, // features = 0
        0x00, 0x00, // client length = 0
    ];
    let input = encode(&bad_payload).unwrap();

    let err = session.receive(&mut server, &input, 0).unwrap_err();
    assert_eq!(err, SessionError::Hello(CodecError::FieldLength));
    assert_eq!(session.phase(), Phase::Closed);
}

#[test]
fn hello_single_version_overlap_welcomes_at_that_version() {
    let mut server = new_server();
    let mut session = Session::new("ivy", server_side());

    // Server speaks 1..=3; client speaks exactly 3..=3.
    // negotiate: lo=max(1,3)=3, hi=min(3,3)=3 → Welcome at 3, features=0b1111&0b1010=0b1010.
    let hello = Hello { min_version: 3, max_version: 3, features: 0b1111, client: "exact".to_string() };
    let input = framed_hello(&hello);

    let out = session.receive(&mut server, &input, 0).unwrap();

    let expected = Reply::Welcome { version: 3, features: 0b1010, server: "crewcraft-server".to_string() };
    assert_eq!(out, framed_reply(&expected));
    assert_eq!(session.phase(), Phase::Open { version: 3, features: 0b1010 });
}

#[test]
fn open_phase_frame_error_wrapped_as_conn_error_and_closes() {
    let mut server = new_server();
    let mut session = Session::new("alice", server_side());

    // Complete the handshake successfully.
    let hello = Hello { min_version: 1, max_version: 2, features: 0, client: "test".to_string() };
    let _ = session.receive(&mut server, &framed_hello(&hello), 0).unwrap();
    assert_eq!(session.phase(), Phase::Open { version: 2, features: 0 });

    // Now send a frame whose header exceeds MAX_FRAME.
    // In the Open phase this surfaces as ConnError::Frame, wrapped in SessionError::Conn.
    let mut too_large = Vec::new();
    too_large.extend_from_slice(&((1u32 << 20) + 1).to_be_bytes());

    let err = session.receive(&mut server, &too_large, 100).unwrap_err();
    assert_eq!(err, SessionError::Conn(ConnError::Frame(FrameError::TooLarge((1usize << 20) + 1))));
    assert_eq!(session.phase(), Phase::Closed);
}

/// Added in review: once welcomed, frames are requests, including bytes that arrive in the same call as the Hello.
#[test]
fn requests_after_the_welcome_reach_the_connection_even_in_the_same_call() {
    use crewcraft_proto::request::{Request, Response, encode_request, encode_response};

    let mut server = new_server();
    let mut session = Session::new("alice", server_side());
    let hello = Hello { min_version: 1, max_version: 3, features: 0, client: "test".to_string() };

    // Hello and a Ping (id 7) in one call: the Welcome, then the Ping's response.
    let mut input = framed_hello(&hello);
    input.extend(encode(&encode_request(7, &Request::Ping).unwrap()).unwrap());
    let out = session.receive(&mut server, &input, 0).unwrap();
    let mut expected = framed_reply(&Reply::Welcome { version: 3, features: 0, server: "crewcraft-server".to_string() });
    expected.extend(encode(&encode_response(7, &Response::Ok { cursor: 0 }).unwrap()).unwrap());
    assert_eq!(out, expected);

    // A later call in the open session: another Ping (id 8).
    let out = session.receive(&mut server, &encode(&encode_request(8, &Request::Ping).unwrap()).unwrap(), 1).unwrap();
    assert_eq!(out, encode(&encode_response(8, &Response::Ok { cursor: 0 }).unwrap()).unwrap());
}
