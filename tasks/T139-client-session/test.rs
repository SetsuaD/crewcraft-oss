#![allow(clippy::unwrap_used)]

use crewcraft_client_core::client::{Client, ClientError, ClientEvent};
use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::session::{ClientSession, Phase, SessionError};
use crewcraft_proto::frame::encode as frame_encode;
use crewcraft_proto::handshake::{Hello, Reply, encode_hello, encode_reply};
use crewcraft_proto::message::CodecError;
use crewcraft_proto::push::{Push, encode_push};

fn make_session() -> (ClientSession, Hello) {
    let hello = Hello { min_version: 1, max_version: 3, features: 0b101, client: "crewcraft-test".to_string() };
    let client = Client::new("me", Settings::default());
    let session = ClientSession::new(hello.clone(), client);
    (session, hello)
}

fn welcome_frame(version: u16, features: u32, server: &str) -> Vec<u8> {
    let reply = Reply::Welcome { version, features, server: server.to_string() };
    let payload = encode_reply(&reply).unwrap();
    frame_encode(&payload).unwrap()
}

fn refuse_frame(min_version: u16, max_version: u16) -> Vec<u8> {
    let reply = Reply::Refuse { min_version, max_version };
    let payload = encode_reply(&reply).unwrap();
    frame_encode(&payload).unwrap()
}

fn other_push_frame(room: &str, cursor: u64) -> Vec<u8> {
    let push = Push::Other { room: room.to_string(), cursor };
    let payload = encode_push(&push).unwrap();
    frame_encode(&payload).unwrap()
}

#[test]
fn new_session_is_in_new_phase() {
    let (session, _) = make_session();
    assert_eq!(session.phase(), Phase::New);
}

#[test]
fn start_returns_framed_hello_and_moves_to_waiting() {
    let (mut session, hello) = make_session();
    let bytes = session.start().unwrap();
    let expected_payload = encode_hello(&hello).unwrap();
    let expected = frame_encode(&expected_payload).unwrap();
    assert_eq!(bytes, expected);
    assert_eq!(session.phase(), Phase::Waiting);
}

#[test]
fn start_in_waiting_phase_is_wrong_phase() {
    let (mut session, _) = make_session();
    session.start().unwrap();
    let err = session.start().unwrap_err();
    assert_eq!(err, SessionError::WrongPhase);
    assert_eq!(session.phase(), Phase::Waiting);
}

#[test]
fn start_with_empty_client_name_stays_new() {
    let hello = Hello { min_version: 1, max_version: 2, features: 0, client: String::new() };
    let client = Client::new("me", Settings::default());
    let mut session = ClientSession::new(hello, client);
    let err = session.start().unwrap_err();
    assert_eq!(err, SessionError::Reply(CodecError::FieldLength));
    assert_eq!(session.phase(), Phase::New);
}

#[test]
fn receive_in_new_phase_is_wrong_phase() {
    let (mut session, _) = make_session();
    let err = session.receive(&[1, 2, 3], 0, 0).unwrap_err();
    assert_eq!(err, SessionError::WrongPhase);
    assert_eq!(session.phase(), Phase::New);
}

#[test]
fn receive_welcome_opens_session_with_version_and_features() {
    let (mut session, _) = make_session();
    session.start().unwrap();
    let frame = welcome_frame(2, 0b100, "server");
    let events = session.receive(&frame, 0, 0).unwrap();
    assert!(events.is_empty());
    assert_eq!(session.phase(), Phase::Open { version: 2, features: 0b100 });
}

#[test]
fn receive_refuse_moves_to_refused_and_ignores_trailing_bytes() {
    let (mut session, _) = make_session();
    session.start().unwrap();
    let frame = refuse_frame(1, 4);
    // Append a valid push frame that must be ignored after Refuse
    let push_frame = other_push_frame("room", 1);
    let mut data = frame;
    data.extend_from_slice(&push_frame);

    let events = session.receive(&data, 0, 0).unwrap();
    assert!(events.is_empty());
    assert_eq!(session.phase(), Phase::Refused { min_version: 1, max_version: 4 });
}

#[test]
fn receive_non_reply_frame_in_waiting_closes_session() {
    let (mut session, _) = make_session();
    session.start().unwrap();
    // A push frame (tag 67) is not a valid handshake reply
    let push_frame = other_push_frame("room", 1);
    let err = session.receive(&push_frame, 0, 0).unwrap_err();
    assert_eq!(err, SessionError::Reply(CodecError::BadKind(67)));
    assert_eq!(session.phase(), Phase::Closed);
}

#[test]
fn receive_in_waiting_buffers_partial_frame() {
    let (mut session, _) = make_session();
    session.start().unwrap();
    let frame = welcome_frame(1, 0, "s");
    // Send only 3 bytes — not enough for a 4-byte length header
    let events = session.receive(&frame[..3], 0, 0).unwrap();
    assert!(events.is_empty());
    assert_eq!(session.phase(), Phase::Waiting);
    // Send the remaining bytes to complete the frame
    let events = session.receive(&frame[3..], 0, 0).unwrap();
    assert!(events.is_empty());
    assert_eq!(session.phase(), Phase::Open { version: 1, features: 0 });
}

#[test]
fn receive_welcome_then_push_in_same_call_returns_client_events() {
    let (mut session, _) = make_session();
    session.start().unwrap();
    let welcome = welcome_frame(3, 7, "srv");
    // Push for a room the client does not follow → Ignored
    let push_frame = other_push_frame("general", 1);
    let mut data = welcome;
    data.extend_from_slice(&push_frame);

    let events = session.receive(&data, 1000, 30).unwrap();
    assert_eq!(session.phase(), Phase::Open { version: 3, features: 7 });
    assert_eq!(events, vec![ClientEvent::Ignored { room: "general".to_string() }]);
}

#[test]
fn receive_in_refused_phase_is_wrong_phase() {
    let (mut session, _) = make_session();
    session.start().unwrap();
    let frame = refuse_frame(2, 5);
    session.receive(&frame, 0, 0).unwrap();
    assert_eq!(session.phase(), Phase::Refused { min_version: 2, max_version: 5 });

    let err = session.receive(&[0], 0, 0).unwrap_err();
    assert_eq!(err, SessionError::WrongPhase);
    assert_eq!(session.phase(), Phase::Refused { min_version: 2, max_version: 5 });
}

#[test]
fn receive_in_closed_phase_is_wrong_phase() {
    let (mut session, _) = make_session();
    session.start().unwrap();
    // Close the session by sending a non-reply frame
    let push_frame = other_push_frame("r", 0);
    session.receive(&push_frame, 0, 0).unwrap_err();
    assert_eq!(session.phase(), Phase::Closed);

    let err = session.receive(&[0], 0, 0).unwrap_err();
    assert_eq!(err, SessionError::WrongPhase);
    assert_eq!(session.phase(), Phase::Closed);
}

#[test]
fn receive_in_open_fatal_error_closes_session() {
    let (mut session, _) = make_session();
    session.start().unwrap();
    let welcome = welcome_frame(1, 0, "s");
    session.receive(&welcome, 0, 0).unwrap();
    assert_eq!(session.phase(), Phase::Open { version: 1, features: 0 });

    // A frame whose first byte (99) is neither a response (128-129) nor a push (64-67)
    let bad_payload = vec![99u8, 1, 2];
    let bad_frame = frame_encode(&bad_payload).unwrap();
    let err = session.receive(&bad_frame, 0, 0).unwrap_err();
    assert_eq!(err, SessionError::Client(ClientError::Malformed(CodecError::BadKind(99))));
    assert_eq!(session.phase(), Phase::Closed);
}

#[test]
fn receive_in_open_routes_valid_push_to_client() {
    let (mut session, _) = make_session();
    session.start().unwrap();
    let welcome = welcome_frame(2, 1, "srv");
    session.receive(&welcome, 0, 0).unwrap();

    // Push for an unfollowed room → Ignored
    let push_frame = other_push_frame("lobby", 42);
    let events = session.receive(&push_frame, 500, 15).unwrap();
    assert_eq!(events, vec![ClientEvent::Ignored { room: "lobby".to_string() }]);
    assert_eq!(session.phase(), Phase::Open { version: 2, features: 1 });
}

#[test]
fn client_mut_accessible_in_open_phase() {
    let (mut session, _) = make_session();
    session.start().unwrap();
    let welcome = welcome_frame(1, 0, "s");
    session.receive(&welcome, 0, 0).unwrap();

    let _client: &mut Client = session.client_mut();
    assert_eq!(session.phase(), Phase::Open { version: 1, features: 0 });
}

#[test]
fn receive_in_waiting_truncated_reply_closes_session() {
    let (mut session, _) = make_session();
    session.start().unwrap();
    // A frame whose payload is just [2] — tag for Welcome but no further bytes
    let payload = vec![2u8];
    let frame = frame_encode(&payload).unwrap();
    let err = session.receive(&frame, 0, 0).unwrap_err();
    assert_eq!(err, SessionError::Reply(CodecError::Truncated));
    assert_eq!(session.phase(), Phase::Closed);
}

#[test]
fn oversized_reply_header_closes_the_session() {
    use crewcraft_proto::frame::{FrameError, MAX_FRAME};
    let (mut session, _) = make_session();
    session.start().unwrap();
    let header = ((MAX_FRAME + 1) as u32).to_be_bytes();
    let err = session.receive(&header, 0, 0).unwrap_err();
    assert_eq!(err, SessionError::Frame(FrameError::TooLarge(MAX_FRAME + 1)));
    assert_eq!(session.phase(), Phase::Closed);
    // Later bytes are not read as a fresh reply.
    assert_eq!(session.receive(&welcome_frame(1, 0, "s"), 0, 0).unwrap_err(), SessionError::WrongPhase);
}
