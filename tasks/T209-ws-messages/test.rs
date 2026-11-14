#![allow(clippy::unwrap_used)]

use crewcraft_proto::ws_frame::{Frame, Opcode, WsError};
use crewcraft_proto::ws_message::{Assembler, Message, to_frame};

fn f(fin: bool, opcode: Opcode, payload: &[u8]) -> Frame {
    Frame { fin, opcode, payload: payload.to_vec() }
}

#[test]
fn whole_messages() {
    let mut a = Assembler::new(1000);
    assert_eq!(a.push(f(true, Opcode::Text, b"hello")).unwrap(), Some(Message::Text("hello".into())));
    assert_eq!(a.push(f(true, Opcode::Binary, &[1, 2, 3])).unwrap(), Some(Message::Binary(vec![1, 2, 3])));
    assert_eq!(a.push(f(true, Opcode::Text, b"")).unwrap(), Some(Message::Text(String::new())));
}

#[test]
fn fragments_are_joined() {
    let mut a = Assembler::new(1000);
    assert_eq!(a.push(f(false, Opcode::Text, b"Hel")).unwrap(), None);
    assert_eq!(a.push(f(false, Opcode::Continuation, b"l")).unwrap(), None);
    assert_eq!(a.push(f(true, Opcode::Continuation, b"o")).unwrap(), Some(Message::Text("Hello".into())));
    // The assembler is ready for the next message.
    assert_eq!(a.push(f(false, Opcode::Binary, &[1])).unwrap(), None);
    assert_eq!(a.push(f(true, Opcode::Continuation, &[2])).unwrap(), Some(Message::Binary(vec![1, 2])));
}

#[test]
fn control_frames_pass_through_between_fragments_without_disturbing_the_message() {
    let mut a = Assembler::new(1000);
    assert_eq!(a.push(f(false, Opcode::Text, b"ab")).unwrap(), None);
    assert_eq!(a.push(f(true, Opcode::Ping, b"p")).unwrap(), Some(Message::Ping(b"p".to_vec())));
    assert_eq!(a.push(f(false, Opcode::Continuation, b"cd")).unwrap(), None);
    assert_eq!(a.push(f(true, Opcode::Pong, b"")).unwrap(), Some(Message::Pong(vec![])));
    assert_eq!(a.push(f(true, Opcode::Continuation, b"ef")).unwrap(), Some(Message::Text("abcdef".into())));
}

#[test]
fn a_character_may_be_split_across_fragments_but_the_whole_must_be_utf8() {
    // "é" is C3 A9.
    let mut a = Assembler::new(1000);
    a.push(f(false, Opcode::Text, &[b'a', 0xC3])).unwrap();
    assert_eq!(a.push(f(true, Opcode::Continuation, &[0xA9])).unwrap(), Some(Message::Text("aé".into())));

    let mut a = Assembler::new(1000);
    assert_eq!(a.push(f(true, Opcode::Text, &[0xFF, 0xFE])).unwrap_err(), WsError::BadUtf8);
    let mut a = Assembler::new(1000);
    a.push(f(false, Opcode::Text, &[0xC3])).unwrap();
    assert_eq!(a.push(f(true, Opcode::Continuation, &[b'x'])).unwrap_err(), WsError::BadUtf8);
    // Binary messages are not checked.
    let mut a = Assembler::new(1000);
    assert!(a.push(f(true, Opcode::Binary, &[0xFF, 0xFE])).is_ok());
}

#[test]
fn ordering_errors() {
    let mut a = Assembler::new(1000);
    assert_eq!(a.push(f(true, Opcode::Continuation, b"x")).unwrap_err(), WsError::UnexpectedContinuation);
    let mut a = Assembler::new(1000);
    assert_eq!(a.push(f(false, Opcode::Continuation, b"x")).unwrap_err(), WsError::UnexpectedContinuation);

    for next in [Opcode::Text, Opcode::Binary] {
        for fin in [true, false] {
            let mut a = Assembler::new(1000);
            a.push(f(false, Opcode::Text, b"start")).unwrap();
            assert_eq!(a.push(f(fin, next, b"x")).unwrap_err(), WsError::InterleavedData, "{next:?} fin={fin}");
        }
    }
}

#[test]
fn the_size_limit_counts_the_whole_message() {
    let mut a = Assembler::new(10);
    assert!(a.push(f(true, Opcode::Binary, &[0; 10])).is_ok());
    assert_eq!(a.push(f(true, Opcode::Binary, &[0; 11])).unwrap_err(), WsError::MessageTooLarge);

    let mut a = Assembler::new(10);
    a.push(f(false, Opcode::Binary, &[0; 6])).unwrap();
    a.push(f(false, Opcode::Continuation, &[0; 4])).unwrap();
    // Ten bytes so far: one more is too many, even though this frame alone is small.
    assert_eq!(a.push(f(true, Opcode::Continuation, &[0; 1])).unwrap_err(), WsError::MessageTooLarge);
}

#[test]
fn close_frames() {
    let mut a = Assembler::new(1000);
    assert_eq!(a.push(f(true, Opcode::Close, b"")).unwrap(), Some(Message::Close { code: None, reason: String::new() }));
    assert_eq!(a.push(f(true, Opcode::Close, &[0x03, 0xE8])).unwrap(), Some(Message::Close { code: Some(1000), reason: String::new() }));
    let mut payload = vec![0x03, 0xE9];
    payload.extend_from_slice("going away".as_bytes());
    assert_eq!(a.push(f(true, Opcode::Close, &payload)).unwrap(), Some(Message::Close { code: Some(1001), reason: "going away".into() }));
    // Application codes.
    assert_eq!(a.push(f(true, Opcode::Close, &3000u16.to_be_bytes())).unwrap(), Some(Message::Close { code: Some(3000), reason: String::new() }));
    assert_eq!(a.push(f(true, Opcode::Close, &4999u16.to_be_bytes())).unwrap(), Some(Message::Close { code: Some(4999), reason: String::new() }));
}

#[test]
fn bad_close_frames() {
    let mut a = Assembler::new(1000);
    assert_eq!(a.push(f(true, Opcode::Close, &[0x03])).unwrap_err(), WsError::BadClose);
    for code in [0u16, 999, 1004, 1005, 1006, 1012, 1015, 1016, 2999, 5000, 65535] {
        let mut a = Assembler::new(1000);
        assert_eq!(a.push(f(true, Opcode::Close, &code.to_be_bytes())).unwrap_err(), WsError::BadClose, "code {code}");
    }
    for code in [1000u16, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 3000, 4000, 4999] {
        let mut a = Assembler::new(1000);
        assert!(a.push(f(true, Opcode::Close, &code.to_be_bytes())).is_ok(), "code {code}");
    }
    let mut a = Assembler::new(1000);
    assert_eq!(a.push(f(true, Opcode::Close, &[0x03, 0xE8, 0xFF, 0xFE])).unwrap_err(), WsError::BadUtf8);
}

#[test]
fn messages_to_frames() {
    assert_eq!(to_frame(&Message::Text("hi".into())), f(true, Opcode::Text, b"hi"));
    assert_eq!(to_frame(&Message::Binary(vec![1, 2])), f(true, Opcode::Binary, &[1, 2]));
    assert_eq!(to_frame(&Message::Ping(vec![9])), f(true, Opcode::Ping, &[9]));
    assert_eq!(to_frame(&Message::Pong(vec![])), f(true, Opcode::Pong, &[]));
    assert_eq!(to_frame(&Message::Close { code: None, reason: String::new() }), f(true, Opcode::Close, &[]));
    assert_eq!(to_frame(&Message::Close { code: Some(1000), reason: "bye".into() }), f(true, Opcode::Close, &[0x03, 0xE8, b'b', b'y', b'e']));
}

#[test]
fn a_frame_made_from_a_message_reads_back_as_the_same_message() {
    let samples = [
        Message::Text("héllo".into()),
        Message::Binary(vec![0, 1, 2, 255]),
        Message::Ping(vec![1]),
        Message::Pong(vec![]),
        Message::Close { code: Some(1001), reason: "bye".into() },
        Message::Close { code: None, reason: String::new() },
    ];
    for m in samples {
        let mut a = Assembler::new(1000);
        assert_eq!(a.push(to_frame(&m)).unwrap(), Some(m.clone()), "{m:?}");
    }
}
