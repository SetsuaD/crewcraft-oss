#![allow(clippy::unwrap_used)]

use crewcraft_proto::message::{CodecError, MAX_BODY, MAX_NAME};
use crewcraft_proto::request::{MAX_DETAIL, Request, Response, decode_request, decode_response, encode_request, encode_response};

// ─── encode_request: exact wire bytes ─────────────────────────────────────────

#[test]
fn encode_post_exact_bytes() {
    // Wire: u8 tag(1) | u32 id | u16 room_len | room | u16 text_len | text
    let req = Request::Post { room: "hello".into(), text: "world".into() };
    let bytes = encode_request(0xDEAD, &req).unwrap();
    let mut expected = Vec::new();
    expected.push(1u8);
    expected.extend_from_slice(&0xDEADu32.to_be_bytes());
    expected.extend_from_slice(&5u16.to_be_bytes());
    expected.extend_from_slice(b"hello");
    expected.extend_from_slice(&5u16.to_be_bytes());
    expected.extend_from_slice(b"world");
    assert_eq!(bytes, expected);
}

#[test]
fn encode_edit_delete_sync_markread_ping_exact_bytes() {
    // Edit: u8(2) | u32 id | u16 room_len | room | u64 target | u16 text_len | text
    let edit = Request::Edit { room: "r".into(), target: 0xABCD, text: "x".into() };
    let mut exp = Vec::new();
    exp.push(2u8);
    exp.extend_from_slice(&7u32.to_be_bytes());
    exp.extend_from_slice(&1u16.to_be_bytes());
    exp.extend_from_slice(b"r");
    exp.extend_from_slice(&0xABCDu64.to_be_bytes());
    exp.extend_from_slice(&1u16.to_be_bytes());
    exp.extend_from_slice(b"x");
    assert_eq!(encode_request(7, &edit).unwrap(), exp);

    // Delete: u8(3) | u32 id | u16 room_len | room | u64 target
    let del = Request::Delete { room: "r".into(), target: 99 };
    let mut exp = Vec::new();
    exp.push(3u8);
    exp.extend_from_slice(&8u32.to_be_bytes());
    exp.extend_from_slice(&1u16.to_be_bytes());
    exp.extend_from_slice(b"r");
    exp.extend_from_slice(&99u64.to_be_bytes());
    assert_eq!(encode_request(8, &del).unwrap(), exp);

    // Sync: u8(4) | u32 id | u16 room_len | room | u64 cursor
    let sync = Request::Sync { room: "r".into(), cursor: 42 };
    let mut exp = Vec::new();
    exp.push(4u8);
    exp.extend_from_slice(&9u32.to_be_bytes());
    exp.extend_from_slice(&1u16.to_be_bytes());
    exp.extend_from_slice(b"r");
    exp.extend_from_slice(&42u64.to_be_bytes());
    assert_eq!(encode_request(9, &sync).unwrap(), exp);

    // MarkRead: u8(5) | u32 id | u16 room_len | room | u64 cursor
    let mr = Request::MarkRead { room: "r".into(), cursor: 42 };
    let mut exp = Vec::new();
    exp.push(5u8);
    exp.extend_from_slice(&10u32.to_be_bytes());
    exp.extend_from_slice(&1u16.to_be_bytes());
    exp.extend_from_slice(b"r");
    exp.extend_from_slice(&42u64.to_be_bytes());
    assert_eq!(encode_request(10, &mr).unwrap(), exp);

    // Ping: u8(6) | u32 id  (no fields)
    let ping = Request::Ping;
    let mut exp = Vec::new();
    exp.push(6u8);
    exp.extend_from_slice(&11u32.to_be_bytes());
    assert_eq!(encode_request(11, &ping).unwrap(), exp);
}

#[test]
fn encode_post_empty_text_allowed() {
    // text range is 0..=MAX_BODY, so zero-length text is valid
    let req = Request::Post { room: "a".into(), text: String::new() };
    let bytes = encode_request(1, &req).unwrap();
    // 1(tag) + 4(id) + 2(room_len) + 1(room) + 2(text_len) + 0(text) = 10
    assert_eq!(bytes.len(), 10);
    assert_eq!(&bytes[8..10], &0u16.to_be_bytes());
}

// ─── decode_request: round-trip and error ordering ───────────────────────────

#[test]
fn decode_request_roundtrip_all_variants() {
    let variants: Vec<(u32, Request)> = vec![
        (1, Request::Post { room: "a".into(), text: "b".into() }),
        (2, Request::Edit { room: "a".into(), target: 3, text: "c".into() }),
        (3, Request::Delete { room: "a".into(), target: 4 }),
        (4, Request::Sync { room: "a".into(), cursor: 5 }),
        (5, Request::MarkRead { room: "a".into(), cursor: 6 }),
        (6, Request::Ping),
    ];
    for (id, req) in variants {
        let bytes = encode_request(id, &req).unwrap();
        let (id2, req2) = decode_request(&bytes).unwrap();
        assert_eq!(id2, id);
        assert_eq!(req2, req);
    }
}

#[test]
fn decode_request_badkind_unknown_tag() {
    // tag 0 is not a valid request tag (valid: 1..=6)
    let mut bytes = Vec::new();
    bytes.push(0u8);
    bytes.extend_from_slice(&1u32.to_be_bytes());
    assert_eq!(decode_request(&bytes).unwrap_err(), CodecError::BadKind(0));

    // tag 7 is not valid either
    bytes[0] = 7;
    assert_eq!(decode_request(&bytes).unwrap_err(), CodecError::BadKind(7));

    // tag 128 (a response tag) is not a request tag
    bytes[0] = 128;
    assert_eq!(decode_request(&bytes).unwrap_err(), CodecError::BadKind(128));
}

#[test]
fn decode_request_truncated_at_each_stage() {
    // Empty input → Truncated (no tag byte)
    assert_eq!(decode_request(&[]).unwrap_err(), CodecError::Truncated);

    // Only tag byte, no id → Truncated
    assert_eq!(decode_request(&[6u8]).unwrap_err(), CodecError::Truncated);

    // Tag + 3 bytes of id → Truncated
    assert_eq!(decode_request(&[6u8, 0, 0, 0]).unwrap_err(), CodecError::Truncated);

    // Ping with tag + full id is complete; add a truncated Ping variant (should not happen)
    // Instead test Post: tag + id + 1 byte (not enough for room_len) → Truncated
    let mut b = Vec::new();
    b.push(1u8);
    b.extend_from_slice(&1u32.to_be_bytes());
    b.push(0); // only 1 of 2 room_len bytes
    assert_eq!(decode_request(&b).unwrap_err(), CodecError::Truncated);

    // Post: tag + id + room_len(1) + no room bytes → Truncated
    let mut b = Vec::new();
    b.push(1u8);
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes());
    assert_eq!(decode_request(&b).unwrap_err(), CodecError::Truncated);
}

#[test]
fn decode_request_fieldlength_zero_room() {
    // room length prefix is 0, which is below the minimum of 1 → FieldLength
    let mut b = Vec::new();
    b.push(1u8); // Post
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes()); // room_len = 0
    assert_eq!(decode_request(&b).unwrap_err(), CodecError::FieldLength);
}

#[test]
fn decode_request_fieldlength_room_too_long_on_wire() {
    // room length prefix exceeds MAX_NAME (64) → FieldLength
    let mut b = Vec::new();
    b.push(1u8); // Post
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&(MAX_NAME as u16 + 1).to_be_bytes());
    assert_eq!(decode_request(&b).unwrap_err(), CodecError::FieldLength);
}

#[test]
fn decode_request_bad_utf8_room() {
    // room_len=2, then 2 bytes that are not valid UTF-8
    let mut b = Vec::new();
    b.push(1u8); // Post
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&2u16.to_be_bytes());
    b.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
    assert_eq!(decode_request(&b).unwrap_err(), CodecError::BadUtf8);
}

#[test]
fn decode_request_trailing_bytes() {
    // Valid Ping (tag 6 + id) followed by one extra byte
    let mut b = Vec::new();
    b.push(6u8);
    b.extend_from_slice(&1u32.to_be_bytes());
    b.push(0xAA); // trailing
    assert_eq!(decode_request(&b).unwrap_err(), CodecError::TrailingBytes);
}

// ─── encode_request: FieldLength errors ──────────────────────────────────────

#[test]
fn encode_request_fieldlength_room_empty() {
    let req = Request::Post { room: String::new(), text: "hi".into() };
    assert_eq!(encode_request(1, &req).unwrap_err(), CodecError::FieldLength);

    let req = Request::Sync { room: String::new(), cursor: 0 };
    assert_eq!(encode_request(1, &req).unwrap_err(), CodecError::FieldLength);
}

#[test]
fn encode_request_fieldlength_room_exceeds_max() {
    let long_room = "x".repeat(MAX_NAME + 1);
    let req = Request::Post { room: long_room, text: "ok".into() };
    assert_eq!(encode_request(1, &req).unwrap_err(), CodecError::FieldLength);

    // Exactly MAX_NAME is valid
    let ok_room = "x".repeat(MAX_NAME);
    let req = Request::Post { room: ok_room, text: "ok".into() };
    assert!(encode_request(1, &req).is_ok());
}

#[test]
fn encode_request_fieldlength_text_exceeds_max() {
    let long_text = "x".repeat(MAX_BODY + 1);
    let req = Request::Post { room: "a".into(), text: long_text };
    assert_eq!(encode_request(1, &req).unwrap_err(), CodecError::FieldLength);

    let req = Request::Edit { room: "a".into(), target: 1, text: "x".repeat(MAX_BODY + 1) };
    assert_eq!(encode_request(1, &req).unwrap_err(), CodecError::FieldLength);

    // Exactly MAX_BODY is valid
    let req = Request::Post { room: "a".into(), text: "x".repeat(MAX_BODY) };
    assert!(encode_request(1, &req).is_ok());
}

// ─── encode_response / decode_response ───────────────────────────────────────

#[test]
fn encode_response_exact_bytes_and_roundtrip() {
    // Ok: u8(128) | u32 id | u64 cursor
    let ok = Response::Ok { cursor: 0xCAFE };
    let bytes = encode_response(0x1234, &ok).unwrap();
    let mut exp = Vec::new();
    exp.push(128u8);
    exp.extend_from_slice(&0x1234u32.to_be_bytes());
    exp.extend_from_slice(&0xCAFEu64.to_be_bytes());
    assert_eq!(bytes, exp);

    let (id, resp) = decode_response(&bytes).unwrap();
    assert_eq!(id, 0x1234);
    assert_eq!(resp, ok);

    // Error: u8(129) | u32 id | u16 code | u16 detail_len | detail
    let err = Response::Error { code: 42, detail: "oops".into() };
    let bytes = encode_response(7, &err).unwrap();
    let mut exp = Vec::new();
    exp.push(129u8);
    exp.extend_from_slice(&7u32.to_be_bytes());
    exp.extend_from_slice(&42u16.to_be_bytes());
    exp.extend_from_slice(&4u16.to_be_bytes());
    exp.extend_from_slice(b"oops");
    assert_eq!(bytes, exp);

    let (id, resp) = decode_response(&bytes).unwrap();
    assert_eq!(id, 7);
    assert_eq!(resp, err);
}

#[test]
fn encode_response_fieldlength_detail_too_long() {
    let detail = "x".repeat(MAX_DETAIL + 1);
    let resp = Response::Error { code: 1, detail };
    assert_eq!(encode_response(1, &resp).unwrap_err(), CodecError::FieldLength);

    // Exactly MAX_DETAIL is valid
    let detail = "x".repeat(MAX_DETAIL);
    let resp = Response::Error { code: 1, detail };
    assert!(encode_response(1, &resp).is_ok());
}

#[test]
fn decode_response_badkind() {
    // tag 1 is a request tag, not a response tag
    let mut b = Vec::new();
    b.push(1u8);
    b.extend_from_slice(&1u32.to_be_bytes());
    assert_eq!(decode_response(&b).unwrap_err(), CodecError::BadKind(1));

    // tag 127 is not a response tag
    b[0] = 127;
    assert_eq!(decode_response(&b).unwrap_err(), CodecError::BadKind(127));

    // tag 130 is not a response tag
    b[0] = 130;
    assert_eq!(decode_response(&b).unwrap_err(), CodecError::BadKind(130));
}

#[test]
fn decode_response_truncated_and_trailing() {
    // Empty → Truncated
    assert_eq!(decode_response(&[]).unwrap_err(), CodecError::Truncated);

    // Only tag → Truncated (no id)
    assert_eq!(decode_response(&[128u8]).unwrap_err(), CodecError::Truncated);

    // Tag + 2 bytes of id → Truncated
    assert_eq!(decode_response(&[128u8, 0, 0]).unwrap_err(), CodecError::Truncated);

    // Valid Ok response followed by extra byte → TrailingBytes
    let mut b = Vec::new();
    b.push(128u8);
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&0u64.to_be_bytes());
    b.push(0xBB); // trailing
    assert_eq!(decode_response(&b).unwrap_err(), CodecError::TrailingBytes);

    // Error: tag + id + code present but no detail → Truncated
    let mut b = Vec::new();
    b.push(129u8);
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes()); // code
    // no detail length or bytes
    assert_eq!(decode_response(&b).unwrap_err(), CodecError::Truncated);
}

#[test]
fn decode_response_fieldlength_detail() {
    // detail length prefix > MAX_DETAIL → FieldLength
    let mut b = Vec::new();
    b.push(129u8);
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes()); // code
    b.extend_from_slice(&((MAX_DETAIL as u16) + 1).to_be_bytes()); // detail_len too big
    assert_eq!(decode_response(&b).unwrap_err(), CodecError::FieldLength);
}

#[test]
fn decode_response_bad_utf8_detail() {
    let mut b = Vec::new();
    b.push(129u8);
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&1u16.to_be_bytes()); // code
    b.extend_from_slice(&2u16.to_be_bytes()); // detail_len = 2
    b.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
    assert_eq!(decode_response(&b).unwrap_err(), CodecError::BadUtf8);
}
