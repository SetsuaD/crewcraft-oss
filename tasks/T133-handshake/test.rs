#![allow(clippy::unwrap_used)]

use crewcraft_proto::handshake::{Hello, Reply, ServerSide, decode_hello, decode_reply, encode_hello, encode_reply, negotiate};
use crewcraft_proto::message::{CodecError, MAX_NAME};

// ─── encode_hello ────────────────────────────────────────────────────────────

#[test]
fn encode_hello_produces_documented_wire_bytes() {
    let hello = Hello { min_version: 1, max_version: 3, features: 0b1010, client: "ab".to_string() };
    let bytes = encode_hello(&hello).unwrap();
    // u8(1) | u16(1) | u16(3) | u32(0b1010) | u16(2) | "ab"
    let expected = [
        0x01, // tag
        0x00, 0x01, // min_version
        0x00, 0x03, // max_version
        0x00, 0x00, 0x00, 0x0A, // features
        0x00, 0x02, // str length
        0x61, 0x62, // "ab"
    ];
    assert_eq!(bytes, expected);
}

#[test]
fn encode_hello_rejects_empty_client() {
    let hello = Hello { min_version: 1, max_version: 2, features: 0, client: String::new() };
    assert!(matches!(encode_hello(&hello), Err(CodecError::FieldLength)));
}

#[test]
fn encode_hello_rejects_oversized_client() {
    let hello = Hello { min_version: 1, max_version: 2, features: 0, client: "x".repeat(MAX_NAME + 1) };
    assert!(matches!(encode_hello(&hello), Err(CodecError::FieldLength)));
}

// ─── decode_hello ────────────────────────────────────────────────────────────

#[test]
fn decode_hello_recovers_fields_from_wire_bytes() {
    // u8(1) | u16(4) | u16(9) | u32(0b1100) | u16(5) | "hello"
    let bytes = [0x01, 0x00, 0x04, 0x00, 0x09, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];
    let hello = decode_hello(&bytes).unwrap();
    assert_eq!(hello, Hello { min_version: 4, max_version: 9, features: 0b1100, client: "hello".to_string() });
}

#[test]
fn decode_hello_rejects_empty_input_and_wrong_tag() {
    assert!(matches!(decode_hello(&[]), Err(CodecError::Truncated)));
    assert!(matches!(decode_hello(&[0x02, 0, 0]), Err(CodecError::BadKind(2))));
    assert!(matches!(decode_hello(&[0xFF, 0, 0]), Err(CodecError::BadKind(0xFF))));
}

#[test]
fn decode_hello_reports_truncation_at_each_field() {
    // tag only
    assert!(matches!(decode_hello(&[0x01]), Err(CodecError::Truncated)));
    // tag + 1 byte of min_version
    assert!(matches!(decode_hello(&[0x01, 0x00]), Err(CodecError::Truncated)));
    // tag + min_version + 1 byte of max_version
    assert!(matches!(decode_hello(&[0x01, 0x00, 0x01, 0x00]), Err(CodecError::Truncated)));
    // tag + min + max + 2 bytes of features
    assert!(matches!(decode_hello(&[0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00]), Err(CodecError::Truncated)));
    // tag + min + max + features + str-length says 3 but only 1 byte follows
    assert!(matches!(decode_hello(&[0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x61]), Err(CodecError::Truncated)));
}

#[test]
fn decode_hello_rejects_bad_string_length_before_reading_bytes() {
    // client length 0 → FieldLength
    let bytes = [
        0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // length 0
    ];
    assert!(matches!(decode_hello(&bytes), Err(CodecError::FieldLength)));

    // client length > MAX_NAME → FieldLength (length field alone is enough)
    let oversized_len = (MAX_NAME + 1) as u16;
    let bytes = [0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, (oversized_len >> 8) as u8, (oversized_len & 0xFF) as u8];
    assert!(matches!(decode_hello(&bytes), Err(CodecError::FieldLength)));
}

#[test]
fn decode_hello_rejects_invalid_utf8() {
    // Valid length (2) but bytes are not valid UTF-8
    let bytes = [
        0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0xFF, 0xFE, // invalid UTF-8
    ];
    assert!(matches!(decode_hello(&bytes), Err(CodecError::BadUtf8)));
}

#[test]
fn decode_hello_rejects_trailing_bytes() {
    // Valid hello followed by one extra byte
    let bytes = [
        0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, b'a', 0xDE, // trailing
    ];
    assert!(matches!(decode_hello(&bytes), Err(CodecError::TrailingBytes)));
}

// ─── negotiate ───────────────────────────────────────────────────────────────

#[test]
fn negotiate_returns_welcome_with_highest_shared_version_and_anded_features() {
    let hello = Hello { min_version: 1, max_version: 5, features: 0b1111, client: "client".to_string() };
    let server = ServerSide { min_version: 3, max_version: 7, features: 0b1010, name: "server-1".to_string() };
    // Overlap: [3, 5]; highest shared version = 5; features = 0b1111 & 0b1010 = 0b1010
    let reply = negotiate(&hello, &server);
    assert_eq!(reply, Reply::Welcome { version: 5, features: 0b1010, server: "server-1".to_string() });
}

#[test]
fn negotiate_returns_welcome_when_ranges_touch_at_single_version() {
    let hello = Hello { min_version: 1, max_version: 3, features: 0b0011, client: "c".to_string() };
    let server = ServerSide { min_version: 3, max_version: 9, features: 0b1100, name: "s".to_string() };
    // Overlap is exactly {3}; highest shared = 3; features = 0b0011 & 0b1100 = 0b0000
    let reply = negotiate(&hello, &server);
    assert_eq!(reply, Reply::Welcome { version: 3, features: 0, server: "s".to_string() });
}

#[test]
fn negotiate_returns_refuse_when_ranges_do_not_overlap() {
    let hello = Hello { min_version: 1, max_version: 2, features: 0, client: "c".to_string() };
    let server = ServerSide { min_version: 4, max_version: 8, features: 0, name: "s".to_string() };
    let reply = negotiate(&hello, &server);
    assert_eq!(reply, Reply::Refuse { min_version: 4, max_version: 8 });
}

#[test]
fn negotiate_returns_refuse_when_either_range_is_empty() {
    // hello range empty (min > max)
    let hello = Hello { min_version: 5, max_version: 3, features: 0, client: "c".to_string() };
    let server = ServerSide { min_version: 1, max_version: 3, features: 0, name: "s".to_string() };
    assert_eq!(negotiate(&hello, &server), Reply::Refuse { min_version: 1, max_version: 3 });

    // server range empty (min > max)
    let hello = Hello { min_version: 1, max_version: 3, features: 0, client: "c".to_string() };
    let server = ServerSide { min_version: 9, max_version: 4, features: 0, name: "s".to_string() };
    assert_eq!(negotiate(&hello, &server), Reply::Refuse { min_version: 9, max_version: 4 });
}

// ─── encode_reply / decode_reply ─────────────────────────────────────────────

#[test]
fn encode_reply_welcome_produces_documented_wire_bytes() {
    let reply = Reply::Welcome { version: 2, features: 0b0010, server: "srv".to_string() };
    let bytes = encode_reply(&reply).unwrap();
    // u8(2) | u16(2) | u32(0b0010) | u16(3) | "srv"
    let expected = [0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x03, b's', b'r', b'v'];
    assert_eq!(bytes, expected);
}

#[test]
fn encode_reply_refuse_produces_documented_wire_bytes() {
    let reply = Reply::Refuse { min_version: 1, max_version: 6 };
    let bytes = encode_reply(&reply).unwrap();
    // u8(3) | u16(1) | u16(6)
    let expected = [0x03, 0x00, 0x01, 0x00, 0x06];
    assert_eq!(bytes, expected);
}

#[test]
fn encode_reply_rejects_empty_or_oversized_server_name() {
    let reply = Reply::Welcome { version: 1, features: 0, server: String::new() };
    assert!(matches!(encode_reply(&reply), Err(CodecError::FieldLength)));

    let reply = Reply::Welcome { version: 1, features: 0, server: "x".repeat(MAX_NAME + 1) };
    assert!(matches!(encode_reply(&reply), Err(CodecError::FieldLength)));
}

#[test]
fn decode_reply_recovers_welcome_and_refuse() {
    // Welcome: u8(2) | u16(4) | u32(0b1010) | u16(2) | "ok"
    let welcome_bytes = [0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x02, b'o', b'k'];
    assert_eq!(decode_reply(&welcome_bytes).unwrap(), Reply::Welcome { version: 4, features: 0b1010, server: "ok".to_string() });

    // Refuse: u8(3) | u16(2) | u16(7)
    let refuse_bytes = [0x03, 0x00, 0x02, 0x00, 0x07];
    assert_eq!(decode_reply(&refuse_bytes).unwrap(), Reply::Refuse { min_version: 2, max_version: 7 });
}

#[test]
fn decode_reply_rejects_unknown_tag_and_trailing_bytes() {
    // tag 0 → BadKind
    assert!(matches!(decode_reply(&[0x00, 0, 0]), Err(CodecError::BadKind(0))));
    // tag 1 (a Hello tag, not a reply tag) → BadKind
    assert!(matches!(decode_reply(&[0x01, 0, 0]), Err(CodecError::BadKind(1))));
    // empty input → Truncated
    assert!(matches!(decode_reply(&[]), Err(CodecError::Truncated)));

    // Refuse with trailing byte → TrailingBytes
    let bytes = [0x03, 0x00, 0x01, 0x00, 0x02, 0xAA];
    assert!(matches!(decode_reply(&bytes), Err(CodecError::TrailingBytes)));
}

#[test]
fn decode_reply_welcome_rejects_truncation_and_bad_fields() {
    // tag only → Truncated
    assert!(matches!(decode_reply(&[0x02]), Err(CodecError::Truncated)));
    // tag + version but features truncated → Truncated
    assert!(matches!(decode_reply(&[0x02, 0x00, 0x01, 0x00]), Err(CodecError::Truncated)));
    // tag + version + features + str-length 0 → FieldLength
    let bytes = [0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
    assert!(matches!(decode_reply(&bytes), Err(CodecError::FieldLength)));

    // tag + version + features + valid length but invalid UTF-8 → BadUtf8
    let bytes = [0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0xFF, 0xFE];
    assert!(matches!(decode_reply(&bytes), Err(CodecError::BadUtf8)));
}
