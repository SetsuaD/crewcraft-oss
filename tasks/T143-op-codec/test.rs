#![allow(clippy::unwrap_used)]

use crewcraft_proto::message::CodecError;
use crewcraft_server_core::op::{MAX_STR, Op, decode_op, encode_op};
use crewcraft_server_core::room::Role;

/// Verify the exact wire bytes for `CreateRoom`: tag 1, two `str` fields (u32 BE length + UTF-8 bytes).
#[test]
fn encode_create_room_wire_format() {
    let op = Op::CreateRoom { owner: "alice".into(), name: "My Room".into() };
    let bytes = encode_op(&op).unwrap();
    // tag(1) + [u32 len(4) + 5 bytes "alice"] + [u32 len(4) + 7 bytes "My Room"]
    let expected: Vec<u8> = vec![1, 0, 0, 0, 5, b'a', b'l', b'i', b'c', b'e', 0, 0, 0, 7, b'M', b'y', b' ', b'R', b'o', b'o', b'm'];
    assert_eq!(bytes, expected);
}

/// Verify the role byte in `AddMember` for all four roles (0 Guest, 1 Member, 2 Admin, 3 Owner).
#[test]
fn encode_add_member_role_byte() {
    let roles = [(Role::Guest, 0u8), (Role::Member, 1), (Role::Admin, 2), (Role::Owner, 3)];
    for (role, expected_byte) in roles {
        let op = Op::AddMember { slug: "s".into(), actor: "a".into(), user: "u".into(), role };
        let bytes = encode_op(&op).unwrap();
        // tag(1) + 3*str(5 each) + role(1) = 1 + 15 + 1 = 17 bytes
        assert_eq!(bytes.len(), 17);
        assert_eq!(bytes[0], 2); // tag AddMember
        assert_eq!(bytes[16], expected_byte);
    }
}

/// Verify exact wire bytes for `Post`: tag 4, three `str` fields, one `u64` BE.
#[test]
fn encode_post_wire_format() {
    let op = Op::Post { slug: "r".into(), author: "bob".into(), text: "hello".into(), now_ms: 1_000_000 };
    let bytes = encode_op(&op).unwrap();
    // 1 + 5 + 7 + 9 + 8 = 30
    let expected: Vec<u8> = vec![
        4, 0, 0, 0, 1, b'r', 0, 0, 0, 3, b'b', b'o', b'b', 0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o', 0, 0, 0, 0, 0, 15, 66,
        64, // 1_000_000 = 0x0F4240
    ];
    assert_eq!(bytes, expected);
}

/// Verify exact wire bytes for `Edit`: tag 5, two `str`, `u64` target, `str` text, `u64` now_ms.
#[test]
fn encode_edit_wire_format() {
    let op = Op::Edit { slug: "r".into(), actor: "a".into(), target: 42, text: "edited".into(), now_ms: 999 };
    let bytes = encode_op(&op).unwrap();
    // 1 + 5 + 5 + 8 + 10 + 8 = 37
    let expected: Vec<u8> = vec![
        5, 0, 0, 0, 1, b'r', 0, 0, 0, 1, b'a', 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 6, b'e', b'd', b'i', b't', b'e', b'd', 0, 0, 0, 0, 0, 0, 3,
        231, // 999 = 0x3E7
    ];
    assert_eq!(bytes, expected);
}

/// Verify exact wire bytes for `Delete`: tag 6, two `str`, `u64` target.
#[test]
fn encode_delete_wire_format() {
    let op = Op::Delete { slug: "r".into(), actor: "a".into(), target: 7 };
    let bytes = encode_op(&op).unwrap();
    let expected: Vec<u8> = vec![6, 0, 0, 0, 1, b'r', 0, 0, 0, 1, b'a', 0, 0, 0, 0, 0, 0, 0, 7];
    assert_eq!(bytes, expected);
}

/// Verify exact wire bytes for `MarkRead`: tag 7, two `str`, `u64` cursor.
#[test]
fn encode_mark_read_wire_format() {
    let op = Op::MarkRead { slug: "r".into(), user: "u".into(), cursor: 100 };
    let bytes = encode_op(&op).unwrap();
    let expected: Vec<u8> = vec![7, 0, 0, 0, 1, b'r', 0, 0, 0, 1, b'u', 0, 0, 0, 0, 0, 0, 0, 100];
    assert_eq!(bytes, expected);
}

/// A string longer than `MAX_STR` bytes must be rejected with `FieldLength`.
#[test]
fn encode_rejects_string_over_max() {
    let long = "a".repeat(MAX_STR + 1);
    let op = Op::CreateRoom { owner: long, name: "x".into() };
    assert_eq!(encode_op(&op), Err(CodecError::FieldLength));
}

/// Empty strings are permitted (the docs state "Strings may be empty here").
#[test]
fn encode_accepts_empty_string() {
    let op = Op::CreateRoom { owner: String::new(), name: String::new() };
    let bytes = encode_op(&op).unwrap();
    // tag(1) + u32 len 0 + u32 len 0 = 1 + 4 + 4 = 9
    let expected: Vec<u8> = vec![1, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(bytes, expected);
}

/// Decoding zero bytes must yield `Truncated` (cannot even read the tag).
#[test]
fn decode_empty_input_truncated() {
    assert_eq!(decode_op(&[]), Err(CodecError::Truncated));
}

/// A tag outside 1..=7 must yield `BadKind(tag)`.
#[test]
fn decode_unknown_tag_bad_kind() {
    assert_eq!(decode_op(&[0]), Err(CodecError::BadKind(0)));
    assert_eq!(decode_op(&[8]), Err(CodecError::BadKind(8)));
    assert_eq!(decode_op(&[255]), Err(CodecError::BadKind(255)));
}

/// After a valid tag, if fewer than 4 bytes remain for a string length prefix, error is `Truncated`.
#[test]
fn decode_truncated_string_length_prefix() {
    // tag 1 (CreateRoom) followed by only 2 bytes (need 4 for u32 length)
    let bytes: Vec<u8> = vec![1, 0, 0];
    assert_eq!(decode_op(&bytes), Err(CodecError::Truncated));
}

/// A string length prefix exceeding `MAX_STR` must yield `FieldLength` before any string bytes are read.
#[test]
fn decode_string_length_over_max_field_length() {
    // tag 1, u32 length = 65537 = 0x0001_0001 (> MAX_STR = 65536)
    let bytes: Vec<u8> = vec![1, 0, 1, 0, 1];
    assert_eq!(decode_op(&bytes), Err(CodecError::FieldLength));
}

/// A string whose bytes are not valid UTF-8 must yield `BadUtf8`.
#[test]
fn decode_invalid_utf8() {
    // tag 1, owner len=2, bytes 0xFF 0xFE (invalid UTF-8)
    let bytes: Vec<u8> = vec![1, 0, 0, 0, 2, 0xFF, 0xFE];
    assert_eq!(decode_op(&bytes), Err(CodecError::BadUtf8));
}

/// In `AddMember`, a role byte above 3 must yield `BadKind(byte)`.
#[test]
fn decode_role_above_three_bad_kind() {
    // tag 2, slug="s", actor="a", user="u", role=4
    let bytes: Vec<u8> = vec![2, 0, 0, 0, 1, b's', 0, 0, 0, 1, b'a', 0, 0, 0, 1, b'u', 4];
    assert_eq!(decode_op(&bytes), Err(CodecError::BadKind(4)));
}

/// Bytes remaining after a complete record must yield `TrailingBytes`.
#[test]
fn decode_trailing_bytes() {
    // Valid CreateRoom { owner: "r", name: "n" } plus one extra byte
    let mut bytes: Vec<u8> = vec![1, 0, 0, 0, 1, b'r', 0, 0, 0, 1, b'n'];
    bytes.push(0);
    assert_eq!(decode_op(&bytes), Err(CodecError::TrailingBytes));
}

/// A string whose declared length exceeds the remaining bytes must yield `Truncated`.
#[test]
fn decode_truncated_string_bytes() {
    // tag 1, owner len=5, but only 3 bytes follow
    let bytes: Vec<u8> = vec![1, 0, 0, 0, 5, b'a', b'b', b'c'];
    assert_eq!(decode_op(&bytes), Err(CodecError::Truncated));
}

/// Round-trip: encode then decode all seven variants and confirm equality.
#[test]
fn roundtrip_all_variants() {
    let ops = vec![
        Op::CreateRoom { owner: "alice".into(), name: "Lobby".into() },
        Op::AddMember { slug: "s1".into(), actor: "alice".into(), user: "bob".into(), role: Role::Member },
        Op::RemoveMember { slug: "s1".into(), actor: "alice".into(), user: "bob".into() },
        Op::Post { slug: "s1".into(), author: "bob".into(), text: "hello world".into(), now_ms: 1_700_000_000_000 },
        Op::Edit { slug: "s1".into(), actor: "bob".into(), target: 3, text: "fixed".into(), now_ms: 1_700_000_000_500 },
        Op::Delete { slug: "s1".into(), actor: "alice".into(), target: 5 },
        Op::MarkRead { slug: "s1".into(), user: "bob".into(), cursor: 42 },
    ];
    for op in &ops {
        let encoded = encode_op(op).unwrap();
        let decoded = decode_op(&encoded).unwrap();
        assert_eq!(&decoded, op, "roundtrip failed for {op:?}");
    }
}

/// Added in review: the length limit is inclusive on both sides, and a record cut off in its role byte or in a u64 is
/// `Truncated`.
#[test]
fn boundaries_and_truncated_numbers() {
    // Exactly MAX_STR bytes encodes and round-trips.
    let op = Op::CreateRoom { owner: "o".into(), name: "y".repeat(MAX_STR) };
    let bytes = encode_op(&op).unwrap();
    assert_eq!(bytes.len(), 1 + 5 + 4 + MAX_STR);
    assert_eq!(decode_op(&bytes).unwrap(), op);

    // A declared length of exactly MAX_STR passes the length check; the missing bytes are Truncated, not FieldLength.
    let mut bytes = vec![1];
    bytes.extend_from_slice(&(MAX_STR as u32).to_be_bytes());
    assert_eq!(decode_op(&bytes), Err(CodecError::Truncated));

    // AddMember with every string present but no role byte.
    let bytes: Vec<u8> = vec![2, 0, 0, 0, 1, b's', 0, 0, 0, 1, b'a', 0, 0, 0, 1, b'u'];
    assert_eq!(decode_op(&bytes), Err(CodecError::Truncated));

    // Delete with only 7 of the 8 target bytes.
    let bytes: Vec<u8> = vec![6, 0, 0, 0, 1, b'r', 0, 0, 0, 1, b'a', 0, 0, 0, 0, 0, 0, 7];
    assert_eq!(decode_op(&bytes), Err(CodecError::Truncated));
}
