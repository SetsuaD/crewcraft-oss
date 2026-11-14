#![allow(clippy::unwrap_used)]

use crewcraft_proto::message::{CodecError, MAX_NAME};
use crewcraft_proto::push::{MAX_HTML, MAX_MENTIONS, Push, decode_push, encode_push};

// --- helpers to build wire bytes by hand ---

fn str_bytes(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = (b.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(b);
    out
}

fn u64_bytes(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

// --- 1. Round-trip: Other ---

#[test]
fn roundtrip_other() {
    let push = Push::Other { room: "room1".into(), cursor: 42 };
    let wire = encode_push(&push).unwrap();
    // expected: [67][u16 len=5]["room1"][u64 42]
    let mut expected = vec![67u8];
    expected.extend_from_slice(&str_bytes("room1"));
    expected.extend_from_slice(&u64_bytes(42));
    assert_eq!(wire, expected);
    assert_eq!(decode_push(&wire).unwrap(), push);
}

// --- 2. Round-trip: Posted with mentions ---

#[test]
fn roundtrip_posted_with_mentions() {
    let push = Push::Posted {
        room: "general".into(),
        cursor: 7,
        author: "alice".into(),
        html: "hello <b>world</b>".into(),
        mentions: vec!["bob".into(), "carol".into()],
    };
    let wire = encode_push(&push).unwrap();
    let mut expected = vec![64u8];
    expected.extend_from_slice(&str_bytes("general"));
    expected.extend_from_slice(&u64_bytes(7));
    expected.extend_from_slice(&str_bytes("alice"));
    expected.extend_from_slice(&str_bytes("hello <b>world</b>"));
    expected.push(2u8); // mention count
    expected.extend_from_slice(&str_bytes("bob"));
    expected.extend_from_slice(&str_bytes("carol"));
    assert_eq!(wire, expected);
    assert_eq!(decode_push(&wire).unwrap(), push);
}

// --- 3. Round-trip: Edited with zero mentions and empty html ---

#[test]
fn roundtrip_edited_empty_html_zero_mentions() {
    let push = Push::Edited { room: "dev".into(), cursor: 100, target: 99, html: String::new(), mentions: Vec::new() };
    let wire = encode_push(&push).unwrap();
    let mut expected = vec![65u8];
    expected.extend_from_slice(&str_bytes("dev"));
    expected.extend_from_slice(&u64_bytes(100));
    expected.extend_from_slice(&u64_bytes(99));
    expected.extend_from_slice(&str_bytes("")); // html len = 0
    expected.push(0u8); // mention count
    assert_eq!(wire, expected);
    assert_eq!(decode_push(&wire).unwrap(), push);
}

// --- 4. Round-trip: Deleted ---

#[test]
fn roundtrip_deleted() {
    let push = Push::Deleted { room: "chat".into(), cursor: 5, target: 77 };
    let wire = encode_push(&push).unwrap();
    let mut expected = vec![66u8];
    expected.extend_from_slice(&str_bytes("chat"));
    expected.extend_from_slice(&u64_bytes(5));
    expected.extend_from_slice(&u64_bytes(77));
    assert_eq!(wire, expected);
    assert_eq!(decode_push(&wire).unwrap(), push);
}

// --- 5. Encode: empty room is rejected (min 1 byte) ---

#[test]
fn encode_posted_empty_room_is_field_length() {
    let push = Push::Posted { room: String::new(), cursor: 0, author: "a".into(), html: "h".into(), mentions: vec!["m".into()] };
    assert_eq!(encode_push(&push), Err(CodecError::FieldLength));
}

// --- 6. Encode: empty author is rejected (min 1 byte) ---

#[test]
fn encode_posted_empty_author_is_field_length() {
    let push = Push::Posted { room: "r".into(), cursor: 0, author: String::new(), html: "h".into(), mentions: vec!["m".into()] };
    assert_eq!(encode_push(&push), Err(CodecError::FieldLength));
}

// --- 7. Encode: empty mention is rejected (min 1 byte) ---

#[test]
fn encode_posted_empty_mention_is_field_length() {
    let push = Push::Posted { room: "r".into(), cursor: 0, author: "a".into(), html: "h".into(), mentions: vec!["m".into(), String::new()] };
    assert_eq!(encode_push(&push), Err(CodecError::FieldLength));
}

// --- 8. Encode: more than MAX_MENTIONS mentions is rejected ---

#[test]
fn encode_posted_too_many_mentions_is_field_length() {
    let mentions: Vec<String> = (0..=MAX_MENTIONS).map(|i| format!("m{i}")).collect();
    assert_eq!(mentions.len(), MAX_MENTIONS + 1);
    let push = Push::Posted { room: "r".into(), cursor: 0, author: "a".into(), html: "h".into(), mentions };
    assert_eq!(encode_push(&push), Err(CodecError::FieldLength));
}

// --- 9. Decode: empty input is Truncated ---

#[test]
fn decode_empty_is_truncated() {
    assert_eq!(decode_push(&[]), Err(CodecError::Truncated));
}

// --- 10. Decode: unknown tag is BadKind ---

#[test]
fn decode_bad_tag_is_bad_kind() {
    // tag 99 is not in 64..=67
    assert_eq!(decode_push(&[99u8, 0, 1, 97]), Err(CodecError::BadKind(99)));
    // tag 63 is just below the valid range
    assert_eq!(decode_push(&[63u8, 0, 1, 97]), Err(CodecError::BadKind(63)));
    // tag 68 is just above
    assert_eq!(decode_push(&[68u8, 0, 1, 97]), Err(CodecError::BadKind(68)));
}

// --- 11. Decode: room length 0 is FieldLength (checked before bytes) ---

#[test]
fn decode_room_zero_length_is_field_length() {
    // tag 67 (Other), room len = 0, then cursor bytes (never reached)
    let bytes: Vec<u8> = vec![67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    assert_eq!(decode_push(&bytes), Err(CodecError::FieldLength));
}

// --- 12. Decode: room bytes truncated ---

#[test]
fn decode_room_truncated() {
    // tag 67, room len = 5 but only 2 bytes of "abc" available, no cursor
    let bytes: Vec<u8> = vec![67, 0, 5, 97, 98];
    assert_eq!(decode_push(&bytes), Err(CodecError::Truncated));
}

// --- 13. Decode: cursor truncated (room ok, only 3 of 8 cursor bytes) ---

#[test]
fn decode_cursor_truncated() {
    // tag 67, room "ab" (len 2), cursor only 3 bytes
    let mut bytes: Vec<u8> = vec![67, 0, 2, 97, 98, 1, 2, 3];
    assert_eq!(decode_push(&bytes), Err(CodecError::Truncated));
    // also: cursor with 7 bytes
    bytes.push(0);
    assert_eq!(decode_push(&bytes), Err(CodecError::Truncated));
}

// --- 14. Decode: bad UTF-8 in room ---

#[test]
fn decode_room_bad_utf8() {
    // tag 67, room len = 1, byte 0xFF (invalid UTF-8)
    let bytes: Vec<u8> = vec![67, 0, 1, 0xFF, 0, 0, 0, 0, 0, 0, 0, 1];
    assert_eq!(decode_push(&bytes), Err(CodecError::BadUtf8));
}

// --- 15. Decode: trailing bytes after a valid Other ---

#[test]
fn decode_trailing_bytes() {
    // valid Other { room: "a", cursor: 1 } followed by one extra byte
    let mut bytes: Vec<u8> = vec![67, 0, 1, 97, 0, 0, 0, 0, 0, 0, 0, 1];
    bytes.push(0);
    assert_eq!(decode_push(&bytes), Err(CodecError::TrailingBytes));
}

// --- 16. Decode: Posted with empty author is FieldLength ---

#[test]
fn decode_posted_empty_author_is_field_length() {
    // tag 64, room "r", cursor 0, author len 0 → FieldLength
    let mut bytes: Vec<u8> = vec![64, 0, 1, 114];
    bytes.extend_from_slice(&u64_bytes(0));
    bytes.extend_from_slice(&[0u8, 0u8]); // author len = 0
    assert_eq!(decode_push(&bytes), Err(CodecError::FieldLength));
}

// --- 17. Decode: Posted with empty mention is FieldLength ---

#[test]
fn decode_posted_empty_mention_is_field_length() {
    // tag 64, room "r", cursor 0, author "a", html "h", count 1, mention len 0
    let mut bytes: Vec<u8> = vec![64, 0, 1, 114];
    bytes.extend_from_slice(&u64_bytes(0));
    bytes.extend_from_slice(&str_bytes("a"));
    bytes.extend_from_slice(&str_bytes("h"));
    bytes.push(1u8); // one mention
    bytes.extend_from_slice(&[0u8, 0u8]); // mention len = 0
    assert_eq!(decode_push(&bytes), Err(CodecError::FieldLength));
}

// --- 18. Decode: Posted with count > MAX_MENTIONS is FieldLength ---

#[test]
fn decode_posted_too_many_mentions_is_field_length() {
    // tag 64, room "r", cursor 0, author "a", html "h", count = MAX_MENTIONS + 1
    let mut bytes: Vec<u8> = vec![64, 0, 1, 114];
    bytes.extend_from_slice(&u64_bytes(0));
    bytes.extend_from_slice(&str_bytes("a"));
    bytes.extend_from_slice(&str_bytes("h"));
    bytes.push((MAX_MENTIONS + 1) as u8);
    assert_eq!(decode_push(&bytes), Err(CodecError::FieldLength));
}

// --- 19. Decode: room length exceeding MAX_NAME is FieldLength ---

#[test]
fn decode_room_exceeds_max_name_is_field_length() {
    // tag 67, room len = MAX_NAME + 1 (as u16), no actual bytes needed (length check first)
    let len = (MAX_NAME + 1) as u16;
    let mut bytes: Vec<u8> = vec![67];
    bytes.extend_from_slice(&len.to_be_bytes());
    assert_eq!(decode_push(&bytes), Err(CodecError::FieldLength));
}

// --- 20. Encode: html longer than MAX_HTML is FieldLength ---

#[test]
fn encode_posted_html_exceeds_max_is_field_length() {
    let html = "x".repeat(MAX_HTML + 1);
    let push = Push::Posted { room: "r".into(), cursor: 0, author: "a".into(), html, mentions: vec!["m".into()] };
    assert_eq!(encode_push(&push), Err(CodecError::FieldLength));
}

// --- 21. Encode: html exactly MAX_HTML is accepted ---

#[test]
fn encode_posted_html_at_max_is_ok() {
    let html = "x".repeat(MAX_HTML);
    let push = Push::Posted { room: "r".into(), cursor: 0, author: "a".into(), html, mentions: Vec::new() };
    assert!(encode_push(&push).is_ok());
}

// --- 22. Round-trip: Posted with max mentions and multi-byte UTF-8 ---

#[test]
fn roundtrip_posted_multibyte_utf8_and_max_mentions() {
    let mentions: Vec<String> = (0..MAX_MENTIONS).map(|i| format!("ü{ü}", ü = i)).collect();
    let push = Push::Posted { room: "çafé".into(), cursor: u64::MAX, author: "日本語".into(), html: "naïve".into(), mentions };
    let wire = encode_push(&push).unwrap();
    assert_eq!(decode_push(&wire).unwrap(), push);
}

// --- 23. Decode: Edited with truncated target ---

#[test]
fn decode_edited_target_truncated() {
    // tag 65, room "r", cursor 0, target only 4 bytes (need 8)
    let mut bytes: Vec<u8> = vec![65, 0, 1, 114];
    bytes.extend_from_slice(&u64_bytes(0));
    bytes.extend_from_slice(&[0u8, 0, 0, 1]); // only 4 bytes of target
    assert_eq!(decode_push(&bytes), Err(CodecError::Truncated));
}

// --- 24. Decode: Deleted with truncated target ---

#[test]
fn decode_deleted_target_truncated() {
    // tag 66, room "r", cursor 0, target only 2 bytes
    let mut bytes: Vec<u8> = vec![66, 0, 1, 114];
    bytes.extend_from_slice(&u64_bytes(0));
    bytes.extend_from_slice(&[0u8, 1u8]);
    assert_eq!(decode_push(&bytes), Err(CodecError::Truncated));
}

// --- 25. Decode: tag 64 with missing html length (truncated after author) ---

#[test]
fn decode_posted_missing_html_is_truncated() {
    // tag 64, room "r", cursor 0, author "a", then nothing (html len missing)
    let mut bytes: Vec<u8> = vec![64, 0, 1, 114];
    bytes.extend_from_slice(&u64_bytes(0));
    bytes.extend_from_slice(&str_bytes("a"));
    // no html length bytes → Truncated
    assert_eq!(decode_push(&bytes), Err(CodecError::Truncated));
}

// --- 26. Decode: Posted html length exceeding MAX_HTML is FieldLength ---

#[test]
fn decode_posted_html_exceeds_max_is_field_length() {
    // tag 64, room "r", cursor 0, author "a", html len = MAX_HTML + 1
    let mut bytes: Vec<u8> = vec![64, 0, 1, 114];
    bytes.extend_from_slice(&u64_bytes(0));
    bytes.extend_from_slice(&str_bytes("a"));
    let bad_len = (MAX_HTML + 1) as u16;
    bytes.extend_from_slice(&bad_len.to_be_bytes());
    assert_eq!(decode_push(&bytes), Err(CodecError::FieldLength));
}

// --- 27. Decode: Posted mention count byte read, then first mention truncated ---

#[test]
fn decode_posted_first_mention_truncated() {
    // tag 64, room "r", cursor 0, author "a", html "h", count 1, mention len 5 but 0 bytes
    let mut bytes: Vec<u8> = vec![64, 0, 1, 114];
    bytes.extend_from_slice(&u64_bytes(0));
    bytes.extend_from_slice(&str_bytes("a"));
    bytes.extend_from_slice(&str_bytes("h"));
    bytes.push(1u8); // count = 1
    bytes.extend_from_slice(&[0u8, 5u8]); // mention len = 5, but no bytes follow
    assert_eq!(decode_push(&bytes), Err(CodecError::Truncated));
}

// --- 28. Encode: room exceeding MAX_NAME is FieldLength ---

#[test]
fn encode_room_exceeds_max_name_is_field_length() {
    let room = "x".repeat(MAX_NAME + 1);
    let push = Push::Other { room, cursor: 0 };
    assert_eq!(encode_push(&push), Err(CodecError::FieldLength));
}

// --- 29. Encode: author exceeding MAX_NAME is FieldLength ---

#[test]
fn encode_posted_author_exceeds_max_name_is_field_length() {
    let author = "x".repeat(MAX_NAME + 1);
    let push = Push::Posted { room: "r".into(), cursor: 0, author, html: "h".into(), mentions: vec!["m".into()] };
    assert_eq!(encode_push(&push), Err(CodecError::FieldLength));
}

// --- 30. Decode: tag check happens before any field (even if rest is garbage) ---

#[test]
fn decode_bad_tag_checked_before_fields() {
    // tag 0 is not valid; even though the rest could look like a valid body, BadKind wins
    assert_eq!(decode_push(&[0u8, 0, 1, 97, 0, 0, 0, 0, 0, 0, 0, 1]), Err(CodecError::BadKind(0)));
    // tag 255
    assert_eq!(decode_push(&[255u8, 0, 1, 97]), Err(CodecError::BadKind(255)));
}
