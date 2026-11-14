// T110: binary message codec (version, kind, cursor, three length-prefixed UTF-8 strings).
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_proto::message::{CodecError, Kind, MAX_BODY, MAX_NAME, Message, decode, encode};

fn msg(kind: Kind, room: &str, author: &str, body: &str) -> Message {
    Message { kind, cursor: 7, room: room.to_string(), author: author.to_string(), body: body.to_string() }
}

fn wire() -> Vec<u8> {
    let mut w = vec![1u8, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 7];
    w.extend(b"general");
    w.extend([0, 3]);
    w.extend(b"ana");
    w.extend([0, 2]);
    w.extend(b"hi");
    w
}

#[test]
fn encodes_the_documented_layout() {
    assert_eq!(encode(&msg(Kind::Text, "general", "ana", "hi")).unwrap(), wire());
}

#[test]
fn round_trips_every_kind() {
    for m in [msg(Kind::Text, "general", "ana", "héllo"), msg(Kind::Edit, "r", "b", "x"), msg(Kind::Delete, "r", "b", "")] {
        assert_eq!(decode(&encode(&m).unwrap()).unwrap(), m);
    }
    assert_eq!(encode(&msg(Kind::Text, "r", "b", "héllo")).unwrap()[16..18], [0, 6]); // body length: bytes, not chars
}

#[test]
fn encode_checks_field_lengths() {
    assert_eq!(encode(&msg(Kind::Text, "", "ana", "hi")), Err(CodecError::FieldLength));
    assert_eq!(encode(&msg(Kind::Text, "r", &"a".repeat(MAX_NAME + 1), "hi")), Err(CodecError::FieldLength));
    assert!(encode(&msg(Kind::Text, &"r".repeat(MAX_NAME), "ana", "hi")).is_ok());
    assert!(encode(&msg(Kind::Text, "r", "ana", &"x".repeat(MAX_BODY))).is_ok());
    assert_eq!(encode(&msg(Kind::Text, "r", "ana", &"x".repeat(MAX_BODY + 1))), Err(CodecError::FieldLength));
}

#[test]
fn every_prefix_is_truncated() {
    let w = wire();
    for n in 0..w.len() {
        assert_eq!(decode(&w[..n]), Err(CodecError::Truncated), "prefix of {n} bytes");
    }
}

#[test]
fn decode_errors() {
    let mut w = wire();
    w[0] = 2;
    assert_eq!(decode(&w), Err(CodecError::BadVersion(2)));
    let mut w = wire();
    w[1] = 9;
    assert_eq!(decode(&w), Err(CodecError::BadKind(9)));
    let mut w = wire();
    w.push(0);
    assert_eq!(decode(&w), Err(CodecError::TrailingBytes));
    let mut w = wire();
    let last = w.len() - 1;
    w[last] = 0xff; // the body's last byte is no longer UTF-8
    assert_eq!(decode(&w), Err(CodecError::BadUtf8));
    // an empty room is refused from its length prefix, before any bytes are read
    assert_eq!(decode(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0]), Err(CodecError::FieldLength));
    assert_eq!(decode(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 65]), Err(CodecError::FieldLength));
}
