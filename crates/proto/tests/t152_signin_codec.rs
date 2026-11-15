use crewcraft_proto::message::CodecError;
use crewcraft_proto::signin::{MAX_EMAIL_BYTES, MAX_PASSWORD_BYTES, Reply, SignIn, decode_reply, decode_request, encode_reply, encode_request};

const REQUEST: &[u8] = b"\x22\x00\x0da@example.org\x00\x03a\xc3\xa9012345";
const TOKEN: &str = "__________________________________________8";

#[test]
fn sign_in_payload_has_exact_wire_bytes_and_round_trips() {
    let request = SignIn { email: "a@example.org", password: "aé", code: "012345" };
    assert_eq!(encode_request(&request).unwrap(), REQUEST);
    assert_eq!(decode_request(REQUEST).unwrap(), request);

    let encoded = encode_request(&SignIn { password: "", ..request }).unwrap();
    assert_eq!(decode_request(&encoded).unwrap().password, "");
}

#[test]
fn request_rejects_wrong_phase_truncation_and_trailing_bytes() {
    for end in 0..REQUEST.len() {
        assert_eq!(decode_request(&REQUEST[..end]), Err(CodecError::Truncated));
    }
    for tag in [1, 6, 32, 33, 160, 163, 164] {
        assert_eq!(decode_request(&[tag]), Err(CodecError::BadKind(tag)));
    }
    let mut extra = REQUEST.to_vec();
    extra.push(0);
    assert_eq!(decode_request(&extra), Err(CodecError::TrailingBytes));
}

#[test]
fn request_checks_lengths_utf8_and_code_format() {
    let email = "a".repeat(MAX_EMAIL_BYTES);
    let password = "é".repeat(MAX_PASSWORD_BYTES / 2);
    let bound = SignIn { email: &email, password: &password, code: "000001" };
    assert_eq!(decode_request(&encode_request(&bound).unwrap()).unwrap(), bound);
    for email in ["", &"a".repeat(MAX_EMAIL_BYTES + 1)] {
        assert_eq!(encode_request(&SignIn { email, ..bound }), Err(CodecError::FieldLength));
    }
    let long_password = format!("{password}!");
    assert_eq!(encode_request(&SignIn { password: &long_password, ..bound }), Err(CodecError::FieldLength));
    for code in ["", "12345", "1234567", "12x456", "1234é"] {
        assert_eq!(encode_request(&SignIn { code, ..bound }), Err(CodecError::FieldLength));
    }

    assert_eq!(decode_request(b"\x22\x01\x41"), Err(CodecError::FieldLength)); // email length 321
    assert_eq!(decode_request(b"\x22\x00\x01a\x04\x01"), Err(CodecError::FieldLength)); // password length 1025
    assert_eq!(decode_request(b"\x22\x00\x01\xff"), Err(CodecError::BadUtf8));
    assert_eq!(decode_request(b"\x22\x00\x01a\x00\x01\xff"), Err(CodecError::BadUtf8));
    assert_eq!(decode_request(b"\x22\x00\x01a\x00\x00x12345"), Err(CodecError::FieldLength));
}

#[test]
fn replies_have_exact_wire_bytes_and_reject_wrong_phase() {
    let mut expected = vec![163];
    expected.extend_from_slice(TOKEN.as_bytes());
    assert_eq!(encode_reply(&Reply::Accepted { token: TOKEN }).unwrap(), expected);
    assert_eq!(decode_reply(&expected).unwrap(), Reply::Accepted { token: TOKEN });
    for end in 0..expected.len() {
        assert_eq!(decode_reply(&expected[..end]), Err(CodecError::Truncated));
    }
    expected.push(0);
    assert_eq!(decode_reply(&expected), Err(CodecError::TrailingBytes));
    assert_eq!(encode_reply(&Reply::Refused).unwrap(), [164]);
    assert_eq!(decode_reply(&[164]), Ok(Reply::Refused));
    assert_eq!(decode_reply(&[164, 0]), Err(CodecError::TrailingBytes));
    for tag in [2, 34, 128, 129, 160, 161, 162] {
        assert_eq!(decode_reply(&[tag]), Err(CodecError::BadKind(tag)));
    }
}

#[test]
fn accepted_token_requires_unpadded_canonical_base64url() {
    for (position, invalid) in [(0, b'+'), (0, b'/'), (42, b'='), (42, b'9')] {
        let mut token = TOKEN.as_bytes().to_vec();
        token[position] = invalid;
        assert_eq!(encode_reply(&Reply::Accepted { token: str::from_utf8(&token).unwrap() }), Err(CodecError::FieldLength));
        let mut wire = vec![163];
        wire.extend_from_slice(&token);
        assert_eq!(decode_reply(&wire), Err(CodecError::FieldLength));
    }
    let mut invalid = vec![163, 0xff];
    invalid.extend_from_slice(&TOKEN.as_bytes()[1..]);
    assert_eq!(decode_reply(&invalid), Err(CodecError::BadUtf8));
    assert_eq!(encode_reply(&Reply::Accepted { token: "" }), Err(CodecError::FieldLength));
    assert_eq!(encode_reply(&Reply::Accepted { token: &format!("{TOKEN}A") }), Err(CodecError::FieldLength));
}

#[test]
fn debug_redacts_all_sign_in_secrets() {
    let request = SignIn { email: "a@example.org", password: "fake wire password", code: "987654" };
    let reply = Reply::Accepted { token: TOKEN };
    for rendered in [format!("{request:?}"), format!("{request:#?}"), format!("{reply:?}"), format!("{reply:#?}")] {
        for secret in [request.email, request.password, request.code, TOKEN] {
            assert!(!rendered.contains(secret));
        }
    }
}
