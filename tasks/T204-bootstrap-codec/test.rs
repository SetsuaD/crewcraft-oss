#![allow(clippy::unwrap_used)]

use crewcraft_proto::bootstrap::{
    BootstrapRequest, BootstrapResponse, CODE_LEN, MAX_CERT, MAX_CSR, MAX_DEVICE_NAME, MAX_PASSWORD, MAX_URI, decode_bootstrap_request,
    decode_bootstrap_response, encode_bootstrap_request, encode_bootstrap_response,
};
use crewcraft_proto::message::CodecError;
use crewcraft_proto::request::decode_request;

fn redeem() -> BootstrapRequest {
    BootstrapRequest::Redeem { device_name: "laptop".into(), csr: vec![1, 2, 3], password: "pw-example-1234".into() }
}

#[test]
fn redeem_wire_format() {
    let bytes = encode_bootstrap_request(7, &redeem()).unwrap();
    let mut expected = vec![32u8, 0, 0, 0, 7, 0, 6];
    expected.extend_from_slice(b"laptop");
    expected.extend_from_slice(&[0, 3, 1, 2, 3, 0, 15]);
    expected.extend_from_slice(b"pw-example-1234");
    assert_eq!(bytes, expected);
    assert_eq!(decode_bootstrap_request(&bytes).unwrap(), (7, redeem()));
}

#[test]
fn confirm_totp_wire_format() {
    let req = BootstrapRequest::ConfirmTotp { code: "123456".into() };
    let bytes = encode_bootstrap_request(0x0102_0304, &req).unwrap();
    assert_eq!(bytes, vec![33, 1, 2, 3, 4, 0, 6, b'1', b'2', b'3', b'4', b'5', b'6']);
    assert_eq!(decode_bootstrap_request(&bytes).unwrap(), (0x0102_0304, req));
}

#[test]
fn response_wire_formats_and_round_trips() {
    let redeemed = BootstrapResponse::Redeemed { certificate: vec![9, 9], totp_uri: "otpauth://x".into() };
    let bytes = encode_bootstrap_response(9, &redeemed).unwrap();
    let mut expected = vec![160u8, 0, 0, 0, 9, 0, 2, 9, 9, 0, 11];
    expected.extend_from_slice(b"otpauth://x");
    assert_eq!(bytes, expected);
    assert_eq!(decode_bootstrap_response(&bytes).unwrap(), (9, redeemed));

    let bytes = encode_bootstrap_response(1, &BootstrapResponse::Activated).unwrap();
    assert_eq!(bytes, vec![161, 0, 0, 0, 1]);
    assert_eq!(decode_bootstrap_response(&bytes).unwrap(), (1, BootstrapResponse::Activated));

    let bytes = encode_bootstrap_response(2, &BootstrapResponse::Error { code: 0x0102 }).unwrap();
    assert_eq!(bytes, vec![162, 0, 0, 0, 2, 1, 2]);
    assert_eq!(decode_bootstrap_response(&bytes).unwrap(), (2, BootstrapResponse::Error { code: 0x0102 }));
}

/// The two vocabularies never overlap: ordinary request tags (1 to 6) are unknown to the bootstrap decoder, the
/// bootstrap tags are unknown to `request::decode_request`, and a response tag is not a request tag.
#[test]
fn the_tag_spaces_are_disjoint() {
    for tag in 1u8..=6 {
        assert_eq!(decode_bootstrap_request(&[tag, 0, 0, 0, 1]).unwrap_err(), CodecError::BadKind(tag));
    }
    for tag in [0u8, 31, 34, 128, 129, 160, 255] {
        assert_eq!(decode_bootstrap_request(&[tag, 0, 0, 0, 1]).unwrap_err(), CodecError::BadKind(tag));
    }
    let redeem = encode_bootstrap_request(1, &redeem()).unwrap();
    assert_eq!(decode_request(&redeem).unwrap_err(), CodecError::BadKind(32));
    let confirm = encode_bootstrap_request(1, &BootstrapRequest::ConfirmTotp { code: "000000".into() }).unwrap();
    assert_eq!(decode_request(&confirm).unwrap_err(), CodecError::BadKind(33));
    // Ordinary response tags are not bootstrap responses.
    assert_eq!(decode_bootstrap_response(&[128, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap_err(), CodecError::BadKind(128));
    assert_eq!(decode_bootstrap_response(&[32, 0, 0, 0, 1]).unwrap_err(), CodecError::BadKind(32));
}

#[test]
fn truncated_and_trailing_input() {
    assert_eq!(decode_bootstrap_request(&[]).unwrap_err(), CodecError::Truncated);
    assert_eq!(decode_bootstrap_request(&[32, 0, 0]).unwrap_err(), CodecError::Truncated);
    let good = encode_bootstrap_request(7, &redeem()).unwrap();
    for cut in 1..good.len() {
        assert_eq!(decode_bootstrap_request(&good[..cut]).unwrap_err(), CodecError::Truncated, "cut at {cut}");
    }
    let mut longer = good.clone();
    longer.push(0);
    assert_eq!(decode_bootstrap_request(&longer).unwrap_err(), CodecError::TrailingBytes);
    let activated = vec![161u8, 0, 0, 0, 1, 0];
    assert_eq!(decode_bootstrap_response(&activated).unwrap_err(), CodecError::TrailingBytes);
}

#[test]
fn field_ranges_are_enforced_both_ways() {
    // Encode: out-of-range fields are refused.
    let big = |n: usize| "x".repeat(n);
    let r = |name: String, csr: Vec<u8>, password: String| BootstrapRequest::Redeem { device_name: name, csr, password };
    assert_eq!(encode_bootstrap_request(1, &r(String::new(), vec![1], "p".into())).unwrap_err(), CodecError::FieldLength);
    assert_eq!(encode_bootstrap_request(1, &r(big(MAX_DEVICE_NAME + 1), vec![1], "p".into())).unwrap_err(), CodecError::FieldLength);
    assert_eq!(encode_bootstrap_request(1, &r("d".into(), vec![], "p".into())).unwrap_err(), CodecError::FieldLength);
    assert_eq!(encode_bootstrap_request(1, &r("d".into(), vec![0; MAX_CSR + 1], "p".into())).unwrap_err(), CodecError::FieldLength);
    assert_eq!(encode_bootstrap_request(1, &r("d".into(), vec![1], String::new())).unwrap_err(), CodecError::FieldLength);
    assert_eq!(encode_bootstrap_request(1, &r("d".into(), vec![1], big(MAX_PASSWORD + 1))).unwrap_err(), CodecError::FieldLength);
    // The limits themselves are fine.
    let at_limit = r(big(MAX_DEVICE_NAME), vec![0; MAX_CSR], big(MAX_PASSWORD));
    let bytes = encode_bootstrap_request(1, &at_limit).unwrap();
    assert_eq!(decode_bootstrap_request(&bytes).unwrap().1, at_limit);

    assert_eq!(CODE_LEN, 6);
    for code in ["", "12345", "1234567"] {
        assert_eq!(encode_bootstrap_request(1, &BootstrapRequest::ConfirmTotp { code: code.into() }).unwrap_err(), CodecError::FieldLength);
    }

    let resp = |cert: Vec<u8>, uri: String| BootstrapResponse::Redeemed { certificate: cert, totp_uri: uri };
    assert_eq!(encode_bootstrap_response(1, &resp(vec![], "u".into())).unwrap_err(), CodecError::FieldLength);
    assert_eq!(encode_bootstrap_response(1, &resp(vec![0; MAX_CERT + 1], "u".into())).unwrap_err(), CodecError::FieldLength);
    assert_eq!(encode_bootstrap_response(1, &resp(vec![1], String::new())).unwrap_err(), CodecError::FieldLength);
    assert_eq!(encode_bootstrap_response(1, &resp(vec![1], big(MAX_URI + 1))).unwrap_err(), CodecError::FieldLength);
    assert!(encode_bootstrap_response(1, &resp(vec![0; MAX_CERT], big(MAX_URI))).is_ok());
}

/// On decode the length prefix is judged before the bytes are read, so a huge announced length is `FieldLength`, not
/// `Truncated`.
#[test]
fn decode_checks_the_length_prefix_first() {
    // Redeem with a device name announced as 65 bytes (MAX_DEVICE_NAME + 1) but not supplied.
    assert_eq!(decode_bootstrap_request(&[32, 0, 0, 0, 1, 0, 65]).unwrap_err(), CodecError::FieldLength);
    // An empty device name.
    assert_eq!(decode_bootstrap_request(&[32, 0, 0, 0, 1, 0, 0]).unwrap_err(), CodecError::FieldLength);
    // A TOTP code announced as 5 bytes.
    assert_eq!(decode_bootstrap_request(&[33, 0, 0, 0, 1, 0, 5, b'1', b'2', b'3', b'4', b'5']).unwrap_err(), CodecError::FieldLength);
    // A csr announced as MAX_CSR + 1 bytes.
    let mut bytes = vec![32u8, 0, 0, 0, 1, 0, 1, b'd'];
    bytes.extend_from_slice(&((MAX_CSR + 1) as u16).to_be_bytes());
    assert_eq!(decode_bootstrap_request(&bytes).unwrap_err(), CodecError::FieldLength);
}

#[test]
fn invalid_utf8_is_refused() {
    let bytes = vec![33u8, 0, 0, 0, 1, 0, 6, 0xFF, 0xFE, b'1', b'2', b'3', b'4'];
    assert_eq!(decode_bootstrap_request(&bytes).unwrap_err(), CodecError::BadUtf8);
}

#[test]
fn secrets_stay_out_of_debug_output() {
    let shown = format!("{:?}", redeem());
    assert!(!shown.contains("pw-example-1234"), "{shown}");
    assert!(shown.contains("laptop"));
    let shown = format!("{:?}", BootstrapRequest::ConfirmTotp { code: "654321".into() });
    assert!(!shown.contains("654321"), "{shown}");

    let response = BootstrapResponse::Redeemed { certificate: vec![1, 2, 3], totp_uri: "otpauth://totp/fixture?secret=mock".into() };
    assert_eq!(format!("{response:?}"), "Redeemed { certificate: <3 bytes>, totp_uri: .. }");
    assert!(!format!("{response:#?}").contains("otpauth://"));
}
