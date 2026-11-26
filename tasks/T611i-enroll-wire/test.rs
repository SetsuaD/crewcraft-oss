//! T611i: the bootstrap messages for enrolling through an organization's identity provider (docs/SECURITY-DESIGN.md
//! section 9): `RedeemExternal`, `ExternalStart` and `ConfirmExternal`, their exact bytes, their limits, what `Debug`
//! hides, and that their tags stay apart from the sign-in and ordinary vocabularies.
#![allow(clippy::unwrap_used)]

use crewcraft_proto::bootstrap::{
    BootstrapRequest, BootstrapResponse, decode_bootstrap_request, decode_bootstrap_response, encode_bootstrap_request, encode_bootstrap_response,
};
use crewcraft_proto::message::CodecError;
use crewcraft_proto::request::decode_request;
use crewcraft_proto::signin::{MAX_AUTH_CODE_BYTES, MAX_REDIRECT_BYTES, MAX_VERIFIER_LEN, MIN_VERIFIER_LEN, decode_opening, decode_reply};

const NONCE: &str = "__________________________________________8";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

fn redeem() -> BootstrapRequest {
    BootstrapRequest::RedeemExternal { device_name: "laptop".into(), csr: vec![1, 2, 3] }
}

fn confirm(code: &str, verifier: &str, redirect_uri: &str) -> BootstrapRequest {
    BootstrapRequest::ConfirmExternal { code: code.into(), verifier: verifier.into(), redirect_uri: redirect_uri.into() }
}

fn start(nonce: &str) -> BootstrapResponse {
    BootstrapResponse::ExternalStart {
        issuer: "https://id/".into(),
        client_id: "chat".into(),
        authorization_endpoint: "https://id/a".into(),
        nonce: nonce.into(),
    }
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[test]
fn redeem_external_wire_format() {
    let bytes = encode_bootstrap_request(7, &redeem()).unwrap();
    let mut expected = vec![39u8, 0, 0, 0, 7];
    field(&mut expected, b"laptop");
    field(&mut expected, &[1, 2, 3]);
    assert_eq!(bytes, expected);
    assert_eq!(decode_bootstrap_request(&bytes).unwrap(), (7, redeem()));
    assert_eq!(format!("{:?}", redeem()), "RedeemExternal { device_name: \"laptop\", csr: <3 bytes> }");
}

#[test]
fn confirm_external_wire_format_and_debug() {
    let request = confirm("the-code", VERIFIER, "http://127.0.0.1:5/callback");
    let bytes = encode_bootstrap_request(0x0102_0304, &request).unwrap();
    let mut expected = vec![40u8, 1, 2, 3, 4];
    field(&mut expected, b"the-code");
    field(&mut expected, VERIFIER.as_bytes());
    field(&mut expected, b"http://127.0.0.1:5/callback");
    assert_eq!(bytes, expected);
    assert_eq!(decode_bootstrap_request(&bytes).unwrap(), (0x0102_0304, request.clone()));
    let debug = format!("{request:?}");
    assert!(!debug.contains("the-code") && !debug.contains(VERIFIER), "Debug leaked a secret: {debug}");
    assert!(debug.contains("127.0.0.1:5"));
}

#[test]
fn external_start_wire_format_and_debug() {
    let bytes = encode_bootstrap_response(9, &start(NONCE)).unwrap();
    let mut expected = vec![167u8, 0, 0, 0, 9];
    for text in ["https://id/", "chat", "https://id/a", NONCE] {
        field(&mut expected, text.as_bytes());
    }
    assert_eq!(bytes, expected);
    assert_eq!(decode_bootstrap_response(&bytes).unwrap(), (9, start(NONCE)));
    let debug = format!("{:?}", start(NONCE));
    assert!(!debug.contains(NONCE) && debug.contains("https://id/a"), "{debug}");
}

#[test]
fn the_limits_are_checked_both_ways() {
    let short = &VERIFIER[..MIN_VERIFIER_LEN - 1];
    let long = "v".repeat(MAX_VERIFIER_LEN + 1);
    let code = "c".repeat(MAX_AUTH_CODE_BYTES + 1);
    let redirect = "r".repeat(MAX_REDIRECT_BYTES + 1);
    for bad in [
        confirm("x", short, "http://127.0.0.1:5/callback"),
        confirm("x", &long, "http://127.0.0.1:5/callback"),
        confirm(&code, VERIFIER, "http://127.0.0.1:5/callback"),
        confirm("x", VERIFIER, &redirect),
        confirm("", VERIFIER, "http://127.0.0.1:5/callback"),
        confirm("has space", VERIFIER, "http://127.0.0.1:5/callback"),
        confirm("x", VERIFIER, "http://127.0.0.1:5/caf\u{e9}"),
    ] {
        assert_eq!(encode_bootstrap_request(1, &bad).unwrap_err(), CodecError::FieldLength, "{bad:?}");
    }
    // The decoder refuses what the encoder would: a code with a space, hand-framed.
    let mut framed = vec![40u8, 0, 0, 0, 1];
    field(&mut framed, b"has space");
    field(&mut framed, VERIFIER.as_bytes());
    field(&mut framed, b"http://127.0.0.1:5/callback");
    assert_eq!(decode_bootstrap_request(&framed).unwrap_err(), CodecError::FieldLength);

    assert_eq!(
        encode_bootstrap_request(1, &BootstrapRequest::RedeemExternal { device_name: String::new(), csr: vec![1] }).unwrap_err(),
        CodecError::FieldLength
    );
    assert_eq!(
        encode_bootstrap_request(1, &BootstrapRequest::RedeemExternal { device_name: "x".into(), csr: Vec::new() }).unwrap_err(),
        CodecError::FieldLength
    );

    // A nonce must be 32 bytes in base64url, like a session token.
    for nonce in ["short", "__________________________________________9", "=_________________________________________8"] {
        assert_eq!(encode_bootstrap_response(1, &start(nonce)).unwrap_err(), CodecError::FieldLength, "{nonce}");
    }
    let mut framed = vec![167u8, 0, 0, 0, 1];
    for text in ["https://id/", "chat", "https://id/a", "__________________________________________9"] {
        field(&mut framed, text.as_bytes());
    }
    assert_eq!(decode_bootstrap_response(&framed).unwrap_err(), CodecError::FieldLength);
}

#[test]
fn truncated_and_trailing_input() {
    for good in [
        encode_bootstrap_request(7, &redeem()).unwrap(),
        encode_bootstrap_request(7, &confirm("x", VERIFIER, "http://127.0.0.1:5/callback")).unwrap(),
    ] {
        for cut in 1..good.len() {
            assert_eq!(decode_bootstrap_request(&good[..cut]).unwrap_err(), CodecError::Truncated, "cut at {cut}");
        }
        let mut longer = good.clone();
        longer.push(0);
        assert_eq!(decode_bootstrap_request(&longer).unwrap_err(), CodecError::TrailingBytes);
    }
    let good = encode_bootstrap_response(7, &start(NONCE)).unwrap();
    for cut in 1..good.len() {
        assert_eq!(decode_bootstrap_response(&good[..cut]).unwrap_err(), CodecError::Truncated, "cut at {cut}");
    }
}

/// The sign-in openings (34 to 38) and replies (163 to 166) are not bootstrap messages, and the new bootstrap tags are
/// neither sign-in openings nor ordinary requests.
#[test]
fn the_tag_spaces_stay_disjoint() {
    for tag in 34u8..=38 {
        assert_eq!(decode_bootstrap_request(&[tag, 0, 0, 0, 1]).unwrap_err(), CodecError::BadKind(tag));
    }
    for tag in [41u8, 160 + 7 + 1] {
        assert_eq!(decode_bootstrap_request(&[tag, 0, 0, 0, 1]).unwrap_err(), CodecError::BadKind(tag));
    }
    for tag in 163u8..=166 {
        assert_eq!(decode_bootstrap_response(&[tag, 0, 0, 0, 1]).unwrap_err(), CodecError::BadKind(tag));
    }
    for request in [redeem(), confirm("x", VERIFIER, "http://127.0.0.1:5/callback")] {
        let bytes = encode_bootstrap_request(1, &request).unwrap();
        assert_eq!(decode_request(&bytes).unwrap_err(), CodecError::BadKind(bytes[0]));
        // A sign-in opening has no id: the tag alone is enough for the decoder to refuse it.
        assert!(decode_opening(&bytes[..1]).is_err());
    }
    assert!(decode_reply(&[167]).is_err());
}
