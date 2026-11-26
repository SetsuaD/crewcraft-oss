//! T611a: the wire format for signing in through an external OpenID Connect provider (docs/SECURITY-DESIGN.md
//! section 9): `BeginExternal` (tag 37), its `ExternalStart` answer (tag 166), and `FinishExternal` (tag 38). Exact
//! bytes, round trips, every truncation, bad shapes, and `Debug` that never shows a code, verifier or nonce.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_proto::message::CodecError;
use crewcraft_proto::signin::{MAX_REDIRECT_BYTES, MAX_VERIFIER_LEN, Opening, Reply, decode_opening, decode_reply, encode_opening, encode_reply};

const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const NONCE: &str = "__________________________________________8";
const REDIRECT: &str = "http://127.0.0.1:51234/cb";

fn finish_bytes() -> Vec<u8> {
    let mut out = vec![38, 0, 3];
    out.extend_from_slice(b"abc");
    out.extend_from_slice(&[0, 43]);
    out.extend_from_slice(VERIFIER.as_bytes());
    out.extend_from_slice(&[0, 25]);
    out.extend_from_slice(REDIRECT.as_bytes());
    out
}

fn start_bytes() -> Vec<u8> {
    let mut out = vec![166];
    for field in ["https://id.example.org/", "chat", "https://id.example.org/authorize/", NONCE] {
        out.extend_from_slice(&(field.len() as u16).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

fn start() -> Reply<'static> {
    Reply::ExternalStart {
        issuer: "https://id.example.org/",
        client_id: "chat",
        authorization_endpoint: "https://id.example.org/authorize/",
        nonce: NONCE,
    }
}

#[test]
fn begin_is_one_byte_and_takes_nothing_more() {
    assert_eq!(encode_opening(&Opening::BeginExternal).unwrap(), [37]);
    assert_eq!(decode_opening(&[37]).unwrap(), Opening::BeginExternal);
    assert_eq!(decode_opening(&[37, 0]), Err(CodecError::TrailingBytes));
}

#[test]
fn finish_has_exact_bytes_and_round_trips() {
    let finish = Opening::FinishExternal { code: "abc", verifier: VERIFIER, redirect_uri: REDIRECT };
    assert_eq!(encode_opening(&finish).unwrap(), finish_bytes());
    assert_eq!(decode_opening(&finish_bytes()).unwrap(), finish);
    for end in 1..finish_bytes().len() {
        assert!(decode_opening(&finish_bytes()[..end]).is_err(), "prefix of {end} bytes");
    }
    let mut extra = finish_bytes();
    extra.push(0);
    assert_eq!(decode_opening(&extra), Err(CodecError::TrailingBytes));
}

#[test]
fn finish_refuses_bad_shapes_both_ways() {
    let long_verifier = "a".repeat(MAX_VERIFIER_LEN + 1);
    let long_redirect = format!("http://127.0.0.1:1/{}", "a".repeat(MAX_REDIRECT_BYTES));
    let bad = [
        ("", VERIFIER, REDIRECT),
        ("a b", VERIFIER, REDIRECT),
        ("abc", &VERIFIER[..42], REDIRECT),
        ("abc", long_verifier.as_str(), REDIRECT),
        ("abc", "dBjftJeZ4CVP+mB92K27uhbUJU1p1r/wW1gFWFOEjXk", REDIRECT),
        ("abc", VERIFIER, ""),
        ("abc", VERIFIER, long_redirect.as_str()),
        ("abc", VERIFIER, "http://127.0.0.1:1/\u{e9}"),
    ];
    for (code, verifier, redirect_uri) in bad {
        let opening = Opening::FinishExternal { code, verifier, redirect_uri };
        assert_eq!(encode_opening(&opening), Err(CodecError::FieldLength), "{code:?} {verifier:?} {redirect_uri:?}");
    }
    // The same shapes arriving from a peer are refused on decode too.
    let mut plus = finish_bytes();
    let at = 1 + 2 + 3 + 2 + 12;
    plus[at] = b'+';
    assert_eq!(decode_opening(&plus), Err(CodecError::FieldLength));
}

#[test]
fn external_start_has_exact_bytes_and_round_trips() {
    assert_eq!(encode_reply(&start()).unwrap(), start_bytes());
    assert_eq!(decode_reply(&start_bytes()).unwrap(), start());
    for end in 1..start_bytes().len() {
        assert!(decode_reply(&start_bytes()[..end]).is_err(), "prefix of {end} bytes");
    }
    let bad_nonce = Reply::ExternalStart { issuer: "https://id.example.org/", client_id: "chat", authorization_endpoint: "x", nonce: "short" };
    assert_eq!(encode_reply(&bad_nonce), Err(CodecError::FieldLength));
    let empty_client = Reply::ExternalStart { issuer: "https://id.example.org/", client_id: "", authorization_endpoint: "x", nonce: NONCE };
    assert_eq!(encode_reply(&empty_client), Err(CodecError::FieldLength));
}

#[test]
fn debug_never_shows_a_code_verifier_or_nonce() {
    let finish = Opening::FinishExternal { code: "CODEMARKER", verifier: VERIFIER, redirect_uri: REDIRECT };
    let shown = format!("{finish:?}");
    assert!(!shown.contains("CODEMARKER") && !shown.contains(VERIFIER), "{shown}");
    assert!(shown.contains(REDIRECT));
    let shown = format!("{:?}", start());
    assert!(!shown.contains(NONCE) && shown.contains("https://id.example.org/"), "{shown}");
    assert_eq!(format!("{:?}", Opening::BeginExternal), "BeginExternal");
}
