#![allow(clippy::unwrap_used)]

use crewcraft_proto::websocket::{MAX_HEAD, Upgrade, UpgradeError, accept_key, head_len, parse_upgrade, upgrade_response};

const ORIGIN: &str = "https://chat.example.org";
/// RFC 6455 section 1.3's example key and the accept value it must give.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

fn head(lines: &[&str]) -> Vec<u8> {
    let mut s = lines.join("\r\n");
    s.push_str("\r\n\r\n");
    s.into_bytes()
}

fn good_lines() -> Vec<&'static str> {
    vec![
        "GET /live HTTP/1.1",
        "Host: chat.example.org",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version: 13",
    ]
}

#[test]
fn accept_key_matches_the_rfc_and_another_published_pair() {
    assert_eq!(accept_key(KEY), ACCEPT);
    // A second pair, computed independently with SHA-1 and base64 over key + GUID.
    assert_eq!(accept_key("x3JJHMbDL1EzLkh9GBhXDw=="), "HSmrc0sMlYUkAGmm5OPpG2HaGWk=");
}

#[test]
fn the_response_is_exact() {
    let expected = format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {ACCEPT}\r\n\r\n");
    assert_eq!(upgrade_response(KEY), expected.into_bytes());
}

#[test]
fn head_len_finds_the_end_of_the_head() {
    let h = head(&good_lines());
    assert_eq!(head_len(&h).unwrap(), Some(h.len()));
    // Bytes after the head (the first frame, say) are not part of it.
    let mut more = h.clone();
    more.extend_from_slice(&[0x81, 0x80]);
    assert_eq!(head_len(&more).unwrap(), Some(h.len()));
    // Not there yet.
    assert_eq!(head_len(&h[..h.len() - 1]).unwrap(), None);
    assert_eq!(head_len(b"").unwrap(), None);
    assert_eq!(head_len(b"GET / HTTP/1.1\r\n").unwrap(), None);
}

#[test]
fn head_len_limits_the_size() {
    // A head that ends exactly at MAX_HEAD is fine.
    let mut exact = b"GET / HTTP/1.1\r\nX: ".to_vec();
    while exact.len() < MAX_HEAD - 4 {
        exact.push(b'a');
    }
    exact.extend_from_slice(b"\r\n\r\n");
    assert_eq!(exact.len(), MAX_HEAD);
    assert_eq!(head_len(&exact).unwrap(), Some(MAX_HEAD));
    // MAX_HEAD bytes with no end in sight: refuse now, do not wait for more.
    let endless = vec![b'a'; MAX_HEAD];
    assert_eq!(head_len(&endless).unwrap_err(), UpgradeError::TooLarge);
    // Fewer than MAX_HEAD bytes with no end: keep reading.
    assert_eq!(head_len(&endless[..MAX_HEAD - 1]).unwrap(), None);
    // An end that arrives only after MAX_HEAD bytes does not count.
    let mut late = vec![b'a'; MAX_HEAD];
    late.extend_from_slice(b"\r\n\r\n");
    assert_eq!(head_len(&late).unwrap_err(), UpgradeError::TooLarge);
}

#[test]
fn a_good_request_is_accepted() {
    let up = parse_upgrade(&head(&good_lines()), ORIGIN).unwrap();
    assert_eq!(up, Upgrade { path: "/live".into(), key: KEY.into() });
}

#[test]
fn header_names_and_tokens_are_case_insensitive_and_values_trimmed() {
    let lines = vec![
        "GET /live HTTP/1.1",
        "host: chat.example.org",
        "UPGRADE:   WebSocket  ",
        "connection: keep-alive,\tUPGRADE",
        "sec-websocket-key:\tdGhlIHNhbXBsZSBub25jZQ== ",
        "SEC-WEBSOCKET-VERSION: 13",
    ];
    let up = parse_upgrade(&head(&lines), ORIGIN).unwrap();
    assert_eq!(up.key, KEY);
}

#[test]
fn origin_must_match_when_present_and_may_be_absent() {
    let mut with = good_lines();
    with.push("Origin: https://chat.example.org");
    assert!(parse_upgrade(&head(&with), ORIGIN).is_ok());

    for bad in [
        "Origin: https://evil.example.com",
        "Origin: https://chat.example.org:8443",
        "Origin: http://chat.example.org",
        "Origin: HTTPS://CHAT.EXAMPLE.ORG",
        "Origin: null",
        "Origin:",
    ] {
        let mut lines = good_lines();
        lines.push(bad);
        assert_eq!(parse_upgrade(&head(&lines), ORIGIN).unwrap_err(), UpgradeError::OriginRefused, "{bad}");
    }
    // Two Origin headers are refused even when both are right.
    let mut twice = good_lines();
    twice.push("Origin: https://chat.example.org");
    twice.push("Origin: https://chat.example.org");
    assert_eq!(parse_upgrade(&head(&twice), ORIGIN).unwrap_err(), UpgradeError::OriginRefused);
}

#[test]
fn request_line_errors() {
    let with_first = |first: &'static str| {
        let mut lines = good_lines();
        lines[0] = first;
        head(&lines)
    };
    assert_eq!(parse_upgrade(&with_first("POST /live HTTP/1.1"), ORIGIN).unwrap_err(), UpgradeError::NotGet);
    assert_eq!(parse_upgrade(&with_first("get /live HTTP/1.1"), ORIGIN).unwrap_err(), UpgradeError::NotGet);
    assert_eq!(parse_upgrade(&with_first("GET /live HTTP/1.0"), ORIGIN).unwrap_err(), UpgradeError::BadVersion);
    assert_eq!(parse_upgrade(&with_first("GET /live HTTP/2"), ORIGIN).unwrap_err(), UpgradeError::BadVersion);
    assert_eq!(parse_upgrade(&with_first("GET /live"), ORIGIN).unwrap_err(), UpgradeError::BadRequestLine);
    assert_eq!(parse_upgrade(&with_first("GET /live HTTP/1.1 extra"), ORIGIN).unwrap_err(), UpgradeError::BadRequestLine);
    assert_eq!(parse_upgrade(&with_first("GET live HTTP/1.1"), ORIGIN).unwrap_err(), UpgradeError::BadRequestLine);
    assert_eq!(parse_upgrade(&with_first(""), ORIGIN).unwrap_err(), UpgradeError::BadRequestLine);
}

#[test]
fn missing_or_wrong_upgrade_and_connection() {
    let without = |name: &str| -> Vec<u8> {
        let lines: Vec<&str> = good_lines().into_iter().filter(|l| !l.to_ascii_lowercase().starts_with(name)).collect();
        head(&lines)
    };
    assert_eq!(parse_upgrade(&without("upgrade:"), ORIGIN).unwrap_err(), UpgradeError::MissingUpgrade);
    assert_eq!(parse_upgrade(&without("connection:"), ORIGIN).unwrap_err(), UpgradeError::MissingConnection);

    let mut lines = good_lines();
    lines[2] = "Upgrade: h2c";
    assert_eq!(parse_upgrade(&head(&lines), ORIGIN).unwrap_err(), UpgradeError::MissingUpgrade);
    let mut lines = good_lines();
    lines[3] = "Connection: keep-alive";
    assert_eq!(parse_upgrade(&head(&lines), ORIGIN).unwrap_err(), UpgradeError::MissingConnection);
    // A token that merely contains the word does not count.
    let mut lines = good_lines();
    lines[2] = "Upgrade: websocketx";
    assert_eq!(parse_upgrade(&head(&lines), ORIGIN).unwrap_err(), UpgradeError::MissingUpgrade);
}

#[test]
fn version_and_key_rules() {
    let mut lines = good_lines();
    lines[5] = "Sec-WebSocket-Version: 8";
    assert_eq!(parse_upgrade(&head(&lines), ORIGIN).unwrap_err(), UpgradeError::BadWsVersion);
    lines.pop();
    assert_eq!(parse_upgrade(&head(&lines), ORIGIN).unwrap_err(), UpgradeError::BadWsVersion);

    // Missing, wrong length, not base64, and repeated keys.
    let mut lines = good_lines();
    lines.remove(4);
    assert_eq!(parse_upgrade(&head(&lines), ORIGIN).unwrap_err(), UpgradeError::BadKey);
    for bad in [
        "Sec-WebSocket-Key: dGhlIHNhbXBsZQ==",
        "Sec-WebSocket-Key: not base64 at all!!",
        "Sec-WebSocket-Key: ",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==AAAA",
    ] {
        let mut lines = good_lines();
        lines[4] = bad;
        assert_eq!(parse_upgrade(&head(&lines), ORIGIN).unwrap_err(), UpgradeError::BadKey, "{bad}");
    }
    let mut twice = good_lines();
    twice.push("Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==");
    assert_eq!(parse_upgrade(&head(&twice), ORIGIN).unwrap_err(), UpgradeError::BadKey);
}

#[test]
fn malformed_headers() {
    let mut lines = good_lines();
    lines.insert(2, "this line has no colon");
    assert_eq!(parse_upgrade(&head(&lines), ORIGIN).unwrap_err(), UpgradeError::BadHeader);
    // Obsolete line folding is refused.
    let mut lines = good_lines();
    lines.insert(2, " folded: continuation");
    assert_eq!(parse_upgrade(&head(&lines), ORIGIN).unwrap_err(), UpgradeError::BadHeader);
    // Not UTF-8.
    let mut bytes = head(&good_lines());
    bytes.insert(20, 0xFF);
    bytes.insert(21, 0xFE);
    assert_eq!(parse_upgrade(&bytes, ORIGIN).unwrap_err(), UpgradeError::BadHeader);
    // Too long.
    let mut bytes = head(&good_lines());
    let tail = bytes.split_off(bytes.len() - 4);
    bytes.extend(vec![b'a'; MAX_HEAD]);
    bytes.extend(tail);
    assert_eq!(parse_upgrade(&bytes, ORIGIN).unwrap_err(), UpgradeError::TooLarge);
}
