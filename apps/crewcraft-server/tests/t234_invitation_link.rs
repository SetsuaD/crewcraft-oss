//! One invitation-link type for the server that writes a link and the client that opens it. Task T234.
#![allow(clippy::unwrap_used)]

use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::invitation::{InvitationLink, LinkError, MAX_LINK, PREFIX, write_link};
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_server::server_install::{self, ServerConfig};
use crewcraft_server::server_name::ServerName;

fn code() -> EnrollmentCode {
    EnrollmentCode::from_bytes([7; 20])
}

fn pin() -> RootFingerprint {
    RootFingerprint::from_der(b"synthetic root certificate bytes")
}

/// A well-formed link with each value given as written in the query.
fn link(server: &str, code: &str, root: &str) -> String {
    format!("{PREFIX}server={server}&code={code}&root_sha256={root}")
}

fn good() -> (String, String) {
    (code().to_display(), pin().to_string())
}

#[test]
fn a_link_round_trips_through_its_text() {
    let (code_text, root) = good();
    let made = InvitationLink::new("chat.example.org:7443", code(), pin()).unwrap();
    let text = made.to_string();
    assert_eq!(text, link("chat.example.org:7443", &code_text, &root));
    let parsed = InvitationLink::parse(&text).unwrap();
    assert_eq!(parsed, made);
    assert_eq!(parsed.server(), "chat.example.org:7443");
    assert_eq!(parsed.server_name(), "chat.example.org");
    assert_eq!(parsed.port(), 7443);
    assert_eq!(parsed.code().as_bytes(), code().as_bytes());
    assert_eq!(parsed.root_sha256(), pin());
    assert_eq!(parsed.to_string(), text);

    // IPv6 is written in brackets, percent-encoded in the query; the certificate name has no brackets.
    let v6 = InvitationLink::new("[2001:db8::1]:8443", code(), pin()).unwrap();
    assert_eq!(v6.to_string(), link("%5B2001:db8::1%5D:8443", &code_text, &root));
    let parsed = InvitationLink::parse(&v6.to_string()).unwrap();
    assert_eq!((parsed.server(), parsed.server_name(), parsed.port()), ("[2001:db8::1]:8443".into(), "2001:db8::1".into(), 8443));

    let v4 = InvitationLink::parse(&link("192.0.2.10:443", &code_text, &root)).unwrap();
    assert_eq!((v4.server(), v4.server_name()), ("192.0.2.10:443".into(), "192.0.2.10".into()));

    // Parameters in any order; a DNS name and the fingerprint in any case; a code as a person might retype it.
    let typed = code_text.to_lowercase().replace('-', "%20");
    let loose = format!("{PREFIX}root_sha256={}&code={typed}&server=Chat.Example.ORG:7443", root.to_uppercase());
    assert_eq!(InvitationLink::parse(&loose).unwrap(), made);
    // The most a link may be is accepted.
    assert!(InvitationLink::parse(&text).is_ok() && text.len() <= MAX_LINK);
}

#[test]
fn the_link_never_prints_its_code_in_debug() {
    let made = InvitationLink::new("chat.example.org:7443", code(), pin()).unwrap();
    let debug = format!("{made:?}");
    assert!(debug.contains("chat.example.org:7443"));
    assert!(!debug.contains(&code().to_display()));
    assert!(!debug.contains(&code().to_display()[4..8]));
}

#[test]
fn every_malformed_link_is_refused() {
    let (code_text, root) = good();
    let ok_server = "chat.example.org:7443";
    let mut wrong_check = code_text.clone();
    let last = wrong_check.pop().unwrap();
    wrong_check.push(if last == '0' { '1' } else { '0' });
    let cases: Vec<(String, LinkError)> = vec![
        (String::new(), LinkError::Length),
        (format!("{}{}", link(ok_server, &code_text, &root), "&".repeat(MAX_LINK)), LinkError::Length),
        // The scheme and path are exact.
        (link(ok_server, &code_text, &root).replacen("crewcraft://", "CrewCraft://", 1), LinkError::Prefix),
        (link(ok_server, &code_text, &root).replacen("enroll?", "Enroll?", 1), LinkError::Prefix),
        (link(ok_server, &code_text, &root).replacen("enroll?", "enroll/?", 1), LinkError::Prefix),
        (link(ok_server, &code_text, &root).replacen("crewcraft://", "https://", 1), LinkError::Prefix),
        (link(ok_server, &code_text, &root).replacen("://", ":", 1), LinkError::Prefix),
        (format!(" {}", link(ok_server, &code_text, &root)), LinkError::Prefix),
        (format!("{}#top", link(ok_server, &code_text, &root)), LinkError::Prefix),
        // Each parameter exactly once, and nothing else.
        (format!("{PREFIX}code={code_text}&root_sha256={root}"), LinkError::Parameter),
        (format!("{PREFIX}server={ok_server}&root_sha256={root}"), LinkError::Parameter),
        (format!("{PREFIX}server={ok_server}&code={code_text}"), LinkError::Parameter),
        (format!("{}&server={ok_server}", link(ok_server, &code_text, &root)), LinkError::Parameter),
        (format!("{}&code={code_text}", link(ok_server, &code_text, &root)), LinkError::Parameter),
        (format!("{}&root_sha256={root}", link(ok_server, &code_text, &root)), LinkError::Parameter),
        (format!("{}&extra=1", link(ok_server, &code_text, &root)), LinkError::Parameter),
        (format!("{}&", link(ok_server, &code_text, &root)), LinkError::Parameter),
        (link(ok_server, &code_text, &root).replacen("&code", "&&code", 1), LinkError::Parameter),
        (link(ok_server, &code_text, &root).replacen("server=", "server", 1), LinkError::Parameter),
        (link("", &code_text, &root), LinkError::Parameter),
        (link(ok_server, &code_text, &root).replacen("server=", "%73erver=", 1), LinkError::Parameter),
        (PREFIX.to_owned(), LinkError::Parameter),
        // Values hold only query-safe characters and well-formed escapes.
        (link("chat.example.org%3", &code_text, &root), LinkError::Encoding),
        (link("chat.example.org%zz443", &code_text, &root), LinkError::Encoding),
        (link("[2001:db8::1]:443", &code_text, &root), LinkError::Encoding),
        (link("chat.example.org:7443+", &code_text, &root), LinkError::Encoding),
        (link("chat.example.org%3A%FF", &code_text, &root), LinkError::Encoding),
        (link("user@example.org:443", &code_text, &root), LinkError::Encoding),
        (link(ok_server, &format!("{code_text}%20x y"), &root), LinkError::Encoding),
        // The server is host:port.
        (link("chat.example.org", &code_text, &root), LinkError::Server),
        (link("chat.example.org:", &code_text, &root), LinkError::Server),
        (link("chat.example.org:0", &code_text, &root), LinkError::Server),
        (link("chat.example.org:07443", &code_text, &root), LinkError::Server),
        (link("chat.example.org:65536", &code_text, &root), LinkError::Server),
        (link("chat.example.org:1234567", &code_text, &root), LinkError::Server),
        (link("chat.example.org%2B443", &code_text, &root), LinkError::Server),
        (link("chat.example.org:%2B443", &code_text, &root), LinkError::Server),
        (link(":7443", &code_text, &root), LinkError::Server),
        (link("2001:db8::1:443", &code_text, &root), LinkError::Server),
        (link("%5B192.0.2.10%5D:443", &code_text, &root), LinkError::Server),
        (link("%5B2001:db8::1:443", &code_text, &root), LinkError::Server),
        (link("0.0.0.0:443", &code_text, &root), LinkError::Server),
        (link("%5B::%5D:443", &code_text, &root), LinkError::Server),
        (link("%5Bff02::1%5D:443", &code_text, &root), LinkError::Server),
        (link("192.0.2:443", &code_text, &root), LinkError::Server),
        (link("chat..example.org:443", &code_text, &root), LinkError::Server),
        (link("-chat.example.org:443", &code_text, &root), LinkError::Server),
        (link("chat_1.example.org:443", &code_text, &root), LinkError::Server),
        (link("%2A.example.org:443", &code_text, &root), LinkError::Server),
        (link("chat%20example.org:443", &code_text, &root), LinkError::Server),
        (link("user%40example.org:443", &code_text, &root), LinkError::Server),
        (link("ch%C3%A4t.example.org:443", &code_text, &root), LinkError::Server),
        (link(&format!("{}.example.org:443", "a".repeat(64)), &code_text, &root), LinkError::Server),
        // The code is an enrollment code, and the fingerprint 64 hexadecimal digits.
        (link(ok_server, &wrong_check, &root), LinkError::Code),
        (link(ok_server, &code_text.replacen("CC1", "CC2", 1), &root), LinkError::Code),
        (link(ok_server, &code_text[..code_text.len() - 2], &root), LinkError::Code),
        (link(ok_server, &format!("{code_text}{}", "-".repeat(200)), &root), LinkError::Code),
        (link(ok_server, &code_text, &root[..63]), LinkError::Fingerprint),
        (link(ok_server, &code_text, &format!("{root}0")), LinkError::Fingerprint),
        (link(ok_server, &code_text, &format!("{}g", &root[..63])), LinkError::Fingerprint),
        (link(ok_server, &code_text, &format!("{}%20", &root[..62])), LinkError::Fingerprint),
    ];
    for (text, expected) in cases {
        assert_eq!(InvitationLink::parse(&text), Err(expected), "{text:?}");
    }
    // `new` checks the server the same way.
    for server in ["chat.example.org", "2001:db8::1:443", "0.0.0.0:443", "chat.example.org:0"] {
        assert_eq!(InvitationLink::new(server, code(), pin()), Err(LinkError::Server), "{server:?}");
    }
}

#[test]
fn a_link_from_the_servers_writer_parses_to_what_it_was_given() {
    let pin_bytes = [0xab; 32];
    let fingerprint = RootFingerprint::from_bytes(pin_bytes);
    for (name, listen) in [("chat.example.org", "0.0.0.0:7443"), ("2001:db8::1", "[::]:8443"), ("192.0.2.10", "0.0.0.0:443")] {
        let config = ServerConfig { name: ServerName::parse(name).unwrap(), listen: listen.parse().unwrap() };
        let server = config.public_server();
        let written = server_install::enrollment_link(&server, &code().to_display(), &pin_bytes);
        assert_eq!(written, write_link(&server, &code().to_display(), fingerprint));
        let parsed = InvitationLink::parse(&written).unwrap();
        assert_eq!(parsed.server(), server);
        assert_eq!(parsed.server_name(), config.name.certificate_name());
        assert_eq!(parsed.port(), config.listen.port());
        assert_eq!(parsed.code().as_bytes(), code().as_bytes());
        assert_eq!(parsed.root_sha256(), fingerprint);
        assert_eq!(parsed.to_string(), written);
        assert_eq!(server_install::invitation(&server, &code().to_display(), &pin_bytes).unwrap(), parsed);
    }
    assert_eq!(server_install::invitation("chat.example.org", &code().to_display(), &pin_bytes), Err(LinkError::Server));
    assert_eq!(server_install::invitation("chat.example.org:7443", "CC1-not-a-code", &pin_bytes), Err(LinkError::Code));
}
