use crewcraft_enroll::server_trust::RootFingerprint;

// The well-known SHA-256 vector for "abc". These bytes model the DER delivered to the adapter.
const CHECKSUM: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

#[test]
fn verifies_the_same_bytes_and_canonicalizes_hexadecimal_case() {
    let derived = RootFingerprint::from_der(b"abc");
    assert_eq!(derived.to_string(), CHECKSUM);
    assert_eq!(RootFingerprint::parse(CHECKSUM), Some(derived));
    assert_eq!(RootFingerprint::parse(&CHECKSUM.to_ascii_uppercase()), Some(derived));
    assert!(derived.matches(b"abc"));
    assert!(!derived.matches(b"abd"));
    assert!(!derived.matches(b"abc\n"));
}

#[test]
fn rejects_invalid_invitation_fingerprints() {
    assert_eq!(RootFingerprint::parse(""), None);
    assert_eq!(RootFingerprint::parse(&CHECKSUM[..63]), None);
    assert_eq!(RootFingerprint::parse(&format!("{CHECKSUM} ")), None);
    assert_eq!(RootFingerprint::parse(&CHECKSUM.replace('a', "g")), None);
    assert_eq!(RootFingerprint::parse(&format!("é{}", &CHECKSUM[2..])), None);
}
