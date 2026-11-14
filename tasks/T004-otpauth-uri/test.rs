// T004: the otpauth:// URI (Key Uri Format) that authenticator apps scan as a QR code.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_totp::{Algorithm, Totp};

#[test]
fn default_uri() {
    let t = Totp::with_defaults(b"12345678901234567890".to_vec()).unwrap();
    assert_eq!(
        t.otpauth_uri("Crew Craft", "ana@example.org"),
        "otpauth://totp/Crew%20Craft:ana%40example.org?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Crew%20Craft&algorithm=SHA1&digits=6&period=30"
    );
}

#[test]
fn uri_carries_non_default_parameters() {
    let t = Totp::new(b"12345678901234567890".to_vec(), Algorithm::Sha256, 8, 60).unwrap();
    let uri = t.otpauth_uri("Acme", "bo");
    assert!(uri.starts_with("otpauth://totp/Acme:bo?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&"), "{uri}");
    assert!(uri.ends_with("&issuer=Acme&algorithm=SHA256&digits=8&period=60"), "{uri}");
}

#[test]
fn reserved_characters_are_percent_encoded() {
    let t = Totp::with_defaults(b"12345678901234567890".to_vec()).unwrap();
    let uri = t.otpauth_uri("A&B:C", "x/y?z");
    assert!(uri.starts_with("otpauth://totp/A%26B%3AC:x%2Fy%3Fz?"), "{uri}");
    assert!(uri.contains("&issuer=A%26B%3AC&"), "{uri}");
}
