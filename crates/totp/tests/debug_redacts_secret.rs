//! A TOTP secret must never appear in Debug output (docs/SECURITY-DESIGN.md: secrets print as `..`).
use crewcraft_totp::{Algorithm, Totp};

#[test]
fn debug_output_hides_the_secret() {
    let secret = b"12345678901234567890".to_vec();
    let totp = Totp::new(secret.clone(), Algorithm::Sha1, 6, 30).expect("valid parameters");
    let shown = format!("{totp:?}");
    assert!(shown.contains("secret: .."), "{shown}");
    assert!(!shown.contains("12345678901234567890"), "{shown}");
    assert!(!shown.contains(&format!("{secret:?}")), "{shown}");
    assert!(!shown.contains("49, 50, 51"), "{shown}");
}
