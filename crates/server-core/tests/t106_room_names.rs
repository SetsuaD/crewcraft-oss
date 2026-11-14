// T106: room display-name validation and URL slugs.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_server_core::room_name::{NameError, slug, validate};

#[test]
fn validate_trims_and_collapses_whitespace() {
    assert_eq!(validate("  Team   Chat "), Ok("Team Chat".to_string()));
    assert_eq!(validate("Général\u{00A0}\u{3000}Chat"), Ok("Général Chat".to_string()));
}

#[test]
fn validate_rejects() {
    assert_eq!(validate(""), Err(NameError::Empty));
    assert_eq!(validate("   "), Err(NameError::Empty));
    assert_eq!(validate("a\tb"), Err(NameError::ControlCharacter));
    assert_eq!(validate("a\u{7}"), Err(NameError::ControlCharacter));
}

#[test]
fn the_limit_is_64_characters_not_bytes() {
    let e = "é".repeat(64);
    assert_eq!(validate(&e), Ok(e.clone()));
    assert_eq!(validate(&"é".repeat(65)), Err(NameError::TooLong));
    assert_eq!(validate(&format!("  {}  ", "a".repeat(64))).map(|s| s.len()), Ok(64));
}

#[test]
fn slugs() {
    assert_eq!(slug("Team Chat"), "team-chat");
    assert_eq!(slug("  Général -- Chat!! "), "g-n-ral-chat");
    assert_eq!(slug("Q3 2026 Plans"), "q3-2026-plans");
    assert_eq!(slug("日本"), "room");
    assert_eq!(slug("--"), "room");
}

#[test]
fn a_slug_is_cut_at_48_without_a_trailing_dash() {
    assert_eq!(slug(&format!("{} {}", "a".repeat(47), "bbbb")), "a".repeat(47));
    assert_eq!(slug(&"x".repeat(60)).len(), 48);
}
