// T008: the email identity shared with the companion mail app. Expected values follow the rules in the doc comment of
// identity::normalize_email (RFC 5321 length limits, a conservative dot-atom local part).
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_accounts::Error;
use crewcraft_accounts::identity::normalize_email;

#[test]
fn trims_and_lowercases() {
    assert_eq!(normalize_email("  Ana.Lopez@Example.ORG \n").unwrap(), "ana.lopez@example.org");
    assert_eq!(normalize_email("X+Tag@Sub.Example.ORG").unwrap(), "x+tag@sub.example.org"); // sanitize-scan: allow (subdomains of example.*)
    assert_eq!(normalize_email("o'brien_1@mail-1.example.net").unwrap(), "o'brien_1@mail-1.example.net"); // sanitize-scan: allow (subdomains of example.*)
}

#[test]
fn same_person_typed_differently_is_one_identity() {
    let forms = ["bo@example.org", "BO@EXAMPLE.ORG", " Bo@Example.Org"];
    for f in forms {
        assert_eq!(normalize_email(f).unwrap(), "bo@example.org");
    }
}

#[test]
fn refuses_malformed_addresses() {
    for bad in [
        "", "   ", "plain", "@example.org", "ana@", "ana@@example.org", "ana@example@org", "ana@localhost",
        "a b@example.org", "ana@exa mple.org", ".ana@example.org", "ana.@example.org", "a..na@example.org",
        "ana@-example.org", "ana@example-.org", "ana@example..org", "ana@.example.org", "\"ana\"@example.org", // sanitize-scan: allow (deliberately malformed)
        "ana@[192.0.2.1]", "\u{e4}na@example.org", "ana@b\u{fc}cher.example", "ana@example.org\u{0}",
    ] {
        assert_eq!(normalize_email(bad), Err(Error::BadEmail), "{bad:?}");
    }
}

#[test]
fn length_limits() {
    let local64 = "a".repeat(64);
    assert!(normalize_email(&format!("{local64}@example.org")).is_ok());
    assert_eq!(normalize_email(&format!("{local64}b@example.org")), Err(Error::BadEmail));
    let label63 = "c".repeat(63);
    assert!(normalize_email(&format!("ana@{label63}.org")).is_ok());
    assert_eq!(normalize_email(&format!("ana@{label63}c.org")), Err(Error::BadEmail));
    let l = "d".repeat(61);
    let at_limit = format!("{l}.{l}.{l}.{l}.e.org"); // 4*61 + 5 dots + 1 + 3 = 253, the most allowed
    assert_eq!(at_limit.len(), 253);
    assert!(normalize_email(&format!("ana@{at_limit}")).is_ok());
    let over = format!("{l}.{l}.{l}.{l}.ex.org"); // 254
    assert_eq!(over.len(), 254);
    assert_eq!(normalize_email(&format!("ana@{over}")), Err(Error::BadEmail));
}
