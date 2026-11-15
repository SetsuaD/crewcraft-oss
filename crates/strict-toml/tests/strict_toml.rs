// The strict TOML subset: what it accepts, and that everything else is refused with its line number.
use crewcraft_strict_toml::{Error, Value, parse};

const MAX: usize = 64 * 1024;

#[test]
fn reads_sections_strings_numbers_and_comments() {
    let doc = parse(
        "# a comment\n\n[theme]\nname = \"Night \\\"owl\\\" \\\\ 1\"  # trailing comment\nsize = 14\n[colors.light]\ntext = \"#000000\"\n",
        MAX,
    )
    .unwrap();
    let theme = doc.require("theme").unwrap();
    assert_eq!(theme.line, 3);
    assert_eq!(theme.req_str("theme", "name").unwrap(), ("Night \"owl\" \\ 1", 4));
    assert_eq!(theme.req_int("theme", "size").unwrap(), (14, 5));
    let colors = doc.require("colors.light").unwrap();
    assert_eq!(colors.entries.get("text").unwrap().value, Value::Str("#000000".into()));
}

#[test]
fn refuses_with_line_numbers() {
    let cases: &[(&str, usize)] = &[
        ("[a]\nkey value\n", 2),
        ("[a]\nkey = 'single'\n", 2),
        ("[a]\nkey = [1, 2]\n", 2),
        ("[a]\nkey = 1.5\n", 2),
        ("[a]\nkey = 007\n", 2),
        ("[a]\nkey = \"open\n", 2),
        ("[a]\nkey = \"bad \\n escape\"\n", 2),
        ("[a]\nkey = \"x\" extra\n", 2),
        ("[a]\nKey = 1\n", 2),
        ("[a]\na.b = 1\n", 2),
        ("[A]\n", 1),
        ("[a\n", 1),
        ("[a] junk\n", 1),
        ("key = 1\n", 1),
        ("[a]\nkey = 1234567890123456789\n", 2),
    ];
    for (text, line) in cases {
        match parse(text, MAX) {
            Err(Error::Syntax { line: got, .. }) => assert_eq!(got, *line, "{text:?}"),
            other => panic!("{text:?} gave {other:?}"),
        }
    }
}

#[test]
fn refuses_duplicates() {
    assert_eq!(parse("[a]\nk = 1\n[b]\n[a]\n", MAX).unwrap_err(), Error::DuplicateSection { line: 4, section: "a".into() });
    assert_eq!(parse("[a]\nk = 1\nk = 2\n", MAX).unwrap_err(), Error::DuplicateKey { line: 3, key: "k".into() });
}

#[test]
fn refuses_large_files() {
    let text = format!("[a]\nk = \"{}\"\n", "x".repeat(100));
    assert!(matches!(parse(&text, 50), Err(Error::TooLarge { max: 50, .. })));
}

#[test]
fn control_characters_in_strings_are_refused() {
    assert!(matches!(parse("[a]\nk = \"tab\there\"\n", MAX), Err(Error::Syntax { line: 2, .. })));
}

#[test]
fn schema_helpers() {
    let doc = parse("[theme]\nname = \"x\"\nsize = \"14\"\nextra = 1\n[weird]\n", MAX).unwrap();
    assert_eq!(doc.check_sections(&["theme"], &["colors."]).unwrap_err(), Error::UnknownSection { line: 5, section: "weird".into() });
    let theme = doc.require("theme").unwrap();
    assert_eq!(
        theme.check_keys("theme", &["name", "size"]).unwrap_err(),
        Error::UnknownKey { line: 4, section: "theme".into(), key: "extra".into() }
    );
    assert!(matches!(theme.req_int("theme", "size"), Err(Error::BadValue { line: 3, .. })));
    assert!(matches!(theme.req_int("theme", "name"), Err(Error::BadValue { line: 2, .. })));
    assert_eq!(theme.opt_str("missing").unwrap(), None);
    assert_eq!(theme.req_str("theme", "missing").unwrap_err(), Error::MissingKey { section: "theme".into(), key: "missing".into() });
    assert_eq!(doc.require("nope").unwrap_err(), Error::MissingSection { section: "nope".into() });
}

#[test]
fn every_error_has_a_readable_message() {
    let e = parse("[a]\nk = 1\nk = 2\n", MAX).unwrap_err();
    assert_eq!(e.to_string(), "line 3: key `k` appears twice in its section");
}
