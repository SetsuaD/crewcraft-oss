// Themes and theme addons (REQUIREMENTS 2.19).
#![allow(clippy::unwrap_used, clippy::panic)] // helper functions outside #[test] unwrap too
use crewcraft_strict_toml::Error as TomlError;
use crewcraft_theme::{
    AddonError, Audience, BUILTIN, COLOR_TOKENS, Color, DEFAULT_THEME_ID, Density, Installed, LoadError, Variant, available, builtin_themes,
    contrast_ratio, load, load_addon, parse, resolve, sha256_hex, verify_delivery,
};

/// The default built-in theme's text with its id, name and accent replaced, for building test themes.
fn variant_of(id: &str, accent_light: &str) -> String {
    let base = BUILTIN.iter().find(|(i, _)| *i == DEFAULT_THEME_ID).unwrap().1;
    base.replacen("id = \"crewcraft\"", &format!("id = \"{id}\""), 1).replacen("name = \"CrewCraft\"", "name = \"Test\"", 1).replacen(
        "accent = \"#2b7a89\"",
        &format!("accent = \"{accent_light}\""),
        1,
    )
}

fn light_only(text: &str) -> String {
    match text.find("[colors.dark]") {
        Some(i) => text[..i].to_string(),
        None => text.to_string(),
    }
}

#[test]
fn contrast_ratio_matches_wcag() {
    let black = Color::parse_hex("#000000").unwrap();
    let white = Color::parse_hex("#FFFFFF").unwrap();
    assert!((contrast_ratio(black, white) - 21.0).abs() < 1e-9);
    assert!((contrast_ratio(white, black) - 21.0).abs() < 1e-9);
    assert!((contrast_ratio(white, white) - 1.0).abs() < 1e-9);
    // #767676 on white is the classic 4.54:1 example.
    let grey = Color::parse_hex("#767676").unwrap();
    assert!((contrast_ratio(grey, white) - 4.54).abs() < 0.01);
}

#[test]
fn hex_colours() {
    assert_eq!(Color::parse_hex("#1A2b3C"), Some(Color { r: 0x1a, g: 0x2b, b: 0x3c }));
    assert_eq!(Color::parse_hex("#1a2b3c").unwrap().to_hex(), "#1a2b3c");
    for bad in ["1a2b3c", "#1a2b3", "#1a2b3c4", "#1a2b3g", "#+1a2b3", ""] {
        assert_eq!(Color::parse_hex(bad), None, "{bad}");
    }
}

#[test]
fn builtin_themes_load_and_pass_contrast() {
    for (id, text) in BUILTIN {
        let theme = load(text).unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(theme.id, *id);
        assert!(theme.has_dark(), "{id} has light and dark");
        for token in COLOR_TOKENS {
            assert!(theme.palette(Variant::Light).get(token).is_some());
            assert!(theme.palette(Variant::Dark).get(token).is_some());
        }
    }
    assert_eq!(builtin_themes().len(), BUILTIN.len());
}

#[test]
fn reads_metadata_type_and_shape() {
    let theme = parse(BUILTIN[0].1).unwrap();
    assert_eq!(theme.name, "CrewCraft");
    assert_eq!(theme.version, "1.0.0");
    assert_eq!(theme.density, Density::Comfortable);
    assert_eq!(theme.typography.font, "system");
    assert_eq!((theme.typography.size_small, theme.typography.size_body, theme.typography.size_title), (12, 14, 20));
    assert_eq!((theme.shape.radius_s, theme.shape.radius_m, theme.shape.radius_l), (4, 6, 8));
    assert_eq!(theme.palette(Variant::Light).get("accent"), Color::parse_hex("#2b7a89"));
    assert_eq!(theme.palette(Variant::Dark).get("accent"), Color::parse_hex("#5cc0d1"));
}

#[test]
fn type_and_shape_have_defaults() {
    let text = variant_of("minimal", "#2b7a89");
    let start = text.find("[type]").unwrap();
    let end = text.find("[colors.light]").unwrap();
    let minimal = format!("{}{}", &text[..start], &text[end..]);
    let theme = load(&minimal).unwrap();
    assert_eq!(theme.typography.font, "system");
    assert_eq!(theme.typography.size_body, 14);
    assert_eq!(theme.shape.radius_m, 6);
}

#[test]
fn light_only_theme_uses_light_for_dark() {
    let theme = load(&light_only(&variant_of("light-only", "#2b7a89"))).unwrap();
    assert!(!theme.has_dark());
    assert_eq!(theme.palette(Variant::Dark), theme.palette(Variant::Light));
}

#[test]
fn low_contrast_is_refused_with_every_finding() {
    // A pale accent fails against the canvas (controls need 3:1) and white text on it fails (text needs 4.5:1).
    let text = variant_of("pale", "#b8e0e8");
    match load(&text) {
        Err(LoadError::Contrast(findings)) => {
            let pairs: Vec<(&str, &str)> = findings.iter().map(|f| (f.foreground, f.background)).collect();
            assert!(pairs.contains(&("accent", "bg-canvas")), "{pairs:?}");
            assert!(pairs.contains(&("on-accent", "accent")), "{pairs:?}");
            assert!(findings.iter().all(|f| f.variant == Variant::Light && f.ratio < f.required));
            let message = LoadError::Contrast(findings).to_string();
            assert!(message.contains("light: accent on bg-canvas is"), "{message}");
        }
        other => panic!("expected contrast findings, got {other:?}"),
    }
    // parse() alone checks only the format.
    assert!(parse(&text).is_ok());
}

#[test]
fn format_errors_name_the_line() {
    let base = variant_of("broken", "#2b7a89");
    let line_of = |text: &str, needle: &str| text.lines().position(|l| l.starts_with(needle)).unwrap() + 1;

    let typo = base.replacen("text-muted = ", "text-mutted = ", 1);
    let line = line_of(&typo, "text-mutted");
    assert!(matches!(parse(&typo), Err(TomlError::UnknownKey { line: l, .. }) if l == line));

    let missing = base.replacen("link = \"#1f6a78\"\n", "", 1);
    assert_eq!(parse(&missing).unwrap_err(), TomlError::MissingKey { section: "colors.light".into(), key: "link".into() });

    let bad_colour = base.replacen("text = \"#1d2327\"", "text = \"black\"", 1);
    let line = line_of(&bad_colour, "text = \"black\"");
    assert!(matches!(parse(&bad_colour), Err(TomlError::BadValue { line: l, .. }) if l == line));

    let extra_section = format!("{base}\n[colors.sepia]\n");
    assert!(matches!(parse(&extra_section), Err(TomlError::UnknownSection { .. })));

    let future = base.replacen("api = 1", "api = 2", 1);
    assert!(matches!(parse(&future), Err(TomlError::BadValue { .. })));

    let bad_id = base.replacen("id = \"broken\"", "id = \"Bad Id\"", 1);
    assert!(matches!(parse(&bad_id), Err(TomlError::BadValue { .. })));

    let bad_version = base.replacen("version = \"1.0.0\"", "version = \"1.0\"", 1);
    assert!(matches!(parse(&bad_version), Err(TomlError::BadValue { .. })));

    let shrinking = base.replacen("size-title = 20", "size-title = 14", 1).replacen("size-body = 14", "size-body = 16", 1);
    assert!(matches!(parse(&shrinking), Err(TomlError::BadValue { .. })));

    let huge_radius = base.replacen("radius-l = 8", "radius-l = 99", 1);
    assert!(matches!(parse(&huge_radius), Err(TomlError::BadValue { .. })));

    let no_light = base.replacen("[colors.light]", "[colors.dark-not]", 1);
    assert!(parse(&no_light).is_err());
}

#[test]
fn addons_carry_their_hash_and_refuse_builtin_ids() {
    let text = variant_of("acme", "#2b7a89");
    let addon = load_addon(text.as_bytes()).unwrap();
    assert_eq!(addon.theme.id, "acme");
    assert_eq!(addon.sha256, sha256_hex(text.as_bytes()));
    assert_eq!(addon.sha256.len(), 64);

    let builtin = BUILTIN[0].1.as_bytes();
    assert_eq!(load_addon(builtin).unwrap_err(), AddonError::ReservedId(DEFAULT_THEME_ID.into()));

    assert_eq!(load_addon(&[0xff, 0xfe, 0x00]).unwrap_err(), AddonError::NotUtf8);
    let big = vec![b'#'; crewcraft_theme::MAX_THEME_BYTES + 1];
    assert!(matches!(load_addon(&big), Err(AddonError::TooLarge { .. })));
}

#[test]
fn clients_apply_only_the_bytes_the_server_announced() {
    let text = variant_of("acme", "#2b7a89");
    let announced = sha256_hex(text.as_bytes());
    assert_eq!(verify_delivery(text.as_bytes(), &announced).unwrap().theme.id, "acme");
    assert_eq!(verify_delivery(text.as_bytes(), &announced.to_uppercase()).unwrap().sha256, announced);

    let tampered = text.replacen("name = \"Test\"", "name = \"Tampered\"", 1);
    assert!(matches!(verify_delivery(tampered.as_bytes(), &announced), Err(AddonError::HashMismatch { .. })));
}

#[test]
fn sha256_known_value() {
    assert_eq!(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

fn installed() -> Vec<Installed> {
    let mut all: Vec<Installed> = builtin_themes().into_iter().map(|theme| Installed { theme, audience: Audience::Everyone }).collect();
    all.push(Installed {
        theme: load_addon(variant_of("private-look", "#2b7a89").as_bytes()).unwrap().theme,
        audience: Audience::Groups(vec!["staff".into()]),
    });
    all
}

#[test]
fn audience_limits_who_sees_an_addon() {
    let all = installed();
    let staff = vec!["staff".to_string()];
    let guest: Vec<String> = vec!["guests".to_string()];
    assert!(available(&all, &staff).iter().any(|t| t.id == "private-look"));
    assert!(!available(&all, &guest).iter().any(|t| t.id == "private-look"));
    assert!(Audience::Everyone.allows(&[]));
    assert!(!Audience::Groups(vec![]).allows(&staff));
}

#[test]
fn resolve_falls_back_in_order() {
    let all = installed();
    let staff = vec!["staff".to_string()];
    let nobody: Vec<String> = vec![];
    // Own choice, when allowed.
    assert_eq!(resolve(&all, Some("private-look"), None, &staff).unwrap().id, "private-look");
    // Own choice not allowed: the organization default, when allowed.
    assert_eq!(resolve(&all, Some("private-look"), Some("crewcraft-high-contrast"), &nobody).unwrap().id, "crewcraft-high-contrast");
    // Organization default not allowed either: the built-in default.
    assert_eq!(resolve(&all, Some("private-look"), Some("private-look"), &nobody).unwrap().id, DEFAULT_THEME_ID);
    // A removed addon (unknown id) falls back the same way.
    assert_eq!(resolve(&all, Some("deleted-theme"), None, &staff).unwrap().id, DEFAULT_THEME_ID);
    // Nothing installed at all.
    assert!(resolve(&[], None, None, &staff).is_none());
}
