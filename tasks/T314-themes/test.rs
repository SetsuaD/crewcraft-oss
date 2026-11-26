//! T314: the desktop window takes its look from a theme (REQUIREMENTS 2.19). Every colour token, the corner radii and
//! the type sizes reach egui's style, in light and in dark; the person chooses light, dark or the system's; an
//! organization's theme addon and name come from files in the data folder; and anything refused is said in words and
//! never applied in part. Test themes only, built from the built-in one; files in a scratch folder.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft::app::{APPEARANCE_FILE, THEME_ADDON_FILE, load_appearance};
use crewcraft_desktop_ui::appearance::{Appearance, Mode, parse_settings, style};
use crewcraft_desktop_ui::{Update, Window, fonts};
use crewcraft_theme::{BUILTIN, Variant, builtin_themes};
use eframe::egui::{self, Color32, CornerRadius, TextStyle, ThemePreference};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("crewcraft-t314-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn rgb(theme: &crewcraft_theme::Theme, variant: Variant, token: &str) -> Color32 {
    let c = theme.palette(variant).get(token).unwrap();
    Color32::from_rgb(c.r, c.g, c.b)
}

/// The built-in theme's file with another id: a valid addon.
fn addon_text(id: &str) -> String {
    BUILTIN[0].1.replacen("id = \"crewcraft\"", &format!("id = \"{id}\""), 1)
}

#[test]
fn every_token_radius_and_size_reaches_the_style() {
    for theme in builtin_themes() {
        for variant in [Variant::Light, Variant::Dark] {
            let s = style(&theme, variant);
            let v = &s.visuals;
            let c = |token| rgb(&theme, variant, token);
            assert_eq!(v.dark_mode, variant == Variant::Dark && theme.has_dark(), "{} {variant:?}", theme.id);
            assert_eq!(v.override_text_color, Some(c("text")));
            assert_eq!(v.weak_text_color, Some(c("text-muted")));
            assert_eq!(v.panel_fill, c("bg-pane"));
            assert_eq!(v.window_fill, c("surface"));
            assert_eq!(v.extreme_bg_color, c("bg-canvas"));
            assert_eq!(v.hyperlink_color, c("link"));
            assert_eq!(v.warn_fg_color, c("warning"));
            assert_eq!(v.error_fg_color, c("danger"));
            assert_eq!(v.selection.bg_fill, c("accent-soft"));
            assert_eq!(v.widgets.inactive.bg_fill, c("surface"));
            assert_eq!(v.widgets.hovered.bg_fill, c("surface-hover"));
            assert_eq!(v.widgets.active.bg_fill, c("accent-pressed"));
            assert_eq!(v.widgets.active.fg_stroke.color, c("on-accent"));
            assert_eq!(v.widgets.inactive.corner_radius, CornerRadius::same(theme.shape.radius_s));
            assert_eq!(v.window_corner_radius, CornerRadius::same(theme.shape.radius_l));
            assert_eq!(s.text_styles[&TextStyle::Body].size, f32::from(theme.typography.size_body));
            assert_eq!(s.text_styles[&TextStyle::Small].size, f32::from(theme.typography.size_small));
            assert_eq!(s.text_styles[&TextStyle::Heading].size, f32::from(theme.typography.size_title));
        }
    }
}

#[test]
fn a_theme_without_a_dark_palette_draws_its_light_one_in_dark_mode() {
    let light_only = addon_text("light-only");
    let light_only = &light_only[..light_only.find("[colors.dark]").unwrap()];
    let theme = crewcraft_theme::load(light_only).unwrap();
    assert!(!theme.has_dark());
    let dark = style(&theme, Variant::Dark);
    assert!(!dark.visuals.dark_mode);
    assert_eq!(dark.visuals.panel_fill, rgb(&theme, Variant::Light, "bg-pane"));
}

#[test]
fn the_settings_file_is_strict() {
    let settings = parse_settings("[appearance]\ntheme = \"crewcraft-high-contrast\"\nmode = \"dark\"\norganization = \"Example Org\"\n").unwrap();
    assert_eq!(settings.theme.as_deref(), Some("crewcraft-high-contrast"));
    assert_eq!(settings.mode, Mode::Dark);
    assert_eq!(settings.organization.as_deref(), Some("Example Org"));
    assert_eq!(parse_settings("").unwrap(), Default::default());
    for (text, says) in [
        ("[appearance]\ncolour = \"x\"\n", "line 2"),
        ("[appearance]\nmode = \"dim\"\n", "mode"),
        ("[look]\n", "unknown section"),
        ("[appearance]\norganization = \"  \"\n", "organization"),
        ("[appearance]\nmode = 1\n", "mode"),
    ] {
        let error = parse_settings(text).unwrap_err().to_string();
        assert!(error.contains(says), "{text:?}: {error}");
    }
    let long = format!("[appearance]\norganization = \"{}\"\n", "x".repeat(65));
    assert!(parse_settings(&long).is_err());
}

#[test]
fn an_addon_is_chosen_only_when_it_passes_every_check() {
    let settings = "[appearance]\ntheme = \"example-org\"\norganization = \"Example Org\"\n";
    let (look, problems) = Appearance::resolve(Some(settings), Some(addon_text("example-org").as_bytes()));
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(look.theme.as_ref().unwrap().id, "example-org");
    assert_eq!(look.title(), "Example Org");

    // Text too pale to read: refused with the contrast finding; the default applies.
    let pale = addon_text("example-org").replacen("text = \"#1d2327\"", "text = \"#d8dcde\"", 1);
    let (look, problems) = Appearance::resolve(Some(settings), Some(pale.as_bytes()));
    assert_eq!(look.theme.as_ref().unwrap().id, "crewcraft");
    assert!(problems.iter().any(|p| p.contains("contrast")), "{problems:?}");
    assert!(problems.iter().any(|p| p.contains("no theme \"example-org\"")), "{problems:?}");

    // A built-in theme's id, a theme that is not there, and a broken settings file.
    let (_, problems) = Appearance::resolve(None, Some(BUILTIN[0].1.as_bytes()));
    assert!(problems.iter().any(|p| p.contains("built-in")), "{problems:?}");
    let (look, problems) = Appearance::resolve(Some("[appearance]\ntheme = \"nope\"\n"), None);
    assert_eq!((look.theme.unwrap().id.as_str(), problems.len()), ("crewcraft", 1));
    let (look, problems) = Appearance::resolve(Some("[appearance]\nmode = \"dim\"\n"), None);
    assert_eq!((look.mode, look.title()), (Mode::System, "CrewCraft"));
    assert!(problems[0].starts_with("The appearance settings were not used"), "{problems:?}");
}

#[test]
fn install_sets_both_styles_and_the_mode() {
    let ctx = egui::Context::default();
    let (look, _) = Appearance::resolve(Some("[appearance]\ntheme = \"crewcraft-high-contrast\"\nmode = \"light\"\n"), None);
    look.install(&ctx);
    let theme = look.theme.as_ref().unwrap();
    assert_eq!(ctx.style_of(egui::Theme::Light).visuals.panel_fill, rgb(theme, Variant::Light, "bg-pane"));
    assert_eq!(ctx.style_of(egui::Theme::Dark).visuals.panel_fill, rgb(theme, Variant::Dark, "bg-pane"));
    assert_eq!(ctx.options(|o| o.theme_preference), ThemePreference::Light);
}

#[test]
fn files_in_the_data_folder_set_the_look_and_bad_ones_are_named() {
    let (look, problems) = load_appearance(None);
    assert!(problems.is_empty() && look.organization.is_none());
    let scratch = Scratch::new("files");
    let (look, problems) = load_appearance(Some(&scratch.0));
    assert!(problems.is_empty());
    assert_eq!(look.theme.unwrap().id, "crewcraft");

    fs::write(scratch.0.join(THEME_ADDON_FILE), addon_text("example-org")).unwrap();
    fs::write(scratch.0.join(APPEARANCE_FILE), "[appearance]\ntheme = \"example-org\"\nmode = \"dark\"\norganization = \"Example Org\"\n").unwrap();
    let (look, problems) = load_appearance(Some(&scratch.0));
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!((look.theme.unwrap().id.as_str(), look.mode, look.organization.as_deref()), ("example-org", Mode::Dark, Some("Example Org")));

    fs::write(scratch.0.join(APPEARANCE_FILE), [0xff, 0xfe, 0x00]).unwrap();
    fs::write(scratch.0.join(THEME_ADDON_FILE), vec![b'#'; 70 * 1024]).unwrap();
    let (look, problems) = load_appearance(Some(&scratch.0));
    assert_eq!(look.theme.unwrap().id, "crewcraft");
    assert!(problems.iter().any(|p| p.contains("not UTF-8")), "{problems:?}");
    assert!(problems.iter().any(|p| p.contains("larger than")), "{problems:?}");

    fs::remove_file(scratch.0.join(APPEARANCE_FILE)).unwrap();
    fs::create_dir(scratch.0.join(APPEARANCE_FILE)).unwrap();
    let (_, problems) = load_appearance(Some(&scratch.0));
    assert!(problems.iter().any(|p| p.contains("not a regular file")), "{problems:?}");
}

#[test]
fn the_organization_name_replaces_crewcraft_in_the_window() {
    let mut window = Window::new();
    window.set_title("  Example Org ");
    assert_eq!(window.title(), "Example Org");
    let mut h = Harness::builder()
        .with_size([900.0, 600.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), window);
    h.state_mut().apply(Update::Enrolled { server: "chat.example.org:7443".to_owned() });
    h.run();
    h.get_by_label("Sign in to Example Org");
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".to_owned(), rooms: vec!["General".to_owned()] });
    h.run();
    h.get_by_label("Example Org");
    h.state_mut().set_title("");
    assert_eq!(h.state().title(), "CrewCraft");
}
