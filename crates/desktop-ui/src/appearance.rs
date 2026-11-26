//! Appearance (REQUIREMENTS 2.19): turning a theme into the window's look, and the appearance settings. Task T314.
//!
//! Owns: the mapping from a theme's colour tokens, corner radii and type sizes to an egui `Style`, the light/dark
//! choice (follow the system, or a fixed variant), and the appearance settings file `appearance.toml`. Called by: the
//! desktop app at start-up, which reads the files and installs the result with `Appearance::install`. Calls:
//! `crewcraft-theme` (themes, addons, contrast), `crewcraft-strict-toml`. Like the rest of this crate it does no I/O.
//!
//! Until the server hands theme addons to clients (M4, with their SHA-256), a person or an organization's installer
//! may put an addon file and the settings in the app's data folder; the same contrast and format checks apply, and a
//! file that fails them is refused with the reason, never applied in part.

use crewcraft_strict_toml as toml;
use crewcraft_theme::{Density, Theme, Variant};
use egui::{Color32, CornerRadius, FontFamily, FontId, Stroke, Style, TextStyle, ThemePreference, Visuals};

/// The largest `appearance.toml` accepted.
pub const MAX_SETTINGS_BYTES: usize = 4 * 1024;
/// The largest theme addon file accepted (the theme format's own limit).
pub const MAX_ADDON_BYTES: usize = crewcraft_theme::MAX_THEME_BYTES;
/// The longest organization name shown in the title bar.
pub const MAX_ORGANIZATION_CHARS: usize = 64;

/// Light, dark, or whatever the operating system uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    System,
    Light,
    Dark,
}

/// What `appearance.toml` says. Every key is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// The id of the theme to use: a built-in one, or the theme addon's.
    pub theme: Option<String>,
    pub mode: Mode,
    /// The name shown in the title bar instead of "CrewCraft".
    pub organization: Option<String>,
}

/// Parse `appearance.toml`:
///
/// ```toml
/// [appearance]
/// theme = "crewcraft-high-contrast"   # a built-in theme id, or the installed addon's id
/// mode = "system"                     # "system", "light" or "dark"
/// organization = "Example Org"        # shown in the title bar
/// ```
///
/// Unknown sections or keys, and values of the wrong shape, are refused with their line number.
pub fn parse_settings(text: &str) -> Result<Settings, toml::Error> {
    let doc = toml::parse(text, MAX_SETTINGS_BYTES)?;
    doc.check_sections(&["appearance"], &[])?;
    let Some(section) = doc.sections.get("appearance") else { return Ok(Settings::default()) };
    section.check_keys("appearance", &["theme", "mode", "organization"])?;
    let bad = |line, key: &str, reason| toml::Error::BadValue { line, key: key.to_owned(), reason };
    let theme = section.opt_str("theme")?.map(|(id, _)| id.to_owned());
    let mode = match section.opt_str("mode")? {
        None | Some(("system", _)) => Mode::System,
        Some(("light", _)) => Mode::Light,
        Some(("dark", _)) => Mode::Dark,
        Some((_, line)) => return Err(bad(line, "mode", "\"system\", \"light\" or \"dark\"")),
    };
    let organization = match section.opt_str("organization")? {
        None => None,
        Some((name, line)) => {
            let name = name.trim();
            if name.is_empty() || name.chars().count() > MAX_ORGANIZATION_CHARS || name.chars().any(char::is_control) {
                return Err(bad(line, "organization", "1 to 64 printable characters"));
            }
            Some(name.to_owned())
        }
    };
    Ok(Settings { theme, mode, organization })
}

/// The window's appearance: a theme, the mode, and the title-bar name.
#[derive(Debug, Clone)]
pub struct Appearance {
    /// `None` only if the built-in default theme failed to load, which crewcraft-theme's tests rule out; the window
    /// then keeps egui's own look rather than failing.
    pub theme: Option<Theme>,
    pub mode: Mode,
    pub organization: Option<String>,
}

impl Default for Appearance {
    fn default() -> Self {
        Self { theme: default_theme(), mode: Mode::System, organization: None }
    }
}

fn default_theme() -> Option<Theme> {
    crewcraft_theme::builtin_themes().into_iter().find(|theme| theme.id == crewcraft_theme::DEFAULT_THEME_ID)
}

impl Appearance {
    /// The appearance from the settings text and an optional theme addon file. Anything refused is left out and
    /// described in the returned problems (shown to the person once), so a bad file never stops the app.
    pub fn resolve(settings_text: Option<&str>, addon: Option<&[u8]>) -> (Self, Vec<String>) {
        let mut problems = Vec::new();
        let settings = match settings_text.map(parse_settings) {
            None => Settings::default(),
            Some(Ok(settings)) => settings,
            Some(Err(error)) => {
                problems.push(format!("The appearance settings were not used: {error}."));
                Settings::default()
            }
        };
        let mut themes = crewcraft_theme::builtin_themes();
        if let Some(bytes) = addon {
            // load_addon checks the format, every contrast rule, and that the id is not a built-in theme's.
            match crewcraft_theme::load_addon(bytes) {
                Ok(addon) => themes.push(addon.theme),
                Err(error) => problems.push(format!("The theme addon was not used: {error}.")),
            }
        }
        let theme = match &settings.theme {
            None => themes.iter().find(|theme| theme.id == crewcraft_theme::DEFAULT_THEME_ID).cloned(),
            Some(id) => {
                let found = themes.iter().find(|theme| &theme.id == id).cloned();
                if found.is_none() {
                    problems.push(format!("There is no theme \"{id}\"; using the default."));
                }
                found
            }
        };
        let theme = theme.or_else(default_theme);
        (Self { theme, mode: settings.mode, organization: settings.organization }, problems)
    }

    /// The title-bar name: the organization's, or "CrewCraft".
    pub fn title(&self) -> &str {
        self.organization.as_deref().unwrap_or("CrewCraft")
    }

    /// Install the look: a style for light and one for dark, and which one to use. egui switches between them when
    /// the operating system does, while `mode` is `System`.
    pub fn install(&self, ctx: &egui::Context) {
        if let Some(theme) = &self.theme {
            ctx.set_style_of(egui::Theme::Light, style(theme, Variant::Light));
            ctx.set_style_of(egui::Theme::Dark, style(theme, Variant::Dark));
        }
        ctx.set_theme(match self.mode {
            Mode::System => ThemePreference::System,
            Mode::Light => ThemePreference::Light,
            Mode::Dark => ThemePreference::Dark,
        });
    }
}

/// The feed's bubble colours from a theme (`bubble-mine`, `bubble-other`), for light and dark (T315).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BubbleColors {
    pub light_mine: Color32,
    pub light_other: Color32,
    pub dark_mine: Color32,
    pub dark_other: Color32,
}

impl BubbleColors {
    pub fn from_theme(theme: &Theme) -> Self {
        Self {
            light_mine: color(theme, Variant::Light, "bubble-mine"),
            light_other: color(theme, Variant::Light, "bubble-other"),
            dark_mine: color(theme, Variant::Dark, "bubble-mine"),
            dark_other: color(theme, Variant::Dark, "bubble-other"),
        }
    }

    /// The fill for one bubble.
    pub fn pick(self, mine: bool, dark: bool) -> Color32 {
        match (mine, dark) {
            (true, false) => self.light_mine,
            (false, false) => self.light_other,
            (true, true) => self.dark_mine,
            (false, true) => self.dark_other,
        }
    }
}

impl Appearance {
    /// The bubble colours for this appearance's theme, if it has one.
    pub fn bubble_colors(&self) -> Option<BubbleColors> {
        self.theme.as_ref().map(BubbleColors::from_theme)
    }
}

fn color(theme: &Theme, variant: Variant, token: &str) -> Color32 {
    // Every token in COLOR_TOKENS is present in a parsed palette, so the fallback is never drawn.
    theme.palette(variant).get(token).map_or(Color32::MAGENTA, |c| Color32::from_rgb(c.r, c.g, c.b))
}

/// The egui style for a theme in one variant. A theme without a dark palette draws its light one in both, as
/// `Theme::palette` does. The window's font stays the bundled Inter; the theme's type sizes and radii apply.
pub fn style(theme: &Theme, variant: Variant) -> Style {
    let c = |token: &str| color(theme, variant, token);
    let dark = matches!(variant, Variant::Dark) && theme.has_dark();
    let mut visuals = if dark { Visuals::dark() } else { Visuals::light() };
    let radius = |r: u8| CornerRadius::same(r);
    let (small, medium, large) = (radius(theme.shape.radius_s), radius(theme.shape.radius_m), radius(theme.shape.radius_l));

    visuals.override_text_color = Some(c("text"));
    visuals.weak_text_color = Some(c("text-muted"));
    visuals.hyperlink_color = c("link");
    visuals.panel_fill = c("bg-pane");
    visuals.window_fill = c("surface");
    visuals.window_stroke = Stroke::new(1.0, c("stroke"));
    visuals.extreme_bg_color = c("bg-canvas");
    visuals.text_edit_bg_color = Some(c("bg-canvas"));
    visuals.faint_bg_color = c("surface-hover");
    visuals.code_bg_color = c("bg-app");
    visuals.warn_fg_color = c("warning");
    visuals.error_fg_color = c("danger");
    visuals.selection.bg_fill = c("accent-soft");
    visuals.selection.stroke = Stroke::new(1.0, c("accent"));
    visuals.window_corner_radius = large;
    visuals.menu_corner_radius = medium;
    visuals.text_cursor.stroke = Stroke::new(2.0, c("accent"));

    let widgets = &mut visuals.widgets;
    widgets.noninteractive.bg_fill = c("bg-pane");
    widgets.noninteractive.weak_bg_fill = c("bg-pane");
    widgets.noninteractive.bg_stroke = Stroke::new(1.0, c("stroke"));
    widgets.noninteractive.fg_stroke = Stroke::new(1.0, c("text"));
    widgets.inactive.bg_fill = c("surface");
    widgets.inactive.weak_bg_fill = c("surface");
    widgets.inactive.bg_stroke = Stroke::new(1.0, c("stroke-strong"));
    widgets.inactive.fg_stroke = Stroke::new(1.0, c("text"));
    widgets.hovered.bg_fill = c("surface-hover");
    widgets.hovered.weak_bg_fill = c("surface-hover");
    widgets.hovered.bg_stroke = Stroke::new(1.0, c("accent-hover"));
    widgets.hovered.fg_stroke = Stroke::new(1.5, c("text"));
    widgets.active.bg_fill = c("accent-pressed");
    widgets.active.weak_bg_fill = c("accent-pressed");
    widgets.active.bg_stroke = Stroke::new(1.0, c("focus-ring"));
    widgets.active.fg_stroke = Stroke::new(2.0, c("on-accent"));
    widgets.open.bg_fill = c("accent-soft");
    widgets.open.weak_bg_fill = c("accent-soft");
    widgets.open.bg_stroke = Stroke::new(1.0, c("accent"));
    widgets.open.fg_stroke = Stroke::new(1.0, c("text"));
    for state in [&mut widgets.noninteractive, &mut widgets.inactive, &mut widgets.hovered, &mut widgets.active, &mut widgets.open] {
        state.corner_radius = small;
    }

    let mut style = Style { visuals, ..Style::default() };
    let body = f32::from(theme.typography.size_body);
    style.text_styles = [
        (TextStyle::Small, FontId::new(f32::from(theme.typography.size_small), FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(body, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(body, FontFamily::Proportional)),
        (TextStyle::Heading, FontId::new(f32::from(theme.typography.size_title), FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(body, FontFamily::Monospace)),
    ]
    .into();
    if theme.density == Density::Compact {
        style.spacing.item_spacing *= 0.75;
        style.spacing.button_padding *= 0.75;
    }
    style
}
