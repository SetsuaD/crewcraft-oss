//! Themes and theme addons (REQUIREMENTS 2.19).
//!
//! Owns: the theme file format (a strict TOML subset, see `crewcraft-strict-toml`), the colour tokens every theme must
//! define, the WCAG 2.2 contrast rules a theme must pass, the built-in themes, theme addons (a theme file plus the
//! SHA-256 the server hands out with it), who may use an addon, and which theme a person ends up with.
//! Called by: the server (installing addons, listing them per person) and every client (applying a theme).
//!
//! A theme changes appearance only. Layout and workflow are fixed (REQUIREMENTS 2.20).

use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;

use crewcraft_strict_toml as toml;
use sha2::{Digest, Sha256};

/// The largest theme file accepted.
pub const MAX_THEME_BYTES: usize = 64 * 1024;
/// The theme format version this crate reads (`api` in `[theme]`).
pub const FORMAT_API: i64 = 1;

/// Every colour a palette must define, in display order.
pub const COLOR_TOKENS: &[&str] = &[
    "bg-app",
    "bg-pane",
    "bg-canvas",
    "surface",
    "surface-hover",
    "stroke",
    "stroke-strong",
    "text",
    "text-muted",
    "text-disabled",
    "accent",
    "accent-hover",
    "accent-pressed",
    "accent-soft",
    "on-accent",
    "bubble-mine",
    "bubble-other",
    "link",
    "focus-ring",
    "danger",
    "success",
    "warning",
    "presence-available",
    "presence-busy",
    "presence-away",
    "presence-offline",
];

/// WCAG 2.2 AA contrast a theme must meet: (foreground, background, minimum ratio). Text needs 4.5:1, controls and
/// focus indicators 3:1. Disabled text is exempt (WCAG 1.4.3), and presence colours are exempt because presence is
/// also shown by icon shape.
pub const CONTRAST_RULES: &[(&str, &str, f64)] = &[
    ("text", "bg-app", 4.5),
    ("text", "bg-pane", 4.5),
    ("text", "bg-canvas", 4.5),
    ("text", "surface", 4.5),
    ("text", "surface-hover", 4.5),
    ("text", "bubble-mine", 4.5),
    ("text", "bubble-other", 4.5),
    ("text", "accent-soft", 4.5),
    ("text-muted", "bg-pane", 4.5),
    ("text-muted", "bg-canvas", 4.5),
    ("text-muted", "surface", 4.5),
    ("link", "bg-canvas", 4.5),
    ("link", "bubble-mine", 4.5),
    ("link", "bubble-other", 4.5),
    ("on-accent", "accent", 4.5),
    ("on-accent", "accent-hover", 4.5),
    ("on-accent", "accent-pressed", 4.5),
    ("accent", "bg-canvas", 3.0),
    ("accent", "bg-pane", 3.0),
    ("focus-ring", "bg-canvas", 3.0),
    ("focus-ring", "bg-pane", 3.0),
    ("stroke-strong", "bg-canvas", 3.0),
    ("danger", "bg-canvas", 3.0),
    ("success", "bg-canvas", 3.0),
    ("warning", "bg-canvas", 3.0),
];

/// The built-in themes, as (id, file text). Every one loads and passes the contrast rules (tests prove it).
pub const BUILTIN: &[(&str, &str)] =
    &[("crewcraft", include_str!("../themes/crewcraft.toml")), ("crewcraft-high-contrast", include_str!("../themes/crewcraft-high-contrast.toml"))];

/// The theme used when nothing else applies.
pub const DEFAULT_THEME_ID: &str = "crewcraft";

/// An sRGB colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Color {
    /// `#rrggbb`, either case.
    pub fn parse_hex(s: &str) -> Option<Color> {
        let hex = s.strip_prefix('#')?;
        if hex.len() != 6 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let v = u32::from_str_radix(hex, 16).ok()?;
        let [_, r, g, b] = v.to_be_bytes();
        Some(Color { r, g, b })
    }

    /// Lower-case `#rrggbb`.
    pub fn to_hex(self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.r, self.g, self.b)
    }

    /// WCAG relative luminance, 0.0 (black) to 1.0 (white).
    pub fn relative_luminance(self) -> f64 {
        fn channel(c: u8) -> f64 {
            let s = f64::from(c) / 255.0;
            if s <= 0.04045 { s / 12.92 } else { ((s + 0.055) / 1.055).powf(2.4) }
        }
        0.2126 * channel(self.r) + 0.7152 * channel(self.g) + 0.0722 * channel(self.b)
    }
}

/// WCAG contrast ratio, 1.0 to 21.0, whichever colour is lighter.
pub fn contrast_ratio(a: Color, b: Color) -> f64 {
    let (la, lb) = (a.relative_luminance(), b.relative_luminance());
    let (hi, lo) = if la >= lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

/// One complete set of colours. Only the parser builds one, so every token in `COLOR_TOKENS` is present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Palette {
    colors: BTreeMap<&'static str, Color>,
}

impl Palette {
    pub fn get(&self, token: &str) -> Option<Color> {
        self.colors.get(token).copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    Light,
    Dark,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Density {
    Comfortable,
    Compact,
}

/// Type sizes in logical pixels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Typography {
    /// `system` for the platform font, or a font family name the client has.
    pub font: String,
    pub size_small: u8,
    pub size_body: u8,
    pub size_title: u8,
}

/// Corner radii in logical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shape {
    pub radius_s: u8,
    pub radius_m: u8,
    pub radius_l: u8,
}

/// A parsed theme.
#[derive(Debug, Clone, PartialEq)]
pub struct Theme {
    pub id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub license: String,
    pub description: Option<String>,
    pub density: Density,
    pub typography: Typography,
    pub shape: Shape,
    light: Palette,
    dark: Option<Palette>,
}

impl Theme {
    /// The palette for `variant`; a theme without a dark palette uses its light one.
    pub fn palette(&self, variant: Variant) -> &Palette {
        match (variant, &self.dark) {
            (Variant::Dark, Some(dark)) => dark,
            _ => &self.light,
        }
    }

    pub fn has_dark(&self) -> bool {
        self.dark.is_some()
    }

    /// Every contrast rule this theme breaks, in each palette it defines.
    pub fn contrast_findings(&self) -> Vec<ContrastFinding> {
        let mut findings = Vec::new();
        let mut palettes = vec![(Variant::Light, &self.light)];
        if let Some(dark) = &self.dark {
            palettes.push((Variant::Dark, dark));
        }
        for (variant, palette) in palettes {
            for &(foreground, background, required) in CONTRAST_RULES {
                if let (Some(fg), Some(bg)) = (palette.get(foreground), palette.get(background)) {
                    let ratio = contrast_ratio(fg, bg);
                    if ratio < required {
                        findings.push(ContrastFinding { variant, foreground, background, ratio, required });
                    }
                }
            }
        }
        findings
    }
}

/// A contrast rule a theme breaks.
#[derive(Debug, Clone, PartialEq)]
pub struct ContrastFinding {
    pub variant: Variant,
    pub foreground: &'static str,
    pub background: &'static str,
    pub ratio: f64,
    pub required: f64,
}

impl fmt::Display for ContrastFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self.variant {
            Variant::Light => "light",
            Variant::Dark => "dark",
        };
        write!(f, "{variant}: {} on {} is {:.2}:1; at least {:.1}:1 is required", self.foreground, self.background, self.ratio, self.required)
    }
}

fn bad(line: usize, key: &str, reason: &'static str) -> toml::Error {
    toml::Error::BadValue { line, key: key.to_string(), reason }
}

fn text_field(section: &toml::Section, key: &str, max: usize) -> Result<(String, usize), toml::Error> {
    let (value, line) = section.req_str("theme", key)?;
    if value.trim().is_empty() || value.chars().count() > max {
        return Err(bad(line, key, "is empty or too long"));
    }
    Ok((value.to_string(), line))
}

fn valid_id(id: &str) -> bool {
    (3..=64).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-')
}

fn valid_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty() && p.len() <= 9 && p.bytes().all(|b| b.is_ascii_digit()))
}

fn int_in(section: Option<&toml::Section>, key: &str, range: std::ops::RangeInclusive<i64>, default: u8) -> Result<u8, toml::Error> {
    let Some(section) = section else { return Ok(default) };
    match section.opt_int(key)? {
        None => Ok(default),
        Some((n, line)) if range.contains(&n) => u8::try_from(n).map_err(|_| bad(line, key, "out of range")),
        Some((_, line)) => Err(bad(line, key, "out of range")),
    }
}

fn palette(doc: &toml::Document, name: &str) -> Result<Option<Palette>, toml::Error> {
    let Some(section) = doc.sections.get(name) else { return Ok(None) };
    section.check_keys(name, COLOR_TOKENS)?;
    let mut colors = BTreeMap::new();
    for &token in COLOR_TOKENS {
        let (value, line) = section.req_str(name, token)?;
        let color = Color::parse_hex(value).ok_or_else(|| bad(line, token, "expected a colour like \"#1a2b3c\""))?;
        colors.insert(token, color);
    }
    Ok(Some(Palette { colors }))
}

/// Parse a theme file. This checks the format only; `load` also checks contrast.
pub fn parse(text: &str) -> Result<Theme, toml::Error> {
    let doc = toml::parse(text, MAX_THEME_BYTES)?;
    doc.check_sections(&["theme", "type", "shape", "colors.light", "colors.dark"], &[])?;

    let meta = doc.require("theme")?;
    meta.check_keys("theme", &["api", "id", "name", "version", "author", "license", "description", "density"])?;
    let (api, api_line) = meta.req_int("theme", "api")?;
    if api != FORMAT_API {
        return Err(bad(api_line, "api", "this CrewCraft reads theme format 1"));
    }
    let (id, id_line) = meta.req_str("theme", "id")?;
    if !valid_id(id) {
        return Err(bad(id_line, "id", "3 to 64 characters of a-z, 0-9 and -, not starting or ending with -"));
    }
    let (name, _) = text_field(meta, "name", 64)?;
    let (version, version_line) = text_field(meta, "version", 32)?;
    if !valid_version(&version) {
        return Err(bad(version_line, "version", "expected major.minor.patch, like \"1.0.0\""));
    }
    let (author, _) = text_field(meta, "author", 128)?;
    let (license, _) = text_field(meta, "license", 128)?;
    let description = match meta.opt_str("description")? {
        None => None,
        Some((d, _)) if d.chars().count() <= 500 => Some(d.to_string()),
        Some((_, line)) => return Err(bad(line, "description", "at most 500 characters")),
    };
    let density = match meta.opt_str("density")? {
        None | Some(("comfortable", _)) => Density::Comfortable,
        Some(("compact", _)) => Density::Compact,
        Some((_, line)) => return Err(bad(line, "density", "\"comfortable\" or \"compact\"")),
    };

    let type_section = doc.sections.get("type");
    if let Some(section) = type_section {
        section.check_keys("type", &["font", "size-small", "size-body", "size-title"])?;
    }
    let font = match type_section.map(|s| s.opt_str("font")).transpose()?.flatten() {
        None => "system".to_string(),
        Some((f, line)) => {
            if f.trim().is_empty() || f.chars().count() > 64 {
                return Err(bad(line, "font", "1 to 64 characters"));
            }
            f.to_string()
        }
    };
    let typography = Typography {
        font,
        size_small: int_in(type_section, "size-small", 10..=20, 12)?,
        size_body: int_in(type_section, "size-body", 11..=24, 14)?,
        size_title: int_in(type_section, "size-title", 14..=40, 20)?,
    };
    if typography.size_small > typography.size_body || typography.size_body > typography.size_title {
        let line = type_section.map_or(0, |s| s.line);
        return Err(bad(line, "type", "sizes must grow: size-small <= size-body <= size-title"));
    }

    let shape_section = doc.sections.get("shape");
    if let Some(section) = shape_section {
        section.check_keys("shape", &["radius-s", "radius-m", "radius-l"])?;
    }
    let shape = Shape {
        radius_s: int_in(shape_section, "radius-s", 0..=16, 4)?,
        radius_m: int_in(shape_section, "radius-m", 0..=24, 6)?,
        radius_l: int_in(shape_section, "radius-l", 0..=32, 8)?,
    };

    let light = palette(&doc, "colors.light")?.ok_or_else(|| toml::Error::MissingSection { section: "colors.light".into() })?;
    let dark = palette(&doc, "colors.dark")?;

    Ok(Theme { id: id.to_string(), name, version, author, license, description, density, typography, shape, light, dark })
}

#[derive(Debug, Clone, PartialEq)]
pub enum LoadError {
    /// The file is not a valid theme.
    Invalid(toml::Error),
    /// The file is valid but breaks contrast rules; every finding is listed.
    Contrast(Vec<ContrastFinding>),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::Invalid(e) => write!(f, "{e}"),
            LoadError::Contrast(findings) => {
                write!(f, "the theme fails {} contrast check(s)", findings.len())?;
                for finding in findings {
                    write!(f, "\n  {finding}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// Parse a theme and refuse it unless it passes every contrast rule.
pub fn load(text: &str) -> Result<Theme, LoadError> {
    let theme = parse(text).map_err(LoadError::Invalid)?;
    let findings = theme.contrast_findings();
    if findings.is_empty() { Ok(theme) } else { Err(LoadError::Contrast(findings)) }
}

/// The built-in themes. Each is checked by the tests, so none is ever skipped in practice; one that failed to load
/// would be left out rather than crash the client.
pub fn builtin_themes() -> Vec<Theme> {
    BUILTIN.iter().filter_map(|(_, text)| load(text).ok()).collect()
}

/// Lower-case hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(64);
    for b in Sha256::digest(bytes) {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A theme addon as the server stores and hands it out: the theme and the SHA-256 of its exact file.
#[derive(Debug, Clone, PartialEq)]
pub struct ThemeAddon {
    pub theme: Theme,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AddonError {
    TooLarge {
        bytes: usize,
    },
    NotUtf8,
    /// The bytes the client received are not the bytes the server announced.
    HashMismatch {
        expected: String,
        actual: String,
    },
    /// The id belongs to a built-in theme.
    ReservedId(String),
    Load(LoadError),
}

impl fmt::Display for AddonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddonError::TooLarge { bytes } => write!(f, "the file is {bytes} bytes; the limit is {MAX_THEME_BYTES}"),
            AddonError::NotUtf8 => write!(f, "the file is not UTF-8 text"),
            AddonError::HashMismatch { expected, actual } => {
                write!(f, "the file's SHA-256 is {actual}, but the server announced {expected}")
            }
            AddonError::ReservedId(id) => write!(f, "`{id}` is the id of a built-in theme"),
            AddonError::Load(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for AddonError {}

/// Read an addon file for installation on the server.
pub fn load_addon(bytes: &[u8]) -> Result<ThemeAddon, AddonError> {
    if bytes.len() > MAX_THEME_BYTES {
        return Err(AddonError::TooLarge { bytes: bytes.len() });
    }
    let text = std::str::from_utf8(bytes).map_err(|_| AddonError::NotUtf8)?;
    let theme = load(text).map_err(AddonError::Load)?;
    if BUILTIN.iter().any(|(id, _)| *id == theme.id) {
        return Err(AddonError::ReservedId(theme.id));
    }
    Ok(ThemeAddon { theme, sha256: sha256_hex(bytes) })
}

/// What a client does with addon bytes it received: check them against the hash the server announced, then load.
pub fn verify_delivery(bytes: &[u8], announced_sha256: &str) -> Result<ThemeAddon, AddonError> {
    let actual = sha256_hex(bytes);
    if !actual.eq_ignore_ascii_case(announced_sha256) {
        return Err(AddonError::HashMismatch { expected: announced_sha256.to_string(), actual });
    }
    load_addon(bytes)
}

/// Who may use an installed theme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    Everyone,
    /// Members of any of these groups (REQUIREMENTS 2.12).
    Groups(Vec<String>),
}

impl Audience {
    pub fn allows(&self, person_groups: &[String]) -> bool {
        match self {
            Audience::Everyone => true,
            Audience::Groups(groups) => groups.iter().any(|g| person_groups.contains(g)),
        }
    }
}

/// An installed theme and who may use it. Built-in themes are installed for everyone.
#[derive(Debug, Clone, PartialEq)]
pub struct Installed {
    pub theme: Theme,
    pub audience: Audience,
}

/// The themes a person may pick from, in order.
pub fn available<'a>(installed: &'a [Installed], person_groups: &[String]) -> Vec<&'a Theme> {
    installed.iter().filter(|i| i.audience.allows(person_groups)).map(|i| &i.theme).collect()
}

/// The theme a person sees: their own choice if they may use it, else the organization default if they may use it,
/// else the built-in default, else the first theme they may use. `None` only when nothing at all is available.
pub fn resolve<'a>(installed: &'a [Installed], chosen: Option<&str>, org_default: Option<&str>, person_groups: &[String]) -> Option<&'a Theme> {
    let usable = available(installed, person_groups);
    let find = |id: &str| usable.iter().copied().find(|t| t.id == id);
    chosen.and_then(find).or_else(|| org_default.and_then(find)).or_else(|| find(DEFAULT_THEME_ID)).or_else(|| usable.first().copied())
}
