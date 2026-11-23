//! T420: `cargo xtask ios` writes `CrewCraft.app` for the iOS Simulator. The build itself needs a Mac; the bundle's
//! contents are pure functions, checked here on any system against Apple's bundle conventions.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use xtask::ios::{self, IosTarget, Platform};
use xtask::version::Version;

const SVG: &[u8] = include_bytes!("../../assets/icon/crewcraft.svg");

fn version(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|arg| arg.to_string()).collect()
}

/// The top-level `<key>` / `<string>` pairs of a plist.
fn plist_strings(text: &str) -> BTreeMap<String, String> {
    let mut entries = BTreeMap::new();
    let lines: Vec<&str> = text.lines().collect();
    for pair in lines.windows(2) {
        if let (Some(key), Some(value)) = (
            pair[0].strip_prefix("\t<key>").and_then(|rest| rest.strip_suffix("</key>")),
            pair[1].strip_prefix("\t<string>").and_then(|rest| rest.strip_suffix("</string>")),
        ) {
            entries.insert(key.to_string(), value.to_string());
        }
    }
    entries
}

/// The value of the top-level `<key>{key}</key>`: its lines up to the one closing it at the same depth, joined
/// without their indentation.
fn plist_value(text: &str, key: &str) -> String {
    let mut lines = text.lines().skip_while(|line| *line != format!("\t<key>{key}</key>")).skip(1);
    let first = lines.next().unwrap_or_else(|| panic!("{key} is missing"));
    let mut value = first.trim().to_string();
    if first.ends_with("/>") || first.contains("</") {
        return value;
    }
    let close = format!("\t</{}>", first.trim().trim_start_matches('<').trim_end_matches('>'));
    for line in lines {
        value.push_str(line.trim());
        if line == close {
            return value;
        }
    }
    panic!("{key} is not closed");
}

/// An icon file name, `AppIcon60x60@<scale>x.png`, as iOS looks it up for a screen scale.
fn at(scale: u32) -> String {
    format!("AppIcon60x60@{scale}x.png")
}

fn png_size(png: &[u8]) -> (u32, u32) {
    assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
    (u32::from_be_bytes(png[16..20].try_into().unwrap()), u32::from_be_bytes(png[20..24].try_into().unwrap()))
}

#[test]
fn arguments() {
    let options = ios::parse_args(&args(&["--version", "0.1.0-beta.1", "--out", "dist-ios", "--target", "sim-arm64"])).unwrap();
    assert_eq!(options.version, version("0.1.0-beta.1"));
    assert_eq!(options.out, PathBuf::from("dist-ios"));
    assert_eq!(options.target, IosTarget::SimArm64);
    let default = ios::parse_args(&args(&["--version", "0.1.0", "--out", "o"])).unwrap();
    assert_eq!(default.target, IosTarget::host_default());
    // The simulator build carries a Keychain access group, so it can keep its device key (T422).
    let entitlements = ios::simulator_entitlements();
    assert!(entitlements.contains("<key>keychain-access-groups</key>"));
    assert!(entitlements.contains("<string>io.github.setsuad.crewcraft</string>"));
    assert!(!entitlements.contains("application-identifier"), "a restricted entitlement would stop the ad-hoc app from launching");
    // The simulator self-test of the Keychain device key (T422) is opt-in.
    assert!(!default.self_test);
    assert!(ios::parse_args(&args(&["--version", "0.1.0", "--out", "o", "--self-test"])).unwrap().self_test);
    assert!(ios::parse_args(&args(&["--out", "o"])).is_err(), "--version is required");
    assert!(ios::parse_args(&args(&["--version", "0.1.0"])).is_err(), "--out is required");
    assert!(ios::parse_args(&args(&["--version", "0.1.0", "--out", "o", "--target", "sim-x86_64", "--target", "sim-arm64"])).is_err());
    assert!(ios::parse_args(&args(&["--version", "0.1.0", "--out", "o", "--bogus"])).is_err());
    let device = ios::parse_args(&args(&["--version", "0.1.0", "--out", "o", "--target", "device-arm64"])).unwrap_err().to_string();
    assert!(device.contains("signing identity"), "a device build waits for signing: {device}");
}

#[test]
fn targets_are_the_simulator_triples() {
    assert_eq!(IosTarget::parse("sim-x86_64").unwrap().triple(), "x86_64-apple-ios");
    assert_eq!(IosTarget::parse("sim-arm64").unwrap().triple(), "aarch64-apple-ios-sim");
    for target in IosTarget::ALL {
        assert_eq!(IosTarget::parse(target.name()).unwrap(), target);
        assert_eq!(target.platform(), Platform::Simulator);
    }
    assert!(IosTarget::parse("macos-universal").is_err());
}

#[test]
fn info_plist() {
    let text = ios::info_plist(&version("0.1.0-beta.1"), Platform::Simulator);
    assert!(text.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\""));
    assert!(text.ends_with("</dict>\n</plist>\n"));
    let strings = plist_strings(&text);
    assert_eq!(strings["CFBundleIdentifier"], "io.github.setsuad.crewcraft");
    assert_eq!(strings["CFBundleExecutable"], "crewcraft");
    assert_eq!(strings["CFBundleName"], "CrewCraft");
    assert_eq!(strings["CFBundleDisplayName"], "CrewCraft");
    assert_eq!(strings["CFBundlePackageType"], "APPL");
    assert_eq!(strings["CFBundleInfoDictionaryVersion"], "6.0");
    assert_eq!(strings["MinimumOSVersion"], "17.0", "docs/SPEC.md D5: iOS 17+");
    // The App Store takes only three numbers here; the pre-release is in CFBundleVersion, numbered as on macOS.
    assert_eq!(strings["CFBundleShortVersionString"], "0.1.0");
    assert_eq!(strings["CFBundleVersion"], "0.1.201");
    assert_eq!(plist_strings(&ios::info_plist(&version("0.1.0"), Platform::Simulator))["CFBundleVersion"], "0.1.900");
    assert_eq!(plist_value(&text, "UILaunchScreen"), "<dict/>", "a launch screen, so the app fills the screen");
    assert_eq!(plist_value(&text, "LSRequiresIPhoneOS"), "<true/>");
    assert_eq!(plist_value(&text, "CFBundleSupportedPlatforms"), "<array><string>iPhoneSimulator</string></array>");
    assert_eq!(plist_value(&text, "UIDeviceFamily"), "<array><integer>1</integer></array>");
    assert_eq!(plist_value(&text, "UISupportedInterfaceOrientations"), "<array><string>UIInterfaceOrientationPortrait</string></array>");
    assert_eq!(
        plist_value(&text, "CFBundleIcons"),
        "<dict><key>CFBundlePrimaryIcon</key><dict><key>CFBundleIconFiles</key><array><string>AppIcon60x60</string></array></dict></dict>"
    );
    // Every element that opens is closed.
    for tag in ["dict", "array", "plist"] {
        assert_eq!(text.matches(&format!("<{tag}>")).count() + usize::from(tag == "plist"), text.matches(&format!("</{tag}>")).count(), "{tag}");
    }
}

#[test]
fn icons_are_the_iphone_home_screen_sizes() {
    let icons = ios::render_icons(SVG).unwrap();
    let sizes: Vec<(String, (u32, u32))> = icons.iter().map(|(name, png)| (name.clone(), png_size(png))).collect();
    // 60 points at 2x and 3x; iOS finds them from CFBundleIconFiles' AppIcon60x60.
    assert_eq!(sizes, [(at(2), (120, 120)), (at(3), (180, 180))]);
    for (scale, _) in ios::ICONS {
        assert_eq!(ios::icon_file(scale), at(scale));
        assert!(at(scale).starts_with(ios::ICON_NAME));
    }
}

#[test]
fn the_bundle_is_flat_with_the_program_at_its_top() {
    let v = version("0.1.0-beta.1");
    let icons = vec![(at(2), b"png2".to_vec()), (at(3), b"png3".to_vec())];
    let docs = vec![("LICENSE-MIT".to_string(), b"mit".to_vec()), ("OFL.txt".to_string(), b"ofl".to_vec())];
    let files = ios::app_files(&v, Platform::Simulator, b"program", &icons, &docs);
    let paths: Vec<(&str, u32)> = files.iter().map(|file| (file.path.as_str(), file.mode)).collect();
    assert_eq!(
        paths,
        [
            (format!("CrewCraft.app/{}", at(2)).as_str(), 0o644),
            (format!("CrewCraft.app/{}", at(3)).as_str(), 0o644),
            ("CrewCraft.app/Info.plist", 0o644),
            ("CrewCraft.app/PkgInfo", 0o644),
            ("CrewCraft.app/crewcraft", 0o755),
            ("CrewCraft.app/licenses/LICENSE-MIT", 0o644),
            ("CrewCraft.app/licenses/OFL.txt", 0o644),
        ]
    );
    let file = |path: &str| files.iter().find(|file| file.path == path).unwrap().data.clone();
    assert_eq!(file("CrewCraft.app/crewcraft"), b"program");
    assert_eq!(file("CrewCraft.app/PkgInfo"), b"APPL????");
    assert_eq!(file("CrewCraft.app/Info.plist"), ios::info_plist(&v, Platform::Simulator).into_bytes());
    assert_eq!(file("CrewCraft.app/licenses/OFL.txt"), b"ofl");
}

/// A 64-bit little-endian Mach-O executable header and one LC_BUILD_VERSION command (no tools).
fn macho(cpu: u32, platform: u32, minos: u32) -> Vec<u8> {
    let mut data = Vec::new();
    let subtype: u32 = if cpu == 0x0100_0007 { 3 } else { 0 };
    for word in [0xfeed_facf_u32, cpu, subtype, 2, 1, 24, 0, 0] {
        data.extend_from_slice(&word.to_le_bytes());
    }
    for word in [0x32_u32, 24, platform, minos, minos, 0] {
        data.extend_from_slice(&word.to_le_bytes());
    }
    data
}

#[test]
fn the_program_must_be_for_the_simulator_and_ios_17() {
    const X86_64: u32 = 0x0100_0007;
    const ARM64: u32 = 0x0100_000c;
    const IOS: u32 = 2;
    const IOS_SIMULATOR: u32 = 7;
    const IOS_17: u32 = 17 << 16;
    assert_eq!(ios::MINIMUM_OS_MACHO, IOS_17);
    ios::check_program(&macho(X86_64, IOS_SIMULATOR, IOS_17), IosTarget::SimX86_64).unwrap();
    ios::check_program(&macho(ARM64, IOS_SIMULATOR, IOS_17), IosTarget::SimArm64).unwrap();
    assert!(ios::check_program(&macho(ARM64, IOS_SIMULATOR, IOS_17), IosTarget::SimX86_64).is_err(), "wrong CPU");
    assert!(ios::check_program(&macho(ARM64, IOS, IOS_17), IosTarget::SimArm64).is_err(), "an iPhone program, not the simulator's");
    let old = ios::check_program(&macho(X86_64, IOS_SIMULATOR, 10 << 16), IosTarget::SimX86_64).unwrap_err().to_string();
    assert!(old.contains("10.0"), "linked for an older iOS than the plist says: {old}");
    let mut none = macho(X86_64, IOS_SIMULATOR, IOS_17);
    none[16..20].copy_from_slice(&0u32.to_le_bytes());
    none[20..24].copy_from_slice(&0u32.to_le_bytes());
    none.truncate(32);
    assert!(ios::check_program(&none, IosTarget::SimX86_64).is_err(), "no LC_BUILD_VERSION");
    assert!(ios::check_program(b"\x7fELF", IosTarget::SimX86_64).is_err());
}

#[test]
fn the_build_runs_on_a_mac_only() {
    if cfg!(target_os = "macos") {
        assert!(ios::require_macos().is_ok());
    } else {
        assert!(ios::require_macos().is_err());
    }
}
