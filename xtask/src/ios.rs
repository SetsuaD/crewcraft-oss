//! `cargo xtask ios`: builds `apps/crewcraft` for the iOS Simulator and writes `CrewCraft.app` (task T420).
//!
//! The bundle is written here in Rust, with no Xcode project and no Swift or Objective-C source: the program, an
//! `Info.plist`, the home-screen icons rendered from `assets/icon/crewcraft.svg`, `PkgInfo` and the license files,
//! then sealed ad hoc with `codesign --sign -` (no identity). The window inside is the same egui client as the
//! desktop, run through winit's iOS backend (`apps/crewcraft/src/ios.rs`, task T421).
//!
//! Everything that does not need a Mac is a pure function tested on Linux: the arguments, the `Info.plist`, the icon
//! sizes, the bundle's files and the check that a built program is for the simulator and iOS 17. Building runs cargo
//! with Apple's SDK and `codesign`, so it runs on macOS only. A device build (`aarch64-apple-ios`) needs a signing
//! identity and a provisioning profile; it comes with TestFlight (task T424), which adds a `Platform::Device` target
//! here, and the Secure Enclave key (task T422) adds its entitlements to the signing step.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use object::Endianness;
use object::macho::MachHeader64;
use object::read::macho::MachHeader;

use crate::archive::TreeFile;
use crate::names::CLIENT;
use crate::version::Version;
use crate::{Context, Error, Result, dist, icon, linkage, macos};

pub const USAGE: &str = "\
usage: cargo xtask ios --version <version> --out <dir> [--target sim-x86_64|sim-arm64]

Builds crewcraft in release mode for the iOS Simulator and writes <dir>/CrewCraft.app, signed ad hoc. Without
--target it builds for this Mac's simulator: sim-arm64 on Apple Silicon, sim-x86_64 on Intel. Install and start it
with `xcrun simctl install booted <dir>/CrewCraft.app` and `xcrun simctl launch booted io.github.setsuad.crewcraft`.
Runs on macOS only, with Xcode and the iOS Simulator. See docs/RELEASE.md.";

/// The bundle identifier, the same as the macOS app's.
pub const BUNDLE_ID: &str = macos::BUNDLE_ID;
/// The bundle folder written into the output folder.
pub const APP_DIR: &str = "CrewCraft.app";
/// The program inside the bundle (`CFBundleExecutable`).
pub const EXECUTABLE: &str = CLIENT;
/// The oldest iOS the app runs on (docs/SPEC.md, D5). The program is linked for it as well.
pub const MINIMUM_OS: &str = "17.0";
/// `MINIMUM_OS` as Mach-O writes it in `LC_BUILD_VERSION`: `xxxx.yy.zz` in nibbles.
pub const MINIMUM_OS_MACHO: u32 = 17 << 16;
/// The icon name in `CFBundleIconFiles`; iOS adds `@2x.png` or `@3x.png` for the screen.
pub const ICON_NAME: &str = "AppIcon60x60";
/// The home-screen icons as (screen scale, pixel size): 60 points at 2x and 3x, the iPhone sizes.
pub const ICONS: [(u32, u32); 2] = [(2, 120), (3, 180)];

/// The icon's file in the bundle for a screen scale: `ICON_NAME`, `@`, the scale, `x.png`.
pub fn icon_file(scale: u32) -> String {
    format!("{ICON_NAME}@{scale}x.png")
}

/// Where the program runs. Only the simulator is built until a signing identity exists (task T424).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    Simulator,
}

impl Platform {
    /// `CFBundleSupportedPlatforms`.
    pub fn plist_name(self) -> &'static str {
        match self {
            Platform::Simulator => "iPhoneSimulator",
        }
    }

    /// The platform number in the program's `LC_BUILD_VERSION` (`PLATFORM_IOSSIMULATOR`).
    pub fn macho_platform(self) -> u32 {
        match self {
            Platform::Simulator => object::macho::PLATFORM_IOSSIMULATOR,
        }
    }
}

/// A build target of `cargo xtask ios`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IosTarget {
    /// The simulator on an Intel Mac.
    SimX86_64,
    /// The simulator on an Apple Silicon Mac.
    SimArm64,
}

impl IosTarget {
    pub const ALL: [IosTarget; 2] = [IosTarget::SimX86_64, IosTarget::SimArm64];

    /// Parses the `--target` value.
    pub fn parse(text: &str) -> Result<IosTarget> {
        match text {
            "sim-x86_64" => Ok(IosTarget::SimX86_64),
            "sim-arm64" => Ok(IosTarget::SimArm64),
            "device-arm64" | "ios-arm64" | "aarch64-apple-ios" => Err(Error::new(format!(
                "target {text}: an iPhone build needs a signing identity and a provisioning profile, which come with TestFlight (task T424); \
                 build for the simulator with sim-x86_64 or sim-arm64"
            ))),
            _ => Err(Error::new(format!("unknown iOS target {text:?}: expected sim-x86_64 or sim-arm64"))),
        }
    }

    /// The simulator of the Mac running the build: arm64 on Apple Silicon, x86_64 on Intel.
    pub fn host_default() -> IosTarget {
        if cfg!(target_arch = "aarch64") { IosTarget::SimArm64 } else { IosTarget::SimX86_64 }
    }

    pub fn name(self) -> &'static str {
        match self {
            IosTarget::SimX86_64 => "sim-x86_64",
            IosTarget::SimArm64 => "sim-arm64",
        }
    }

    /// The Rust target triple.
    pub fn triple(self) -> &'static str {
        match self {
            IosTarget::SimX86_64 => "x86_64-apple-ios",
            IosTarget::SimArm64 => "aarch64-apple-ios-sim",
        }
    }

    pub fn platform(self) -> Platform {
        match self {
            IosTarget::SimX86_64 | IosTarget::SimArm64 => Platform::Simulator,
        }
    }
}

/// The parsed `ios` command line.
#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    pub version: Version,
    pub out: PathBuf,
    pub target: IosTarget,
}

/// Parses the arguments after `ios`.
pub fn parse_args(args: &[String]) -> Result<Options> {
    let mut version = None;
    let mut out = None;
    let mut target = None;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        let mut value = || rest.next().ok_or_else(|| Error::new(format!("{flag} needs a value\n\n{USAGE}")));
        match flag.as_str() {
            "--version" => version = Some(Version::parse(value()?)?),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--target" => {
                let parsed = IosTarget::parse(value()?)?;
                if target.is_some_and(|earlier| earlier != parsed) {
                    return Err(Error::new(format!("cargo xtask ios builds one target at a time\n\n{USAGE}")));
                }
                target = Some(parsed);
            }
            _ => return Err(Error::new(format!("unknown argument {flag:?}\n\n{USAGE}"))),
        }
    }
    let version = version.ok_or_else(|| Error::new(format!("--version is required\n\n{USAGE}")))?;
    let out = out.ok_or_else(|| Error::new(format!("--out is required\n\n{USAGE}")))?;
    Ok(Options { version, out, target: target.unwrap_or_else(IosTarget::host_default) })
}

/// `CFBundleShortVersionString`: the release's three numbers, the only form the App Store accepts. The pre-release
/// shows in `CFBundleVersion`, which is the MSI and macOS numbering (`0.1.0-beta.1` is `0.1.201`).
pub fn short_version(version: &Version) -> String {
    format!("{}.{}.{}", version.major, version.minor, version.patch)
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// The app's `Info.plist`, in the XML property-list format.
pub fn info_plist(version: &Version, platform: Platform) -> String {
    let strings = [
        ("CFBundleDevelopmentRegion", "en".to_string()),
        ("CFBundleDisplayName", "CrewCraft".to_string()),
        ("CFBundleExecutable", EXECUTABLE.to_string()),
        ("CFBundleIdentifier", BUNDLE_ID.to_string()),
        ("CFBundleInfoDictionaryVersion", "6.0".to_string()),
        ("CFBundleName", "CrewCraft".to_string()),
        ("CFBundlePackageType", "APPL".to_string()),
        ("CFBundleShortVersionString", short_version(version)),
        ("CFBundleVersion", macos::bundle_version(version)),
        ("MinimumOSVersion", MINIMUM_OS.to_string()),
    ];
    let mut text = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n",
    );
    for (key, value) in strings {
        text.push_str(&format!("\t<key>{key}</key>\n\t<string>{}</string>\n", escape(&value)));
    }
    // The home-screen icon: PNG files in the bundle, found by name (no asset catalog, so no actool).
    text.push_str(&format!(
        "\t<key>CFBundleIcons</key>\n\t<dict>\n\t\t<key>CFBundlePrimaryIcon</key>\n\t\t<dict>\n\t\t\t<key>CFBundleIconFiles</key>\n\
         \t\t\t<array>\n\t\t\t\t<string>{ICON_NAME}</string>\n\t\t\t</array>\n\t\t</dict>\n\t</dict>\n"
    ));
    text.push_str(&format!("\t<key>CFBundleSupportedPlatforms</key>\n\t<array>\n\t\t<string>{}</string>\n\t</array>\n", platform.plist_name()));
    text.push_str("\t<key>LSRequiresIPhoneOS</key>\n\t<true/>\n");
    // iPhone only for now (1 = iPhone); an iPad runs it in its iPhone mode.
    text.push_str("\t<key>UIDeviceFamily</key>\n\t<array>\n\t\t<integer>1</integer>\n\t</array>\n");
    // An empty launch screen: the system background until the first frame, and the app fills the whole screen
    // instead of running letterboxed at an old iPhone size.
    text.push_str("\t<key>UILaunchScreen</key>\n\t<dict/>\n");
    text.push_str("\t<key>UIRequiresFullScreen</key>\n\t<true/>\n");
    text.push_str("\t<key>UISupportedInterfaceOrientations</key>\n\t<array>\n\t\t<string>UIInterfaceOrientationPortrait</string>\n\t</array>\n");
    text.push_str("</dict>\n</plist>\n");
    text
}

/// Renders the [`ICONS`] from the SVG, as (file name, png).
pub fn render_icons(svg: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    ICONS.iter().map(|&(scale, size)| Ok((icon_file(scale), icon::render_png(svg, size)?))).collect()
}

/// The files of `CrewCraft.app`, with paths starting `CrewCraft.app/`. An iOS bundle is flat: the program, the
/// `Info.plist` and the icons sit at its top. `docs` are the license files, placed in `licenses/`.
pub fn app_files(version: &Version, platform: Platform, binary: &[u8], icons: &[(String, Vec<u8>)], docs: &[(String, Vec<u8>)]) -> Vec<TreeFile> {
    let mut files = vec![
        TreeFile::new(format!("{APP_DIR}/Info.plist"), 0o644, info_plist(version, platform).into_bytes()),
        TreeFile::new(format!("{APP_DIR}/PkgInfo"), 0o644, b"APPL????".to_vec()),
        TreeFile::new(format!("{APP_DIR}/{EXECUTABLE}"), 0o755, binary),
    ];
    for (name, png) in icons {
        files.push(TreeFile::new(format!("{APP_DIR}/{name}"), 0o644, png.clone()));
    }
    for (name, data) in docs {
        files.push(TreeFile::new(format!("{APP_DIR}/licenses/{name}"), 0o644, data.clone()));
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files
}

/// Checks a built program: a 64-bit Mach-O for the target's CPU, linked for the target's platform and for
/// [`MINIMUM_OS`] (the `LC_BUILD_VERSION` load command), so the bundle never says one thing and the program another.
pub fn check_program(data: &[u8], target: IosTarget) -> Result<()> {
    linkage::check_macho(data, target.triple())?;
    let read_error = |error: object::Error| Error::new(format!("reading the Mach-O program's load commands: {error}"));
    // Only the header and the load commands are read: the check needs nothing else.
    let header = MachHeader64::<Endianness>::parse(data, 0).map_err(read_error)?;
    let endian = header.endian().map_err(read_error)?;
    let mut commands = header.load_commands(endian, data, 0).map_err(read_error)?;
    let mut build = None;
    while let Some(command) = commands.next().map_err(read_error)? {
        if let Some(found) = command.build_version().map_err(read_error)? {
            build = Some((found.platform.get(endian), found.minos.get(endian)));
        }
    }
    let (platform, minos) = build.ok_or_else(|| Error::new("the program has no LC_BUILD_VERSION, so the platform it was built for is unknown"))?;
    if platform != target.platform().macho_platform() {
        return Err(Error::new(format!(
            "the program is built for Mach-O platform {platform}, not {} ({:?})",
            target.platform().macho_platform(),
            target.platform()
        )));
    }
    if minos != MINIMUM_OS_MACHO {
        return Err(Error::new(format!(
            "the program is linked for iOS {}.{}, not {MINIMUM_OS}; IPHONEOS_DEPLOYMENT_TARGET was not applied",
            minos >> 16,
            (minos >> 8) & 0xff
        )));
    }
    Ok(())
}

/// Fails unless this is a Mac: the iOS targets link against Apple's SDK and the bundle is signed with `codesign`.
pub fn require_macos() -> Result<()> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        Err(Error::new("cargo xtask ios runs on macOS only: it builds with Xcode's iOS SDK and signs with codesign (docs/RELEASE.md)"))
    }
}

/// Builds the client for `target` and returns the program's path.
fn cargo_build(root: &Path, target: IosTarget, epoch: u64) -> Result<PathBuf> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    println!("== building {CLIENT} for the iOS Simulator ({}, {})", target.name(), target.triple());
    let status = Command::new(&cargo)
        .current_dir(root)
        .args(["build", "--release", "--locked", "--target", target.triple(), "-p", CLIENT])
        .env("SOURCE_DATE_EPOCH", epoch.to_string())
        .env("CARGO_PROFILE_RELEASE_STRIP", "symbols")
        .env("CARGO_ENCODED_RUSTFLAGS", dist::release_rustflags(root))
        .env("IPHONEOS_DEPLOYMENT_TARGET", MINIMUM_OS)
        .env_remove("RUSTFLAGS")
        .status()
        .context(|| "running cargo build".to_string())?;
    if !status.success() {
        return Err(Error::new(format!("cargo build for {} failed ({status})", target.triple())));
    }
    Ok(dist::target_dir(root).join(target.triple()).join("release").join(EXECUTABLE))
}

/// Runs `ios`: builds the program, checks it, writes `<out>/CrewCraft.app` (replacing an earlier one) and signs it.
pub fn run(options: &Options) -> Result<()> {
    require_macos()?;
    let root = dist::workspace_root()?;
    let epoch = dist::source_date_epoch(&root)?;
    let built = env!("CARGO_PKG_VERSION");
    if built != options.version.to_string() {
        println!("warning: the program reports version {built}, not {}; set workspace.package.version before a release", options.version);
    }
    let program = cargo_build(&root, options.target, epoch)?;
    let binary = fs::read(&program).context(|| format!("reading {}", program.display()))?;
    check_program(&binary, options.target)?;
    let svg = fs::read(root.join("assets/icon/crewcraft.svg")).context(|| "reading the icon SVG".to_string())?;
    let docs = dist::license_files(&root, true, false)?;
    let files = app_files(&options.version, options.target.platform(), &binary, &render_icons(&svg)?, &docs);
    fs::create_dir_all(&options.out).context(|| format!("creating {}", options.out.display()))?;
    let app = options.out.join(APP_DIR);
    if app.exists() {
        fs::remove_dir_all(&app).context(|| format!("removing the earlier {}", app.display()))?;
    }
    // The paths already start with `CrewCraft.app/`, so they are written under a staging folder and moved.
    let staging = options.out.join(format!(".{APP_DIR}.partial"));
    if staging.exists() {
        fs::remove_dir_all(&staging).context(|| format!("removing {}", staging.display()))?;
    }
    crate::appimage::write_appdir(&staging, &files)?;
    fs::rename(staging.join(APP_DIR), &app).context(|| format!("writing {}", app.display()))?;
    fs::remove_dir(&staging).context(|| format!("removing {}", staging.display()))?;
    macos::adhoc_sign(&app)?;
    println!("   {} ({} bytes program, signed ad hoc)", app.display(), binary.len());
    println!("== install it: xcrun simctl install booted {}", app.display());
    println!("   start it:   xcrun simctl launch booted {BUNDLE_ID}");
    Ok(())
}
