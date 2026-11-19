//! The macOS release: `CrewCraft.app` in a disk image, and the server as a `.tar.gz`, both universal (x86_64 and
//! arm64 in one binary).
//!
//! Everything that does not need a Mac is a pure function here and is tested on Linux: the `Info.plist`, the `.icns`
//! icon, the bundle's files and the disk image's staging folder. Only joining the two builds (`lipo`) and making the
//! disk image (`hdiutil`) run Apple's tools, so `--target macos-universal` runs on macOS only.

use std::path::Path;
use std::process::Command;

use crate::archive::TreeFile;
use crate::version::Version;
use crate::{Context, Error, Result};

/// The bundle identifier, the app's name on macOS.
pub const BUNDLE_ID: &str = "io.github.setsuad.crewcraft";
/// The bundle folder inside the disk image.
pub const APP_DIR: &str = "CrewCraft.app";
/// The disk image's volume name.
pub const VOLUME_NAME: &str = "CrewCraft";
/// The icon file in `Contents/Resources`.
pub const ICON_FILE: &str = "crewcraft.icns";
/// The oldest macOS the app declares it runs on.
pub const MINIMUM_SYSTEM: &str = "11.0";
/// The two architectures joined into the universal binaries.
pub const TRIPLES: [&str; 2] = ["x86_64-apple-darwin", "aarch64-apple-darwin"];

/// The `.icns` entries as (type, pixel size): PNG images from 16 to 1024 px, each normal and Retina size macOS uses.
pub const ICNS_ENTRIES: [(&[u8; 4], u32); 10] = [
    (b"icp4", 16),
    (b"icp5", 32),
    (b"ic11", 32),
    (b"ic12", 64),
    (b"ic07", 128),
    (b"ic13", 256),
    (b"ic08", 256),
    (b"ic14", 512),
    (b"ic09", 512),
    (b"ic10", 1024),
];

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// `CFBundleVersion`, which macOS compares as numbers: the same three numbers as the MSI version, so that every later
/// release is larger (`0.1.0-beta.1` is `0.1.201`; see [`crate::version`]).
pub fn bundle_version(version: &Version) -> String {
    version.msi_product_version()
}

/// `Contents/Info.plist`. `CFBundleShortVersionString`, the version people see, is the release version as written.
pub fn info_plist(version: &Version) -> String {
    let entries = [
        ("CFBundleDevelopmentRegion", "en".to_string()),
        ("CFBundleDisplayName", "CrewCraft".to_string()),
        ("CFBundleExecutable", "crewcraft".to_string()),
        ("CFBundleIconFile", ICON_FILE.to_string()),
        ("CFBundleIdentifier", BUNDLE_ID.to_string()),
        ("CFBundleInfoDictionaryVersion", "6.0".to_string()),
        ("CFBundleName", "CrewCraft".to_string()),
        ("CFBundlePackageType", "APPL".to_string()),
        ("CFBundleShortVersionString", version.to_string()),
        ("CFBundleVersion", bundle_version(version)),
        ("LSMinimumSystemVersion", MINIMUM_SYSTEM.to_string()),
    ];
    let mut text = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n",
    );
    for (key, value) in entries {
        text.push_str(&format!("\t<key>{key}</key>\n\t<string>{}</string>\n", escape(&value)));
    }
    text.push_str("\t<key>NSHighResolutionCapable</key>\n\t<true/>\n</dict>\n</plist>\n");
    text
}

/// An `.icns` file of PNG images, given as (type, png) in the order to write them.
pub fn icns(images: &[(&[u8; 4], Vec<u8>)]) -> Result<Vec<u8>> {
    let total: usize = 8 + images.iter().map(|(_, png)| 8 + png.len()).sum::<usize>();
    let total = u32::try_from(total).map_err(|_| Error::new("icon too large"))?;
    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(b"icns");
    out.extend_from_slice(&total.to_be_bytes());
    for (kind, png) in images {
        let len = u32::try_from(8 + png.len()).map_err(|_| Error::new("icon image too large"))?;
        out.extend_from_slice(*kind);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(png);
    }
    Ok(out)
}

/// Renders every [`ICNS_ENTRIES`] size from the SVG and writes the `.icns`.
pub fn render_icns(svg: &[u8]) -> Result<Vec<u8>> {
    let mut images = Vec::new();
    for (kind, size) in ICNS_ENTRIES {
        images.push((kind, crate::icon::render_png(svg, size)?));
    }
    icns(&images)
}

/// The files of `CrewCraft.app`, with paths starting `CrewCraft.app/`. `docs` are the license files, placed in
/// `Contents/Resources/licenses/`.
pub fn app_files(version: &Version, binary: &[u8], icns: &[u8], docs: &[(String, Vec<u8>)]) -> Vec<TreeFile> {
    let contents = format!("{APP_DIR}/Contents");
    let mut files = vec![
        TreeFile::new(format!("{contents}/Info.plist"), 0o644, info_plist(version).into_bytes()),
        TreeFile::new(format!("{contents}/PkgInfo"), 0o644, b"APPL????".to_vec()),
        TreeFile::new(format!("{contents}/MacOS/crewcraft"), 0o755, binary),
        TreeFile::new(format!("{contents}/Resources/{ICON_FILE}"), 0o644, icns),
    ];
    for (name, data) in docs {
        files.push(TreeFile::new(format!("{contents}/Resources/licenses/{name}"), 0o644, data.clone()));
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files
}

/// The symbolic link beside the app in the disk image, so the app can be dragged onto it: (name, target).
pub const APPLICATIONS_LINK: (&str, &str) = ("Applications", "/Applications");

/// Writes the disk image's staging folder: the app and the `Applications` link.
pub fn write_staging(dir: &Path, app: &[TreeFile]) -> Result<()> {
    crate::appimage::write_appdir(dir, app)?;
    symlink(APPLICATIONS_LINK.1, &dir.join(APPLICATIONS_LINK.0))
}

#[cfg(unix)]
fn symlink(target: &str, link: &Path) -> Result<()> {
    std::os::unix::fs::symlink(target, link).context(|| format!("linking {}", link.display()))
}

#[cfg(not(unix))]
fn symlink(_target: &str, _link: &Path) -> Result<()> {
    Err(Error::new("the macOS disk image is built on macOS"))
}

/// Fails unless this is a Mac, where `lipo` and `hdiutil` exist.
pub fn require_macos() -> Result<()> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        Err(Error::new("--target macos-universal runs on macOS only: it builds with Apple's SDK and uses lipo and hdiutil (docs/RELEASE.md)"))
    }
}

fn run(command: &mut Command, what: &str) -> Result<()> {
    let output = command.output().context(|| format!("running {what}"))?;
    if !output.status.success() {
        return Err(Error::new(format!("{what} failed ({}): {}", output.status, String::from_utf8_lossy(&output.stderr).trim())));
    }
    Ok(())
}

/// Joins the per-architecture binaries into one universal binary with `lipo -create`.
pub fn lipo(inputs: &[&Path], output: &Path) -> Result<()> {
    run(Command::new("lipo").arg("-create").args(inputs).arg("-output").arg(output), "lipo")
}

/// Makes a compressed disk image (UDZO) of `staging` with `hdiutil create`.
pub fn hdiutil(staging: &Path, image: &Path) -> Result<()> {
    run(
        Command::new("hdiutil").args(["create", "-volname", VOLUME_NAME, "-srcfolder"]).arg(staging).args(["-ov", "-format", "UDZO"]).arg(image),
        "hdiutil",
    )
}
