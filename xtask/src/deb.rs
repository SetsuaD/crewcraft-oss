//! The desktop client as a Debian package, written directly: an `ar` archive of `debian-binary` (`2.0`),
//! `control.tar.gz` (`control`, `md5sums`) and `data.tar.gz` (the installed files).
//!
//! Installed files: `/usr/bin/crewcraft`, the desktop entry, the icon (scalable SVG and PNG sizes in the hicolor
//! theme) and the license files under `/usr/share/doc/crewcraft/`.

use md5::{Digest, Md5};

use crate::archive::{self, TreeFile};
use crate::names::CLIENT;
use crate::version::Version;
use crate::{Error, Result};

/// The desktop entry installed as `/usr/share/applications/crewcraft.desktop`.
pub const DESKTOP_ENTRY: &str = include_str!("../assets/crewcraft.desktop");

/// Libraries the desktop window loads at run time (winit and glutin open them with `dlopen` instead of linking
/// them), so the `Depends:` read from the binary cannot see them. The window cannot open without OpenGL (EGL on
/// Wayland, GLX on X11), the keyboard map, and either the Wayland or the X11 client library.
pub const WINDOW_DEPENDS: [&str; 4] = ["libegl1", "libgl1", "libxkbcommon0", "libwayland-client0 | libx11-6"];

/// The rest of the two display stacks winit and glutin load at run time (the `lib*.so.N` names in the built binary):
/// EGL surfaces on Wayland, and XCB with its Xlib bridge, cursors, input, rendering and the keyboard extension on X11.
/// Each desktop needs one of the two sets, so they are `Recommends:`, which apt installs by default.
pub const WINDOW_RECOMMENDS: [&str; 7] = ["libwayland-egl1", "libxcb1", "libx11-xcb1", "libxcursor1", "libxi6", "libxrender1", "libxkbcommon-x11-0"];

/// What goes into the client's `.deb`.
pub struct DebInput<'a> {
    pub version: &'a Version,
    /// The `crewcraft` binary.
    pub binary: &'a [u8],
    /// `Depends:` entries, from [`crate::linkage::debian_depends`].
    pub depends: &'a [String],
    /// `Recommends:` entries.
    pub recommends: &'a [&'a str],
    /// `assets/icon/crewcraft.svg`.
    pub svg: &'a [u8],
    /// PNG renderings of the icon as `(size, png)`.
    pub pngs: &'a [(u32, Vec<u8>)],
    /// License and notice files as `(file name, contents)`, installed in `/usr/share/doc/crewcraft/`.
    pub docs: &'a [(String, Vec<u8>)],
    /// The time every entry carries (the release's source date).
    pub mtime: u64,
}

/// The Debian copyright file, pointing at the license files installed next to it.
fn copyright() -> String {
    "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\
     Upstream-Name: CrewCraft\n\
     Source: https://github.com/SetsuaD/crewcraft-oss\n\
     \n\
     Files: *\n\
     Copyright: 2026 the CrewCraft contributors (see /usr/share/doc/crewcraft/NOTICE)\n\
     License: MIT or Apache-2.0\n \
     CrewCraft is licensed under either of the MIT license or the Apache License, Version 2.0, at your option.\n \
     The full texts are in /usr/share/doc/crewcraft/LICENSE-MIT and /usr/share/doc/crewcraft/LICENSE-APACHE.\n"
        .to_string()
}

/// The files of `data.tar.gz`, without the leading `./`.
pub fn data_files(input: &DebInput<'_>) -> Vec<TreeFile> {
    let mut files = vec![
        TreeFile::new(format!("usr/bin/{CLIENT}"), 0o755, input.binary),
        TreeFile::new(format!("usr/share/applications/{CLIENT}.desktop"), 0o644, DESKTOP_ENTRY.as_bytes()),
        TreeFile::new(format!("usr/share/icons/hicolor/scalable/apps/{CLIENT}.svg"), 0o644, input.svg),
        TreeFile::new(format!("usr/share/doc/{CLIENT}/copyright"), 0o644, copyright().into_bytes()),
    ];
    for (size, png) in input.pngs {
        files.push(TreeFile::new(format!("usr/share/icons/hicolor/{size}x{size}/apps/{CLIENT}.png"), 0o644, png.clone()));
    }
    for (name, data) in input.docs {
        files.push(TreeFile::new(format!("usr/share/doc/{CLIENT}/{name}"), 0o644, data.clone()));
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files
}

/// `Installed-Size:` as dpkg counts it: each file's size rounded up to KiB, plus one KiB per folder.
fn installed_kib(files: &[TreeFile]) -> u64 {
    let mut dirs = std::collections::BTreeSet::new();
    for file in files {
        let mut end = 0;
        while let Some(slash) = file.path[end..].find('/') {
            end += slash + 1;
            dirs.insert(&file.path[..end]);
        }
    }
    files.iter().map(|file| (file.data.len() as u64).div_ceil(1024)).sum::<u64>() + dirs.len() as u64
}

/// The `control` file.
pub fn control(input: &DebInput<'_>, files: &[TreeFile]) -> Result<String> {
    for entry in input.depends.iter().map(String::as_str).chain(input.recommends.iter().copied()) {
        if entry.is_empty() || entry.contains([',', '\n']) {
            return Err(Error::new(format!("{entry:?} is not one Debian relation")));
        }
    }
    let mut text = format!(
        "Package: {CLIENT}\nVersion: {}\nArchitecture: amd64\nMaintainer: CrewCraft contributors <https://github.com/SetsuaD/crewcraft-oss/issues>\nInstalled-Size: {}\n",
        input.version.debian(),
        installed_kib(files)
    );
    if !input.depends.is_empty() {
        text.push_str(&format!("Depends: {}\n", input.depends.join(", ")));
    }
    if !input.recommends.is_empty() {
        text.push_str(&format!("Recommends: {}\n", input.recommends.join(", ")));
    }
    text.push_str(
        "Section: net\n\
         Priority: optional\n\
         Homepage: https://github.com/SetsuaD/crewcraft-oss\n\
         Description: self-hosted team chat (desktop client)\n \
         CrewCraft is self-hosted team chat on a server you own. This is the desktop\n \
         client: it enrolls the device from a one-time code, signs in with an\n \
         authenticator-app code and chats in the server's rooms.\n",
    );
    Ok(text)
}

/// The `md5sums` file: one line per installed file, as `dpkg --verify` reads it.
pub fn md5sums(files: &[TreeFile]) -> String {
    files
        .iter()
        .map(|file| {
            let digest: String = Md5::digest(&file.data).iter().map(|byte| format!("{byte:02x}")).collect();
            format!("{digest}  {}\n", file.path)
        })
        .collect()
}

/// The finished `.deb`.
pub fn build(input: &DebInput<'_>) -> Result<Vec<u8>> {
    let files = data_files(input);
    let control_files =
        vec![TreeFile::new("control", 0o644, control(input, &files)?.into_bytes()), TreeFile::new("md5sums", 0o644, md5sums(&files).into_bytes())];
    let control_tar = archive::tar_gz(&control_files, "./", input.mtime)?;
    let data_tar = archive::tar_gz(&files, "./", input.mtime)?;
    archive::ar(&[("debian-binary", b"2.0\n"), ("control.tar.gz", &control_tar), ("data.tar.gz", &data_tar)], input.mtime)
}
