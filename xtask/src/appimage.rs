//! The desktop client as an AppImage: the pinned AppImage type2 runtime followed by a SquashFS image of the AppDir.
//!
//! The runtime is a prebuilt program from the AppImage project (docs/NON-RUST-DEPENDENCIES.md). It is never fetched:
//! the person running the build passes its path (`--appimage-runtime` or `CREWCRAFT_APPIMAGE_RUNTIME`), and the build
//! refuses any file whose SHA-256 is not the pinned one. The SquashFS image is written by `mksquashfs` (Debian package
//! `squashfs-tools`), with every file owned by root and one fixed time, so the image is reproducible.
//!
//! The AppDir holds the same files as the `.deb` (under `usr/`), plus what the runtime and desktop integration look for
//! at the top: `AppRun` (a copy of the program; the image stores it once), `crewcraft.desktop`, `crewcraft.png` and
//! `.DirIcon`, and the runtime's license, the LGPL 2.1 for its libfuse code, and where its source is.

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::archive::TreeFile;
use crate::deb::{self, DebInput};
use crate::names::CLIENT;
use crate::sums::sha256_hex;
use crate::{Context, Error, Result};

/// The pinned runtime: release 20251108 of the AppImage type2 runtime, file `runtime-x86_64` (MIT).
pub const RUNTIME_VERSION: &str = "20251108";
pub const RUNTIME_URL: &str = "https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64";
pub const RUNTIME_SHA256: &str = "2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d";
/// The environment variable that can name the runtime instead of `--appimage-runtime`.
pub const RUNTIME_ENV: &str = "CREWCRAFT_APPIMAGE_RUNTIME";
/// The icon size at the top of the AppDir.
pub const TOP_ICON_SIZE: u32 = 256;

/// Fails unless `runtime` is the pinned runtime.
pub fn check_runtime(runtime: &[u8]) -> Result<()> {
    let digest = sha256_hex(runtime);
    if digest != RUNTIME_SHA256 {
        return Err(Error::new(format!(
            "the AppImage runtime has SHA-256 {digest}, not the pinned {RUNTIME_SHA256} (release {RUNTIME_VERSION}, {RUNTIME_URL})"
        )));
    }
    Ok(())
}

/// The runtime's own license (MIT, with its list of statically linked libraries), from the runtime's repository at
/// the pinned tag; committed as `assets/appimage/RUNTIME-LICENSE.txt`.
pub const RUNTIME_LICENSE_FILE: &str = "assets/appimage/RUNTIME-LICENSE.txt";
/// The GNU LGPL 2.1 text for the libfuse code in the runtime, read at build time from Debian's `base-files`.
pub const LGPL_FILE: &str = "/usr/share/common-licenses/LGPL-2.1";
/// Where the runtime's license files go in the AppDir.
pub const RUNTIME_LICENSE_DIR: &str = "usr/share/licenses/appimage-runtime";

/// `SOURCE.txt` beside the runtime's licenses: where its source is, and how to replace it.
pub fn runtime_source_note() -> String {
    format!(
        "The program at the start of this AppImage, before the image of the app, is the AppImage type2 runtime,\n\
         release {RUNTIME_VERSION}, unmodified:\n\
         \x20   https://github.com/AppImage/type2-runtime/releases/tag/{RUNTIME_VERSION}\n\
         \x20   file runtime-x86_64, SHA-256 {RUNTIME_SHA256}\n\
         \n\
         It is built from https://github.com/AppImage/type2-runtime/tree/{RUNTIME_VERSION} and links statically\n\
         libfuse (GNU LGPL 2.1, the text is in LGPL-2.1 here), musl libc, squashfuse, zstd and zlib (their terms are\n\
         listed in LICENSE here). Their sources and the build scripts are at that tag.\n\
         \n\
         Anyone may rebuild the runtime from those sources, or modify it, and use it in place of this one: unpack this\n\
         AppImage with --appimage-extract, then join the new runtime and a SquashFS image of squashfs-root again, as\n\
         CrewCraft's docs/RELEASE.md describes (cargo xtask dist does the same with a runtime you give it).\n"
    )
}

/// The AppDir's files: the `.deb` files plus `AppRun`, the top-level desktop entry, `crewcraft.png` and `.DirIcon`,
/// and the runtime's `LICENSE`, `LGPL-2.1` and `SOURCE.txt` in [`RUNTIME_LICENSE_DIR`]. `top_icon` is the PNG for
/// the top of the AppDir.
pub fn appdir_files(input: &DebInput<'_>, top_icon: &[u8], runtime_license: &[u8], lgpl: &[u8]) -> Vec<TreeFile> {
    let mut files = deb::data_files(input);
    files.push(TreeFile::new("AppRun", 0o755, input.binary));
    files.push(TreeFile::new(format!("{CLIENT}.desktop"), 0o644, deb::DESKTOP_ENTRY.as_bytes()));
    files.push(TreeFile::new(format!("{CLIENT}.png"), 0o644, top_icon));
    files.push(TreeFile::new(".DirIcon", 0o644, top_icon));
    files.push(TreeFile::new(format!("{RUNTIME_LICENSE_DIR}/LICENSE"), 0o644, runtime_license));
    files.push(TreeFile::new(format!("{RUNTIME_LICENSE_DIR}/LGPL-2.1"), 0o644, lgpl));
    files.push(TreeFile::new(format!("{RUNTIME_LICENSE_DIR}/SOURCE.txt"), 0o644, runtime_source_note().into_bytes()));
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files
}

/// Writes `files` under the new, empty folder `dir`, with each file's mode and every folder `0755`.
pub fn write_appdir(dir: &Path, files: &[TreeFile]) -> Result<()> {
    fs::create_dir(dir).context(|| format!("creating {}", dir.display()))?;
    for file in files {
        let path = dir.join(&file.path);
        let mut parent = path.parent();
        let mut created = Vec::new();
        while let Some(folder) = parent {
            if folder == dir || folder.exists() {
                break;
            }
            created.push(folder.to_path_buf());
            parent = folder.parent();
        }
        for folder in created.iter().rev() {
            fs::create_dir(folder).context(|| format!("creating {}", folder.display()))?;
            set_mode(folder, 0o755)?;
        }
        fs::write(&path, &file.data).context(|| format!("writing {}", path.display()))?;
        set_mode(&path, file.mode)?;
    }
    set_mode(dir, 0o755)
}

#[cfg(unix)]
pub(crate) fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).context(|| format!("setting the mode of {}", path.display()))
}

#[cfg(not(unix))]
pub(crate) fn set_mode(_path: &Path, _mode: u32) -> Result<()> {
    Err(Error::new("the Linux packages keep Unix file modes, so they are built on Linux"))
}

/// Packs `appdir` into the SquashFS image `image` with `mksquashfs`: zstd, root-owned, no extended attributes, and
/// `mtime` as every file's time and the image's time.
pub fn mksquashfs(appdir: &Path, image: &Path, mtime: u64) -> Result<()> {
    let output = Command::new("mksquashfs")
        .arg(appdir)
        .arg(image)
        .args(["-noappend", "-root-owned", "-no-xattrs", "-comp", "zstd", "-b", "1M", "-no-progress"])
        .args(["-mkfs-time", &mtime.to_string(), "-all-time", &mtime.to_string()])
        // mksquashfs refuses SOURCE_DATE_EPOCH together with the time options above.
        .env_remove("SOURCE_DATE_EPOCH")
        .output()
        .context(|| "running mksquashfs (Debian package squashfs-tools; see docs/RELEASE.md)".to_string())?;
    if !output.status.success() {
        return Err(Error::new(format!("mksquashfs failed ({}): {}", output.status, String::from_utf8_lossy(&output.stderr).trim())));
    }
    Ok(())
}

/// The AppImage: the runtime, then the SquashFS image.
pub fn assemble(runtime: &[u8], image: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(runtime.len() + image.len());
    out.extend_from_slice(runtime);
    out.extend_from_slice(image);
    out
}
