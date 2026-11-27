//! `cargo xtask dist`: builds the release binaries for each target and writes the release assets and
//! `SHA256SUMS.txt` into the output folder.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::appimage;
use crate::archive::{self, TreeFile};
use crate::deb::{self, DebInput};
use crate::icon;
use crate::linkage;
use crate::macos;
use crate::names::{Asset, CLIENT, SERVER, Target};
use crate::sums;
use crate::version::Version;
use crate::windows_msi::{self, MsiInput};
use crate::{Context, Error, Result};

pub const USAGE: &str = "\
usage: cargo xtask dist --version <version> --out <dir> [--target linux-x86_64|windows-x86_64|macos-universal]...
                        [--appimage-runtime <file> | --no-appimage] [--receipt <file>]

Builds crewcraft and crewcraft-server in release mode for each target and writes the release assets and
SHA256SUMS.txt into <dir>. Without --target it builds linux-x86_64 and windows-x86_64, or macos-universal on a Mac
(which is the only place macos-universal builds). The Linux AppImage needs the pinned AppImage runtime, given with
--appimage-runtime or CREWCRAFT_APPIMAGE_RUNTIME; --no-appimage leaves it out. --receipt records a candidate build
from a clean Git checkout, with a separate receipt path and an empty output directory. See docs/RELEASE.md.";

/// The parsed `dist` command line.
#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    pub version: Version,
    pub out: PathBuf,
    pub targets: Vec<Target>,
    /// Where to write the optional candidate build receipt.
    pub receipt: Option<PathBuf>,
    /// The AppImage runtime file, from `--appimage-runtime` (or, when `None`, the environment at run time).
    pub appimage_runtime: Option<PathBuf>,
    /// False with `--no-appimage`.
    pub appimage: bool,
}

/// Parses the arguments after `dist`.
pub fn parse_args(args: &[String]) -> Result<Options> {
    let mut version = None;
    let mut out = None;
    let mut targets = Vec::new();
    let mut receipt = None;
    let mut appimage_runtime = None;
    let mut appimage = true;
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        let mut value = || rest.next().ok_or_else(|| Error::new(format!("{flag} needs a value\n\n{USAGE}")));
        match flag.as_str() {
            "--version" => version = Some(Version::parse(value()?)?),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--receipt" => receipt = Some(PathBuf::from(value()?)),
            "--appimage-runtime" => appimage_runtime = Some(PathBuf::from(value()?)),
            "--no-appimage" => appimage = false,
            "--target" => {
                let target = Target::parse(value()?)?;
                if !targets.contains(&target) {
                    targets.push(target);
                }
            }
            _ => return Err(Error::new(format!("unknown argument {flag:?}\n\n{USAGE}"))),
        }
    }
    let version = version.ok_or_else(|| Error::new(format!("--version is required\n\n{USAGE}")))?;
    let out = out.ok_or_else(|| Error::new(format!("--out is required\n\n{USAGE}")))?;
    if targets.is_empty() {
        targets = Target::host_default();
    }
    if !appimage && appimage_runtime.is_some() {
        return Err(Error::new(format!("--no-appimage and --appimage-runtime contradict each other\n\n{USAGE}")));
    }
    Ok(Options { version, out, targets, receipt, appimage_runtime, appimage })
}

/// The workspace root (the folder above `xtask/`).
pub fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().map(Path::to_path_buf).ok_or_else(|| Error::new("cannot find the workspace root"))
}

/// The time every archive entry carries: `SOURCE_DATE_EPOCH` when set, otherwise the time of the checked-out commit.
pub fn source_date_epoch(root: &Path) -> Result<u64> {
    if let Some(value) = env::var_os("SOURCE_DATE_EPOCH") {
        let text = value.to_str().ok_or_else(|| Error::new("SOURCE_DATE_EPOCH is not UTF-8"))?;
        return text.trim().parse().map_err(|_| Error::new(format!("SOURCE_DATE_EPOCH {text:?} is not a number of seconds")));
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["log", "-1", "--format=%ct"])
        .output()
        .context(|| "running git to read the commit time (or set SOURCE_DATE_EPOCH)".to_string())?;
    let text = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        return Err(Error::new("git could not read the commit time; set SOURCE_DATE_EPOCH"));
    }
    text.trim().parse().map_err(|_| Error::new(format!("git printed {:?} as the commit time; set SOURCE_DATE_EPOCH", text.trim())))
}

fn clean_head(root: &Path) -> Result<String> {
    let status = Command::new("git")
        .current_dir(root)
        .args(["status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none"])
        .output()
        .context(|| "running git to check the worktree".to_string())?;
    if !status.status.success() {
        return Err(Error::new("git could not check the worktree"));
    }
    if !status.stdout.is_empty() {
        return Err(Error::new("--receipt requires a clean Git worktree"));
    }
    let head =
        Command::new("git").current_dir(root).args(["rev-parse", "--verify", "HEAD"]).output().context(|| "running git to read HEAD".to_string())?;
    if !head.status.success() {
        return Err(Error::new("git could not read HEAD"));
    }
    let head = String::from_utf8_lossy(&head.stdout);
    let commit = head.trim();
    sums::validate_commit(commit)?;
    Ok(commit.to_string())
}

fn ensure_build_head(root: &Path, commit: &str) -> Result<()> {
    let actual = clean_head(root)?;
    if actual != commit {
        return Err(Error::new(format!("Git HEAD changed during the candidate build from {commit} to {actual}")));
    }
    Ok(())
}

fn check_candidate_output(out: &Path, receipt: &Path) -> Result<()> {
    match fs::symlink_metadata(receipt) {
        Ok(_) => return Err(Error::new(format!("receipt path already exists: {}", receipt.display()))),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error).context(|| format!("checking receipt path {}", receipt.display())),
    }
    let mut entries = fs::read_dir(out).context(|| format!("checking output directory {}", out.display()))?;
    if entries.next().is_some() {
        return Err(Error::new(format!("--receipt requires an empty output directory: {}", out.display())));
    }
    let out = fs::canonicalize(out).context(|| format!("resolving {}", out.display()))?;
    let parent = receipt.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).context(|| format!("resolving the folder for receipt {}", receipt.display()))?;
    if parent.starts_with(out) {
        return Err(Error::new("--receipt must be outside the package output directory"));
    }
    Ok(())
}

pub(crate) fn target_dir(root: &Path) -> PathBuf {
    match env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => root.join(dir),
        None => root.join("target"),
    }
}

/// The rustc flags for a release build: the caller's flags, plus path remapping so that no folder of the machine
/// that ran the build (the checkout, the cargo home) is written into the binaries.
pub(crate) fn release_rustflags(root: &Path) -> OsString {
    let mut flags: Vec<OsString> = match (env::var_os("CARGO_ENCODED_RUSTFLAGS"), env::var("RUSTFLAGS")) {
        (Some(encoded), _) if !encoded.is_empty() => encoded.to_string_lossy().split('\u{1f}').map(OsString::from).collect(),
        (_, Ok(plain)) => plain.split_whitespace().map(OsString::from).collect(),
        _ => Vec::new(),
    };
    let mut remap = |from: &Path, to: &str| {
        let mut flag = OsString::from("--remap-path-prefix=");
        flag.push(from.as_os_str());
        flag.push("=");
        flag.push(to);
        flags.push(flag);
    };
    remap(root, "/crewcraft");
    let cargo_home = env::var_os("CARGO_HOME").map(PathBuf::from).or_else(|| env::var_os("HOME").map(|home| Path::new(&home).join(".cargo")));
    if let Some(cargo_home) = cargo_home {
        remap(&cargo_home, "/cargo");
    }
    let mut encoded = OsString::new();
    for (at, flag) in flags.iter().enumerate() {
        if at > 0 {
            encoded.push("\u{1f}");
        }
        encoded.push(flag);
    }
    encoded
}

/// Builds both binaries for `target` and returns `(client, server)` paths. For macOS it builds each architecture,
/// checks each build, and joins them with `lipo` into a work folder.
fn cargo_build(root: &Path, target: Target, epoch: u64) -> Result<(PathBuf, PathBuf)> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let triples = target.triples();
    println!("== building {CLIENT} and {SERVER} for {} ({})", target.name(), triples.join(", "));
    let mut command = Command::new(&cargo);
    command.current_dir(root).args(["build", "--release", "--locked"]);
    for triple in triples {
        command.args(["--target", triple]);
    }
    let status = command
        .args(["-p", CLIENT, "-p", SERVER])
        .env("SOURCE_DATE_EPOCH", epoch.to_string())
        .env("CARGO_PROFILE_RELEASE_STRIP", "symbols")
        .env("CARGO_ENCODED_RUSTFLAGS", release_rustflags(root))
        .env_remove("RUSTFLAGS")
        .status()
        .context(|| "running cargo build".to_string())?;
    if !status.success() {
        return Err(Error::new(format!("cargo build for {} failed ({status})", target.name())));
    }
    let built = |triple: &str, name: &str| target_dir(root).join(triple).join("release").join(target.binary(name));
    match triples {
        [triple] => Ok((built(triple, CLIENT), built(triple, SERVER))),
        _ => {
            let work = work_dir(root, "universal")?;
            let mut joined = Vec::new();
            for name in [CLIENT, SERVER] {
                let parts: Vec<PathBuf> = triples.iter().map(|triple| built(triple, name)).collect();
                for (part, triple) in parts.iter().zip(triples) {
                    linkage::check_macho(&read(part)?, triple)?;
                }
                let output = work.join(name);
                macos::lipo(&parts.iter().map(PathBuf::as_path).collect::<Vec<_>>(), &output)?;
                joined.push(output);
            }
            let server = joined.pop().ok_or_else(|| Error::new("no universal server"))?;
            let client = joined.pop().ok_or_else(|| Error::new("no universal client"))?;
            Ok((client, server))
        }
    }
}

pub(crate) fn read(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).context(|| format!("reading {}", path.display()))
}

/// The license and notice files every package carries, as `(file name, contents)`. `with_font` adds the font
/// license when the client bundles a font. `txt` gives each name a `.txt` extension, for Windows.
pub(crate) fn license_files(root: &Path, with_font: bool, txt: bool) -> Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::new();
    for name in ["LICENSE-MIT", "LICENSE-APACHE", "NOTICE"] {
        files.push((name.to_string(), read(&root.join(name))?));
    }
    let font_license = root.join("assets/fonts/OFL.txt");
    if with_font && font_license.is_file() {
        files.push(("OFL.txt".to_string(), read(&font_license)?));
    }
    if txt {
        for (name, _) in &mut files {
            if !name.ends_with(".txt") {
                name.push_str(".txt");
            }
        }
    }
    Ok(files)
}

/// The server archive's files: the binary, the license files and the README.
pub fn server_files(binary_name: &str, binary: &[u8], docs: &[(String, Vec<u8>)], readme: &str) -> Vec<TreeFile> {
    let mut files = vec![TreeFile::new(binary_name, 0o755, binary), TreeFile::new("README.txt", 0o644, readme.as_bytes())];
    files.extend(docs.iter().map(|(name, data)| TreeFile::new(name.clone(), 0o644, data.clone())));
    files
}

/// The README that ships in the server archives.
pub const SERVER_README: &str = include_str!("../assets/server-README.txt");

pub(crate) fn write_asset(out: &Path, name: &str, data: &[u8], executable: bool) -> Result<()> {
    let partial = out.join(format!(".{name}.partial"));
    fs::write(&partial, data).context(|| format!("writing {}", partial.display()))?;
    if executable {
        appimage::set_mode(&partial, 0o755)?;
    }
    fs::rename(&partial, out.join(name)).context(|| format!("writing {name}"))?;
    println!("   {name} ({} bytes)", data.len());
    Ok(())
}

/// The pinned AppImage runtime, from `--appimage-runtime` or `CREWCRAFT_APPIMAGE_RUNTIME`, checked against its
/// SHA-256 before anything is built.
fn appimage_runtime(options: &Options) -> Result<Vec<u8>> {
    let path = options.appimage_runtime.clone().or_else(|| env::var_os(appimage::RUNTIME_ENV).map(PathBuf::from)).ok_or_else(|| {
        Error::new(format!(
            "the AppImage needs the AppImage runtime {} ({}): pass --appimage-runtime <file> or set {}, or leave the AppImage out with --no-appimage",
            appimage::RUNTIME_VERSION,
            appimage::RUNTIME_URL,
            appimage::RUNTIME_ENV
        ))
    })?;
    let runtime = read(&path)?;
    appimage::check_runtime(&runtime)?;
    println!("== AppImage runtime {} verified: {}", appimage::RUNTIME_VERSION, path.display());
    Ok(runtime)
}

/// A new, empty work folder under the target folder.
pub(crate) fn work_dir(root: &Path, name: &str) -> Result<PathBuf> {
    let dir = target_dir(root).join("xtask-dist").join(name);
    if dir.exists() {
        fs::remove_dir_all(&dir).context(|| format!("clearing {}", dir.display()))?;
    }
    fs::create_dir_all(&dir).context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

fn build_target(root: &Path, options: &Options, target: Target, epoch: u64, runtime: Option<&[u8]>, commit: Option<&str>) -> Result<()> {
    if let Some(commit) = commit {
        ensure_build_head(root, commit)?;
    }
    let (client_path, server_path) = cargo_build(root, target, epoch)?;
    if let Some(commit) = commit {
        ensure_build_head(root, commit)?;
    }
    let client = read(&client_path)?;
    let server = read(&server_path)?;
    let svg = read(&root.join("assets/icon/crewcraft.svg"))?;
    let version = &options.version;
    let mut depends = Vec::new();
    if target == Target::LinuxX86_64 {
        let links = linkage::elf_links(&client)?;
        depends = linkage::debian_depends(&links)?;
        println!("   {CLIENT} links {}", links.needed.join(", "));
        depends.extend(deb::WINDOW_DEPENDS.iter().map(|entry| entry.to_string()));
    }
    let pngs = icon::render_sizes(&svg, &icon::HICOLOR_SIZES)?;
    let linux_docs = license_files(root, true, false)?;
    let client_input = DebInput {
        version,
        binary: &client,
        depends: &depends,
        recommends: &deb::WINDOW_RECOMMENDS,
        svg: &svg,
        pngs: &pngs,
        docs: &linux_docs,
        mtime: epoch,
    };
    for &asset in target.assets() {
        let data = match asset {
            Asset::ClientDeb => {
                println!("   Depends: {}", depends.join(", "));
                deb::build(&client_input)?
            }
            Asset::ClientAppImage => {
                let Some(runtime) = runtime else {
                    println!("   {} left out (--no-appimage)", asset.file_name(version));
                    continue;
                };
                let work = work_dir(root, "appimage")?;
                let appdir = work.join("AppDir");
                let top_icon = icon::render_png(&svg, appimage::TOP_ICON_SIZE)?;
                let runtime_license = read(&root.join(appimage::RUNTIME_LICENSE_FILE))?;
                let lgpl = fs::read(appimage::LGPL_FILE)
                    .context(|| format!("reading {} (Debian package base-files) for the runtime's libfuse code", appimage::LGPL_FILE))?;
                appimage::write_appdir(&appdir, &appimage::appdir_files(&client_input, &top_icon, &runtime_license, &lgpl))?;
                let image = work.join(format!("{CLIENT}.squashfs"));
                appimage::mksquashfs(&appdir, &image, epoch)?;
                appimage::assemble(runtime, &read(&image)?)
            }
            Asset::ServerTarGz | Asset::ServerMacTarGz => {
                if asset == Asset::ServerTarGz {
                    let links = linkage::elf_links(&server)?;
                    println!("   {SERVER} links {}", links.needed.join(", "));
                }
                let files = server_files(SERVER, &server, &license_files(root, false, false)?, SERVER_README);
                archive::tar_gz(&files, &format!("{}/", asset.stem(version)), epoch)?
            }
            Asset::ClientDmg => {
                let work = work_dir(root, "dmg")?;
                let staging = work.join(macos::VOLUME_NAME);
                let app = macos::app_files(version, &client, &macos::render_icns(&svg)?, &linux_docs);
                macos::write_staging(&staging, &app)?;
                macos::adhoc_sign(&staging.join(macos::APP_DIR))?;
                let image = work.join(asset.file_name(version));
                macos::hdiutil(&staging, &image)?;
                read(&image)?
            }
            Asset::ClientMsi => {
                let dlls = linkage::pe_imports(&client)?;
                linkage::check_windows_imports(&dlls)?;
                println!("   {} imports {}", target.binary(CLIENT), dlls.join(", "));
                let ico = icon::ico(&icon::render_sizes(&svg, &icon::ICO_SIZES)?)?;
                let docs = license_files(root, true, true)?;
                windows_msi::build(&MsiInput { version, exe: &client, docs: &docs, ico: &ico, mtime: epoch })?
            }
            Asset::ServerZip => {
                let dlls = linkage::pe_imports(&server)?;
                linkage::check_windows_imports(&dlls)?;
                println!("   {} imports {}", target.binary(SERVER), dlls.join(", "));
                let files = server_files(&target.binary(SERVER), &server, &license_files(root, false, true)?, SERVER_README);
                archive::zip(&files, &format!("{}/", asset.stem(version)), epoch)?
            }
        };
        write_asset(&options.out, &asset.file_name(version), &data, asset == Asset::ClientAppImage)?;
    }
    Ok(())
}

/// Runs `dist`, then writes `SHA256SUMS.txt` and the candidate receipt if requested.
pub fn run(options: &Options) -> Result<()> {
    let root = workspace_root()?;
    // xtask shares the workspace version, which is what the binaries print for --version.
    let built = env!("CARGO_PKG_VERSION");
    if built != options.version.to_string() {
        let message = format!("the binaries report version {built}, not {}; set workspace.package.version before a release", options.version);
        if options.receipt.is_some() {
            return Err(Error::new(message));
        }
        println!("warning: {message}");
    }
    let linux = options.targets.contains(&Target::LinuxX86_64);
    let candidate = if let Some(receipt) = &options.receipt {
        if linux && !options.appimage {
            return Err(Error::new("--receipt requires an AppImage for Linux targets"));
        }
        Some((receipt, clean_head(&root)?))
    } else {
        None
    };
    let epoch = source_date_epoch(&root)?;
    if options.targets.contains(&Target::MacosUniversal) {
        macos::require_macos()?;
    }
    let runtime = if options.appimage && linux { Some(appimage_runtime(options)?) } else { None };
    fs::create_dir_all(&options.out).context(|| format!("creating {}", options.out.display()))?;
    if let Some((receipt, _)) = &candidate {
        check_candidate_output(&options.out, receipt)?;
    }
    for &target in &options.targets {
        let commit = candidate.as_ref().map(|(_, commit)| commit.as_str());
        build_target(&root, options, target, epoch, runtime.as_deref(), commit)?;
    }
    let text = sums::write_sums(&options.out)?;
    if let Some((receipt, commit)) = candidate {
        ensure_build_head(&root, &commit)?;
        sums::write_build_receipt(receipt, &commit, &options.version, &text)?;
    }
    println!("== {} in {}\n{text}", sums::SUMS_FILE, options.out.display());
    Ok(())
}
