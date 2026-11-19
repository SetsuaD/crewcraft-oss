//! `cargo xtask apk`: the Android app, an APK around a `NativeActivity` with no Java or Kotlin source. Task T400.
//!
//! The app is `apps/crewcraft-android`, built as a shared library (`libcrewcraft_android.so`) for one Android ABI
//! with the Android NDK's linker. Android's own `android.app.NativeActivity` loads it (the manifest names it in
//! `android.app.lib_name`) and the library runs the same egui window as the desktop app (T401). The APK has no
//! `classes.dex` (`android:hasCode="false"`).
//!
//! What is Rust and what is not: the manifest text, the icon PNGs (rendered from `assets/icon/crewcraft.svg`), the
//! APK zip with its alignment and the v2 signature are written here and in [`crate::apk`]. Two Android SDK tools
//! run: the NDK's `clang` links the library (Rust's Android targets link through it) and `aapt2` compiles the
//! manifest and the icon into Android's binary XML and resource table (`aapt2 link --output-to-dir`). With a release
//! keystore (`--keystore`) the APK is signed by the build-tools' `apksigner` instead. docs/NON-RUST-DEPENDENCIES.md lists them.
//!
//! Called by: `main.rs`. Calls: cargo, `aapt2`, `apksigner` (only with `--keystore`), [`crate::apk`],
//! [`crate::icon`], [`crate::version`] and the shared helpers of [`crate::dist`].

use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use object::read::elf::{Dyn, FileHeader};
use object::{Architecture, BinaryFormat, Object, ObjectSymbol, elf};

use crate::apk::{self, ApkEntry, LIBRARY_ALIGN, STORED_ALIGN, SigningKey, Storage};
use crate::dist;
use crate::icon;
use crate::version::Version;
use crate::{Context, Error, Result};

/// The application ID, the same reverse-domain name as the macOS bundle identifier.
pub const PACKAGE: &str = "io.github.setsuad.crewcraft";
/// Android 10 (docs/SPEC.md decision D4).
pub const MIN_SDK: u32 = 29;
/// The platform the APK is compiled and targeted against (`platforms;android-34`).
pub const TARGET_SDK: u32 = 34;
/// The app crate and its library name, which the manifest's `android.app.lib_name` names.
pub const APP_CRATE: &str = "crewcraft-android";
pub const LIB_NAME: &str = "crewcraft_android";
/// The icon's resource name (`@mipmap/crewcraft`).
pub const ICON: &str = "crewcraft";
/// The launcher icon densities and their sizes in pixels (48 dp at each density).
pub const MIPMAPS: [(&str, u32); 5] = [("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144), ("xxxhdpi", 192)];
/// The environment variable that holds the password of a `--keystore`, passed to `apksigner` by name.
pub const KEYSTORE_PASS_ENV: &str = "CREWCRAFT_APK_KEYSTORE_PASS";
/// The symbol Android's `NativeActivity` calls in the library (from `android-activity`), which starts the app's
/// entry point.
pub const ENTRY_SYMBOL: &str = "ANativeActivity_onCreate";
/// The app's entry point, which `android-activity` calls; it must be defined in the library, not left to the loader.
pub const MAIN_SYMBOL: &str = "android_main";
/// The libraries the app may link: the NDK's stable system libraries, which every Android 10 phone has. Anything
/// else (such as `libc++_shared.so`) would have to ship in the APK, so the build fails on it.
pub const SYSTEM_LIBRARIES: [&str; 9] =
    ["libandroid.so", "libc.so", "libdl.so", "libEGL.so", "libGLESv2.so", "libGLESv3.so", "liblog.so", "libm.so", "libnativewindow.so"];

pub const USAGE: &str = "\
usage: cargo xtask apk --version <version> --out <dir> [--target aarch64|x86_64]
                       [--keystore <file> --key-alias <alias>]

Builds the Android app (apps/crewcraft-android) for one ABI, aarch64 (phones, the default) or x86_64 (the
emulator), and writes crewcraft-<version>-android-<arch>.apk into <dir>. Needs ANDROID_HOME (the SDK, with
build-tools and platforms;android-34) and the NDK (ANDROID_NDK_HOME, or the newest under $ANDROID_HOME/ndk).

Without --keystore the APK is signed with a test key, made on the first build and kept under the target folder
(target/xtask-apk/test-signing-key/), so later test builds install over earlier ones. --keystore signs with a
release key instead, through the build-tools' apksigner; the keystore's password is read from
CREWCRAFT_APK_KEYSTORE_PASS. See docs/RELEASE.md.";

/// An Android ABI the app is built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Abi {
    Aarch64,
    X86_64,
}

impl Abi {
    pub fn parse(text: &str) -> Result<Abi> {
        match text {
            "aarch64" | "arm64-v8a" => Ok(Abi::Aarch64),
            "x86_64" => Ok(Abi::X86_64),
            _ => Err(Error::new(format!("unknown Android target {text:?}: expected aarch64 or x86_64"))),
        }
    }

    /// The name in the asset file name.
    pub fn name(self) -> &'static str {
        match self {
            Abi::Aarch64 => "aarch64",
            Abi::X86_64 => "x86_64",
        }
    }

    pub fn triple(self) -> &'static str {
        match self {
            Abi::Aarch64 => "aarch64-linux-android",
            Abi::X86_64 => "x86_64-linux-android",
        }
    }

    /// The folder under `lib/` in the APK, Android's name for the ABI.
    pub fn lib_dir(self) -> &'static str {
        match self {
            Abi::Aarch64 => "arm64-v8a",
            Abi::X86_64 => "x86_64",
        }
    }

    fn architecture(self) -> Architecture {
        match self {
            Abi::Aarch64 => Architecture::Aarch64,
            Abi::X86_64 => Architecture::X86_64,
        }
    }
}

/// The asset name, `crewcraft-<version>-android-<arch>.apk`.
pub fn file_name(version: &Version, abi: Abi) -> String {
    format!("crewcraft-{version}-android-{}.apk", abi.name())
}

/// The path of the library inside the APK.
pub fn library_path(abi: Abi) -> String {
    format!("lib/{}/lib{LIB_NAME}.so", abi.lib_dir())
}

/// `AndroidManifest.xml` (as text; `aapt2` compiles it). One `NativeActivity` that loads the app's library and is
/// the launcher entry; the INTERNET permission and nothing else; no Java code; no backups of the app's data (it
/// will hold the device's enrollment); the window resizes for the soft keyboard and is not restarted by rotation,
/// a keyboard or a size change (egui redraws at the new size).
pub fn manifest(version: &Version) -> Result<String> {
    let code = version.android_version_code()?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{PACKAGE}"
    android:versionCode="{code}"
    android:versionName="{version}">
    <uses-sdk android:minSdkVersion="{MIN_SDK}" android:targetSdkVersion="{TARGET_SDK}" />
    <uses-permission android:name="android.permission.INTERNET" />
    <application
        android:label="CrewCraft"
        android:icon="@mipmap/{ICON}"
        android:hasCode="false"
        android:allowBackup="false"
        android:extractNativeLibs="false">
        <activity
            android:name="android.app.NativeActivity"
            android:label="CrewCraft"
            android:exported="true"
            android:launchMode="singleTask"
            android:theme="@android:style/Theme.DeviceDefault.NoActionBar"
            android:windowSoftInputMode="adjustResize"
            android:configChanges="orientation|screenSize|screenLayout|smallestScreenSize|keyboard|keyboardHidden|navigation|density|uiMode">
            <meta-data android:name="android.app.lib_name" android:value="{LIB_NAME}" />
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
"#
    ))
}

/// The launcher icon at every density, as `(path under res/, png)`: `res/mipmap-<density>/crewcraft.png`.
pub fn icon_resources(svg: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    MIPMAPS.iter().map(|&(density, size)| Ok((format!("res/mipmap-{density}/{ICON}.png"), icon::render_png(svg, size)?))).collect()
}

/// The APK's entries, in order: the compiled manifest, the resource table, the compiled resources, the license
/// files under `assets/licenses/`, and the library. `linked` is what `aapt2 link --output-to-dir` wrote, as
/// `(path, contents)`; it must hold `AndroidManifest.xml` and `resources.arsc`. The resource table, images and
/// library are stored (aligned) and everything else deflated.
pub fn apk_entries(linked: &[(String, Vec<u8>)], licenses: &[(String, Vec<u8>)], abi: Abi, library: &[u8]) -> Result<Vec<ApkEntry>> {
    let mut linked: Vec<&(String, Vec<u8>)> = linked.iter().collect();
    linked.sort_by(|a, b| a.0.cmp(&b.0));
    let mut entries = Vec::new();
    for first in ["AndroidManifest.xml", "resources.arsc"] {
        let at = linked.iter().position(|(path, _)| path == first).ok_or_else(|| Error::new(format!("aapt2 did not write {first}")))?;
        let (path, data) = linked.remove(at);
        let storage = if first == "resources.arsc" { Storage::Stored { align: STORED_ALIGN } } else { Storage::Deflated };
        entries.push(ApkEntry::new(path.clone(), data.clone(), storage));
    }
    for (path, data) in linked {
        if path.starts_with("lib/") || path.starts_with("assets/") || path.starts_with("META-INF/") || path.ends_with(".dex") {
            return Err(Error::new(format!("aapt2 wrote an unexpected file {path}")));
        }
        let storage = if path.ends_with(".png") { Storage::Stored { align: STORED_ALIGN } } else { Storage::Deflated };
        entries.push(ApkEntry::new(path.clone(), data.clone(), storage));
    }
    for (name, data) in licenses {
        entries.push(ApkEntry::new(format!("assets/licenses/{name}"), data.clone(), Storage::Deflated));
    }
    entries.push(ApkEntry::new(library_path(abi), library.to_vec(), Storage::Stored { align: LIBRARY_ALIGN }));
    Ok(entries)
}

/// Checks the built library: a 64-bit ELF shared object for `abi` that exports [`ENTRY_SYMBOL`], does not leave
/// [`MAIN_SYMBOL`] undefined, and links only [`SYSTEM_LIBRARIES`]. Returns the libraries it links.
pub fn check_library(data: &[u8], abi: Abi) -> Result<Vec<String>> {
    let error = |error: object::Error| Error::new(format!("reading the app library: {error}"));
    let file = object::File::parse(data).map_err(error)?;
    if file.format() != BinaryFormat::Elf || file.architecture() != abi.architecture() || !file.is_64() {
        return Err(Error::new(format!(
            "expected a 64-bit {:?} ELF library, found {:?} {:?}",
            abi.architecture(),
            file.format(),
            file.architecture()
        )));
    }
    let header = elf::FileHeader64::<object::Endianness>::parse(data).map_err(error)?;
    let endian = header.endian().map_err(error)?;
    if header.e_type(endian) != elf::ET_DYN {
        return Err(Error::new("the app library is not a shared object"));
    }
    if !file.dynamic_symbols().any(|symbol| symbol.is_definition() && symbol.is_global() && symbol.name().is_ok_and(|name| name == ENTRY_SYMBOL)) {
        return Err(Error::new(format!("the app library does not export {ENTRY_SYMBOL}")));
    }
    if file.dynamic_symbols().any(|symbol| symbol.is_undefined() && symbol.name().is_ok_and(|name| name == MAIN_SYMBOL)) {
        return Err(Error::new(format!("the app library does not define {MAIN_SYMBOL}")));
    }
    let sections = header.sections(endian, data).map_err(error)?;
    let mut needed = Vec::new();
    if let Some((dynamic, link)) = sections.dynamic(endian, data).map_err(error)? {
        let strings = sections.strings(endian, data, link).map_err(error)?;
        for entry in dynamic {
            if entry.tag32(endian) == Some(elf::DT_NEEDED) {
                let name = entry.string(endian, strings).map_err(error)?;
                needed.push(String::from_utf8_lossy(name).into_owned());
            }
        }
    }
    if let Some(other) = needed.iter().find(|name| !SYSTEM_LIBRARIES.contains(&name.as_str())) {
        return Err(Error::new(format!("the app library links {other}, which is not an Android system library and is not in the APK")));
    }
    Ok(needed)
}

/// The parsed `apk` command line.
#[derive(Debug, PartialEq, Eq)]
pub struct Options {
    pub version: Version,
    pub out: PathBuf,
    pub abi: Abi,
    /// A release keystore and the alias of the key in it, from `--keystore` and `--key-alias`.
    pub keystore: Option<(PathBuf, String)>,
}

/// Parses the arguments after `apk`.
pub fn parse_args(args: &[String]) -> Result<Options> {
    let (mut version, mut out, mut abi, mut keystore, mut alias) = (None, None, None, None, None);
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        let mut value = || rest.next().ok_or_else(|| Error::new(format!("{flag} needs a value\n\n{USAGE}")));
        match flag.as_str() {
            "--version" => version = Some(Version::parse(value()?)?),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--target" => abi = Some(Abi::parse(value()?)?),
            "--keystore" => keystore = Some(PathBuf::from(value()?)),
            "--key-alias" => alias = Some(value()?.clone()),
            _ => return Err(Error::new(format!("unknown argument {flag:?}\n\n{USAGE}"))),
        }
    }
    let version = version.ok_or_else(|| Error::new(format!("--version is required\n\n{USAGE}")))?;
    version.android_version_code()?;
    let out = out.ok_or_else(|| Error::new(format!("--out is required\n\n{USAGE}")))?;
    let keystore = match (keystore, alias) {
        (Some(file), Some(alias)) => Some((file, alias)),
        (None, None) => None,
        _ => return Err(Error::new(format!("--keystore and --key-alias go together\n\n{USAGE}"))),
    };
    Ok(Options { version, out, abi: abi.unwrap_or(Abi::Aarch64), keystore })
}

/// The Android SDK and NDK pieces the build uses.
#[derive(Debug)]
struct Sdk {
    /// `platforms/android-34/android.jar`, the platform's resources that aapt2 links against.
    android_jar: PathBuf,
    /// The newest build-tools folder (aapt2, apksigner).
    build_tools: PathBuf,
    /// The NDK's LLVM `bin` folder.
    llvm_bin: PathBuf,
}

fn env_dir(names: &[&str]) -> Option<PathBuf> {
    names.iter().find_map(|name| env::var_os(name).filter(|value| !value.is_empty()).map(PathBuf::from))
}

/// The subfolder of `dir` whose name is the highest dotted version number.
fn newest(dir: &Path) -> Option<PathBuf> {
    let key = |name: &str| name.split(['.', '-']).map(|part| part.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
    let mut found: Vec<(Vec<u64>, PathBuf)> =
        fs::read_dir(dir).ok()?.filter_map(|entry| entry.ok()).filter_map(|entry| Some((key(entry.file_name().to_str()?), entry.path()))).collect();
    found.sort();
    found.pop().map(|(_, path)| path)
}

impl Sdk {
    fn locate() -> Result<Sdk> {
        let home =
            env_dir(&["ANDROID_HOME", "ANDROID_SDK_ROOT"]).ok_or_else(|| Error::new(format!("set ANDROID_HOME to the Android SDK\n\n{USAGE}")))?;
        let android_jar = home.join(format!("platforms/android-{TARGET_SDK}/android.jar"));
        if !android_jar.is_file() {
            return Err(Error::new(format!("{} is missing: install the SDK package platforms;android-{TARGET_SDK}", android_jar.display())));
        }
        let build_tools = newest(&home.join("build-tools"))
            .filter(|dir| dir.join("aapt2").is_file())
            .ok_or_else(|| Error::new(format!("no build-tools with aapt2 under {}", home.join("build-tools").display())))?;
        let ndk = env_dir(&["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"])
            .or_else(|| newest(&home.join("ndk")))
            .ok_or_else(|| Error::new("no Android NDK: set ANDROID_NDK_HOME or install one under $ANDROID_HOME/ndk"))?;
        let host = if cfg!(target_os = "macos") { "darwin-x86_64" } else { "linux-x86_64" };
        let llvm_bin = ndk.join("toolchains/llvm/prebuilt").join(host).join("bin");
        if !llvm_bin.is_dir() {
            return Err(Error::new(format!("{} is missing: the NDK's LLVM toolchain for this machine", llvm_bin.display())));
        }
        Ok(Sdk { android_jar, build_tools, llvm_bin })
    }

    /// The NDK's clang wrapper for `abi` at the minimum API level, used as the linker and C compiler.
    fn clang(&self, abi: Abi) -> PathBuf {
        self.llvm_bin.join(format!("{}{MIN_SDK}-clang", abi.triple()))
    }
}

fn run_tool(command: &mut Command, what: &str) -> Result<()> {
    let status = command.status().context(|| format!("running {what}"))?;
    if status.success() { Ok(()) } else { Err(Error::new(format!("{what} failed ({status})"))) }
}

/// Builds the app library for `abi` with the NDK and returns its contents.
fn cargo_build(root: &Path, sdk: &Sdk, abi: Abi, epoch: u64) -> Result<Vec<u8>> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let triple = abi.triple();
    println!("== building {APP_CRATE} for {triple}");
    let clang = sdk.clang(abi);
    if !clang.is_file() {
        return Err(Error::new(format!("{} is missing from the NDK", clang.display())));
    }
    let env_triple = triple.replace('-', "_");
    // 16 KiB pages: the library loads on phones with 4 KiB or 16 KiB pages.
    let mut rustflags = dist::release_rustflags(root);
    rustflags.push("\u{1f}-Clink-arg=-Wl,-z,max-page-size=16384");
    run_tool(
        Command::new(&cargo)
            .current_dir(root)
            .args(["build", "--release", "--locked", "--target", triple, "-p", APP_CRATE])
            .env(format!("CARGO_TARGET_{}_LINKER", env_triple.to_uppercase()), &clang)
            .env(format!("CC_{env_triple}"), &clang)
            .env(format!("AR_{env_triple}"), sdk.llvm_bin.join("llvm-ar"))
            .env("SOURCE_DATE_EPOCH", epoch.to_string())
            .env("CARGO_PROFILE_RELEASE_STRIP", "symbols")
            .env("CARGO_ENCODED_RUSTFLAGS", rustflags)
            .env_remove("RUSTFLAGS"),
        "cargo build",
    )?;
    dist::read(&dist::target_dir(root).join(triple).join("release").join(format!("lib{LIB_NAME}.so")))
}

/// Every file under `dir`, as `(path relative to dir with / separators, contents)`.
fn read_tree(dir: &Path) -> Result<Vec<(String, Vec<u8>)>> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(folder) = pending.pop() {
        for entry in fs::read_dir(&folder).context(|| format!("reading {}", folder.display()))? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                pending.push(path);
                continue;
            }
            let relative = path.strip_prefix(dir).map_err(|_| Error::new("a file outside the aapt2 output"))?;
            let parts: Option<Vec<&str>> = relative.components().map(|part| part.as_os_str().to_str()).collect();
            let parts = parts.ok_or_else(|| Error::new(format!("{} is not UTF-8", relative.display())))?;
            files.push((parts.join("/"), dist::read(&path)?));
        }
    }
    Ok(files)
}

/// Compiles the manifest and the icon with aapt2 and returns what it linked.
fn aapt2(sdk: &Sdk, work: &Path, version: &Version, svg: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let aapt2 = sdk.build_tools.join("aapt2");
    let manifest_path = work.join("AndroidManifest.xml");
    fs::write(&manifest_path, manifest(version)?).context(|| format!("writing {}", manifest_path.display()))?;
    let compiled = work.join("compiled");
    fs::create_dir_all(&compiled)?;
    let mut flats = Vec::new();
    for (path, png) in icon_resources(svg)? {
        let file = work.join(&path);
        if let Some(parent) = file.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&file, png).context(|| format!("writing {}", file.display()))?;
        run_tool(Command::new(&aapt2).arg("compile").arg("-o").arg(&compiled).arg(&file), "aapt2 compile")?;
    }
    for entry in fs::read_dir(&compiled)? {
        flats.push(entry?.path());
    }
    flats.sort();
    let linked = work.join("linked");
    fs::create_dir_all(&linked)?;
    run_tool(
        Command::new(&aapt2)
            .args(["link", "--output-to-dir", "-o"])
            .arg(&linked)
            .arg("-I")
            .arg(&sdk.android_jar)
            .arg("--manifest")
            .arg(&manifest_path)
            .args(flats),
        "aapt2 link",
    )?;
    read_tree(&linked)
}

/// The test signing key kept under the target folder, made on the first build.
fn test_key(root: &Path) -> Result<SigningKey> {
    let dir = dist::target_dir(root).join("xtask-apk").join("test-signing-key");
    let (key_path, cert_path) = (dir.join("key.pk8"), dir.join("certificate.der"));
    if key_path.is_file() && cert_path.is_file() {
        return SigningKey::from_parts(&dist::read(&key_path)?, &dist::read(&cert_path)?);
    }
    let key = SigningKey::generate("CrewCraft test signing key (not for release)")?;
    fs::create_dir_all(&dir).context(|| format!("creating {}", dir.display()))?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&key_path).and_then(|mut file| file.write_all(key.pkcs8())).context(|| format!("writing {}", key_path.display()))?;
    fs::write(&cert_path, key.certificate()).context(|| format!("writing {}", cert_path.display()))?;
    println!("   made a test signing key in {}", dir.display());
    Ok(key)
}

/// Signs `unsigned` with a release keystore through apksigner, and returns the signed APK.
fn sign_with_keystore(sdk: &Sdk, work: &Path, unsigned: &apk::Unsigned, keystore: &Path, alias: &str) -> Result<Vec<u8>> {
    if env::var_os(KEYSTORE_PASS_ENV).is_none() {
        return Err(Error::new(format!("--keystore needs the keystore password in {KEYSTORE_PASS_ENV}")));
    }
    let input = work.join("unsigned.apk");
    let output = work.join("signed.apk");
    fs::write(&input, unsigned.to_bytes()).context(|| format!("writing {}", input.display()))?;
    run_tool(
        Command::new(sdk.build_tools.join("apksigner"))
            .arg("sign")
            .arg("--ks")
            .arg(keystore)
            .args(["--ks-key-alias", alias, "--ks-pass", &format!("env:{KEYSTORE_PASS_ENV}")])
            // No v1 (JAR) signature; for API 29 and later apksigner then writes the v3 scheme.
            .args(["--min-sdk-version", &MIN_SDK.to_string(), "--v1-signing-enabled", "false"])
            .arg("--out")
            .arg(&output)
            .arg(&input),
        "apksigner sign",
    )?;
    dist::read(&output)
}

/// Runs `apk`: builds the library, compiles the resources, writes and signs the APK into the output folder.
pub fn run(options: &Options) -> Result<()> {
    let root = dist::workspace_root()?;
    let epoch = dist::source_date_epoch(&root)?;
    let built = env!("CARGO_PKG_VERSION");
    if built != options.version.to_string() {
        println!("warning: the app reports version {built}, not {}; set workspace.package.version before a release", options.version);
    }
    let sdk = Sdk::locate()?;
    let abi = options.abi;
    let library = cargo_build(&root, &sdk, abi, epoch)?;
    let needed = check_library(&library, abi)?;
    println!("   lib{LIB_NAME}.so links {}", needed.join(", "));
    let work = dist::work_dir(&root, &format!("android-{}", abi.name()))?;
    let svg = dist::read(&root.join("assets/icon/crewcraft.svg"))?;
    let linked = aapt2(&sdk, &work, &options.version, &svg)?;
    let licenses = dist::license_files(&root, true, false)?;
    let unsigned = apk::zip(&apk_entries(&linked, &licenses, abi, &library)?, epoch)?;
    let signed = match &options.keystore {
        Some((keystore, alias)) => sign_with_keystore(&sdk, &work, &unsigned, keystore, alias)?,
        None => apk::sign_v2(&unsigned, &test_key(&root)?)?,
    };
    if options.keystore.is_none() {
        apk::verify_v2(&signed)?;
    }
    fs::create_dir_all(&options.out).context(|| format!("creating {}", options.out.display()))?;
    dist::write_asset(&options.out, &file_name(&options.version, abi), &signed, false)?;
    Ok(())
}
