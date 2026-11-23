# Release packages

`cargo xtask dist` builds the release binaries and writes the release assets plus `SHA256SUMS.txt`: the Linux and
Windows assets on one Linux x86_64 machine, the macOS assets on a Mac ([below](#macos)). The packages are written in
Rust (`xtask/`). These are not: the MinGW-w64 linker for the Windows binaries, `mksquashfs` for the AppImage's image,
the prebuilt AppImage runtime at the front of the AppImage, Apple's `lipo` and `hdiutil` on the Mac, the Android
NDK's linker and `aapt2` for the Android app ([below](#android)), and Xcode's iOS SDK and `codesign` for the iPhone
app ([below](#ios-simulator)) ([NON-RUST-DEPENDENCIES.md](NON-RUST-DEPENDENCIES.md)).

## Build the release packages

On Linux x86_64 (Debian or Ubuntu shown), with Rust 1.95:

```sh
rustup target add x86_64-pc-windows-gnu
sudo apt-get install gcc-mingw-w64-x86-64 squashfs-tools   # the Windows linker; mksquashfs for the AppImage

cargo xtask dist --version 0.1.0-beta.1 --out dist --appimage-runtime /path/to/runtime-x86_64
(cd dist && sha256sum -c SHA256SUMS.txt)
```

The AppImage runtime is the file `runtime-x86_64` of release `20251108` of
[AppImage/type2-runtime](https://github.com/AppImage/type2-runtime/releases/tag/20251108). Get it yourself and pass its
path with `--appimage-runtime` or `CREWCRAFT_APPIMAGE_RUNTIME`; the build never downloads it, and refuses a file whose
SHA-256 is not `2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d`. `--no-appimage` leaves the
AppImage out.

`--target linux-x86_64` or `--target windows-x86_64` builds one platform (both when the flag is left out; it can be
repeated; on a Mac the default is `macos-universal`). Each run rewrites `SHA256SUMS.txt` over every asset in the output folder, so two runs into one folder give
one list.

Before a release, set `workspace.package.version` in `Cargo.toml` to the release version: the binaries print it for
`--version`, and `dist` warns when it differs from `--version`.

## What it writes

| Asset | Contents |
|---|---|
| `crewcraft-<v>-linux-x86_64.deb` | `/usr/bin/crewcraft`; the desktop entry; the icon as SVG and as PNG from 16 to 512 px in the hicolor theme; the license files and a Debian `copyright` under `/usr/share/doc/crewcraft/`. `Depends:` is what the binary links, read from it (the build fails on a library it cannot map), plus the OpenGL, keyboard and Wayland-or-X11 libraries the window opens at run time; `Recommends:` lists the rest of the Wayland and X11 libraries |
| `crewcraft-<v>-linux-x86_64.AppImage` | The AppImage runtime, then a SquashFS image (zstd) of an AppDir: `AppRun` (the program), `crewcraft.desktop`, `crewcraft.png`, `.DirIcon`, the `.deb`'s files under `usr/`, and the runtime's `LICENSE`, `LGPL-2.1` and `SOURCE.txt` in `usr/share/licenses/appimage-runtime/`. It uses the system's C library and window libraries: it needs a glibc at least as new as the `.deb`'s `Depends:` names (2.35 for a build on Debian 12) |
| `crewcraft-server-<v>-linux-x86_64.tar.gz` | One folder `crewcraft-server-<v>-linux-x86_64/` with the server, the license files and a `README.txt` on `first-run` and `serve` |
| `crewcraft-<v>-windows-x86_64.msi` | A per-machine install of `crewcraft.exe` and the license files into `Program Files\CrewCraft`, a Start menu shortcut and an Installed apps entry with the icon. A newer MSI removes the older version first; an older MSI refuses to install over a newer one |
| `crewcraft-server-<v>-windows-x86_64.zip` | The same folder as the Linux archive, with `crewcraft-server.exe` and `.txt` names |
| `SHA256SUMS.txt` | `sha256sum` format, one line per asset |

The MSI is per-machine, so Windows asks for administrator approval. Install it with `msiexec /i <file>.msi`, or
silently with `/qn`; `INSTALLDIR=<folder>` changes the folder. Its UpgradeCode,
`{7B22B52D-5053-41BB-A254-FF039F9B37C3}`, is fixed for every version; never change it, or new versions install beside
old ones instead of replacing them.

The AppImage needs FUSE to mount itself. Without FUSE, `APPIMAGE_EXTRACT_AND_RUN=1 ./crewcraft-<v>-linux-x86_64.AppImage`
unpacks it to a temporary folder and runs it from there; `--appimage-extract` unpacks it to `squashfs-root/`.

The runtime links libfuse, which is under the GNU LGPL 2.1, so anyone may replace it with a runtime they built
(from https://github.com/AppImage/type2-runtime/tree/20251108, or modified) without rebuilding CrewCraft:

```sh
./crewcraft-<v>-linux-x86_64.AppImage --appimage-extract
mksquashfs squashfs-root crewcraft.squashfs -noappend -root-owned -comp zstd
cat my-runtime-x86_64 crewcraft.squashfs > crewcraft.AppImage && chmod +x crewcraft.AppImage
```

## Versions

A release version is `MAJOR.MINOR.PATCH` or `MAJOR.MINOR.PATCH-alpha.N`, `-beta.N` or `-rc.N` (N up to 99). Asset names
use it as written. Debian writes `0.1.0~beta.1`, which sorts before `0.1.0`. Windows Installer compares only three
numbers, so the MSI ProductVersion packs the patch and the pre-release into the third: `PATCH * 1000 + 100 + N` for
alpha, `200 + N` for beta, `300 + N` for rc and `900` for the release. `0.1.0-beta.1` is `0.1.201` and `0.1.0` is
`0.1.900`, so every later release has a larger MSI version. The patch number can be at most 64.

## Reproducible builds

The same commit and toolchain give the same assets:

- every archive entry carries one time, `SOURCE_DATE_EPOCH` when it is set, otherwise the commit's time;
- entries are sorted, each folder comes before its contents, and every entry is owned by root;
- the binaries are built with `--remap-path-prefix` for the checkout and the cargo home, so no folder of the build
  machine is written into them, and stripped of symbols;
- the MSI's ProductCode, PackageCode and component GUIDs are name-based UUIDs under the UpgradeCode;
- the AppImage's image is made with fixed times and root ownership.

## Checking a build

These tools are not needed to build; they read the packages independently:

```sh
dpkg-deb --info dist/crewcraft-*-linux-x86_64.deb
dpkg-deb --contents dist/crewcraft-*-linux-x86_64.deb
msiinfo export dist/crewcraft-*-windows-x86_64.msi Property      # Debian package msitools
msiextract -C extracted dist/crewcraft-*-windows-x86_64.msi
file extracted/PFiles/CrewCraft/crewcraft.exe                    # PE32+ executable x86-64
dist/crewcraft-*-linux-x86_64.AppImage --appimage-extract        # lists and unpacks the AppDir
```

`cargo test -p xtask` checks the layouts from fake binaries without building a release (task T307).

## macOS

The macOS assets are built on a Mac, because the Apple targets link against Apple's SDK, which is licensed for Apple
hardware only. With Rust 1.95 and Xcode's command-line tools (`xcode-select --install`, which provides the linker and
`lipo`; `hdiutil` is part of macOS):

```sh
rustup target add x86_64-apple-darwin aarch64-apple-darwin
cargo xtask dist --version 0.1.0-beta.1 --out dist --target macos-universal
(cd dist && shasum -a 256 -c SHA256SUMS.txt)
```

It builds both binaries for `x86_64-apple-darwin` and `aarch64-apple-darwin`, checks each build's architecture, joins
each pair with `lipo -create`, signs `CrewCraft.app` ad hoc (`codesign --sign -`: it seals the bundle without naming
anyone, so an Apple Silicon Mac offers "Open" instead of calling the app damaged; it is not a Developer ID signature),
and writes:

| Asset | Contents |
|---|---|
| `crewcraft-<v>-macos-universal.dmg` | A compressed disk image (`hdiutil create -format UDZO`, volume `CrewCraft`) holding `CrewCraft.app` and a link to `/Applications` to drag it onto. The app: `Contents/MacOS/crewcraft` (universal), `Contents/Info.plist` (identifier `io.github.setsuad.crewcraft`, version shown as the release version, `CFBundleVersion` the same three numbers as the MSI version, macOS 11.0 or later, high-resolution capable), `Contents/Resources/crewcraft.icns` (16 to 1024 px, rendered from the SVG) and the license files in `Contents/Resources/licenses/` |
| `crewcraft-server-<v>-macos-universal.tar.gz` | The same folder as the Linux server archive, with the universal server |

To publish one release with every platform, run `dist` on Linux and on the Mac into two folders, copy the assets into
one folder and run `sha256sum *.AppImage *.deb *.dmg *.msi *.tar.gz *.zip > SHA256SUMS.txt` there. The plist, the icon and the
bundle layout are checked on Linux by `cargo test -p xtask`; on any other system `--target macos-universal` stops
before building, with an error.

## Android

`cargo xtask apk` builds the Android app (`apps/crewcraft-android`, task T400) as one APK per ABI, on Linux x86_64 or
a Mac, with Rust 1.95 and the Android SDK and NDK from Google's command-line tools:

```sh
rustup target add aarch64-linux-android x86_64-linux-android
sdkmanager "platforms;android-34" "build-tools;34.0.0" "ndk;27.3.13750724"
export ANDROID_HOME=/path/to/android-sdk     # the NDK is found under $ANDROID_HOME/ndk, or set ANDROID_NDK_HOME

cargo xtask apk --version 0.1.0-beta.1 --out dist                   # phones: crewcraft-<v>-android-aarch64.apk
cargo xtask apk --version 0.1.0-beta.1 --out dist --target x86_64   # the emulator: ...-android-x86_64.apk
```

It builds the library with the NDK's clang as linker (API 29, 16 KiB pages), checks it exports
`ANativeActivity_onCreate` and links only Android system libraries, renders the launcher icon from the SVG at five
densities, compiles the generated `AndroidManifest.xml` and the icons with `aapt2`, and writes the APK in Rust:

| Entry | Contents |
|---|---|
| `AndroidManifest.xml` | Package `io.github.setsuad.crewcraft`, `versionName` the version, `versionCode` as below, Android 10 (API 29) or later, target API 34, the INTERNET permission only, no Java code (`hasCode="false"`), no backups, one `android.app.NativeActivity` that loads `libcrewcraft_android.so` and is the launcher entry |
| `resources.arsc`, `res/mipmap-*/crewcraft.png` | The app label and the icon at 48 to 192 px; stored, 4-byte aligned |
| `assets/licenses/` | `LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE` and the font's `OFL.txt` |
| `lib/<abi>/libcrewcraft_android.so` | The app; stored and 16 KiB aligned, so Android maps it from the APK (`extractNativeLibs="false"`) |

The `versionCode` is `MAJOR * 10000000 + MINOR * 100000 + PATCH * 1000 + STAGE`, with STAGE as in the MSI version
(`100 + N` alpha, `200 + N` beta, `300 + N` rc, `900` release): `0.1.0-beta.1` is `100201`, and every later release
has a larger code, which Android needs to install it as an update. The minor number can be at most 99.

**Signing.** Without `--keystore` the APK is signed in Rust with APK Signature Scheme v2 (ECDSA P-256) by a test
key that the first build makes and keeps in `target/xtask-apk/test-signing-key/` (it is never committed), so later
test builds install over earlier ones; a new checkout makes a new key, and Android then needs the old app removed
first. xtask verifies every signature it writes. A test-signed APK is for emulators and test phones, not a release.
Which identity signs released APKs is decided before task T406; the hook for it is a keystore:

```sh
export CREWCRAFT_APK_KEYSTORE_PASS=...        # read by apksigner from the environment, never on the command line
cargo xtask apk --version 0.1.0 --out dist --keystore release.p12 --key-alias upload
```

which signs the same APK with the build-tools' `apksigner` (a Java program; it needs a Java runtime) instead.

Check an APK independently, install it and read its log:

```sh
$ANDROID_HOME/build-tools/34.0.0/apksigner verify --verbose dist/crewcraft-*-android-x86_64.apk
$ANDROID_HOME/build-tools/34.0.0/zipalign -c -p 4 dist/crewcraft-*-android-x86_64.apk
$ANDROID_HOME/build-tools/34.0.0/aapt2 dump badging dist/crewcraft-*-android-x86_64.apk
adb install -r dist/crewcraft-*-android-x86_64.apk
adb shell am start -n io.github.setsuad.crewcraft/android.app.NativeActivity
adb logcat -s CrewCraft      # crewcraft <version> (protocol <n>) on Android
```

`cargo test -p xtask --test t400_android_apk` checks the manifest, icons, zip layout and signature without the SDK.

## iOS (simulator)

The iPhone app is built on a Mac with Xcode and its iOS Simulator (Rust 1.95; Xcode provides the iOS SDK, the linker
and `codesign`). It is not a release asset yet: a build for real iPhones needs a signing identity and comes with
TestFlight (task T424).

```sh
rustup target add x86_64-apple-ios aarch64-apple-ios-sim
cargo xtask ios --version 0.1.0-beta.1 --out dist-ios        # --target sim-x86_64 or sim-arm64; default: this Mac's
xcrun simctl boot "iPhone 17"                                 # any iPhone on iOS 17 or later
xcrun simctl install booted dist-ios/CrewCraft.app
xcrun simctl launch --console-pty booted io.github.setsuad.crewcraft
```

It builds `crewcraft` for `x86_64-apple-ios` (Intel Macs) or `aarch64-apple-ios-sim` (Apple Silicon) with
`IPHONEOS_DEPLOYMENT_TARGET=17.0`, checks that the program is a Mach-O for that CPU built for the simulator and iOS
17.0, and writes `dist-ios/CrewCraft.app`, replacing an earlier one, signed ad hoc (`codesign --sign -`). The bundle
is flat and written by xtask in Rust, with no Xcode project:

| File | Contents |
|---|---|
| `crewcraft` | The program (stripped, with the build machine's folders remapped as in the release builds) |
| `Info.plist` | Identifier `io.github.setsuad.crewcraft`, `CFBundleShortVersionString` the release's three numbers (the only form the App Store accepts), `CFBundleVersion` the same numbers as the MSI and macOS (`0.1.0-beta.1` is `0.1.201`), `MinimumOSVersion` 17.0, an empty `UILaunchScreen`, iPhone (`UIDeviceFamily` 1), portrait, `CFBundleSupportedPlatforms` `iPhoneSimulator` |
| `AppIcon60x60` at `@2x` and `@3x` | The home-screen icon at 120 and 180 px, rendered from `assets/icon/crewcraft.svg` and named in `CFBundleIcons` |
| `PkgInfo`, `licenses/` | `APPL????`, and the license files with the font's license |

`--console-pty` shows what the program prints (its first line is `crewcraft <version> (protocol <n>)`); the system's
log of the app is `xcrun simctl spawn booted log stream --predicate 'process == "crewcraft"'`.
The plist, the icons, the bundle layout and the program check are tested on Linux by `cargo test -p xtask` (task
T420); on any other system `cargo xtask ios` stops before building, with an error.

## Unsigned beta builds

The beta builds are not code-signed.

- Windows: SmartScreen warns before the MSI runs; choose **More info**, then **Run anyway**.
- macOS: Gatekeeper refuses to open an unsigned app downloaded from the internet. Open it the first time with
  right-click (or Control-click) on `CrewCraft.app`, then **Open**, then **Open** again; or, after copying it to
  Applications, remove the download mark with `xattr -dr com.apple.quarantine /Applications/CrewCraft.app`. On macOS 15
  and later, if right-click Open is not offered, allow it under System Settings, Privacy & Security, **Open Anyway**.
- Linux: the deb and the AppImage are not signed; check them against `SHA256SUMS.txt`.

## Signed release manifests (milestone M5)

A server updates itself, and its apps update from it, only from a release manifest signed with a release key whose
public half the build pins (REQUIREMENTS 2.21, `crewcraft_update`). `cargo xtask release` (task T501) makes and
checks them:

```sh
# Once, on the release owner's own machine: a new release key and its public half.
cargo xtask release key --out ~/crewcraft-release.key
# For each release, after `dist` and `apk` wrote the packages into dist/:
cargo xtask release manifest --version 0.2.0 --channel beta --published 2026-12-31 --min-client 0.1.0 \
  --dir dist --out dist/crewcraft-0.2.0.release.toml
cargo xtask release sign --manifest dist/crewcraft-0.2.0.release.toml --key ~/crewcraft-release.key \
  --out dist/crewcraft-0.2.0.release.toml.sig
# Anyone, with the published public key:
cargo xtask release verify --manifest dist/crewcraft-0.2.0.release.toml --signature dist/crewcraft-0.2.0.release.toml.sig \
  --public <public-key-hex> --dir dist
```

- The key file holds the private key (64 hex characters). `key` writes it to a new file, owner-only on Unix, and
  prints only the public key; `sign` refuses a key file others can read. Keep it off build machines and out of the
  repository; where it lives is the release owner's decision. Several public keys may be pinned at once, so a key can
  be replaced by pinning its successor a release before the switch.
- The manifest lists one package per kind and platform: the server archives, the desktop AppImage, MSI and DMG (the
  `.deb` is updated by the system's package manager instead), and the phone APK. Each entry carries the file's size
  and SHA-256, so a client checks the download against the signed manifest.
- `sign` checks the new signature with the public key before writing it, and never overwrites a file. `verify` is
  what a server or client does on receipt: the signature against the pinned keys, then each file.
- Not yet: pinning the release keys in the server and the apps, the server's self-update and the apps' updaters (the
  rest of M5).
