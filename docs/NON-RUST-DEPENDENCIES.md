# Non-Rust dependencies

CrewCraft is written in Rust ([SPEC.md](SPEC.md) section 7) and prefers dependencies that are pure Rust. A dependency
that compiles C, C++ or assembly, or a platform SDK that is not written in Rust, is allowed only when it is listed in
the table below with the reason and the pure-Rust option that was considered. `tools/rust-only.sh` (part of the gate)
fails when `Cargo.lock` contains a native build helper that this table does not list.

The build helpers the gate looks for: `cc`, `cmake`, `bindgen`, `pkg-config`, `vcpkg`, `nasm-rs`. Add a row in the
same change that adds the dependency; the security contributor reviews it (CODEOWNERS).

| Helper | Pulled in by | Why it is needed | Pure-Rust option considered | Approved |
|---|---|---|---|---|
| `cc` | `ring` 0.17 (through `rustls`, crate `crewcraft-tls`, in the chat server and, for its control connection only, the media server binary `crewcraft-media-server` (decided 2026-11-26, docs/CALLS.md);  directly in `xtask`, which signs the Android APK with it; and directly in `crewcraft-sframe` (AES-GCM and HKDF of end-to-end encrypted calls, T360c)) | ring compiles its C and assembly routines with `cc`. It is the crypto provider of the first owned TLS proof (M2, work item W0). | `rustls-graviola` (no C, but x86_64 and aarch64 only and very new), `rustls-rustcrypto` (pre-release), `aws-lc-rs` (audited, but also needs `cmake`) | No: waits for the security contributor's review (CODEOWNERS) |
| `pkg-config` | `wayland-sys` 0.31 (through `winit` and `glutin`, used by `eframe` for the desktop window on Linux, crate `crewcraft`) | wayland-sys's build script can look up the system's Wayland library. The window loads libwayland at run time (winit's `wayland-dlopen`), so nothing is compiled or linked at build time; the helper is listed because it is in `Cargo.lock`. Linux desktops supply libwayland, libxkbcommon, X11 and OpenGL; they are run-time requirements of the package, not build inputs | None mature: winit is the Rust windowing library egui uses, and it reaches the display server through these system libraries | No: waits for the security contributor's review (CODEOWNERS) |

Only the helpers in the table are native; every other dependency is pure Rust.

## Build-time tools

Programs that a build runs, rather than crates it compiles. Each is listed with the command that needs it.

| Tool | Needed by | Why it is needed | Pure-Rust option considered | Approved |
|---|---|---|---|---|
| MinGW-w64 (Debian packages `gcc-mingw-w64-x86-64` and `binutils-mingw-w64-x86-64`) | `cargo xtask dist --target windows-x86_64` ([RELEASE.md](RELEASE.md)) | Rust's `x86_64-pc-windows-gnu` target links through the MinGW gcc driver, its import libraries and C runtime start files; `cc` uses the same gcc to compile ring's C and assembly for Windows. The Linux packages and the gate do not need it | `x86_64-pc-windows-msvc` with `rust-lld` needs the Microsoft C runtime and Windows SDK libraries, which are not licensed for redistribution or use on a Linux build machine; `x86_64-pc-windows-gnullvm` still needs MinGW import libraries and C runtime (from llvm-mingw) | No: waits for the security contributor's review (CODEOWNERS) |

| `mksquashfs` (Debian package `squashfs-tools`) | `cargo xtask dist --target linux-x86_64` (the AppImage) | Writes the AppImage's SquashFS image (zstd, root-owned, fixed times). It runs at build time only; nothing it is made of ships | The `backhand` crate (MIT OR Apache-2.0) writes SquashFS in Rust with gzip through `flate2`, but it depends on `xxhash-rust`, which is `BSL-1.0`, not on the `deny.toml` allowlist. Admitting `BSL-1.0` would let xtask drop this tool | No: waits for the security contributor's review (CODEOWNERS) |

| `lipo`, `codesign` and `hdiutil` (Apple platform tools: `lipo` from Xcode's command-line tools, `hdiutil` part of macOS), with Xcode's linker | `cargo xtask dist --target macos-universal`, on a Mac only | `lipo -create` joins the x86_64 and arm64 builds into universal binaries; `codesign --sign -` seals the app bundle ad hoc (no identity); `hdiutil create -format UDZO` makes the compressed disk image. Rust's Apple targets link through Apple's linker and SDK, which are licensed for Apple hardware, so the macOS build runs on a Mac. The `Info.plist`, the `.icns` icon and the bundle layout are written by xtask in Rust | A universal Mach-O can be written in Rust (it is a header and the two builds), but a UDZO disk image has no maintained Rust writer, and the Apple linker is needed anyway | Listed as platform tools of the Mac build (2026-11-19) |

| The Android NDK (r27: its `clang` driver with `lld`, and `llvm-ar`) | `cargo xtask apk` ([RELEASE.md](RELEASE.md)) | Rust's Android targets link through the NDK's clang, which supplies Android's C library, start files and system libraries to link against; `cc` uses the same clang to compile ring's C and assembly for Android. The app links only Android's own system libraries (xtask checks this), so nothing from the NDK ships | None: the NDK is Android's only supported way to link native code for it | Listed as a platform tool of the Android build (2026-11-19) |

| `aapt2` (Android SDK build-tools) and the platform's `android.jar` (`platforms;android-34`) | `cargo xtask apk` | `aapt2 link` turns `AndroidManifest.xml` and the launcher icons into Android's binary XML and resource table (`resources.arsc`), resolving attribute and theme names against the platform's `android.jar`. The manifest text, the icon PNGs, the APK zip and its v2 signature are written by xtask in Rust | A binary XML and resource table writer in Rust is possible (the formats are documented by AOSP's source) but no maintained crate on the license allowlist does it; the Rust crates that try are young and not reviewed | Listed as a platform tool of the Android build (2026-11-19) |

| `apksigner` (Android SDK build-tools, a Java program; needs a Java runtime) | `cargo xtask apk --keystore`, only | Signs the APK with a release key held in a Java keystore (PKCS#12 or JKS), which is how release and Play upload keys are usually kept. Without `--keystore` xtask signs in Rust (v2 scheme, ECDSA P-256, `ring`) and needs neither apksigner nor Java. `apksigner verify` is also the independent check of an APK ([RELEASE.md](RELEASE.md)) | Reading a PKCS#12 keystore in Rust (`p12` crates) and signing in Rust, which xtask already does for the test key; decided with the release identity (T406) | Listed as a platform tool of the Android build (2026-11-19) |

| Xcode with its iOS SDK and Simulator (the linker, clang and `xcrun`), and `codesign` | `cargo xtask ios`, on a Mac only ([RELEASE.md](RELEASE.md#ios-simulator)) | Rust's iOS targets link against Apple's iOS SDK through Apple's linker, and `cc` compiles ring's C and assembly with Xcode's clang, as for macOS; the SDK is licensed for Apple hardware. `codesign --sign -` seals `CrewCraft.app` ad hoc (no identity). The `Info.plist`, the icons and the bundle layout are written by xtask in Rust: no Xcode project, asset catalog (`actool`), storyboard (`ibtool`), Swift or Objective-C. `xcrun simctl` only installs and starts the app on a simulator | None: no other iOS SDK or linker exists. A build for iPhones adds a signing identity and provisioning profile (T424) | No: waits for the maintainers' review |

## Crates that stay pure Rust

Some crates must stay free of native code even though the workspace as a whole is not: `tools/rust-only.sh` fails when
the normal or build dependencies of one of them, on any target, include `cc`, `cmake`, `bindgen`, `pkg-config`,
`vcpkg`, `nasm-rs`, `ring`, AWS-LC, OpenSSL or `rcgen`.

| Crate | Why it stays pure Rust |
|---|---|
| `crewcraft-media-crypto` | The media server's DTLS, SRTP and hashes (T362a, [CALLS.md](CALLS.md)). Every ready-made str0m backend links C (AWS-LC, OpenSSL, or `rcgen`'s AWS-LC even in str0m's RustCrypto mode), so CrewCraft supplies its own provider from RustCrypto crates and `dimpl`'s RustCrypto mode, and makes its DTLS certificate with `p256` and `x509-cert` |
| `crewcraft-media-auth` | The media credentials the media server checks (T360b1). Ed25519 and the media key's PKCS#8 form come from `ed25519-dalek` (until T363a they came from `ring`), so the media server can link it |
| `crewcraft-media` | The media path of the media server (T363a, [CALLS.md](CALLS.md)): str0m with no backend of its own, on `crewcraft-media-crypto` and `crewcraft-media-auth`. The binary, `crewcraft-media-server`, is not on this list: its control connection uses `crewcraft-tls` (ring), decided 2026-11-26 |

The lab browser lobby uses the pure-Rust request-head parser `httparse` 1.10.1, licensed MIT OR Apache-2.0.
It adds no native runtime or build tool. Its published checksum is in `Cargo.lock`.

## Shipped third-party binaries

Prebuilt programs that are not built from source here but go into a release asset. Each is pinned by SHA-256, never
downloaded by the build, and passed in by the person running it ([RELEASE.md](RELEASE.md)).

| Binary | Version and source | SHA-256 | License | Shipped in | Why |
|---|---|---|---|---|---|
| AppImage type2 runtime, `runtime-x86_64` (static-pie ELF, C) | Release `20251108` of https://github.com/AppImage/type2-runtime (file `runtime-x86_64`) | `2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d` | MIT for the runtime's own code (`assets/appimage/RUNTIME-LICENSE.txt`); it links statically libfuse (LGPL-2.1), musl, squashfuse, zstd and zlib, whose terms that file lists | The front of `crewcraft-<v>-linux-x86_64.AppImage` | It is the program that mounts the AppImage's image (or unpacks it) and starts the app; an AppImage cannot run without one. No Rust runtime exists. Approved by the maintainers on 2026-11-19 |

Every AppImage carries the runtime's license files in `usr/share/licenses/appimage-runtime/`: `LICENSE` (the file
above), `LGPL-2.1` (the GNU LGPL 2.1 text for libfuse, copied at build time from the build machine's
`/usr/share/common-licenses/LGPL-2.1`, Debian package `base-files`; nothing is downloaded) and `SOURCE.txt`, which says
the runtime is built from https://github.com/AppImage/type2-runtime/tree/20251108, where the sources and build scripts
of the runtime and the libraries it links are, and that anyone may rebuild the runtime from them and replace it in the
AppImage (`--appimage-extract`, then repack, as [RELEASE.md](RELEASE.md) describes).

Tools that only inspect a build (`dpkg-deb`, `msiinfo` from `msitools`, `file`) are optional and listed in
[RELEASE.md](RELEASE.md); nothing depends on them. The package formats themselves (`.deb`, `.tar.gz`, `.zip`, `.msi`
with its cabinet, the PNG and `.ico` icons, `SHA256SUMS.txt`) are written by `xtask` in Rust.

## Expected decisions

Each is decided when its milestone starts, and recorded here if it adds a row.

- **TLS cryptography (M2).** The mature rustls providers contain C and assembly; pure-Rust providers are younger.
  Security outranks purity here, so a mature, audited provider is the expected exception.
- **Audio and video codecs (M7).** Opus audio and the video codecs; Rust encoders and decoders exist for AV1, and
  hardware codecs are reached through the operating system.
- **Android (M6).** The window reaches Android through `android-activity`, `ndk`, `ndk-sys`, `jni` and
  `android_log-sys` (logging), which declare the system's own functions and compile no C. Their FFI is in those
  crates. The app has three unsafe items: the `android_main` entry symbol, and turning the JVM and activity pointers
  android-activity hands out into `jni` handles (T403, T405), through which it calls the Android Keystore's Java API
  and reads the link it was opened with, with no Java source of its own (docs/MOBILE.md).
- **Android push (M6).** The Google push library is Java; a held connection or a UnifiedPush distributor avoids it.
- **Platform APIs.** Operating-system services (key stores, camera, notifications, call screens) are reached from Rust
  through bindings. Bindings that only declare the system's own functions, such as `libc` or `windows-sys`, compile no
  C and need no row. The key stores that seal the desktop's device record (T313) are reached this way: Credential
  Manager through `windows-sys`, the macOS Keychain through `security-framework-sys`, and the Linux Secret Service
  over D-Bus in Rust (`zbus`, with RustCrypto for the session encryption), not through `libdbus`, whose crates
  would need `pkg-config` and the C library. On iOS the window's safe area and the keyboard's frame come from UIKit
  through `objc2-ui-kit` and `objc2-foundation` (T421), which winit and egui-winit already use there; they declare
  Apple's own Objective-C classes and compile no C.
