# Non-Rust dependencies

CrewCraft is written in Rust ([SPEC.md](SPEC.md) section 7) and prefers dependencies that are pure Rust. A dependency
that compiles C, C++ or assembly, or a platform SDK that is not written in Rust, is allowed only when it is listed in
the table below with the reason and the pure-Rust option that was considered. `tools/rust-only.sh` (part of the gate)
fails when `Cargo.lock` contains a native build helper that this table does not list.

The build helpers the gate looks for: `cc`, `cmake`, `bindgen`, `pkg-config`, `vcpkg`, `nasm-rs`. Add a row in the
same change that adds the dependency; the security contributor reviews it (CODEOWNERS).

| Helper | Pulled in by | Why it is needed | Pure-Rust option considered | Approved |
|---|---|---|---|---|
| `cc` | `ring` 0.17 (through `rustls`, crate `crewcraft-tls`) | ring compiles its C and assembly routines with `cc`. It is the crypto provider of the first owned TLS proof (M2, work item W0). | `rustls-graviola` (no C, but x86_64 and aarch64 only and very new), `rustls-rustcrypto` (pre-release), `aws-lc-rs` (audited, but also needs `cmake`) | No: waits for the security contributor's review (CODEOWNERS) |
| `pkg-config` | `wayland-sys` 0.31 (through `winit` and `glutin`, used by `eframe` for the desktop window on Linux, crate `crewcraft`) | wayland-sys's build script can look up the system's Wayland library. The window loads libwayland at run time (winit's `wayland-dlopen`), so nothing is compiled or linked at build time; the helper is listed because it is in `Cargo.lock`. Linux desktops supply libwayland, libxkbcommon, X11 and OpenGL; they are run-time requirements of the package, not build inputs | None mature: winit is the Rust windowing library egui uses, and it reaches the display server through these system libraries | No: waits for the security contributor's review (CODEOWNERS) |

Only the helpers in the table are native; every other dependency is pure Rust.

## Build-time tools

Programs that a build runs, rather than crates it compiles. Each is listed with the command that needs it.

| Tool | Needed by | Why it is needed | Pure-Rust option considered | Approved |
|---|---|---|---|---|
| MinGW-w64 (Debian packages `gcc-mingw-w64-x86-64` and `binutils-mingw-w64-x86-64`) | `cargo xtask dist --target windows-x86_64` ([RELEASE.md](RELEASE.md)) | Rust's `x86_64-pc-windows-gnu` target links through the MinGW gcc driver, its import libraries and C runtime start files; `cc` uses the same gcc to compile ring's C and assembly for Windows. The Linux packages and the gate do not need it | `x86_64-pc-windows-msvc` with `rust-lld` needs the Microsoft C runtime and Windows SDK libraries, which are not licensed for redistribution or use on a Linux build machine; `x86_64-pc-windows-gnullvm` still needs MinGW import libraries and C runtime (from llvm-mingw) | No: waits for the security contributor's review (CODEOWNERS) |

| `mksquashfs` (Debian package `squashfs-tools`) | `cargo xtask dist --target linux-x86_64` (the AppImage) | Writes the AppImage's SquashFS image (zstd, root-owned, fixed times). It runs at build time only; nothing it is made of ships | The `backhand` crate (MIT OR Apache-2.0) writes SquashFS in Rust with gzip through `flate2`, but it depends on `xxhash-rust`, which is `BSL-1.0`, not on the `deny.toml` allowlist. Admitting `BSL-1.0` would let xtask drop this tool | No: waits for the security contributor's review (CODEOWNERS) |

| `lipo`, `codesign` and `hdiutil` (Apple platform tools: `lipo` from Xcode's command-line tools, `hdiutil` part of macOS), with Xcode's linker | `cargo xtask dist --target macos-universal`, on a Mac only | `lipo -create` joins the x86_64 and arm64 builds into universal binaries; `codesign --sign -` seals the app bundle ad hoc (no identity); `hdiutil create -format UDZO` makes the compressed disk image. Rust's Apple targets link through Apple's linker and SDK, which are licensed for Apple hardware, so the macOS build runs on a Mac. The `Info.plist`, the `.icns` icon and the bundle layout are written by xtask in Rust | A universal Mach-O can be written in Rust (it is a header and the two builds), but a UDZO disk image has no maintained Rust writer, and the Apple linker is needed anyway | Listed as platform tools of the Mac build (2026-11-19) |

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
- **Android push (M6).** The Google push library is Java; a held connection or a UnifiedPush distributor avoids it.
- **Platform APIs.** Operating-system services (key stores, camera, notifications, call screens) are reached from Rust
  through bindings. Bindings that only declare the system's own functions, such as `libc` or `windows-sys`, compile no
  C and need no row.
