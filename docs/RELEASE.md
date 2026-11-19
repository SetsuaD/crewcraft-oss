# Release packages

`cargo xtask dist` builds the release binaries and writes the release assets plus `SHA256SUMS.txt`: the Linux and
Windows assets on one Linux x86_64 machine, the macOS assets on a Mac ([below](#macos)). The packages are written in
Rust (`xtask/`). These are not: the MinGW-w64 linker for the Windows binaries, `mksquashfs` for the AppImage's image,
the prebuilt AppImage runtime at the front of the AppImage, and Apple's `lipo` and `hdiutil` on the Mac
([NON-RUST-DEPENDENCIES.md](NON-RUST-DEPENDENCIES.md)).

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
each pair with `lipo -create`, and writes:

| Asset | Contents |
|---|---|
| `crewcraft-<v>-macos-universal.dmg` | A compressed disk image (`hdiutil create -format UDZO`, volume `CrewCraft`) holding `CrewCraft.app` and a link to `/Applications` to drag it onto. The app: `Contents/MacOS/crewcraft` (universal), `Contents/Info.plist` (identifier `io.github.setsuad.crewcraft`, version shown as the release version, `CFBundleVersion` the same three numbers as the MSI version, macOS 11.0 or later, high-resolution capable), `Contents/Resources/crewcraft.icns` (16 to 1024 px, rendered from the SVG) and the license files in `Contents/Resources/licenses/` |
| `crewcraft-server-<v>-macos-universal.tar.gz` | The same folder as the Linux server archive, with the universal server |

To publish one release with every platform, run `dist` on Linux and on the Mac into two folders, copy the assets into
one folder and run `sha256sum *.AppImage *.deb *.dmg *.msi *.tar.gz *.zip > SHA256SUMS.txt` there. The plist, the icon and the
bundle layout are checked on Linux by `cargo test -p xtask`; on any other system `--target macos-universal` stops
before building, with an error.

## Unsigned beta builds

The beta builds are not code-signed.

- Windows: SmartScreen warns before the MSI runs; choose **More info**, then **Run anyway**.
- macOS: Gatekeeper refuses to open an unsigned app downloaded from the internet. Open it the first time with
  right-click (or Control-click) on `CrewCraft.app`, then **Open**, then **Open** again; or, after copying it to
  Applications, remove the download mark with `xattr -dr com.apple.quarantine /Applications/CrewCraft.app`. On macOS 15
  and later, if right-click Open is not offered, allow it under System Settings, Privacy & Security, **Open Anyway**.
- Linux: the deb and the AppImage are not signed; check them against `SHA256SUMS.txt`.
