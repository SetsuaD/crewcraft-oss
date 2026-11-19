# Asset attribution

Every non-code asset in this repository (fonts, icons, images, sounds, example data) is listed here with its author,
source and license, in the same change that adds it.

**Policy:** every asset is original work by CrewCraft contributors or third-party material under a license on the
Craft allowlist (see [AGENTS.md](AGENTS.md)). No asset is copied from another chat product, and screenshots of other
vendors' software are never committed. Fonts are under OFL-1.1 only, with the license text next to the font file
(docs/CLEAN-ROOM.md rule 3); egui's own bundled fonts are not used.

| Asset | Author | Source | License | Notes |
|---|---|---|---|---|
| `assets/icon/crewcraft.svg`, `assets/icon/crewcraft.png`, `assets/icon/crewcraft.ico` | CrewCraft contributors | Original work, drawn for this repository | MIT OR Apache-2.0 | The app icon: a speech bubble holding three people on a coral tile. The PNG is the SVG rendered at 512 px with `resvg`; the ICO (16 to 256 px, embedded in `crewcraft.exe`) is written by `cargo xtask icons`; packages render their other sizes from the SVG |
| AppImage type2 runtime (not in this repository; the front of the Linux AppImage release asset) | The AppImage project and contributors | https://github.com/AppImage/type2-runtime, release `20251108`, file `runtime-x86_64` (SHA-256 in [docs/NON-RUST-DEPENDENCIES.md](docs/NON-RUST-DEPENDENCIES.md)) | MIT (`assets/appimage/RUNTIME-LICENSE.txt`, the runtime's `LICENSE` at that tag); it links statically libfuse (LGPL-2.1), musl, squashfuse, zstd and zlib | Unmodified prebuilt program, passed to `cargo xtask dist` by the person building the release ([docs/RELEASE.md](docs/RELEASE.md)). Every AppImage carries, in `usr/share/licenses/appimage-runtime/`, the runtime's `LICENSE`, the `LGPL-2.1` text (copied at build time from Debian's `/usr/share/common-licenses/LGPL-2.1`) and `SOURCE.txt`: built from https://github.com/AppImage/type2-runtime/tree/20251108, where the sources and build scripts of the runtime and its libraries are, and anyone may rebuild it and replace it in the AppImage (`--appimage-extract`, then repack) |
| `assets/fonts/InterVariable.ttf` | The Inter Project Authors | https://github.com/rsms/inter, release v4.1 (`Inter-4.1.zip`; byte-identical to `docs/font-files/InterVariable.ttf` at tag `v4.1`) | OFL-1.1 (`assets/fonts/OFL.txt`) | Unmodified. The desktop window's only font |
