# Asset attribution

Every non-code asset in this repository (fonts, icons, images, sounds, example data) is listed here with its author,
source and license, in the same change that adds it.

**Policy:** every asset is original work by CrewCraft contributors or third-party material under a license on the
Craft allowlist (see [AGENTS.md](AGENTS.md)). No asset is copied from another chat product, and screenshots of other
vendors' software are never committed. Fonts are under OFL-1.1 only, with the license text next to the font file
(docs/CLEAN-ROOM.md rule 3); egui's own bundled fonts are not used.

| Asset | Author | Source | License | Notes |
|---|---|---|---|---|
| `assets/icon/crewcraft.svg`, `assets/icon/crewcraft.png` | CrewCraft contributors | Original work, drawn for this repository | MIT OR Apache-2.0 | The app icon: a speech bubble holding three people on a coral tile. The PNG is the SVG rendered at 512 px with `resvg`; packages render their other sizes from the SVG |
| `assets/fonts/InterVariable.ttf` | The Inter Project Authors | https://github.com/rsms/inter, release v4.1 (`Inter-4.1.zip`; byte-identical to `docs/font-files/InterVariable.ttf` at tag `v4.1`) | OFL-1.1 (`assets/fonts/OFL.txt`) | Unmodified. The desktop window's only font |
