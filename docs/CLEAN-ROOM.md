# Clean-room rules

CrewCraft is written from scratch, and it is developed in the open. These rules keep it an independent codebase and free of anything private.

1. **CrewCraft is written from its own written requirements.** It is built from scratch from [REQUIREMENTS.md](REQUIREMENTS.md) and [SPEC.md](SPEC.md); no code, schema, strings or assets are copied from other products.
2. **No copying.** No file, snippet, schema, test, string or asset from another product's implementation. Implementing a behaviour that REQUIREMENTS.md describes is the point; transcribing someone else's implementation is not.
3. **Open-source dependencies are fine** under licenses compatible with MIT OR Apache-2.0 (checked by `cargo deny`
   once dependencies grow). Libraries such as egui (and forks of it) and ArtCraft's craft-libs (https://github.com/storytold/craft-libs) would be acceptable dependencies.
   **Fonts** may be under the SIL Open Font License 1.1 (`OFL-1.1`). The font stays under the OFL. Its license text
   ships next to the font file in the repo and in every release, and a modified font may not keep a Reserved Font Name.
   No other font license is approved. egui's `default_fonts` feature pulls in `Ubuntu-font-1.0`, so the client turns
   that feature off and bundles its own OFL font.
4. **Nothing private, ever.** No hostnames, domains, IP addresses, people's names, customer names, email addresses
   other than `example.org`/`example.com`, credentials, keys, certificate fingerprints, or names of internal systems.
   `tools/sanitize-scan.sh` enforces a pattern list in the gate; the release gate adds human review.
