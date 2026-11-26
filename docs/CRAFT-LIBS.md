# CrewCraft and craft-libs

The Craft rules ask a repository to check
[storytold/craft-libs](https://github.com/storytold/craft-libs) before adding reusable file-format, codec, protocol or
UI code, and to reuse or extend it instead of keeping an app copy (AGENTS.md rule 9). This file records that check
for the parsers, codecs, protocols and widgets CrewCraft already has. For each one it says whether craft-libs has an
equivalent, and whether moving makes sense now, later or not at all, and why.

It was read on 2026-11-26 against crewcraft-oss `main` and craft-libs `main` at `0ebc591`. Update it when either side
changes a row, or when a CrewCraft change adds reusable code.

## What adopting any craft-libs crate costs

These apply to every "later" and "candidate" row below, so they are stated once.

- **A git dependency.** craft-libs is not on crates.io. AGENTS.md rule 10 asks for every craft-libs crate at one
  `rev` that is merged on its `main`, and a `rev` move is its own pull request. `deny.toml` refuses unknown git
  sources today, so the first adoption also adds `storytold/craft-libs` to `[sources] allow-git`, in its own pull
  request.
- **Licence.** craft-libs is MIT OR Apache-2.0, like CrewCraft. Each adopted crate's own dependencies still go through
  `cargo deny` and `tools/rust-only.sh`.
- **egui.** craft-libs patches egui, epaint, egui-winit and egui-wgpu to a storytold fork (`[patch.crates-io]` in its
  workspace `Cargo.toml`, pinned to one commit). Its UI crates (`ui-contract`, `ui-widgets`) assume that fork.
  CrewCraft uses egui 0.37 from crates.io. Taking the UI crates means taking the fork, which is a decision of its own,
  not a side effect of one pull request.
- **CrewCraft's limits stay.** A move keeps CrewCraft's input limits, refusals and tests (AGENTS.md rule 9: a move
  keeps behaviour, limits, attribution and tests). The security-sensitive crates are reviewed by the security
  contributor (CODEOWNERS).

## The survey

| CrewCraft code | What it does | craft-libs | Move? |
|---|---|---|---|
| `crates/theme` (contrast rules) | Themes and theme addons; WCAG 2.2 AA contrast checks on every theme (REQUIREMENTS 2.19) | `theme`: the suite's design-system model, including WCAG contrast, OKLCH and colour ramps. `theme-store`: the suite's shared theme library in a machine-local `ArtCraft/themes` folder | **Later, partly.** The contrast arithmetic could come from craft-libs `theme`. CrewCraft's addon format and policy stay local: addons are installed on a person's own server and never leave it. `theme-store`'s shared machine-wide library does not fit that, so it is not a candidate |
| `crates/desktop-ui/src/text.rs`, `crates/server-core/src/html_text.rs`, the HTML-to-text part of `apps/crewcraft-server/src/import_teams.rs` | Plain text from HTML: a message's safe HTML for the text-only feed, search and previews; an imported message's HTML | `html`: a tolerant HTML lexer, entity decoding and escaping, with caps (`Limits`) | **Candidate, with the rich-text feed (M3).** Three small copies of one job is what rule 9 warns about. `html` could replace the importer's reader, which meets arbitrary HTML, first. The two readers of CrewCraft's own safe HTML only undo what `render` writes and may stay that small |
| `crates/server-core/src/render.rs` | Message text to safe HTML: code spans, bold and italic, `http(s)` links, everything else escaped | `markdown`: a CommonMark subset plus GitHub tables and strikethrough, import and export | **No, for now.** `render` deliberately supports a tiny, safe subset. Revisit if messages grow to full Markdown |
| Image previews in `crates/desktop-ui` (the `image` crate) | Decode PNG, JPEG, GIF and WebP attachments for previews (T333) | `image-codecs`: decoders for many raster formats, including these four, with decode `Limits` (it uses `image`, `image-webp` and its own crates underneath). Also `jpeg`, `gif`, `png` (writing), `webp` (the container) and `sniff` | **Not now.** `image-codecs` covers the four formats, but it brings a much larger tree for them: TIFF, EXR, JPEG XL and a JPEG encoder that craft-contrib issue #91 says carries `IJG`-licensed code, which is outside `deny.toml`'s list. Revisit if it offers a decode-only feature set. `sniff` could later name a file's type from its bytes instead of its extension |
| `crates/update` | Update rules: Ed25519-signed release manifests, file hashes, roll back on a failed health check. Apps update only from their own server, never the internet (REQUIREMENTS 2.21) | `update`: release checking, downloading and self-updating for the suite and its launcher, through `ureq` from published releases | **No.** Different trust model and network path. CrewCraft must not fetch updates from the internet |
| Device-record sealing in `apps/crewcraft` (`keyring-core`) | The enrolled device's record, sealed with a key kept in the system key store | `suite-account`: the suite's shared keychain and account list, so a person signs in once for every Craft app | **No.** A CrewCraft identity is a device certificate plus a one-time code per server, not a suite account. Sharing a sign-in across apps would weaken that |
| `crates/strict-toml` | A strict TOML subset for theme addons and release manifests | No TOML crate found (`jsonc` is JSON with comments; `settings` stores app settings) | **No counterpart.** Could be offered to craft-libs if another app needs strict small-file parsing |
| `crates/https` | A strict HTTPS client for the server's outgoing calls: OpenID Connect discovery and keys, token exchange, the external authorizer | `http-url`: URL parsing and redirect resolution only. It says it permits local and private addresses and is "not a network permission or SSRF policy" | **No.** CrewCraft's client is the policy (no redirects, bounded reads), which `http-url` explicitly is not |
| `crates/totp`, `crates/enroll`, `crates/accounts` | One-time passwords (RFC 6238, base32, `otpauth://`), enrollment codes, password hashing, PKCE | None found | **No counterpart.** These are CrewCraft's sign-in core. Offer them only if a Craft app asks |
| `crates/pki`, `crates/tls`, `crates/admission`, `crates/bootstrap` | The server's certificate authority, mutual TLS, who may complete the handshake, the bootstrap calls | None found (`smime` and `openpgp` are MailCraft's mail signatures) | **No counterpart; stays.** These are the reason CrewCraft exists |
| `crates/oidc`, `crates/authz` | OpenID Connect checks (JWS/JWK) and external authorization decisions | None found | **No counterpart.** |
| `crates/sframe`, `crates/media-auth`, `crates/media-crypto`, `crates/audio` | Call media: SFrame (RFC 9605) end-to-end encryption, media credentials, a pure-Rust crypto provider for the WebRTC stack, Opus audio | None found. `audio` and `audio-dsp` exist but are the suite's editing audio, not real-time call audio. craft-contrib RFC-0020 (live collaboration) defines only contracts, no media code | **No counterpart.** SFrame is a self-contained RFC implementation. It could be offered if the suite ever carries calls |
| `crates/proto`, `crates/server-core`, `crates/client-core`, `crates/ui-model` | CrewCraft's wire protocol, server and client logic | Not applicable | App-specific; stays (rule 9: app policy stays in the app) |
| `crates/desktop-ui` (widgets) | The window, drawn with plain egui widgets | `ui-contract` and `ui-widgets`: the Craft UI library with focus, test-kit and component contracts. craft-libs#437 tracks shared focus and announcement helpers | **Candidate, the biggest one.** It would bring the shared accessibility helpers that `docs/ACCESSIBILITY.md` lists as missing. It needs the egui fork decision above, so it is a decision for the owner and the UI work, not a drop-in |

## Not in CrewCraft yet, where craft-libs would be the first stop

| Need | craft-libs | Note |
|---|---|---|
| Translations (AGENTS.md rule 16) | `i18n`, which embeds the shared craft-i18n catalogs | Translations of a community app in the suite's shared catalogs would need the suite's agreement. A local catalog with the same English-key shape keeps that door open |
| Keyboard shortcuts and a shortcuts dialog (REQUIREMENTS 2.20; `docs/ACCESSIBILITY.md` gap 5) | `keymap` | Its canonical key-chord text form would let shortcuts be shown and remapped |
| Calendar and contacts (ROADMAP milestones) | `ical` (RFC 5545), `vcard` (2.1, 3.0, 4.0) | Use them when those milestones start, instead of writing new parsers |
| An automation interface (AGENTS.md rule 14) | `control` (the shared control channel), `mcp-server` | Only if CrewCraft adds automation. Rule 18's read and write roots then apply |
