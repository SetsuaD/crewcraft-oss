<h1 align="center">CrewCraft</h1>

<p align="center">
  <b>Self-hosted team chat; open source, built from scratch in pure Rust.</b>
</p>

<p align="center">
  Chats, teams with threaded channels, end-to-end encrypted calls and meetings, guests by invite link, shared files,
  documents you edit together, calendar, contacts, user management, plugins and themes, on a server you own.
  Rust from end to end: a Linux server, native egui apps for desktop and mobile, and the same client in the browser
  through WebAssembly.<br>
  <i>A community app by CRU Technologies, built to the Craft apps' conventions.</i>
</p>

<p align="center">
  <img alt="Written in Rust" src="https://img.shields.io/badge/written%20in-Rust-2b47b5?style=flat-square&logo=rust&logoColor=white">
  <img alt="Server on Linux; clients on Windows, macOS, Linux, Android, iOS and the web" src="https://img.shields.io/badge/runs%20on-Linux%20server%20%C2%B7%20desktop%20%C2%B7%20mobile%20%C2%B7%20web-3b5bdb?style=flat-square">
  <img alt="License: MIT OR Apache-2.0" src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-2b47b5?style=flat-square">
  <img alt="Strict mTLS: the server answers only enrolled devices" src="https://img.shields.io/badge/server-strict%20mTLS%20%C2%B7%20dark-3b5bdb?style=flat-square">
  <img alt="Status: early development" src="https://img.shields.io/badge/status-early%20development-lightgrey?style=flat-square">
</p>

> [!NOTE]
> **Early development.** Nothing here is usable yet. The server core is being built task by task; the plan is in
> [ROADMAP.md](ROADMAP.md), and [CONTRIBUTING.md](CONTRIBUTING.md) says how to pick up a task.

<p align="center">
  <a href="#why-crewcraft">Why CrewCraft</a> ·
  <a href="#what-works-today">What works today</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#roadmap">Roadmap</a> ·
  <a href="#contributing">Contributing</a> ·
  <a href="#license-and-credits">License and credits</a>
</p>

## Why CrewCraft

- **Dark by design.** The staff entrance completes a TLS handshake only with a device that holds a client certificate
  the server issued. Everything else gets a closed connection and no bytes: no login page, no banner, nothing to probe.
- **Every person, every sign-in.** Devices are enrolled from an emailed one-time code, keys never leave the device, and
  every person signs in with an authenticator-app code. The server never trusts a name a client claims.
- **Yours to run.** One server binary on a Linux machine or VM, with its own certificate authority created at install
  time. No third-party service is in the path, and nothing phones home.
- **Familiar from day one.** The layout and workflow people know from Microsoft Teams, with feature parity as the
  target ([docs/PARITY.md](docs/PARITY.md)), in CrewCraft's own look.
- **Keeps itself current.** The server updates itself from signed releases and rolls back if the new version fails its
  health check; every app then updates from its own server, never from the internet (REQUIREMENTS 2.21).
- **Your look, kept private.** Theme addons are files you install on your own server. They never leave it, and every
  theme must pass the accessibility contrast checks (REQUIREMENTS 2.19).
- **Rust from end to end.** Server, media server, desktop, web and phone apps, plugins and tooling; the gate refuses
  other languages (docs/SPEC.md section 7).
- **Built in the open.** Clean-room, MIT OR Apache-2.0, and every open task is a written behaviour plus the test that defines it.

## What works today

Libraries, each proven by the tests in `crates/*/tests`:

- **Sign-in building blocks:** one-time codes (RFC 6238, base32, `otpauth://` URIs), enrollment codes and the bootstrap
  key they derive, email identities, Argon2id password hashing, PKCE, sessions.
- **Wire protocol:** framing, handshake, messages, requests and push payloads.
- **Server core (in memory):** rooms and membership, messages and edits, mentions, unread counts, search, presence,
  invites, devices and enrollment, uploads, rate limits, retention, an operation journal and an audit chain.
- **Client core:** timeline, room view, inbox, outbox, notifications and the client session.

- **Server binary:** a dark TLS server with a `first-run` setup; see "Run a server" below.
- **Desktop app** (`crewcraft`, egui): enroll this device from an invitation link, set up an authenticator, sign in,
  see your rooms with unread counts, read and send messages. See "Use the desktop app" below.

Installers come with the first beta (`0.1.0-beta.1`, due 2026-12-31; see ROADMAP.md). Until then, build from source.

## Quick start

Rust 1.95 or newer.

```sh
git clone https://github.com/SetsuaD/crewcraft-oss.git
cd crewcraft-oss
bash ci/validate.sh                  # the whole gate: format, lint, every test, sanitize scan
cargo build --release --workspace
```

On Windows, `setup.bat`, `run_dev.bat` and `build.bat` do the same.

## Run a server

The server answers only enrolled devices. One data directory holds everything: its certificate authority, accounts,
rooms, the settings `first-run` records (`server.conf`) and the public root certificate (`trust-root.der`).

```sh
# Once, in a private terminal: the administrator's invitation is shown here and nowhere else.
crewcraft-server first-run /srv/crewcraft --name chat.example.org --admin admin@example.org --listen 0.0.0.0:7443
crewcraft-server serve /srv/crewcraft                       # until interrupted
crewcraft-server invite /srv/crewcraft person@example.org   # private terminal again
crewcraft-server room /srv/crewcraft admin@example.org General
crewcraft-server add-member /srv/crewcraft <room> admin@example.org person@example.org
```

`--name` is the DNS name or IP address clients connect to; the server certificate is signed for it. `--listen`
defaults to `127.0.0.1:7443`. Each invitation is shown as a
`crewcraft://enroll?server=<name:port>&code=<code>&root_sha256=<hex>` link and as its parts. Send the person the
link over a channel you trust: it is their invitation. `crewcraft-server --help` lists every command, including the
loopback-only `lab` ones.

## Use the desktop app

Run `crewcraft` (no arguments) to open the window.

1. **Join:** paste the invitation link and choose a password. The app fetches the server's root certificate and
   accepts it only if it matches the fingerprint in the link, so a link copied from a trusted message is all it needs.
2. **Authenticator:** add the entry the app shows to any authenticator app, then type its current code.
3. **Sign in** with your email, password and a fresh code. Every sign-in asks for a code.

The enrolled device is kept in your user data folder (`%APPDATA%\CrewCraft` on Windows,
`~/Library/Application Support/CrewCraft` on macOS, `$XDG_DATA_HOME/crewcraft` or `~/.local/share/crewcraft` on
Linux), so the next start goes straight to sign-in. On Unix the folder and file are owner-only; protecting the key with
the system's key store is planned (docs/SECURITY-DESIGN.md).

## Architecture

| Path | Owns |
|---|---|
| `crates/totp` | RFC 6238 one-time passwords, base32, `otpauth://` URIs |
| `crates/enroll` | enrollment codes and the bootstrap key they derive |
| `crates/accounts` | standalone accounts: email identity, password hashing, PKCE for mail-client sign-in |
| `crates/proto` | wire types shared by server and clients |
| `crates/server-core` | server behaviour: accounts, devices, rooms, messages, access rules |
| `crates/client-core` | client behaviour shared by desktop, web, Android, iOS |
| `apps/crewcraft-server` | the server binary (dark TLS, web client, admin console) |
| `apps/crewcraft` | the desktop client |
| `tasks/` | open work, one test per task |
| `xtask` | build tasks: `cargo xtask dist` writes the release packages ([docs/RELEASE.md](docs/RELEASE.md)) |
| `ci/validate.sh` | the whole gate |

| Read | For |
|---|---|
| [docs/SPEC.md](docs/SPEC.md) | what CrewCraft is: deliverables, onboarding, scope |
| [docs/SECURITY-DESIGN.md](docs/SECURITY-DESIGN.md) | keys, dark enrollment, TOTP, sessions |
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | the behaviours CrewCraft must have, section by section |
| [docs/CLEAN-ROOM.md](docs/CLEAN-ROOM.md) | rules that keep this an independent, publishable codebase |
| [docs/PARITY.md](docs/PARITY.md) | feature parity with Microsoft Teams, row by row |
| [docs/NON-RUST-DEPENDENCIES.md](docs/NON-RUST-DEPENDENCIES.md) | the only dependencies allowed to contain non-Rust code |
| [tasks/README.md](tasks/README.md) | work units, each defined by a test |

## Roadmap

[ROADMAP.md](ROADMAP.md) lists the milestones, each ending in something a person can run and proven by a command:
M1 the server core, M2 the dark TLS server, M3 the desktop client, then the web client with user management,
installers, mobile apps, calls and guests, files, calendar and contacts, collaborative documents, plugins and themes,
a parity sweep and 1.0.

## Downloads

None yet. The first beta, `0.1.0-beta.1` (due 2026-12-31, [ROADMAP.md](ROADMAP.md)), will be published on this
repository's Releases page: the desktop app for Windows (MSI), Linux (AppImage and deb) and macOS (DMG), and the server
for each, with a `SHA256SUMS.txt`. The packages are built with `cargo xtask dist`; how, and what each one holds, is in
[docs/RELEASE.md](docs/RELEASE.md). The beta builds are not code-signed: Windows warns before running them, and macOS
needs the app opened from the context menu the first time. `docs/ACCEPTANCE.md` lists what each release must pass first.

## Secrets & access

None. The server will generate its own certificate authority at install time, under its data directory; nothing secret
is committed to this repository, and the sanitize scan in the gate fails on private keys.

## Vendored binaries

None in the repository. The Linux AppImage release asset starts with the prebuilt AppImage runtime, which is not
committed: the person building a release passes it in, pinned by SHA-256 (version, source and license in
[docs/NON-RUST-DEPENDENCIES.md](docs/NON-RUST-DEPENDENCIES.md)).

## Contributing

Contributions of code, tests, documentation and bug reports are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and
[AGENTS.md](AGENTS.md) (the Craft house rules, and where CrewCraft differs), then pick an open task in
[`tasks/`](tasks/README.md). Report security problems privately as described in [SECURITY.md](SECURITY.md).

## License and credits

CrewCraft is licensed under either of the [Apache License 2.0](LICENSE-APACHE) or the [MIT license](LICENSE-MIT), at
your option. Copyright (c) 2026 CRU Technologies and the CrewCraft contributors. Required notices are in [NOTICE](NOTICE); assets, when there are
any, are listed with their authors and licenses in [ATTRIBUTION.md](ATTRIBUTION.md). Contributors are credited in
[`contributors/people.toml`](contributors/people.toml).

CrewCraft is an independent community project. It follows the conventions of the open-source Craft apps by the
ArtCraft team and uses [egui](https://github.com/emilk/egui) for its interface, but it is not made, endorsed or
reviewed by the ArtCraft team, and it carries none of their trademarks.
