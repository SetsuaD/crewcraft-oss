# CrewCraft roadmap

Each milestone ends in something a person can run, and has a `DONE_WHEN` that a command proves. Work inside a milestone
is cut into tasks under [`tasks/`](tasks/README.md): a written behaviour plus the test that defines it. Everything is
Rust ([docs/SPEC.md](docs/SPEC.md) section 7). The target is feature parity with Microsoft Teams, tracked row by row in
[docs/PARITY.md](docs/PARITY.md).

| M | Milestone | DONE_WHEN |
|---|---|---|
| M0 | **Foundations**: workspace, gate, TOTP and enrollment-code crates (tasks T001 to T006) | `ci/validate.sh` passes with every `tasks/T00*` test installed |
| M1 | **Server core**: accounts, devices, invitations, rooms, memberships, messages, cursor log, durable store, lock order, read-back writes | `cargo test -p crewcraft-server-core` covers the REQUIREMENTS 2.1 and 2.2 behaviours |
| M2 | **Dark TLS server + enrollment**: rustls with the verifier from SECURITY-DESIGN.md 3, CA and certificate issuance, TOTP activation, sessions, WebSocket live updates; build tooling moves from shell to `cargo xtask` | an integration test enrolls a device from a code, signs in with TOTP, and a client without a certificate gets a failed handshake and zero bytes |
| M3 | **Desktop client** (egui) in the CrewCraft layout (REQUIREMENTS 2.20) with the built-in themes and theme addons (2.19): enroll, rooms, teams and channels, messages, files, presence, search | enroll and chat between two desktop clients on two operating systems |
| M4 | **Web client + admin console**: the same Rust client compiled to WebAssembly, served by the server; full user management (2.12); first-run setup wizard; invitation email (SMTP) | a browser on an enrolled machine uses the web client; an administrator imports people from CSV, sets a policy and the wizard sends a real invitation |
| M5 | **Installers and updates**: server (Linux, Windows, macOS), desktop client (Windows, macOS, Linux); server self-update with rollback, and clients updating from their server (2.21) | install, upgrade, repair and uninstall each pass on a clean VM per platform; a server updates itself from a signed release, rolls back when its health check fails, and a desktop client then updates from that server |
| M6 | **Android and iOS apps**, all Rust, over `crewcraft-client-core` with hardware-backed device keys | a phone enrolls from an emailed code and chats; TOTP required |
| M7 | **Calls and meetings**: Rust media server, end-to-end encrypted audio, video and screen sharing, guest lobby, guest invite links (2.13), push while closed | the SPEC.md section 6 real-device test, plus a guest who joins a team from an invite link |
| M8 | **Files and sharing** (2.14): team and personal libraries, folders, versions, recycle bin, share links, WebDAV | two people on two platforms share a folder, restore an earlier version, and mount the library from the OS file manager |
| M9 | **Calendar and contacts** (2.16, 2.17): calendars, invitations with RSVP, scheduling assistant, directory, org chart, personal contacts, CalDAV and CardDAV | an invitation sent from CrewCraft is answered from an OS calendar app over CalDAV, and the meeting starts from the event |
| M10 | **Collaborative documents** (2.15): rich-text co-editing in every client, comments, history, offline merge, export | two people edit one document at once on two platforms, one of them offline for part of it, and both end with the same text |
| M11 | **Plugins and themes** (2.18, 2.19): WebAssembly plugin host, `crewcraft-plugin-sdk`, declarative plugin UI, theme packages | a sample bot, a slash command and a channel tab built with the SDK run on a real server; a theme package installs and passes the contrast check |
| M12 | **Parity sweep**: whiteboard, spreadsheets, live cards, breakout rooms, webinars, captions and the other rows of PARITY.md | every PARITY.md row is `done` or a recorded non-goal |
| M13 | **1.0 release**: an external security review and signed installers for every platform | review findings closed and 1.0 tagged |

## First beta

The first public beta (`0.1.0-beta.1`) is M2 plus a thin slice of M3. A person installs the server, runs its first-run
setup, enrolls two desktop clients from codes, signs in with TOTP on each, and the two exchange messages in a room.
Teams, files, presence, search and themes come in later betas.

DONE_WHEN: a release carries a Windows MSI, a Linux AppImage and deb, a macOS DMG, the Linux server and `SHA256SUMS.txt`,
and that two-client flow passes on a clean machine per platform.

The desktop client is split so most of it is tested without a window:

| Task | Piece | Crate |
|---|---|---|
| T300 | Room list: followed rooms, the open room, unread badges | ui-model |
| T301 | Composer: one draft per room, trimming and length limit | ui-model |
| T302 | Feed rows: messages and pending sends, grouped by author | ui-model |

Still to write: the egui views over these three, and the worker thread that runs the chat session for the window.
The egui views wait on a font decision, because every usable UI font is under the SIL Open Font License, which
`deny.toml` does not list yet.
