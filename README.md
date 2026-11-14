# CrewCraft

**Self-hosted team chat, written in Rust.** Direct messages, group rooms, teams with threaded channels, files,
presence, search, and end-to-end encrypted calls, on a server you own. Every device is enrolled from an emailed
one-time code, every person signs in with a mandatory authenticator-app code, and the server answers nothing to a
device it has not enrolled.

> **Status: early development.** Nothing here is usable yet. The plan is in [docs/ROADMAP.md](docs/ROADMAP.md), and
> [CONTRIBUTING.md](CONTRIBUTING.md) says how to help.

| Read | For |
|---|---|
| [docs/SPEC.md](docs/SPEC.md) | what CrewCraft is: deliverables, onboarding, scope |
| [docs/SECURITY-DESIGN.md](docs/SECURITY-DESIGN.md) | keys, dark enrollment, TOTP, sessions |
| [docs/ROADMAP.md](docs/ROADMAP.md) | milestones and how each is proven |
| [docs/REQUIREMENTS.md](docs/REQUIREMENTS.md) | the behaviours CrewCraft must have, section by section |
| [docs/CLEAN-ROOM.md](docs/CLEAN-ROOM.md) | rules that keep this an independent, publishable codebase |
| [tasks/README.md](tasks/README.md) | work units, each defined by a test |

## Layout

| Path | Owns |
|---|---|
| `crates/totp` | RFC 6238 one-time passwords, base32, `otpauth://` URIs |
| `crates/enroll` | enrollment codes and the bootstrap key they derive |
| `crates/proto` | wire types shared by server and clients |
| `crates/server-core` | server behaviour: accounts, devices, rooms, messages, access rules |
| `crates/client-core` | client behaviour shared by desktop, web, Android, iOS |
| `apps/crewcraft-server` | the server binary (TLS, web client, admin console) |
| `apps/crewcraft` | the desktop client |
| `tasks/` | open work, one test per task |
| `ci/validate.sh` | the whole gate: format, lint, tests, sanitize scan |

## Build

Rust 1.95 or newer. `bash ci/validate.sh` runs the gate; `cargo build --release --workspace` builds. On Windows,
`setup.bat`, `run_dev.bat` and `build.bat` do the same.

## Secrets & access

None yet. The server will generate its own certificate authority at install time, under its data directory; nothing
secret is committed to this repository, and the sanitize scan in the gate fails on private keys.

## Vendored binaries

None.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Open work is in [`tasks/`](tasks/README.md), one test per task. Report security
problems privately as described in [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). See [NOTICE](NOTICE).
