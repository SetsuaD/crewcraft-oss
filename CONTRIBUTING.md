# Contributing to CrewCraft

Thank you for helping. CrewCraft is a self-hosted team chat written in Rust; its server answers only devices it has
enrolled. Contributions of code, tests, documentation, translations and bug reports are all welcome.

## Before you start

- **Read [docs/CLEAN-ROOM.md](docs/CLEAN-ROOM.md).** CrewCraft is written from scratch. Do not copy code, schemas,
  strings or assets from other projects, including other chat servers; open-source *dependencies* under licenses
  compatible with MIT OR Apache-2.0 are fine.
- **Read [AGENTS.md](AGENTS.md).** The same short rules apply to people and to AI coding agents.
- **Read the Craft house rules.** CrewCraft follows the shared rules of the Craft apps; [AGENTS.md](AGENTS.md)
  links them and lists where CrewCraft differs.
- **Security issues are not filed as issues.** See [SECURITY.md](SECURITY.md).

## Finding work

- Open work is in [`tasks/`](tasks/README.md). Each task is a folder with a written `spec`, a `test.rs` that defines
  "done", and the list of files the change may touch. Milestones are in [ROADMAP.md](ROADMAP.md).
- **Claim before you build:** comment on the task's issue (or open one named after the task, e.g. `T150 room export`)
  and open a draft pull request early, so two people don't do the same work.
- Larger ideas (new features, protocol changes, new dependencies) start as an issue so the design can be agreed first.

## Making a change

- **One change per pull request**, on a branch named `feature/`, `bugfix/`, `docs/`, `test/`, `refactor/` or `chore/`
  followed by the task id or a short name, e.g. `feature/t150-room-export`.
- Pull requests are squash-merged, so the PR title becomes the commit message. Write it in plain English: what changed
  for the person using CrewCraft or for the developer.
- Safe Rust only: the workspace forbids `unsafe` code. Code must not panic on bad input from the network or from files.
- Tests use `example.org` / `example.com` addresses and documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`). No real names, hosts, keys or secrets anywhere, ever.
- A new dependency needs a sentence in the PR saying why it is needed. Cryptography comes only from audited crates.

## Checks

Run the whole gate before asking for review:

```sh
bash ci/validate.sh
```

It runs `cargo fmt --check`, `cargo clippy` with warnings denied, every test, the sanitize scan, the Rust-only check
and `cargo deny check` (licenses, advisories and sources). Without `cargo-deny` installed, that last step is skipped
and the run says so; `CARGO_DENY_REQUIRED=1`, set in CI and release builds, makes a missing `cargo-deny` a failure. The scan refuses PEM
private keys, email addresses outside the example domains, IPv4 addresses outside loopback and documentation ranges,
and unsafe file names; a deployment can add its own host and domain patterns with `SANITIZE_EXTRA_PATTERNS`. It is a
safety net, not a guarantee: you are still responsible for not committing private data. Turn on the pre-commit secret scan once per clone:

```sh
git config core.hooksPath .githooks
```

This repository does not use hosted CI services, so please run the gate yourself before asking for review.
Maintainers read a pull request before running any of its code, and run contributors' code only in a disposable,
network-restricted environment that holds no credentials.

## Credits

Everyone who contributes is credited by GitHub username. To be credited by more (a real name, a display name, or a
role), add **your own** entry to [`contributors/people.toml`](contributors/people.toml) in your own pull request.
Never add or edit someone else's entry.

Changes to the security-sensitive code (enrollment, one-time codes, accounts, the server's access rules, the scan)
are reviewed by the security contributor listed there; [`.github/CODEOWNERS`](.github/CODEOWNERS) requests that
review automatically.

## License

CrewCraft is licensed under either of the [Apache License 2.0](LICENSE-APACHE) or the [MIT license](LICENSE-MIT), at
your option. Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in
CrewCraft, as defined in the Apache-2.0 license, is dual licensed as above, without any additional terms or
conditions, and you confirm that you have the right to submit it.
