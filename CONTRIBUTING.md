# Contributing to CrewCraft

Thank you for helping. CrewCraft is a self-hosted team chat written in Rust; its server answers only devices it has
enrolled. Contributions of code, tests, documentation, translations and bug reports are all welcome.

## Before you start

- **Read [docs/CLEAN-ROOM.md](docs/CLEAN-ROOM.md).** CrewCraft is written from scratch. Do not copy code, schemas,
  strings or assets from other projects, including other chat servers; open-source *dependencies* under licenses
  compatible with Apache-2.0 are fine.
- **Read [AGENTS.md](AGENTS.md).** The same short rules apply to people and to AI coding agents.
- **Security issues are not filed as issues.** See [SECURITY.md](SECURITY.md).

## Finding work

- Open work is in [`tasks/`](tasks/README.md). Each task is a folder with a written `spec`, a `test.rs` that defines
  "done", and the list of files the change may touch. Milestones are in [docs/ROADMAP.md](docs/ROADMAP.md).
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

It runs `cargo fmt --check`, `cargo clippy` with warnings denied, every test, and the sanitize scan. The scan refuses PEM
private keys, email addresses outside the example domains, IPv4 addresses outside loopback and documentation ranges,
and unsafe file names; a deployment can add its own host and domain patterns with `SANITIZE_EXTRA_PATTERNS`. It is a
safety net, not a guarantee: you are still responsible for not committing private data. Turn on the pre-commit secret scan once per clone:

```sh
git config core.hooksPath .githooks
```

This repository does not use hosted CI services, so please run the gate yourself before asking for review.
Maintainers read a pull request before running any of its code, and run contributors' code only in a disposable,
network-restricted environment that holds no credentials.

## License

CrewCraft is licensed under the [Apache License 2.0](LICENSE). By submitting a contribution you agree that it is
licensed under the same terms (Apache-2.0, section 5), and that you have the right to submit it.
