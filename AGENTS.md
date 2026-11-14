# Working in CrewCraft

## House rules

CrewCraft follows the shared rules of the Craft apps, kept in
[storytold/craft-contrib](https://github.com/storytold/craft-contrib): the core rules in
[`standards/house-rules-core.md`](https://github.com/storytold/craft-contrib/blob/main/standards/house-rules-core.md)
and, because this is a native Rust repository, the Rust rules in
[`standards/house-rules-rust.md`](https://github.com/storytold/craft-contrib/blob/main/standards/house-rules-rust.md),
including its license allowlist. Read them before your first change. The rules below may be stricter, never weaker.

Where CrewCraft differs, and why:

- **CI.** There are no hosted workflows. `ci/validate.sh` is the whole gate; contributors run it before review and
  the maintainers run it on their own machines. It does not call `storytold/craft-common-actions`.
- **Never crash.** The workspace forbids `unsafe` and turns the crash lints into errors through `[workspace.lints]`
  plus `clippy -D warnings`, instead of a `deny` attribute in each crate root. One named exception until task T144
  lands: the `todo!()` stubs in `crates/server-core/src/durable.rs`, so `clippy::todo` is not yet enabled.
- **Licenses.** CrewCraft itself is Apache-2.0 only. `deny.toml` also admits a few permissive identifiers that are
  common in the Rust dependency tree and are not on the Craft allowlist (`Apache-2.0 WITH LLVM-exception`, `Zlib`,
  `Unicode-3.0`, `CDLA-Permissive-2.0`); they are reviewed before any catalog request.
- **Credits.** `contributors/people.toml` as in the Craft apps: only your own entry, only in your own pull request.

## CrewCraft rules

1. Read `docs/CLEAN-ROOM.md` first. Build from `docs/REQUIREMENTS.md` and `docs/SPEC.md`; copy no code, schema, strings or assets from other products.
2. Work comes from `tasks/`: a task is its `spec`, its `test.rs` and its listed files. Edit only the listed files.
3. The gate is `ci/validate.sh`. A change is done when the gate passes with the task's test installed.
4. Nothing private in the tree (the sanitize scan enforces it). Use `example.org` and documentation IP ranges in tests.
5. No new dependency without saying why; cryptography only from audited crates.
