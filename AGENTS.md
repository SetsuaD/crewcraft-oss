# Working in CrewCraft

1. Read `docs/CLEAN-ROOM.md` first. Build from `docs/REQUIREMENTS.md` and `docs/SPEC.md`; copy no code, schema, strings or assets from other products.
2. Work comes from `tasks/`: a task is its `spec`, its `test.rs` and its listed files. Edit only the listed files.
3. The gate is `ci/validate.sh`. A change is done when the gate passes with the task's test installed.
4. Nothing private in the tree (the sanitize scan enforces it). Use `example.org` and documentation IP ranges in tests.
5. No new dependency without saying why; cryptography only from audited crates.
