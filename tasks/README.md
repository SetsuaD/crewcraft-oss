# Tasks

Each folder is one unit of work, defined by a test, small enough for one change:

- `task.json`: `id`, `title`, the `crate`, the `files` the change may edit, where the test goes (`test_path`), the
  command that proves it (`test_cmd`), `depends_on`, a plain-language `spec`, and `status` (`open`, `done`).
- `test.rs`: the test. It is the contract: a task is done when its test passes, `ci/validate.sh` passes with it installed,
  and a reviewer has read the change.

Work a task by hand:

```bash
tools/task.sh install T001-base32   # copies test.rs to test_path
cargo test -p crewcraft-totp --test t001_base32   # red, then make it green by editing only the listed files
tools/task.sh done T001-base32      # marks status done
```

Writing a new task: describe the behaviour in `spec`, write `test.rs` against the public API (with expected values from a
standard, an RFC test vector, or computed independently, never from the implementation), list the files, and keep the
stub in the source compiling (`todo!("T00N: ...")`) so the gate stays green until the task lands.

The same folders feed automated workers (local models in a test-gated loop): they receive `spec`, `test.rs` and the
listed files, and their output is only ever a proposed change that a reviewer accepts or rejects.
