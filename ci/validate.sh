#!/usr/bin/env bash
# validate.sh - the whole gate. Exit 0 passes, anything else fails. Runs the same anywhere: a CI runner, a cron, a shell.
#   ci/validate.sh            format, lint, tests, sanitize scan
#   ci/validate.sh --tasks    also install every open task's test into a scratch copy and report which pass
#                             (informational: open tasks are expected to fail; never changes the exit status)
set -euo pipefail
cd "$(dirname "$0")/.."
step() { echo; echo "== $*"; }

step "rustfmt";  cargo fmt --all -- --check
step "clippy";   cargo clippy --workspace --all-targets --locked -- -D warnings
step "tests";    cargo test --workspace --locked
step "sanitize"; bash tools/sanitize-scan.sh
step "rust-only"; bash tools/rust-only.sh
step "cargo-deny"
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny --locked check
else
  echo "cargo-deny: not installed here, SKIPPED (licenses, advisories, bans and sources were not checked)"
fi

if [ "${1:-}" = "--tasks" ]; then
  step "open tasks (informational)"
  repo="$PWD"; scratch="$(mktemp -d)"; trap 'rm -rf "$scratch"' EXIT
  git ls-files -z | xargs -0 -I{} cp --parents -- {} "$scratch"
  for d in tasks/T*/; do
    id=$(basename "$d")
    st=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$d/task.json")
    [ "$st" = open ] || continue
    tp=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["test_path"])' "$d/task.json")
    cmd=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["test_cmd"])' "$d/task.json")
    # A task's test_cmd comes from a file a pull request can change, so only the one expected shape is ever run.
    task_cmd_re='^cargo test -p [a-z0-9-]+ --test t[0-9]+_[a-z0-9_]+$'
    task_path_re='^((crates|apps)/[a-z0-9-]+|xtask)/tests/t[0-9]+_[a-z0-9_]+\.rs$'
    if ! [[ "$tp" =~ $task_path_re ]]; then echo "REFUSED $id: test_path is not under crates/, apps/ or xtask/ with a task test name"; continue; fi
    if ! [[ "$cmd" =~ $task_cmd_re ]]; then echo "REFUSED $id: test_cmd is not 'cargo test -p <crate> --test t<n>_<name>'"; continue; fi
    mkdir -p "$scratch/$(dirname "$tp")"; cp "$d/test.rs" "$scratch/$tp"
    if (cd "$scratch" && export CARGO_TARGET_DIR="$repo/target/tasks" && eval "$cmd" >/dev/null 2>&1); then echo "pass  $id"; else echo "open  $id"; fi
  done
fi
echo; echo "validate: PASS"
