#!/usr/bin/env bash
# validate.sh - the whole gate. Exit 0 passes, anything else fails. Runs the same anywhere: a CI runner, a cron, a shell.
#   ci/validate.sh            format, lint, tests, sanitize scan
#   ci/validate.sh --tasks    also install every open task's test into a scratch copy and report which pass
#                             (informational: open tasks are expected to fail; never changes the exit status)
# CARGO_DENY_REQUIRED=1 turns a missing cargo-deny into a failure (set it wherever licences must be checked: CI and
# release builds). Unset or empty, a missing cargo-deny is skipped and the run says so; any other value fails.
set -euo pipefail
cd "$(dirname "$0")/.."
step() { echo; echo "== $*"; }

step "rustfmt";  cargo fmt --all -- --check
step "clippy";   cargo clippy --workspace --all-targets --locked -- -D warnings
step "tests";    cargo test --workspace --locked
step "sanitize"; bash tools/sanitize-scan.sh
step "rust-only"; bash tools/rust-only.sh
step "agents";   bash tools/agents-check.sh --self-test
step "task names"; bash tools/task.sh check-names
skipped=""
step "windows check"
# The release ships crewcraft and crewcraft-server for Windows (docs/RELEASE.md), so both must compile for it. cargo check
# needs only the target's standard library, no linker. WINDOWS_CHECK_REQUIRED=1 turns a missing target into a failure.
case "${WINDOWS_CHECK_REQUIRED:-}" in
  ""|1) ;;
  *) echo "windows check: WINDOWS_CHECK_REQUIRED must be unset, empty or 1, not '${WINDOWS_CHECK_REQUIRED}'"; exit 1 ;;
esac
win_target=x86_64-pc-windows-gnu
if [ -d "$(rustc --print sysroot)/lib/rustlib/$win_target/lib" ]; then
  cargo check --locked --target "$win_target" -p crewcraft -p crewcraft-server
elif [ "${WINDOWS_CHECK_REQUIRED:-}" = 1 ]; then
  echo "windows check: the $win_target standard library is not installed, and WINDOWS_CHECK_REQUIRED=1"
  exit 1
else
  echo "windows check: the $win_target standard library is not installed here, SKIPPED"
  echo "               (rustup target add $win_target enables it; WINDOWS_CHECK_REQUIRED=1 makes this a failure)"
  skipped="${skipped} (windows check SKIPPED)"
fi

step "cargo-deny"
case "${CARGO_DENY_REQUIRED:-}" in
  ""|1) ;;
  *) echo "cargo-deny: CARGO_DENY_REQUIRED must be unset, empty or 1, not '${CARGO_DENY_REQUIRED}'"; exit 1 ;;
esac
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny --locked check
elif [ "${CARGO_DENY_REQUIRED:-}" = 1 ]; then
  echo "cargo-deny: not installed here, and CARGO_DENY_REQUIRED=1: licenses, advisories, bans and sources must be checked"
  exit 1
else
  echo "cargo-deny: not installed here, SKIPPED (licenses, advisories, bans and sources were not checked;"
  echo "            CARGO_DENY_REQUIRED=1 makes this a failure)"
  skipped="${skipped} (cargo-deny SKIPPED: licenses not checked)"
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
    # A task's test_cmd comes from a file a pull request can change, so only the expected shapes are ever run.
    . tools/task-names.sh
    if ! [[ "$tp" =~ $task_path_re ]]; then echo "REFUSED $id: test_path is not under crates/, apps/ or xtask/ with a task test name"; continue; fi
    if ! [[ "$cmd" =~ $task_cmd_re ]]; then echo "REFUSED $id: test_cmd is not 'cargo test -p <crate> --test t<n>_<name>'"; continue; fi
    mkdir -p "$scratch/$(dirname "$tp")"; cp "$d/test.rs" "$scratch/$tp"
    if (cd "$scratch" && export CARGO_TARGET_DIR="$repo/target/tasks" && eval "$cmd" >/dev/null 2>&1); then echo "pass  $id"; else echo "open  $id"; fi
  done
fi
echo; echo "validate: PASS${skipped}"
