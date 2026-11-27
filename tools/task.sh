#!/usr/bin/env bash
# task.sh - install a task's test into the tree, or mark a task done.
#   tools/task.sh list
#   tools/task.sh install <task-id>     copy tasks/<id>/test.rs to its test_path
#   tools/task.sh done <task-id>        set status to done (checks the test is installed; run its test_cmd first)
#   tools/task.sh check-names           every task's test_path and test_cmd has an accepted shape, and bad ones do not
set -euo pipefail
cd "$(dirname "$0")/.."
. tools/task-names.sh
field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "tasks/$1/task.json" "$2"; }
case "${1:-}" in
  list)
    for d in tasks/T*/; do id=$(basename "$d"); printf '%-24s %-6s %s\n' "$id" "$(field "$id" status)" "$(field "$id" title)"; done ;;
  install)
    id="${2:?task id}"; dst="$(field "$id" test_path)"
    [[ "$dst" =~ $task_path_re ]] || { echo "refused: test_path '$dst' is not under crates/, apps/ or xtask/ with a task test name" >&2; exit 1; }
    mkdir -p "$(dirname "$dst")"; cp "tasks/$id/test.rs" "$dst"; echo "installed $dst"
    cmd="$(field "$id" test_cmd)"
    [[ "$cmd" =~ $task_cmd_re ]] || { echo "refused: unexpected test_cmd in task.json" >&2; exit 1; }
    echo "prove it: $cmd" ;;
  done)
    id="${2:?task id}"
    [ -f "$(field "$id" test_path)" ] || { echo "test not installed: $(field "$id" test_path)" >&2; exit 1; }
    python3 - "$id" <<'EOF'
import json, sys
p = f"tasks/{sys.argv[1]}/task.json"
d = json.load(open(p)); d["status"] = "done"
open(p, "w", newline="\n").write(json.dumps(d, indent=2) + "\n")
EOF
    echo "$id done" ;;
  check-names)
    bad=0
    # One python run for every task.json (one per field is slow): tab-separated fields, one task per line, written as
    # bytes so Python on Windows adds no CR.
    while IFS=$'\t' read -r id path cmd; do
      [[ "$path" =~ $task_path_re ]] || { echo "refused test_path in $id: $path" >&2; bad=1; }
      [[ "$cmd" =~ $task_cmd_re ]] || { echo "refused test_cmd in $id: $cmd" >&2; bad=1; }
    done < <(python3 -c 'import glob, json, os, sys
for p in sorted(glob.glob("tasks/T*/task.json")):
    d = json.load(open(p))
    line = "\t".join([os.path.basename(os.path.dirname(p)), d["test_path"], d["test_cmd"]]) + "\n"
    sys.stdout.buffer.write(line.encode())')
    # Negative controls: shapes that must stay refused, so a widened pattern cannot quietly accept anything.
    bad_paths=(crates/audio/tests/t360E2_audio.rs crates/audio/tests/t_audio.rs crates/audio/tests/x360_audio.rs
      crates/audio/tests/t360e2-audio.rs crates/audio/tests/t360e2.rs crates/audio/src/t360e2_audio.rs
      crates/audio/tests/../../../t1_x.rs /crates/audio/tests/t360e2_audio.rs)
    bad_cmds=("cargo test -p crewcraft-audio --test t360e2_audio; true" "cargo test -p crewcraft-audio --test t360E2_audio"
      "cargo test -p crewcraft-audio --test t360e2" "cargo test --workspace" "cargo test -p crewcraft-audio --test t_audio")
    for path in "${bad_paths[@]}"; do
      if [[ "$path" =~ $task_path_re ]]; then echo "accepted a bad test_path: $path" >&2; bad=1; fi
    done
    for cmd in "${bad_cmds[@]}"; do
      if [[ "$cmd" =~ $task_cmd_re ]]; then echo "accepted a bad test_cmd: $cmd" >&2; bad=1; fi
    done
    [ "$bad" = 0 ] || exit 1
    echo "task names: every task's test_path and test_cmd is accepted; the bad shapes are refused" ;;
  *) echo "usage: tools/task.sh list | install <id> | done <id> | check-names" >&2; exit 2 ;;
esac
