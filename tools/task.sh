#!/usr/bin/env bash
# task.sh - install a task's test into the tree, or mark a task done.
#   tools/task.sh list
#   tools/task.sh install <task-id>     copy tasks/<id>/test.rs to its test_path
#   tools/task.sh done <task-id>        set status to done (checks the test is installed; run its test_cmd first)
set -euo pipefail
cd "$(dirname "$0")/.."
field() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "tasks/$1/task.json" "$2"; }
case "${1:-}" in
  list)
    for d in tasks/T*/; do id=$(basename "$d"); printf '%-24s %-6s %s\n' "$id" "$(field "$id" status)" "$(field "$id" title)"; done ;;
  install)
    id="${2:?task id}"; dst="$(field "$id" test_path)"
    task_path_re='^((crates|apps)/[a-z0-9-]+|xtask)/tests/t[0-9]+_[a-z0-9_]+\.rs$'   # task.json can come from a pull request
    [[ "$dst" =~ $task_path_re ]] || { echo "refused: test_path '$dst' is not under crates/, apps/ or xtask/ with a task test name" >&2; exit 1; }
    mkdir -p "$(dirname "$dst")"; cp "tasks/$id/test.rs" "$dst"; echo "installed $dst"
    cmd="$(field "$id" test_cmd)"
    [[ "$cmd" =~ ^cargo\ test\ -p\ [a-z0-9-]+\ --test\ t[0-9]+_[a-z0-9_]+$ ]] || { echo "refused: unexpected test_cmd in task.json" >&2; exit 1; }
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
  *) echo "usage: tools/task.sh list | install <id> | done <id>" >&2; exit 2 ;;
esac
