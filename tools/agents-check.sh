#!/usr/bin/env bash
# agents-check.sh - fail unless AGENTS.md carries the shared Craft agent rules unchanged.
#
# AGENTS.md starts with storytold/craft-contrib's standards/app-agents.md, copied between
#   <!-- craft-agents:start source=<craft-contrib commit> sha256=<digest> -->  and  <!-- craft-agents:end -->
# (RFC-0072). craft-contrib's own check (craft-common-actions actions/house-rules/house_rules.py) runs in hosted CI,
# which CrewCraft does not use, so this script runs the same checks locally:
#   1. exactly one craft-agents block, with a well-formed start marker, and none of the retired craft-house-rules blocks;
#   2. the block's text, normalized as house_rules.py normalizes it (no BOM, LF line ends, one final newline), hashes
#      to the sha256 recorded in its start marker, so a hand edit inside the block fails;
#   3. the recorded commit and digest are the ones pinned below, so a digest rewritten to suit an edit fails too;
#   4. with CRAFT_CONTRIB_DIR set to a craft-contrib clone, the block equals standards/app-agents.md at the recorded
#      commit and that commit is on the clone's origin/main (or main). CRAFT_CONTRIB_REQUIRED=1 makes a missing clone
#      a failure; unset or empty skips step 4 and says so; any other value fails.
# Refreshing the copy: replace the block with the newer standards/app-agents.md and update PINNED_* in the same change.
#
#   tools/agents-check.sh              check ./AGENTS.md
#   tools/agents-check.sh FILE         check FILE instead
#   tools/agents-check.sh --self-test  check AGENTS.md, then show that a one-byte edit inside the block fails
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

PINNED_SOURCE=646f558b8a9c0319faea6c938454634de5054864
PINNED_SHA256=41dc0e35957946bfe7639237fbf1eca92093fe7f6bd76a778779c359c4e4a82a
START_RE='^<!-- craft-agents:start source=([0-9a-f]{40}) sha256=([0-9a-f]{64}) -->$'
END_LINE='<!-- craft-agents:end -->'

# Prints the normalized block body of $1 to stdout; prints problems to stderr and returns 1.
block_body() {
  local file=$1 starts ends
  starts=$(grep -c -- '<!-- *craft-agents:start' "$file" || true)
  ends=$(grep -c -x -- "$END_LINE" "$file" || true)
  if grep -q -- '<!-- *craft-house-rules:' "$file"; then
    echo "agents-check: $file still has a retired craft-house-rules block (RFC-0072)" >&2; return 1
  fi
  if [ "$starts" != 1 ] || [ "$ends" != 1 ]; then
    echo "agents-check: $file needs exactly one craft-agents start and end marker (found $starts and $ends)" >&2
    return 1
  fi
  # The body: every line after the start marker up to the end marker; BOM dropped, CRLF and lone CR become LF.
  sed '1s/^\xEF\xBB\xBF//' "$file" | sed 's/\r$//' | tr '\r' '\n' | awk -v end="$END_LINE" '
    inside && $0 == end { done = 1; exit }
    inside { print }
    /^<!-- craft-agents:start / { inside = 1 }
    END { if (!done) exit 1 }'
}

check_file() {
  local file=$1 marker source recorded body actual canonical ref
  [ -f "$file" ] || { echo "agents-check: $file not found" >&2; return 1; }
  marker=$(sed 's/\r$//' "$file" | grep -m1 -- '<!-- *craft-agents:start' || true)
  if ! [[ "$marker" =~ $START_RE ]]; then
    echo "agents-check: $file: the craft-agents start marker is missing or malformed" >&2; return 1
  fi
  source=${BASH_REMATCH[1]}; recorded=${BASH_REMATCH[2]}
  body=$(block_body "$file") || { echo "agents-check: $file: no complete craft-agents block" >&2; return 1; }
  # Command substitution drops trailing newlines; printf adds back exactly one, as house_rules.py's normalize does.
  actual=$(printf '%s\n' "$body" | sha256sum | cut -d' ' -f1)
  if [ "$actual" != "$recorded" ]; then
    echo "agents-check: $file: the craft-agents block does not match its sha256 (edited inside the markers?)" >&2
    return 1
  fi
  if [ "$source" != "$PINNED_SOURCE" ] || [ "$recorded" != "$PINNED_SHA256" ]; then
    echo "agents-check: $file: the block records $source / $recorded, not the pinned copy" >&2
    echo "              (refresh the copy and PINNED_* in tools/agents-check.sh in the same change)" >&2
    return 1
  fi
  case "${CRAFT_CONTRIB_REQUIRED:-}" in
    ""|1) ;;
    *) echo "agents-check: CRAFT_CONTRIB_REQUIRED must be unset, empty or 1, not '${CRAFT_CONTRIB_REQUIRED}'" >&2; return 1 ;;
  esac
  if [ -z "${CRAFT_CONTRIB_DIR:-}" ]; then
    if [ "${CRAFT_CONTRIB_REQUIRED:-}" = 1 ]; then
      echo "agents-check: CRAFT_CONTRIB_REQUIRED=1 but CRAFT_CONTRIB_DIR is not set" >&2; return 1
    fi
    echo "agents-check: $file matches its digest and the pinned copy; comparison with craft-contrib SKIPPED (set CRAFT_CONTRIB_DIR)"
    return 0
  fi
  ref=$(git -C "$CRAFT_CONTRIB_DIR" rev-parse -q --verify origin/main 2>/dev/null || git -C "$CRAFT_CONTRIB_DIR" rev-parse -q --verify main 2>/dev/null || true)
  if [ -z "$ref" ] || ! git -C "$CRAFT_CONTRIB_DIR" merge-base --is-ancestor "$source" "$ref" 2>/dev/null; then
    echo "agents-check: $source is not on craft-contrib main in $CRAFT_CONTRIB_DIR (or the clone cannot be read)" >&2; return 1
  fi
  canonical=$(git -C "$CRAFT_CONTRIB_DIR" show "$source:standards/app-agents.md" | sed '1s/^\xEF\xBB\xBF//' | sed 's/\r$//' | tr '\r' '\n') || {
    echo "agents-check: cannot read standards/app-agents.md at $source" >&2; return 1; }
  if [ "$canonical" != "$body" ]; then
    echo "agents-check: $file: the block differs from standards/app-agents.md at $source" >&2; return 1
  fi
  echo "agents-check: $file matches standards/app-agents.md at $source (on craft-contrib main)"
}

if [ "${1:-}" = "--self-test" ]; then
  check_file AGENTS.md
  scratch=$(mktemp -d); trap 'rm -rf "$scratch"' EXIT
  # Negative control: change one byte inside the block (the first "MUST" becomes "MUSt"); the check must fail.
  awk '!done && /MUST/ { sub(/MUST/, "MUSt"); done = 1 } { print }' AGENTS.md > "$scratch/AGENTS.md"
  if cmp -s AGENTS.md "$scratch/AGENTS.md"; then echo "agents-check: self-test could not edit the copy" >&2; exit 1; fi
  if check_file "$scratch/AGENTS.md" 2>/dev/null; then
    echo "agents-check: self-test FAILED: a one-byte edit inside the block was not caught" >&2; exit 1
  fi
  echo "agents-check: self-test passed: a one-byte edit inside the block fails the check"
  exit 0
fi
check_file "${1:-AGENTS.md}"
