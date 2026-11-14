#!/usr/bin/env bash
# sanitize-scan.sh - fail if the tree holds anything that must never be published (docs/CLEAN-ROOM.md rule 4).
# Generic checks live here. A deployment adds its own patterns (its host and domain names) by setting
# SANITIZE_EXTRA_PATTERNS to a file of extended regexes, one per line ('#' comments allowed), kept outside the
# published tree, so the public tree never lists them.
# A line containing "sanitize-scan: allow" is exempt.
# Exit 0 clean, 1 findings, 2 cannot scan.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
exclude='^LICENSE-APACHE$|^NOTICE$|^Cargo\.lock$'
# NUL-separated, so git never quotes or escapes a name and no file is silently skipped.
mapfile -d '' -t files < <(git ls-files -z | grep -z -v -E "$exclude")
[ "${#files[@]}" -gt 0 ] || { echo "sanitize-scan: no tracked files" >&2; exit 2; }
fail=0

# report <description> <hits>: hits are grep -n -o lines "file:line:match"
report() {
  [ -n "$2" ] || return 0
  echo "FAIL $1:"; printf '%s\n' "$2" | head -20; fail=1
}
# matches <ERE> [grep flags]: every "file:line:match" outside allow-listed lines. Each file is grepped on its own, so a
# path is never parsed back out of grep's output (a crafted file name cannot become a sed script), and the line number
# must be digits before it reaches sed.
matches() {
  local pat="$1"; shift
  local f hit n
  local -a hits
  # One pass finds the files with any hit; names come back NUL-separated, so nothing is parsed out of them.
  mapfile -d '' -t hits < <(grep -l -Z -I -E "$@" -- "$pat" "${files[@]}" 2>/dev/null)
  for f in "${hits[@]}"; do
    grep -n -I -o -E "$@" -- "$pat" "$f" 2>/dev/null | while IFS= read -r hit; do
      n="${hit%%:*}"
      [[ "$n" =~ ^[0-9]+$ ]] || continue
      sed -n "${n}p" -- "$f" | grep -q 'sanitize-scan: allow' || printf '%s:%s\n' "$f" "$hit"
    done
  done
}

# File names that tools could misread: a colon (grep output), a leading dash (options) or control characters.
report "unsafe file name (':' , leading '-' or control character)" \
  "$(git ls-files -z | grep -z -E '(^-|/-|:|[[:cntrl:]])' | tr '\0' '\n')"

report "private key material" "$(matches '-----BEGIN ([A-Z]+ )*PRIVATE KEY-----')"
report "email address outside example domains" \
  "$(matches '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' | grep -v -i -E '@(example\.(org|com|net)|users\.noreply\.github\.com)$')"
report "IPv4 address outside loopback and documentation ranges" \
  "$(matches '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | grep -v -E ':(127\.[0-9.]+|0\.0\.0\.0|192\.0\.2\.[0-9]+|198\.51\.100\.[0-9]+|203\.0\.113\.[0-9]+)$')"

extra="${SANITIZE_EXTRA_PATTERNS:-}"
if [ -n "$extra" ] && [ -f "$extra" ]; then
  while IFS= read -r pat; do
    case "$pat" in ''|'#'*) continue ;; esac
    report "deployment pattern from $extra" "$(matches "$pat" -i)"
  done < "$extra"
fi

[ "$fail" -eq 0 ] && echo "sanitize-scan: clean (${#files[@]} files)"
exit "$fail"
