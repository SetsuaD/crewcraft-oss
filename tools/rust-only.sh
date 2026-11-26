#!/usr/bin/env bash
# CrewCraft is written in Rust (docs/SPEC.md section 7). Fails on
#   1. a tracked source file in a language other than Rust, outside the launcher and transitional tooling list, and
#   2. a native build helper in Cargo.lock that docs/NON-RUST-DEPENDENCIES.md does not list, and
#   3. native code in the dependency tree of a crate that must stay pure Rust (the media server and its crates).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fail=0
code_ext='c|cc|cpp|cxx|h|hh|hpp|m|mm|swift|kt|kts|java|js|mjs|cjs|jsx|ts|tsx|py|go|rb|php|cs|dart|lua|pl|zig|s|asm|wat|ps1|psm1|cmd|sh|bat'
# Root .bat launchers stay (one line each around cargo). Shell tooling in ci/, tools/ and .githooks/ moves to
# `cargo xtask` in milestone M2 and leaves this list then.
allowed='^[^/]+\.bat$|^ci/[^/]+\.sh$|^tools/[^/]+\.sh$'

while IFS= read -r -d '' f; do
  lower=$(printf '%s' "$f" | tr '[:upper:]' '[:lower:]')
  if printf '%s' "$lower" | grep -qE "\.(${code_ext})$"; then
    if ! printf '%s' "$f" | grep -qE "$allowed"; then
      echo "rust-only: non-Rust source file: $f"
      fail=1
    fi
  fi
done < <(git ls-files -z)

register=docs/NON-RUST-DEPENDENCIES.md
for helper in cc cmake bindgen pkg-config vcpkg nasm-rs; do
  if grep -qE "^name = \"${helper}\"$" Cargo.lock; then
    if ! grep -qE "^\| \`?${helper}\`? \|" "$register"; then
      echo "rust-only: Cargo.lock contains the native build helper '${helper}', which ${register} does not list"
      fail=1
    fi
  fi
done

# 3. Crates that must stay free of native code whatever the rest of the workspace needs: nothing in their normal or
#    build dependencies, on any target, may compile C or assembly or bring a native crypto library.
pure_crates='crewcraft-media-crypto crewcraft-media-auth crewcraft-media'
native='^(cc|cmake|bindgen|pkg-config|vcpkg|nasm-rs|ring|aws-lc-rs|aws-lc-sys|aws-lc-fips-sys|openssl|openssl-sys|rcgen) v'
for crate in $pure_crates; do
  # A tree that cannot be listed, or that does not even name the crate, fails rather than passing as clean.
  if ! tree=$(cargo tree --locked -q -p "$crate" -e normal,build --target all --prefix none) || ! grep -q "^${crate} v" <<< "$tree"; then
    echo "rust-only: could not list the dependencies of ${crate}"
    fail=1
    continue
  fi
  found=$(grep -E "$native" <<< "$tree" | sort -u || true)
  if [ -n "$found" ]; then
    echo "rust-only: ${crate} must stay pure Rust (${register}), but its dependency tree has:"
    echo "$found" | sed 's/^/  /'
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "rust-only: FAILED (see docs/SPEC.md section 7)"
  exit 1
fi
echo "rust-only: clean"
