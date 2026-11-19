# Non-Rust dependencies

CrewCraft is written in Rust ([SPEC.md](SPEC.md) section 7) and prefers dependencies that are pure Rust. A dependency
that compiles C, C++ or assembly, or a platform SDK that is not written in Rust, is allowed only when it is listed in
the table below with the reason and the pure-Rust option that was considered. `tools/rust-only.sh` (part of the gate)
fails when `Cargo.lock` contains a native build helper that this table does not list.

The build helpers the gate looks for: `cc`, `cmake`, `bindgen`, `pkg-config`, `vcpkg`, `nasm-rs`. Add a row in the
same change that adds the dependency; the security contributor reviews it (CODEOWNERS).

| Helper | Pulled in by | Why it is needed | Pure-Rust option considered | Approved |
|---|---|---|---|---|
| `cc` | `ring` 0.17 (through `rustls`, crate `crewcraft-tls`) | ring compiles its C and assembly routines with `cc`. It is the crypto provider of the first owned TLS proof (M2, work item W0). | `rustls-graviola` (no C, but x86_64 and aarch64 only and very new), `rustls-rustcrypto` (pre-release), `aws-lc-rs` (audited, but also needs `cmake`) | No: waits for the security contributor's review (CODEOWNERS) |

Only the helper in the table is native; every other dependency is pure Rust.

## Expected decisions

Each is decided when its milestone starts, and recorded here if it adds a row.

- **TLS cryptography (M2).** The mature rustls providers contain C and assembly; pure-Rust providers are younger.
  Security outranks purity here, so a mature, audited provider is the expected exception.
- **Audio and video codecs (M7).** Opus audio and the video codecs; Rust encoders and decoders exist for AV1, and
  hardware codecs are reached through the operating system.
- **Android push (M6).** The Google push library is Java; a held connection or a UnifiedPush distributor avoids it.
- **Platform APIs.** Operating-system services (key stores, camera, notifications, call screens) are reached from Rust
  through bindings. Bindings that only declare the system's own functions, such as `libc` or `windows-sys`, compile no
  C and need no row.
