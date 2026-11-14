# CrewCraft roadmap

Each milestone ends in something a person can run, and has a `DONE_WHEN` that a command proves. Work inside a milestone
is cut into tasks under [`tasks/`](../tasks/README.md): a written behaviour plus the test that defines it.

| M | Milestone | DONE_WHEN |
|---|---|---|
| M0 | **Foundations**: workspace, gate, TOTP and enrollment-code crates (tasks T001 to T006) | `ci/validate.sh` passes with every `tasks/T00*` test installed |
| M1 | **Server core**: accounts, devices, invitations, rooms, memberships, messages, cursor log, SQLite store, lock order, read-back writes | `cargo test -p crewcraft-server-core` covers the REQUIREMENTS 2.1 and 2.2 behaviours |
| M2 | **Dark TLS server + enrollment**: rustls with the verifier from SECURITY-DESIGN.md 3, CA and certificate issuance, TOTP activation, sessions, WebSocket live updates | an integration test enrolls a device from a code, signs in with TOTP, and a client without a certificate gets a failed handshake and zero bytes |
| M3 | **Desktop client** (egui): enroll, rooms, messages, files, presence, search | enroll and chat between two desktop clients on two operating systems |
| M4 | **Web client + admin console** served by the server; first-run setup wizard; invitation email (SMTP) | a browser on an enrolled machine uses the web client; the wizard sends a real invitation |
| M5 | **Installers**: server (Linux, Windows, macOS), desktop client (Windows, macOS, Linux) | install, upgrade, repair and uninstall each pass on a clean VM per platform |
| M6 | **Android and iOS apps** over `crewcraft-client-core` with hardware-backed device keys | a phone enrolls from an emailed code and chats; TOTP required |
| M7 | **Calls and meetings**: end-to-end encrypted calls, guest lobby, calendar, push while closed | the SPEC.md section 6 real-device test |
| M8 | **1.0 release**: an external security review and signed installers for every platform | review findings closed and 1.0 tagged |
