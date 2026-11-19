# CrewCraft product specification

CrewCraft is a self-hosted team-communication server and its clients, written entirely in Rust (section 7): direct
messages, group rooms, teams with threaded channels, files and documents edited together, presence, search, calls
and guest meetings, calendar, contacts, user management, plugins and themes. The target is feature parity with
Microsoft Teams, tracked in [PARITY.md](PARITY.md). It runs entirely on hardware its owner
controls. This file says **what CrewCraft is**; [REQUIREMENTS.md](REQUIREMENTS.md) lists the behaviours it must have,
[SECURITY-DESIGN.md](SECURITY-DESIGN.md) is how access works, and [ROADMAP.md](../ROADMAP.md) is the order it gets built in.

Where this file and REQUIREMENTS.md disagree, this file wins.

## 1. Deliverables

| # | Deliverable | Platforms | Notes |
|---|---|---|---|
| D1 | **Server installer** | Linux (deb, rpm, container image), Windows (MSI or NSIS, runs as a service), macOS (pkg, launchd) | Installs the server, the built-in **web client and admin console**, creates the server's certificate authority on first run, and prints the first administrator's enrollment code. |
| D2 | **Desktop client installer** | Windows, macOS, Linux (AppImage, deb, rpm) | Native client (egui, the toolkit the ArtCraft Craft apps also use). Enrolls the device, keeps the device key in the OS key store, and registers the device certificate with the OS so a browser on the same machine can open the web client. |
| D3 | **Web client** | Any modern browser | The Rust client compiled to WebAssembly, served by the server (D1). The same features as the desktop client. Reachable only from a browser that presents an enrolled device certificate (D2 installs one), or from the server's own loopback address during setup. |
| D4 | **Android app** | Android 10+ | All Rust: the egui client over the shared client core, with Android features reached from Rust. Device key in Android Keystore (hardware-backed where available). |
| D5 | **iOS app** | iOS 17+ | All Rust: the egui client over the shared client core, with iOS features reached from Rust. Device key in the Secure Enclave. |
| D6 | **Plugin SDK** | A Rust crate and its guide | Builds WebAssembly plugins and theme packages (REQUIREMENTS 2.18, 2.19). |

Every client talks to the same server API; features are built once in `crewcraft-client-core` and each platform gets
them together (REQUIREMENTS.md section 5: one client logic, thin shells).

## 2. Onboarding

All new users are onboarded by an **emailed enrollment code**. The client enrolls its own device key and certificate.

1. An administrator invites a person (name, email, role) in the admin console. The server creates a single-use code
   (160 random bits, `CC1-XXXX-...-C` with a typo-catching check symbol, valid 72 hours by default) and emails it with
   a `crewcraft://enroll?server=...&code=...&root_sha256=...` link. The trusted invitation supplies the server name
   and SHA-256 fingerprint of its root certificate. The code itself is never stored, only a key derived from it
   (SECURITY-DESIGN.md "Dark enrollment").
2. The person installs a client (D2, D4 or D5), opens the link or enters the server address, code and root fingerprint.
   The administrator supplies the root certificate with the invitation or through the organization's trust setup.
3. The client does all certificate work itself: it derives the **bootstrap key** from the code, connects with it
   (the server recognises it, see SECURITY-DESIGN.md "Dark enrollment"), generates the real **device key** inside the OS
   key store (never exportable), and sends a certificate signing request. The server verifies the request and
   stages its public key for issuance.
4. **The person gives their password.** Their email address, from the invitation, is their sign-in identity. With the
   `mailbox` password source they type their mailbox password once and the server checks it at the
   mail server; with the `own` source they set a new one (12 or more characters, Argon2id). SECURITY-DESIGN.md
   section 8.
5. **TOTP 2FA is mandatory and set up in the same flow**: the server issues a TOTP secret, the client shows it as a QR
   code (`otpauth://` URI) for any authenticator app, and the account is not activated until the person enters a valid
   code. There is no way to skip it and no setting that turns it off.
6. The server uses the invitation's identity to issue the device certificate. It saves the device and account,
   consumes the code, and records the accepted TOTP counter in one commit before returning the device chain.
   Every later sign-in needs **the device certificate, the email and password, AND a TOTP code** (at session start; sessions
   re-ask after a configurable period, default 14 days, and immediately after a new device enrolls).

Adding a second device is the same flow with a new code, which an administrator issues or the person requests from an
already-enrolled device (approved with a TOTP code).

## 3. Product scope

CrewCraft implements REQUIREMENTS.md sections 2.1 to 2.7 and 2.9 to 2.21 as written, with these decisions:

> **Implementation status (early development).** Deletion clears the post and its revisions in the room log.
> Sync preserves the cursor order and sends the deletion event without the redacted bodies or mentions, including after
> reopening the journal. The append-only journal still retains the recorded operations. Storage redaction remains open
> for ROADMAP M2.

- **Accounts.** CrewCraft is standalone: it has its own account store (email, TOTP, devices) because a public product
  cannot depend on any one organization's identity system. The password is the person's mailbox password, checked at
  the mail server (the default where a mail server exists), or a CrewCraft password on an install with no mail server. It can also serve as the
  sign-in for a mail client: SECURITY-DESIGN.md section 8 proposes a generic OpenID Connect sign-in that an independent
  client such as MailCraft (by UCS Care Group) could adopt, so one email identity and one TOTP enrollment serve both. Two plug-in points replace it where an organization has one: an **OIDC identity
  provider** and an **authorizer** (an HTTP service that answers "what may this person do here?", REQUIREMENTS 7). With an
  external authorizer configured, CrewCraft's admin console stops managing roles and shows them read-only.
- **Live updates** use a WebSocket per client with the **cursor log as the source of truth**: a reconnecting client asks
  "everything after cursor N" and is always made whole (REQUIREMENTS principle 2).
- **Server-side sessions and authorization state**, never in a cookie or token alone (principles 3 and 15).
- **Every security-relevant write is read back** after commit before the request reports success (principle 4).
- **One documented lock order** for membership changes, with tests that observe the lock (principle 5).
- **Uploads stream to disk while hashing** and refuse before reading the body (principle 7).
- **Removed means removed** for calls: short-lived media credentials and a server-side enforcement point (principle 6).
- **Extensible kinds**: room kinds, guest states and the like are strings validated by the server, not database enums
  (principle 10).
- **Pre-provisioned people**: an invited person exists (and can be messaged) before they enroll (principle 8).
- Website visitor chat (REQUIREMENTS 2.8) is a later, optional module; managed-device chat is a plug-in API.
- **The look.** Every client uses the layout and workflow in REQUIREMENTS 2.20, the shape people know from Microsoft
  Teams, so nobody has to relearn their day. Colours, type and density come from themes (2.19); CrewCraft ships its own
  themes, and an organization can install a theme of its own.
- **Guests** join teams and chats from invite links that lead to the same dark enrollment staff use, with a
  guest-scoped certificate and TOTP, and join meetings from a browser lobby (REQUIREMENTS 2.5, 2.13).
- **Collaborative documents** use conflict-free replicated data types so offline edits merge deterministically, and
  live in the file libraries so versions, quotas and permissions apply (2.14, 2.15).
- **Interoperability through open standards**: WebDAV for files, CalDAV and iCalendar for calendars, CardDAV and vCard
  for contacts, SCIM for directory provisioning, OpenID Connect for sign-in, all behind the certificate-gated entrance.
- **Theme addons** are files an administrator installs on one server; they never leave it, so an organization can
  keep a theme of its own private (REQUIREMENTS 2.19). CrewCraft's public themes never imitate another product.
- **Updates flow from the server** (REQUIREMENTS 2.21): the server updates itself from a signed release, with automatic
  rollback on a failed health check, and every client then updates from that server. The update rules (version
  ordering, downgrade refusal, rollout buckets, required updates, the rollback state machine) live in the
  `crewcraft-update` crate so they are tested once and shared by the server and every client.
- **Plugins are WebAssembly** modules written in Rust against `crewcraft-plugin-sdk`, sandboxed with declared
  capabilities, and draw client UI only through declarative cards (2.18).

## 4. Non-goals

Telephone dial-in; matching any commercial product's branding (CrewCraft matches the workflow and layout, never a
name, icon set or colour scheme); an anonymous sign-up page; portable certificate files;
any feature that needs a paid third-party service to work.

## 5. Signed releases

Official releases are signed: macOS builds are signed and notarized, Windows installers carry an Authenticode
signature, and Android builds are signed for the Play Store with a direct APK download beside it. Self-builders
need none of this: unsigned builds work, with the operating system's usual warning.

## 6. Definition of done for the whole product

The real-device proof of REQUIREMENTS principle 1, not a simulation: two people, each enrolled from an emailed code with TOTP,
on two different platforms, exchange messages, share a file and hold an encrypted call; a third person on a phone with
the app closed receives the ring. For 1.0, additionally, every row of [PARITY.md](PARITY.md) is `done` or a recorded
non-goal.

## 7. Rust only

Every part of CrewCraft is written in Rust: the server, the media server, the desktop, web, Android and iOS clients,
the plugin host and SDK, and, from milestone M2, the build tooling (`cargo xtask`).

- **Source.** The repository holds Rust plus data (TOML, JSON, Markdown). The web client is Rust compiled to
  WebAssembly. The phone apps have no Kotlin, Java, Swift or Objective-C source; platform features (key store, camera,
  notifications, call screens) are reached from Rust through bindings. The root `setup.bat`, `run_dev.bat` and
  `build.bat` stay as one-line launchers around cargo; the shell scripts in `ci/` and `tools/` are transitional.
- **Dependencies** are pure Rust by default. One that compiles C, C++ or assembly, or a platform SDK not written in
  Rust, is allowed only when [NON-RUST-DEPENDENCIES.md](NON-RUST-DEPENDENCIES.md) lists it with the reason and the
  pure-Rust option considered. Security outranks purity: cryptography comes from mature, audited crates even when
  they contain assembly.
- **Enforced** by `tools/rust-only.sh` in the gate: it fails on a non-Rust source file outside the launcher and
  transitional list, and on a native build helper in `Cargo.lock` that the register does not list.
