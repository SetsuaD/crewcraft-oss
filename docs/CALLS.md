# Calls (design, task T360)

REQUIREMENTS.md section 2.5 says what calls must do: calls in any room, end-to-end encryption by default, call history
and missed calls, liveness, guest meetings, staff-only meetings, a calendar and a relay for networks that allow only
TCP 443. SPEC.md adds that removed means removed (short-lived media credentials and a server-side enforcement point)
and that everything, the media server included, is Rust. This is the plan for building it. Each part below lands as
its own test-defined task; the parts that need a dependency decision say so, and NON-RUST-DEPENDENCIES.md gets its row
in the same change.

## The shape

Two servers, two jobs:

- The **chat server** (what exists) is the control plane. It owns call records, who may join, the call's history
  lines, liveness, ringing, and the per-call keys' distribution. Everything goes over the signed-in device connection,
  so the device rule of SECURITY-DESIGN.md applies unchanged.
- A new **media server** (`apps/crewcraft-media`) forwards media and nothing else: a selective forwarding unit (SFU).
  It never sees plaintext media (end-to-end encryption, below), never decides who may join (it checks a credential the
  chat server issued), and drops a participant the moment the chat server says so. It can run on the same host as the
  chat server or on its own.

WebRTC is the transport, so browser guests (guest meetings) and native clients use one protocol. The media server is
built on **str0m**, a Sans-I/O WebRTC implementation in Rust (MIT OR Apache-2.0): it has no threads or sockets of its
own, so the server owns its sockets and timers and every part can be tested in memory, two peers and the SFU in one
process. Native clients use str0m too.

## Call records and liveness (T360a, chat server only)

- New requests on the device connection, behind a handshake feature bit `FEATURE_CALLS`: `CallStart { room, video }`,
  `CallJoin { call }`, `CallHeartbeat { call }`, `CallLeave { call }`. A room has at most one open call; starting one
  while another is open joins it instead.
- Journal records for start, join, leave and end, so a restart keeps open calls and history. The room gets system
  lines "started a call" and "call ended" with the duration and participants.
- Liveness exactly as REQUIREMENTS 2.5 says: a heartbeat every 20 seconds; a call with no heartbeat for 75 seconds is
  closed at its last heartbeat. A heartbeat refused because the person is no longer a member, or the call ended, tells
  the client to leave and why.
- Missed calls: a call in one of my rooms that someone else started, that ended, that I never joined, and that started
  after I joined the room, dated by when it ended. Archive rooms (docs/IMPORT.md) never have calls.
- Pushes `CallStarted`, `CallChanged` (who is in it) and `CallEnded` after `Sync`, so clients ring and show "call in
  progress, join".

This part needs no media and no new dependency, and it can ship (with ringing and history) before media works.

## Admission: removed means removed (T360b)

- `CallJoin` answers with a **media credential**: the call id, the person and device, the media server's address and
  an expiry of 60 seconds, signed by the chat server (Ed25519, a key the media server is configured to trust). The
  media server accepts a WebRTC session only with a valid, unexpired credential, and only once per credential.
- The chat server keeps a control connection to each media server (mutual TLS, the same CA as devices). When a person
  leaves the room, is removed, loses the authorizer's permission (T611j) or the call ends, the chat server tells the
  media server to drop that participant, and the media server does so at once. A participant whose heartbeat stops is
  dropped when the call closes them.

## End-to-end encryption (T360c, T360d)

Hop-by-hop, WebRTC already encrypts (DTLS-SRTP) between each client and the media server. End-to-end, each media frame
is also encrypted with **SFrame** (RFC 9605, a Proposed Standard since August 2024), designed for exactly this: the
SFU can read the RTP headers and feedback it needs but not the media.

- T360c, an `sframe` crate: the RFC's frame format (key id and counter in an authenticated header) and its AEAD cipher
  suites, with the RFC's test vectors as the test. AES-GCM through `ring`, which the TLS stack already brings (no new
  native code).
- T360d, keys. Each participant makes a random **sender key** per call and sends it to each other admitted
  participant through the chat server, sealed to that participant's device key (ECDH P-256 with the device's
  enrolled key, HKDF, AES-GCM; all in `ring`). The chat server relays sealed keys and can read none of them. When
  anyone leaves or is removed, everyone makes a new sender key (a new key id) and the departed device never receives
  it: removed means removed for the media too. In-call chat uses the same keys.
- The client shows that a call is end-to-end encrypted, and that recording or transcription, when they come, need a
  visible opt-in for that call (REQUIREMENTS 2.5).

A group key agreement (MLS) can replace the sender keys later without touching SFrame: RFC 9605 keeps key management
apart from media encryption.

## The media server's crypto (decided 2026-11-26)

str0m's crypto is pluggable, but none of its ready-made backends is free of C today: even its `rust-crypto` backend
compiles AWS-LC, because the DTLS library it uses (`dimpl`) makes its certificates through `rcgen` with AWS-LC. So
CrewCraft writes **its own str0m crypto provider in pure Rust**: str0m without a default backend, `dimpl` in its
RustCrypto mode for DTLS, RustCrypto for SRTP (AES-GCM, AES-CTR with HMAC-SHA1) and the hashes, and the DTLS
certificate made with RustCrypto (P-256 and `x509-cert`) instead of `rcgen`. A probe build of that combination has no
AWS-LC, `cc`, `cmake` or `ring` in its tree. The provider is a crate of its own (`crates/media-crypto`), tested against
str0m's interface in memory (two peers completing DTLS and exchanging SRTP) before the media server uses it.

**Built (T362a).** `crates/media-crypto` is that provider: `crewcraft_media_crypto::provider()` is handed to
`RtcConfig::set_crypto_provider`. Its tests check the SRTP ciphers and hashes against published vectors (RFC 3711 B.2,
FIPS-197, the GCM test cases, RFC 2202), the certificate (self-signed P-256, its PKCS#8 key loads, fresh each time),
DTLS 1.2, 1.3 and either-version handshakes between two of its own peers (same SRTP keys, each sees the other's
certificate, data both ways), and two str0m peers with no backend of str0m's own connecting over an in-memory network
and carrying an audio stream that never crosses it in the clear. The gate (`tools/rust-only.sh`) fails if the crate's
dependency tree ever gains C, assembly or a native crypto library.

## Audio (T360e) and video (T360f): decisions first

These need native code or young crates; each is decided when its task starts and recorded in NON-RUST-DEPENDENCIES.md.

- **Opus audio (decided 2026-11-26).** A pure-Rust Opus crate (`opus-rs`, a port of libopus 1.6; `ruopus` and `opus1`,
  implementations of RFC 6716): the one that passes the official Opus conformance vectors and encodes in real time on
  the smallest target (a phone), proved in T360e's test. libopus through `cc` is only the fallback.
- **Audio input and output.** `cpal` is the usual Rust audio library; on Linux it needs the ALSA development files at
  build time (`alsa-sys` through `pkg-config`), even with PipeWire or PulseAudio. Windows (WASAPI), macOS and iOS
  (CoreAudio) and Android (AAudio) are reached through system bindings. The Linux row is the decision.
- **Video.** AV1 has a Rust encoder (`rav1e`, with near real-time speed settings) and a Rust decoder (`rav1d`, a port
  of dav1d that keeps its hand-written assembly, so its build compiles assembly and needs a row). Hardware encoders
  and decoders are reached through the operating system (Media Foundation, VideoToolbox, MediaCodec, VA-API) where
  available. Camera capture and screen capture are platform APIs too. The proposal: AV1 everywhere for one codec path,
  hardware first, `rav1e`/`rav1d` as the software path. Browser support for AV1 in WebRTC differs by browser and device
  (Safari needs AV1 hardware), so guest meetings may need a second, browser-friendly codec (VP8); that is checked when
  guest meetings start.

## The app (T360g)

Call buttons in the room header; a ring (toast, tone, desktop notification) and a "call in progress, join" banner;
a call stage in the main area with grid and focus layouts that can pop out; mute, camera and screen-share controls;
device choice; in-call chat in the side pane. Missed calls in Activity.

## Later

- The TCP 443 relay for restricted networks (a TLS-wrapped TURN-style relay answering only to its own server name).
- Guest meetings with the lobby, and staff-only meetings (REQUIREMENTS 2.5); the calendar.
- Background blur without any outside service; picture-in-picture; a call-quality indicator; raising a hand.
- Recording and transcription, with consent and, for encrypted calls, a visible per-call opt-in.
