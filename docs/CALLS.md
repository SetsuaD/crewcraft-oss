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

**Built (T363a).** `apps/crewcraft-media` holds the media server's core, Sans-I/O like str0m: the caller owns the
UDP socket and the clock. A participant joins with its offer and a media credential, checked against the chat
server's trusted key (expired, replayed, for another call or another media server, or forged: refused; a bad offer
uses nothing up). The server answers with ICE lite on its one address, Opus only for now. Each participant's offer has
one audio section it sends and some it only receives; the server gives each receiving section to another participant
of the same call, so a new participant is forwarded without renegotiation, and forwards each frame's bytes unchanged,
never to another call. Dropping a participant (`drop_person`, `end_call`, or its connection going) stops its media at
once and closes its session. `crewcraft-media-auth` now signs and checks with `ed25519-dalek` instead of `ring`, so the
media server, its credentials and its crypto are all pure Rust (`tools/rust-only.sh`). The test runs three str0m
clients against the server in memory. Still to come: the binary (socket loop, configuration, the signalling intake
that brings offers and credentials), the chat server's control connection that calls `drop_person` and `end_call`,
`CallJoin` issuing credentials (T360b2), video and keyframe requests, and telling clients who is in which section.

**Built (T363b).** The binary: `crewcraft-media <media.toml>` reads its settings in the strict TOML subset (server
name, listen address, public address for the ICE candidate, the chat server's key file and a call size cap) and the
key, a file next to it that must be owner-only like the server's other keys. One UDP socket drives the core: requests
in, datagrams in, str0m's timeouts, datagrams out. Ctrl+C or SIGTERM closes every session, sends the goodbyes and
exits. Requests come through `crewcraft_media::intake`: an in-process seam (`Intake`, with a channel `Handle`) that
the chat server's control connection will implement; until it does, the binary admits no one. The test runs the loop
on loopback UDP with two str0m clients.

## Audio (T360e) and video (T360f): decisions first

These need native code or young crates; each is decided when its task starts and recorded in NON-RUST-DEPENDENCIES.md.

- **Opus audio (decided 2026-11-26, crate chosen 2026-11-26).** A pure-Rust Opus crate: the one that passes the
  official Opus conformance vectors and encodes in real time on the smallest target (a phone). libopus through `cc` is
  only the fallback. **The vectors chose `opus-pure`**; the results are in "Opus: the crate, chosen by the conformance
  vectors" below. Real time on a phone is still proved in T360e's own test.
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

## Opus: the crate, chosen by the conformance vectors (T360e)

**Decision: `opus-pure` 0.2.5** (BSD-3-Clause, no dependencies, no build script, no C). It is one of the two
candidates that pass all 12 RFC 8251 test vectors on both checks, and the only one of those two that is also fast and
actively maintained. `ruopus` passes too, but decodes at about 4 times real time and encodes at about 8 times on a
server core (not measured on a phone), which leaves a phone little headroom when a call decodes one stream per
participant. libopus is not needed.

The test is the one libopus runs on itself (`tests/run_vectors.sh`): decode each vector to 48 kHz once as mono and once
as stereo, and

- **final range:** after every packet the decoder's range-coder state must equal the encoder's, stored next to the
  packet in the `.bit` file (checked on every packet, including the first, which `opus_demo` skips);
- **opus_compare:** the output must score at least 0 on libopus's quality metric against `testvectorNN.dec` or
  `testvectorNNm.dec` (`-s` for the stereo output), with a Rust port of libopus's `opus_compare.c` (BSD license, the
  algorithm ported, nothing vendored). Float output becomes 16-bit samples as libopus's `FLOAT2INT16` does.

A vector passes a check only when the mono and the stereo decode both pass it. As a check on the port, libopus 1.5.2's
own `opus_compare.c`, compiled on the side, scored all 120 decodes below against both references and agreed with
the port on all 240 verdicts and on every error value to six decimals.

| Crate | License | Final range | opus_compare | Encode, complexity 10 | Encode, complexity 5 | Decode | `unsafe` sites | Maintenance (2026-11-26) |
|---|---|---|---|---|---|---|---|---|
| **opus-pure** 0.2.5 | BSD-3-Clause | **12/12** | **12/12** | 324 µs/frame (62x) | 268 µs/frame (75x) | 258x | 132 | released 2026-11-23; 29 commits in 90 days, 3 contributors |
| ruopus 0.1.2 | MIT | **12/12** | **12/12** | 2500 µs/frame (8x) | 2516 µs/frame (8x) | 4x | 39 | released 2026-07-01; no commits since 2026-07-07, 1 contributor |
| opus-rs 0.1.42 | BSD-3-Clause | 12/12 | 11/12 | 400 µs/frame (50x) | 302 µs/frame (66x) | 225x | 251 | released 2026-11-10; 100+ commits in 90 days, 11 contributors |
| rusty-opus 1.2.1 | BSD-3-Clause | 12/12 | 6/12 | 286 µs/frame (70x) | 248 µs/frame (81x) | 220x | 187 | released 2026-11-23; 98 commits in 90 days, 5 contributors |
| mousiki 0.2.1 | MIT | 4/12 | 0/12 | 476 µs/frame (42x) | 349 µs/frame (57x) | 210x | 29 | released 2026-03-26; its repository is no longer public |

- **Failures.** `opus-rs` fails vector 07 (mono and stereo) and only just passes 08 and 09 (scores 7 and 12 of 100);
  its range coder is right, so the error is in the synthesis. `rusty-opus` decodes stereo correctly but fails the mono
  output of vectors 02, 04, 07, 08, 09 and 10. `mousiki` loses the range state on 8 vectors and fails the quality
  metric on all 12, through both its float and its 16-bit decode calls.
- **Encoding.** 48 kHz mono, 20 ms frames, VoIP application, 32 kbit/s target; the input is the mono downmix of the 12
  reference decodes (321 s of speech and music), best of 3 runs, one crate at a time, on one core of a 2.4 GHz Xeon
  Gold 6148 (x86-64, release build, no `target-cpu` flag). "62x" means 62 times faster than real time; a 20 ms frame
  has a 20 000 µs budget. `ruopus`'s complexity setting does not change its speed.
- **The encoders' output is valid Opus.** Each encoder's complexity-10 stream (16 031 packets) was decoded by
  `opus-pure`, `ruopus` and `opus-rs`: no final-range mismatch in any of the 15 combinations.
- **Decode** is the 641 s of audio in the 24 conformance decodes divided by the decoding time (five crates running at
  once, one core each).
- **`unsafe` sites** count code lines in `src/` that open an `unsafe` block, function, impl or extern block (command
  in the probe doc linked below). In `opus-pure` they are SIMD kernels (SSE, AVX2 with FMA, NEON) chosen at run time by CPU-feature detection,
  plus one `get_unchecked`. CrewCraft's own crates stay free of `unsafe`; a dependency's is reviewed, as here.
- **Ruled out before the run:** `opus1` (needs Rust 1.98), `symphonia-opus` (MPL-2.0, decode only), `opus-decoder`
  (decode only), `audio-codec` (no final range). `ruopus` is tested with its default features off (the default
  `spectrograms` feature pulls in `pkg-config`) and `std` on.

**Risks we accept with `opus-pure`.** It is young (first release 2026-08-27) and has few maintainers; its 132 `unsafe`
sites are SIMD code; its encoder speed on a phone is not measured yet. If it stalls, `ruopus` is the conformant
fallback (after its speed is fixed) and `opus-rs` the nearest fast one (after vector 07 is fixed); libopus through `cc`
stays the last resort. The audio pipeline task adds the dependency, its entry in `tools/rust-only.sh`'s list of crates
that must stay pure Rust, and a phone encode test.

The program, the commands to rerun all of this and the cross-check against the original `opus_compare.c` are in
[probes/opus-conformance.md](probes/opus-conformance.md).

**Built (T360e2).** `crates/audio` (`crewcraft-audio`) is the call audio on `opus-pure`, with no device I/O (capture
and playback are a separate decision): `VoiceEncoder` and `VoiceDecoder` for 48 kHz mono in 20 ms frames, the VoIP
application, configurable bit rate and complexity, in-band FEC on (for an expected 10 % loss) and DTX off by default,
taking and returning `f32` or `i16` PCM; a `JitterBuffer` keyed by RTP sequence numbers (16 bits, wrapping) and
timestamps that starts after a set number of packets, reorders within a bounded window, drops late packets, conceals
underruns and reports every loss; and a `Receiver` that plays one frame per tick, rebuilding a lost packet from the next
packet's FEC copy when it has one and concealing it otherwise. Its test checks relations, not sample values: a tone
keeps its frequency within 1 % and its level within 3 dB; reordered packets come out in order; a lost packet is
concealed, or recovered from FEC and then closer to the real frame than concealment; a late packet is dropped; and
random bytes, single-bit changes and truncations never make the decoder or the receiver panic. `tools/rust-only.sh`
keeps `crewcraft-audio` and `opus-pure` free of C.

## The app (T360g)

Call buttons in the room header; a ring (toast, tone, desktop notification) and a "call in progress, join" banner;
a call stage in the main area with grid and focus layouts that can pop out; mute, camera and screen-share controls;
device choice; in-call chat in the side pane. Missed calls in Activity.

## Later

- The TCP 443 relay for restricted networks (a TLS-wrapped TURN-style relay answering only to its own server name).
- Guest meetings with the lobby, and staff-only meetings (REQUIREMENTS 2.5); the calendar.
- Background blur without any outside service; picture-in-picture; a call-quality indicator; raising a hand.
- Recording and transcription, with consent and, for encrypted calls, a visible per-call opt-in.
