# CrewCraft security design

> This document is the **target design**. CrewCraft is in early development; where the code does not do something yet,
> an *Implementation status* note says so.

## 1. Principles

- **Dark by default.** The staff entrance (the server's main port) speaks only mutual TLS. A client without an acceptable certificate
  fails the TLS handshake, so it receives no HTTP response at all: no banner, no login page, no error page, nothing
  that confirms what is listening. One thing a prober does learn: in TLS 1.3 the server sends its own certificate
  before it checks the client's, so anyone who opens a handshake can read the server certificate, and with it the
  server's name and that its issuer is a private CrewCraft root. Choose a server name that says nothing you would not
  put in DNS. A client's own connection also sends that name in the clear (SNI), as any TLS client does.
- **Devices are enrolled, people are verified.** A device certificate says "this is an enrolled device of person P";
  the person's email and password and a TOTP code say "person P is present". All of them are required for a session
  (section 8).
- **No anonymous endpoint exists on the staff entrance**, including for enrollment (section 3). The planned guest and
  website-visitor entrances (REQUIREMENTS.md 2.5 and 2.8) are separate public listeners with their own limits.
- **No hand-rolled cryptography.** TLS is rustls; primitives come from the RustCrypto crates; codes compare in
  constant time.
- **Secrets are never logged.** Types that hold secrets print as `..` in `Debug`.

## 2. Keys and certificates

| Key | Where it lives | Signs |
|---|---|---|
| Root CA | Created by the server installer; the installer offers to move it offline after the issuing CA exists | the issuing CA only |
| Issuing CA | Server data directory, readable only by the server's service account | device certificates, the server certificate |
| Server key | Server data directory | TLS server handshakes |
| Device key | The client's OS key store (Windows CNG/TPM, macOS Keychain, Linux kernel keyring or an encrypted file, Android Keystore, iOS Secure Enclave), generated there, never exportable | TLS client handshakes |
| Bootstrap key | Derived in memory from an enrollment code, discarded after enrollment | one enrollment handshake |

> **Implementation status (first beta).** The desktop client does not keep the device key itself in an OS key store
> yet. It generates the key in the process (`crewcraft::device::NewDevice`) and saves it, with the device certificate
> and the server's pinned root, in one record file per server profile (`crewcraft::device_store`, task T304). Since
> task T313 that file is **sealed**: the whole record is encrypted with XChaCha20-Poly1305 under a random 32-byte key
> per profile, and that key lives in the OS key store (`crewcraft::key_vault`):
>
> | Platform | Where the sealing key lives |
> |---|---|
> | Windows | A generic credential in the person's Credential Manager, which Windows encrypts under their logon (DPAPI) |
> | macOS | A generic password in the person's login Keychain |
> | Linux and the BSDs | An item in the default collection of the Secret Service (GNOME Keyring, KWallet, KeePassXC and others), reached over the session D-Bus |
>
> The sealed file holds a version line, a random nonce and the ciphertext with its tag. The version line and the
> profile name are authenticated, so a changed byte, a record copied to another profile's name or a record opened
> with another key is refused. The private key is never written to disk in the clear, temporary files included. A
> record written before T313 is read once and saved again sealed, replacing the old file. That happens only while
> the key store holds no key for the profile: once a sealed record has been written, an unsealed file in its place
> is refused, so it cannot be swapped back in to point the app at another server.
>
> What that changes:
>
> - **Someone with the person's files but not their session** (a copied home folder or data folder, a backup, a
>   synced folder, a stolen disk read from another system, another non-administrator user who can read the file)
>   gets ciphertext only: not the device key, not the certificate, not even the server's address. To open it they
>   also need the key from the key store, which the platform protects with the person's login (DPAPI on Windows,
>   the login keychain's password on macOS, the keyring password on Linux; a GNOME Keyring or KWallet whose
>   password is empty, or that is set to unlock without one, protects nothing). A backup restored on another
>   computer or user account cannot be opened there; the person enrolls that device again.
> - **Unchanged with a compromised session.** Any program running as the person can ask the key store for the key
>   (Credential Manager and the Secret Service do not tell apps apart; the macOS Keychain may ask the person first)
>   and read the file, so it can copy the device key, as it could read it from the process. An administrator or
>   root can do the same. A copied key alone still does not open a session: signing in needs the email, the password
>   and a current TOTP code, and an administrator can revoke the device's certificate.
> - **The file permissions stay** as a second layer. On Unix the record directory is `0700` and each record `0600`;
>   the client refuses to load a record, or to read from a directory, that grants any group or other permission,
>   and refuses a symbolic link in place of a record. On Windows the record relies on the per-user data directory's
>   inherited access list, which the client does not check.
>
> **No key store.** When the client cannot open or reach a key store (for example a Linux desktop with no Secret
> Service on its session bus, or a locked key store the person does not unlock), it says so and does not save the
> enrollment; it never falls back to an unsealed file on its own. A person who accepts the weaker protection can opt
> in by creating an empty file named `plain-device-record` in the client's data folder. The client then keeps the
> record unsealed, protected by the file permissions above only, and does not open the key store; a sealed record is
> then refused, not decrypted.
>
> Records are written to a new file, synced, then renamed over the old one, so a crash leaves the old record or the
> new one. Each record carries a SHA-256 checksum inside the seal, and on load its root must match its fingerprint
> and its key must match its certificate. The key bytes are wiped from memory when a record is dropped and never
> printed.
>
> Generating the device key inside the OS key store, non-exportable where the platform allows (Windows CNG or the
> TPM, the Secure Enclave), is still the planned replacement. Until then a session running as the person can export
> the key, which is the beta's honest limit.

> **Implementation status (Android, task T403).** On Android the device key is generated inside the Android Keystore
> and is never in the app's memory or files: `AndroidKeystore` (apps/crewcraft-android) asks for a P-256 signing key
> (SHA-256 only) in StrongBox where the phone has one, otherwise in its trusted environment, and the Keystore signs
> the enrollment request and every TLS client handshake (`crewcraft::hardware_key`). The saved record (version 3)
> holds the server's endpoint, the certificates and the key's alias, and no secret; it lives in the app's private
> storage. The app reads where the Keystore says the key lives (`KeyInfo`) and logs it. A record whose key the
> Keystore no longer holds is refused, and the person enrolls again; a new enrollment deletes the old key, and a
> failed one deletes the key it made. What a hardware key does not change: any code running inside the app can still
> ask the Keystore to sign, so a compromised app can act as the device while it runs, but it cannot copy the key off
> the phone. The emulator's Keystore is software only, so the emulator test proves the flow, not the hardware.

> **Implementation status (iOS, task T422).** On iOS the device key is a P-256 key generated in the Secure Enclave and
> kept in the app's Keychain under its alias (`crewcraft::ios_keys`). The Secure Enclave signs the enrollment request
> and every TLS client handshake; the private key cannot be exported. The record is the same version 3 record as on
> Android and holds no secret. The same limit applies: code running inside the app can ask the Secure Enclave to sign
> while it runs, but cannot take the key off the phone. The simulator's Secure Enclave is simulated, so the simulator
> test proves the flow, not the hardware.

Device keys are ECDSA P-256 because it is the one algorithm every hardware key store supports (the Secure Enclave
supports nothing else). The bootstrap key is Ed25519 (software only, short-lived).

Device certificates carry: the person id, the device id, and an extended key usage for TLS client authentication.
The server forces the subject from its own records; anything the client puts in the request's subject is ignored.
Default lifetime 90 days with automatic renewal from the device; revocation is immediate on the server (a revoked
serial fails the handshake) and published as a CRL for any reverse proxy in front.

## 3. Dark enrollment

The problem: a new device has no certificate yet, but the server answers only mutual TLS.

The enrollment code is the bootstrap credential while its invitation is unexpired and unused.

1. When an administrator creates an invitation, the server draws 160 random bits (the code), computes
   `seed = HKDF-SHA256(ikm = code bits, salt = "crewcraft-enroll-v1", info = "bootstrap-ed25519")`, derives the Ed25519
   public key from `seed`, and stores **only that public key**, the invitation record and its expiry. The trusted
   invitation includes the code, the server name and the SHA-256 fingerprint of the root certificate's DER bytes.
   The administrator supplies the root certificate with the invitation or through the organization's trust setup,
   or the client fetches it from the server's own chain, accepting it only by that fingerprint and only when the
   chain verifies against it for the server name; fetching presents no certificate and sends no application byte.
2. The client parses the code (typos are caught by the check symbol before any network traffic), derives the same
   seed and key pair, and makes a self-signed certificate for it. Before connecting, it verifies the root certificate's
   fingerprint. The TLS handshake verifies the server chain and hostname before the client sends a request or password.
3. For a device, the verifier requires the exact active client-authentication certificate from the enrolled-device
   record and a valid chain. For bootstrap, it requires a valid self-signed certificate and proof of possession of the
   public key that matches a live invitation. Other connections fail the TLS handshake before any application reply.
4. A bootstrap connection can reach exactly two calls. The first stages the verified certificate signing request
   and password setup, then returns the authenticator setup URI. The same connection confirms the first TOTP code
   against that staged request. Every other request on the connection is closed without a response.
5. A successful confirmation commits the account, exact issued device certificate, consumed invitation and accepted
   TOTP counter together. The bootstrap public key stops matching. Only after the commit does the server return the
   device leaf and issuing certificate. A disconnect before the commit can restart setup while the invitation is live.
   If the commit succeeds but delivery fails, the invitation stays consumed. An administrator revokes the inaccessible
   device and uses the account recovery flow.

Properties: the server never stores the code; a database leak does not reveal codes (the public key does not give
the seed back); an attacker without the code cannot complete a handshake; guessing is online-only (one handshake per
guess) and rate-limited per source address and globally; 160 bits makes guessing hopeless anyway.

> **Implementation status (early development).** `server-core`'s enrollment currently completes at redeem: it burns
> the invitation and registers the device before any TOTP step, and its limiter is per source address only. The TOTP
> confirmation step (point 5) and the global limit arrive with the dark TLS server (ROADMAP M2); until then this section
> is the target, not a description of the code.

The honest limit: whoever holds the email holds the invitation, until it is redeemed. Mitigations: 72-hour default
expiry, single use, administrators see each invitation's state and can revoke it, and an optional "administrator
approves each new device" step.

### Administration while serving

`invite`, `room` and `add-member` reach a running server over a Unix domain socket, `control.sock`, inside its data
directory (Linux and macOS; task T238). It is a local channel for the server's own account, never a network listener:

- The data directory must be private (`0700`; the server refuses to open one that is not). The server creates the
  socket inside it, makes it `0600` and checks it belongs to the directory's owner. Connecting needs search permission
  on the directory and write permission on the socket, so the kernel refuses every other account (the superuser, who
  can read the directory's keys anyway, is the exception). The standard library has no stable call to read the peer's
  credentials, so the server does not check them itself; the file permissions are the gate. A command trusts a socket
  only in a private directory and only when it belongs to the directory's owner.
- A request is applied to the live account store and room journal under the same locks, and with the same checks, as
  offline: the same invitation rules, and the same refusals with the same text.
- An invitation's code goes from the server to the command once, over the socket, and the command shows it or writes
  it to a new owner-only file. If the command does not confirm it was shown, the server withdraws the invitation, as
  a failed display does offline. Nothing logs a request or a code.
- Messages are small and strict: a 4-byte length up to 4096, at most 8 length-prefixed UTF-8 fields, one exchange per
  connection within 10 seconds, answered one at a time.
- A socket left behind by a crash is replaced only once connecting to it is refused; anything else at that path is
  left alone. The socket is removed when the server stops.

On Windows the Rust standard library offers neither Unix domain sockets nor named pipes, and CrewCraft's crates use no
`unsafe` code, so a Windows server has no control socket: there, these commands still need the server stopped.

## 4. TOTP

RFC 6238, SHA-1, 6 digits, 30-second steps (what every authenticator app supports), a skew of one step either side,
and replay protection: the server stores the last accepted counter per person and rejects that counter and older ones.
The TOTP secret is 20 random bytes, encrypted at rest with a key held by the server's service account. Repeated wrong
codes slow down (exponential delay per person) and lock the session attempt after ten failures, without locking the
account permanently (an administrator can reset).

Recovery: an administrator can reset a person's TOTP, which ends all their sessions and requires a new enrollment code.
There are no SMS or email fallback codes.

## 5. Sessions and authorization

Sessions are rows in the server database (device, created, last seen, TOTP verified at, revoked). Authorization state
(roles or capabilities, when resolved, last good answer, any definitive denial) is stored server-side under the
person's lock, and read back after every write that changes it. With an external authorizer: re-check after 10 minutes,
retry after 60 seconds on failure, keep the last good grant at most 24 hours during an outage, never borrow grace for a
fresh sign-in (REQUIREMENTS.md section 4).

**Resuming a session (task T240).** A session ends after 30 minutes without a request, and 12 hours after its
sign-in however busy it is. The sign-in returns a session token (32 random bytes; the server keeps only its SHA-256),
and a device that lost its connection can reopen the same session with it instead of a password and a new code, as
long as:

- it presents the token over a TLS connection with the exact certificate of the device the session belongs to, so a
  copied token is useless without that device's private key (sealed by the OS key store, or held by the phone's
  hardware key store); and
- less than 12 hours have passed since the sign-in. The 30-minute idle limit does not apply to a resume: a phone
  in the background for an hour comes back without a code, but never more than 12 hours after the person last
  typed one.

Signing out asks the server to end the session (it is revoked and journaled), and the app forgets the token.
Revoking the device or resetting the person's authenticator ends it as before. The app keeps the token in
`resume-ticket` in its data folder, owner-only, next to the device record; a new enrollment discards it. This was the
owner's decision of 2026-11-24 ("12 h resume ticket"), weighing a fresh code on every phone reconnect against the
device-bound token.

## 6. The web client

A browser can only present a client certificate from its OS certificate store. The desktop client (D2) registers the
device certificate there (non-exportable where the OS allows it) so a browser on that machine can open the web client.
During first-run setup the server also serves its setup wizard on its loopback address without client certificates,
reachable only from the server machine itself; the wizard closes once the first administrator is enrolled.

## 7. Status codes and existence

As REQUIREMENTS.md section 4: a resource in a room you are not in is 404, never 403; guests' failures are one indistinguishable 404.

## 8. Standalone accounts, and a shared 2FA for mail clients (proposal)

CrewCraft owns its accounts. It needs no outside identity system to run; the OIDC and authorizer plug-ins (SPEC.md
section 3) stay optional for organisations that already have one.

**An account** is a normalised email address (the identity, `crewcraft-accounts::identity`), a password checked by the
server's configured **password source** (below), exactly one TOTP enrollment (section 4) and the person's enrolled
devices. The password step comes right before the TOTP step in enrollment (SPEC.md section 2).

**Signing in** takes all of: an enrolled device certificate (the TLS handshake), the email, the password and a TOTP code.

- Every failure gets the same answer ("email, password or code not accepted") in the same time. When the email is
  unknown the server still verifies against a fixed dummy hash, so sign-in does not reveal which addresses exist.
- Wrong passwords count toward the same per-person delay and ten-failure lock as wrong codes (section 4).
- With the `own` source, a hash with old parameters is replaced at the next successful sign-in
  (`password::needs_rehash`).

### One authenticator entry, one verifier

This section is a proposal, not a partnership: it uses MailCraft (an independent open-source mail, calendar and contacts
client by UCS Care Group, https://github.com/UCS-Care-Group/mailcraft) as the worked example. MailCraft has no accounts of its own. The credentials it keeps
belong to the person's mailbox (Exchange, Microsoft 365, IMAP) and live in the OS keyring. CrewCraft never sees them.
The two apps tie together through the **person's email address**, and the CrewCraft server is the single place that
checks the password and the TOTP code for both.

1. The CrewCraft server is an OpenID Connect provider for companion apps, on its usual dark mutual-TLS port. It
   supports the authorization-code flow with PKCE S256 only (RFC 7636), public clients, and loopback redirects
   `http://127.0.0.1:<port>/` (RFC 8252).
2. MailCraft's "Sign in with CrewCraft" opens the system browser at the authorize URL.
   - The browser presents the device certificate that the CrewCraft desktop client registered in the OS store
     (section 6).
   - On a machine with no enrolled device the handshake fails and nothing answers. That is the dark rule, not a bug:
     enroll the machine first.
3. CrewCraft's sign-in page asks for the email, password and TOTP code, then redirects with a one-time code that lives
   60 seconds.
4. MailCraft exchanges the code, with its PKCE verifier, for an ID token that lives 10 minutes. The token carries:
   - `sub`, the person id;
   - `email`, normalised;
   - `amr = ["mtls", "pwd", "otp"]`;
   - `aud`, the companion app's client id.

   Optionally MailCraft also gets a refresh token bound to the device certificate (RFC 8705) that expires on the same
   14-day re-ask schedule as CrewCraft sessions.
5. MailCraft uses the token for two things:
   - to unlock its profile;
   - to link a mailbox to the person. It links only a mailbox whose address normalises to the token's `email`, and
     asks the person to confirm any other.

   Revoking the person or the device in CrewCraft ends both apps' sessions.

**Why one verifier, and not a TOTP secret copied into both apps:**

- A copy doubles the places the secret can be stolen from.
- Replay protection needs a single last-used counter. Two verifiers would each accept the same code once.
- A reset or a revocation would have to reach two places.

So the authenticator app holds one CrewCraft entry, and it serves both apps. Rejected alternatives:

- exporting the `otpauth://` secret to MailCraft;
- a shared crate that verifies codes locally in each app.

### The password source

The recommended default is **the mailbox password**: people sign in to CrewCraft, and through it to a companion
mail client such as MailCraft, with the password of the mailbox their account's email belongs to. There is one password to remember and
one to reset, and both live at the mail server.

The server has one setting, `password_source`:

| Value | Checks the password by | Stores |
|---|---|---|
| `mailbox` (the recommended default where a mail server exists) | one login to the configured mail server: EWS (an authenticated `GetFolder` on the inbox) or IMAP (`AUTHENTICATE PLAIN` over TLS, then `LOGOUT`) | no password and no hash |
| `own` (an install with no mail server) | Argon2id (`crewcraft-accounts::password`) | the PHC string only |

The installer asks which to use. A public product cannot assume a mail server, so `own` stays available, but it is not
a fallback: a server uses exactly one source, and a `mailbox` server never accepts a stored password.

How a `mailbox` sign-in works:

1. The device certificate is checked first, in the TLS handshake. Nothing below happens for an unenrolled device.
2. **The TOTP code is checked before the mail server is contacted.** A person without the authenticator never causes a
   mail-server login, so CrewCraft cannot be used to guess mailbox passwords or to lock directory accounts. The answer
   is still the uniform one, so it does not say which factor failed. The per-person delay and ten-failure lock
   (section 4) apply before the mail server is asked, too.
3. The server logs in to the mail server as the person: the login name is the normalised email unless the server's
   config gives a template. TLS to the mail server is always verified, against the system roots or a certificate
   pinned in the config. There is no skip-verify option.
4. The password exists only in memory for that one request. It is never stored, logged, cached or hashed, so a stolen
   CrewCraft database holds no password material.
5. If the mail server cannot be reached, sign-in fails closed with "sign-in is unavailable, try again later", which
   does not depend on the account. Sessions already open continue until their re-ask time. The server's health check
   connects to the mail server (TLS and capabilities, no credentials) so an outage shows up at once.

What follows from it:

- Enrollment needs no new password: the person types their mailbox password once and the server checks it, which
  also proves they hold the invited address.
- A password change or reset happens at the mail server and applies to the next CrewCraft sign-in. CrewCraft has no
  password-reset flow of its own in this mode.
- A disabled mailbox stops new sign-ins at once. Open sessions end at their next re-ask, or immediately when an
  administrator revokes the person.

Choosing `mailbox` accepts these costs, which are stated here so they stay visible:

- Sign-in depends on the mail server being up.
- The chat server sees mailbox passwords in memory during sign-in. A compromised CrewCraft server could capture them
  as people sign in, which a server with its own passwords would not expose.
- One stolen password now reaches both mail and chat. The device certificate and the TOTP code still stand between
  that password and a CrewCraft session.

**MailCraft's side** is a generic OpenID Connect sign-in. MailCraft already runs an OAuth 2.0 sign-in for
Microsoft accounts, so this is the same shape pointed at a different issuer. It is proposed to MailCraft as a generic
feature, so it is not CrewCraft-specific code.

First test-defined pieces: `tasks/T007-password-hash` (the `own` source), `tasks/T008-email-identity` and `tasks/T009-pkce` (the server's
PKCE check).

## 9. Signing in through an external OpenID Connect provider (plan, task T611)

An organization that already has an identity provider can let people sign in with it instead of a CrewCraft password
and code (REQUIREMENTS.md section 4, "Identity provider"). The checks are built and tested in `crates/oidc` (T610), and
the external authorizer's rules in `crates/authz` (T600, contract in [AUTHORIZER.md](AUTHORIZER.md)). This section is
the plan for joining them to the sign-in path. Nothing here weakens the device rule: **a session still needs an enrolled
device's certificate in the TLS handshake**; the provider replaces only the password and the TOTP code.

**Configuration (server).** `[identity] source = "oidc"` with the provider's exact `issuer`, the `client_id` of a
*public* client (no client secret anywhere: RFC 8252 section 8.5, PKCE instead), and `require-mfa` (default on: the ID
token's `amr` must contain `mfa`, because the provider's second factor stands in for CrewCraft's TOTP). The server
fetches the discovery document and the keys over https, caches them, and fetches the keys again at most once a minute
when a token names a `kid` it does not have. Its health check fetches discovery, so a provider outage shows at once.

**The flow (native apps, RFC 8252).**

1. Over its mutual-TLS connection, the app asks the server to begin an external sign-in. The server answers with the
   issuer, the client id, the authorization endpoint and a fresh **nonce bound to this device's certificate**, valid
   for 10 minutes and usable once.
2. The app makes the PKCE pair and a state value, listens on a loopback port (`127.0.0.1`, a random port, one request
   only), and opens the system browser at the authorization URL. Embedded web views are not used (RFC 8252 section 8.12).
3. The provider redirects the browser to the loopback port with a code. The app accepts the request only with the
   state it made, then sends the code, the PKCE verifier and the redirect URI to the server, over the same
   certificate-gated connection.
4. **The server exchanges the code** at the provider's token endpoint and verifies the ID token itself:
   `crewcraft_oidc::verify_id_token` with the nonce it issued for this device and `require-mfa`. The app never holds
   or forwards an ID token, so a token stolen elsewhere cannot be replayed through CrewCraft.
5. The server looks up the account **bound to that issuer and subject** (below). With an external authorizer
   configured, it asks it (`purpose: sign-in`) and applies `crewcraft_authz::Record::sign_in`: no fresh `allow` with
   `use`, no session. Then it issues the same session as a password sign-in, bound to the device certificate, with the
   same resume ticket (section 5).

**Binding accounts to the provider.** An account is bound to the provider's `(issuer, subject)` pair, never to an email
address (an address can be reassigned). The binding is made once, at enrollment: an invitation for a server in `oidc`
mode is redeemed by an external sign-in instead of choosing a password and setting up TOTP, and the subject of that
sign-in is stored on the account. After that, only that subject signs in to it; an ID token for another subject with
the same email is refused. An administrator can re-bind an account (audited).

**Enrolling through the provider (task T611i).** On a server whose `identity.toml` sets `source = "oidc"`, the
bootstrap connection (section 3) takes a third pair of calls in place of the password and the authenticator:

1. `RedeemExternal { device_name, csr }`: the same checks as `Redeem` up to staging (invitation live, CSR, limits), but no
   password. The server answers `ExternalStart { issuer, client_id, authorization_endpoint, nonce }` with a fresh
   nonce bound to **this bootstrap key**, valid for 10 minutes and usable once. Nothing durable changes.
2. The app runs steps 2 and 3 of the flow above (PKCE, state, loopback, system browser) while the bootstrap connection
   stays open, as it does today while the person reads the authenticator code. The connection's confirmation window is
   at least the browser timeout.
3. `ConfirmExternal { code, verifier, redirect_uri }` on the same connection and the same staged attempt. The server
   exchanges the code, verifies the ID token with the nonce it issued for this bootstrap key and `require-mfa`, and then
   checks, in this order, refusing with a generic error and nothing durable changed:
   - the token's `email` equals the invitation's address (case-insensitive), so a colleague who obtains the link cannot
     bind their own provider account to someone else's invitation (the subject, not the email, is what is stored);
   - no account is bound to that `(issuer, subject)` already;
   - with an authorizer configured, a fresh `allow` with `use` (`purpose: sign-in`), and the decision is stored.
   One `activate` then commits the invitation, the person (no password, no TOTP secret), the device and its exact leaf,
   **and the binding** together (`AccountOp::ActivatedExternal`, one journal record, so an account never exists
   unbound). Only after it returns `Ok` is the leaf sent as `Activated`.

On an `oidc` server, `Redeem` (password and authenticator) is refused, and on any other server `RedeemExternal` is
refused, so a server has exactly one way in. The invitation link carries the mode (`&signin=org`) so the app shows the
right form; the server, not the link, decides. Signing in afterwards is the flow above. An account enrolled this way
has no CrewCraft password or code, so it cannot be signed in to any other way.

The sub-tasks, each test-defined: the bootstrap wire messages (`crewcraft-proto`), the account store's
`ActivatedExternal`, the bootstrap state machine's external path, the app's enrollment through the browser and the
link's mode, and an end-to-end test that enrolls, signs in and chats against a running server with a fake provider.

**While signed in.** The session layer re-checks the authorizer by the T600 rules (10 minutes, 60-second retry, at most
24 hours of grace from the last confirmation, none for the visitor module). A `deny` ends the person's sessions at the
next check; signing out and device revocation work as before.

**What is built (tasks T611a to T611h).** The opening and reply for steps 1 and 3 in `crewcraft-proto`, the account
binding and the authorization record in the account store, an https client on the server (`crates/https`) for
discovery, keys, the token exchange and the authorizer, the server's sign-in and its `identity.toml`, and in the app the
loopback listener, the browser launch, the whole flow, and the sign-in screen's "Sign in with your organization" button
with a Cancel while the browser page is open (the connection worker runs the flow; cancelling or closing the app ends
the wait at once). **Still to build:** binding an account to its provider identity when an invitation is redeemed (today
the binding is made in the account store directly), and an end-to-end test against a running server.
