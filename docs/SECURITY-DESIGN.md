# CrewCraft security design

> This document is the **target design**. CrewCraft is in early development; where the code does not do something yet,
> an *Implementation status* note says so.

## 1. Principles

- **Dark by default.** The staff entrance (the server's main port) speaks only mutual TLS. A client without an acceptable certificate
  fails the TLS handshake, so it receives no HTTP response at all: no banner, no login page, no error page, nothing
  that confirms what is listening.
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
   public key from `seed`, and stores **only that public key**, the invitation record and its expiry. It emails the code.
2. The client parses the code (typos are caught by the check symbol before any network traffic), derives the same
   seed and key pair, makes a self-signed certificate for it, and connects.
3. The server's client-certificate verifier accepts a handshake if the certificate chains to the issuing CA and is not
   revoked, **or** if it is self-signed with a public key that matches an unexpired, unused invitation. Anything else
   fails the handshake.
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
