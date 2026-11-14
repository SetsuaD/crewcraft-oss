//! Each person's TOTP enrollment and the check of the codes they type, with replay protection. The server's single
//! verifier for a person's authenticator (docs/SECURITY-DESIGN.md sections 4 and 8): one enrollment, one last-accepted
//! counter, so a code works once. Wrong-code slowdown and lockout are `throttle` (T202), not here. Task T201.

use std::collections::HashMap;

use crewcraft_totp::Totp;

/// Steps of clock skew accepted either side of the current one.
pub const SKEW_STEPS: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardError {
    /// The person has no TOTP enrollment.
    NotEnrolled,
    /// The code is wrong, outside the skew window, or already used (this counter or an older one).
    Rejected,
}

struct Entry {
    totp: Totp,
    last_used: Option<u64>,
}

#[derive(Default)]
pub struct TotpGuard {
    people: HashMap<String, Entry>,
}

// Secrets never reach logs or panics.
impl std::fmt::Debug for TotpGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TotpGuard(..)")
    }
}

#[allow(clippy::todo, reason = "stubs until task T201 lands; remove this allow with them")]
impl TotpGuard {
    /// No one enrolled.
    pub fn new() -> Self {
        Self { people: HashMap::new() }
    }

    /// Enroll `person` with a 20-byte secret (RFC 6238 defaults: SHA-1, 6 digits, 30-second steps), with no code used
    /// yet. `false`, and nothing changes, when the person is already enrolled (an administrator must `reset` first).
    /// People are keyed exactly as given.
    pub fn enroll(&mut self, person: &str, secret: [u8; 20]) -> bool {
        let _ = (person, secret, &self.people);
        todo!("T201: enroll")
    }

    pub fn is_enrolled(&self, person: &str) -> bool {
        let _ = person;
        todo!("T201: is_enrolled")
    }

    /// Check `code` for `person` at `now_secs` (Unix seconds) against the counters within `SKEW_STEPS` of the current one
    /// (`Totp::verify`). Unknown person: `NotEnrolled`. A counter at or below the last accepted one is `Rejected` even
    /// when the code matches. On success the counter becomes the last accepted one and is returned; a rejection changes
    /// nothing.
    pub fn verify(&mut self, person: &str, code: &str, now_secs: u64) -> Result<u64, GuardError> {
        let _ = (person, code, now_secs);
        todo!("T201: verify")
    }

    /// The last accepted counter; `None` when the person is not enrolled or has not used a code yet.
    pub fn last_counter(&self, person: &str) -> Option<u64> {
        let _ = person;
        todo!("T201: last_counter")
    }

    /// An administrator's reset: forget the enrollment (the person must enroll again with a new secret). `true` if they
    /// were enrolled.
    pub fn reset(&mut self, person: &str) -> bool {
        let _ = person;
        todo!("T201: reset")
    }

    /// The `otpauth://` URI for the person's authenticator app (`Totp::otpauth_uri` with this issuer and the person as
    /// the account); `None` when not enrolled.
    pub fn otpauth_uri(&self, person: &str, issuer: &str) -> Option<String> {
        let _ = (person, issuer);
        todo!("T201: otpauth_uri")
    }
}

#[allow(dead_code, reason = "fields are used by the implementation of task T201")]
impl Entry {
    fn _fields(&self) -> (&Totp, Option<u64>) {
        (&self.totp, self.last_used)
    }
}
