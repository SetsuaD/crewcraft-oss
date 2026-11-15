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

impl TotpGuard {
    /// No one enrolled.
    pub fn new() -> Self {
        Self { people: HashMap::new() }
    }

    /// Enroll `person` with a 20-byte secret (RFC 6238 defaults: SHA-1, 6 digits, 30-second steps), with no code used
    /// yet. `false`, and nothing changes, when the person is already enrolled (an administrator must `reset` first).
    /// People are keyed exactly as given.
    pub fn enroll(&mut self, person: &str, secret: [u8; 20]) -> bool {
        self.insert(person, secret, None)
    }

    /// Enroll after verifying the person's first code, storing its counter at the same time.
    /// Leaves any existing enrollment unchanged.
    pub fn enroll_with_counter(&mut self, person: &str, secret: [u8; 20], accepted_counter: u64) -> bool {
        self.insert(person, secret, Some(accepted_counter))
    }

    fn insert(&mut self, person: &str, secret: [u8; 20], last_used: Option<u64>) -> bool {
        if self.is_enrolled(person) {
            return false;
        }
        let Ok(totp) = Totp::with_defaults(secret.to_vec()) else {
            return false;
        };
        self.people.insert(person.to_owned(), Entry { totp, last_used });
        true
    }

    pub fn is_enrolled(&self, person: &str) -> bool {
        self.people.contains_key(person)
    }

    /// Borrow the enrolled credential and last accepted counter for server-side multifactor verification.
    /// The credential's secret is for verification only and must not be sent in a sign-in response.
    pub fn credential(&self, person: &str) -> Option<(&Totp, Option<u64>)> {
        self.people.get(person).map(|entry| (&entry.totp, entry.last_used))
    }

    /// Record a counter already verified for this enrollment. Reject equal or older counters.
    /// The caller must serialize verification, persistence and update for the same person and enrollment,
    /// using a transaction or person lock, before issuing a session.
    pub fn record_counter(&mut self, person: &str, counter: u64) -> Result<(), GuardError> {
        let entry = self.people.get_mut(person).ok_or(GuardError::NotEnrolled)?;
        if entry.last_used.is_some_and(|last| counter <= last) {
            return Err(GuardError::Rejected);
        }
        entry.last_used = Some(counter);
        Ok(())
    }

    /// Check `code` for `person` at `now_secs` (Unix seconds) against the counters within `SKEW_STEPS` of the current one
    /// (`Totp::verify`). Unknown person: `NotEnrolled`. A counter at or below the last accepted one is `Rejected` even
    /// when the code matches. On success the counter becomes the last accepted one and is returned; a rejection changes
    /// nothing.
    pub fn verify(&mut self, person: &str, code: &str, now_secs: u64) -> Result<u64, GuardError> {
        let (totp, last_used) = self.credential(person).ok_or(GuardError::NotEnrolled)?;
        let counter = totp.verify(code, now_secs, SKEW_STEPS, last_used).ok_or(GuardError::Rejected)?;
        self.record_counter(person, counter)?;
        Ok(counter)
    }

    /// The last accepted counter; `None` when the person is not enrolled or has not used a code yet.
    pub fn last_counter(&self, person: &str) -> Option<u64> {
        self.credential(person).and_then(|(_, last_used)| last_used)
    }

    /// An administrator's reset: forget the enrollment (the person must enroll again with a new secret). `true` if they
    /// were enrolled.
    pub fn reset(&mut self, person: &str) -> bool {
        self.people.remove(person).is_some()
    }

    /// The `otpauth://` URI for the person's authenticator app (`Totp::otpauth_uri` with this issuer and the person as
    /// the account); `None` when not enrolled.
    pub fn otpauth_uri(&self, person: &str, issuer: &str) -> Option<String> {
        self.credential(person).map(|(totp, _)| totp.otpauth_uri(issuer, person))
    }
}
