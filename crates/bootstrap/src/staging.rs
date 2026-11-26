//! What is ephemeral about an enrollment in progress: the staged authenticator secret for each live invitation, the
//! attempt that owns it, the count of wrong codes, and the two rate limiters. Nothing here decides who may enroll or
//! what is registered: the durable store does (`Services`). Losing this on a restart only means the person starts the
//! setup again on a new connection, which is exactly right for an unfinished enrollment.
//!
//! The limits are taken in `begin` and `confirm` before any expensive work, one per-source bucket and one server-wide
//! bucket shared by both calls, as `server-core::activation` does.

use std::collections::HashMap;

use crewcraft_accounts::totp_guard::SKEW_STEPS;
use crewcraft_server_core::activation::{GLOBAL_BURST, GLOBAL_PER_SEC, ISSUER, MAX_WRONG_CODES, SOURCE_BURST, SOURCE_PER_SEC};
use crewcraft_server_core::rate_limit::Limiter;
use crewcraft_totp::Totp;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageError {
    RateLimited,
    /// Nothing is staged for this key, or it is for another attempt.
    NoAttempt,
    BadCode,
    /// The secret was unusable (cannot happen with 20 bytes).
    Totp,
}

/// What `begin` stages: the invitation's person, the device's name and stable key identity, the drawn secret.
pub(crate) struct Candidate<'a> {
    pub email: &'a str,
    pub device_name: &'a str,
    pub key_id: [u8; 32],
    pub secret: Zeroizing<[u8; 20]>,
}

pub(crate) struct Begun {
    pub attempt: u64,
    pub otpauth_uri: String,
}

/// What a correct first code proved, ready to be committed.
pub(crate) struct Confirmed {
    pub email: String,
    pub device_name: String,
    pub key_id: [u8; 32],
    pub secret: Zeroizing<[u8; 20]>,
    pub counter: u64,
}

struct Pending {
    attempt: u64,
    email: String,
    device_name: String,
    key_id: [u8; 32],
    secret: Zeroizing<[u8; 20]>,
    wrong_codes: u32,
}

pub(crate) struct Staging {
    source_limit: Limiter<String>,
    global_limit: Limiter<()>,
    pending: HashMap<[u8; 32], Pending>,
    next_attempt: u64,
}

impl Staging {
    pub fn new() -> Self {
        Self {
            source_limit: Limiter::new(SOURCE_BURST, SOURCE_PER_SEC),
            global_limit: Limiter::new(GLOBAL_BURST, GLOBAL_PER_SEC),
            pending: HashMap::new(),
            next_attempt: 0,
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    fn take_call(&mut self, source: &str, now_ms: u64) -> Result<(), StageError> {
        if !self.global_limit.check(&(), now_ms) {
            return Err(StageError::RateLimited);
        }
        self.source_limit.prune(now_ms);
        if !self.source_limit.check(&source.to_owned(), now_ms) {
            return Err(StageError::RateLimited);
        }
        Ok(())
    }

    /// Forget staged setups whose invitation is no longer live.
    pub fn retain_live(&mut self, mut live: impl FnMut(&[u8; 32]) -> bool) {
        self.pending.retain(|key, _| live(key));
    }

    /// Stage a setup for `bootstrap_pub`, replacing (and so invalidating) any earlier attempt. Takes the limits first.
    pub fn begin(&mut self, source: &str, bootstrap_pub: &[u8; 32], candidate: Candidate<'_>, now_ms: u64) -> Result<Begun, StageError> {
        self.take_call(source, now_ms)?;
        let Candidate { email, device_name, key_id, secret } = candidate;
        let totp = Totp::with_defaults(secret.to_vec()).map_err(|_| StageError::Totp)?;
        let otpauth_uri = totp.otpauth_uri(ISSUER, email);
        let attempt = self.next_attempt;
        self.next_attempt = self.next_attempt.saturating_add(1);
        self.pending.insert(
            *bootstrap_pub,
            Pending { attempt, email: email.to_string(), device_name: device_name.to_string(), key_id, secret, wrong_codes: 0 },
        );
        Ok(Begun { attempt, otpauth_uri })
    }

    /// Check the first code against exactly this attempt. A wrong code counts against it, and the `MAX_WRONG_CODES`-th
    /// ends it. A right code leaves the setup staged until `finish`, so a refused commit can be retried on the same
    /// connection.
    pub fn confirm(&mut self, source: &str, bootstrap_pub: &[u8; 32], attempt: u64, code: &str, now_ms: u64) -> Result<Confirmed, StageError> {
        self.take_call(source, now_ms)?;
        let pending = self.pending.get_mut(bootstrap_pub).ok_or(StageError::NoAttempt)?;
        if pending.attempt != attempt {
            return Err(StageError::NoAttempt);
        }
        let totp = Totp::with_defaults(pending.secret.to_vec()).map_err(|_| StageError::Totp)?;
        let Some(counter) = totp.verify(code, now_ms / 1000, SKEW_STEPS, None) else {
            pending.wrong_codes += 1;
            if pending.wrong_codes >= MAX_WRONG_CODES {
                self.pending.remove(bootstrap_pub);
            }
            return Err(StageError::BadCode);
        };
        Ok(Confirmed {
            email: pending.email.clone(),
            device_name: pending.device_name.clone(),
            key_id: pending.key_id,
            secret: pending.secret.clone(),
            counter,
        })
    }

    /// Take the limits for exactly this attempt's `ConfirmExternal` (task T611i), before the provider call.
    pub fn take_external(&mut self, source: &str, bootstrap_pub: &[u8; 32], attempt: u64, now_ms: u64) -> Result<(), StageError> {
        self.take_call(source, now_ms)?;
        match self.pending.get(bootstrap_pub) {
            Some(pending) if pending.attempt == attempt => Ok(()),
            _ => Err(StageError::NoAttempt),
        }
    }

    /// What this attempt staged, for an enrollment the provider verified (task T611i). No authenticator code was
    /// accepted, so the counter is 0.
    pub fn confirmed_external(&self, bootstrap_pub: &[u8; 32], attempt: u64) -> Option<Confirmed> {
        let pending = self.pending.get(bootstrap_pub).filter(|pending| pending.attempt == attempt)?;
        Some(Confirmed {
            email: pending.email.clone(),
            device_name: pending.device_name.clone(),
            key_id: pending.key_id,
            secret: pending.secret.clone(),
            counter: 0,
        })
    }

    /// The activation is durable: the staged setup is spent.
    pub fn finish(&mut self, bootstrap_pub: &[u8; 32]) {
        self.pending.remove(bootstrap_pub);
    }
}
