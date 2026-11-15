//! Enrolling a new device in two steps, so a device is registered only after its person has proved they hold the
//! authenticator (docs/SECURITY-DESIGN.md section 3, point 5): `begin` takes the bootstrap key from the emailed code and
//! the device's details and hands back the TOTP enrollment to scan; `confirm` takes the first code, and only then burns
//! the invitation, registers the device and enrolls the TOTP secret. Redeeming and confirming share per-source and
//! server-wide limits. The listener must limit attempts before doing expensive TLS or password work.
//! The server calls this in-memory first-enrollment flow after it verifies the bootstrap connection, password setup
//! and the candidate device certificate. Store and commit the real account, invitation, device and TOTP state together
//! before exposing an activation response from a listener.
//! Task T205.

use std::collections::HashMap;

use crewcraft_accounts::identity::normalize_email;
use crewcraft_accounts::totp_guard::{GuardError, SKEW_STEPS, TotpGuard};
use crewcraft_totp::Totp;

use crate::devices::{Device, DeviceError, Devices};
use crate::invites::{Invite, InviteBook, InviteError};
use crate::rate_limit::Limiter;

/// The name authenticator apps show for the entry.
pub const ISSUER: &str = "CrewCraft";
/// Calls (`begin` and `confirm` together) per source address: `SOURCE_BURST` at once, refilled at `SOURCE_PER_SEC` a second.
pub const SOURCE_BURST: u32 = 5;
pub const SOURCE_PER_SEC: u32 = 1;
/// The same across every source.
pub const GLOBAL_BURST: u32 = 50;
pub const GLOBAL_PER_SEC: u32 = 5;
/// Wrong codes one pending enrollment tolerates; the `MAX_WRONG_CODES`-th wrong code drops it.
pub const MAX_WRONG_CODES: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationError {
    /// The server-wide bucket, or the source address's, is empty.
    RateLimited,
    /// No live invitation has this bootstrap key (`Unknown`, for expired ones too), or the invitation expired before
    /// `confirm` (`Expired`).
    Invite(InviteError),
    /// `confirm` without a pending enrollment for this key (never begun, dropped after too many wrong codes, or the
    /// invitation expired).
    NoPending,
    /// The code is wrong.
    BadCode,
    /// The person already has a TOTP enrollment. A second-device flow must use that enrollment.
    AlreadyEnrolled,
    /// The verified password setup belongs to a different identity than the invitation.
    AccountMismatch,
    /// The invitation does not identify a valid CrewCraft email address.
    InvalidInvite,
    /// Confirmation came from a different or superseded attempt.
    WrongAttempt,
    /// No more enrollment attempts can be assigned for this instance.
    AttemptLimit,
    /// The server could not create the pending TOTP setup.
    TotpSetup,
    /// The device could not be registered (as `Devices::enroll`); the pending enrollment is kept.
    Device(DeviceError),
}

/// Identifies one staged candidate. Keep this in the verified bootstrap connection's server-side context.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ActivationAttempt(u64);

/// Data supplied by the server after verifying password setup and the candidate certificate.
pub struct EnrollmentCandidate<'a> {
    pub verified_email: &'a str,
    pub device_name: &'a str,
    pub fingerprint: [u8; 32],
    pub totp_secret: [u8; 20],
}

/// What `begin` returns to the bootstrap handler. Only the URI is sent to the client.
#[derive(Clone, PartialEq, Eq)]
pub struct Begun {
    /// The invitation's canonical email, the person's identity.
    pub email: String,
    /// The `otpauth://` URI to show as a QR code (`Totp::otpauth_uri` with `ISSUER` and the email).
    pub otpauth_uri: String,
    pub attempt: ActivationAttempt,
}

impl std::fmt::Debug for Begun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Begun").field("email", &self.email).field("otpauth_uri", &format_args!("..")).finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activated {
    pub email: String,
    pub device_id: u64,
    pub accepted_counter: u64,
}

struct Pending {
    attempt: ActivationAttempt,
    email: String,
    device_name: String,
    fingerprint: [u8; 32],
    secret: [u8; 20],
    wrong_codes: u32,
}

pub struct Activation {
    invites: InviteBook,
    devices: Devices,
    totp: TotpGuard,
    source_limit: Limiter<String>,
    global_limit: Limiter<()>,
    pending: HashMap<[u8; 32], Pending>,
    next_attempt: u64,
}

impl Default for Activation {
    fn default() -> Self {
        Self::new()
    }
}

impl Activation {
    /// No invitations, devices, enrollments or pending enrollments.
    pub fn new() -> Self {
        Self {
            invites: InviteBook::new(),
            devices: Devices::new(),
            totp: TotpGuard::new(),
            source_limit: Limiter::new(SOURCE_BURST, SOURCE_PER_SEC),
            global_limit: Limiter::new(GLOBAL_BURST, GLOBAL_PER_SEC),
            pending: HashMap::new(),
            next_attempt: 0,
        }
    }

    /// Record an invitation and discard any superseded or expired pending setup.
    pub fn invite(&mut self, mut invite: Invite, now_ms: u64) -> Result<(), ActivationError> {
        invite.email = normalize_email(&invite.email).map_err(|_| ActivationError::InvalidInvite)?;
        let key = invite.bootstrap_pub;
        self.invites.issue(invite, now_ms).map_err(ActivationError::Invite)?;
        self.pending.retain(|pending_key, _| pending_key != &key && self.invites.is_pending(pending_key, now_ms));
        Ok(())
    }

    /// With the password setup verified for this invitation, stage the signed certificate fingerprint and name using a
    /// server-generated TOTP secret. The invitation stays pending. A replacement invalidates the old attempt.
    pub fn begin(
        &mut self,
        source: &str,
        bootstrap_pub: &[u8; 32],
        candidate: EnrollmentCandidate<'_>,
        now_ms: u64,
    ) -> Result<Begun, ActivationError> {
        self.take_call(source, now_ms)?;
        let invite = self.invites.get(bootstrap_pub, now_ms).ok_or(ActivationError::Invite(InviteError::Unknown))?;
        if candidate.verified_email != invite.email {
            return Err(ActivationError::AccountMismatch);
        }
        let email = invite.email.clone();
        if self.totp.is_enrolled(&email) {
            return Err(ActivationError::AlreadyEnrolled);
        }
        let totp = Totp::with_defaults(candidate.totp_secret.to_vec()).map_err(|_| ActivationError::TotpSetup)?;
        let otpauth_uri = totp.otpauth_uri(ISSUER, &email);
        let attempt = ActivationAttempt(self.next_attempt);
        self.next_attempt = self.next_attempt.checked_add(1).ok_or(ActivationError::AttemptLimit)?;
        self.pending.insert(
            *bootstrap_pub,
            Pending {
                attempt,
                email: email.clone(),
                device_name: candidate.device_name.into(),
                fingerprint: candidate.fingerprint,
                secret: candidate.totp_secret,
                wrong_codes: 0,
            },
        );
        Ok(Begun { email, otpauth_uri, attempt })
    }

    /// Verify the first code within the exact server-held attempt on this bootstrap connection. A wrong code counts
    /// only against that attempt. A failed device registration leaves the invitation and staged setup available.
    pub fn confirm(
        &mut self,
        source: &str,
        bootstrap_pub: &[u8; 32],
        attempt: ActivationAttempt,
        code: &str,
        now_ms: u64,
    ) -> Result<Activated, ActivationError> {
        self.take_call(source, now_ms)?;
        let pending = self.pending.get_mut(bootstrap_pub).ok_or(ActivationError::NoPending)?;
        if pending.attempt != attempt {
            return Err(ActivationError::WrongAttempt);
        }
        if !self.invites.is_pending(bootstrap_pub, now_ms) {
            self.pending.remove(bootstrap_pub);
            return Err(ActivationError::Invite(InviteError::Expired));
        }
        let totp = Totp::with_defaults(pending.secret.to_vec()).map_err(|_| ActivationError::TotpSetup)?;
        let Some(accepted_counter) = totp.verify(code, now_ms / 1000, SKEW_STEPS, None) else {
            pending.wrong_codes += 1;
            if pending.wrong_codes >= MAX_WRONG_CODES {
                self.pending.remove(bootstrap_pub);
            }
            return Err(ActivationError::BadCode);
        };
        let email = &pending.email;
        if !self.totp.enroll_with_counter(email, pending.secret, accepted_counter) {
            return Err(ActivationError::AlreadyEnrolled);
        }
        let device_id = match self.devices.enroll(email, &pending.device_name, pending.fingerprint, now_ms) {
            Ok(device_id) => device_id,
            Err(error) => {
                self.totp.reset(email);
                return Err(ActivationError::Device(error));
            }
        };
        let email = email.clone();
        self.invites.consume(bootstrap_pub);
        self.pending.remove(bootstrap_pub);
        Ok(Activated { email, device_id, accepted_counter })
    }

    /// Whether the key may still make the enrollment calls: a live invitation has it (as `InviteBook::is_pending`).
    pub fn is_pending(&self, bootstrap_pub: &[u8; 32], now_ms: u64) -> bool {
        self.invites.is_pending(bootstrap_pub, now_ms)
    }

    /// How many pending enrollments are held.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Read enrolled devices without exposing direct registration.
    pub fn devices(&self) -> &Devices {
        &self.devices
    }

    pub fn authenticate_device(&mut self, fingerprint: &[u8; 32], now_ms: u64) -> Result<Device, DeviceError> {
        self.devices.authenticate(fingerprint, now_ms)
    }

    pub fn revoke_device(&mut self, email: &str, device_id: u64) -> Result<bool, DeviceError> {
        self.devices.revoke(email, device_id)
    }

    /// Read the account's TOTP credential and replay state for sign-in.
    pub fn totp(&self) -> &TotpGuard {
        &self.totp
    }

    /// Record a counter from complete sign-in verification while holding the account's lock.
    pub fn record_totp_counter(&mut self, email: &str, counter: u64) -> Result<(), GuardError> {
        self.totp.record_counter(email, counter)
    }

    fn take_call(&mut self, source: &str, now_ms: u64) -> Result<(), ActivationError> {
        if !self.global_limit.check(&(), now_ms) {
            return Err(ActivationError::RateLimited);
        }
        self.source_limit.prune(now_ms);
        if !self.source_limit.check(&source.to_owned(), now_ms) {
            return Err(ActivationError::RateLimited);
        }
        Ok(())
    }
}
