//! Enrolling a new device in two steps, so a device is registered only after its person has proved they hold the
//! authenticator (docs/SECURITY-DESIGN.md section 3, point 5): `begin` takes the bootstrap key from the emailed code and
//! the device's details and hands back the TOTP enrollment to scan; `confirm` takes the first code, and only then burns
//! the invitation, registers the device and enrolls the TOTP secret. Redeeming and confirming share a per-source limit and
//! a global one, so guessing a code costs a handshake each time and the whole server's guessing rate is capped.
//! Composed from `invites` (T103), `devices` (T127), `rate_limit` (T102) and `accounts::totp_guard` (T201). The older
//! `enrollment` (T130) registers at redeem and stays as it is. The password step is a separate task and is not here.
//! Task T205.

use std::collections::HashMap;

use crewcraft_accounts::totp_guard::TotpGuard;

use crate::devices::{DeviceError, Devices};
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
    /// The device could not be registered (as `Devices::enroll`); the pending enrollment is kept.
    Device(DeviceError),
}

/// What `begin` returns for the client to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Begun {
    /// The invitation's email, ASCII-lowercased: the person's identity.
    pub email: String,
    /// The `otpauth://` URI to show as a QR code (`Totp::otpauth_uri` with `ISSUER` and the email).
    pub otpauth_uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activated {
    pub email: String,
    pub device_id: u64,
}

#[allow(dead_code, reason = "fields are read by the implementation of task T205")]
struct Pending {
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
}

impl Default for Activation {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::todo, reason = "stubs until task T205 lands; remove this allow with them")]
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
        }
    }

    /// Record an invitation (as `InviteBook::issue`).
    pub fn invite(&mut self, invite: Invite, now_ms: u64) -> Result<(), InviteError> {
        let _ = (invite, now_ms, &self.invites);
        todo!("T205: invite")
    }

    /// A new device presents the bootstrap key from its emailed code, its name, its certificate fingerprint and a TOTP
    /// secret the caller drew from the OS RNG. Checks, in order:
    /// 1. one token from the global bucket, then one from `source`'s bucket (`RateLimited` if either is empty);
    /// 2. a live invitation must have this bootstrap key (`Invite(Unknown)`), read with `InviteBook::get`.
    ///
    /// Nothing is registered or burned: the key stays pending and no device exists. A pending enrollment already held for
    /// the key is replaced (the new name, fingerprint and secret win and the wrong-code count starts again), so the
    /// person can retry with a better device name.
    pub fn begin(
        &mut self,
        source: &str,
        bootstrap_pub: &[u8; 32],
        device_name: &str,
        fingerprint: [u8; 32],
        totp_secret: [u8; 20],
        now_ms: u64,
    ) -> Result<Begun, ActivationError> {
        let _ = (source, bootstrap_pub, device_name, fingerprint, totp_secret, now_ms, &self.pending, &self.source_limit);
        todo!("T205: begin")
    }

    /// The first TOTP code. Checks, in order:
    /// 1. the same two buckets as `begin`;
    /// 2. a pending enrollment for the key (`NoPending`);
    /// 3. the invitation is still live (`Invite(Expired)`, and the pending enrollment is dropped);
    /// 4. the code, with the pending secret at `now_ms / 1000` and `totp_guard::SKEW_STEPS` of skew. A wrong code is
    ///    `BadCode` and counts against the pending enrollment, which is dropped (the invitation stays) when the count
    ///    reaches `MAX_WRONG_CODES`;
    /// 5. the device is registered for the lowercased email (`Devices::enroll`; its error is `Device(..)`, with the
    ///    pending enrollment, the invitation and the TOTP state all unchanged).
    ///
    /// On success the invitation is burned (`InviteBook::redeem`), the pending enrollment is removed, the secret is
    /// enrolled in the guard and the code's counter is recorded as used, so the same code cannot sign in afterwards.
    pub fn confirm(&mut self, source: &str, bootstrap_pub: &[u8; 32], code: &str, now_ms: u64) -> Result<Activated, ActivationError> {
        let _ = (source, bootstrap_pub, code, now_ms, &self.global_limit);
        todo!("T205: confirm")
    }

    /// Whether the key may still make the enrollment calls: a live invitation has it (as `InviteBook::is_pending`).
    pub fn is_pending(&self, bootstrap_pub: &[u8; 32], now_ms: u64) -> bool {
        let _ = (bootstrap_pub, now_ms);
        todo!("T205: is_pending")
    }

    /// How many pending enrollments are held.
    pub fn pending_count(&self) -> usize {
        todo!("T205: pending_count")
    }

    /// The device registry, for sign-in and revocation.
    pub fn devices(&mut self) -> &mut Devices {
        &mut self.devices
    }

    /// The TOTP guard, for sign-in.
    pub fn totp(&mut self) -> &mut TotpGuard {
        &mut self.totp
    }
}
