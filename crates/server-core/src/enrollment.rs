//! Turning an emailed invitation into an enrolled device: the invitation is redeemed by its bootstrap key and the
//! device's certificate fingerprint is registered. Composed from `invites` (T103), `devices` (T127) and `rate_limit`
//! (T102). Task T130.

use crate::devices::{DeviceError, Devices};
use crate::invites::{Invite, InviteBook, InviteError};
use crate::rate_limit::Limiter;

/// Redemption attempts per source address: `REDEEM_BURST` at once, refilled at `REDEEM_PER_SEC` a second.
pub const REDEEM_BURST: u32 = 5;
pub const REDEEM_PER_SEC: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollError {
    /// The source address has no attempts left.
    RateLimited,
    /// Passed through from `InviteBook`.
    Invite(InviteError),
    /// Passed through from `Devices::enroll`.
    Device(DeviceError),
}

pub struct Enrollment {
    invites: InviteBook,
    devices: Devices,
    limiter: Limiter<String>,
}

impl Default for Enrollment {
    fn default() -> Self {
        Self::new()
    }
}

impl Enrollment {
    /// No invitations, no devices.
    pub fn new() -> Self {
        Self { invites: InviteBook::new(), devices: Devices::new(), limiter: Limiter::new(REDEEM_BURST, REDEEM_PER_SEC) }
    }

    /// Record an invitation (as `InviteBook::issue`).
    pub fn invite(&mut self, invite: Invite, now_ms: u64) -> Result<(), EnrollError> {
        self.invites.issue(invite, now_ms).map_err(EnrollError::Invite)
    }

    /// A new device presents the bootstrap key from its emailed code, its name and its certificate fingerprint. Checks,
    /// in order:
    /// 1. one attempt is taken from `source`'s bucket (`RateLimited` if none; a refused attempt has still used it);
    /// 2. a live invitation must have this bootstrap key (`Invite(Unknown)`; `Invite(Expired)`, and the expired one is
    ///    removed, as `InviteBook::redeem` does);
    /// 3. the device is enrolled for the invitation's email, ASCII-lowercased (`Device(..)` as `Devices::enroll`).
    ///
    /// The invitation is used up only when the device is enrolled: after a `Device(..)` error it is still pending,
    /// unchanged, so the user can try again (for example with a better device name). Returns the lowercased email and
    /// the new device id.
    pub fn redeem(
        &mut self,
        source: &str,
        bootstrap_pub: &[u8; 32],
        device_name: &str,
        fingerprint: [u8; 32],
        now_ms: u64,
    ) -> Result<(String, u64), EnrollError> {
        // 1. Rate limit check
        if !self.limiter.check(&source.to_string(), now_ms) {
            return Err(EnrollError::RateLimited);
        }

        // 2. Redeem the invitation (removes it from the book)
        let invite = self.invites.redeem(bootstrap_pub, now_ms).map_err(EnrollError::Invite)?;

        // 3. Enroll the device for the lowercased email
        let email = invite.email.to_ascii_lowercase();
        match self.devices.enroll(&email, device_name, fingerprint, now_ms) {
            Ok(id) => Ok((email, id)),
            Err(dev_err) => {
                // Re-insert the invitation so the user can retry
                self.invites.issue(invite, now_ms).map_err(EnrollError::Invite)?;
                Err(EnrollError::Device(dev_err))
            }
        }
    }

    /// Whether a live invitation has this bootstrap key (as `InviteBook::is_pending`).
    pub fn is_pending(&self, bootstrap_pub: &[u8; 32], now_ms: u64) -> bool {
        self.invites.is_pending(bootstrap_pub, now_ms)
    }

    /// The device registry, for sign-in (`Devices::authenticate`) and revocation.
    pub fn devices(&mut self) -> &mut Devices {
        &mut self.devices
    }
}
