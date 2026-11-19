//! Pending enrollment invitations, keyed by the bootstrap public key derived from the emailed code
//! (docs/SECURITY-DESIGN.md). The server never holds the code itself. Task T103.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    pub email: String,
    pub bootstrap_pub: [u8; 32],
    /// The invitation is live while `now_ms < expires_ms`.
    pub expires_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteError {
    /// No invitation has this bootstrap key.
    Unknown,
    /// The invitation was found but is past its expiry (it is removed).
    Expired,
    /// A live invitation for another email already uses this bootstrap key.
    KeyInUse,
}

#[derive(Debug, Default)]
pub struct InviteBook {
    invites: Vec<Invite>,
}

impl InviteBook {
    pub fn new() -> Self {
        Self { invites: Vec::new() }
    }

    /// Record an invitation. A new invitation for an email that already has one replaces it, so the older code stops
    /// working; emails compare ASCII-case-insensitively. `KeyInUse` (and nothing changes) when a live invitation for a
    /// different email has the same bootstrap key; an expired one with that key is simply discarded.
    pub fn issue(&mut self, invite: Invite, now_ms: u64) -> Result<(), InviteError> {
        self.check_issue(&invite, now_ms)?;
        let new_email_lower = invite.email.to_ascii_lowercase();
        self.invites.retain(|i| i.email.to_ascii_lowercase() != new_email_lower && i.bootstrap_pub != invite.bootstrap_pub);

        self.invites.push(invite);
        Ok(())
    }

    /// What `issue` would refuse, without changing anything (the account store validates before it journals).
    pub fn check_issue(&self, invite: &Invite, now_ms: u64) -> Result<(), InviteError> {
        let new_email_lower = invite.email.to_ascii_lowercase();
        for existing in &self.invites {
            if existing.bootstrap_pub == invite.bootstrap_pub
                && existing.expires_ms > now_ms
                && existing.email.to_ascii_lowercase() != new_email_lower
            {
                return Err(InviteError::KeyInUse);
            }
        }
        Ok(())
    }

    /// The live invitation with this bootstrap key, without redeeming it.
    pub fn pending(&self, bootstrap_pub: &[u8; 32], now_ms: u64) -> Option<&Invite> {
        self.invites.iter().find(|i| &i.bootstrap_pub == bootstrap_pub && now_ms < i.expires_ms)
    }

    /// Withdraw the invitation with this bootstrap key, live or expired; `true` when there was one.
    pub fn revoke(&mut self, bootstrap_pub: &[u8; 32]) -> bool {
        let before = self.invites.len();
        self.invites.retain(|i| &i.bootstrap_pub != bootstrap_pub);
        before != self.invites.len()
    }

    /// Single use: a live invitation is removed and returned; an expired one is removed and `Expired`; no match is
    /// `Unknown`.
    pub fn redeem(&mut self, bootstrap_pub: &[u8; 32], now_ms: u64) -> Result<Invite, InviteError> {
        let idx = self.invites.iter().position(|i| &i.bootstrap_pub == bootstrap_pub);
        match idx {
            None => Err(InviteError::Unknown),
            Some(i) => {
                let invite = self.invites.remove(i);
                if now_ms < invite.expires_ms { Ok(invite) } else { Err(InviteError::Expired) }
            }
        }
    }

    /// Whether a live invitation has this bootstrap key.
    pub fn is_pending(&self, bootstrap_pub: &[u8; 32], now_ms: u64) -> bool {
        self.invites.iter().any(|i| &i.bootstrap_pub == bootstrap_pub && now_ms < i.expires_ms)
    }

    /// Consume a checked invitation after activation's other writes succeeded under exclusive access.
    pub(crate) fn consume(&mut self, bootstrap_pub: &[u8; 32]) {
        self.revoke(bootstrap_pub);
    }

    /// The live invitation with this bootstrap key, without using it up.
    pub fn get(&self, bootstrap_pub: &[u8; 32], now_ms: u64) -> Option<&Invite> {
        self.pending(bootstrap_pub, now_ms)
    }

    /// Remove every expired invitation; returns how many.
    pub fn prune(&mut self, now_ms: u64) -> usize {
        let before = self.invites.len();
        self.invites.retain(|i| now_ms < i.expires_ms);
        before - self.invites.len()
    }

    /// Invitations held (live or not yet pruned).
    pub fn len(&self) -> usize {
        self.invites.len()
    }

    pub fn is_empty(&self) -> bool {
        self.invites.is_empty()
    }
}
