//! Classify a client identity after TLS verification (docs/SECURITY-DESIGN.md section 3).
//! Two kinds are accepted:
//! an issued device certificate whose device is enrolled and not revoked, and the self-signed bootstrap certificate of a
//! live invitation. Every refusal is the same `Reject`, so a client cannot learn why. Task T203.

use crate::devices::{Device, Devices};
use crate::invites::InviteBook;

/// A client certificate, as far as the TLS layer could tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presented {
    /// Chains to the server's issuing CA (checked by the TLS library); identified by the SHA-256 fingerprint of the
    /// certificate.
    Issued { fingerprint: [u8; 32] },
    /// A self-signed certificate valid for bootstrap and the Ed25519 public key proven by the TLS handshake.
    SelfSigned { public_key: [u8; 32] },
    /// Anything else: an unknown CA, a bad signature, an expired certificate.
    Untrusted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// An enrolled, live device. Full access to the staff entrance (its user still has to sign in).
    Device(Device),
    /// A pending invitation's bootstrap certificate: the connection may make only the two enrollment calls
    /// (`proto::bootstrap`, T204).
    Bootstrap,
    /// Refuse entry. Do not write an application response.
    Reject,
}

/// Decide at `now_ms`:
/// - `Issued`: `Devices::authenticate` (which also records the sighting). A live device is `Device`; an unknown
///   fingerprint or a revoked device is `Reject`.
/// - `SelfSigned`: `Bootstrap` while a live invitation has this bootstrap key (`InviteBook::is_pending`), else `Reject`.
///   A self-signed certificate is never treated as a device, even if its key bytes equal some fingerprint.
/// - `Untrusted`: `Reject`.
pub fn decide(presented: &Presented, devices: &mut Devices, invites: &InviteBook, now_ms: u64) -> Verdict {
    match presented {
        Presented::Issued { fingerprint } => devices.authenticate(fingerprint, now_ms).map_or(Verdict::Reject, Verdict::Device),
        Presented::SelfSigned { public_key } if invites.is_pending(public_key, now_ms) => Verdict::Bootstrap,
        _ => Verdict::Reject,
    }
}
