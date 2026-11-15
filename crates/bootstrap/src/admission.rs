//! Admission from durable state: who may complete the handshake, answered from the account store and nothing else.
//!
//! After a restart the store is all there is, so this must not depend on the certificate authority's in-memory ledger. The
//! TLS layer has already verified the chain, the `clientAuth` extended key usage, the validity period and the proof of the
//! key (`crewcraft-admission`); what is left is whether this is the exact active leaf of a live device:
//! - the registry knows the SHA-256 of the presented leaf, and that device is not revoked;
//! - the leaf stored for that device is byte-identical to the one presented;
//! - the device registered under the leaf's SPKI is the same device (a stable key identity, not just a hash match).
//!
//! A bootstrap key is live while its invitation is pending in the store, which a consumed, expired or revoked invitation is
//! not. A poisoned `Enroller` admits no bootstrap peer, because it cannot tell whether an invitation was just consumed.

use std::sync::{Arc, Mutex};

use crewcraft_admission::Admission;
use crewcraft_pki::key_id_of_certificate;
use crewcraft_server_core::account_store::{AppendLog, fingerprint};

use crate::{Enroller, Environment, Services, StoreServices};

/// `Admission` over the enroller that owns the durable store.
pub struct DurableAdmission<L: AppendLog + Send + 'static, E: Environment + Send + 'static>(pub Arc<Mutex<Enroller<StoreServices<L, E>>>>);

impl<L: AppendLog + Send + 'static, E: Environment + Send + 'static> std::fmt::Debug for DurableAdmission<L, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DurableAdmission(..)")
    }
}

impl<L: AppendLog + Send + 'static, E: Environment + Send + 'static> Admission for DurableAdmission<L, E> {
    fn device_ok(&self, certificate: &[u8]) -> bool {
        let Ok(mut enroller) = self.0.lock() else { return false };
        let now = enroller.services().now_ms();
        let Ok(spki) = key_id_of_certificate(certificate) else { return false };
        let store = enroller.services_mut().store_mut();
        let Some(device_id) = store.device_by_key(&spki) else { return false };
        if store.device_certificate(device_id) != Some(certificate) {
            return false;
        }
        // `authenticate` is `Ok` for a registered, unrevoked fingerprint and records that the device was seen.
        store.authenticate(&fingerprint(certificate), now).is_ok_and(|device| device.id == device_id)
    }

    fn bootstrap_key_live(&self, public_key: &[u8; 32]) -> bool {
        let Ok(enroller) = self.0.lock() else { return false };
        !enroller.is_poisoned() && enroller.services().store().is_invite_pending(public_key, enroller.services().now_ms())
    }
}
