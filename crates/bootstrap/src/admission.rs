//! Admission from durable state: who may complete the handshake, answered from the account store and nothing else.
//!
//! After a restart the store is all there is, so this must not depend on the certificate authority's in-memory ledger. The
//! TLS layer has already verified the chain, the `clientAuth` extended key usage, the validity period and the proof of the
//! key (`crewcraft-admission`); what is left is whether this is the exact active leaf of a live device, which is
//! `AccountStore::admit` (the device is live and the stored active leaf is byte-equal to the presented one), plus:
//! - the device registered under the leaf SPKI is that same device (a stable key identity, not just a hash match).
//!
//! A bootstrap key is live while its invitation is pending in the store, which a consumed, expired or revoked invitation is
//! not. A poisoned store admits no device and no bootstrap peer: an earlier write has an unknown outcome, so nothing is
//! trusted until the store is reopened. An `Enroller` that poisoned itself for a reason the store cannot see is read from a
//! shared flag, so admission never takes the Enroller lock (lock order is Enroller, then the account store).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crewcraft_admission::Admission;
use crewcraft_pki::key_id_of_certificate;
use crewcraft_server_core::account_store::{AccountStore, AppendLog};

/// `Admission` over the shared account store.
pub struct DurableAdmission<L: AppendLog + Send + 'static> {
    store: Arc<Mutex<AccountStore<L>>>,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
    enroller_poisoned: Arc<AtomicBool>,
}

impl<L: AppendLog + Send + 'static> DurableAdmission<L> {
    /// `store` is the one durable writer (`StoreServices::shared`), `clock` gives Unix milliseconds, and
    /// `enroller_poisoned` is `Enroller::poison_flag`.
    pub fn new(store: Arc<Mutex<AccountStore<L>>>, clock: Arc<dyn Fn() -> u64 + Send + Sync>, enroller_poisoned: Arc<AtomicBool>) -> Self {
        Self { store, clock, enroller_poisoned }
    }
}

impl<L: AppendLog + Send + 'static> std::fmt::Debug for DurableAdmission<L> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DurableAdmission(..)")
    }
}

impl<L: AppendLog + Send + 'static> Admission for DurableAdmission<L> {
    fn device_ok(&self, certificate: &[u8]) -> bool {
        let Ok(spki) = key_id_of_certificate(certificate) else { return false };
        let now = (self.clock)();
        let Ok(mut store) = self.store.lock() else { return false };
        // `admit`: a live device whose stored active leaf is byte-equal to the presented one; it fails for a poisoned store.
        let Ok(device) = store.admit(certificate, now) else { return false };
        // And the device registered under the leaf key is that same device.
        store.device_by_key(&spki) == Some(device.id)
    }

    fn bootstrap_key_live(&self, public_key: &[u8; 32]) -> bool {
        if self.enroller_poisoned.load(Ordering::SeqCst) {
            return false;
        }
        let now = (self.clock)();
        self.store.lock().is_ok_and(|store| store.is_invite_pending(public_key, now))
    }
}
