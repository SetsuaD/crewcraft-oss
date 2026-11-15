//! The real `Services`: the durable `AccountStore` (issue #35) plus an `Environment` for the clock, the random source and
//! the password hasher. Every decision about who may enroll comes from the store, so nothing is lost or decided in
//! memory across a restart.
//!
//! How a store failure is classified (this is the recovery policy of the bootstrap connection):
//! - **Proven before anything was written** (`check` refused it, or `Journal(TooLarge)` where "nothing was written"):
//!   `Refused`. Nothing durable changed, the staged setup is untouched, and the connection is closed with an error.
//! - **The device id moved** between building the certificate and committing: `OrdinalMoved`, nothing written. The
//!   handler rebuilds the certificate once with the new id and commits again.
//! - **Anything else** (`Journal(Io)`, `Poisoned`, `WrongKey`, `Corrupt`): `Ambiguous`. A failed sync can leave the record
//!   on disk although the caller was told it failed (`Journal::append` cuts the file back only best-effort), so the
//!   activation may be durable with a certificate nobody received. The handler poisons itself and releases nothing.

use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_accounts::password;
use crewcraft_server_core::account_store::{AccountStore, Activation, AppendLog, FirstDevice, StoreError};
use crewcraft_server_core::journal::JournalError;

use crate::{ActivationRecord, CommitFailure, Services, random_totp_secret};

/// The clock, the random source and the password hasher the handler uses.
pub trait Environment {
    fn now_ms(&self) -> u64;

    /// A fresh 20-byte TOTP secret from the system random source, or `None` if it failed.
    fn totp_secret(&mut self) -> Option<[u8; 20]>;

    /// Hash a new account password (Argon2id PHC). Called only after the request passed the rate limits.
    fn hash_password(&mut self, password: &str) -> Option<String> {
        password::hash(password).ok()
    }
}

/// The wall clock and the operating system's random source.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEnvironment;

impl Environment for SystemEnvironment {
    fn now_ms(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    fn totp_secret(&mut self) -> Option<[u8; 20]> {
        random_totp_secret()
    }
}

/// `Services` over the durable account store.
pub struct StoreServices<L: AppendLog, E: Environment> {
    store: AccountStore<L>,
    env: E,
}

impl<L: AppendLog, E: Environment> std::fmt::Debug for StoreServices<L, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreServices(..)")
    }
}

impl<L: AppendLog, E: Environment> StoreServices<L, E> {
    pub fn new(store: AccountStore<L>, env: E) -> Self {
        Self { store, env }
    }

    pub fn store(&self) -> &AccountStore<L> {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut AccountStore<L> {
        &mut self.store
    }

    pub fn env(&self) -> &E {
        &self.env
    }

    pub fn env_mut(&mut self) -> &mut E {
        &mut self.env
    }

    /// Give back the store and the environment, for a restart that reopens the store.
    pub fn into_parts(self) -> (AccountStore<L>, E) {
        (self.store, self.env)
    }
}

/// Whether `error` was found before anything was appended.
fn proven_before_write(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::NoInvite
            | StoreError::Invite(_)
            | StoreError::PersonExists
            | StoreError::NoSuchPerson
            | StoreError::NoOwnPassword
            | StoreError::Device(_)
            | StoreError::StaleCounter { .. }
            | StoreError::BadField
            | StoreError::Seal(_)
            | StoreError::KeyInUse
            | StoreError::Codec(_)
            | StoreError::Journal(JournalError::TooLarge)
    )
}

/// The failure class of a store error (see the module docs).
pub fn classify(error: &StoreError) -> CommitFailure {
    match error {
        StoreError::Ordinal { .. } => CommitFailure::OrdinalMoved,
        e if proven_before_write(e) => CommitFailure::Refused,
        _ => CommitFailure::Ambiguous,
    }
}

impl<L: AppendLog, E: Environment> Services for StoreServices<L, E> {
    fn now_ms(&self) -> u64 {
        self.env.now_ms()
    }

    fn new_totp_secret(&mut self) -> Option<[u8; 20]> {
        self.env.totp_secret()
    }

    fn hash_password(&mut self, password: &str) -> Option<String> {
        self.env.hash_password(password)
    }

    fn invitation_email(&self, bootstrap_pub: &[u8; 32], now_ms: u64) -> Option<String> {
        self.store.pending_invite_email(bootstrap_pub, now_ms)
    }

    fn has_person(&self, email: &str) -> bool {
        self.store.person(email).is_some()
    }

    fn key_registered(&self, key_id: &[u8; 32]) -> bool {
        self.store.device_by_key(key_id).is_some()
    }

    fn next_device_ordinal(&self) -> u64 {
        self.store.next_device_id()
    }

    fn activate(&mut self, record: &ActivationRecord, now_ms: u64) -> Result<u64, CommitFailure> {
        let Some(leaf) = record.chain.first() else { return Err(CommitFailure::Refused) };
        let activation = Activation {
            bootstrap_pub: record.bootstrap_pub,
            device_name: &record.device_name,
            certificate: leaf,
            spki_sha256: record.key_id,
            counter: record.accepted_counter,
            first_device: Some(FirstDevice { password_phc: Some(&record.password_phc), totp_secret: &record.totp_secret }),
        };
        self.store.activate_expecting(activation, record.device_id, now_ms).map_err(|e| classify(&e))
    }
}
