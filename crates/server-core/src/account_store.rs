//! The authentication store that survives a restart (issue #35): people (password verifier, sealed TOTP secret, last
//! accepted TOTP counter), their enrolled devices (`devices`, T127) and pending invitations (`invites`, T103), kept in
//! their own journal file (`journal`, T140) of `account_op` records, separate from the room journal (`durable`).
//!
//! Owns: the single-writer rule (`&mut self` for every change), the order validate -> append -> apply (nothing reaches
//! memory, and no success is returned, unless its record is on disk; T140 cuts a failed append back off the file), one
//! record per activation (the invitation is consumed, the person created or extended, the device registered and the
//! first counter saved together or not at all), a strictly increasing TOTP counter, and exact replay: a record that
//! does not apply, a store written under another service key, or a sealed secret that fails authentication refuses
//! the whole open (fail closed; no partially initialised store is ever returned).
//! Does not own: verifying a TOTP code or a password (the caller does that with `crewcraft-totp` / `crewcraft-accounts`
//! and passes the accepted counter), session tokens, or how the certificate reaches the client.
//! Called by: the server's enrollment and sign-in paths.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use crewcraft_proto::message::CodecError;
use zeroize::Zeroizing;

use sha2::{Digest, Sha256};

use crate::account_op::{AccountOp, FORMAT, MAX_CERT, MAX_STR, NewPerson, decode_account_op, encode_account_op};
use crate::devices::{Device, DeviceError, Devices};
use crate::invites::{Invite, InviteBook, InviteError};
use crate::journal::{Journal, JournalError};
use crate::seal::{SealError, Sealed, ServiceKey};

/// Where records go. `Journal` in production; tests wrap it to force a write failure.
pub trait AppendLog {
    /// Append one record durably, or fail having written nothing that a later open would read.
    fn append(&mut self, record: &[u8]) -> Result<(), JournalError>;
}

impl AppendLog for Journal {
    fn append(&mut self, record: &[u8]) -> Result<(), JournalError> {
        Journal::append(self, record)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Journal(JournalError),
    Codec(CodecError),
    /// The store was written under a different service key, or a sealed secret names another key.
    WrongKey,
    /// Record `record` (0-based) does not decode or does not apply to the state before it.
    Corrupt {
        record: usize,
        cause: Box<StoreError>,
    },
    /// A record was appended but could not be applied in memory (a bug); the store refuses further changes.
    Poisoned,
    /// No live invitation has this bootstrap key (unknown, expired, consumed or revoked).
    NoInvite,
    Invite(InviteError),
    /// A first-device activation for an email that already has a person.
    PersonExists,
    NoSuchPerson,
    /// The person has no stored password (the `mailbox` source stores none).
    NoOwnPassword,
    Device(DeviceError),
    /// The counter is not newer than the last accepted one.
    StaleCounter {
        last: u64,
    },
    Seal(SealError),
    /// An empty or overlong email, password or certificate.
    BadField,
    /// The device key (its SubjectPublicKeyInfo) is already registered, live or revoked: a revoked key never returns.
    KeyInUse,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Corrupt { record, cause } => write!(f, "account store record {record}: {cause}"),
            StoreError::StaleCounter { last } => write!(f, "TOTP counter not newer than {last}"),
            other => write!(f, "{other:?}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<JournalError> for StoreError {
    fn from(e: JournalError) -> Self {
        StoreError::Journal(e)
    }
}

/// A first device's person: what the activation creates.
pub struct FirstDevice<'a> {
    /// Argon2id PHC with the `own` password source; `None` with `mailbox`.
    pub password_phc: Option<&'a str>,
    /// The TOTP secret the person just confirmed. It is sealed before it is written.
    pub totp_secret: &'a [u8],
}

/// One activation: the invitation (by its bootstrap key), the device, and the counter of the confirmation code.
pub struct Activation<'a> {
    pub bootstrap_pub: [u8; 32],
    pub device_name: &'a str,
    /// The exact leaf certificate (DER) the server will hand out once this returns `Ok`. Its SHA-256 becomes the
    /// device's certificate fingerprint.
    pub certificate: &'a [u8],
    /// SHA-256 of the leaf's SubjectPublicKeyInfo: the device's stable identity across certificate renewals.
    pub spki_sha256: [u8; 32],
    /// What `crewcraft_totp::Totp::verify` returned for the confirmation code.
    pub counter: u64,
    /// `Some` for the person's first device; `None` adds a device to the existing person the invitation names, whose
    /// counter must then be newer than the last one accepted.
    pub first_device: Option<FirstDevice<'a>>,
}

struct Person {
    password_phc: Option<String>,
    totp: Sealed,
    last_counter: u64,
}

/// What a caller may read about a person. No secret is in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonInfo {
    pub email: String,
    /// The PHC string with the `own` password source (for `crewcraft_accounts::password::verify`).
    pub password_phc: Option<String>,
    pub last_totp_counter: u64,
}

pub struct AccountStore<L: AppendLog = Journal> {
    log: L,
    key: ServiceKey,
    people: BTreeMap<String, Person>,
    invites: InviteBook,
    devices: Devices,
    /// Device id by SPKI SHA-256, every device ever registered (revoked ones too).
    keys: BTreeMap<[u8; 32], u64>,
    /// The issued leaf certificate by device id.
    certificates: BTreeMap<u64, Vec<u8>>,
    poisoned: bool,
}

impl<L: AppendLog> fmt::Debug for AccountStore<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountStore").field("people", &self.people.len()).field("invites", &self.invites.len()).field("key", &self.key).finish()
    }
}

impl AccountStore<Journal> {
    /// Open (or create) the store at `path` with the service key. A new store's first record names the key; an
    /// existing store opens only with that same key, and only if every record replays exactly.
    pub fn open(path: &Path, key: ServiceKey) -> Result<Self, StoreError> {
        let (journal, records) = Journal::open(path)?;
        Self::from_records(journal, key, records)
    }
}

impl<L: AppendLog> AccountStore<L> {
    /// Replay `records` (as `Journal::open` returned them) over an empty store; for an empty list, write the `Created`
    /// record through `log` first.
    pub fn from_records(log: L, key: ServiceKey, records: Vec<Vec<u8>>) -> Result<Self, StoreError> {
        let mut store = AccountStore {
            log,
            key,
            people: BTreeMap::new(),
            invites: InviteBook::new(),
            devices: Devices::new(),
            keys: BTreeMap::new(),
            certificates: BTreeMap::new(),
            poisoned: false,
        };
        if records.is_empty() {
            let created = AccountOp::Created { format: FORMAT, key_id: store.key.id() };
            store.log.append(&encode_account_op(&created).map_err(StoreError::Codec)?)?;
            return Ok(store);
        }
        for (index, bytes) in records.iter().enumerate() {
            let op = decode_account_op(bytes).map_err(|e| StoreError::Corrupt { record: index, cause: Box::new(StoreError::Codec(e)) })?;
            if index == 0 {
                match op {
                    AccountOp::Created { format, key_id } if format == FORMAT => {
                        if key_id != store.key.id() {
                            return Err(StoreError::WrongKey);
                        }
                        continue;
                    }
                    _ => return Err(StoreError::Corrupt { record: 0, cause: Box::new(StoreError::Codec(CodecError::BadKind(0))) }),
                }
            }
            match store.check(&op).and_then(|()| store.apply(&op)) {
                Ok(()) => {}
                Err(StoreError::WrongKey | StoreError::Seal(SealError::WrongKey)) => return Err(StoreError::WrongKey),
                Err(cause) => return Err(StoreError::Corrupt { record: index, cause: Box::new(cause) }),
            }
        }
        Ok(store)
    }

    /// Validate, append, apply. The caller gets `Ok` only once the record is durable and applied.
    fn commit(&mut self, op: AccountOp) -> Result<(), StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        self.check(&op)?;
        let bytes = encode_account_op(&op).map_err(StoreError::Codec)?;
        self.log.append(&bytes)?;
        if self.apply(&op).is_err() {
            self.poisoned = true;
            return Err(StoreError::Poisoned);
        }
        Ok(())
    }

    /// Whether `op` applies to the current state. Used both before journaling a change and while replaying one.
    fn check(&self, op: &AccountOp) -> Result<(), StoreError> {
        match op {
            AccountOp::Created { .. } => Err(StoreError::Codec(CodecError::BadKind(1))),
            AccountOp::InviteIssued { email, bootstrap_pub, expires_ms, now_ms } => {
                field(email)?;
                let invite = Invite { email: email.clone(), bootstrap_pub: *bootstrap_pub, expires_ms: *expires_ms };
                self.invites.check_issue(&invite, *now_ms).map_err(StoreError::Invite)
            }
            AccountOp::InviteRevoked { bootstrap_pub } => {
                // `pending` at time 0 finds every invitation held, live or not yet pruned.
                self.invites.pending(bootstrap_pub, 0).map(|_| ()).ok_or(StoreError::NoInvite)
            }
            AccountOp::Activated { bootstrap_pub, new_person, device_id, device_name, certificate, spki_sha256, counter, now_ms } => {
                if certificate.is_empty() || certificate.len() > MAX_CERT {
                    return Err(StoreError::BadField);
                }
                if self.keys.contains_key(spki_sha256) {
                    return Err(StoreError::KeyInUse);
                }
                let email = &self.invites.pending(bootstrap_pub, *now_ms).ok_or(StoreError::NoInvite)?.email;
                match (new_person, self.people.get(email)) {
                    (Some(_), Some(_)) => return Err(StoreError::PersonExists),
                    (None, None) => return Err(StoreError::NoSuchPerson),
                    (None, Some(person)) if *counter <= person.last_counter => return Err(StoreError::StaleCounter { last: person.last_counter }),
                    (Some(person), None) => {
                        if let Some(phc) = &person.password_phc {
                            field(phc)?;
                        }
                        // Authenticate the sealed secret now, so a record that would not open later is never accepted.
                        self.key.open(&person.totp, email.as_bytes()).map_err(StoreError::Seal)?;
                    }
                    _ => {}
                }
                let next = self.devices.check_enroll(email, device_name, &fingerprint(certificate)).map_err(StoreError::Device)?;
                if next != *device_id {
                    return Err(StoreError::Device(DeviceError::NoSuchDevice));
                }
                Ok(())
            }
            AccountOp::TotpAccepted { email, counter } => {
                let person = self.people.get(email).ok_or(StoreError::NoSuchPerson)?;
                if *counter <= person.last_counter {
                    return Err(StoreError::StaleCounter { last: person.last_counter });
                }
                Ok(())
            }
            AccountOp::PasswordChanged { email, phc } => {
                field(phc)?;
                match self.people.get(email) {
                    None => Err(StoreError::NoSuchPerson),
                    Some(person) if person.password_phc.is_none() => Err(StoreError::NoOwnPassword),
                    Some(_) => Ok(()),
                }
            }
            AccountOp::DeviceRevoked { email, device_id } => match self.devices.list(email).iter().find(|d| d.id == *device_id) {
                Some(device) if !device.revoked => Ok(()),
                Some(_) => Err(StoreError::Device(DeviceError::Revoked)),
                None => Err(StoreError::Device(DeviceError::NoSuchDevice)),
            },
        }
    }

    /// Apply a checked op. An error here after `check` passed is a bug (the caller poisons the store).
    fn apply(&mut self, op: &AccountOp) -> Result<(), StoreError> {
        match op {
            AccountOp::Created { .. } => Err(StoreError::Codec(CodecError::BadKind(1))),
            AccountOp::InviteIssued { email, bootstrap_pub, expires_ms, now_ms } => self
                .invites
                .issue(Invite { email: email.clone(), bootstrap_pub: *bootstrap_pub, expires_ms: *expires_ms }, *now_ms)
                .map_err(StoreError::Invite),
            AccountOp::InviteRevoked { bootstrap_pub } => {
                self.invites.revoke(bootstrap_pub);
                Ok(())
            }
            AccountOp::Activated { bootstrap_pub, new_person, device_id, device_name, certificate, spki_sha256, counter, now_ms } => {
                let email = self.invites.redeem(bootstrap_pub, *now_ms).map_err(StoreError::Invite)?.email;
                let id = self.devices.enroll(&email, device_name, fingerprint(certificate), *now_ms).map_err(StoreError::Device)?;
                if id != *device_id {
                    return Err(StoreError::Device(DeviceError::NoSuchDevice));
                }
                self.keys.insert(*spki_sha256, id);
                self.certificates.insert(id, certificate.clone());
                match new_person {
                    Some(NewPerson { password_phc, totp }) => {
                        self.people.insert(email, Person { password_phc: password_phc.clone(), totp: totp.clone(), last_counter: *counter });
                    }
                    None => self.people.get_mut(&email).ok_or(StoreError::NoSuchPerson)?.last_counter = *counter,
                }
                Ok(())
            }
            AccountOp::TotpAccepted { email, counter } => {
                self.people.get_mut(email).ok_or(StoreError::NoSuchPerson)?.last_counter = *counter;
                Ok(())
            }
            AccountOp::PasswordChanged { email, phc } => {
                self.people.get_mut(email).ok_or(StoreError::NoSuchPerson)?.password_phc = Some(phc.clone());
                Ok(())
            }
            AccountOp::DeviceRevoked { email, device_id } => self.devices.revoke(email, *device_id).map(|_| ()).map_err(StoreError::Device),
        }
    }

    /// Record an invitation (only its bootstrap public key; `crewcraft_enroll` derives it from the code).
    pub fn issue_invite(&mut self, invite: Invite, now_ms: u64) -> Result<(), StoreError> {
        self.commit(AccountOp::InviteIssued { email: invite.email, bootstrap_pub: invite.bootstrap_pub, expires_ms: invite.expires_ms, now_ms })
    }

    /// Withdraw an invitation; `Ok(false)` (and nothing written) when there is none.
    pub fn revoke_invite(&mut self, bootstrap_pub: &[u8; 32]) -> Result<bool, StoreError> {
        if self.invites.pending(bootstrap_pub, 0).is_none() {
            return Ok(false);
        }
        self.commit(AccountOp::InviteRevoked { bootstrap_pub: *bootstrap_pub }).map(|()| true)
    }

    /// Whether a live invitation has this bootstrap key (the bootstrap TLS verifier asks this).
    pub fn is_invite_pending(&self, bootstrap_pub: &[u8; 32], now_ms: u64) -> bool {
        self.invites.is_pending(bootstrap_pub, now_ms)
    }

    /// Commit an activation as ONE record and return the new device id. The person is the invitation's email: the
    /// client cannot choose it. Only after `Ok` may the server answer the client with success (or its certificate).
    pub fn activate(&mut self, activation: Activation<'_>, now_ms: u64) -> Result<u64, StoreError> {
        let email = self.invites.pending(&activation.bootstrap_pub, now_ms).ok_or(StoreError::NoInvite)?.email.clone();
        let new_person = match activation.first_device {
            None => None,
            Some(first) => Some(NewPerson {
                password_phc: first.password_phc.map(str::to_string),
                totp: self.key.seal(first.totp_secret, email.as_bytes()).map_err(StoreError::Seal)?,
            }),
        };
        let device_id =
            self.devices.check_enroll(&email, activation.device_name, &fingerprint(activation.certificate)).map_err(StoreError::Device)?;
        self.commit(AccountOp::Activated {
            bootstrap_pub: activation.bootstrap_pub,
            new_person,
            device_id,
            device_name: activation.device_name.trim().to_string(),
            certificate: activation.certificate.to_vec(),
            spki_sha256: activation.spki_sha256,
            counter: activation.counter,
            now_ms,
        })?;
        Ok(device_id)
    }

    /// Save a sign-in's accepted TOTP counter. Call it after the code verified and BEFORE issuing a session: the same
    /// or an older counter is refused, also after a restart.
    pub fn accept_totp(&mut self, email: &str, counter: u64) -> Result<(), StoreError> {
        self.commit(AccountOp::TotpAccepted { email: email.to_string(), counter })
    }

    /// Replace the stored password verifier (for example after `password::needs_rehash`).
    pub fn set_password(&mut self, email: &str, phc: &str) -> Result<(), StoreError> {
        self.commit(AccountOp::PasswordChanged { email: email.to_string(), phc: phc.to_string() })
    }

    /// Revoke one of `email`'s devices; `Ok(false)` (and nothing written) when it was already revoked. A revoked
    /// fingerprint stays banned after a restart.
    pub fn revoke_device(&mut self, email: &str, device_id: u64) -> Result<bool, StoreError> {
        match self.devices.list(email).iter().find(|d| d.id == device_id) {
            Some(device) if device.revoked => Ok(false),
            _ => self.commit(AccountOp::DeviceRevoked { email: email.to_string(), device_id }).map(|()| true),
        }
    }

    pub fn person(&self, email: &str) -> Option<PersonInfo> {
        self.people.get(email).map(|p| PersonInfo {
            email: email.to_string(),
            password_phc: p.password_phc.clone(),
            last_totp_counter: p.last_counter,
        })
    }

    /// The person's TOTP secret, opened with the service key, for verifying a code.
    pub fn totp_secret(&self, email: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let person = self.people.get(email).ok_or(StoreError::NoSuchPerson)?;
        self.key.open(&person.totp, email.as_bytes()).map_err(StoreError::Seal)
    }

    /// The live device for a certificate fingerprint (its last-seen time is kept in memory only).
    pub fn authenticate(&mut self, fingerprint: &[u8; 32], now_ms: u64) -> Result<Device, DeviceError> {
        self.devices.authenticate(fingerprint, now_ms)
    }

    /// The exact leaf certificate issued to a device (to hand out after `activate`, or to compare on reconnect).
    pub fn device_certificate(&self, device_id: u64) -> Option<&[u8]> {
        self.certificates.get(&device_id).map(Vec::as_slice)
    }

    /// The device registered with this key, live or revoked (renewal and revocation look it up by key).
    pub fn device_by_key(&self, spki_sha256: &[u8; 32]) -> Option<u64> {
        self.keys.get(spki_sha256).copied()
    }

    /// The person's devices, live and revoked.
    pub fn devices_of(&self, email: &str) -> Vec<Device> {
        self.devices.list(email)
    }
}

/// The device's certificate fingerprint: SHA-256 of the leaf DER (what `devices` and the TLS layer compare).
pub fn fingerprint(certificate: &[u8]) -> [u8; 32] {
    Sha256::digest(certificate).into()
}

fn field(s: &str) -> Result<(), StoreError> {
    if s.is_empty() || s.len() > MAX_STR { Err(StoreError::BadField) } else { Ok(()) }
}
