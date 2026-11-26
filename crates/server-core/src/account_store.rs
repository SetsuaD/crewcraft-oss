//! The authentication store that survives a restart (issue #35): people (password verifier, sealed TOTP secret, last
//! accepted TOTP counter), their enrolled devices (`devices`, T127), pending invitations (`invites`, T103) and sign-in
//! sessions (`crewcraft_accounts::sessions`, by token hash only), kept in their own strict journal file
//! (`account_journal`) of `account_op` records, separate from the room journal (`durable`).
//!
//! Owns: the single-writer rule (`&mut self` for every change), the order validate -> append -> apply (nothing reaches
//! memory, and no success is returned, unless its record is on disk), one record per activation (the invitation is
//! consumed, the person created or extended, the device registered with its exact leaf and SPKI, and the counter
//! saved, together or not at all), a strictly increasing TOTP counter, canonical account identity (an email must
//! already be in `crewcraft_accounts::identity::normalize_email` form, so one mailbox is one person with one counter),
//! and exact replay: a store written under another service key, a sealed secret that fails authentication, or a record
//! that does not apply refuses the whole open (fail closed; no partially initialised store is ever returned).
//! Writer health: an append whose outcome on disk is unknown poisons the store until it is reopened; a poisoned store
//! refuses every write, every device admission and every session check.
//! Task T611b adds, for sign-in through an external OpenID Connect provider (SECURITY-DESIGN.md section 9), each
//! person's binding to one provider `(issuer, subject)` (unique across people) and their authorization record from an
//! external authorizer (`crewcraft_authz::Record`), which the store keeps for the authorizer rules as their `Ledger`.
//! Does not own: verifying a TOTP code or a password (the caller does that and passes the accepted counter), or how the
//! certificate reaches the client.
//! Called by: the server's enrollment, sign-in and connection paths.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;

use crewcraft_accounts::identity::normalize_email;
use crewcraft_accounts::sessions::{Session, Sessions, token_for, token_hash};
use crewcraft_proto::message::CodecError;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::account_journal::{AccountJournal, AppendError, OpenError};
use crate::account_op::{AccountOp, FORMAT, MAX_CERT, MAX_STR, NewPerson, decode_account_op, encode_account_op};
use crate::devices::{Device, DeviceError, Devices};
use crate::invites::{Invite, InviteBook, InviteError};
use crate::seal::{SealError, Sealed, ServiceKey};

/// Where records go. `AccountJournal` in production; tests wrap it to force write failures.
pub trait AppendLog {
    /// Append one record durably. `NotWritten` promises the file is exactly as before the call.
    fn append(&mut self, record: &[u8]) -> Result<(), AppendError>;
}

impl AppendLog for AccountJournal {
    fn append(&mut self, record: &[u8]) -> Result<(), AppendError> {
        AccountJournal::append(self, record)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Open(OpenError),
    Append(AppendError),
    Codec(CodecError),
    /// `open` found no store, or an empty file: a store is made only by `create`.
    NotInitialized,
    /// The store was written under a different service key, or a sealed secret names another key.
    WrongKey,
    /// Record `record` (0-based) does not decode or does not apply to the state before it.
    Corrupt {
        record: usize,
        cause: Box<StoreError>,
    },
    /// An earlier write's outcome is unknown; nothing is written or admitted until the store is reopened.
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
    /// The email is not in canonical form (`normalize_email(email) == email`).
    NotCanonical,
    /// The device key (its SubjectPublicKeyInfo) is already registered, live or revoked: a revoked key never returns.
    KeyInUse,
    /// The device id the caller expected (from `preview_activation`, already written into the certificate) is no
    /// longer the one the commit would assign.
    DeviceIdMoved {
        expected: u64,
        next: u64,
    },
    /// The presented leaf is not the device's exact active certificate.
    NotActiveLeaf,
    /// A session with this token hash already exists, or none does (for a revocation).
    Session,
    /// This provider identity is already bound to another person (T611b).
    ExternalInUse,
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

impl From<OpenError> for StoreError {
    fn from(e: OpenError) -> Self {
        StoreError::Open(e)
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
    /// The device id written into the certificate (from `preview_activation`). Checked again inside the commit, so
    /// the certificate's claims and the durable id cannot disagree. `None` skips the check.
    pub expected_device_id: Option<u64>,
}

struct Person {
    password_phc: Option<String>,
    totp: Sealed,
    last_counter: u64,
}

/// What a caller may read about a person. Its `Debug` never prints the password verifier.
#[derive(Clone, PartialEq, Eq)]
pub struct PersonInfo {
    pub email: String,
    /// The PHC string with the `own` password source (for `crewcraft_accounts::password::verify`).
    pub password_phc: Option<String>,
    pub last_totp_counter: u64,
}

impl fmt::Debug for PersonInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersonInfo")
            .field("email", &self.email)
            .field("own_password", &self.password_phc.is_some())
            .field("last_totp_counter", &self.last_totp_counter)
            .finish()
    }
}

pub struct AccountStore<L: AppendLog = AccountJournal> {
    log: L,
    key: ServiceKey,
    people: BTreeMap<String, Person>,
    invites: InviteBook,
    devices: Devices,
    /// Device id by SPKI SHA-256, every device ever registered (revoked ones too).
    keys: BTreeMap<[u8; 32], u64>,
    /// The issued leaf certificate by device id.
    certificates: BTreeMap<u64, Vec<u8>>,
    sessions: Sessions,
    /// The person each external `(issuer, subject)` signs in as, and the reverse (T611b).
    external: BTreeMap<(String, String), String>,
    bound: BTreeMap<String, (String, String)>,
    /// Each person's authorization record from an external authorizer (T611b).
    authorization: BTreeMap<String, crewcraft_authz::Record>,
    poisoned: bool,
}

impl<L: AppendLog> fmt::Debug for AccountStore<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountStore")
            .field("people", &self.people.len())
            .field("invites", &self.invites.len())
            .field("sessions", &self.sessions.len())
            .field("poisoned", &self.poisoned)
            .field("key", &self.key)
            .finish()
    }
}

impl AccountStore<AccountJournal> {
    /// Make a NEW store at `path` (setup only): the file must not exist; its first record pins the service key.
    pub fn create(path: &Path, key: ServiceKey) -> Result<Self, StoreError> {
        let journal = AccountJournal::create(path)?;
        let mut store = Self::empty(journal, key);
        let created = AccountOp::Created { format: FORMAT, key_id: store.key.id() };
        store.log.append(&encode_account_op(&created).map_err(StoreError::Codec)?).map_err(StoreError::Append)?;
        Ok(store)
    }

    /// Open an existing store. A missing or empty file is `NotInitialized` (ordinary start never creates one). Nothing on
    /// disk changes unless the key matches and every record replays; then an incomplete final frame is cut off.
    pub fn open(path: &Path, key: ServiceKey) -> Result<Self, StoreError> {
        let (journal, records) = match AccountJournal::open(path) {
            Err(OpenError::Missing) => return Err(StoreError::NotInitialized),
            other => other?,
        };
        let mut store = Self::from_records(journal, key, records)?;
        store.log.recover_tail()?;
        Ok(store)
    }
}

impl<L: AppendLog> AccountStore<L> {
    fn empty(log: L, key: ServiceKey) -> Self {
        AccountStore {
            log,
            key,
            people: BTreeMap::new(),
            invites: InviteBook::new(),
            devices: Devices::new(),
            keys: BTreeMap::new(),
            certificates: BTreeMap::new(),
            sessions: Sessions::new(),
            external: BTreeMap::new(),
            bound: BTreeMap::new(),
            authorization: BTreeMap::new(),
            poisoned: false,
        }
    }

    /// Replay `records` (as the journal returned them). The first must be the `Created` record for this key.
    pub fn from_records(log: L, key: ServiceKey, records: Vec<Vec<u8>>) -> Result<Self, StoreError> {
        if records.is_empty() {
            return Err(StoreError::NotInitialized);
        }
        let mut store = Self::empty(log, key);
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

    /// False once a write's outcome on disk became unknown. Device admission and every established frame check this.
    pub fn healthy(&self) -> bool {
        !self.poisoned
    }

    /// Validate, append, apply. The caller gets `Ok` only once the record is durable and applied.
    fn commit(&mut self, op: AccountOp) -> Result<(), StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        self.check(&op)?;
        let bytes = encode_account_op(&op).map_err(StoreError::Codec)?;
        if let Err(e) = self.log.append(&bytes) {
            if matches!(e, AppendError::Ambiguous(_)) {
                self.poisoned = true;
            }
            return Err(StoreError::Append(e));
        }
        if self.apply(&op).is_err() {
            self.poisoned = true;
            return Err(StoreError::Poisoned);
        }
        Ok(())
    }

    /// Whether `op` applies to the current state. Used both before journaling a change and while replaying one.
    fn check(&self, op: &AccountOp) -> Result<(), StoreError> {
        match op {
            AccountOp::ExternalBound { email, issuer, subject } => {
                canonical(email)?;
                field(issuer)?;
                field(subject)?;
                if !self.people.contains_key(email) {
                    return Err(StoreError::NoSuchPerson);
                }
                match self.external.get(&(issuer.clone(), subject.clone())) {
                    Some(owner) if owner != email => Err(StoreError::ExternalInUse),
                    _ => Ok(()),
                }
            }
            AccountOp::AuthorizationRecorded { email, .. } => {
                canonical(email)?;
                if self.people.contains_key(email) { Ok(()) } else { Err(StoreError::NoSuchPerson) }
            }
            AccountOp::Created { .. } => Err(StoreError::Codec(CodecError::BadKind(1))),
            AccountOp::InviteIssued { email, bootstrap_pub, expires_ms, now_ms } => {
                canonical(email)?;
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
                canonical(email)?;
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
            AccountOp::DeviceRevoked { email, device_id } => self.live_device(email, *device_id).map(|_| ()),
            AccountOp::SessionCreated { token_sha256, email, device_id, .. } => {
                if !self.people.contains_key(email) {
                    return Err(StoreError::NoSuchPerson);
                }
                self.live_device(email, *device_id)?;
                if self.sessions.contains_hash(token_sha256) {
                    return Err(StoreError::Session);
                }
                Ok(())
            }
            AccountOp::SignedIn { email, device_id, counter, token_sha256, .. } => {
                let person = self.people.get(email).ok_or(StoreError::NoSuchPerson)?;
                if *counter <= person.last_counter {
                    return Err(StoreError::StaleCounter { last: person.last_counter });
                }
                self.live_device(email, *device_id)?;
                if self.sessions.contains_hash(token_sha256) {
                    return Err(StoreError::Session);
                }
                Ok(())
            }
            AccountOp::SessionRevoked { token_sha256 } => {
                if self.sessions.contains_hash(token_sha256) {
                    Ok(())
                } else {
                    Err(StoreError::Session)
                }
            }
        }
    }

    /// Apply a checked op. An error here after `check` passed is a bug (the caller poisons the store).
    fn apply(&mut self, op: &AccountOp) -> Result<(), StoreError> {
        match op {
            AccountOp::ExternalBound { email, issuer, subject } => {
                if let Some(old) = self.bound.remove(email) {
                    self.external.remove(&old);
                }
                self.external.insert((issuer.clone(), subject.clone()), email.clone());
                self.bound.insert(email.clone(), (issuer.clone(), subject.clone()));
                Ok(())
            }
            AccountOp::AuthorizationRecorded { email, record } => {
                self.authorization.insert(email.clone(), record.clone());
                Ok(())
            }
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
            AccountOp::DeviceRevoked { email, device_id } => {
                self.devices.revoke(email, *device_id).map_err(StoreError::Device)?;
                // The device's sessions end with it, in the same record.
                self.sessions.revoke_device(email, &device_id.to_string());
                Ok(())
            }
            AccountOp::SessionCreated { token_sha256, email, device_id, created_ms } => {
                let session = Session { user: email.clone(), device: device_id.to_string(), created_ms: *created_ms, last_seen_ms: *created_ms };
                self.sessions.restore(*token_sha256, session);
                Ok(())
            }
            AccountOp::SessionRevoked { token_sha256 } => {
                self.sessions.revoke_hash(token_sha256);
                Ok(())
            }
            AccountOp::SignedIn { email, device_id, counter, token_sha256, created_ms } => {
                self.people.get_mut(email).ok_or(StoreError::NoSuchPerson)?.last_counter = *counter;
                let session = Session { user: email.clone(), device: device_id.to_string(), created_ms: *created_ms, last_seen_ms: *created_ms };
                self.sessions.restore(*token_sha256, session);
                Ok(())
            }
        }
    }

    fn live_device(&self, email: &str, device_id: u64) -> Result<Device, StoreError> {
        match self.devices.list(email).into_iter().find(|d| d.id == device_id) {
            Some(device) if !device.revoked => Ok(device),
            Some(_) => Err(StoreError::Device(DeviceError::Revoked)),
            None => Err(StoreError::Device(DeviceError::NoSuchDevice)),
        }
    }

    /// Record an invitation (only its bootstrap public key; `crewcraft_enroll` derives it from the code). The email must
    /// already be canonical.
    pub fn issue_invite(&mut self, invite: Invite, now_ms: u64) -> Result<(), StoreError> {
        self.commit(AccountOp::InviteIssued { email: invite.email, bootstrap_pub: invite.bootstrap_pub, expires_ms: invite.expires_ms, now_ms })
    }

    /// Withdraw an invitation; `Ok(false)` (and nothing written) when there is none.
    pub fn revoke_invite(&mut self, bootstrap_pub: &[u8; 32]) -> Result<bool, StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        if self.invites.pending(bootstrap_pub, 0).is_none() {
            return Ok(false);
        }
        self.commit(AccountOp::InviteRevoked { bootstrap_pub: *bootstrap_pub }).map(|()| true)
    }

    /// Whether a live invitation has this bootstrap key (the bootstrap TLS verifier asks this). False when poisoned.
    pub fn is_invite_pending(&self, bootstrap_pub: &[u8; 32], now_ms: u64) -> bool {
        !self.poisoned && self.invites.is_pending(bootstrap_pub, now_ms)
    }

    /// Commit an activation as ONE record and return the new device id. The person is the invitation's email: the
    /// client cannot choose it. Only after `Ok` may the server answer the client with success (or its certificate).
    pub fn activate(&mut self, activation: Activation<'_>, now_ms: u64) -> Result<u64, StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
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
        if let Some(expected) = activation.expected_device_id
            && expected != device_id
        {
            return Err(StoreError::DeviceIdMoved { expected, next: device_id });
        }
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

    /// Revoke one of `email`'s devices and every session on it, in one record; `Ok(false)` (and nothing written) when
    /// it was already revoked. A revoked device stays revoked, and its key and certificate banned, after a restart.
    pub fn revoke_device(&mut self, email: &str, device_id: u64) -> Result<bool, StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        match self.devices.list(email).iter().find(|d| d.id == device_id) {
            Some(device) if device.revoked => Ok(false),
            _ => self.commit(AccountOp::DeviceRevoked { email: email.to_string(), device_id }).map(|()| true),
        }
    }

    /// What an activation of this invitation would assign: the canonical email from the STORED invitation and the next
    /// device id. Issue the certificate with exactly these claims, then pass the id as `expected_device_id`.
    pub fn preview_activation(&self, bootstrap_pub: &[u8; 32], now_ms: u64) -> Result<(String, u64), StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        let email = self.invites.pending(bootstrap_pub, now_ms).ok_or(StoreError::NoInvite)?.email.clone();
        Ok((email, self.devices.next_id()))
    }

    /// A normal sign-in, after the password and code verified: saves the code's counter AND starts the session in ONE
    /// record, and returns the token. The counter must be newer than the last accepted one, which after activation is
    /// the setup code's, so the first sign-in needs a fresh time step. Only the token's SHA-256 is journaled.
    pub fn sign_in(&mut self, random: [u8; 32], email: &str, device_id: u64, counter: u64, now_ms: u64) -> Result<String, StoreError> {
        let token = token_for(random);
        self.commit(AccountOp::SignedIn { email: email.to_string(), device_id, counter, token_sha256: token_hash(&token), created_ms: now_ms })?;
        Ok(token)
    }

    /// Start a session for `email` on its live device `device_id` from 32 bytes the caller drew from the OS RNG; returns
    /// the token for the client. Only the token's SHA-256 is journaled and kept. Call after `accept_totp`.
    pub fn create_session(&mut self, random: [u8; 32], email: &str, device_id: u64, now_ms: u64) -> Result<String, StoreError> {
        let token = token_for(random);
        self.commit(AccountOp::SessionCreated { token_sha256: token_hash(&token), email: email.to_string(), device_id, created_ms: now_ms })?;
        Ok(token)
    }

    /// Continue a session by its bearer token on a connection whose verified client certificate has `fingerprint`: the
    /// device must be live and the session must belong to that same device and canonical account (T148). `None` when
    /// poisoned, when the device is revoked or unknown, or when the session is unknown, expired or someone else's.
    /// Restored sessions count their idle time from creation, so a restart ends sessions idle since then.
    pub fn continue_session(&mut self, token: &str, fingerprint: &[u8; 32], now_ms: u64) -> Option<Session> {
        let device = self.authenticate(fingerprint, now_ms).ok()?;
        self.sessions.validate_hash_for(&token_hash(token), &device.user, &device.id.to_string(), now_ms)
    }

    /// Continue a session by the SHA-256 of its token, for a stream that dropped the bearer secret after sign-in and
    /// kept only the digest and the captured leaf. `None` when poisoned, when the leaf is not a live device's exact
    /// active certificate (revoked, unknown or replaced), or when the session is unknown, expired, or belongs to another
    /// person or device (T148). Each success refreshes the session's idle clock (in memory only; restored sessions count
    /// idle time from creation). The leaf's own validity dates are NOT checked here: the TLS verifier checks them at
    /// the handshake, and a long-lived stream must re-check expiry itself.
    pub fn continue_session_by_hash(&mut self, token_sha256: &[u8; 32], leaf_der: &[u8], now_ms: u64) -> Option<Session> {
        let device = self.admit(leaf_der, now_ms).ok()?;
        self.sessions.validate_hash_for(token_sha256, &device.user, &device.id.to_string(), now_ms)
    }

    /// Resume a session by the SHA-256 of its token on a new connection (task T240): the leaf must be the live device's
    /// exact active certificate and the session that device's, as in `continue_session_by_hash`, and the session lives
    /// for `ABSOLUTE_MS` from its creation however long it was idle. `None` otherwise, or when poisoned.
    pub fn resume_session_by_hash(&mut self, token_sha256: &[u8; 32], leaf_der: &[u8], now_ms: u64) -> Option<Session> {
        let device = self.admit(leaf_der, now_ms).ok()?;
        self.sessions.resume_hash_for(token_sha256, &device.user, &device.id.to_string(), now_ms)
    }

    /// End a session by the SHA-256 of its token, asked over the connection of the device it belongs to (task T240).
    /// `Ok(false)` (and nothing written) when the leaf is not a live device, or the session is unknown or another
    /// device's.
    pub fn end_session_by_hash(&mut self, token_sha256: &[u8; 32], leaf_der: &[u8], now_ms: u64) -> Result<bool, StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        let Ok(device) = self.admit(leaf_der, now_ms) else {
            return Ok(false);
        };
        if !self.sessions.owned_by(token_sha256, &device.user, &device.id.to_string()) {
            return Ok(false);
        }
        self.commit(AccountOp::SessionRevoked { token_sha256: *token_sha256 }).map(|()| true)
    }

    /// End one session; `Ok(false)` (and nothing written) when the token is unknown.
    pub fn revoke_session(&mut self, token: &str) -> Result<bool, StoreError> {
        let hash = token_hash(token);
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        if !self.sessions.contains_hash(&hash) {
            return Ok(false);
        }
        self.commit(AccountOp::SessionRevoked { token_sha256: hash }).map(|()| true)
    }

    /// The hex SHA-256 of every session token held (lets a test prove no raw token is kept).
    pub fn session_hashes(&self) -> Vec<String> {
        self.sessions.stored_keys()
    }

    /// Bind `email`'s person to an external provider's `(issuer, subject)` (T611b): from then on, an ID token for that
    /// subject signs in as this person. Re-binding replaces the earlier binding; a subject bound to another person is
    /// `ExternalInUse`.
    pub fn bind_external(&mut self, email: &str, issuer: &str, subject: &str) -> Result<(), StoreError> {
        self.commit(AccountOp::ExternalBound { email: email.to_string(), issuer: issuer.to_string(), subject: subject.to_string() })
    }

    /// The person an external `(issuer, subject)` is bound to.
    pub fn person_for_external(&self, issuer: &str, subject: &str) -> Option<&str> {
        self.external.get(&(issuer.to_string(), subject.to_string())).map(String::as_str)
    }

    /// The external `(issuer, subject)` a person is bound to.
    pub fn external_of(&self, email: &str) -> Option<(&str, &str)> {
        self.bound.get(email).map(|(issuer, subject)| (issuer.as_str(), subject.as_str()))
    }

    /// The person's last stored authorization record (T611b).
    pub fn authorization(&self, email: &str) -> Option<&crewcraft_authz::Record> {
        self.authorization.get(email)
    }

    pub fn person(&self, email: &str) -> Option<PersonInfo> {
        if self.poisoned {
            return None;
        }
        self.people.get(email).map(|p| PersonInfo {
            email: email.to_string(),
            password_phc: p.password_phc.clone(),
            last_totp_counter: p.last_counter,
        })
    }

    /// The person's TOTP secret, opened with the service key, for verifying a code.
    pub fn totp_secret(&self, email: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        let person = self.people.get(email).ok_or(StoreError::NoSuchPerson)?;
        self.key.open(&person.totp, email.as_bytes()).map_err(StoreError::Seal)
    }

    /// Device admission by the presented leaf: the device must be live and `leaf_der` byte-equal to its stored active
    /// certificate. Use this on every admission; `device.user` is the canonical person (for throttling and session
    /// frames).
    pub fn admit(&mut self, leaf_der: &[u8], now_ms: u64) -> Result<Device, StoreError> {
        let device = self.authenticate(&fingerprint(leaf_der), now_ms)?;
        match self.certificates.get(&device.id) {
            Some(active) if active.as_slice() == leaf_der => Ok(device),
            _ => Err(StoreError::NotActiveLeaf),
        }
    }

    /// Device admission: the live device for a certificate fingerprint (its last-seen time is kept in memory only).
    pub fn authenticate(&mut self, fingerprint: &[u8; 32], now_ms: u64) -> Result<Device, StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        self.devices.authenticate(fingerprint, now_ms).map_err(StoreError::Device)
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

/// The store's account identity: exactly the `normalize_email` form, never a variant of it.
fn canonical(email: &str) -> Result<(), StoreError> {
    field(email)?;
    match normalize_email(email) {
        Ok(normal) if normal == email => Ok(()),
        _ => Err(StoreError::NotCanonical),
    }
}

/// The account store keeps authorization records for the authorizer rules (`crewcraft_authz`, T611b). `commit` returns
/// only once the record is on disk and applied (the store's validate, append, apply order); `read_back` reads the
/// applied state, and refuses while the store is poisoned, so `commit_decision` grants nothing after an unknown write.
impl<L: AppendLog> crewcraft_authz::Ledger for AccountStore<L> {
    type Error = StoreError;

    fn commit(&mut self, identity: &str, record: &crewcraft_authz::Record) -> Result<(), StoreError> {
        AccountStore::commit(self, AccountOp::AuthorizationRecorded { email: identity.to_string(), record: record.clone() })
    }

    fn read_back(&self, identity: &str) -> Result<Option<crewcraft_authz::Record>, StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        Ok(self.authorization.get(identity).cloned())
    }
}
