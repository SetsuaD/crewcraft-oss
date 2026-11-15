//! The server side of the bootstrap connection (docs/SECURITY-DESIGN.md section 3): the two calls a device holding a live
//! invitation may make, `Redeem` and `ConfirmTotp`, and nothing else.
//!
//! Owns: the per-connection state machine that turns the two requests into a staged device, the first TOTP check and one
//! durable activation, and the order in which things happen. Holds no sockets, no TLS and no storage format: bytes come in
//! through `BootstrapConnection::receive`, every decision about who may enroll comes from `Services` (in production the
//! durable `AccountStore`, `StoreServices`), and certificates come from `crewcraft-pki`. Called by: the listener, for a peer
//! admitted as `crewcraft_admission::Class::Bootstrap`.
//!
//! The order is the point:
//! 1. `Redeem` re-checks that the invitation is live, takes the cheap checks, then `Staging::begin` (the per-source and
//!    server-wide limits) and only then the Argon2 password hash. The hash can run with no lock held: `receive_step` stops
//!    at `NeedsHash` and `finish_hash` resumes (`receive_shared` is that loop for a shared enroller). It answers `Setup` with the authenticator URI and
//!    NOTHING ELSE: no certificate exists yet.
//! 2. `ConfirmTotp` must arrive on the same connection and the same staged attempt. The invitation is re-checked against
//!    the store immediately before it is used. After the code is accepted, the leaf is built with the device id the store
//!    will allocate, and ONE `Services::activate` commits invitation, person, password, device, exact leaf, key identity
//!    and the first TOTP counter together. Only when it returns `Ok` is the leaf sent as `Activated`.
//! 3. Recovery policy. A refusal found before anything was written (invitation gone, key reused, person exists, ...) is an
//!    error reply and a closed connection with nothing durable changed. A device id that moved is retried once with the
//!    new id. Any ambiguous failure poisons the `Enroller`: the activation may be durable with a leaf nobody received, the
//!    invitation is then consumed and the key identity is registered for good, so the recovery is an administrator
//!    revoking that device and issuing a new invitation, and the person generating a NEW device key. A retry on a new
//!    connection cannot succeed (the bootstrap key is no longer live).
//!
//! The setup code that activated the device counts as spent: its counter is the account's last accepted counter, so the
//! first normal sign-in needs a code from a later time step.
//!
//! Any other message, an out-of-order one, a malformed frame, or a peer whose invitation is no longer live is closed
//! without a reply. Sign-in and chat requests cannot even be decoded here (the tags are disjoint).

mod admission;
mod staging;
mod store;

pub use admission::DurableAdmission;
pub use store::{Environment, StoreServices, SystemEnvironment, classify};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crewcraft_accounts::password;
use crewcraft_pki::{Authority, Claims, csr_key_id};
use crewcraft_proto::bootstrap::{BootstrapRequest, BootstrapResponse, decode_bootstrap_request, encode_bootstrap_response};
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_server_core::devices::MAX_NAME_CHARS;
use rand_core::{OsRng, RngCore};

use staging::{Candidate, StageError, Staging};

/// A malformed or unacceptable request (device name, signing request). The connection is closed after it.
pub const ERR_BAD_REQUEST: u16 = 1;
/// The password does not meet the policy. The connection stays open for another `Redeem`.
pub const ERR_PASSWORD: u16 = 2;
/// A source or server-wide limit. The connection is closed after it.
pub const ERR_RATE_LIMITED: u16 = 3;
/// The first TOTP code was wrong. The connection stays open for another code, up to `activation::MAX_WRONG_CODES`.
pub const ERR_BAD_CODE: u16 = 4;
/// Anything the server could not complete (including a refused or failed durable commit). The connection is closed after it.
pub const ERR_UNAVAILABLE: u16 = 5;

/// Everything that becomes durable together before the device is given its certificate.
#[derive(Clone)]
pub struct ActivationRecord {
    /// The account: the invitation's canonical email.
    pub email: String,
    /// The account password, as an Argon2id PHC string. Never the password.
    pub password_phc: String,
    /// The device id the certificate carries (`OU=device-<id>`), which the store must allocate.
    pub device_id: u64,
    /// The device's identity: SHA-256 of its public key's SubjectPublicKeyInfo, stable across renewals.
    pub key_id: [u8; 32],
    pub device_name: String,
    /// The exact chain that will be sent: the leaf, then the issuing authority.
    pub chain: Vec<Vec<u8>>,
    /// The leaf's serial, the handle for revocation. Separate from the ordinal and from the key identity.
    pub serial: Vec<u8>,
    /// When the leaf expires, Unix seconds.
    pub not_after: i64,
    /// The TOTP secret, to be sealed by the store.
    pub totp_secret: [u8; 20],
    /// The counter of the code that just proved the authenticator: the first accepted counter, now spent.
    pub accepted_counter: u64,
    /// The bootstrap key whose invitation this consumes.
    pub bootstrap_pub: [u8; 32],
}

impl std::fmt::Debug for ActivationRecord {
    // Neither the password hash nor the TOTP secret is ever printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivationRecord")
            .field("email", &self.email)
            .field("device_id", &self.device_id)
            .field("device_name", &self.device_name)
            .finish_non_exhaustive()
    }
}

/// What a live invitation will create: the person it names and the device id the next activation takes. The leaf is issued
/// with exactly these claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preview {
    pub email: String,
    pub next_device_id: u64,
}

/// Why `Services::activate` did not succeed. See `store` for how a store error maps onto these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitFailure {
    /// The journal promises nothing was written and the file is as before: the same request may be sent again.
    NotWritten,
    /// Refused before anything was written; retrying the same request cannot help.
    Refused,
    /// Nothing was written because the device id moved since the certificate was built; rebuild and commit again.
    OrdinalMoved,
    /// It cannot be known whether the record is durable.
    Ambiguous,
}

/// What the handler needs from the server around it. `StoreServices` implements it over the durable store.
pub trait Services {
    fn now_ms(&self) -> u64;

    /// A fresh 20-byte TOTP secret from the system random source, or `None` if it failed (`random_totp_secret`).
    fn new_totp_secret(&mut self) -> Option<[u8; 20]>;

    /// Hash the account password (Argon2id PHC). Called only after the request passed the rate limits.
    fn hash_password(&mut self, password: &str) -> Option<String> {
        password::hash(password).ok()
    }

    /// The live invitation with this bootstrap key, as the store holds it (`None`: unknown, expired, consumed, revoked,
    /// or the store is poisoned).
    fn preview(&self, bootstrap_pub: &[u8; 32], now_ms: u64) -> Option<Preview>;

    /// Whether this person already has an account. Only a first device is enrolled through this path.
    fn has_person(&self, email: &str) -> bool;

    /// Whether a device was ever registered under this key identity, live or revoked. Such a key never enrolls again.
    fn key_registered(&self, key_id: &[u8; 32]) -> bool;

    /// Commit the whole record as one durable unit and return the allocated device id. `Ok` only when it is durable; the
    /// id must equal `record.device_id` (checked before anything is written).
    fn activate(&mut self, record: &ActivationRecord, now_ms: u64) -> Result<u64, CommitFailure>;
}

/// A fresh TOTP secret from the operating system's random source.
pub fn random_totp_secret() -> Option<[u8; 20]> {
    let mut secret = [0u8; 20];
    OsRng.try_fill_bytes(&mut secret).ok()?;
    Some(secret)
}

/// The shared server state the bootstrap connections act on.
pub struct Enroller<S: Services> {
    staging: Staging,
    authority: Authority,
    services: S,
    poisoned: Arc<AtomicBool>,
}

impl<S: Services> std::fmt::Debug for Enroller<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Enroller(.., poisoned: {})", self.is_poisoned())
    }
}

impl<S: Services> Enroller<S> {
    pub fn new(authority: Authority, services: S) -> Self {
        Self { staging: Staging::new(), authority, services, poisoned: Arc::new(AtomicBool::new(false)) }
    }

    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    pub fn services(&self) -> &S {
        &self.services
    }

    pub fn services_mut(&mut self) -> &mut S {
        &mut self.services
    }

    /// Take the enroller apart, for a restart that reopens the durable state and keeps the authority.
    pub fn into_parts(self) -> (Authority, S) {
        (self.authority, self.services)
    }

    /// How many setups are staged (an unfinished enrollment is held only in memory).
    pub fn staged_count(&self) -> usize {
        self.staging.pending_count()
    }

    /// A commit failed ambiguously: whether an activation is durable is unknown, so every bootstrap connection is closed
    /// until the `Enroller` is rebuilt from the store.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.load(Ordering::SeqCst)
    }

    /// The poison flag, shared with `DurableAdmission` so that admission never has to take the Enroller lock.
    pub fn poison_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.poisoned)
    }

    fn poison(&self) {
        self.poisoned.store(true, Ordering::SeqCst);
    }
}

/// What `receive` produced.
#[derive(Debug, PartialEq, Eq)]
pub struct Output {
    /// Whole frames to write to the peer, possibly none.
    pub bytes: Vec<u8>,
    /// `false`: write `bytes` (if any) and close the connection.
    pub open: bool,
}

struct Staged {
    attempt: u64,
    csr: Vec<u8>,
    password_phc: String,
}

/// A Redeem that passed the limits and is waiting for the password hash, which the caller computes with no lock held.
struct Awaiting {
    attempt: u64,
    csr: Vec<u8>,
    request_id: u32,
    totp_uri: String,
}

enum State {
    Start,
    AwaitingHash(Box<Awaiting>),
    Staged(Box<Staged>),
    Done,
}

enum Step {
    NeedsHash(String),
    Reply(Vec<u8>),
    ReplyAndClose(Vec<u8>),
    Close,
}

fn frame(id: u32, response: BootstrapResponse) -> Option<Vec<u8>> {
    encode_bootstrap_response(id, &response).ok().and_then(|payload| encode(&payload).ok())
}

fn error_open(id: u32, code: u16) -> Step {
    frame(id, BootstrapResponse::Error { code }).map_or(Step::Close, Step::Reply)
}

fn error_close(id: u32, code: u16) -> Step {
    frame(id, BootstrapResponse::Error { code }).map_or(Step::Close, Step::ReplyAndClose)
}

/// The password to hash. Compute the Argon2id PHC string WITHOUT holding any lock, then give it to `finish_hash`.
pub struct HashJob {
    password: String,
}

impl HashJob {
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl std::fmt::Debug for HashJob {
    // The password is never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HashJob(..)")
    }
}

/// Where `receive_step` and `finish_hash` stopped.
#[derive(Debug)]
pub enum Progress {
    /// Everything buffered so far is handled.
    Done(Output),
    /// A Redeem passed its limits and is staged; `bytes` are the replies produced before it. Hash `job` (no lock held) and
    /// call `finish_hash`. Frames that arrived after the Redeem wait until then.
    NeedsHash { bytes: Vec<u8>, job: HashJob },
}

/// The pattern for a listener: lock the shared enroller only for each short step, and hash the password with NO lock held.
/// `hasher` turns a password into an Argon2id PHC string (`None` on failure). Socket I/O stays outside, as before.
pub fn receive_shared<S: Services>(
    conn: &mut BootstrapConnection,
    enroller: &Mutex<Enroller<S>>,
    hasher: &dyn Fn(&str) -> Option<String>,
    input: &[u8],
) -> Output {
    let mut bytes = Vec::new();
    let Ok(mut guard) = enroller.lock() else {
        conn.closed = true;
        return Output { bytes, open: false };
    };
    let mut progress = conn.receive_step(&mut guard, input);
    drop(guard);
    loop {
        match progress {
            Progress::Done(out) => {
                bytes.extend(out.bytes);
                return Output { bytes, open: out.open };
            }
            Progress::NeedsHash { bytes: before, job } => {
                bytes.extend(before);
                let phc = hasher(job.password());
                let Ok(mut guard) = enroller.lock() else {
                    conn.closed = true;
                    return Output { bytes, open: false };
                };
                progress = conn.finish_hash(&mut guard, job, phc);
            }
        }
    }
}

/// One bootstrap connection, from its first admitted byte.
pub struct BootstrapConnection {
    /// The bootstrap key the peer was admitted with.
    key: [u8; 32],
    /// The peer's address, for the per-source limit.
    source: String,
    decoder: Decoder,
    state: State,
    closed: bool,
}

impl std::fmt::Debug for BootstrapConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BootstrapConnection(closed: {})", self.closed)
    }
}

impl BootstrapConnection {
    /// A connection for the peer admitted as `Class::Bootstrap(bootstrap_pub)` from `source`.
    pub fn new(bootstrap_pub: [u8; 32], source: &str) -> Self {
        Self { key: bootstrap_pub, source: source.to_string(), decoder: Decoder::new(), state: State::Start, closed: false }
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Take bytes from the peer and return what to send back. After `open: false` write the bytes and drop the
    /// connection; later calls return nothing. This hashes the password with `Services::hash_password` while the caller
    /// holds the `Enroller`; a listener that shares the enroller between connections should use `receive_shared`.
    pub fn receive<S: Services>(&mut self, enroller: &mut Enroller<S>, input: &[u8]) -> Output {
        let mut bytes = Vec::new();
        let mut progress = self.receive_step(enroller, input);
        loop {
            match progress {
                Progress::Done(out) => {
                    bytes.extend(out.bytes);
                    return Output { bytes, open: out.open };
                }
                Progress::NeedsHash { bytes: before, job } => {
                    bytes.extend(before);
                    let phc = enroller.services.hash_password(job.password());
                    progress = self.finish_hash(enroller, job, phc);
                }
            }
        }
    }

    /// Like `receive`, but stops at the password hash instead of computing it, so the caller can release the lock first.
    /// The limits and the staging have already happened when it stops: a rate-limited Redeem never asks for a hash.
    pub fn receive_step<S: Services>(&mut self, enroller: &mut Enroller<S>, input: &[u8]) -> Progress {
        if self.closed || enroller.is_poisoned() {
            self.closed = true;
            return Progress::Done(Output { bytes: Vec::new(), open: false });
        }
        self.decoder.push(input);
        self.drive(enroller, Vec::new())
    }

    /// Resume after `NeedsHash` with the PHC string for the job's password (`None` if hashing failed). Re-checks the
    /// enroller (it may have been poisoned while the lock was released), answers the pending Redeem with Setup, and goes on
    /// with any frames that arrived meanwhile.
    pub fn finish_hash<S: Services>(&mut self, enroller: &mut Enroller<S>, job: HashJob, phc: Option<String>) -> Progress {
        drop(job);
        let State::AwaitingHash(awaiting) = std::mem::replace(&mut self.state, State::Done) else {
            self.closed = true;
            return Progress::Done(Output { bytes: Vec::new(), open: false });
        };
        if self.closed || enroller.is_poisoned() {
            self.closed = true;
            return Progress::Done(Output { bytes: Vec::new(), open: false });
        }
        let Some(password_phc) = phc else {
            self.closed = true;
            let bytes = frame(awaiting.request_id, BootstrapResponse::Error { code: ERR_UNAVAILABLE }).unwrap_or_default();
            return Progress::Done(Output { bytes, open: false });
        };
        let Awaiting { attempt, csr, request_id, totp_uri } = *awaiting;
        let Some(reply) = frame(request_id, BootstrapResponse::Setup { totp_uri }) else {
            self.closed = true;
            return Progress::Done(Output { bytes: Vec::new(), open: false });
        };
        self.state = State::Staged(Box::new(Staged { attempt, csr, password_phc }));
        self.drive(enroller, reply)
    }

    fn drive<S: Services>(&mut self, enroller: &mut Enroller<S>, mut bytes: Vec<u8>) -> Progress {
        if matches!(self.state, State::AwaitingHash(_)) {
            // Frames wait until the hash is supplied.
            return Progress::Done(Output { bytes, open: !self.closed });
        }
        loop {
            let payload = match self.decoder.next_frame() {
                Ok(Some(payload)) => payload,
                Ok(None) => break,
                Err(_) => {
                    self.closed = true;
                    break;
                }
            };
            match self.handle(enroller, &payload) {
                Step::Reply(reply) => bytes.extend(reply),
                Step::ReplyAndClose(reply) => {
                    bytes.extend(reply);
                    self.closed = true;
                    break;
                }
                Step::NeedsHash(password) => return Progress::NeedsHash { bytes, job: HashJob { password } },
                Step::Close => {
                    self.closed = true;
                    break;
                }
            }
        }
        Progress::Done(Output { bytes, open: !self.closed })
    }

    fn handle<S: Services>(&mut self, enroller: &mut Enroller<S>, payload: &[u8]) -> Step {
        let Ok((id, request)) = decode_bootstrap_request(payload) else { return Step::Close };
        let staged = matches!(self.state, State::Staged(_));
        let start = matches!(self.state, State::Start);
        match request {
            BootstrapRequest::Redeem { device_name, csr, password } if start || staged => self.redeem(enroller, id, &device_name, csr, &password),
            BootstrapRequest::ConfirmTotp { code } if staged => self.confirm(enroller, id, &code),
            _ => Step::Close,
        }
    }

    fn redeem<S: Services>(&mut self, e: &mut Enroller<S>, id: u32, device_name: &str, csr: Vec<u8>, password: &str) -> Step {
        let now = e.services.now_ms();
        // The store is the truth about whether this invitation is live, asked again now.
        let Some(Preview { email, .. }) = e.services.preview(&self.key, now) else { return Step::Close };
        let name = device_name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME_CHARS || name.chars().any(char::is_control) {
            return error_open(id, ERR_BAD_REQUEST);
        }
        if password::check_policy(password).is_err() {
            return error_open(id, ERR_PASSWORD);
        }
        // Possession of the key and P-256 are checked here; the stable key identity is staged from the request.
        let Ok(key_id) = csr_key_id(&csr) else { return error_close(id, ERR_BAD_REQUEST) };
        // A key that was ever registered, revoked or not, never enrolls again; an existing person adds devices another way.
        if e.services.key_registered(&key_id) || e.services.has_person(&email) {
            return error_close(id, ERR_UNAVAILABLE);
        }
        let Some(secret) = e.services.new_totp_secret() else { return error_close(id, ERR_UNAVAILABLE) };
        let services = &e.services;
        e.staging.retain_live(|key| services.preview(key, now).is_some());
        // The limits are taken inside `begin`, before any password hashing.
        let candidate = Candidate { email: &email, device_name: name, key_id, secret };
        let begun = match e.staging.begin(&self.source, &self.key, candidate, now) {
            Ok(begun) => begun,
            Err(StageError::RateLimited) => return error_close(id, ERR_RATE_LIMITED),
            Err(_) => return error_close(id, ERR_UNAVAILABLE),
        };
        // The limits are taken and the setup is staged. The hash is the caller's to compute, so it can run with no lock held;
        // `finish_hash` answers the Redeem.
        self.state = State::AwaitingHash(Box::new(Awaiting { attempt: begun.attempt, csr, request_id: id, totp_uri: begun.otpauth_uri }));
        Step::NeedsHash(password.to_string())
    }

    fn confirm<S: Services>(&mut self, e: &mut Enroller<S>, id: u32, code: &str) -> Step {
        let State::Staged(staged) = std::mem::replace(&mut self.state, State::Done) else { return Step::Close };
        let now = e.services.now_ms();
        // Re-check against the store immediately before the invitation is used.
        let Some(Preview { email, next_device_id }) = e.services.preview(&self.key, now) else { return Step::Close };
        let mut next_device_id = next_device_id;
        let confirmed = match e.staging.confirm(&self.source, &self.key, staged.attempt, code, now) {
            Ok(confirmed) if confirmed.email == email => confirmed,
            Err(StageError::BadCode) => {
                self.state = State::Staged(staged);
                return error_open(id, ERR_BAD_CODE);
            }
            Err(StageError::RateLimited) => return error_close(id, ERR_RATE_LIMITED),
            _ => return Step::Close,
        };
        // Build the leaf with the device id the store will allocate and commit once. If the id moved in between (nothing
        // was written), build again with the new id; a second move is a refusal.
        for round in 0..2 {
            let device_id = next_device_id;
            let claims = Claims { person: &email, device_id };
            let issued = match e.authority.prepare_device(&staged.csr, &claims, now) {
                Ok(issued) if issued.key_id == confirmed.key_id => issued,
                _ => return error_close(id, ERR_UNAVAILABLE),
            };
            let record = ActivationRecord {
                email: email.clone(),
                password_phc: staged.password_phc.clone(),
                device_id,
                key_id: confirmed.key_id,
                device_name: confirmed.device_name.clone(),
                chain: issued.chain.clone(),
                serial: issued.serial.clone(),
                not_after: issued.not_after,
                totp_secret: confirmed.secret,
                accepted_counter: confirmed.counter,
                bootstrap_pub: self.key,
            };
            match e.services.activate(&record, now) {
                Ok(allocated) if allocated == device_id => {
                    // Durable, and the subject names the allocated id. Only now does the peer see the leaf.
                    e.staging.finish(&self.key);
                    let reply =
                        BootstrapResponse::Activated { certificate: issued.certificate, issuer_certificate: e.authority.certificate().to_vec() };
                    return frame(id, reply).map_or(Step::Close, Step::ReplyAndClose);
                }
                Ok(_) => {
                    // Durable under a different id than the certificate claims: the identity is split. Release nothing.
                    e.poison();
                    return error_close(id, ERR_UNAVAILABLE);
                }
                Err(CommitFailure::OrdinalMoved) if round == 0 => {
                    // Nothing was written; the store says which id it would assign now.
                    match e.services.preview(&self.key, now) {
                        Some(moved) => next_device_id = moved.next_device_id,
                        None => return Step::Close,
                    }
                }
                Err(CommitFailure::NotWritten) => {
                    // The journal left the file exactly as before. The staged setup is untouched, so the client may send
                    // ConfirmTotp again on this connection (within the source limit).
                    self.state = State::Staged(staged);
                    return error_open(id, ERR_UNAVAILABLE);
                }
                Err(CommitFailure::Refused | CommitFailure::OrdinalMoved) => return error_close(id, ERR_UNAVAILABLE),
                Err(CommitFailure::Ambiguous) => {
                    e.poison();
                    return error_close(id, ERR_UNAVAILABLE);
                }
            }
        }
        error_close(id, ERR_UNAVAILABLE)
    }
}
