//! The server side of the bootstrap connection (docs/SECURITY-DESIGN.md section 3): the two calls a device holding a live
//! invitation may make, `Redeem` and `ConfirmTotp`, and nothing else.
//!
//! Owns: the per-connection state machine that turns the two requests into the staged device, the first TOTP check and the
//! activation record, and the order in which things happen. Holds no sockets, no TLS and no storage: bytes come in through
//! `BootstrapConnection::receive`, the in-memory first-enrollment flow is `server-core::activation`, certificates come
//! from `crewcraft-pki`, and everything that must survive a restart goes out through the `Services::commit_activation` hook.
//! Called by: the listener, for a peer admitted as `crewcraft_admission::Class::Bootstrap`.
//!
//! The order is the point:
//! 1. `Redeem` takes the cheap checks first, then the liveness re-check, then `Activation::begin` (which takes the per-source
//!    and server-wide limits), and only then the Argon2 password hash. It answers `Setup` with the authenticator URI and
//!    NOTHING ELSE: no certificate exists yet.
//! 2. `ConfirmTotp` must arrive on the same connection and the same staged attempt. The invitation is re-checked
//!    immediately before it is used. After the code is accepted the exact leaf is built (not yet recorded), handed with
//!    everything else to `commit_activation`, and only when that returns `Ok` is the leaf recorded and sent as `Activated`.
//! 3. A failed commit releases no certificate. Because `Activation::confirm` has already registered the device in memory
//!    and cannot roll back, the `Enroller` is then POISONED: every later connection is closed without a byte until it is
//!    rebuilt from durable state.
//!
//! Any other message, an out-of-order one, a malformed frame, or a peer that fails a liveness check is closed without a
//! reply. Sign-in and chat requests cannot even be decoded here (the tags are disjoint).

use crewcraft_accounts::password;
use crewcraft_pki::{Authority, Claims, csr_key_id};
use crewcraft_proto::bootstrap::{BootstrapRequest, BootstrapResponse, decode_bootstrap_request, encode_bootstrap_response};
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_server_core::activation::{Activation, ActivationAttempt, ActivationError, EnrollmentCandidate};
use crewcraft_server_core::devices::MAX_NAME_CHARS;
use rand_core::{OsRng, RngCore};

/// A malformed or unacceptable request (device name, signing request). The connection is closed after it.
pub const ERR_BAD_REQUEST: u16 = 1;
/// The password does not meet the policy. The connection stays open for another `Redeem`.
pub const ERR_PASSWORD: u16 = 2;
/// A source or server-wide limit. The connection is closed after it.
pub const ERR_RATE_LIMITED: u16 = 3;
/// The first TOTP code was wrong. The connection stays open for another code, up to `activation::MAX_WRONG_CODES`.
pub const ERR_BAD_CODE: u16 = 4;
/// Anything the server could not complete (including a failed durable commit). The connection is closed after it.
pub const ERR_UNAVAILABLE: u16 = 5;

/// Everything that must become durable together before the device is given its certificate.
#[derive(Clone)]
pub struct ActivationRecord {
    /// The account: the invitation's canonical email.
    pub email: String,
    /// The account password, as an Argon2id PHC string. Never the password.
    pub password_phc: String,
    /// The device's ordinal in the registry, for display. NOT its identity.
    pub device_id: u64,
    /// The device's identity: SHA-256 of its public key's SubjectPublicKeyInfo, stable across renewals. This is also the
    /// registry fingerprint.
    pub key_id: [u8; 32],
    pub device_name: String,
    /// The exact chain that will be sent: the leaf, then the issuing authority.
    pub chain: Vec<Vec<u8>>,
    /// The leaf's serial, the handle for revocation. Separate from the ordinal and from the key identity.
    pub serial: Vec<u8>,
    /// When the leaf expires, Unix seconds.
    pub not_after: i64,
    /// The TOTP secret, to be encrypted at rest by the store.
    pub totp_secret: [u8; 20],
    /// The counter of the code that just proved the authenticator: the first accepted counter, so it can never be replayed.
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

/// The durable commit failed. Nothing about why is shared with the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitError;

/// What the handler needs from the server around it.
pub trait Services {
    fn now_ms(&self) -> u64;

    /// A fresh 20-byte TOTP secret from the system random source, or `None` if it failed (`random_totp_secret`).
    fn new_totp_secret(&mut self) -> Option<[u8; 20]>;

    /// The canonical email of the live invitation with this bootstrap key.
    fn invitation_email(&self, bootstrap_pub: &[u8; 32], now_ms: u64) -> Option<String>;

    /// Whether the peer is still admitted as this bootstrap key right now (the listener asks `Admission`). Called before
    /// the invitation is used, so a revocation or a consumed invitation since the handshake fails closed.
    fn still_admitted(&self, bootstrap_pub: &[u8; 32], now_ms: u64) -> bool;

    /// Hash the account password (Argon2id PHC). Called only after the request passed the rate limits.
    fn hash_password(&mut self, password: &str) -> Option<String> {
        password::hash(password).ok()
    }

    /// Commit the whole record atomically: account, invitation consumed, exact chain, device and first TOTP counter. Return
    /// `Ok` only when all of it is durable. On `Err` nothing may be left half written.
    fn commit_activation(&mut self, record: &ActivationRecord) -> Result<(), CommitError>;
}

/// A fresh TOTP secret from the operating system's random source.
pub fn random_totp_secret() -> Option<[u8; 20]> {
    let mut secret = [0u8; 20];
    OsRng.try_fill_bytes(&mut secret).ok()?;
    Some(secret)
}

/// The shared server state the bootstrap connections act on.
pub struct Enroller<S: Services> {
    activation: Activation,
    authority: Authority,
    services: S,
    poisoned: bool,
}

impl<S: Services> std::fmt::Debug for Enroller<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Enroller(.., poisoned: {})", self.poisoned)
    }
}

impl<S: Services> Enroller<S> {
    pub fn new(activation: Activation, authority: Authority, services: S) -> Self {
        Self { activation, authority, services, poisoned: false }
    }

    pub fn activation(&self) -> &Activation {
        &self.activation
    }

    pub fn activation_mut(&mut self) -> &mut Activation {
        &mut self.activation
    }

    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    pub fn authority_mut(&mut self) -> &mut Authority {
        &mut self.authority
    }

    pub fn services(&self) -> &S {
        &self.services
    }

    pub fn services_mut(&mut self) -> &mut S {
        &mut self.services
    }

    /// A commit failed after the device was registered in memory: the in-memory state is ahead of the durable state, so
    /// every bootstrap connection is closed until the `Enroller` is rebuilt from the store.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
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
    attempt: ActivationAttempt,
    device_name: String,
    csr: Vec<u8>,
    key_id: [u8; 32],
    password_phc: String,
    totp_secret: [u8; 20],
}

enum State {
    Start,
    Staged(Box<Staged>),
    Done,
}

enum Step {
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
    /// connection; later calls return nothing.
    pub fn receive<S: Services>(&mut self, enroller: &mut Enroller<S>, input: &[u8]) -> Output {
        let mut bytes = Vec::new();
        if self.closed || enroller.poisoned {
            self.closed = true;
            return Output { bytes, open: false };
        }
        self.decoder.push(input);
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
                Step::Close => {
                    self.closed = true;
                    break;
                }
            }
        }
        Output { bytes, open: !self.closed }
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
        if !e.services.still_admitted(&self.key, now) {
            return Step::Close;
        }
        let name = device_name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME_CHARS || name.chars().any(char::is_control) {
            return error_open(id, ERR_BAD_REQUEST);
        }
        if password::check_policy(password).is_err() {
            return error_open(id, ERR_PASSWORD);
        }
        // Possession of the key and P-256 are checked here; the key identity is staged from the request.
        let Ok(key_id) = csr_key_id(&csr) else { return error_close(id, ERR_BAD_REQUEST) };
        let Some(email) = e.services.invitation_email(&self.key, now) else { return Step::Close };
        let Some(totp_secret) = e.services.new_totp_secret() else { return error_close(id, ERR_UNAVAILABLE) };
        let candidate = EnrollmentCandidate { verified_email: &email, device_name: name, fingerprint: key_id, totp_secret };
        // The limits are taken inside `begin`, before any password hashing.
        let begun = match e.activation.begin(&self.source, &self.key, candidate, now) {
            Ok(begun) => begun,
            Err(ActivationError::RateLimited) => return error_close(id, ERR_RATE_LIMITED),
            Err(ActivationError::AlreadyEnrolled | ActivationError::AccountMismatch | ActivationError::TotpSetup) => {
                return error_close(id, ERR_UNAVAILABLE);
            }
            Err(_) => return Step::Close,
        };
        let Some(password_phc) = e.services.hash_password(password) else {
            self.state = State::Start;
            return error_close(id, ERR_UNAVAILABLE);
        };
        self.state =
            State::Staged(Box::new(Staged { attempt: begun.attempt, device_name: name.to_string(), csr, key_id, password_phc, totp_secret }));
        frame(id, BootstrapResponse::Setup { totp_uri: begun.otpauth_uri }).map_or(Step::Close, Step::Reply)
    }

    fn confirm<S: Services>(&mut self, e: &mut Enroller<S>, id: u32, code: &str) -> Step {
        let State::Staged(staged) = std::mem::replace(&mut self.state, State::Done) else { return Step::Close };
        let now = e.services.now_ms();
        // Re-check against live state immediately before the invitation is used.
        if !e.services.still_admitted(&self.key, now) || !e.activation.is_pending(&self.key, now) {
            return Step::Close;
        }
        let activated = match e.activation.confirm(&self.source, &self.key, staged.attempt, code, now) {
            Ok(activated) => activated,
            Err(ActivationError::BadCode) => {
                self.state = State::Staged(staged);
                return error_open(id, ERR_BAD_CODE);
            }
            Err(ActivationError::RateLimited) => return error_close(id, ERR_RATE_LIMITED),
            Err(ActivationError::Device(_) | ActivationError::AlreadyEnrolled | ActivationError::TotpSetup) => {
                return error_close(id, ERR_UNAVAILABLE);
            }
            Err(_) => return Step::Close,
        };
        // From here the device is registered in memory and cannot be unregistered: any failure poisons the enroller.
        let claims = Claims { person: &activated.email, device_id: activated.device_id };
        let issued = match e.authority.prepare_device(&staged.csr, &claims, now) {
            Ok(issued) if issued.key_id == staged.key_id => issued,
            _ => {
                e.poisoned = true;
                return error_close(id, ERR_UNAVAILABLE);
            }
        };
        let record = ActivationRecord {
            email: activated.email.clone(),
            password_phc: staged.password_phc,
            device_id: activated.device_id,
            key_id: staged.key_id,
            device_name: staged.device_name,
            chain: issued.chain.clone(),
            serial: issued.serial.clone(),
            not_after: issued.not_after,
            totp_secret: staged.totp_secret,
            accepted_counter: activated.accepted_counter,
            bootstrap_pub: self.key,
        };
        if e.services.commit_activation(&record).is_err() {
            e.poisoned = true;
            return error_close(id, ERR_UNAVAILABLE);
        }
        // Durable. Only now does the authority treat the leaf as good, and only now does the peer see it.
        e.authority.record_issued(&issued, &claims);
        let activated_reply =
            BootstrapResponse::Activated { certificate: issued.certificate, issuer_certificate: e.authority.certificate().to_vec() };
        frame(id, activated_reply).map_or(Step::Close, Step::ReplyAndClose)
    }
}
