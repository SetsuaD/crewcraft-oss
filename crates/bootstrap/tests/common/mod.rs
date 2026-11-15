//! Shared fixtures: a memory store that proves protocol order (it is a fixture, not a runnable server), a world with one
//! invitation, and the client's side of the wire. Synthetic names only (example.org), no real keys.

#![allow(dead_code, clippy::unwrap_used)]

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_accounts::password;
use crewcraft_bootstrap::{ActivationRecord, BootstrapConnection, CommitError, Enroller, Services};
use crewcraft_pki::Authority;
use crewcraft_proto::bootstrap::{BootstrapRequest, BootstrapResponse, decode_bootstrap_response, encode_bootstrap_request};
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_server_core::activation::Activation;
use crewcraft_server_core::invites::Invite;
use crewcraft_totp::Totp;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519, PublicKeyData};

pub const EMAIL: &str = "alice@example.org";
pub const PASSWORD: &str = "Tr1ck-Harbor-Quiet-Lantern-42";
pub const SOURCE: &str = "192.0.2.10";

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// The stand-in for durable storage and the server around the handler.
#[derive(Debug, Default)]
pub struct MemoryStore {
    /// TOTP secrets handed out, front first. Empty gives `None` (a failed random source).
    pub secrets: VecDeque<[u8; 20]>,
    pub emails: HashMap<[u8; 32], String>,
    /// What the listener's liveness check answers.
    pub refuse_admission: bool,
    pub fail_next_commit: bool,
    /// Everything `commit_activation` was asked to commit, even when it then failed.
    pub attempted: Vec<ActivationRecord>,
    /// Only what was durably committed.
    pub committed: Vec<ActivationRecord>,
    pub hash_calls: usize,
    /// The handler's clock, in milliseconds. Tests move it by hand so rate limits do not depend on how long hashing takes.
    pub clock_ms: u64,
}

impl Services for MemoryStore {
    fn now_ms(&self) -> u64 {
        self.clock_ms
    }

    fn new_totp_secret(&mut self) -> Option<[u8; 20]> {
        self.secrets.pop_front()
    }

    fn invitation_email(&self, bootstrap_pub: &[u8; 32], _now_ms: u64) -> Option<String> {
        self.emails.get(bootstrap_pub).cloned()
    }

    fn still_admitted(&self, _bootstrap_pub: &[u8; 32], _now_ms: u64) -> bool {
        !self.refuse_admission
    }

    fn hash_password(&mut self, password: &str) -> Option<String> {
        self.hash_calls += 1;
        password::hash(password).ok()
    }

    fn commit_activation(&mut self, record: &ActivationRecord) -> Result<(), CommitError> {
        self.attempted.push(record.clone());
        if std::mem::take(&mut self.fail_next_commit) {
            return Err(CommitError);
        }
        self.committed.push(record.clone());
        Ok(())
    }
}

pub struct World {
    pub enroller: Enroller<MemoryStore>,
    /// The bootstrap key pair (Ed25519) of the invitation, and its raw public key.
    pub bootstrap_key: KeyPair,
    pub key: [u8; 32],
    pub root_cert: Vec<u8>,
    pub secret: [u8; 20],
}

/// One live invitation for `EMAIL`, an issuing authority, and a store that will hand out `secret` first.
pub fn world() -> World {
    let root = Authority::create_root("Test Root", now_ms()).unwrap();
    let issuing = root.create_issuing("Test Issuing", now_ms()).unwrap();
    let bootstrap_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let key: [u8; 32] = bootstrap_key.der_bytes().try_into().unwrap();
    let mut activation = Activation::new();
    activation.invite(Invite { email: EMAIL.into(), bootstrap_pub: key, expires_ms: now_ms() + 3_600_000 }, now_ms()).unwrap();
    let secret = [0x42u8; 20];
    let mut store = MemoryStore { clock_ms: now_ms(), ..MemoryStore::default() };
    store.emails.insert(key, EMAIL.into());
    store.secrets.push_back(secret);
    World { enroller: Enroller::new(activation, issuing, store), bootstrap_key, key, root_cert: root.certificate().to_vec(), secret }
}

pub fn connection(world: &World) -> BootstrapConnection {
    BootstrapConnection::new(world.key, SOURCE)
}

/// A signing request for a fresh P-256 device key.
pub fn device_csr() -> (KeyPair, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let csr = CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&key).unwrap().der().to_vec();
    (key, csr)
}

pub fn frame_of(id: u32, request: &BootstrapRequest) -> Vec<u8> {
    encode(&encode_bootstrap_request(id, request).unwrap()).unwrap()
}

pub fn redeem_frame(id: u32, name: &str, csr: &[u8], password: &str) -> Vec<u8> {
    frame_of(id, &BootstrapRequest::Redeem { device_name: name.into(), csr: csr.to_vec(), password: password.into() })
}

pub fn confirm_frame(id: u32, code: &str) -> Vec<u8> {
    frame_of(id, &BootstrapRequest::ConfirmTotp { code: code.into() })
}

/// The client's decoder for what the server wrote: every whole frame, in order.
pub fn replies(bytes: &[u8]) -> Vec<(u32, BootstrapResponse)> {
    let mut decoder = Decoder::new();
    decoder.push(bytes);
    let mut out = Vec::new();
    while let Some(payload) = decoder.next_frame().unwrap() {
        out.push(decode_bootstrap_response(&payload).unwrap());
    }
    assert_eq!(decoder.buffered(), 0, "the server wrote a partial frame");
    out
}

/// The code an authenticator app would show for `secret` at `at_ms`.
pub fn code_at(secret: [u8; 20], at_ms: u64) -> String {
    Totp::with_defaults(secret.to_vec()).unwrap().generate(at_ms / 1000)
}

impl World {
    /// The code for `secret` on the handler's clock.
    pub fn code_for(&self, secret: [u8; 20]) -> String {
        code_at(secret, self.enroller.services().clock_ms)
    }
}

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}
