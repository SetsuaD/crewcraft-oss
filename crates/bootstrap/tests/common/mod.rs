//! Shared fixtures. The account state is the REAL durable store (`AccountStore`): over an in-memory append log for the
//! protocol tests (so a write can be made to fail), and over a real journal file for the restart tests. Nothing here
//! models invitations, people or devices on its own. Synthetic names only (example.org), no real keys.

#![allow(dead_code, clippy::unwrap_used)]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_accounts::password;
use crewcraft_bootstrap::{BootstrapConnection, Enroller, Environment, StoreServices};
use crewcraft_pki::Authority;
use crewcraft_proto::bootstrap::{BootstrapRequest, BootstrapResponse, decode_bootstrap_response, encode_bootstrap_request};
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_server_core::account_journal::AppendError;
use crewcraft_server_core::account_op::{AccountOp, FORMAT, encode_account_op};
use crewcraft_server_core::account_store::{AccountStore, AppendLog};
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::seal::ServiceKey;
use crewcraft_totp::Totp;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519, PublicKeyData};

pub const EMAIL: &str = "alice@example.org";
pub const PASSWORD: &str = "Tr1ck-Harbor-Quiet-Lantern-42";
pub const SOURCE: &str = "192.0.2.10";
pub const HOUR: u64 = 3_600_000;

pub fn real_now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

pub fn service_key() -> ServiceKey {
    ServiceKey::from_bytes([7; 32])
}

/// The clock, the random source and the hasher, all under the test's control.
#[derive(Debug)]
pub struct TestEnv {
    pub clock_ms: u64,
    /// TOTP secrets handed out, front first. Empty gives `None` (a failed random source).
    pub secrets: VecDeque<[u8; 20]>,
    pub hash_calls: usize,
}

impl Environment for TestEnv {
    fn now_ms(&self) -> u64 {
        self.clock_ms
    }

    fn totp_secret(&mut self) -> Option<[u8; 20]> {
        self.secrets.pop_front()
    }

    fn hash_password(&mut self, p: &str) -> Option<String> {
        self.hash_calls += 1;
        password::hash(p).ok()
    }
}

/// What the account store writes to, kept in memory, with a switch to make the next write fail.
#[derive(Debug, Default)]
pub struct MemState {
    pub records: Vec<Vec<u8>>,
    pub fail_next: Option<AppendError>,
}

#[derive(Debug, Clone, Default)]
pub struct MemLog(pub Arc<Mutex<MemState>>);

impl MemLog {
    pub fn records(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().records.clone()
    }

    pub fn len(&self) -> usize {
        self.0.lock().unwrap().records.len()
    }

    pub fn fail_next(&self, error: AppendError) {
        self.0.lock().unwrap().fail_next = Some(error);
    }

    /// A log that already holds `records` (what a restart reads back).
    pub fn with_records(records: Vec<Vec<u8>>) -> Self {
        Self(Arc::new(Mutex::new(MemState { records, fail_next: None })))
    }
}

impl AppendLog for MemLog {
    fn append(&mut self, record: &[u8]) -> Result<(), AppendError> {
        let mut state = self.0.lock().unwrap();
        if let Some(error) = state.fail_next.take() {
            return Err(error);
        }
        state.records.push(record.to_vec());
        Ok(())
    }
}

/// The first record of every store: names the service key. A store is made by writing it, never silently by `open`.
pub fn created_record() -> Vec<u8> {
    encode_account_op(&AccountOp::Created { format: FORMAT, key_id: service_key().id() }).unwrap()
}

/// A new in-memory store over `log`: the created record goes into the log and the store replays it.
pub fn mem_store(log: &MemLog) -> AccountStore<MemLog> {
    let created = created_record();
    log.0.lock().unwrap().records.push(created.clone());
    AccountStore::from_records(log.clone(), service_key(), vec![created]).unwrap()
}

pub type Rig<L> = Enroller<StoreServices<L, TestEnv>>;

pub struct World<L: AppendLog> {
    pub enroller: Rig<L>,
    /// The bootstrap key pair (Ed25519) of the invitation, and its raw public key.
    pub bootstrap_key: KeyPair,
    pub key: [u8; 32],
    pub root_cert: Vec<u8>,
    pub secret: [u8; 20],
}

pub struct Parts {
    pub authority: Authority,
    pub root_cert: Vec<u8>,
    pub bootstrap_key: KeyPair,
    pub key: [u8; 32],
    pub secret: [u8; 20],
}

pub fn parts() -> Parts {
    let root = Authority::create_root("Test Root", real_now_ms()).unwrap();
    let issuing = root.create_issuing("Test Issuing", real_now_ms()).unwrap();
    let bootstrap_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let key: [u8; 32] = bootstrap_key.der_bytes().try_into().unwrap();
    Parts { authority: issuing, root_cert: root.certificate().to_vec(), bootstrap_key, key, secret: [0x42u8; 20] }
}

pub fn env_at(clock_ms: u64, secrets: &[[u8; 20]]) -> TestEnv {
    TestEnv { clock_ms, secrets: secrets.iter().copied().collect(), hash_calls: 0 }
}

/// A world over `store`, with one live invitation for `EMAIL` issued into it when `issue` is set.
pub fn world_over<L: AppendLog>(mut store: AccountStore<L>, p: Parts, clock_ms: u64, issue: bool) -> World<L> {
    if issue {
        store.issue_invite(Invite { email: EMAIL.into(), bootstrap_pub: p.key, expires_ms: clock_ms + HOUR }, clock_ms).unwrap();
    }
    let services = StoreServices::new(store, env_at(clock_ms, &[p.secret]));
    World { enroller: Enroller::new(p.authority, services), bootstrap_key: p.bootstrap_key, key: p.key, root_cert: p.root_cert, secret: p.secret }
}

/// A fresh in-memory world.
pub fn world() -> (World<MemLog>, MemLog) {
    let log = MemLog::default();
    let store = mem_store(&log);
    (world_over(store, parts(), real_now_ms(), true), log)
}

/// Restart: rebuild the store from what was written, keep the authority and the clock.
pub fn restart(w: World<MemLog>, log: &MemLog) -> (World<MemLog>, MemLog) {
    let (authority, services) = w.enroller.into_parts();
    let (store, env) = services.into_parts();
    drop(store);
    let records = log.records();
    let log2 = MemLog::with_records(records.clone());
    let store = AccountStore::from_records(log2.clone(), service_key(), records).unwrap();
    let services = StoreServices::new(store, env);
    (
        World { enroller: Enroller::new(authority, services), bootstrap_key: w.bootstrap_key, key: w.key, root_cert: w.root_cert, secret: w.secret },
        log2,
    )
}

impl<L: AppendLog> World<L> {
    /// The code for `secret` on the handler's clock.
    pub fn code_for(&self, secret: [u8; 20]) -> String {
        code_at(secret, crewcraft_bootstrap::Services::now_ms(self.enroller.services()))
    }

    pub fn advance(&mut self, ms: u64) {
        self.enroller.services_mut().env_mut().clock_ms += ms;
    }

    pub fn now(&self) -> u64 {
        crewcraft_bootstrap::Services::now_ms(self.enroller.services())
    }
}

pub fn connection<L: AppendLog>(world: &World<L>) -> BootstrapConnection {
    BootstrapConnection::new(world.key, SOURCE)
}

/// A signing request for a fresh P-256 device key.
pub fn device_csr() -> (KeyPair, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let csr = csr_for(&key);
    (key, csr)
}

pub fn csr_for(key: &KeyPair) -> Vec<u8> {
    CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(key).unwrap().der().to_vec()
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

pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}
