//! Device keys that live in a hardware key store and never leave it: the Android Keystore (task T403) and, later, the
//! iOS Secure Enclave (task T422). The key is a P-256 key generated inside the store; the app only ever holds its
//! name (the alias), its public key, and a way to ask the store for a signature.
//!
//! Owns: the `HardwareKeys` and `HardwareKey` interfaces each platform implements, the adapters that let such a key
//! sign the enrollment request (rcgen) and every TLS client handshake (rustls), new key aliases, and `MemoryKeys`,
//! an in-process stand-in for tests. Called by `device` (enrollment, rebuilding an identity), `device_store`
//! (version 3 records, which name the alias instead of holding a key) and `app`. The platform implementations live in
//! the platform shells (the Android one is in apps/crewcraft-android), because they need the platform's API.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rand_core::{OsRng, RngCore};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData, SignatureAlgorithm};
use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm as TlsAlgorithm, SignatureScheme};

/// The fixed DER header of a P-256 SubjectPublicKeyInfo (id-ecPublicKey, prime256v1, a 66-byte BIT STRING), before
/// the 65-byte uncompressed point.
const P256_SPKI_HEADER: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00,
];
/// The length of a P-256 SubjectPublicKeyInfo.
pub const P256_SPKI_BYTES: usize = P256_SPKI_HEADER.len() + 65;
/// The longest alias a record may name.
pub const MAX_ALIAS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareKeyError {
    /// The key store cannot be reached or refused the request (for example, no key store on this device).
    Unavailable,
    /// The key store holds no key under that alias.
    NotFound,
    /// The key store would not sign.
    SignFailed,
    /// The key store answered with something that is not a P-256 public key, or the alias is not valid.
    Invalid,
}

impl fmt::Display for HardwareKeyError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Unavailable => "the key store is not available",
            Self::NotFound => "the key store holds no such key",
            Self::SignFailed => "the key store would not sign",
            Self::Invalid => "the key store returned an unusable key",
        })
    }
}

impl std::error::Error for HardwareKeyError {}

/// Where the key store says a key lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLocation {
    /// A separate secure chip (Android StrongBox).
    SecureElement,
    /// The processor's trusted environment (an Android TEE, the iOS Secure Enclave).
    TrustedEnvironment,
    /// Software only: an emulator or simulator, or a device without secure hardware.
    Software,
    /// The store did not say.
    Unknown,
}

/// One P-256 key held by a key store.
pub trait HardwareKey: Send + Sync {
    /// The name the key store knows the key by.
    fn alias(&self) -> &str;
    /// The public key as a DER SubjectPublicKeyInfo, `P256_SPKI_BYTES` long.
    fn public_key(&self) -> &[u8];
    /// An ECDSA signature over SHA-256 of `message`, DER encoded (as X.509 and TLS carry it).
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, HardwareKeyError>;
    /// Where the key lives.
    fn location(&self) -> KeyLocation;
}

/// A key store that makes, finds and deletes P-256 signing keys by alias.
pub trait HardwareKeys: fmt::Debug + Send + Sync {
    /// Make a new key under `alias`, replacing any key of that name.
    fn generate(&self, alias: &str) -> Result<Arc<dyn HardwareKey>, HardwareKeyError>;
    /// The key under `alias` (`NotFound` if there is none).
    fn open(&self, alias: &str) -> Result<Arc<dyn HardwareKey>, HardwareKeyError>;
    /// Delete the key under `alias`. False if there was none.
    fn delete(&self, alias: &str) -> Result<bool, HardwareKeyError>;
}

/// A new alias for `profile`'s device key: `crewcraft-<profile>-` and 16 random hex digits, so a new enrollment never
/// reuses an earlier key's name.
pub fn new_alias(profile: &str) -> String {
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let hex: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("crewcraft-{profile}-{hex}")
}

/// Whether `alias` is one this app could have made: 1 to `MAX_ALIAS` of `a-z`, `0-9`, `-` and `_`.
pub fn valid_alias(alias: &str) -> bool {
    !alias.is_empty()
        && alias.len() <= MAX_ALIAS
        && alias.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_')
}

/// The 65-byte uncompressed point inside a P-256 SubjectPublicKeyInfo, or `None` for anything else.
pub fn p256_point(spki: &[u8]) -> Option<&[u8]> {
    let point = spki.strip_prefix(&P256_SPKI_HEADER[..])?;
    (point.len() == 65 && point[0] == 0x04).then_some(point)
}

/// A P-256 SubjectPublicKeyInfo around a 65-byte uncompressed point (how the iOS Keychain hands out a public key),
/// or `None` if `point` is not one.
pub fn p256_spki(point: &[u8]) -> Option<Vec<u8>> {
    (point.len() == 65 && point[0] == 0x04).then(|| [&P256_SPKI_HEADER[..], point].concat())
}

/// Lets a hardware key sign a certificate request (`rcgen::CertificateParams::serialize_request`).
pub struct RequestSigner {
    key: Arc<dyn HardwareKey>,
    point: Vec<u8>,
}

impl RequestSigner {
    /// `Invalid` unless the key's public key is a P-256 SubjectPublicKeyInfo.
    pub fn new(key: Arc<dyn HardwareKey>) -> Result<Self, HardwareKeyError> {
        let point = p256_point(key.public_key()).ok_or(HardwareKeyError::Invalid)?.to_vec();
        Ok(Self { key, point })
    }
}

impl PublicKeyData for RequestSigner {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for RequestSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.key.sign(message).map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

/// Lets a hardware key sign TLS 1.3 client handshakes (`ecdsa_secp256r1_sha256` only).
pub struct TlsSigningKey {
    key: Arc<dyn HardwareKey>,
}

impl TlsSigningKey {
    /// `Invalid` unless the key's public key is a P-256 SubjectPublicKeyInfo.
    pub fn new(key: Arc<dyn HardwareKey>) -> Result<Self, HardwareKeyError> {
        p256_point(key.public_key()).ok_or(HardwareKeyError::Invalid)?;
        Ok(Self { key })
    }
}

impl fmt::Debug for TlsSigningKey {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.debug_struct("TlsSigningKey").field("alias", &self.key.alias()).finish()
    }
}

impl SigningKey for TlsSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&SignatureScheme::ECDSA_NISTP256_SHA256).then(|| Box::new(TlsSigner { key: self.key.clone() }) as Box<dyn Signer>)
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.key.public_key()))
    }

    fn algorithm(&self) -> TlsAlgorithm {
        TlsAlgorithm::ECDSA
    }
}

struct TlsSigner {
    key: Arc<dyn HardwareKey>,
}

impl fmt::Debug for TlsSigner {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("TlsSigner { .. }")
    }
}

impl Signer for TlsSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.key.sign(message).map_err(|error| rustls::Error::General(error.to_string()))
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

/// An in-process key store for tests: keys live in memory, are never handed out, and clones share them. It counts
/// signatures, can be switched off (`set_unavailable`) and can refuse to sign (`set_refuse_signing`).
#[derive(Clone, Default)]
pub struct MemoryKeys {
    keys: Arc<Mutex<HashMap<String, Arc<MemoryKey>>>>,
    unavailable: Arc<AtomicBool>,
    refuse: Arc<AtomicBool>,
    signatures: Arc<AtomicUsize>,
}

impl fmt::Debug for MemoryKeys {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("MemoryKeys { .. }")
    }
}

impl MemoryKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// While true, every call fails as `Unavailable`.
    pub fn set_unavailable(&self, unavailable: bool) {
        self.unavailable.store(unavailable, Ordering::SeqCst);
    }

    /// While true, signing fails as `SignFailed`.
    pub fn set_refuse_signing(&self, refuse: bool) {
        self.refuse.store(refuse, Ordering::SeqCst);
    }

    /// The aliases held, sorted.
    pub fn aliases(&self) -> Vec<String> {
        let mut aliases: Vec<String> = self.lock().keys().cloned().collect();
        aliases.sort();
        aliases
    }

    /// How many signatures the store has made.
    pub fn signatures(&self) -> usize {
        self.signatures.load(Ordering::SeqCst)
    }

    /// The private key under `alias` as PKCS#8, so a test can check it appears nowhere on disk. A hardware store has
    /// no such call.
    pub fn private_key_for_test(&self, alias: &str) -> Option<Vec<u8>> {
        self.lock().get(alias).map(|key| key.pair.serialize_der())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<MemoryKey>>> {
        self.keys.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn available(&self) -> Result<(), HardwareKeyError> {
        if self.unavailable.load(Ordering::SeqCst) { Err(HardwareKeyError::Unavailable) } else { Ok(()) }
    }
}

impl HardwareKeys for MemoryKeys {
    fn generate(&self, alias: &str) -> Result<Arc<dyn HardwareKey>, HardwareKeyError> {
        self.available()?;
        if !valid_alias(alias) {
            return Err(HardwareKeyError::Invalid);
        }
        let pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| HardwareKeyError::Unavailable)?;
        let key = Arc::new(MemoryKey {
            alias: alias.to_owned(),
            spki: pair.subject_public_key_info(),
            pair,
            refuse: self.refuse.clone(),
            signatures: self.signatures.clone(),
        });
        self.lock().insert(alias.to_owned(), key.clone());
        Ok(key)
    }

    fn open(&self, alias: &str) -> Result<Arc<dyn HardwareKey>, HardwareKeyError> {
        self.available()?;
        self.lock().get(alias).cloned().map(|key| key as Arc<dyn HardwareKey>).ok_or(HardwareKeyError::NotFound)
    }

    fn delete(&self, alias: &str) -> Result<bool, HardwareKeyError> {
        self.available()?;
        Ok(self.lock().remove(alias).is_some())
    }
}

struct MemoryKey {
    alias: String,
    spki: Vec<u8>,
    pair: KeyPair,
    refuse: Arc<AtomicBool>,
    signatures: Arc<AtomicUsize>,
}

impl HardwareKey for MemoryKey {
    fn alias(&self) -> &str {
        &self.alias
    }

    fn public_key(&self) -> &[u8] {
        &self.spki
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, HardwareKeyError> {
        if self.refuse.load(Ordering::SeqCst) {
            return Err(HardwareKeyError::SignFailed);
        }
        let signature = rcgen::SigningKey::sign(&self.pair, message).map_err(|_| HardwareKeyError::SignFailed)?;
        self.signatures.fetch_add(1, Ordering::SeqCst);
        Ok(signature)
    }

    fn location(&self) -> KeyLocation {
        KeyLocation::Software
    }
}
