//! Secrets at rest under the server's service key (docs/SECURITY-DESIGN.md section 4): authenticated encryption of a
//! person's TOTP secret before it is written to the account store (`account_store`).
//!
//! Owns: the service key (32 bytes, supplied by the server's service account: `load` reads a provisioned key file,
//! `provision` creates one only where none exists, and nothing here ever creates a key silently), its public key id,
//! and `seal` / `open` with XChaCha20-Poly1305 (RustCrypto `chacha20poly1305`; a fresh random 24-byte nonce per seal;
//! the associated data binds the key id and a caller context such as the person's email, so a sealed secret cannot
//! be moved to another record). Holds no storage of its own.
//! Called by: `account_store` (sealing on activation, opening on replay and at sign-in).
//!
//! Secrets are held in `Zeroizing` buffers and print as `..` in `Debug`.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Length of the service key.
pub const KEY_BYTES: usize = 32;
/// Length of the public key id stored next to every sealed secret.
pub const KEY_ID_BYTES: usize = 8;
/// Length of the per-seal nonce.
pub const NONCE_BYTES: usize = 24;
/// The largest plaintext `seal` accepts (a TOTP secret is 20 bytes).
pub const MAX_PLAINTEXT: usize = 1024;
/// Length of the authentication tag appended to every ciphertext.
pub const TAG_BYTES: usize = 16;

const KEY_ID_LABEL: &[u8] = b"crewcraft-service-key-v1";
const AAD_LABEL: &[u8] = b"crewcraft-seal-v1";

/// A secret sealed under a service key.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    pub key_id: [u8; KEY_ID_BYTES],
    pub nonce: [u8; NONCE_BYTES],
    /// The ciphertext followed by the 16-byte tag.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for Sealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sealed {{ key_id: {}, .. }}", hex(&self.key_id))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// The secret was sealed under a different service key.
    WrongKey,
    /// The tag did not verify: the bytes or their context were changed.
    Corrupt,
    /// The plaintext is empty or longer than `MAX_PLAINTEXT`.
    BadLength,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SealError::WrongKey => "sealed under a different service key",
            SealError::Corrupt => "sealed secret failed authentication",
            SealError::BadLength => "secret length out of range",
        })
    }
}

impl std::error::Error for SealError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFileError {
    /// There is no key file: the service account has not been given a key. The server must not start.
    Missing,
    /// `provision` found a key file already there; it never replaces one.
    Exists,
    /// The key file is not exactly `KEY_BYTES` long.
    WrongLength,
    Io(std::io::ErrorKind),
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyFileError::Missing => f.write_str("no service key file"),
            KeyFileError::Exists => f.write_str("a service key file already exists; it is never replaced"),
            KeyFileError::WrongLength => write!(f, "the service key file is not {KEY_BYTES} bytes"),
            KeyFileError::Io(kind) => write!(f, "service key file: {kind}"),
        }
    }
}

impl std::error::Error for KeyFileError {}

/// The server's service key.
pub struct ServiceKey {
    key: Zeroizing<[u8; KEY_BYTES]>,
    id: [u8; KEY_ID_BYTES],
}

impl fmt::Debug for ServiceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServiceKey {{ id: {}, .. }}", hex(&self.id))
    }
}

impl ServiceKey {
    /// A key from bytes the caller already holds (tests, or a key handed over by an OS key store).
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        let key = Zeroizing::new(bytes);
        let mut hasher = Sha256::new();
        hasher.update(KEY_ID_LABEL);
        hasher.update(&key[..]);
        let digest = hasher.finalize();
        let mut id = [0u8; KEY_ID_BYTES];
        id.copy_from_slice(&digest[..KEY_ID_BYTES]);
        ServiceKey { key, id }
    }

    /// Read a provisioned key file of exactly `KEY_BYTES` bytes. `Missing` when there is none.
    pub fn load(path: &Path) -> Result<Self, KeyFileError> {
        let mut file = match OpenOptions::new().read(true).open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(KeyFileError::Missing),
            Err(e) => return Err(KeyFileError::Io(e.kind())),
        };
        let mut buf = Zeroizing::new(Vec::with_capacity(KEY_BYTES + 1));
        Read::by_ref(&mut file).take(KEY_BYTES as u64 + 1).read_to_end(&mut buf).map_err(|e| KeyFileError::Io(e.kind()))?;
        let bytes: [u8; KEY_BYTES] = buf.as_slice().try_into().map_err(|_| KeyFileError::WrongLength)?;
        Ok(Self::from_bytes(bytes))
    }

    /// Create a NEW key file with random bytes (owner read/write only on Unix). Refuses with `Exists` if the file is
    /// already there, so an existing store's key is never replaced. For the installer and first-run setup only.
    pub fn provision(path: &Path) -> Result<Self, KeyFileError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(KeyFileError::Exists),
            Err(e) => return Err(KeyFileError::Io(e.kind())),
        };
        let mut bytes = Zeroizing::new([0u8; KEY_BYTES]);
        OsRng.fill_bytes(&mut bytes[..]);
        file.write_all(&bytes[..]).and_then(|()| file.sync_all()).map_err(|e| KeyFileError::Io(e.kind()))?;
        Ok(Self::from_bytes(*bytes))
    }

    /// The public id of this key (8 bytes of a labelled SHA-256 of it). Safe to store and to print.
    pub fn id(&self) -> [u8; KEY_ID_BYTES] {
        self.id
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&*self.key).into())
    }

    /// Seal `plaintext`; `context` (for example the person's email) must be given again to `open`.
    pub fn seal(&self, plaintext: &[u8], context: &[u8]) -> Result<Sealed, SealError> {
        if plaintext.is_empty() || plaintext.len() > MAX_PLAINTEXT {
            return Err(SealError::BadLength);
        }
        let mut nonce = [0u8; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let aad = aad(&self.id, context);
        let ciphertext =
            self.cipher().encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad }).map_err(|_| SealError::BadLength)?;
        Ok(Sealed { key_id: self.id, nonce, ciphertext })
    }

    /// Open a sealed secret. `WrongKey` when it names another key id; `Corrupt` when the tag does not verify.
    pub fn open(&self, sealed: &Sealed, context: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
        if sealed.key_id != self.id {
            return Err(SealError::WrongKey);
        }
        let aad = aad(&self.id, context);
        self.cipher()
            .decrypt(XNonce::from_slice(&sealed.nonce), Payload { msg: &sealed.ciphertext, aad: &aad })
            .map(Zeroizing::new)
            .map_err(|_| SealError::Corrupt)
    }
}

/// `label | key id | u32 context length | context`, so no two (key, context) pairs give the same bytes.
fn aad(key_id: &[u8; KEY_ID_BYTES], context: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_LABEL.len() + KEY_ID_BYTES + 4 + context.len());
    out.extend_from_slice(AAD_LABEL);
    out.extend_from_slice(key_id);
    out.extend_from_slice(&(context.len() as u32).to_be_bytes());
    out.extend_from_slice(context);
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
