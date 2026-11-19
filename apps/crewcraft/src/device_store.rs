//! Enrolled devices saved between runs: one file per server profile in a per-user directory the caller chooses
//! (the window passes the platform's data directory). Tasks T304 (the record) and T313 (sealing it).
//!
//! Owns: the record file formats, sealing a record under its profile's key from a `KeyVault` and opening it again,
//! the one-time move of an unsealed record to a sealed one, atomic replacement (a new file, synced, then renamed over
//! the old one), owner-only permissions on Unix (0700 directory, 0600 file, and a refusal to read anything looser),
//! and a bound on every read. Called by the window. Calls `device` to check a record before handing it out, and
//! `key_vault` for the sealing keys.
//!
//! A store is sealed (`open_sealed`, what the app uses) or plain (`open`, for a person who has opted out of the key
//! store; see docs/SECURITY-DESIGN.md section 2). A sealed store never writes the private key to disk in the clear,
//! not even in its temporary files.
//!
//! Record format, version 1 (the plain file, and what a sealed file holds inside): the magic line below, then seven
//! fields, each a `u32` big-endian byte length and the bytes (address, server name, root fingerprint as 64 lowercase
//! hex digits, root certificate DER, device certificate DER, issuer certificate DER, PKCS#8 device key), then the
//! SHA-256 of everything before it.
//!
//! Sealed format, version 2: the magic line `crewcraft device v2`, a 24-byte random nonce, then a version 1 record
//! encrypted with XChaCha20-Poly1305 under the profile's 32-byte key, followed by its 16-byte tag. The associated
//! data is the version 2 magic line, the profile name's length (`u32` big-endian) and the profile name, so a sealed
//! record cannot be renamed to another profile or read as another version.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::bootstrap::MAX_CERT;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::device::{MAX_KEY_DER, StoredDevice};
use crate::key_vault::{KEY_BYTES, KeyVault, VaultError, VaultKey};
use crate::server_endpoint::{MAX_ADDRESS, MAX_ROOT_DER, ServerEndpoint};

const MAGIC: &[u8] = b"crewcraft device v1\n";
const SEALED_MAGIC: &[u8] = b"crewcraft device v2\n";
const NONCE: usize = 24;
const TAG: usize = 16;
/// What sealing adds to a record: the version 2 magic line, the nonce and the tag.
const SEAL_OVERHEAD: usize = SEALED_MAGIC.len() + NONCE + TAG;
const EXTENSION: &str = ".device";
const MAX_PROFILE: usize = 64;
const MAX_SERVER_NAME: usize = 253;
const FINGERPRINT_HEX: usize = 64;
const DIGEST: usize = 32;
/// No record file is longer than this; a longer file is refused before it is read.
pub const MAX_RECORD: usize = 32 * 1024;
/// `profiles` lists at most this many.
const MAX_PROFILES: usize = 256;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    /// A profile name other than 1 to 64 of `a-z`, `0-9`, `-` and `_`, starting with a letter or digit.
    InvalidName,
    /// No record for this profile.
    NotFound,
    /// The file or directory is readable or writable by someone other than its owner, or the path is not a plain
    /// file (for example a symbolic link).
    Permissions,
    /// The file is longer than `MAX_RECORD`.
    TooLarge,
    /// The file is not a whole, intact record, or its parts do not fit together. For a sealed record this includes a
    /// changed byte, a record renamed from another profile, and a key other than the one it was sealed with.
    Corrupt,
    /// The key store could not be reached, is locked, or refused access, so a sealed record cannot be read or written.
    KeyStoreUnavailable,
    /// The record is sealed but the key store holds no key for its profile (the key was deleted, or the files came
    /// from another computer or another user).
    KeyMissing,
    /// A plain store found a sealed record. Only a sealed store, with the key store, can read it.
    Sealed,
    Io(io::ErrorKind),
}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

impl From<VaultError> for StoreError {
    fn from(error: VaultError) -> Self {
        match error {
            VaultError::Unavailable => Self::KeyStoreUnavailable,
            VaultError::Damaged => Self::Corrupt,
        }
    }
}

/// The directory that holds the device records.
#[derive(Debug)]
pub struct DeviceStore {
    dir: PathBuf,
    /// The key store that seals the records; `None` for a plain store.
    vault: Option<Arc<dyn KeyVault>>,
}

impl DeviceStore {
    /// A plain store in `dir`: records are unsealed (version 1) and protected by file permissions only. It is for a
    /// person who has chosen that over the key store; the app otherwise uses `open_sealed`. A plain store refuses a
    /// sealed record (`Sealed`). `dir` is created (with missing parents) if needed, and on Unix made owner-only (0700)
    /// if it is not already.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        create_private_dir(dir)?;
        Ok(Self { dir: dir.to_owned(), vault: None })
    }

    /// A sealed store in `dir`: each record is sealed under its profile's key in `vault` (version 2), and an unsealed
    /// record found there is sealed the first time it is loaded. The directory is handled as in `open`.
    pub fn open_sealed(dir: &Path, vault: Arc<dyn KeyVault>) -> Result<Self, StoreError> {
        create_private_dir(dir)?;
        Ok(Self { dir: dir.to_owned(), vault: Some(vault) })
    }

    /// Whether this store seals its records.
    pub fn is_sealed(&self) -> bool {
        self.vault.is_some()
    }

    /// For a sealed store, ask the key store for `profile`'s key and report only whether it answered
    /// (`KeyStoreUnavailable` if not), so the app can say there is no usable key store before anyone enrolls. A plain
    /// store always answers `Ok`.
    pub fn check_key_store(&self, profile: &str) -> Result<(), StoreError> {
        if !valid_profile(profile) {
            return Err(StoreError::InvalidName);
        }
        match &self.vault {
            Some(vault) => match vault.load(profile) {
                Ok(_) | Err(VaultError::Damaged) => Ok(()),
                Err(VaultError::Unavailable) => Err(StoreError::KeyStoreUnavailable),
            },
            None => Ok(()),
        }
    }

    /// Where `profile`'s record lives.
    pub fn path(&self, profile: &str) -> Result<PathBuf, StoreError> {
        if !valid_profile(profile) {
            return Err(StoreError::InvalidName);
        }
        Ok(self.dir.join(format!("{profile}{EXTENSION}")))
    }

    /// Write `device` as `profile`, replacing any earlier record in one step: a reader sees the old record or the
    /// new one, never a mix.
    ///
    /// A sealed store seals the record under the profile's key. It keeps the key the key store already holds, so the
    /// old record stays readable until the rename, and creates and saves a new random key first when there is none
    /// (or what is there is not a key).
    pub fn save(&self, profile: &str, device: &StoredDevice) -> Result<(), StoreError> {
        let target = self.path(profile)?;
        let record = match &self.vault {
            None => encode(device, MAX_RECORD)?,
            Some(vault) => {
                let plain = encode(device, MAX_RECORD - SEAL_OVERHEAD)?;
                let key = match vault.load(profile) {
                    Ok(Some(key)) => key,
                    Ok(None) | Err(VaultError::Damaged) => {
                        let mut key: VaultKey = Zeroizing::new([0; KEY_BYTES]);
                        OsRng.try_fill_bytes(&mut key[..]).map_err(|_| StoreError::Io(io::ErrorKind::Other))?;
                        vault.store(profile, &key)?;
                        key
                    }
                    Err(error) => return Err(error.into()),
                };
                // Ciphertext only; held like the plain record so both arms have one type.
                Zeroizing::new(seal(&key, profile, &plain)?)
            }
        };
        self.replace(profile, &target, &record)
    }

    /// Write `record` to a new temporary file next to `target`, sync it, and rename it over `target`.
    fn replace(&self, profile: &str, target: &Path, record: &[u8]) -> Result<(), StoreError> {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.subsec_nanos());
        let temporary = self.dir.join(format!(".{profile}.{}.{sequence}.{nanos}.tmp", std::process::id()));
        let written = write_new(&temporary, record).and_then(|()| fs::rename(&temporary, target));
        if let Err(error) = written {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        sync_dir(&self.dir)?;
        Ok(())
    }

    /// Read `profile`'s record and check it whole before returning it.
    ///
    /// A sealed store opens a sealed record with the profile's key. An unsealed (version 1) record is read once and
    /// saved again sealed, replacing the old file. That happens only while the key store holds no key for the
    /// profile: a key there means a sealed record was written before, so an unsealed file in its place was put there
    /// by something else and is refused as `Corrupt`.
    pub fn load(&self, profile: &str) -> Result<StoredDevice, StoreError> {
        let path = self.path(profile)?;
        let link = match fs::symlink_metadata(&path) {
            Ok(link) => link,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(StoreError::NotFound),
            Err(error) => return Err(error.into()),
        };
        if !link.file_type().is_file() {
            return Err(StoreError::Permissions);
        }
        check_private(&fs::metadata(&self.dir)?)?;
        let mut file = File::open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(StoreError::Permissions);
        }
        check_private(&metadata)?;
        if metadata.len() > MAX_RECORD as u64 {
            return Err(StoreError::TooLarge);
        }
        // Allocated once, so no copy of the key is left behind by a reallocation.
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_RECORD + 1));
        Read::by_ref(&mut file).take(MAX_RECORD as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_RECORD {
            return Err(StoreError::TooLarge);
        }
        let Some(vault) = &self.vault else {
            if bytes.starts_with(SEALED_MAGIC) {
                return Err(StoreError::Sealed);
            }
            return decode(&bytes).ok_or(StoreError::Corrupt);
        };
        if bytes.starts_with(SEALED_MAGIC) {
            let key = vault.load(profile)?.ok_or(StoreError::KeyMissing)?;
            let plain = open(&key, profile, &bytes).ok_or(StoreError::Corrupt)?;
            return decode(&plain).ok_or(StoreError::Corrupt);
        }
        // An unsealed record: seal it now, unless a key already exists for this profile (see above).
        let device = decode(&bytes).ok_or(StoreError::Corrupt)?;
        if vault.load(profile)?.is_some() {
            return Err(StoreError::Corrupt);
        }
        self.save(profile, &device)?;
        Ok(device)
    }

    /// Delete `profile`'s record and, for a sealed store, its key. False if there was no record.
    ///
    /// The file goes first, so a key store that cannot be reached never leaves a readable record behind; then the
    /// key is deleted, and a key store error is returned even though the record is already gone.
    pub fn remove(&self, profile: &str) -> Result<bool, StoreError> {
        let removed = match fs::remove_file(self.path(profile)?) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if let Some(vault) = &self.vault {
            vault.remove(profile)?;
        }
        Ok(removed)
    }

    /// The saved profiles, sorted. Other files in the directory, such as an interrupted save's leftover, are ignored.
    pub fn profiles(&self) -> Result<Vec<String>, StoreError> {
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str().and_then(|name| name.strip_suffix(EXTENSION))
                && valid_profile(name)
            {
                names.push(name.to_owned());
                if names.len() >= MAX_PROFILES {
                    break;
                }
            }
        }
        names.sort();
        Ok(names)
    }
}

fn valid_profile(profile: &str) -> bool {
    !profile.is_empty()
        && profile.len() <= MAX_PROFILE
        && profile.bytes().next().is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && profile.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_')
}

/// The version 1 record of `device`, refused as `TooLarge` past `max` bytes.
fn encode(device: &StoredDevice, max: usize) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let endpoint = device.endpoint();
    let fingerprint = endpoint.fingerprint().to_string();
    let fields: [&[u8]; 7] = [
        endpoint.address().as_bytes(),
        endpoint.server_name().as_bytes(),
        fingerprint.as_bytes(),
        endpoint.root_der(),
        device.certificate(),
        device.issuer_certificate(),
        device.key_pkcs8(),
    ];
    let length = MAGIC.len() + fields.iter().map(|field| 4 + field.len()).sum::<usize>() + DIGEST;
    if length > max {
        return Err(StoreError::TooLarge);
    }
    let mut record = Zeroizing::new(Vec::with_capacity(length));
    record.extend_from_slice(MAGIC);
    for field in fields {
        let size = u32::try_from(field.len()).map_err(|_| StoreError::TooLarge)?;
        record.extend_from_slice(&size.to_be_bytes());
        record.extend_from_slice(field);
    }
    let digest = Sha256::digest(record.as_slice());
    record.extend_from_slice(&digest);
    Ok(record)
}

fn decode(bytes: &[u8]) -> Option<StoredDevice> {
    let (body, digest) = bytes.split_at_checked(bytes.len().checked_sub(DIGEST)?)?;
    if Sha256::digest(body).as_slice() != digest {
        return None;
    }
    let mut fields = Fields(body.strip_prefix(MAGIC)?);
    let address = std::str::from_utf8(fields.field(MAX_ADDRESS)?).ok()?.to_owned();
    let server_name = std::str::from_utf8(fields.field(MAX_SERVER_NAME)?).ok()?.to_owned();
    let fingerprint = RootFingerprint::parse(std::str::from_utf8(fields.field(FINGERPRINT_HEX)?).ok()?)?;
    let root = fields.field(MAX_ROOT_DER)?.to_vec();
    let leaf = fields.field(MAX_CERT)?.to_vec();
    let issuer = fields.field(MAX_CERT)?.to_vec();
    let key = Zeroizing::new(fields.field(MAX_KEY_DER)?.to_vec());
    if !fields.0.is_empty() || leaf.is_empty() || issuer.is_empty() {
        return None;
    }
    let endpoint = ServerEndpoint::new(&address, &server_name, fingerprint, &root).ok()?;
    StoredDevice::from_parts(endpoint, leaf, issuer, key).ok()
}

/// The associated data of a sealed record: the version 2 magic line and the length-prefixed profile name.
fn sealed_aad(profile: &str) -> Option<Vec<u8>> {
    let size = u32::try_from(profile.len()).ok()?;
    let mut aad = Vec::with_capacity(SEALED_MAGIC.len() + 4 + profile.len());
    aad.extend_from_slice(SEALED_MAGIC);
    aad.extend_from_slice(&size.to_be_bytes());
    aad.extend_from_slice(profile.as_bytes());
    Some(aad)
}

/// Seal a version 1 `record` for `profile`: the magic line, a fresh random nonce, the ciphertext and its tag.
fn seal(key: &[u8; KEY_BYTES], profile: &str, record: &[u8]) -> Result<Vec<u8>, StoreError> {
    let mut nonce = [0; NONCE];
    OsRng.try_fill_bytes(&mut nonce).map_err(|_| StoreError::Io(io::ErrorKind::Other))?;
    let aad = sealed_aad(profile).ok_or(StoreError::InvalidName)?;
    // The record is copied only into this buffer, which has room for the tag (so it is never reallocated), is
    // encrypted where it stands, and is wiped when dropped.
    let mut body = Zeroizing::new(Vec::with_capacity(record.len() + TAG));
    body.extend_from_slice(record);
    XChaCha20Poly1305::new(key.into()).encrypt_in_place(XNonce::from_slice(&nonce), &aad, &mut *body).map_err(|_| StoreError::TooLarge)?;
    let mut sealed = Vec::with_capacity(SEALED_MAGIC.len() + NONCE + body.len());
    sealed.extend_from_slice(SEALED_MAGIC);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&body);
    Ok(sealed)
}

/// Open a sealed record for `profile`; `None` if it is not one, or if its tag does not verify under `key`.
fn open(key: &[u8; KEY_BYTES], profile: &str, bytes: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let (nonce, ciphertext) = bytes.strip_prefix(SEALED_MAGIC)?.split_at_checked(NONCE)?;
    if ciphertext.len() < TAG {
        return None;
    }
    let aad = sealed_aad(profile)?;
    // Decrypted in place in a buffer allocated once and wiped when dropped.
    let mut plain = Zeroizing::new(Vec::with_capacity(ciphertext.len()));
    plain.extend_from_slice(ciphertext);
    XChaCha20Poly1305::new(key.into()).decrypt_in_place(XNonce::from_slice(nonce), &aad, &mut *plain).ok()?;
    Some(plain)
}

/// The length-prefixed fields of a record body, read front to back.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn field(&mut self, max: usize) -> Option<&'a [u8]> {
        let (size, rest) = self.0.split_first_chunk::<4>()?;
        let size = usize::try_from(u32::from_be_bytes(*size)).ok().filter(|&size| size <= max)?;
        let (value, rest) = rest.split_at_checked(size)?;
        self.0 = rest;
        Some(value)
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let metadata = fs::metadata(dir)?;
    if !metadata.is_dir() {
        return Err(StoreError::Permissions);
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    // Windows: the per-user data directory's inherited access list limits it to the user (see the module comment).
    fs::create_dir_all(dir)?;
    if !fs::metadata(dir)?.is_dir() {
        return Err(StoreError::Permissions);
    }
    Ok(())
}

#[cfg(unix)]
fn check_private(metadata: &fs::Metadata) -> Result<(), StoreError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 == 0 { Ok(()) } else { Err(StoreError::Permissions) }
}

#[cfg(not(unix))]
fn check_private(_: &fs::Metadata) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    // Make the rename itself durable.
    File::open(dir)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_: &Path) -> Result<(), StoreError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{KEY_BYTES, NONCE, SEALED_MAGIC, TAG, open, seal, valid_profile};

    #[test]
    fn profile_names_are_plain_file_names() {
        for good in ["work", "a", "team-2", "x_y", "0"] {
            assert!(valid_profile(good), "{good}");
        }
        for bad in ["", "-work", "_work", "Work", "../work", "a/b", "a.b", "a b", &"a".repeat(65)] {
            assert!(!valid_profile(bad), "{bad}");
        }
    }

    #[test]
    fn sealing_round_trips_and_binds_key_and_profile() {
        let key = [9; KEY_BYTES];
        let text = b"synthetic record bytes";
        let record = [&b"crewcraft device v1\n"[..], text].concat();
        let sealed = seal(&key, "work", &record).unwrap_or_default();
        assert_eq!(sealed.len(), SEALED_MAGIC.len() + NONCE + record.len() + TAG);
        assert!(sealed.starts_with(SEALED_MAGIC));
        assert!(!sealed.windows(text.len()).any(|window| window == text), "the record is not in the clear");
        assert_eq!(open(&key, "work", &sealed).as_deref().map(Vec::as_slice), Some(record.as_slice()));
        assert!(open(&[8; KEY_BYTES], "work", &sealed).is_none(), "another key");
        assert!(open(&key, "home", &sealed).is_none(), "another profile");
        assert!(open(&key, "work", &sealed[..SEALED_MAGIC.len() + NONCE + TAG - 1]).is_none(), "shorter than a tag");
        let again = seal(&key, "work", &record).unwrap_or_default();
        assert_ne!(again[SEALED_MAGIC.len()..SEALED_MAGIC.len() + NONCE], sealed[SEALED_MAGIC.len()..SEALED_MAGIC.len() + NONCE], "a fresh nonce");
    }
}
