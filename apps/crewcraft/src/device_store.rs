//! Enrolled devices saved between runs: one file per server profile in a per-user directory the caller chooses
//! (the window passes the platform's data directory). Task T304.
//!
//! Owns: the record file format, atomic replacement (a new file, synced, then renamed over the old one), owner-only
//! permissions on Unix (0700 directory, 0600 file, and a refusal to read anything looser), and a bound on every read.
//! Called by the window. Calls `device` to check a record before handing it out.
//!
//! At rest the record is protected only by file permissions, including the device's private key. See
//! docs/SECURITY-DESIGN.md section 2 ("Implementation status") for what that does and does not cover.
//!
//! File format, version 1: the magic line below, then seven fields, each a `u32` big-endian byte length and the
//! bytes (address, server name, root fingerprint as 64 lowercase hex digits, root certificate DER, device certificate
//! DER, issuer certificate DER, PKCS#8 device key), then the SHA-256 of everything before it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::bootstrap::MAX_CERT;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::device::{MAX_KEY_DER, StoredDevice};
use crate::server_endpoint::{MAX_ADDRESS, MAX_ROOT_DER, ServerEndpoint};

const MAGIC: &[u8] = b"crewcraft device v1\n";
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
    /// The file is not a whole, intact record, or its parts do not fit together.
    Corrupt,
    Io(io::ErrorKind),
}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

/// The directory that holds the device records.
#[derive(Debug)]
pub struct DeviceStore {
    dir: PathBuf,
}

impl DeviceStore {
    /// Use `dir`, creating it (and missing parents) if needed. On Unix the directory itself is made owner-only (0700)
    /// if it is not already.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        create_private_dir(dir)?;
        Ok(Self { dir: dir.to_owned() })
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
    pub fn save(&self, profile: &str, device: &StoredDevice) -> Result<(), StoreError> {
        let target = self.path(profile)?;
        let record = encode(device)?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.subsec_nanos());
        let temporary = self.dir.join(format!(".{profile}.{}.{sequence}.{nanos}.tmp", std::process::id()));
        let written = write_new(&temporary, &record).and_then(|()| fs::rename(&temporary, &target));
        if let Err(error) = written {
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        sync_dir(&self.dir)?;
        Ok(())
    }

    /// Read `profile`'s record and check it whole before returning it.
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
        decode(&bytes).ok_or(StoreError::Corrupt)
    }

    /// Delete `profile`'s record. False if there was none.
    pub fn remove(&self, profile: &str) -> Result<bool, StoreError> {
        match fs::remove_file(self.path(profile)?) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
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

fn encode(device: &StoredDevice) -> Result<Zeroizing<Vec<u8>>, StoreError> {
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
    if length > MAX_RECORD {
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
    use super::valid_profile;

    #[test]
    fn profile_names_are_plain_file_names() {
        for good in ["work", "a", "team-2", "x_y", "0"] {
            assert!(valid_profile(good), "{good}");
        }
        for bad in ["", "-work", "_work", "Work", "../work", "a/b", "a.b", "a b", &"a".repeat(65)] {
            assert!(!valid_profile(bad), "{bad}");
        }
    }
}
