//! The loopback lab's persistent issuing authority. The caller supplies the service key and a private state directory.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

use crewcraft_pki::{Authority, IssuingLoadError};
use crewcraft_server_core::seal::{KEY_ID_BYTES, MAX_PLAINTEXT, NONCE_BYTES, SealError, Sealed, ServiceKey, TAG_BYTES};
use sha2::{Digest, Sha256};

// V1: magic, two u16 big-endian DER lengths, root DER, issuer DER, service-key id, nonce, and sealed PKCS#8.
// The header and both certificates are authenticated as the sealing context.
const MAGIC: &[u8; 8] = b"CCPKI001";
const HEADER: usize = MAGIC.len() + 4;
const MAX_CERT: usize = 16 * 1024;
const MAX_RECORD: usize = HEADER + 2 * MAX_CERT + KEY_ID_BYTES + NONCE_BYTES + MAX_PLAINTEXT + TAG_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerCustodyError {
    Exists,
    Missing,
    Malformed,
    PinMismatch,
    Generation,
    Pki(IssuingLoadError),
    Seal(SealError),
    Io(io::ErrorKind),
}

impl From<io::Error> for IssuerCustodyError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

/// Loaded issuer and the public trust anchor for the lab client.
pub struct LabIssuer {
    root_der: Vec<u8>,
    issuer: Authority,
}

impl fmt::Debug for LabIssuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LabIssuer").finish_non_exhaustive()
    }
}

impl LabIssuer {
    /// Create a fresh lab authority. The caller owns the private parent directory. A committed or partial file at
    /// `path` is never replaced. The root signing key is only used to create the issuer and is dropped before writing.
    pub fn initialize(path: &Path, key: &ServiceKey, now_ms: u64) -> Result<Self, IssuerCustodyError> {
        let root = Authority::create_root("CrewCraft Lab Root", now_ms).map_err(|_| IssuerCustodyError::Generation)?;
        let issuer = root.create_issuing("CrewCraft Lab Issuer", now_ms).map_err(|_| IssuerCustodyError::Generation)?;
        let root_der = root.certificate().to_vec();
        drop(root);

        let mut record = seal_context(&root_der, issuer.certificate())?;
        let sealed = issuer.with_issuing_key(|pkcs8| key.seal(pkcs8, &record)).map_err(IssuerCustodyError::Pki)?.map_err(IssuerCustodyError::Seal)?;
        record.extend_from_slice(&sealed.key_id);
        record.extend_from_slice(&sealed.nonce);
        record.extend_from_slice(&sealed.ciphertext);
        publish(path, &record)?;
        Ok(Self { root_der, issuer })
    }

    /// Open the exact existing state. `expected_root`, when supplied, is SHA-256 of the configured root DER.
    pub fn load(path: &Path, key: &ServiceKey, expected_root: Option<[u8; 32]>, now_ms: u64) -> Result<Self, IssuerCustodyError> {
        let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => IssuerCustodyError::Missing,
            kind => IssuerCustodyError::Io(kind),
        })?;
        if !metadata.is_file() || metadata.len() > MAX_RECORD as u64 {
            return Err(IssuerCustodyError::Malformed);
        }
        let mut record = Vec::new();
        File::open(path)?.take(MAX_RECORD as u64 + 1).read_to_end(&mut record)?;
        let IssuerRecord { root_der, issuing_der, context, sealed } = parse_record(&record).ok_or(IssuerCustodyError::Malformed)?;
        let pkcs8 = key.open(&sealed, context).map_err(IssuerCustodyError::Seal)?;
        if expected_root.is_some_and(|pin| pin != root_fingerprint(root_der)) {
            return Err(IssuerCustodyError::PinMismatch);
        }
        let issuer = Authority::load_issuing(root_der, issuing_der, pkcs8.as_slice(), now_ms).map_err(IssuerCustodyError::Pki)?;
        Ok(Self { root_der: root_der.to_vec(), issuer })
    }

    pub fn root_certificate(&self) -> &[u8] {
        &self.root_der
    }

    pub fn root_fingerprint(&self) -> [u8; 32] {
        root_fingerprint(&self.root_der)
    }

    pub fn into_parts(self) -> (Vec<u8>, Authority) {
        (self.root_der, self.issuer)
    }
}

fn root_fingerprint(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

fn seal_context(root_der: &[u8], issuing_der: &[u8]) -> Result<Vec<u8>, IssuerCustodyError> {
    if ![root_der, issuing_der].iter().all(|der| (1..=MAX_CERT).contains(&der.len())) {
        return Err(IssuerCustodyError::Malformed);
    }
    let mut context = Vec::with_capacity(HEADER + root_der.len() + issuing_der.len());
    context.extend_from_slice(MAGIC);
    context.extend_from_slice(&(root_der.len() as u16).to_be_bytes());
    context.extend_from_slice(&(issuing_der.len() as u16).to_be_bytes());
    context.extend_from_slice(root_der);
    context.extend_from_slice(issuing_der);
    Ok(context)
}

struct IssuerRecord<'a> {
    root_der: &'a [u8],
    issuing_der: &'a [u8],
    context: &'a [u8],
    sealed: Sealed,
}

fn parse_record(record: &[u8]) -> Option<IssuerRecord<'_>> {
    let (lengths, _) = record.strip_prefix(MAGIC)?.split_first_chunk::<4>()?;
    let root_len = usize::from(u16::from_be_bytes([lengths[0], lengths[1]]));
    let issuer_len = usize::from(u16::from_be_bytes([lengths[2], lengths[3]]));
    if ![root_len, issuer_len].iter().all(|len| (1..=MAX_CERT).contains(len)) {
        return None;
    }
    let issuer_at = HEADER + root_len;
    let (context, envelope) = record.split_at_checked(issuer_at + issuer_len)?;
    let (key_id, envelope) = envelope.split_first_chunk::<KEY_ID_BYTES>()?;
    let (nonce, ciphertext) = envelope.split_first_chunk::<NONCE_BYTES>()?;
    if !(TAG_BYTES + 1..=MAX_PLAINTEXT + TAG_BYTES).contains(&ciphertext.len()) {
        return None;
    }
    let sealed = Sealed { key_id: *key_id, nonce: *nonce, ciphertext: ciphertext.to_vec() };
    Some(IssuerRecord { root_der: &context[HEADER..issuer_at], issuing_der: &context[issuer_at..], context, sealed })
}

fn publish(path: &Path, record: &[u8]) -> Result<(), IssuerCustodyError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| match error.kind() {
        io::ErrorKind::AlreadyExists => IssuerCustodyError::Exists,
        kind => IssuerCustodyError::Io(kind),
    })?;
    file.write_all(record)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}
