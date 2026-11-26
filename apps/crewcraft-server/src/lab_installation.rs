//! Open the lab issuer, account store and room journal under one state-directory lock. Task T224.

use std::fs;
#[cfg(unix)]
use std::fs::File;
use std::io;
use std::path::Path;

use crewcraft_server_core::account_store::{AccountStore, StoreError};
use crewcraft_server_core::durable::{DurableError, DurableServer};
use crewcraft_server_core::file_store::FileStore;
use crewcraft_server_core::seal::{KeyFileError, ServiceKey};

use crate::issuer_custody::{IssuerCustodyError, LabIssuer};
use crate::lab_state::LabState;

const SERVICE_KEY: &str = "service.key";
const ISSUER: &str = "issuer.state";
const ACCOUNTS: &str = "accounts.journal";
const ROOMS: &str = "rooms.journal";
/// The folder of uploaded files (`crewcraft_server_core::file_store`).
const FILES: &str = "files";

#[derive(Debug)]
pub enum InstallationError {
    Directory(io::ErrorKind),
    Key(KeyFileError),
    Issuer(IssuerCustodyError),
    Accounts(StoreError),
    Rooms(DurableError),
}

impl From<io::Error> for InstallationError {
    fn from(error: io::Error) -> Self {
        Self::Directory(error.kind())
    }
}

/// Loaded lab state. Keep `ownership` alive as long as any journal is in use.
pub struct LabInstallation {
    pub ownership: LabState,
    pub issuer: LabIssuer,
    pub accounts: AccountStore,
    pub rooms: DurableServer,
}

impl LabInstallation {
    /// Create the first state in a previously absent directory. A failure leaves this path reserved for review.
    pub fn initialize(path: &Path, now_ms: u64) -> Result<Self, InstallationError> {
        let ownership = LabState::create(path)?;
        let key = ServiceKey::provision(&path.join(SERVICE_KEY)).map_err(InstallationError::Key)?;
        let issuer = LabIssuer::initialize(&path.join(ISSUER), &key, now_ms).map_err(InstallationError::Issuer)?;
        let accounts = AccountStore::create(&path.join(ACCOUNTS), key).map_err(InstallationError::Accounts)?;
        let rooms = DurableServer::open(&path.join(ROOMS)).map_err(InstallationError::Rooms)?;
        // Uploaded files (docs/FILES.md, task T330b), in the same data directory.
        let rooms = rooms.with_files(FileStore::open(&path.join(FILES))?)?;

        #[cfg(unix)]
        {
            File::open(path)?.sync_all()?;
            let parent = path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
            File::open(parent)?.sync_all()?;
        }
        Ok(Self { ownership, issuer, accounts, rooms })
    }

    /// Open the existing state. A missing store makes startup fail before changing any journal.
    pub fn open(path: &Path, expected_root: [u8; 32], now_ms: u64) -> Result<Self, InstallationError> {
        let ownership = LabState::open(path)?;
        for name in [SERVICE_KEY, ISSUER, ACCOUNTS, ROOMS] {
            if !fs::symlink_metadata(path.join(name))?.is_file() {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "lab state must contain regular files").into());
            }
        }
        let key = ServiceKey::load(&path.join(SERVICE_KEY)).map_err(InstallationError::Key)?;
        let issuer = LabIssuer::load(&path.join(ISSUER), &key, Some(expected_root), now_ms).map_err(InstallationError::Issuer)?;
        let accounts = AccountStore::open(&path.join(ACCOUNTS), key).map_err(InstallationError::Accounts)?;
        let rooms = DurableServer::open(&path.join(ROOMS)).map_err(InstallationError::Rooms)?;
        // Uploaded files (docs/FILES.md, task T330b), in the same data directory.
        let rooms = rooms.with_files(FileStore::open(&path.join(FILES))?)?;
        Ok(Self { ownership, issuer, accounts, rooms })
    }
}
