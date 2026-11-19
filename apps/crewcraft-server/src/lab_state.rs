//! Exclusive ownership for a private lab state directory. Task T222.

use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

const LOCK_FILE: &str = "state.lock";
/// How long `open` waits for a lock that looks held before refusing. A lock can look held for a moment after its
/// owner closed it: a child process this program is starting shares the open lock file until it runs its own program.
const LOCK_WAIT: Duration = Duration::from_millis(500);
const LOCK_RETRY: Duration = Duration::from_millis(20);

/// The lab server and offline administrative commands hold this for their entire use of the state directory.
pub struct LabState {
    path: PathBuf,
    _lock: File,
}

impl LabState {
    /// Create a new directory for explicit lab setup. An existing directory belongs to its current state.
    pub fn create(path: &Path) -> io::Result<Self> {
        let builder = &mut DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)?;
        Self::open(path)
    }

    /// Open an existing private directory and obtain exclusive ownership before opening its journals. A lock held by
    /// another owner is refused (`WouldBlock`) after waiting up to `LOCK_WAIT`.
    pub fn open(path: &Path) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_dir() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "lab state path must be a directory"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "lab state directory must be private"));
            }
        }
        // Offline and serving code use the same file. It stays in place when the handle closes.
        let lock_path = path.join(LOCK_FILE);
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = match options.create_new(true).open(&lock_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if !fs::symlink_metadata(&lock_path)?.is_file() {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "lab state lock must be a regular file"));
                }
                options.create_new(false).open(&lock_path)?
            }
            Err(error) => return Err(error),
        };
        let deadline = Instant::now() + LOCK_WAIT;
        loop {
            match lock.try_lock() {
                Ok(()) => break,
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => thread::sleep(LOCK_RETRY),
                Err(TryLockError::WouldBlock) => return Err(io::Error::new(io::ErrorKind::WouldBlock, "lab state is in use")),
                Err(TryLockError::Error(error)) => return Err(error),
            }
        }
        Ok(Self { path: path.to_path_buf(), _lock: lock })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
