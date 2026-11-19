#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crewcraft_server::lab_state::LabState;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let parent = std::env::temp_dir().join(format!("crewcraft-state-{}-{index}", std::process::id()));
        fs::create_dir(&parent).unwrap();
        Self(parent)
    }

    fn state_path(&self) -> PathBuf {
        self.0.join("data")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn setup_is_explicit_and_another_handle_cannot_take_the_open_state() {
    let dir = TestDirectory::new();
    let path = dir.state_path();
    assert_eq!(LabState::open(&path).err().unwrap().kind(), ErrorKind::NotFound);
    let state = LabState::create(&path).unwrap();
    assert_eq!(state.path(), path);
    fs::write(state.path().join("accounts.journal"), b"synthetic").unwrap();
    assert_eq!(LabState::create(&path).err().unwrap().kind(), ErrorKind::AlreadyExists);
    assert_eq!(LabState::open(&path).err().unwrap().kind(), ErrorKind::WouldBlock);
    drop(state);
    let reopened = LabState::open(&path).unwrap();
    assert_eq!(fs::read(reopened.path().join("accounts.journal")).unwrap(), b"synthetic");
}

#[cfg(unix)]
#[test]
fn open_refuses_a_shared_directory_or_a_lock_symlink() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let dir = TestDirectory::new();
    let path = dir.state_path();
    let state = LabState::create(&path).unwrap();
    drop(state);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(LabState::open(&path).err().unwrap().kind(), ErrorKind::PermissionDenied);

    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_file(path.join("state.lock")).unwrap();
    let target = path.join("regular");
    fs::write(&target, b"synthetic").unwrap();
    symlink(&target, path.join("state.lock")).unwrap();
    assert_eq!(LabState::open(&path).err().unwrap().kind(), ErrorKind::InvalidInput);
    assert_eq!(fs::read(target).unwrap(), b"synthetic");
}
