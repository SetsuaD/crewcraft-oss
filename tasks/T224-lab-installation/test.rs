#![allow(clippy::unwrap_used)]

use std::fs;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crewcraft_server::lab_installation::{InstallationError, LabInstallation};
use crewcraft_server_core::invites::Invite;

const NOW: u64 = 1_750_000_000_000;
const PERSON: &str = "pilot@example.org";
const BOOTSTRAP_KEY: [u8; 32] = [17; 32];

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("crewcraft-lab-installation-{}-{index}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn all_three_stores_reopen_together_without_regenerating_state() {
    let temp = TestDirectory::new();
    let path = temp.0.join("state");
    let mut state = LabInstallation::initialize(&path, NOW).unwrap();
    let pin = state.issuer.root_fingerprint();
    let invite = Invite { email: PERSON.into(), bootstrap_pub: BOOTSTRAP_KEY, expires_ms: NOW + 100_000 };
    state.accounts.issue_invite(invite, NOW).unwrap();
    let slug = state.rooms.create_room(PERSON, "Pilot").unwrap();
    assert!(matches!(LabInstallation::open(&path, pin, NOW), Err(InstallationError::Directory(ErrorKind::WouldBlock))));
    drop(state);

    let state = LabInstallation::open(&path, pin, NOW + 1000).unwrap();
    assert_eq!(state.issuer.root_fingerprint(), pin);
    assert!(state.accounts.is_invite_pending(&BOOTSTRAP_KEY, NOW + 1000));
    assert!(state.rooms.server().room(&slug).is_ok());
    drop(state);

    let rooms = path.join("rooms.journal");
    fs::remove_file(&rooms).unwrap();
    assert!(matches!(LabInstallation::open(&path, pin, NOW), Err(InstallationError::Directory(ErrorKind::NotFound))));
    assert!(!rooms.exists());
}
