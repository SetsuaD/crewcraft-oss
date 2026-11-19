//! Lab operator commands: explicit init and reopen keep the root; an offline invitation records only its public
//! bootstrap key, shows the code only through the protected display and only after the record is durable, and leaks
//! the code nowhere else. Synthetic addresses only.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use crewcraft_enroll::EnrollmentCode;
use crewcraft_server::lab_admin::{
    AdminError, DEFAULT_INVITE_TTL_MS, DisplayFailed, IssuedCode, MAX_INVITE_TTL_MS, ProtectedDisplay, init, invite, reopen,
};
use crewcraft_server_core::account_journal::{AccountJournal, AppendError};
use crewcraft_server_core::account_store::{AccountStore, AppendLog, StoreError};
use crewcraft_server_core::seal::ServiceKey;

const NOW: u64 = 1_750_000_000_000;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let index = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("crewcraft-lab-admin-{}-{index}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Records what it was shown; can be told to fail.
#[derive(Default)]
struct Recorder {
    shown: Vec<(String, String, u64)>,
    debug: Vec<String>,
    fail: bool,
}

impl ProtectedDisplay for Recorder {
    fn show(&mut self, issued: &IssuedCode<'_>) -> Result<(), DisplayFailed> {
        self.debug.push(format!("{issued:?}"));
        if self.fail {
            return Err(DisplayFailed);
        }
        self.shown.push((issued.email().to_string(), issued.code().to_string(), issued.expires_ms()));
        Ok(())
    }
}

fn every_file_under(dir: &Path) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(every_file_under(&path));
        } else {
            out.push(fs::read(&path).unwrap());
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn init_creates_new_state_only_and_reopen_keeps_the_root() {
    let temp = TestDirectory::new();
    let path = temp.0.join("state");
    let root = {
        let (_installation, root) = init(&path, NOW).unwrap();
        root
    };
    assert_eq!(root.sha256.len(), 32);
    assert!(!root.certificate_der.is_empty());
    assert!(matches!(init(&path, NOW), Err(AdminError::Installation(_))), "init never opens or replaces existing state");
    let reopened = reopen(&path, root.sha256, NOW + 1).unwrap();
    assert_eq!(reopened.issuer.root_certificate(), root.certificate_der.as_slice(), "the same root after reopen");
    drop(reopened);
    let mut wrong = root.sha256;
    wrong[0] ^= 1;
    assert!(matches!(reopen(&path, wrong, NOW + 1), Err(AdminError::Installation(_))), "a wrong pin opens nothing");
    assert!(matches!(reopen(&temp.0.join("absent"), root.sha256, NOW), Err(AdminError::Installation(_))), "reopen never creates");
    let debug = format!("{root:?}");
    assert!(debug.contains("bytes") && debug.len() < 120, "{debug}");
}

#[test]
fn an_invitation_records_only_the_public_key_and_shows_the_code_once() {
    let temp = TestDirectory::new();
    let path = temp.0.join("state");
    let (mut installation, root) = init(&path, NOW).unwrap();
    let mut display = Recorder::default();
    let receipt = invite(&mut installation.accounts, "  Pilot@Example.ORG ", None, NOW, &mut display).unwrap();
    assert_eq!(receipt.email, "pilot@example.org", "the address is canonical");
    assert_eq!(receipt.expires_ms, NOW + DEFAULT_INVITE_TTL_MS);
    assert_eq!(display.shown.len(), 1);
    let (email, code_text, expires) = display.shown[0].clone();
    assert_eq!((email.as_str(), expires), ("pilot@example.org", receipt.expires_ms));
    // The shown code is a real code for exactly the recorded key.
    let code = EnrollmentCode::parse(&code_text).unwrap();
    assert_eq!(code.bootstrap_public_key(), receipt.bootstrap_pub);
    assert!(installation.accounts.is_invite_pending(&receipt.bootstrap_pub, NOW + 1));
    // Debug of everything the operator path touched leaves the code out.
    for debug in display.debug.iter().chain([format!("{receipt:?}"), format!("{root:?}")].iter()) {
        assert!(!debug.contains(&code_text), "{debug}");
    }
    drop(installation);
    // Durable: the invitation survives a reopen. The code is in no file of the state directory.
    let reopened = reopen(&path, root.sha256, NOW + 2).unwrap();
    assert!(reopened.accounts.is_invite_pending(&receipt.bootstrap_pub, NOW + 2));
    drop(reopened);
    for bytes in every_file_under(&path) {
        assert!(!contains(&bytes, code_text.as_bytes()), "the code text is on disk");
        assert!(!contains(&bytes, code.as_bytes()), "the code's secret bytes are on disk");
    }
}

#[test]
fn lifetimes_are_bounded_and_nothing_is_shown_for_a_bad_request() {
    let temp = TestDirectory::new();
    let (mut installation, _) = init(&temp.0.join("state"), NOW).unwrap();
    let mut display = Recorder::default();
    for ttl in [0, MAX_INVITE_TTL_MS + 1, u64::MAX] {
        assert!(matches!(invite(&mut installation.accounts, "pilot@example.org", Some(ttl), NOW, &mut display), Err(AdminError::BadTtl)));
    }
    for bad in ["not an address", "", "a@b@example.org"] {
        assert!(matches!(invite(&mut installation.accounts, bad, None, NOW, &mut display), Err(AdminError::BadEmail)));
    }
    assert!(display.shown.is_empty() && display.debug.is_empty(), "no code was made visible for a refused request");
    let receipt = invite(&mut installation.accounts, "pilot@example.org", Some(MAX_INVITE_TTL_MS), NOW, &mut display).unwrap();
    assert_eq!(receipt.expires_ms, NOW + MAX_INVITE_TTL_MS);
    assert!(!installation.accounts.is_invite_pending(&receipt.bootstrap_pub, NOW + MAX_INVITE_TTL_MS), "expires at its bound");
}

/// Wraps the real journal and refuses every append without writing.
struct RefusingLog {
    inner: AccountJournal,
    refuse: Rc<Cell<bool>>,
}

impl AppendLog for RefusingLog {
    fn append(&mut self, record: &[u8]) -> Result<(), AppendError> {
        if self.refuse.get() {
            return Err(AppendError::NotWritten(std::io::ErrorKind::StorageFull));
        }
        self.inner.append(record)
    }
}

#[test]
fn a_refused_write_never_shows_the_code() {
    let temp = TestDirectory::new();
    let file = temp.0.join("accounts.journal");
    drop(AccountStore::create(&file, ServiceKey::from_bytes([3; 32])).unwrap());
    let (journal, records) = AccountJournal::open(&file).unwrap();
    let refuse = Rc::new(Cell::new(true));
    let mut store =
        AccountStore::from_records(RefusingLog { inner: journal, refuse: Rc::clone(&refuse) }, ServiceKey::from_bytes([3; 32]), records).unwrap();
    let mut display = Recorder::default();
    let outcome = invite(&mut store, "pilot@example.org", None, NOW, &mut display);
    assert!(matches!(outcome, Err(AdminError::Store(StoreError::Append(AppendError::NotWritten(_))))), "{outcome:?}");
    assert!(display.shown.is_empty() && display.debug.is_empty(), "the code was shown although nothing was recorded");
    refuse.set(false);
    assert!(invite(&mut store, "pilot@example.org", None, NOW, &mut display).is_ok());
    assert_eq!(display.shown.len(), 1);
}

#[test]
fn a_failed_display_withdraws_the_invitation() {
    let temp = TestDirectory::new();
    let path = temp.0.join("state");
    let (mut installation, root) = init(&path, NOW).unwrap();
    let mut display = Recorder { fail: true, ..Recorder::default() };
    let outcome = invite(&mut installation.accounts, "pilot@example.org", None, NOW, &mut display);
    assert!(matches!(outcome, Err(AdminError::DisplayFailed { withdrawn: true })), "{outcome:?}");
    assert_eq!(display.debug.len(), 1);
    assert!(!display.debug[0].contains("CC1-"), "Debug must not carry the code: {}", display.debug[0]);
    drop(installation);
    let reopened = reopen(&path, root.sha256, NOW + 1).unwrap();
    // No usable, unseen code is left behind (the withdrawal is durable too).
    assert!(format!("{:?}", reopened.accounts).contains("invites: 0"), "{:?}", reopened.accounts);
}
