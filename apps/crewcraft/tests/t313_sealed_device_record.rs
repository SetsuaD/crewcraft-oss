//! T313: the saved device record is sealed under a random key from a key store, so the device's private key is never
//! on disk in the clear. These tests use the in-memory vault; the operating system's key stores are checked by the
//! ignored test at the end, run by hand on each desktop.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft::app::{Controller, Join, PLAIN_RECORD_SETTING, Wake, store_problem};
use crewcraft::device_store::{DeviceStore, StoreError};
use crewcraft::key_vault::{KEY_BYTES, KeyVault, MemoryVault, OpenVault, SystemVault, VaultError};
use crewcraft::worker::WorkerConfig;
use crewcraft_desktop_ui::Update;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_pki::{Authority, Claims};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest, Sha256};

const ADDRESS: &str = "127.0.0.1:9";
const SEALED_MAGIC: &[u8] = b"crewcraft device v2\n";
const NONCE: usize = 24;

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

/// A private scratch directory, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        Self(std::env::temp_dir().join(format!("crewcraft-t313-{tag}-{}-{}", std::process::id(), now_ms())))
    }

    fn dir(&self) -> PathBuf {
        self.0.join("devices")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A device made here, not by enrolling: a fresh P-256 key, a certificate for it from a test authority, and the
/// unsealed (version 1) record of it, written by this test from the documented format.
struct Fixture {
    pkcs8: Vec<u8>,
    certificate: Vec<u8>,
    plain_record: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let root = Authority::create_root("Test Root", now_ms()).unwrap();
        let mut issuer = root.create_issuing("Test Issuer", now_ms()).unwrap();
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let csr = CertificateParams::default().serialize_request(&key).unwrap();
        let issued = issuer.issue_device(csr.der(), &Claims { person: "reader@example.org", device_id: 7 }, now_ms()).unwrap();
        let pkcs8 = key.serialize_der();
        let fingerprint = RootFingerprint::from_der(root.certificate()).to_string();
        let fields: [&[u8]; 7] =
            [ADDRESS.as_bytes(), b"localhost", fingerprint.as_bytes(), root.certificate(), &issued.certificate, issuer.certificate(), &pkcs8];
        let mut plain_record = b"crewcraft device v1\n".to_vec();
        for field in fields {
            plain_record.extend_from_slice(&(field.len() as u32).to_be_bytes());
            plain_record.extend_from_slice(field);
        }
        let digest = Sha256::digest(&plain_record);
        plain_record.extend_from_slice(&digest);
        Self { pkcs8, certificate: issued.certificate, plain_record }
    }

    /// The 32-byte private scalar inside the PKCS#8 key (its SEC1 `ECPrivateKey`: version 1, then a 32-byte string).
    fn scalar(&self) -> Vec<u8> {
        let at = self.pkcs8.windows(5).position(|window| window == [0x02, 0x01, 0x01, 0x04, 0x20]).unwrap() + 5;
        self.pkcs8[at..at + 32].to_vec()
    }

    /// Panic if `bytes` holds the key in any form: the PKCS#8 DER, any 16-byte run of it, or the private scalar.
    fn assert_no_key_in(&self, bytes: &[u8]) {
        let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|window| window == needle);
        assert!(!contains(&self.pkcs8), "the PKCS#8 key is in the file");
        assert!(!contains(&self.scalar()), "the private scalar is in the file");
        for run in self.pkcs8.windows(16) {
            assert!(!contains(run), "part of the PKCS#8 key is in the file");
        }
    }
}

/// Write a file the store will read: on Unix owner-only, as the store requires.
fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(dir).unwrap().map(|entry| entry.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    names
}

/// A sealed store in `scratch` holding the fixture as `profile`, saved through the store (not migrated).
fn sealed_with(scratch: &Scratch, vault: &MemoryVault, fixture: &Fixture, profile: &str) -> DeviceStore {
    // Load the fixture through a plain store in another folder, then save it sealed.
    let plain_dir = scratch.0.join("plain");
    let plain = DeviceStore::open(&plain_dir).unwrap();
    write_private(&plain.path(profile).unwrap(), &fixture.plain_record);
    let device = plain.load(profile).unwrap();
    let store = DeviceStore::open_sealed(&scratch.dir(), vault.shared()).unwrap();
    assert!(store.is_sealed() && !plain.is_sealed());
    store.save(profile, &device).unwrap();
    store
}

fn no_join() -> Join {
    Box::new(|_link: &str| Err("not used".to_owned()))
}

fn no_wake() -> Wake {
    Arc::new(|| {})
}

/// A computer with no key store: opening one fails.
fn no_key_store() -> OpenVault<'static> {
    Box::new(|| -> Result<Arc<dyn KeyVault>, VaultError> { Err(VaultError::Unavailable) })
}

#[test]
fn a_sealed_record_holds_no_copy_of_the_key_and_loads_again() {
    let scratch = Scratch::new("sealed");
    let fixture = Fixture::new();
    let vault = MemoryVault::new();
    let store = sealed_with(&scratch, &vault, &fixture, "work");
    assert!(vault.contains("work"), "saving made a key for the profile");
    assert_eq!(entries(&scratch.dir()), ["work.device"], "no temporary file is left behind");

    let file = fs::read(store.path("work").unwrap()).unwrap();
    assert!(file.starts_with(SEALED_MAGIC));
    fixture.assert_no_key_in(&file);
    let contains = |needle: &[u8]| file.windows(needle.len()).any(|window| window == needle);
    assert!(!contains(ADDRESS.as_bytes()) && !contains(&fixture.certificate[..64]), "the rest of the record is sealed too");

    let reloaded = DeviceStore::open_sealed(&scratch.dir(), vault.shared()).unwrap().load("work").unwrap();
    assert_eq!(reloaded.certificate(), fixture.certificate.as_slice());
    assert_eq!(reloaded.endpoint().address(), ADDRESS);
    assert!(reloaded.identity().is_ok(), "the reloaded key still matches its certificate");

    // Saving again keeps the profile's key and seals with a fresh nonce.
    let key = vault.load("work").unwrap().unwrap();
    store.save("work", &reloaded).unwrap();
    let again = fs::read(store.path("work").unwrap()).unwrap();
    assert_eq!(*vault.load("work").unwrap().unwrap(), *key);
    assert_ne!(again[SEALED_MAGIC.len()..SEALED_MAGIC.len() + NONCE], file[SEALED_MAGIC.len()..SEALED_MAGIC.len() + NONCE]);
    assert_eq!(store.load("work").unwrap().certificate(), fixture.certificate.as_slice());

    // A plain store cannot read a sealed record and says why.
    assert_eq!(DeviceStore::open(&scratch.dir()).unwrap().load("work").err(), Some(StoreError::Sealed));
}

#[test]
fn a_wrong_key_a_changed_byte_or_a_renamed_record_is_refused() {
    let scratch = Scratch::new("tamper");
    let fixture = Fixture::new();
    let vault = MemoryVault::new();
    let store = sealed_with(&scratch, &vault, &fixture, "work");
    let file = store.path("work").unwrap();
    let good = fs::read(&file).unwrap();
    let key = vault.load("work").unwrap().unwrap();
    let refused = |bytes: &[u8]| {
        write_private(&file, bytes);
        store.load("work").err()
    };

    vault.store("work", &[0x5a; KEY_BYTES]).unwrap();
    assert_eq!(refused(&good), Some(StoreError::Corrupt), "another key");
    vault.store("work", &key).unwrap();

    let flip = |at: usize| {
        let mut bytes = good.clone();
        bytes[at] ^= 0x01;
        bytes
    };
    assert_eq!(refused(&flip(3)), Some(StoreError::Corrupt), "the magic line");
    assert_eq!(refused(&flip(SEALED_MAGIC.len() - 3)), Some(StoreError::Corrupt), "the version");
    assert_eq!(refused(&flip(SEALED_MAGIC.len() + 5)), Some(StoreError::Corrupt), "the nonce");
    assert_eq!(refused(&flip(good.len() / 2)), Some(StoreError::Corrupt), "the ciphertext");
    assert_eq!(refused(&flip(good.len() - 1)), Some(StoreError::Corrupt), "the tag");
    assert_eq!(refused(&good[..good.len() - 1]), Some(StoreError::Corrupt), "truncated");
    assert_eq!(refused(&good[..SEALED_MAGIC.len() + NONCE]), Some(StoreError::Corrupt), "no ciphertext");
    let mut as_v1 = good.clone();
    as_v1[..SEALED_MAGIC.len()].copy_from_slice(b"crewcraft device v1\n");
    assert_eq!(refused(&as_v1), Some(StoreError::Corrupt), "relabelled as an unsealed record");
    assert!(refused(&good).is_none(), "the original still loads");

    // The same bytes under another profile name, even with the same key there, do not open.
    vault.store("home", &key).unwrap();
    write_private(&store.path("home").unwrap(), &good);
    assert_eq!(store.load("home").err(), Some(StoreError::Corrupt));
}

#[test]
fn a_missing_key_or_key_store_is_a_clear_error_and_nothing_falls_back() {
    let scratch = Scratch::new("missing");
    let fixture = Fixture::new();
    let vault = MemoryVault::new();
    let store = sealed_with(&scratch, &vault, &fixture, "work");
    let device = store.load("work").unwrap();

    assert_eq!(vault.remove("work"), Ok(true));
    assert_eq!(store.load("work").err(), Some(StoreError::KeyMissing));
    assert!(store_problem(StoreError::KeyMissing).contains("Enroll this device again"));

    vault.set_unavailable(true);
    let before = fs::read(store.path("work").unwrap()).unwrap();
    assert_eq!(store.load("work").err(), Some(StoreError::KeyStoreUnavailable));
    assert_eq!(store.save("work", &device), Err(StoreError::KeyStoreUnavailable));
    assert_eq!(store.save("home", &device), Err(StoreError::KeyStoreUnavailable));
    assert_eq!(store.check_key_store("work"), Err(StoreError::KeyStoreUnavailable));
    assert_eq!(fs::read(store.path("work").unwrap()).unwrap(), before, "a failed save leaves the old record");
    assert_eq!(entries(&scratch.dir()), ["work.device"], "and writes nothing else");
    assert!(store_problem(StoreError::KeyStoreUnavailable).contains("key store"));
    vault.set_unavailable(false);
    assert_eq!(store.check_key_store("work"), Ok(()));

    // The app: no key store means a clear message, no plain file, and a store that saves nothing.
    let app_dir = scratch.0.join("app");
    let (_controller, updates) = Controller::start_with_vault(Some(app_dir.clone()), no_key_store(), no_join(), no_wake(), WorkerConfig::default());
    assert_eq!(updates.first(), Some(&Update::NeedsEnrollment));
    assert!(
        matches!(updates.get(1), Some(Update::Failed(text)) if text.contains("no key store") && text.contains(PLAIN_RECORD_SETTING)),
        "{updates:?}"
    );
    assert_eq!(updates.len(), 2);

    // A key store that is there but does not answer is reported the same way before anyone enrolls.
    let locked = MemoryVault::new();
    locked.set_unavailable(true);
    let (_controller, updates) = Controller::start_with_vault(Some(app_dir.clone()), locked.opener(), no_join(), no_wake(), WorkerConfig::default());
    assert!(matches!(updates.as_slice(), [Update::NeedsEnrollment, Update::Failed(text)] if text.contains("no key store")), "{updates:?}");

    // Opting into a plain file is explicit: then the key store is not even opened.
    fs::write(app_dir.join(PLAIN_RECORD_SETTING), b"").unwrap();
    let opened = Arc::new(AtomicBool::new(false));
    let probe = opened.clone();
    let open_vault: OpenVault<'_> = Box::new(move || -> Result<Arc<dyn KeyVault>, VaultError> {
        probe.store(true, Ordering::SeqCst);
        Err(VaultError::Unavailable)
    });
    let (_controller, updates) = Controller::start_with_vault(Some(app_dir), open_vault, no_join(), no_wake(), WorkerConfig::default());
    assert_eq!(updates, vec![Update::NeedsEnrollment]);
    assert!(!opened.load(Ordering::SeqCst));
}

#[test]
fn an_unsealed_record_is_sealed_on_first_load_and_only_then() {
    let scratch = Scratch::new("migrate");
    let fixture = Fixture::new();
    let vault = MemoryVault::new();
    let store = DeviceStore::open_sealed(&scratch.dir(), vault.shared()).unwrap();
    let file = store.path("work").unwrap();
    write_private(&file, &fixture.plain_record);

    // While the key store cannot be reached the old file is left exactly as it was.
    vault.set_unavailable(true);
    assert_eq!(store.load("work").err(), Some(StoreError::KeyStoreUnavailable));
    assert_eq!(fs::read(&file).unwrap(), fixture.plain_record);
    vault.set_unavailable(false);

    let device = store.load("work").unwrap();
    assert_eq!(device.certificate(), fixture.certificate.as_slice());
    let sealed = fs::read(&file).unwrap();
    assert!(sealed.starts_with(SEALED_MAGIC), "the old file was replaced by a sealed one");
    fixture.assert_no_key_in(&sealed);
    assert!(vault.contains("work"));
    assert_eq!(entries(&scratch.dir()), ["work.device"]);
    assert_eq!(store.load("work").unwrap().certificate(), fixture.certificate.as_slice());

    // Once a key exists, an unsealed file in the record's place is not taken for the record.
    write_private(&file, &fixture.plain_record);
    assert_eq!(store.load("work").err(), Some(StoreError::Corrupt));
    assert_eq!(fs::read(&file).unwrap(), fixture.plain_record, "and is not rewritten");
}

#[test]
fn removing_a_profile_removes_its_key() {
    let scratch = Scratch::new("remove");
    let fixture = Fixture::new();
    let vault = MemoryVault::new();
    let store = sealed_with(&scratch, &vault, &fixture, "work");
    let device = store.load("work").unwrap();
    store.save("home", &device).unwrap();
    assert_eq!(store.profiles().unwrap(), ["home", "work"]);

    assert_eq!(store.remove("work"), Ok(true));
    assert!(!vault.contains("work") && vault.contains("home"));
    assert_eq!(store.load("work").err(), Some(StoreError::NotFound));
    assert_eq!(store.remove("work"), Ok(false));
    assert_eq!(store.load("home").unwrap().certificate(), fixture.certificate.as_slice());

    // With the key store out of reach the record still goes, and the error says the key may remain.
    vault.set_unavailable(true);
    assert_eq!(store.remove("home"), Err(StoreError::KeyStoreUnavailable));
    assert!(!store.path("home").unwrap().exists());
    vault.set_unavailable(false);
    assert_eq!(store.remove("home"), Ok(false));
    assert!(!vault.contains("home"));
}

/// The operating system's key store on this desktop: a key is stored, read back, and removed. It touches the real
/// key store (under a profile name used only here), so it runs only when asked:
/// `cargo test -p crewcraft --test t313_sealed_device_record -- --ignored`.
#[test]
#[ignore = "uses this desktop's real key store"]
fn the_system_key_store_keeps_and_forgets_a_key() {
    let vault = SystemVault::open().expect("this desktop has a key store");
    let profile = format!("t313-check-{}", std::process::id());
    let mut key = [0u8; KEY_BYTES];
    key.iter_mut().enumerate().for_each(|(at, byte)| *byte = (now_ms() as u8).wrapping_add(at as u8));
    assert_eq!(vault.load(&profile).map(|key| key.is_none()), Ok(true));
    vault.store(&profile, &key).unwrap();
    assert_eq!(vault.load(&profile).unwrap().map(|key| *key), Some(key));
    vault.store(&profile, &[1; KEY_BYTES]).unwrap();
    assert_eq!(vault.load(&profile).unwrap().map(|key| *key), Some([1; KEY_BYTES]), "a second store replaces the key");
    assert_eq!(vault.remove(&profile), Ok(true));
    assert_eq!(vault.load(&profile).map(|key| key.is_none()), Ok(true));
    assert_eq!(vault.remove(&profile), Ok(false));
}
