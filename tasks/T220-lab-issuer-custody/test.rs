#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_server::issuer_custody::{IssuerCustodyError, LabIssuer};
use crewcraft_server_core::seal::{SealError, ServiceKey};

const NOW_MS: u64 = 1_800_000_000_000;

struct StateDir(PathBuf);

impl StateDir {
    fn new(test: &str) -> Self {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("crewcraft-t220-{test}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for StateDir {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("issuer.bin"));
        let _ = fs::remove_dir(&self.0);
    }
}

#[test]
fn initialize_once_and_reload_the_same_trust_anchor() {
    let state = StateDir::new("restart");
    let path = state.0.join("issuer.bin");
    let key = ServiceKey::from_bytes([1; 32]);
    assert_eq!(LabIssuer::load(&path, &key, None, NOW_MS).unwrap_err(), IssuerCustodyError::Missing);
    assert!(!path.exists());

    let initial = LabIssuer::initialize(&path, &key, NOW_MS).unwrap();
    let pin = initial.root_fingerprint();
    let (root_der, issuer) = initial.into_parts();
    let issuer_der = issuer.certificate().to_vec();
    let original_record = fs::read(&path).unwrap();
    assert!(original_record.windows(root_der.len()).any(|bytes| bytes == root_der.as_slice()));
    issuer.with_issuing_key(|private| assert!(!original_record.windows(private.len()).any(|bytes| bytes == private))).unwrap();
    drop(issuer);

    let reloaded = LabIssuer::load(&path, &key, Some(pin), NOW_MS + 1000).unwrap();
    assert_eq!(reloaded.root_certificate(), root_der.as_slice());
    assert_eq!(reloaded.root_fingerprint(), pin);
    let (_, reloaded_issuer) = reloaded.into_parts();
    let server = reloaded_issuer.server_certificate("server.example.org", NOW_MS + 1000).unwrap();
    assert_eq!(server.chain[1], issuer_der);
    assert_eq!(LabIssuer::initialize(&path, &key, NOW_MS + 1000).unwrap_err(), IssuerCustodyError::Exists);
    assert_eq!(fs::read(&path).unwrap(), original_record);
}

#[test]
fn rejects_wrong_keys_pins_and_authenticated_data_changes() {
    let state = StateDir::new("authentication");
    let path = state.0.join("issuer.bin");
    let key = ServiceKey::from_bytes([1; 32]);
    let wrong_key = ServiceKey::from_bytes([2; 32]);
    let initial = LabIssuer::initialize(&path, &key, NOW_MS).unwrap();
    let mut wrong_pin = initial.root_fingerprint();
    wrong_pin[0] ^= 1;
    assert_eq!(LabIssuer::load(&path, &key, Some(wrong_pin), NOW_MS).unwrap_err(), IssuerCustodyError::PinMismatch);
    assert_eq!(LabIssuer::load(&path, &wrong_key, None, NOW_MS).unwrap_err(), IssuerCustodyError::Seal(SealError::WrongKey));

    let original = fs::read(&path).unwrap();
    for at in [12, original.len() - 1] {
        let mut changed = original.clone();
        changed[at] ^= 1;
        fs::write(&path, &changed).unwrap();
        assert_eq!(LabIssuer::load(&path, &key, None, NOW_MS).unwrap_err(), IssuerCustodyError::Seal(SealError::Corrupt));
        assert_eq!(fs::read(&path).unwrap(), changed);
    }
}

#[test]
fn partial_or_oversized_state_is_not_repaired_or_replaced() {
    let state = StateDir::new("partial");
    let path = state.0.join("issuer.bin");
    let key = ServiceKey::from_bytes([1; 32]);
    let initial = LabIssuer::initialize(&path, &key, NOW_MS).unwrap();
    let partial = initial.root_certificate();
    fs::write(&path, partial).unwrap();
    assert_eq!(LabIssuer::load(&path, &key, None, NOW_MS).unwrap_err(), IssuerCustodyError::Malformed);
    assert_eq!(LabIssuer::initialize(&path, &key, NOW_MS).unwrap_err(), IssuerCustodyError::Exists);
    assert_eq!(fs::read(&path).unwrap().as_slice(), partial);

    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_len(128 * 1024).unwrap();
    assert_eq!(LabIssuer::load(&path, &key, None, NOW_MS).unwrap_err(), IssuerCustodyError::Malformed);
}
