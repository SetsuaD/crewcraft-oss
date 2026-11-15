//! A certificate issued before the commit names the device id it will get. The store checks that id against the one it
//! would allocate before it writes anything (issue #35, additive to the account store). Synthetic values only.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use crewcraft_server_core::account_store::{AccountStore, Activation, FirstDevice, StoreError, fingerprint};
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::seal::ServiceKey;

const T0: u64 = 1_800_000_000_000;
const HOUR: u64 = 3_600_000;
const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljc2FsdA$c3ludGhldGljLWhhc2gtZm9yLXRlc3RzLW9ubHk";

fn path(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("crewcraft-ordinal-{name}-{}.journal", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

fn activation(n: u8) -> Activation<'static> {
    let cert: &'static [u8] = Box::leak(vec![0x30, 0x82, n, n].into_boxed_slice());
    Activation {
        bootstrap_pub: [n; 32],
        device_name: "laptop",
        certificate: cert,
        spki_sha256: [n.wrapping_add(100); 32],
        counter: 1000 + u64::from(n),
        first_device: Some(FirstDevice { password_phc: Some(PHC), totp_secret: b"synthetic-totp-AAAAA" }),
    }
}

fn store(p: &Path) -> AccountStore {
    let mut s = AccountStore::open(p, ServiceKey::from_bytes([7; 32])).unwrap();
    for n in [1u8, 2] {
        s.issue_invite(Invite { email: format!("p{n}@example.org"), bootstrap_pub: [n; 32], expires_ms: T0 + HOUR }, T0).unwrap();
    }
    s
}

#[test]
fn the_next_device_id_is_known_before_the_commit_and_survives_a_restart() {
    let p = path("next");
    let mut s = store(&p);
    assert_eq!(s.next_device_id(), 1);
    assert_eq!(s.activate_expecting(activation(1), 1, T0 + 1).unwrap(), 1);
    assert_eq!(s.next_device_id(), 2);
    drop(s);
    let s = AccountStore::open(&p, ServiceKey::from_bytes([7; 32])).unwrap();
    assert_eq!(s.next_device_id(), 2, "ids are replayed, not reset");
}

#[test]
fn a_different_expected_id_is_refused_before_anything_is_written() {
    let p = path("mismatch");
    let mut s = store(&p);
    let before = fs::metadata(&p).unwrap().len();
    let refused = s.activate_expecting(activation(1), 5, T0 + 1).unwrap_err();
    assert_eq!(refused, StoreError::Ordinal { expected: 5, next: 1 });
    assert_eq!(fs::metadata(&p).unwrap().len(), before, "a refused ordinal must not touch the file");
    // Nothing changed in memory either: the invitation is still pending, there is no person, and the right id works.
    assert!(s.is_invite_pending(&[1; 32], T0 + 2));
    assert!(s.person("p1@example.org").is_none());
    assert_eq!(s.next_device_id(), 1);
    assert_eq!(s.activate_expecting(activation(1), 1, T0 + 3).unwrap(), 1);
}

#[test]
fn the_live_invitation_names_the_person_and_stops_naming_them_once_used() {
    let p = path("email");
    let mut s = store(&p);
    assert_eq!(s.pending_invite_email(&[1; 32], T0 + 1).as_deref(), Some("p1@example.org"));
    assert_eq!(s.pending_invite_email(&[9; 32], T0 + 1), None, "unknown key");
    assert_eq!(s.pending_invite_email(&[1; 32], T0 + HOUR), None, "expired");
    s.activate(activation(1), T0 + 2).unwrap();
    assert_eq!(s.pending_invite_email(&[1; 32], T0 + 3), None, "consumed");
}

#[test]
fn plain_activate_still_allocates_and_activate_expecting_is_the_same_record() {
    let p = path("same");
    let mut s = store(&p);
    assert_eq!(s.activate(activation(1), T0 + 1).unwrap(), 1);
    assert_eq!(s.activate_expecting(activation(2), 2, T0 + 2).unwrap(), 2);
    assert_eq!(s.device_certificate(2).unwrap(), &[0x30, 0x82, 2, 2]);
    assert_eq!(fingerprint(s.device_certificate(1).unwrap()), fingerprint(&[0x30, 0x82, 1, 1]));
}
