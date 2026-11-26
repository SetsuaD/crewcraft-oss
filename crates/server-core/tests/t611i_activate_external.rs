//! T611i: enrollment through an external provider commits the activation and the person's binding in ONE record
//! (SECURITY-DESIGN.md section 9, "Enrolling through the provider"): a new person has no password and a provider
//! identity no one else holds, another device needs the person bound to exactly that identity, and every refusal
//! writes nothing. Fresh files under the temp directory and synthetic values only.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use crewcraft_proto::message::CodecError;
use crewcraft_server_core::account_op::{AccountOp, decode_account_op, encode_account_op};
use crewcraft_server_core::account_store::{AccountStore, Activation, FirstDevice, StoreError};
use crewcraft_server_core::invites::Invite;
use crewcraft_server_core::seal::ServiceKey;

const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$c3ludGhldGljc2FsdA$c3ludGhldGljLWhhc2gtZm9yLXRlc3RzLW9ubHk";
const T0: u64 = 1_800_000_000_000;
const A: &str = "a@example.com";
const B: &str = "b@example.com";
const ISSUER: &str = "https://id.example.org/application/o/chat/";
/// A TOTP secret no one is shown: an external person signs in only through the provider.
const UNUSED_TOTP: &[u8] = b"never-shown-secret-1";

fn path(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("crewcraft-t611i-{name}-{}.journal", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

fn key() -> ServiceKey {
    ServiceKey::from_bytes([7; 32])
}

fn size(p: &Path) -> u64 {
    fs::metadata(p).unwrap().len()
}

fn invite(s: &mut AccountStore, email: &str, n: u8) {
    s.issue_invite(Invite { email: email.to_string(), bootstrap_pub: [n; 32], expires_ms: T0 + 86_400_000 }, T0).unwrap();
}

/// A device activation for invitation `n`; `first` makes the person, with `password` as their stored password.
fn device(n: u8, first: bool, password: Option<&'static str>) -> Activation<'static> {
    Activation {
        bootstrap_pub: [n; 32],
        device_name: "laptop",
        certificate: Box::leak(vec![0x30, 0x82, n, n].into_boxed_slice()),
        spki_sha256: [n.wrapping_add(100); 32],
        counter: 1000 + u64::from(n),
        first_device: first.then_some(FirstDevice { password_phc: password, totp_secret: UNUSED_TOTP }),
        expected_device_id: None,
    }
}

#[test]
fn a_first_device_makes_a_bound_person_with_no_password_in_one_record() {
    let p = path("first");
    let mut s = AccountStore::create(&p, key()).unwrap();
    invite(&mut s, A, 1);
    let before = size(&p);
    let id = s.activate_external(device(1, true, None), ISSUER, "sub-a", T0 + 1).unwrap();
    assert!(size(&p) > before);
    let person = s.person(A).unwrap();
    assert_eq!(person.password_phc, None, "an external person has no CrewCraft password");
    assert_eq!(s.person_for_external(ISSUER, "sub-a"), Some(A));
    assert_eq!(s.external_of(A), Some((ISSUER, "sub-a")));
    assert!(!s.is_invite_pending(&[1; 32], T0 + 2), "the invitation is consumed");
    assert_eq!(s.device_by_key(&[101; 32]), Some(id));
    drop(s);

    // The journal holds the binding in the activation's own record: a replay rebuilds both.
    let s = AccountStore::open(&p, key()).unwrap();
    assert_eq!(s.person_for_external(ISSUER, "sub-a"), Some(A));
    assert_eq!(s.person(A).unwrap().password_phc, None);
    assert_eq!(s.device_by_key(&[101; 32]), Some(id));
    fs::remove_file(&p).unwrap();
}

#[test]
fn every_refusal_writes_nothing_and_leaves_the_invitation_live() {
    let p = path("refused");
    let mut s = AccountStore::create(&p, key()).unwrap();
    invite(&mut s, A, 1);
    s.activate_external(device(1, true, None), ISSUER, "sub-a", T0 + 1).unwrap();
    invite(&mut s, B, 2);
    let before = size(&p);

    // Someone else's provider identity.
    assert_eq!(s.activate_external(device(2, true, None), ISSUER, "sub-a", T0 + 2).unwrap_err(), StoreError::ExternalInUse);
    // A CrewCraft password on an external person.
    assert_eq!(s.activate_external(device(2, true, Some(PHC)), ISSUER, "sub-b", T0 + 2).unwrap_err(), StoreError::ExternalPassword);
    // Empty identity fields.
    assert_eq!(s.activate_external(device(2, true, None), "", "sub-b", T0 + 2).unwrap_err(), StoreError::BadField);
    assert_eq!(s.activate_external(device(2, true, None), ISSUER, "", T0 + 2).unwrap_err(), StoreError::BadField);
    // An unknown or expired invitation.
    assert_eq!(s.activate_external(device(9, true, None), ISSUER, "sub-b", T0 + 2).unwrap_err(), StoreError::NoInvite);
    assert_eq!(s.activate_external(device(2, true, None), ISSUER, "sub-b", T0 + 86_400_000).unwrap_err(), StoreError::NoInvite);

    assert_eq!(size(&p), before, "nothing was written");
    assert!(s.is_invite_pending(&[2; 32], T0 + 3));
    assert!(s.person(B).is_none() && s.person_for_external(ISSUER, "sub-b").is_none());
    // The same identity under another issuer is another identity, and is accepted.
    s.activate_external(device(2, true, None), "https://other.example.org/", "sub-a", T0 + 3).unwrap();
    assert_eq!(s.person_for_external("https://other.example.org/", "sub-a"), Some(B));
    fs::remove_file(&p).unwrap();
}

#[test]
fn another_device_needs_the_person_bound_to_exactly_that_identity() {
    let p = path("second");
    let mut s = AccountStore::create(&p, key()).unwrap();
    invite(&mut s, A, 1);
    s.activate_external(device(1, true, None), ISSUER, "sub-a", T0 + 1).unwrap();
    // B enrolled with a password, before any provider.
    invite(&mut s, B, 2);
    s.activate(device(2, true, Some(PHC)), T0 + 1).unwrap();

    invite(&mut s, A, 3);
    invite(&mut s, B, 4);
    let before = size(&p);
    assert_eq!(s.activate_external(device(3, false, None), ISSUER, "sub-x", T0 + 2).unwrap_err(), StoreError::ExternalMismatch);
    assert_eq!(
        s.activate_external(device(4, false, None), ISSUER, "sub-b", T0 + 2).unwrap_err(),
        StoreError::ExternalMismatch,
        "B is bound to nothing"
    );
    assert_eq!(size(&p), before);

    let second = s.activate_external(device(3, false, None), ISSUER, "sub-a", T0 + 2).unwrap();
    assert_eq!(s.device_by_key(&[103; 32]), Some(second));
    assert_eq!(s.external_of(A), Some((ISSUER, "sub-a")));
    drop(s);
    let s = AccountStore::open(&p, key()).unwrap();
    assert_eq!(s.device_by_key(&[103; 32]), Some(second));
    assert_eq!(s.person_for_external(ISSUER, "sub-a"), Some(A));
    fs::remove_file(&p).unwrap();
}

#[test]
fn the_record_round_trips_and_its_debug_names_no_subject() {
    let op = AccountOp::ActivatedExternal {
        bootstrap_pub: [1; 32],
        new_person: None,
        device_id: 7,
        device_name: "laptop".into(),
        certificate: vec![0x30, 0x82, 1, 1],
        spki_sha256: [2; 32],
        counter: 1001,
        now_ms: T0,
        issuer: ISSUER.into(),
        subject: "sub-secret-looking".into(),
    };
    let bytes = encode_account_op(&op).unwrap();
    assert_eq!(bytes[0], 13);
    assert_eq!(decode_account_op(&bytes).unwrap(), op);
    for cut in 1..bytes.len() {
        assert!(decode_account_op(&bytes[..cut]).is_err(), "cut at {cut}");
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert!(decode_account_op(&longer).is_err());
    let debug = format!("{op:?}");
    assert!(debug.starts_with("ActivatedExternal") && !debug.contains("sub-secret-looking"), "{debug}");

    // The plain activation inside it is the same record an ordinary activation writes.
    let (plain, issuer, subject) = op.split_external().unwrap();
    assert_eq!((issuer, subject), (ISSUER, "sub-secret-looking"));
    let plain_bytes = encode_account_op(&plain).unwrap();
    assert_eq!(plain_bytes[0], 4);
    assert_eq!(&plain_bytes[1..], &bytes[1..plain_bytes.len()]);
    assert!(plain.split_external().is_none());
    assert_eq!(decode_account_op(&[13]).unwrap_err(), CodecError::Truncated);
}
