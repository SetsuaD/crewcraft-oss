//! T611b: the account store binds people to an external OpenID Connect provider's `(issuer, subject)` and keeps their
//! authorization records for the external-authorizer rules, both durably (SECURITY-DESIGN.md section 9). Fresh files
//! under the temp directory and synthetic values only.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use crewcraft_authz::{Access, Answer, Area, Capabilities, Capability, Ledger, Record, Refusal, commit_decision};
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

fn path(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("crewcraft-t611b-{name}-{}.journal", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

fn key() -> ServiceKey {
    ServiceKey::from_bytes([7; 32])
}

fn first(n: u8) -> Activation<'static> {
    Activation {
        bootstrap_pub: [n; 32],
        device_name: "laptop",
        certificate: Box::leak(vec![0x30, 0x82, n, n].into_boxed_slice()),
        spki_sha256: [n.wrapping_add(100); 32],
        counter: 1000 + u64::from(n),
        first_device: Some(FirstDevice { password_phc: Some(PHC), totp_secret: b"synthetic-totp-AAAAA" }),
        expected_device_id: None,
    }
}

fn two_people(p: &Path) -> AccountStore {
    let mut s = AccountStore::create(p, key()).unwrap();
    for (email, n) in [(A, 1), (B, 2)] {
        s.issue_invite(Invite { email: email.to_string(), bootstrap_pub: [n; 32], expires_ms: T0 + 86_400_000 }, T0).unwrap();
        s.activate(first(n), T0 + 1).unwrap();
    }
    s
}

#[test]
fn a_subject_is_bound_to_one_person_and_survives_a_restart() {
    let p = path("bind");
    let mut s = two_people(&p);
    s.bind_external(A, ISSUER, "sub-a").unwrap();
    assert_eq!(s.person_for_external(ISSUER, "sub-a"), Some(A));
    assert_eq!(s.external_of(A), Some((ISSUER, "sub-a")));
    // The same subject for another person is refused; an unknown person, a non-canonical email or empty fields too.
    assert_eq!(s.bind_external(B, ISSUER, "sub-a").unwrap_err(), StoreError::ExternalInUse);
    assert_eq!(s.bind_external("nobody@example.com", ISSUER, "sub-x").unwrap_err(), StoreError::NoSuchPerson);
    assert_eq!(s.bind_external("A@example.com", ISSUER, "sub-x").unwrap_err(), StoreError::NotCanonical);
    assert_eq!(s.bind_external(B, "", "sub-b").unwrap_err(), StoreError::BadField);
    assert_eq!(s.bind_external(B, ISSUER, "").unwrap_err(), StoreError::BadField);
    // The same subject under another issuer is a different identity.
    s.bind_external(B, "https://other.example.org/", "sub-a").unwrap();
    // Re-binding A frees the old subject.
    s.bind_external(A, ISSUER, "sub-a2").unwrap();
    assert_eq!(s.person_for_external(ISSUER, "sub-a"), None);
    drop(s);

    let s = AccountStore::open(&p, key()).unwrap();
    assert_eq!(s.person_for_external(ISSUER, "sub-a2"), Some(A));
    assert_eq!(s.person_for_external(ISSUER, "sub-a"), None);
    assert_eq!(s.person_for_external("https://other.example.org/", "sub-a"), Some(B));
    assert_eq!(s.external_of(B), Some(("https://other.example.org/", "sub-a")));
    fs::remove_file(&p).unwrap();
}

#[test]
fn authorization_records_are_durable_and_drive_the_rules() {
    let p = path("authz");
    let mut s = two_people(&p);
    let answer = Answer::Allow { capabilities: Capabilities::from_names(["use", "moderate"]), revision: 7, recheck_after_secs: None };
    let (record, access) = Record::default().sign_in(&answer, 1000);
    assert!(matches!(commit_decision(&mut s, A, &record, access), Access::Allowed(_)));
    assert_eq!(s.authorization(A), Some(&record));
    // A record for someone who is not a person is never stored, so it grants nothing.
    assert_eq!(
        commit_decision(&mut s, "nobody@example.com", &record, Access::Allowed(Capabilities::default())),
        Access::Refused(Refusal::NotDurable)
    );

    // A denial stored now is still there after a restart, and the rules still refuse.
    let (denied, access) = record.recheck(&Answer::Deny { revision: 8 }, Area::Staff, 1600);
    assert_eq!(commit_decision(&mut s, A, &denied, access), Access::Refused(Refusal::Denied));
    drop(s);
    let s = AccountStore::open(&p, key()).unwrap();
    let stored = s.authorization(A).unwrap().clone();
    assert_eq!(stored, denied);
    assert_eq!(stored.current(Area::Staff, 1700), Access::Refused(Refusal::Denied));
    assert_eq!(Ledger::read_back(&s, A).unwrap(), Some(denied));
    assert_eq!(Ledger::read_back(&s, B).unwrap(), None);
    fs::remove_file(&p).unwrap();
}

#[test]
fn the_records_round_trip_and_corruption_is_refused() {
    let full = AccountOp::AuthorizationRecorded {
        email: A.into(),
        record: Record::default()
            .sign_in(
                &Answer::Allow { capabilities: Capabilities::from_names(["use", "respond", "dispatch"]), revision: 3, recheck_after_secs: Some(120) },
                50,
            )
            .0,
    };
    let denied = AccountOp::AuthorizationRecorded { email: B.into(), record: Record::default().sign_in(&Answer::Deny { revision: 9 }, 60).0 };
    let bound = AccountOp::ExternalBound { email: A.into(), issuer: ISSUER.into(), subject: "sub-a".into() };
    for op in [&full, &denied, &bound] {
        let bytes = encode_account_op(op).unwrap();
        assert_eq!(&decode_account_op(&bytes).unwrap(), op);
        for end in 0..bytes.len() {
            assert!(decode_account_op(&bytes[..end]).is_err(), "prefix {end} of {op:?}");
        }
    }
    let AccountOp::AuthorizationRecorded { record, .. } = &full else { panic!("not an authorization record") };
    assert!(record.grant.as_ref().unwrap().capabilities.has(Capability::Dispatch));
    // A capability name this code does not know is corruption in a stored record, not something to drop silently.
    let mut bytes = encode_account_op(&full).unwrap();
    let at = bytes.windows(7).position(|w| w == b"respond").unwrap();
    bytes[at..at + 7].copy_from_slice(b"respxnd");
    assert_eq!(decode_account_op(&bytes), Err(CodecError::FieldLength));
    // Debug shows who and the state, not the revisions or capabilities.
    let shown = format!("{full:?}");
    assert!(shown.contains("granted: true") && !shown.contains("respond"), "{shown}");
}
