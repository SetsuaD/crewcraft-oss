#![allow(clippy::unwrap_used)]

use crewcraft_server_core::audit::{AuditError, AuditLog, Entry, MAX_FIELD, VerifyError, entry_hash, verify};

const ZERO32: [u8; 32] = [0u8; 32];

#[test]
fn entry_hash_matches_test_vector() {
    let prev = ZERO32;
    let seq: u64 = 1;
    let at_ms: u64 = 1_700_000_000_000;
    let actor = "alice";
    let action = "room.create general";

    let expected: [u8; 32] = [
        0xf2, 0x4c, 0x93, 0x4b, 0xc1, 0x87, 0xbe, 0xc8, 0x1d, 0x14, 0x92, 0x00, 0x25, 0xba, 0xbf, 0x85, 0x28, 0x52, 0x45, 0x30, 0x2d, 0xdf, 0x48,
        0xc0, 0x70, 0xf8, 0xbc, 0x5c, 0x70, 0x40, 0x00, 0x63,
    ];

    assert_eq!(entry_hash(&prev, seq, at_ms, actor, action), expected);
}

#[test]
fn verify_empty_slice_is_ok() {
    assert_eq!(verify(&[]), Ok(()));
}

#[test]
fn verify_valid_single_entry() {
    let prev = ZERO32;
    let seq: u64 = 1;
    let at_ms: u64 = 1000;
    let actor = "admin";
    let action = "login";
    let hash = entry_hash(&prev, seq, at_ms, actor, action);

    let entry = Entry { seq, at_ms, actor: actor.to_string(), action: action.to_string(), prev, hash };

    assert_eq!(verify(std::slice::from_ref(&entry)), Ok(()));
}

#[test]
fn verify_valid_chained_log() {
    let mut log = AuditLog::new();
    log.append("alice", "room.create general", 1_700_000_000_000).unwrap();
    log.append("bob", "room.delete general", 1_700_000_000_500).unwrap();
    log.append("alice", "room.rename general", 1_700_000_001_000).unwrap();

    assert_eq!(verify(log.entries()), Ok(()));
}

#[test]
fn verify_bad_seq_reported_before_bad_prev() {
    // Index 0: seq is 99 (should be 1) AND prev is [1;32] (should be zeros).
    // Docs: "BadSeq, then BadPrev, then BadHash" — BadSeq must win.
    // We set hash = entry_hash(own fields) so BadHash would not fire.
    let prev: [u8; 32] = [1u8; 32];
    let seq: u64 = 99;
    let at_ms: u64 = 100;
    let actor = "a";
    let action = "b";
    let hash = entry_hash(&prev, seq, at_ms, actor, action);

    let entry = Entry { seq, at_ms, actor: actor.to_string(), action: action.to_string(), prev, hash };

    assert_eq!(verify(std::slice::from_ref(&entry)), Err(VerifyError::BadSeq { index: 0 }));
}

#[test]
fn verify_bad_prev() {
    // seq is correct (1), prev is wrong ([9;32] instead of zeros),
    // hash is computed from the entry's own fields so BadHash would not fire.
    let prev: [u8; 32] = [9u8; 32];
    let seq: u64 = 1;
    let at_ms: u64 = 100;
    let actor = "a";
    let action = "b";
    let hash = entry_hash(&prev, seq, at_ms, actor, action);

    let entry = Entry { seq, at_ms, actor: actor.to_string(), action: action.to_string(), prev, hash };

    assert_eq!(verify(std::slice::from_ref(&entry)), Err(VerifyError::BadPrev { index: 0 }));
}

#[test]
fn verify_bad_hash() {
    // seq and prev are both correct; only hash is wrong.
    let prev = ZERO32;
    let seq: u64 = 1;
    let at_ms: u64 = 100;
    let actor = "a";
    let action = "b";
    let hash = [7u8; 32]; // deliberately wrong

    let entry = Entry { seq, at_ms, actor: actor.to_string(), action: action.to_string(), prev, hash };

    assert_eq!(verify(std::slice::from_ref(&entry)), Err(VerifyError::BadHash { index: 0 }));
}

#[test]
fn append_rejects_empty_actor_and_stores_nothing() {
    let mut log = AuditLog::new();
    let result = log.append("", "do_thing", 1000);
    assert_eq!(result, Err(AuditError::FieldLength));
    assert!(log.entries().is_empty());
}

#[test]
fn append_rejects_empty_action_and_stores_nothing() {
    let mut log = AuditLog::new();
    let result = log.append("alice", "", 1000);
    assert_eq!(result, Err(AuditError::FieldLength));
    assert!(log.entries().is_empty());
}

#[test]
fn append_rejects_actor_exceeding_max_field() {
    let mut log = AuditLog::new();
    let long = "x".repeat(MAX_FIELD + 1); // 256 bytes
    let result = log.append(&long, "do_thing", 1000);
    assert_eq!(result, Err(AuditError::FieldLength));
    assert!(log.entries().is_empty());
}

#[test]
fn append_accepts_actor_at_exactly_max_field() {
    let mut log = AuditLog::new();
    let max = "x".repeat(MAX_FIELD); // 255 bytes
    let entry = log.append(&max, "do_thing", 1000).unwrap();
    assert_eq!(entry.actor, max);
    assert_eq!(entry.seq, 1);
    assert_eq!(entry.prev, ZERO32);
}

#[test]
fn append_rejects_clock_backwards_and_stores_nothing() {
    let mut log = AuditLog::new();
    log.append("alice", "first", 2000).unwrap();
    let result = log.append("bob", "second", 1999);
    assert_eq!(result, Err(AuditError::ClockBackwards));
    assert_eq!(log.entries().len(), 1);
}

#[test]
fn append_accepts_equal_timestamp() {
    let mut log = AuditLog::new();
    log.append("alice", "first", 2000).unwrap();
    let entry = log.append("bob", "second", 2000).unwrap();
    assert_eq!(entry.seq, 2);
    assert_eq!(log.entries().len(), 2);
}

#[test]
fn head_is_zeros_when_empty() {
    let log = AuditLog::new();
    assert_eq!(log.head(), ZERO32);
}

#[test]
fn head_equals_newest_entry_hash() {
    let mut log = AuditLog::new();
    log.append("alice", "a", 100).unwrap();
    log.append("bob", "b", 200).unwrap();
    let last = log.entries().last().unwrap();
    assert_eq!(log.head(), last.hash);
}

#[test]
fn append_chains_prev_hash_and_increments_seq() {
    let mut log = AuditLog::new();
    let e1 = log.append("alice", "a", 100).unwrap();
    let e2 = log.append("bob", "b", 200).unwrap();
    let e3 = log.append("carol", "c", 300).unwrap();

    assert_eq!(e1.seq, 1);
    assert_eq!(e2.seq, 2);
    assert_eq!(e3.seq, 3);

    assert_eq!(e1.prev, ZERO32);
    assert_eq!(e2.prev, e1.hash);
    assert_eq!(e3.prev, e2.hash);

    // Each hash is entry_hash of its own fields.
    assert_eq!(e1.hash, entry_hash(&e1.prev, e1.seq, e1.at_ms, &e1.actor, &e1.action));
    assert_eq!(e2.hash, entry_hash(&e2.prev, e2.seq, e2.at_ms, &e2.actor, &e2.action));
    assert_eq!(e3.hash, entry_hash(&e3.prev, e3.seq, e3.at_ms, &e3.actor, &e3.action));
}

#[test]
fn verify_finds_tampering_past_the_first_entry() {
    let mut log = AuditLog::new();
    for (i, action) in ["a", "b", "c"].iter().enumerate() {
        log.append("alice", action, 100 + i as u64).unwrap();
    }
    let mut changed = log.entries().to_vec();
    changed[1].action = "x".into();
    assert_eq!(verify(&changed), Err(VerifyError::BadHash { index: 1 }));

    let mut removed = log.entries().to_vec();
    removed.remove(1);
    assert_eq!(verify(&removed), Err(VerifyError::BadSeq { index: 1 }));

    let mut rehashed = log.entries().to_vec();
    rehashed[1].action = "x".into();
    rehashed[1].hash = entry_hash(&rehashed[1].prev, 2, rehashed[1].at_ms, "alice", "x");
    assert_eq!(verify(&rehashed), Err(VerifyError::BadPrev { index: 2 }));
}
