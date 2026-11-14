#![allow(clippy::unwrap_used)]

use crewcraft_server_core::devices::*;

fn fp(b: u8) -> [u8; 32] {
    [b; 32]
}

#[test]
fn enroll_sets_fields_and_increments_id() {
    let mut d = Devices::new();
    let id1 = d.enroll("alice", "  My Phone  ", fp(1), 1_000).unwrap();
    assert_eq!(id1, 1);
    let id2 = d.enroll("bob", "Laptop", fp(2), 2_000).unwrap();
    assert_eq!(id2, 2);

    let list = d.list("alice");
    assert_eq!(list.len(), 1);
    let dev = &list[0];
    assert_eq!(dev.id, 1);
    assert_eq!(dev.user, "alice");
    assert_eq!(dev.name, "My Phone"); // trimmed
    assert_eq!(dev.fingerprint, fp(1));
    assert_eq!(dev.enrolled_ms, 1_000);
    assert_eq!(dev.last_seen_ms, 1_000);
    assert!(!dev.revoked);
}

#[test]
fn enroll_bad_name_empty_after_trim() {
    let mut d = Devices::new();
    assert_eq!(d.enroll("alice", "", fp(1), 0), Err(DeviceError::BadName));
    assert_eq!(d.enroll("alice", "   ", fp(1), 0), Err(DeviceError::BadName));
}

#[test]
fn enroll_bad_name_exceeds_max_chars() {
    let mut d = Devices::new();
    // 65 chars after trimming → BadName
    let too_long = "a".repeat(65);
    assert_eq!(d.enroll("alice", &too_long, fp(1), 0), Err(DeviceError::BadName));
    // exactly 64 chars after trimming → OK
    let exact = "a".repeat(64);
    assert!(d.enroll("alice", &exact, fp(1), 0).is_ok());
}

#[test]
fn enroll_bad_name_control_character() {
    let mut d = Devices::new();
    let with_ctrl = "a\u{01}b";
    assert_eq!(d.enroll("alice", with_ctrl, fp(1), 0), Err(DeviceError::BadName));
    // A name that is otherwise fine but has a tab embedded
    let with_tab = "a\tb";
    assert_eq!(d.enroll("bob", with_tab, fp(2), 0), Err(DeviceError::BadName));
}

#[test]
fn check_order_badname_precedes_revoked() {
    let mut d = Devices::new();
    let id = d.enroll("alice", "Phone", fp(1), 0).unwrap();
    d.revoke("alice", id).unwrap();
    // Fingerprint is now revoked, but BadName is checked first.
    assert_eq!(d.enroll("alice", "", fp(1), 0), Err(DeviceError::BadName));
}

#[test]
fn check_order_fingerprint_inuse_precedes_toomany() {
    let mut d = Devices::new();
    // Fill alice to the limit (10 live devices).
    for i in 0..MAX_DEVICES {
        d.enroll("alice", &format!("D{}", i), fp(100 + i as u8), 0).unwrap();
    }
    // Bob has a live device with fp(200).
    d.enroll("bob", "BobPhone", fp(200), 0).unwrap();
    // Alice is at the limit AND fp(200) is in use → FingerprintInUse wins over TooMany.
    assert_eq!(d.enroll("alice", "New", fp(200), 0), Err(DeviceError::FingerprintInUse));
}

#[test]
fn too_many_live_devices() {
    let mut d = Devices::new();
    for i in 0..MAX_DEVICES {
        assert!(d.enroll("alice", &format!("D{}", i), fp(i as u8), 0).is_ok());
    }
    // 11th enrollment must fail with TooMany.
    assert_eq!(d.enroll("alice", "D10", fp(99), 0), Err(DeviceError::TooMany));
}

#[test]
fn fingerprint_inuse_across_users() {
    let mut d = Devices::new();
    d.enroll("alice", "Phone", fp(1), 0).unwrap();
    assert_eq!(d.enroll("bob", "Phone", fp(1), 0), Err(DeviceError::FingerprintInUse));
}

#[test]
fn enroll_revoked_fingerprint() {
    let mut d = Devices::new();
    let id = d.enroll("alice", "Phone", fp(1), 0).unwrap();
    d.revoke("alice", id).unwrap();
    // No one can re-enrol this fingerprint.
    assert_eq!(d.enroll("alice", "Again", fp(1), 0), Err(DeviceError::Revoked));
    assert_eq!(d.enroll("bob", "Phone", fp(1), 0), Err(DeviceError::Revoked));
}

#[test]
fn id_never_reused_after_revoke() {
    let mut d = Devices::new();
    let id1 = d.enroll("alice", "P1", fp(1), 0).unwrap();
    let _id2 = d.enroll("bob", "BP", fp(2), 0).unwrap();
    d.revoke("alice", id1).unwrap();
    // Next global id must be 3, not 1.
    let id3 = d.enroll("alice", "P3", fp(3), 0).unwrap();
    assert_eq!(id3, 3);
}

#[test]
fn authenticate_updates_last_seen_but_never_moves_back() {
    let mut d = Devices::new();
    d.enroll("alice", "Phone", fp(1), 1_000).unwrap();

    // Advance time.
    let dev = d.authenticate(&fp(1), 5_000).unwrap();
    assert_eq!(dev.last_seen_ms, 5_000);

    // Earlier timestamp must not move it back.
    let dev = d.authenticate(&fp(1), 2_000).unwrap();
    assert_eq!(dev.last_seen_ms, 5_000);

    // Equal timestamp is fine (still 5_000).
    let dev = d.authenticate(&fp(1), 5_000).unwrap();
    assert_eq!(dev.last_seen_ms, 5_000);
}

#[test]
fn authenticate_revoked_and_unknown_fingerprint() {
    let mut d = Devices::new();
    let id = d.enroll("alice", "Phone", fp(1), 0).unwrap();
    d.revoke("alice", id).unwrap();

    assert_eq!(d.authenticate(&fp(1), 0), Err(DeviceError::Revoked));
    assert_eq!(d.authenticate(&fp(99), 0), Err(DeviceError::NoSuchDevice));
}

#[test]
fn revoke_returns_true_for_live_false_for_already_revoked() {
    let mut d = Devices::new();
    let id = d.enroll("alice", "Phone", fp(1), 0).unwrap();
    assert_eq!(d.revoke("alice", id), Ok(true));
    // Second call: already revoked.
    assert_eq!(d.revoke("alice", id), Ok(false));
}

#[test]
fn revoke_check_order_nosuch_before_notyours() {
    let mut d = Devices::new();
    let id = d.enroll("alice", "Phone", fp(1), 0).unwrap();
    // Non-existent id → NoSuchDevice (checked before NotYours).
    assert_eq!(d.revoke("bob", 99_999), Err(DeviceError::NoSuchDevice));
    // Existing id but wrong user → NotYours.
    assert_eq!(d.revoke("bob", id), Err(DeviceError::NotYours));
}

#[test]
fn revoke_all_counts_only_live_devices() {
    let mut d = Devices::new();
    d.enroll("alice", "P1", fp(1), 0).unwrap();
    let id2 = d.enroll("alice", "P2", fp(2), 0).unwrap();
    d.enroll("alice", "P3", fp(3), 0).unwrap();
    d.revoke("alice", id2).unwrap(); // P2 already revoked

    let count = d.revoke_all("alice");
    assert_eq!(count, 2); // P1 and P3 were live; P2 was already revoked.

    let list = d.list("alice");
    assert_eq!(list.len(), 3);
    assert!(list.iter().all(|dev| dev.revoked));

    // Bob's devices are unaffected.
    d.enroll("bob", "BP", fp(4), 0).unwrap();
    let bob_list = d.list("bob");
    assert!(!bob_list[0].revoked);
}

#[test]
fn list_returns_all_devices_sorted_by_id() {
    let mut d = Devices::new();
    let id1 = d.enroll("alice", "P1", fp(1), 0).unwrap();
    d.enroll("bob", "BP", fp(2), 0).unwrap();
    let id3 = d.enroll("alice", "P3", fp(3), 0).unwrap();
    d.revoke("alice", id1).unwrap();
    d.revoke("alice", id3).unwrap();

    let list = d.list("alice");
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].id, 1);
    assert_eq!(list[1].id, 3);
    assert!(list[0].revoked);
    assert!(list[1].revoked);
}

#[test]
fn revoked_device_frees_a_slot_for_reenrollment() {
    let mut d = Devices::new();
    // Fill alice to the limit.
    for i in 0..MAX_DEVICES {
        d.enroll("alice", &format!("D{}", i), fp(i as u8), 0).unwrap();
    }
    // Revoking one frees a slot.
    d.revoke("alice", 1).unwrap();
    // Now alice can enroll again.
    assert!(d.enroll("alice", "New", fp(200), 0).is_ok());
}
