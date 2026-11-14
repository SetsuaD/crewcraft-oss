#![allow(clippy::unwrap_used)]

use crewcraft_server_core::admin::{Admin, AdminError, action_text};
use crewcraft_server_core::audit::{AuditError, MAX_FIELD, verify};
use crewcraft_server_core::room::Role;
use crewcraft_server_core::server::ServerError;

#[test]
fn action_text_simple_join() {
    let parts = ["member.add", "general", "bob", "member"];
    assert_eq!(action_text(&parts), "member.add general bob member");
}

#[test]
fn action_text_single_part() {
    assert_eq!(action_text(&["room.create", "general"]), "room.create general");
}

#[test]
fn action_text_truncates_at_char_boundary_multibyte() {
    // 254 a's (254 bytes) + 'é' (2 bytes) = 256 bytes > 255.
    // Char boundaries at 0..=254 and 256. Longest prefix ≤ 255 on a boundary is 254.
    let s: String = "a".repeat(254) + "\u{e9}";
    assert_eq!(s.len(), 256);
    let result = action_text(&[&s]);
    assert_eq!(result, "a".repeat(254));
    assert_eq!(result.len(), 254);
}

#[test]
fn action_text_truncates_across_parts() {
    // part1 = 253 a's, space, part2 = 'é' (2 bytes) → 256 bytes total.
    // Boundaries: 0..=253 (a's), 254 (space), 256 (é start). 255 is not a boundary.
    // Result: 254 bytes (253 a's + space).
    let p1: String = "a".repeat(253);
    let p2: String = "\u{e9}".to_string();
    let result = action_text(&[&p1, &p2]);
    assert_eq!(result, format!("{} ", "a".repeat(253)));
    assert_eq!(result.len(), 254);
}

#[test]
fn action_text_exactly_max_field_no_truncation() {
    // Exactly 255 bytes of ASCII: no truncation needed.
    let s: String = "a".repeat(255);
    assert_eq!(s.len(), 255);
    assert_eq!(action_text(&[&s]), s);
}

#[test]
fn new_starts_with_empty_state() {
    let mut admin = Admin::new();
    assert!(admin.audit().entries().is_empty());
    assert_eq!(admin.audit().head(), [0u8; 32]);
    assert!(admin.server().rooms_of("anyone").is_empty());
    assert!(admin.devices_mut().list("anyone").is_empty());
}

#[test]
fn create_room_success_returns_slug_and_appends_audit() {
    let mut admin = Admin::new();
    let slug = admin.create_room("alice", "General", 1_000).unwrap();
    assert!(!slug.is_empty());

    let entries = admin.audit().entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].seq, 1);
    assert_eq!(entries[0].at_ms, 1_000);
    assert_eq!(entries[0].actor, "alice");
    assert_eq!(entries[0].action, format!("room.create {slug}"));
    assert_eq!(entries[0].prev, [0u8; 32]);

    // Verify the hash chain.
    assert_eq!(verify(entries), Ok(()));

    // The room should exist in the server.
    let rooms = admin.server().rooms_of("alice");
    assert_eq!(rooms.len(), 1);
    assert_eq!(rooms[0].slug, slug);
    assert_eq!(rooms[0].role, Role::Owner);
}

#[test]
fn create_room_empty_actor_is_audit_field_length() {
    let mut admin = Admin::new();
    let err = admin.create_room("", "General", 1_000).unwrap_err();
    assert_eq!(err, AdminError::Audit(AuditError::FieldLength));
    assert!(admin.audit().entries().is_empty());
    assert!(admin.server().rooms_of("anyone").is_empty());
}

#[test]
fn create_room_actor_too_long_is_audit_field_length() {
    let mut admin = Admin::new();
    let long_actor: String = "x".repeat(MAX_FIELD + 1); // 256 bytes
    let err = admin.create_room(&long_actor, "General", 1_000).unwrap_err();
    assert_eq!(err, AdminError::Audit(AuditError::FieldLength));
    assert!(admin.audit().entries().is_empty());
}

#[test]
fn create_room_actor_exactly_max_field_is_ok() {
    let mut admin = Admin::new();
    let actor: String = "x".repeat(MAX_FIELD); // exactly 255 bytes
    let slug = admin.create_room(&actor, "General", 1_000).unwrap();
    assert!(!slug.is_empty());
    assert_eq!(admin.audit().entries().len(), 1);
}

#[test]
fn create_room_clock_backwards_is_audit_clock_backwards() {
    let mut admin = Admin::new();
    admin.create_room("alice", "General", 2_000).unwrap();
    // Now try with an earlier timestamp.
    let err = admin.create_room("bob", "Other", 1_000).unwrap_err();
    assert_eq!(err, AdminError::Audit(AuditError::ClockBackwards));
    // Only the first entry exists.
    assert_eq!(admin.audit().entries().len(), 1);
    assert_eq!(admin.audit().entries()[0].at_ms, 2_000);
}

#[test]
fn audit_check_happens_before_action() {
    // Empty actor + nonexistent room slug → Audit(FieldLength), not Server(NoSuchRoom).
    let mut admin = Admin::new();
    let err = admin.add_member("", "nonexistent", "bob", Role::Member, 1_000).unwrap_err();
    assert_eq!(err, AdminError::Audit(AuditError::FieldLength));
    assert!(admin.audit().entries().is_empty());
}

#[test]
fn add_member_success_appends_audit_and_returns_cursor() {
    let mut admin = Admin::new();
    let slug = admin.create_room("alice", "General", 1_000).unwrap();
    let cursor = admin.add_member("alice", &slug, "bob", Role::Member, 2_000).unwrap();

    let entries = admin.audit().entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].seq, 2);
    assert_eq!(entries[1].at_ms, 2_000);
    assert_eq!(entries[1].actor, "alice");
    assert_eq!(entries[1].action, format!("member.add {slug} bob member"));

    assert_eq!(verify(entries), Ok(()));
    assert!(cursor >= 1);
}

#[test]
fn add_member_no_such_room_no_audit() {
    let mut admin = Admin::new();
    let err = admin.add_member("alice", "ghost", "bob", Role::Member, 1_000).unwrap_err();
    assert_eq!(err, AdminError::Server(ServerError::NoSuchRoom));
    // No audit entry was appended.
    assert!(admin.audit().entries().is_empty());
}

#[test]
fn remove_member_success_appends_audit() {
    let mut admin = Admin::new();
    let slug = admin.create_room("alice", "General", 1_000).unwrap();
    admin.add_member("alice", &slug, "bob", Role::Member, 2_000).unwrap();
    let cursor = admin.remove_member("alice", &slug, "bob", 3_000).unwrap();

    let entries = admin.audit().entries();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[2].seq, 3);
    assert_eq!(entries[2].at_ms, 3_000);
    assert_eq!(entries[2].actor, "alice");
    assert_eq!(entries[2].action, format!("member.remove {slug} bob"));

    assert_eq!(verify(entries), Ok(()));
    assert!(cursor >= 1);
}

#[test]
fn remove_member_no_such_room_no_audit() {
    let mut admin = Admin::new();
    let err = admin.remove_member("alice", "ghost", "bob", 1_000).unwrap_err();
    assert_eq!(err, AdminError::Server(ServerError::NoSuchRoom));
    assert!(admin.audit().entries().is_empty());
}

#[test]
fn revoke_device_live_appends_audit() {
    let mut admin = Admin::new();
    // Enroll a device for "alice".
    let id = admin.devices_mut().enroll("alice", "Phone", [1u8; 32], 500).unwrap();
    assert_eq!(id, 1);

    let was_live = admin.revoke_device("root", "alice", id, 1_000).unwrap();
    assert!(was_live);

    let entries = admin.audit().entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].actor, "root");
    assert_eq!(entries[0].action, format!("device.revoke alice {id}"));
    assert_eq!(entries[0].at_ms, 1_000);

    assert_eq!(verify(entries), Ok(()));
}

#[test]
fn revoke_device_already_revoked_no_audit() {
    let mut admin = Admin::new();
    let id = admin.devices_mut().enroll("alice", "Phone", [1u8; 32], 500).unwrap();

    // First revoke: live → true, audit appended.
    assert!(admin.revoke_device("root", "alice", id, 1_000).unwrap());
    assert_eq!(admin.audit().entries().len(), 1);

    // Second revoke: already revoked → false, no new audit entry.
    let was_live = admin.revoke_device("root", "alice", id, 2_000).unwrap();
    assert!(!was_live);
    assert_eq!(admin.audit().entries().len(), 1);
}

#[test]
fn revoke_all_with_devices_appends_audit() {
    let mut admin = Admin::new();
    // Enroll three devices for "alice".
    for i in 0u64..3 {
        let fp: [u8; 32] = {
            let mut f = [0u8; 32];
            f[0] = i as u8;
            f
        };
        admin.devices_mut().enroll("alice", "Phone", fp, 100 + i).unwrap();
    }

    let count = admin.revoke_all("root", "alice", 1_000).unwrap();
    assert_eq!(count, 3);

    let entries = admin.audit().entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].actor, "root");
    assert_eq!(entries[0].action, "device.revoke_all alice 3");
    assert_eq!(entries[0].at_ms, 1_000);

    assert_eq!(verify(entries), Ok(()));
}

#[test]
fn revoke_all_zero_devices_no_audit() {
    let mut admin = Admin::new();
    let count = admin.revoke_all("root", "alice", 1_000).unwrap();
    assert_eq!(count, 0);
    assert!(admin.audit().entries().is_empty());
}

#[test]
fn revoke_all_clock_backwards_rejected() {
    let mut admin = Admin::new();
    admin.devices_mut().enroll("alice", "Phone", [1u8; 32], 100).unwrap();
    // First revoke_all at 2000: succeeds.
    assert_eq!(admin.revoke_all("root", "alice", 2_000).unwrap(), 1);
    // Enroll another device.
    admin.devices_mut().enroll("alice", "Tablet", [2u8; 32], 2_500).unwrap();
    // Second revoke_all at 1000 (< 2000): clock backwards.
    let err = admin.revoke_all("root", "alice", 1_000).unwrap_err();
    assert_eq!(err, AdminError::Audit(AuditError::ClockBackwards));
    // Only one audit entry.
    assert_eq!(admin.audit().entries().len(), 1);
}

#[test]
fn multiple_actions_produce_valid_chain() {
    let mut admin = Admin::new();
    let slug = admin.create_room("alice", "General", 1_000).unwrap();
    admin.add_member("alice", &slug, "bob", Role::Member, 2_000).unwrap();
    admin.devices_mut().enroll("bob", "Phone", [9u8; 32], 3_000).unwrap();
    let dev_id = 1u64;
    admin.revoke_device("root", "bob", dev_id, 4_000).unwrap();

    let entries = admin.audit().entries();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].seq, 1);
    assert_eq!(entries[1].seq, 2);
    assert_eq!(entries[2].seq, 3);

    // Verify the full hash chain.
    assert_eq!(verify(entries), Ok(()));

    // Each entry's prev matches the previous entry's hash.
    assert_eq!(entries[1].prev, entries[0].hash);
    assert_eq!(entries[2].prev, entries[1].hash);
}

#[test]
fn equal_timestamps_are_allowed() {
    let mut admin = Admin::new();
    admin.create_room("alice", "General", 5_000).unwrap();
    // Same timestamp should be fine (equal is OK per docs).
    let slug2 = admin.create_room("bob", "Other", 5_000).unwrap();
    assert!(!slug2.is_empty());
    assert_eq!(admin.audit().entries().len(), 2);
    assert_eq!(verify(admin.audit().entries()), Ok(()));
}

#[test]
fn add_member_role_admin_in_action_text() {
    let mut admin = Admin::new();
    let slug = admin.create_room("alice", "General", 1_000).unwrap();
    admin.add_member("alice", &slug, "carol", Role::Admin, 2_000).unwrap();

    let entries = admin.audit().entries();
    assert_eq!(entries[1].action, format!("member.add {slug} carol admin"));
}

#[test]
fn add_member_role_owner_in_action_text() {
    let mut admin = Admin::new();
    let slug = admin.create_room("alice", "General", 1_000).unwrap();
    admin.add_member("alice", &slug, "dave", Role::Owner, 2_000).unwrap();

    let entries = admin.audit().entries();
    assert_eq!(entries[1].action, format!("member.add {slug} dave owner"));
}

#[test]
fn revoke_device_not_yours_is_device_error() {
    let mut admin = Admin::new();
    // Enroll for "alice", try to revoke as "bob".
    let id = admin.devices_mut().enroll("alice", "Phone", [1u8; 32], 500).unwrap();
    let err = admin.revoke_device("root", "bob", id, 1_000).unwrap_err();
    assert_eq!(err, AdminError::Device(crewcraft_server_core::devices::DeviceError::NotYours));
    // No audit entry.
    assert!(admin.audit().entries().is_empty());
}

#[test]
fn revoke_device_no_such_device() {
    let mut admin = Admin::new();
    let err = admin.revoke_device("root", "alice", 99, 1_000).unwrap_err();
    assert_eq!(err, AdminError::Device(crewcraft_server_core::devices::DeviceError::NoSuchDevice));
    assert!(admin.audit().entries().is_empty());
}
