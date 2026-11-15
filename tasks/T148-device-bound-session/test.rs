use crewcraft_accounts::sessions::{ABSOLUTE_MS, IDLE_MS, Session, Sessions};

#[test]
fn the_presented_certificate_must_identify_both_session_fields() {
    let mut sessions = Sessions::new();
    let token = sessions.create([1; 32], "alice@example.org", "1", 10);

    assert_eq!(sessions.validate_for(&token, "alice@example.org", "2", 11), None);
    assert_eq!(sessions.validate_for(&token, "bob@example.org", "1", 12), None);
    assert_eq!(sessions.validate_for("unknown", "alice@example.org", "1", 13), None);
    assert_eq!(
        sessions.validate_for(&token, "alice@example.org", "1", 14),
        Some(Session { user: "alice@example.org".into(), device: "1".into(), created_ms: 10, last_seen_ms: 14 })
    );
}

#[test]
fn mismatches_do_not_extend_idle_time_or_remove_the_entry() {
    let mut sessions = Sessions::new();
    let token = sessions.create([2; 32], "alice@example.org", "1", 0);

    assert_eq!(sessions.validate_for(&token, "alice@example.org", "2", IDLE_MS - 1), None);
    assert_eq!(sessions.validate_for(&token, "bob@example.org", "1", IDLE_MS), None);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions.validate_for(&token, "alice@example.org", "1", IDLE_MS), None);
    assert!(sessions.is_empty());
}

#[test]
fn certificate_bound_sessions_keep_absolute_expiry_and_revocation() {
    let mut sessions = Sessions::new();
    let token = sessions.create([3; 32], "alice@example.org", "1", 0);
    let mut now = 0;
    while now + IDLE_MS - 1 < ABSOLUTE_MS {
        now += IDLE_MS - 1;
        assert!(sessions.validate_for(&token, "alice@example.org", "1", now).is_some());
    }
    assert_eq!(sessions.validate_for(&token, "alice@example.org", "1", ABSOLUTE_MS), None);
    assert!(sessions.is_empty());

    let token = sessions.create([4; 32], "alice@example.org", "2", ABSOLUTE_MS);
    assert_eq!(sessions.revoke_device("alice@example.org", "2"), 1);
    assert_eq!(sessions.validate_for(&token, "alice@example.org", "2", ABSOLUTE_MS + 1), None);
}
