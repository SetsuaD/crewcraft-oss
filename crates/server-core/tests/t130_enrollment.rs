#![allow(clippy::unwrap_used)]

use crewcraft_server_core::devices::DeviceError;
use crewcraft_server_core::enrollment::{EnrollError, Enrollment, REDEEM_BURST};
use crewcraft_server_core::invites::{Invite, InviteError};

#[test]
fn new_has_no_invitations_or_devices() {
    let mut enroll = Enrollment::new();
    let key = [7u8; 32];
    assert!(!enroll.is_pending(&key, 0));
    let devs = enroll.devices();
    assert!(devs.list("alice@example.com").is_empty());
}

#[test]
fn invite_records_and_is_pending_until_expiry() {
    let mut enroll = Enrollment::new();
    let key = [1u8; 32];
    let invite = Invite { email: "alice@example.com".into(), bootstrap_pub: key, expires_ms: 10_000 };
    enroll.invite(invite, 0).unwrap();
    assert!(enroll.is_pending(&key, 0));
    assert!(enroll.is_pending(&key, 9_999));
    // At or after expiry the invitation is no longer live.
    assert!(!enroll.is_pending(&key, 10_000));
    assert!(!enroll.is_pending(&key, 20_000));
}

#[test]
fn invite_key_in_use_when_different_email_same_key() {
    let mut enroll = Enrollment::new();
    let key = [2u8; 32];
    let invite_a = Invite { email: "alice@example.com".into(), bootstrap_pub: key, expires_ms: 10_000 };
    let invite_b = Invite { email: "bob@example.com".into(), bootstrap_pub: key, expires_ms: 10_000 };
    enroll.invite(invite_a, 0).unwrap();
    let err = enroll.invite(invite_b, 0).unwrap_err();
    assert_eq!(err, EnrollError::Invite(InviteError::KeyInUse));
    // "nothing changes": the original invitation is still live.
    assert!(enroll.is_pending(&key, 0));
}

#[test]
fn invite_same_email_case_insensitive_replaces_old_key() {
    let mut enroll = Enrollment::new();
    let key_old = [3u8; 32];
    let key_new = [4u8; 32];
    let invite_old = Invite { email: "Alice@Example.COM".into(), bootstrap_pub: key_old, expires_ms: 10_000 };
    let invite_new = Invite { email: "alice@example.com".into(), bootstrap_pub: key_new, expires_ms: 20_000 };
    enroll.invite(invite_old, 0).unwrap();
    enroll.invite(invite_new, 0).unwrap();
    // Old key is gone (replaced).
    assert!(!enroll.is_pending(&key_old, 0));
    // New key is live.
    assert!(enroll.is_pending(&key_new, 0));
}

#[test]
fn redeem_success_returns_lowercased_email_and_device_id() {
    let mut enroll = Enrollment::new();
    let key = [5u8; 32];
    let invite = Invite { email: "Alice@Example.COM".into(), bootstrap_pub: key, expires_ms: 10_000 };
    enroll.invite(invite, 0).unwrap();

    let fp = [9u8; 32];
    let (email, id) = enroll.redeem("192.0.2.1", &key, "My Laptop", fp, 0).unwrap();
    assert_eq!(email, "alice@example.com");
    assert_eq!(id, 1);

    // Invitation is consumed.
    assert!(!enroll.is_pending(&key, 0));

    // Device is registered under the lowercased email.
    let devs = enroll.devices();
    let list = devs.list("alice@example.com");
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "My Laptop");
    assert_eq!(list[0].fingerprint, fp);
    assert!(!list[0].revoked);
}

#[test]
fn redeem_rate_limited_after_burst_exhausted() {
    let mut enroll = Enrollment::new();
    let key = [6u8; 32];
    let fp = [10u8; 32];

    // No invitation exists; each call still consumes a rate-limit token.
    for _ in 0..REDEEM_BURST {
        let err = enroll.redeem("192.0.2.1", &key, "Dev", fp, 0).unwrap_err();
        assert_eq!(err, EnrollError::Invite(InviteError::Unknown));
    }
    // (REDEEM_BURST + 1)-th attempt at the same instant: no tokens left.
    let err = enroll.redeem("192.0.2.1", &key, "Dev", fp, 0).unwrap_err();
    assert_eq!(err, EnrollError::RateLimited);
}

#[test]
fn redeem_rate_limit_refills_one_per_second() {
    let mut enroll = Enrollment::new();
    let key = [7u8; 32];
    let fp = [11u8; 32];

    // Exhaust all burst tokens at t=0.
    for _ in 0..REDEEM_BURST {
        enroll.redeem("192.0.2.1", &key, "Dev", fp, 0).unwrap_err();
    }
    assert_eq!(enroll.redeem("192.0.2.1", &key, "Dev", fp, 0).unwrap_err(), EnrollError::RateLimited);

    // After exactly 1 s, REDEEM_PER_SEC (=1) token has refilled.
    let err = enroll.redeem("192.0.2.1", &key, "Dev", fp, 1000).unwrap_err();
    assert_eq!(err, EnrollError::Invite(InviteError::Unknown));

    // But now the bucket is empty again.
    let err = enroll.redeem("192.0.2.1", &key, "Dev", fp, 1000).unwrap_err();
    assert_eq!(err, EnrollError::RateLimited);
}

#[test]
fn redeem_rate_limit_is_independent_per_source() {
    let mut enroll = Enrollment::new();
    let key = [8u8; 32];
    let fp = [12u8; 32];

    // Exhaust source A's bucket.
    for _ in 0..REDEEM_BURST {
        enroll.redeem("192.0.2.10", &key, "Dev", fp, 0).unwrap_err();
    }
    assert_eq!(enroll.redeem("192.0.2.10", &key, "Dev", fp, 0).unwrap_err(), EnrollError::RateLimited);

    // Source B still has a full bucket.
    let err = enroll.redeem("192.0.2.11", &key, "Dev", fp, 0).unwrap_err();
    assert_eq!(err, EnrollError::Invite(InviteError::Unknown));
}

#[test]
fn redeem_expired_invite_is_removed() {
    let mut enroll = Enrollment::new();
    let key = [13u8; 32];
    let invite = Invite { email: "alice@example.com".into(), bootstrap_pub: key, expires_ms: 5_000 };
    enroll.invite(invite, 0).unwrap();
    assert!(enroll.is_pending(&key, 0));

    let fp = [14u8; 32];
    let err = enroll.redeem("192.0.2.1", &key, "Dev", fp, 10_000).unwrap_err();
    assert_eq!(err, EnrollError::Invite(InviteError::Expired));

    // The expired invitation has been removed.
    assert!(!enroll.is_pending(&key, 10_000));
}

#[test]
fn redeem_device_error_leaves_invite_pending_for_retry() {
    let mut enroll = Enrollment::new();
    let key = [15u8; 32];
    let invite = Invite { email: "alice@example.com".into(), bootstrap_pub: key, expires_ms: 10_000 };
    enroll.invite(invite, 0).unwrap();

    let fp = [16u8; 32];
    // Empty (after trim) name → BadName.
    let err = enroll.redeem("192.0.2.1", &key, "   ", fp, 0).unwrap_err();
    assert_eq!(err, EnrollError::Device(DeviceError::BadName));

    // Invitation is still live: the user can try again with a valid name.
    assert!(enroll.is_pending(&key, 0));

    let (email, id) = enroll.redeem("192.0.2.1", &key, "Good Name", fp, 0).unwrap();
    assert_eq!(email, "alice@example.com");
    assert_eq!(id, 1);
    assert!(!enroll.is_pending(&key, 0));
}

#[test]
fn redeem_with_unknown_bootstrap_key() {
    let mut enroll = Enrollment::new();
    let key = [20u8; 32];
    let fp = [21u8; 32];
    let err = enroll.redeem("192.0.2.1", &key, "Dev", fp, 0).unwrap_err();
    assert_eq!(err, EnrollError::Invite(InviteError::Unknown));
}

#[test]
fn devices_registry_exposes_enrolled_device() {
    let mut enroll = Enrollment::new();
    let key = [22u8; 32];
    let invite = Invite { email: "bob@example.com".into(), bootstrap_pub: key, expires_ms: 10_000 };
    enroll.invite(invite, 0).unwrap();

    let fp = [23u8; 32];
    enroll.redeem("192.0.2.1", &key, "Phone", fp, 0).unwrap();

    let devs = enroll.devices();
    let auth = devs.authenticate(&fp, 500).unwrap();
    assert_eq!(auth.name, "Phone");
    assert_eq!(auth.last_seen_ms, 500);
}
