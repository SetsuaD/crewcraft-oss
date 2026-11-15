#![allow(clippy::unwrap_used)]

use crewcraft_server_core::cert_policy::{Presented, Verdict, decide};
use crewcraft_server_core::devices::Devices;
use crewcraft_server_core::invites::{Invite, InviteBook};

const FP: [u8; 32] = [0xAA; 32];
const BOOT: [u8; 32] = [0xBB; 32];

fn invite(key: [u8; 32], expires_ms: u64) -> Invite {
    Invite { email: "alice@example.org".into(), bootstrap_pub: key, expires_ms }
}

#[test]
fn an_enrolled_device_is_accepted_and_seen() {
    let mut devices = Devices::new();
    let id = devices.enroll("alice@example.org", "laptop", FP, 1_000).unwrap();
    let invites = InviteBook::new();
    let verdict = decide(&Presented::Issued { fingerprint: FP }, &mut devices, &invites, 5_000);
    match verdict {
        Verdict::Device(d) => {
            assert_eq!(d.id, id);
            assert_eq!(d.user, "alice@example.org");
            assert_eq!(d.last_seen_ms, 5_000);
        }
        other => panic!("expected Device, got {other:?}"),
    }
    // The sighting was recorded in the registry itself.
    assert_eq!(devices.list("alice@example.org")[0].last_seen_ms, 5_000);
}

#[test]
fn an_unknown_issued_certificate_is_rejected() {
    let mut devices = Devices::new();
    let invites = InviteBook::new();
    assert_eq!(decide(&Presented::Issued { fingerprint: FP }, &mut devices, &invites, 0), Verdict::Reject);
}

#[test]
fn a_revoked_device_is_rejected_for_good() {
    let mut devices = Devices::new();
    let id = devices.enroll("alice@example.org", "laptop", FP, 0).unwrap();
    let invites = InviteBook::new();
    assert!(matches!(decide(&Presented::Issued { fingerprint: FP }, &mut devices, &invites, 1), Verdict::Device(_)));
    devices.revoke("alice@example.org", id).unwrap();
    assert_eq!(decide(&Presented::Issued { fingerprint: FP }, &mut devices, &invites, 2), Verdict::Reject);
}

#[test]
fn a_live_invitation_key_is_bootstrap_and_changes_nothing() {
    let mut devices = Devices::new();
    let mut invites = InviteBook::new();
    invites.issue(invite(BOOT, 10_000), 0).unwrap();
    assert_eq!(decide(&Presented::SelfSigned { public_key: BOOT }, &mut devices, &invites, 9_999), Verdict::Bootstrap);
    // Deciding does not use the invitation up.
    assert!(invites.is_pending(&BOOT, 9_999));
    assert!(devices.list("alice@example.org").is_empty());
}

#[test]
fn an_expired_or_unknown_bootstrap_key_is_rejected() {
    let mut devices = Devices::new();
    let mut invites = InviteBook::new();
    invites.issue(invite(BOOT, 10_000), 0).unwrap();
    assert_eq!(decide(&Presented::SelfSigned { public_key: BOOT }, &mut devices, &invites, 10_000), Verdict::Reject);
    assert_eq!(decide(&Presented::SelfSigned { public_key: [0xCC; 32] }, &mut devices, &invites, 1), Verdict::Reject);
}

#[test]
fn a_used_up_invitation_stops_matching() {
    let mut devices = Devices::new();
    let mut invites = InviteBook::new();
    invites.issue(invite(BOOT, 10_000), 0).unwrap();
    invites.redeem(&BOOT, 1).unwrap();
    assert_eq!(decide(&Presented::SelfSigned { public_key: BOOT }, &mut devices, &invites, 2), Verdict::Reject);
}

#[test]
fn a_self_signed_certificate_is_never_a_device() {
    // A device whose fingerprint bytes happen to equal a self-signed key still must not get in as a device that way.
    let mut devices = Devices::new();
    devices.enroll("alice@example.org", "laptop", FP, 0).unwrap();
    let invites = InviteBook::new();
    assert_eq!(decide(&Presented::SelfSigned { public_key: FP }, &mut devices, &invites, 1), Verdict::Reject);
    // And an issued certificate is never a bootstrap one, even for a key with a live invitation.
    let mut invites = InviteBook::new();
    invites.issue(invite(BOOT, 10_000), 0).unwrap();
    assert_eq!(decide(&Presented::Issued { fingerprint: BOOT }, &mut devices, &invites, 1), Verdict::Reject);
}

#[test]
fn untrusted_is_always_rejected() {
    let mut devices = Devices::new();
    devices.enroll("alice@example.org", "laptop", FP, 0).unwrap();
    let mut invites = InviteBook::new();
    invites.issue(invite(BOOT, 10_000), 0).unwrap();
    assert_eq!(decide(&Presented::Untrusted, &mut devices, &invites, 1), Verdict::Reject);
}
