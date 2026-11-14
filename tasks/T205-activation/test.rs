#![allow(clippy::unwrap_used)]

use crewcraft_accounts::totp_guard::GuardError;
use crewcraft_server_core::activation::{Activated, Activation, ActivationError, GLOBAL_BURST, ISSUER, MAX_WRONG_CODES, SOURCE_BURST};
use crewcraft_server_core::devices::DeviceError;
use crewcraft_server_core::invites::{Invite, InviteError};
use crewcraft_totp::Totp;

const B1: [u8; 32] = [0x11; 32];
const FP: [u8; 32] = [0x22; 32];
const FP2: [u8; 32] = [0x33; 32];
const SECRET: [u8; 20] = *b"12345678901234567890";
const SECRET2: [u8; 20] = [5u8; 20];
/// 60 s after the epoch: TOTP counter 2.
const NOW: u64 = 60_000;
const EXPIRES: u64 = 1_000_000;

fn code(secret: [u8; 20], t_secs: u64) -> String {
    Totp::with_defaults(secret.to_vec()).unwrap().generate(t_secs)
}

fn src(i: u32) -> String {
    format!("10.0.0.{i}")
}

fn setup() -> Activation {
    let mut a = Activation::new();
    a.invite(Invite { email: "Alice@Example.org".into(), bootstrap_pub: B1, expires_ms: EXPIRES }, 0).unwrap();
    a
}

#[test]
fn begin_hands_back_the_enrollment_and_registers_nothing() {
    let mut a = setup();
    let begun = a.begin(&src(1), &B1, "laptop", FP, SECRET, NOW).unwrap();
    assert_eq!(begun.email, "alice@example.org");
    assert!(begun.otpauth_uri.starts_with("otpauth://totp/"), "{}", begun.otpauth_uri);
    assert!(begun.otpauth_uri.contains(ISSUER));
    assert!(begun.otpauth_uri.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"));
    // No device, no TOTP enrollment, and the invitation is still there.
    assert!(a.devices().list("alice@example.org").is_empty());
    assert!(!a.totp().is_enrolled("alice@example.org"));
    assert!(a.is_pending(&B1, NOW));
    assert_eq!(a.pending_count(), 1);
}

#[test]
fn begin_needs_a_live_invitation() {
    let mut a = setup();
    assert_eq!(a.begin(&src(1), &[0x99; 32], "laptop", FP, SECRET, NOW).unwrap_err(), ActivationError::Invite(InviteError::Unknown));
    // Expired invitations are reported the same way as unknown ones.
    assert_eq!(a.begin(&src(2), &B1, "laptop", FP, SECRET, EXPIRES).unwrap_err(), ActivationError::Invite(InviteError::Unknown));
    assert_eq!(a.pending_count(), 0);
}

#[test]
fn confirm_with_the_right_code_activates_the_device() {
    let mut a = setup();
    a.begin(&src(1), &B1, "laptop", FP, SECRET, NOW).unwrap();
    let c = code(SECRET, 60);
    let done = a.confirm(&src(2), &B1, &c, NOW).unwrap();
    assert_eq!(done, Activated { email: "alice@example.org".into(), device_id: 1 });

    let devices = a.devices().list("alice@example.org");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, "laptop");
    assert_eq!(devices[0].fingerprint, FP);
    assert!(!devices[0].revoked);

    // The invitation is burned and nothing is pending.
    assert!(!a.is_pending(&B1, NOW));
    assert_eq!(a.pending_count(), 0);
    // The TOTP secret is enrolled and the code just used cannot sign in again.
    assert!(a.totp().is_enrolled("alice@example.org"));
    assert_eq!(a.totp().last_counter("alice@example.org"), Some(2));
    assert_eq!(a.totp().verify("alice@example.org", &c, 61).unwrap_err(), GuardError::Rejected);
    // A fresh code from the next step does sign in.
    assert_eq!(a.totp().verify("alice@example.org", &code(SECRET, 90), 90), Ok(3));
}

#[test]
fn confirm_without_begin_is_no_pending() {
    let mut a = setup();
    assert_eq!(a.confirm(&src(1), &B1, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::NoPending);
    assert_eq!(a.confirm(&src(2), &[0x99; 32], &code(SECRET, 60), NOW).unwrap_err(), ActivationError::NoPending);
}

#[test]
fn a_wrong_code_changes_nothing_and_does_not_burn_the_right_one() {
    let mut a = setup();
    a.begin(&src(1), &B1, "laptop", FP, SECRET, NOW).unwrap();
    assert_eq!(a.confirm(&src(2), &B1, "000000", NOW).unwrap_err(), ActivationError::BadCode);
    assert!(a.devices().list("alice@example.org").is_empty());
    assert!(!a.totp().is_enrolled("alice@example.org"));
    assert!(a.is_pending(&B1, NOW));
    assert_eq!(a.pending_count(), 1);
    // The right code still works afterwards.
    assert!(a.confirm(&src(3), &B1, &code(SECRET, 60), NOW).is_ok());
}

#[test]
fn the_code_window_is_one_step_either_side() {
    let mut a = setup();
    a.begin(&src(1), &B1, "laptop", FP, SECRET, NOW).unwrap();
    // NOW is counter 2. A code from counter 0 (two steps back) is refused...
    assert_eq!(a.confirm(&src(2), &B1, &code(SECRET, 0), NOW).unwrap_err(), ActivationError::BadCode);
    // ...one from counter 1 (T=30) is accepted.
    assert!(a.confirm(&src(3), &B1, &code(SECRET, 30), NOW).is_ok());
}

#[test]
fn too_many_wrong_codes_drop_the_pending_enrollment_but_not_the_invitation() {
    assert_eq!(MAX_WRONG_CODES, 5);
    let mut a = setup();
    a.begin(&src(100), &B1, "laptop", FP, SECRET, NOW).unwrap();
    for i in 0..MAX_WRONG_CODES {
        assert_eq!(a.confirm(&src(i), &B1, "000000", NOW).unwrap_err(), ActivationError::BadCode, "wrong code {}", i + 1);
    }
    // Even the right code is now refused: the pending enrollment is gone.
    assert_eq!(a.confirm(&src(50), &B1, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::NoPending);
    assert_eq!(a.pending_count(), 0);
    // The invitation survived, so the person can begin again with a new secret.
    assert!(a.is_pending(&B1, NOW));
    a.begin(&src(51), &B1, "laptop", FP, SECRET2, NOW).unwrap();
    assert!(a.confirm(&src(52), &B1, &code(SECRET2, 60), NOW).is_ok());
}

#[test]
fn an_invitation_that_expired_before_the_code_was_entered_is_refused_and_forgotten() {
    let mut a = setup();
    a.begin(&src(1), &B1, "laptop", FP, SECRET, NOW).unwrap();
    let late = EXPIRES;
    assert_eq!(a.confirm(&src(2), &B1, &code(SECRET, late / 1000), late).unwrap_err(), ActivationError::Invite(InviteError::Expired));
    assert_eq!(a.pending_count(), 0);
    assert!(a.devices().list("alice@example.org").is_empty());
    assert_eq!(a.confirm(&src(3), &B1, &code(SECRET, late / 1000), late).unwrap_err(), ActivationError::NoPending);
}

#[test]
fn a_device_the_registry_refuses_keeps_the_pending_enrollment() {
    let mut a = setup();
    // Another person's device already has this fingerprint.
    a.devices().enroll("bob@example.org", "bobs", FP, 0).unwrap();
    a.begin(&src(1), &B1, "laptop", FP, SECRET, NOW).unwrap();
    assert_eq!(a.confirm(&src(2), &B1, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::Device(DeviceError::FingerprintInUse));
    // Nothing was burned or enrolled.
    assert!(a.devices().list("alice@example.org").is_empty());
    assert!(a.is_pending(&B1, NOW));
    assert!(!a.totp().is_enrolled("alice@example.org"));
    assert_eq!(a.pending_count(), 1);
    // The person starts the device over with another fingerprint and a new secret, and gets through.
    a.begin(&src(3), &B1, "laptop", FP2, SECRET2, NOW).unwrap();
    let done = a.confirm(&src(4), &B1, &code(SECRET2, 60), NOW).unwrap();
    assert_eq!(done.device_id, 2);
}

#[test]
fn beginning_again_replaces_the_pending_enrollment() {
    let mut a = setup();
    a.begin(&src(1), &B1, "laptop", FP, SECRET, NOW).unwrap();
    a.begin(&src(2), &B1, "phone", FP2, SECRET2, NOW).unwrap();
    assert_eq!(a.pending_count(), 1);
    // The first secret no longer works, the second does, and the device is the second one.
    assert_eq!(a.confirm(&src(3), &B1, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::BadCode);
    a.confirm(&src(4), &B1, &code(SECRET2, 60), NOW).unwrap();
    let devices = a.devices().list("alice@example.org");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, "phone");
    assert_eq!(devices[0].fingerprint, FP2);
}

#[test]
fn each_source_gets_a_few_calls_then_waits() {
    assert_eq!(SOURCE_BURST, 5);
    let mut a = setup();
    for _ in 0..SOURCE_BURST {
        a.begin("192.0.2.1", &B1, "laptop", FP, SECRET, NOW).unwrap();
    }
    assert_eq!(a.begin("192.0.2.1", &B1, "laptop", FP, SECRET, NOW).unwrap_err(), ActivationError::RateLimited);
    // Another address is unaffected.
    assert!(a.begin("192.0.2.2", &B1, "laptop", FP, SECRET, NOW).is_ok());
    // One token comes back each second.
    assert!(a.begin("192.0.2.1", &B1, "laptop", FP, SECRET, NOW + 1_000).is_ok());
    assert_eq!(a.begin("192.0.2.1", &B1, "laptop", FP, SECRET, NOW + 1_000).unwrap_err(), ActivationError::RateLimited);
}

#[test]
fn the_limit_comes_before_the_invitation_lookup() {
    let mut a = setup();
    for _ in 0..SOURCE_BURST {
        assert_eq!(a.begin("192.0.2.1", &[0x99; 32], "laptop", FP, SECRET, NOW).unwrap_err(), ActivationError::Invite(InviteError::Unknown));
    }
    // Guessing keys from one address stops being answered at all after the burst: the right key is limited too.
    assert_eq!(a.begin("192.0.2.1", &B1, "laptop", FP, SECRET, NOW).unwrap_err(), ActivationError::RateLimited);
}

#[test]
fn begin_and_confirm_share_one_bucket_per_source() {
    let mut a = setup();
    a.begin("192.0.2.1", &B1, "laptop", FP, SECRET, NOW).unwrap();
    for _ in 0..(SOURCE_BURST - 1) {
        assert_eq!(a.confirm("192.0.2.1", &B1, "000000", NOW).unwrap_err(), ActivationError::BadCode);
    }
    // Five calls made: the sixth, with the right code, is limited.
    assert_eq!(a.confirm("192.0.2.1", &B1, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::RateLimited);
}

#[test]
fn the_whole_server_has_a_cap_too() {
    assert_eq!(GLOBAL_BURST, 50);
    let mut a = setup();
    for i in 0..GLOBAL_BURST {
        a.begin(&src(i), &B1, "laptop", FP, SECRET, NOW).unwrap();
    }
    // A source that has made no calls is still refused: the server-wide bucket is empty.
    assert_eq!(a.begin("203.0.113.9", &B1, "laptop", FP, SECRET, NOW).unwrap_err(), ActivationError::RateLimited);
    assert_eq!(a.confirm("203.0.113.9", &B1, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::RateLimited);
    // Five tokens a second come back: 200 ms later there is one.
    assert!(a.begin("203.0.113.9", &B1, "laptop", FP, SECRET, NOW + 200).is_ok());
}
