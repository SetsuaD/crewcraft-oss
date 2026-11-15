#![allow(clippy::unwrap_used)]

use crewcraft_accounts::totp_guard::{GuardError, SKEW_STEPS};
use crewcraft_server_core::activation::{
    Activated, Activation, ActivationError, Begun, EnrollmentCandidate, GLOBAL_BURST, ISSUER, MAX_WRONG_CODES, SOURCE_BURST,
};
use crewcraft_server_core::devices::DeviceError;
use crewcraft_server_core::invites::{Invite, InviteError};
use crewcraft_totp::Totp;

const B1: [u8; 32] = [0x11; 32];
const B2: [u8; 32] = [0x64; 32];
const FP: [u8; 32] = [0x22; 32];
const FP2: [u8; 32] = [0x33; 32];
const SECRET: [u8; 20] = *b"12345678901234567890";
const SECRET2: [u8; 20] = [5u8; 20];
/// 60 s after the epoch: TOTP counter 2.
const NOW: u64 = 60_000;
const EXPIRES: u64 = 1_000_000;
const ALICE: &str = "alice@example.org";

fn code(secret: [u8; 20], t_secs: u64) -> String {
    Totp::with_defaults(secret.to_vec()).unwrap().generate(t_secs)
}

fn src(i: u32) -> String {
    format!("192.0.2.{i}")
}

fn setup() -> Activation {
    let mut a = Activation::new();
    a.invite(Invite { email: "Alice@Example.org".into(), bootstrap_pub: B1, expires_ms: EXPIRES }, 0).unwrap();
    a
}

fn begin(
    activation: &mut Activation,
    source: &str,
    bootstrap: &[u8; 32],
    device_name: &str,
    fingerprint: [u8; 32],
    totp_secret: [u8; 20],
    now_ms: u64,
) -> Result<Begun, ActivationError> {
    activation.begin(source, bootstrap, EnrollmentCandidate { verified_email: ALICE, device_name, fingerprint, totp_secret }, now_ms)
}

#[test]
fn begin_hands_back_the_enrollment_and_registers_nothing() {
    let mut a = setup();
    let begun = begin(&mut a, &src(1), &B1, "laptop", FP, SECRET, NOW).unwrap();
    assert_eq!(begun.email, "alice@example.org");
    assert!(begun.otpauth_uri.starts_with("otpauth://totp/"));
    assert!(begun.otpauth_uri == Totp::with_defaults(SECRET.to_vec()).unwrap().otpauth_uri(ISSUER, ALICE));
    assert!(!format!("{begun:?}").contains("otpauth://"));
    assert!(!format!("{begun:#?}").contains(begun.otpauth_uri.as_str()));
    // No device, no TOTP enrollment, and the invitation is still there.
    assert!(a.devices().list("alice@example.org").is_empty());
    assert_eq!(a.authenticate_device(&FP, NOW), Err(DeviceError::NoSuchDevice));
    assert!(!a.totp().is_enrolled("alice@example.org"));
    assert!(a.is_pending(&B1, NOW));
    assert_eq!(a.pending_count(), 1);
}

#[test]
fn begin_needs_a_live_invitation() {
    let mut a = setup();
    assert_eq!(begin(&mut a, &src(1), &[0x99; 32], "laptop", FP, SECRET, NOW).unwrap_err(), ActivationError::Invite(InviteError::Unknown));
    // Expired invitations are reported the same way as unknown ones.
    assert_eq!(begin(&mut a, &src(2), &B1, "laptop", FP, SECRET, EXPIRES).unwrap_err(), ActivationError::Invite(InviteError::Unknown));
    assert_eq!(a.pending_count(), 0);
}

#[test]
fn confirm_with_the_right_code_activates_the_device() {
    let mut a = setup();
    let attempt = begin(&mut a, &src(1), &B1, "laptop", FP, SECRET, NOW).unwrap().attempt;
    let c = code(SECRET, 60);
    let done = a.confirm(&src(2), &B1, attempt, &c, NOW).unwrap();
    assert_eq!(done, Activated { email: ALICE.into(), device_id: 1, accepted_counter: 2 });

    let devices = a.devices().list("alice@example.org");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, "laptop");
    assert_eq!(devices[0].fingerprint, FP);
    assert!(!devices[0].revoked);
    assert_eq!(a.authenticate_device(&FP, NOW).unwrap().id, done.device_id);

    // The invitation is burned and nothing is pending.
    assert!(!a.is_pending(&B1, NOW));
    assert_eq!(a.pending_count(), 0);
    // The TOTP secret is enrolled and the code just used cannot sign in again.
    assert!(a.totp().is_enrolled("alice@example.org"));
    assert_eq!(a.totp().last_counter("alice@example.org"), Some(2));
    let (totp, last) = a.totp().credential(ALICE).unwrap();
    assert_eq!(totp.verify(&c, 61, SKEW_STEPS, last), None);
    let next = totp.verify(&code(SECRET, 90), 90, SKEW_STEPS, last).unwrap();
    assert_eq!(next, 3);
    assert_eq!(a.record_totp_counter(ALICE, next), Ok(()));
    assert_eq!(a.record_totp_counter(ALICE, next), Err(GuardError::Rejected));
    assert_eq!(a.confirm(&src(3), &B1, attempt, &c, NOW).unwrap_err(), ActivationError::NoPending);
    assert_eq!(a.revoke_device(ALICE, done.device_id), Ok(true));
    assert_eq!(a.authenticate_device(&FP, NOW), Err(DeviceError::Revoked));
}

#[test]
fn confirm_without_begin_is_no_pending() {
    let mut a = setup();
    let mut elsewhere = setup();
    let attempt = begin(&mut elsewhere, &src(1), &B1, "laptop", FP, SECRET, NOW).unwrap().attempt;
    assert_eq!(a.confirm(&src(1), &B1, attempt, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::NoPending);
    assert_eq!(a.confirm(&src(2), &[0x99; 32], attempt, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::NoPending);
}

#[test]
fn a_wrong_code_changes_nothing_and_does_not_burn_the_right_one() {
    let mut a = setup();
    let attempt = begin(&mut a, &src(1), &B1, "laptop", FP, SECRET, NOW).unwrap().attempt;
    assert_eq!(a.confirm(&src(2), &B1, attempt, "000000", NOW).unwrap_err(), ActivationError::BadCode);
    assert!(a.devices().list("alice@example.org").is_empty());
    assert!(!a.totp().is_enrolled("alice@example.org"));
    assert!(a.is_pending(&B1, NOW));
    assert_eq!(a.pending_count(), 1);
    // The right code still works afterwards.
    assert!(a.confirm(&src(3), &B1, attempt, &code(SECRET, 60), NOW).is_ok());
}

#[test]
fn the_code_window_is_one_step_either_side() {
    let mut a = setup();
    let attempt = begin(&mut a, &src(1), &B1, "laptop", FP, SECRET, NOW).unwrap().attempt;
    // NOW is counter 2. A code from counter 0 (two steps back) is refused...
    assert_eq!(a.confirm(&src(2), &B1, attempt, &code(SECRET, 0), NOW).unwrap_err(), ActivationError::BadCode);
    // ...one from counter 1 (T=30) is accepted.
    assert!(a.confirm(&src(3), &B1, attempt, &code(SECRET, 30), NOW).is_ok());
}

#[test]
fn too_many_wrong_codes_drop_the_pending_enrollment_but_not_the_invitation() {
    assert_eq!(MAX_WRONG_CODES, 5);
    let mut a = setup();
    let attempt = begin(&mut a, &src(100), &B1, "laptop", FP, SECRET, NOW).unwrap().attempt;
    for i in 0..MAX_WRONG_CODES {
        assert_eq!(a.confirm(&src(i), &B1, attempt, "000000", NOW).unwrap_err(), ActivationError::BadCode, "wrong code {}", i + 1);
    }
    // Even the right code is now refused: the pending enrollment is gone.
    assert_eq!(a.confirm(&src(50), &B1, attempt, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::NoPending);
    assert_eq!(a.pending_count(), 0);
    // The invitation survived, so the person can begin again with a new secret.
    assert!(a.is_pending(&B1, NOW));
    let attempt = begin(&mut a, &src(51), &B1, "laptop", FP, SECRET2, NOW).unwrap().attempt;
    assert!(a.confirm(&src(52), &B1, attempt, &code(SECRET2, 60), NOW).is_ok());
}

#[test]
fn an_invitation_that_expired_before_the_code_was_entered_is_refused_and_forgotten() {
    let mut a = setup();
    let attempt = begin(&mut a, &src(1), &B1, "laptop", FP, SECRET, NOW).unwrap().attempt;
    let late = EXPIRES;
    assert_eq!(a.confirm(&src(2), &B1, attempt, &code(SECRET, late / 1000), late).unwrap_err(), ActivationError::Invite(InviteError::Expired));
    assert_eq!(a.pending_count(), 0);
    assert!(a.devices().list("alice@example.org").is_empty());
    assert_eq!(a.confirm(&src(3), &B1, attempt, &code(SECRET, late / 1000), late).unwrap_err(), ActivationError::NoPending);
}

#[test]
fn a_device_the_registry_refuses_keeps_the_pending_enrollment() {
    let mut a = setup();
    // Another person's device already has this fingerprint.
    let bob = "bob@example.org";
    a.invite(Invite { email: bob.into(), bootstrap_pub: B2, expires_ms: EXPIRES }, 0).unwrap();
    let candidate = EnrollmentCandidate { verified_email: bob, device_name: "bobs", fingerprint: FP, totp_secret: SECRET2 };
    let bobs_attempt = a.begin(&src(5), &B2, candidate, NOW).unwrap().attempt;
    a.confirm(&src(6), &B2, bobs_attempt, &code(SECRET2, 60), NOW).unwrap();
    let attempt = begin(&mut a, &src(1), &B1, "laptop", FP, SECRET, NOW).unwrap().attempt;
    assert_eq!(a.confirm(&src(2), &B1, attempt, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::Device(DeviceError::FingerprintInUse));
    // Nothing was burned or enrolled.
    assert!(a.devices().list("alice@example.org").is_empty());
    assert!(a.is_pending(&B1, NOW));
    assert!(!a.totp().is_enrolled("alice@example.org"));
    assert_eq!(a.pending_count(), 1);
    // The person starts the device over with another fingerprint and a new secret, and gets through.
    let attempt = begin(&mut a, &src(3), &B1, "laptop", FP2, SECRET2, NOW).unwrap().attempt;
    let done = a.confirm(&src(4), &B1, attempt, &code(SECRET2, 60), NOW).unwrap();
    assert_eq!(done.device_id, 2);
}

#[test]
fn beginning_again_replaces_the_pending_enrollment() {
    let mut a = setup();
    let abandoned = begin(&mut a, &src(1), &B1, "laptop", FP, SECRET, NOW).unwrap().attempt;
    let attempt = begin(&mut a, &src(2), &B1, "phone", FP2, SECRET2, NOW).unwrap().attempt;
    assert_eq!(a.pending_count(), 1);
    // Even the replacement's correct code cannot be used from the abandoned connection.
    assert_eq!(a.confirm(&src(3), &B1, abandoned, &code(SECRET2, 60), NOW).unwrap_err(), ActivationError::WrongAttempt);
    assert_eq!(a.confirm(&src(3), &B1, attempt, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::BadCode);
    a.confirm(&src(4), &B1, attempt, &code(SECRET2, 60), NOW).unwrap();
    let devices = a.devices().list("alice@example.org");
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, "phone");
    assert_eq!(devices[0].fingerprint, FP2);
}

#[test]
fn reissuing_an_invitation_invalidates_the_staged_setup() {
    for new_key in [B1, B2] {
        let mut a = setup();
        let abandoned = begin(&mut a, &src(1), &B1, "laptop", FP, SECRET, NOW).unwrap().attempt;
        a.invite(Invite { email: " ALICE@example.org ".into(), bootstrap_pub: new_key, expires_ms: EXPIRES + 1 }, NOW).unwrap();
        assert_eq!(a.pending_count(), 0);
        assert_eq!(a.confirm(&src(2), &B1, abandoned, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::NoPending);
        let attempt = begin(&mut a, &src(3), &new_key, "laptop", FP, SECRET, NOW).unwrap().attempt;
        assert_eq!(a.confirm(&src(4), &new_key, abandoned, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::WrongAttempt);
        assert!(a.confirm(&src(5), &new_key, attempt, &code(SECRET, 60), NOW).is_ok());
    }
}

#[test]
fn staging_requires_the_password_verified_identity_and_a_first_enrollment() {
    let mut a = setup();
    let candidate = EnrollmentCandidate { verified_email: "bob@example.org", device_name: "laptop", fingerprint: FP, totp_secret: SECRET };
    assert_eq!(a.begin(&src(1), &B1, candidate, NOW).unwrap_err(), ActivationError::AccountMismatch);
    assert_eq!(a.pending_count(), 0);
    assert_eq!(a.authenticate_device(&FP, NOW), Err(DeviceError::NoSuchDevice));

    let attempt = begin(&mut a, &src(2), &B1, "laptop", FP, SECRET, NOW).unwrap().attempt;
    a.confirm(&src(3), &B1, attempt, &code(SECRET, 60), NOW).unwrap();
    a.invite(Invite { email: ALICE.into(), bootstrap_pub: B2, expires_ms: EXPIRES }, NOW).unwrap();
    assert_eq!(begin(&mut a, &src(4), &B2, "phone", FP2, SECRET2, NOW).unwrap_err(), ActivationError::AlreadyEnrolled);
    assert!(a.is_pending(&B2, NOW));
    assert_eq!(a.pending_count(), 0);
    let (totp, last) = a.totp().credential(ALICE).unwrap();
    assert_eq!(totp.secret(), &SECRET);
    assert_eq!(last, Some(2));
    assert_eq!(a.authenticate_device(&FP2, NOW), Err(DeviceError::NoSuchDevice));
}

#[test]
fn each_source_gets_a_few_calls_then_waits() {
    assert_eq!(SOURCE_BURST, 5);
    let mut a = setup();
    for _ in 0..SOURCE_BURST {
        begin(&mut a, "192.0.2.1", &B1, "laptop", FP, SECRET, NOW).unwrap();
    }
    assert_eq!(begin(&mut a, "192.0.2.1", &B1, "laptop", FP, SECRET, NOW).unwrap_err(), ActivationError::RateLimited);
    // Another address is unaffected.
    assert!(begin(&mut a, "192.0.2.2", &B1, "laptop", FP, SECRET, NOW).is_ok());
    // One token comes back each second.
    assert!(begin(&mut a, "192.0.2.1", &B1, "laptop", FP, SECRET, NOW + 1_000).is_ok());
    assert_eq!(begin(&mut a, "192.0.2.1", &B1, "laptop", FP, SECRET, NOW + 1_000).unwrap_err(), ActivationError::RateLimited);
}

#[test]
fn the_limit_comes_before_the_invitation_lookup() {
    let mut a = setup();
    for _ in 0..SOURCE_BURST {
        assert_eq!(begin(&mut a, "192.0.2.1", &[0x99; 32], "laptop", FP, SECRET, NOW).unwrap_err(), ActivationError::Invite(InviteError::Unknown));
    }
    // Guessing keys from one address stops being answered at all after the burst: the right key is limited too.
    assert_eq!(begin(&mut a, "192.0.2.1", &B1, "laptop", FP, SECRET, NOW).unwrap_err(), ActivationError::RateLimited);
}

#[test]
fn begin_and_confirm_share_one_bucket_per_source() {
    let mut a = setup();
    let attempt = begin(&mut a, "192.0.2.1", &B1, "laptop", FP, SECRET, NOW).unwrap().attempt;
    for _ in 0..(SOURCE_BURST - 1) {
        assert_eq!(a.confirm("192.0.2.1", &B1, attempt, "000000", NOW).unwrap_err(), ActivationError::BadCode);
    }
    // Five calls made: the sixth, with the right code, is limited.
    assert_eq!(a.confirm("192.0.2.1", &B1, attempt, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::RateLimited);
}

#[test]
fn the_whole_server_has_a_cap_too() {
    assert_eq!(GLOBAL_BURST, 50);
    let mut a = setup();
    let attempt = begin(&mut a, &src(0), &B1, "laptop", FP, SECRET, NOW).unwrap().attempt;
    for i in 1..GLOBAL_BURST {
        begin(&mut a, &src(i), &B1, "laptop", FP, SECRET, NOW).unwrap();
    }
    // A source that has made no calls is still refused: the server-wide bucket is empty.
    assert_eq!(begin(&mut a, "203.0.113.9", &B1, "laptop", FP, SECRET, NOW).unwrap_err(), ActivationError::RateLimited);
    assert_eq!(a.confirm("203.0.113.9", &B1, attempt, &code(SECRET, 60), NOW).unwrap_err(), ActivationError::RateLimited);
    // Five tokens a second come back: 200 ms later there is one.
    assert!(begin(&mut a, "203.0.113.9", &B1, "laptop", FP, SECRET, NOW + 200).is_ok());
}
