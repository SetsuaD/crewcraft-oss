//! The bootstrap handler's order of operations, on byte frames with no network: what Redeem and ConfirmTotp release, when,
//! and what closes the connection without a byte.

#![allow(clippy::unwrap_used)]

mod common;

use common::*;
use crewcraft_bootstrap::{BootstrapConnection, ERR_BAD_CODE, ERR_BAD_REQUEST, ERR_PASSWORD, ERR_RATE_LIMITED, ERR_UNAVAILABLE};
use crewcraft_pki::{Status, key_id_of_certificate};
use crewcraft_proto::bootstrap::BootstrapResponse;
use crewcraft_server_core::activation::{MAX_WRONG_CODES, SOURCE_BURST};
use rcgen::{KeyPair, PKCS_ED25519};

fn only(out: &crewcraft_bootstrap::Output) -> BootstrapResponse {
    let mut all = replies(&out.bytes);
    assert_eq!(all.len(), 1, "expected exactly one reply, got {all:?}");
    all.remove(0).1
}

/// A connection that has redeemed and received Setup, ready to confirm.
fn staged() -> (World, BootstrapConnection, KeyPair, Vec<u8>) {
    let mut w = world();
    let mut conn = connection(&w);
    let (key, csr) = device_csr();
    let out = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    assert!(out.open && matches!(only(&out), BootstrapResponse::Setup { .. }));
    (w, conn, key, csr)
}

fn assert_closed_silently(out: &crewcraft_bootstrap::Output) {
    assert!(out.bytes.is_empty(), "a closing connection wrote {:?}", out.bytes);
    assert!(!out.open);
}

#[test]
fn redeem_answers_setup_with_the_authenticator_uri_and_no_certificate() {
    let mut w = world();
    let mut conn = connection(&w);
    let (_key, csr) = device_csr();
    let out = conn.receive(&mut w.enroller, &redeem_frame(7, "laptop", &csr, PASSWORD));
    assert!(out.open);
    let all = replies(&out.bytes);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, 7, "the reply repeats the request id");
    let BootstrapResponse::Setup { totp_uri } = &all[0].1 else { panic!("not Setup: {:?}", all[0].1) };
    assert!(totp_uri.starts_with("otpauth://totp/"), "{totp_uri}");
    // Setup carries exactly the authenticator enrollment for the server-drawn secret, and not one byte more.
    let expected = crewcraft_totp::Totp::with_defaults(w.secret.to_vec()).unwrap().otpauth_uri(crewcraft_server_core::activation::ISSUER, EMAIL);
    assert_eq!(totp_uri, &expected);
    // Nothing a device could use exists yet: the reply is small, holds no authority certificate, and nothing was
    // committed or registered.
    assert!(out.bytes.len() < 400, "a Setup reply of {} bytes", out.bytes.len());
    assert!(!contains(&out.bytes, w.enroller.authority().certificate()));
    assert!(w.enroller.services().attempted.is_empty());
    assert!(w.enroller.activation().devices().list(EMAIL).is_empty());
    assert!(!w.enroller.activation().totp().is_enrolled(EMAIL));
    assert!(w.enroller.activation().is_pending(&w.key, now_ms()), "the invitation is not used up by Redeem");
}

#[test]
fn confirm_commits_everything_then_releases_the_chain() {
    let (mut w, mut conn, key, csr) = staged();
    let secret = w.secret;
    let code = w.code_for(secret);
    let out = conn.receive(&mut w.enroller, &confirm_frame(2, &code));
    assert!(!out.open, "the connection closes after Activated");
    let BootstrapResponse::Activated { certificate, issuer_certificate } = only(&out) else { panic!("not Activated") };

    // The issuer is the authority; the leaf is the one the store was asked to commit, byte for byte.
    assert_eq!(issuer_certificate, w.enroller.authority().certificate());
    let store = w.enroller.services();
    assert_eq!(store.committed.len(), 1);
    let record = &store.committed[0];
    assert_eq!(record.chain, vec![certificate.clone(), issuer_certificate]);
    assert_eq!(record.email, EMAIL);
    assert_eq!(record.device_name, "laptop");
    assert_eq!(record.bootstrap_pub, w.key);
    assert_eq!(record.totp_secret, secret);
    assert!(record.password_phc.starts_with("$argon2id$"), "the password is stored only as an Argon2id hash");
    assert!(!record.password_phc.contains(PASSWORD));

    // Identity: the stable key identity is the SPKI hash of the key the device proved it holds. The ordinal and the serial
    // are separate fields and neither is the identity.
    assert_eq!(record.key_id, key_id_of_certificate(&certificate).unwrap());
    assert_eq!(record.key_id, crewcraft_pki::csr_key_id(&csr).unwrap());
    assert_eq!(record.device_id, 1);
    assert_eq!(record.serial, crewcraft_pki::serial_of_certificate(&certificate).unwrap());
    assert_ne!(record.serial, record.device_id.to_be_bytes());
    let _ = key;

    // The authority now knows the leaf, the registry has the device under the same key identity, the invitation is used up
    // and the first code's counter is recorded so it cannot be replayed.
    let Status::Good(info) = w.enroller.authority().status(&certificate, now_ms()).unwrap() else { panic!("leaf not good") };
    assert_eq!((info.person.as_str(), info.device_id, info.key_id), (EMAIL, 1, record.key_id));
    let devices = w.enroller.activation().devices().list(EMAIL);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].fingerprint, record.key_id);
    assert!(!w.enroller.activation().is_pending(&w.key, now_ms()));
    assert_eq!(w.enroller.activation().totp().last_counter(EMAIL), Some(record.accepted_counter));
}

#[test]
fn a_wrong_code_keeps_the_attempt_and_the_right_one_still_works() {
    let (mut w, mut conn, _key, _csr) = staged();
    let out = conn.receive(&mut w.enroller, &confirm_frame(2, "000000"));
    assert!(out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_BAD_CODE });
    assert!(w.enroller.services().attempted.is_empty(), "nothing is committed for a wrong code");
    assert!(w.enroller.activation().devices().list(EMAIL).is_empty());
    let secret = w.secret;
    let code = w.code_for(secret);
    let out = conn.receive(&mut w.enroller, &confirm_frame(3, &code));
    assert!(matches!(only(&out), BootstrapResponse::Activated { .. }));
}

#[test]
fn too_many_wrong_codes_end_the_attempt_and_even_the_right_code_is_refused() {
    let (mut w, mut conn, _key, _csr) = staged();
    for n in 0..MAX_WRONG_CODES {
        // One second between tries: the source bucket (shared by Redeem and Confirm) refills one call a second.
        w.enroller.services_mut().clock_ms += 1100;
        let out = conn.receive(&mut w.enroller, &confirm_frame(10 + n, "000000"));
        assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_BAD_CODE }, "wrong code {}", n + 1);
    }
    let secret = w.secret;
    w.enroller.services_mut().clock_ms += 1100;
    let code = w.code_for(secret);
    let out = conn.receive(&mut w.enroller, &confirm_frame(99, &code));
    assert_closed_silently(&out);
    assert!(w.enroller.services().attempted.is_empty());
    assert!(w.enroller.activation().is_pending(&w.key, now_ms()), "the invitation survives for a fresh attempt");
}

#[test]
fn guessing_codes_from_one_source_runs_into_the_source_limit_first() {
    let (mut w, mut conn, _key, _csr) = staged();
    // Redeem used one of the source's five calls; four wrong codes use the rest, and the fifth is limited and ends it.
    for n in 0..4 {
        let out = conn.receive(&mut w.enroller, &confirm_frame(10 + n, "000000"));
        assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_BAD_CODE }, "wrong code {}", n + 1);
    }
    let out = conn.receive(&mut w.enroller, &confirm_frame(20, "000000"));
    assert!(!out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_RATE_LIMITED });
    assert!(w.enroller.services().attempted.is_empty());
    assert!(w.enroller.activation().is_pending(&w.key, now_ms()), "the invitation survives");
}

#[test]
fn a_second_redeem_replaces_the_attempt() {
    let mut w = world();
    w.enroller.services_mut().secrets.push_back([0x24u8; 20]);
    let mut conn = connection(&w);
    let (_key, csr) = device_csr();
    let first = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    let second = conn.receive(&mut w.enroller, &redeem_frame(2, "laptop", &csr, PASSWORD));
    let (BootstrapResponse::Setup { totp_uri: a }, BootstrapResponse::Setup { totp_uri: b }) = (only(&first), only(&second)) else {
        panic!("not Setup")
    };
    assert_ne!(a, b, "a replacement draws a new authenticator secret");
    // The first secret no longer works; the second does.
    let code = w.code_for([0x42u8; 20]);
    let old = conn.receive(&mut w.enroller, &confirm_frame(3, &code));
    assert_eq!(only(&old), BootstrapResponse::Error { code: ERR_BAD_CODE });
    let code = w.code_for([0x24u8; 20]);
    let new = conn.receive(&mut w.enroller, &confirm_frame(4, &code));
    assert!(matches!(only(&new), BootstrapResponse::Activated { .. }));
}

#[test]
fn any_other_message_closes_without_a_byte() {
    // Confirm before Redeem.
    let mut w = world();
    let mut conn = connection(&w);
    assert_closed_silently(&conn.receive(&mut w.enroller, &confirm_frame(1, "123456")));

    // Ordinary chat requests and sign-in style tags cannot even be decoded here: the tags are disjoint.
    for payload in [vec![0u8, 0, 0, 0, 1], vec![1, 0, 0, 0, 1], vec![5, 0, 0, 0, 1, 0, 0], vec![160, 0, 0, 0, 1, 0, 0], vec![255, 0, 0, 0, 1]] {
        let mut conn = connection(&w);
        let framed = crewcraft_proto::frame::encode(&payload).unwrap();
        assert_closed_silently(&conn.receive(&mut w.enroller, &framed));
    }

    // Truncated and trailing bytes inside a frame.
    let (_key, csr) = device_csr();
    let good = redeem_frame(1, "laptop", &csr, PASSWORD);
    let mut inner = good[4..].to_vec();
    inner.push(0);
    let mut conn = connection(&w);
    assert_closed_silently(&conn.receive(&mut w.enroller, &crewcraft_proto::frame::encode(&inner).unwrap()));
    let mut conn = connection(&w);
    assert_closed_silently(&conn.receive(&mut w.enroller, &crewcraft_proto::frame::encode(&good[4..good.len() - 3]).unwrap()));

    // An oversized frame header.
    let mut conn = connection(&w);
    assert_closed_silently(&conn.receive(&mut w.enroller, &[0x7f, 0xff, 0xff, 0xff, 1, 2, 3]));

    // None of it staged or registered anything.
    assert_eq!(w.enroller.activation().pending_count(), 0);
    assert!(w.enroller.services().attempted.is_empty());
    assert!(w.enroller.activation().is_pending(&w.key, now_ms()));
}

#[test]
fn a_closed_connection_stays_closed() {
    let (mut w, mut conn, _key, _csr) = staged();
    let secret = w.secret;
    let code = w.code_for(secret);
    assert!(!conn.receive(&mut w.enroller, &confirm_frame(2, &code)).open);
    assert!(conn.is_closed());
    let code = w.code_for(secret);
    let again = conn.receive(&mut w.enroller, &confirm_frame(3, &code));
    assert_closed_silently(&again);
    assert_eq!(w.enroller.services().committed.len(), 1, "no second commit");
}

#[test]
fn a_failed_durable_commit_releases_no_chain_and_poisons_the_enroller() {
    let (mut w, mut conn, _key, _csr) = staged();
    w.enroller.services_mut().fail_next_commit = true;
    let secret = w.secret;
    let code = w.code_for(secret);
    let out = conn.receive(&mut w.enroller, &confirm_frame(2, &code));
    assert!(!out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_UNAVAILABLE });

    // The store was asked, it refused, and the leaf it was asked to commit appears nowhere on the wire.
    let store = w.enroller.services();
    assert_eq!(store.attempted.len(), 1);
    assert!(store.committed.is_empty());
    let leaf = &store.attempted[0].chain[0];
    assert!(!contains(&out.bytes, leaf), "the uncommitted leaf was sent");
    assert!(!contains(&out.bytes, w.enroller.authority().certificate()), "no chain part was sent");
    // The authority never recorded it either.
    assert_eq!(w.enroller.authority().status(leaf, now_ms()).unwrap(), Status::Unknown);

    // In-memory state is ahead of durable state, so the enroller fails closed for everyone until it is rebuilt.
    assert!(w.enroller.is_poisoned());
    let mut next = connection(&w);
    let (_k, csr) = device_csr();
    assert_closed_silently(&next.receive(&mut w.enroller, &redeem_frame(1, "phone", &csr, PASSWORD)));
}

#[test]
fn the_invitation_is_rechecked_against_live_state_before_it_is_used() {
    let (mut w, mut conn, _key, _csr) = staged();
    // Revoked or consumed since the handshake: the listener's liveness answer is now no.
    w.enroller.services_mut().refuse_admission = true;
    let secret = w.secret;
    let code = w.code_for(secret);
    let out = conn.receive(&mut w.enroller, &confirm_frame(2, &code));
    assert_closed_silently(&out);
    assert!(w.enroller.services().attempted.is_empty());
    assert!(w.enroller.activation().devices().list(EMAIL).is_empty());
    assert!(!w.enroller.is_poisoned(), "nothing was changed, so nothing is poisoned");
    assert!(w.enroller.activation().is_pending(&w.key, now_ms()), "the invitation was not consumed");

    // And before Redeem does any work.
    let mut fresh = connection(&w);
    let (_k, csr) = device_csr();
    assert_closed_silently(&fresh.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD)));
    assert_eq!(w.enroller.services().hash_calls, 1, "only the first staged Redeem hashed");
}

#[test]
fn limits_apply_before_any_password_hashing() {
    let mut w = world();
    let (_key, csr) = device_csr();
    for n in 0..SOURCE_BURST {
        w.enroller.services_mut().secrets.push_back([n as u8 + 1; 20]);
        let mut conn = connection(&w);
        let out = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
        assert!(matches!(only(&out), BootstrapResponse::Setup { .. }), "call {}", n + 1);
    }
    assert_eq!(w.enroller.services().hash_calls, SOURCE_BURST as usize);
    // The next call from the same source is limited and costs no Argon2 work.
    w.enroller.services_mut().secrets.push_back([0x77u8; 20]);
    let mut conn = connection(&w);
    let out = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    assert!(!out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_RATE_LIMITED });
    assert_eq!(w.enroller.services().hash_calls, SOURCE_BURST as usize, "a limited call must not be hashed");
}

#[test]
fn a_weak_password_or_a_bad_name_is_refused_before_anything_is_staged() {
    let mut w = world();
    let mut conn = connection(&w);
    let (_key, csr) = device_csr();
    let out = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, "short"));
    assert!(out.open, "the person may try another password on this connection");
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_PASSWORD });
    let out = conn.receive(&mut w.enroller, &redeem_frame(2, "   ", &csr, PASSWORD));
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_BAD_REQUEST });
    assert_eq!(w.enroller.activation().pending_count(), 0);
    assert_eq!(w.enroller.services().hash_calls, 0);
    // A good request on the same connection then works.
    let out = conn.receive(&mut w.enroller, &redeem_frame(3, "laptop", &csr, PASSWORD));
    assert!(matches!(only(&out), BootstrapResponse::Setup { .. }));
}

#[test]
fn a_bad_signing_request_is_refused_and_closes() {
    for csr in [b"not a request".to_vec(), device_csr().1[..10].to_vec(), {
        let ed = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        rcgen::CertificateParams::new(Vec::<String>::new()).unwrap().serialize_request(&ed).unwrap().der().to_vec()
    }] {
        let mut w = world();
        let mut conn = connection(&w);
        let out = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
        assert!(!out.open);
        assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_BAD_REQUEST });
        assert_eq!(w.enroller.activation().pending_count(), 0);
        assert_eq!(w.enroller.services().hash_calls, 0);
    }
}

#[test]
fn a_signing_request_with_a_damaged_signature_is_refused() {
    let mut w = world();
    let mut conn = connection(&w);
    let (_key, mut csr) = device_csr();
    let last = csr.len() - 1;
    csr[last] ^= 0xff;
    let out = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_BAD_REQUEST });
    assert_eq!(w.enroller.activation().pending_count(), 0);
}

#[test]
fn an_invitation_that_is_not_live_gets_no_reply() {
    let mut w = world();
    // A bootstrap key with no invitation behind it.
    let mut conn = BootstrapConnection::new([9u8; 32], SOURCE);
    let (_key, csr) = device_csr();
    assert_closed_silently(&conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD)));
    assert_eq!(w.enroller.activation().pending_count(), 0);
}

#[test]
fn a_failed_random_source_closes_with_an_error_and_stages_nothing() {
    let mut w = world();
    w.enroller.services_mut().secrets.clear();
    let mut conn = connection(&w);
    let (_key, csr) = device_csr();
    let out = conn.receive(&mut w.enroller, &redeem_frame(1, "laptop", &csr, PASSWORD));
    assert!(!out.open);
    assert_eq!(only(&out), BootstrapResponse::Error { code: ERR_UNAVAILABLE });
    assert_eq!(w.enroller.activation().pending_count(), 0);
}

#[test]
fn the_activation_record_never_prints_the_password_hash_or_the_authenticator_secret() {
    let (mut w, mut conn, _key, _csr) = staged();
    let secret = w.secret;
    let code = w.code_for(secret);
    conn.receive(&mut w.enroller, &confirm_frame(2, &code));
    let record = &w.enroller.services().committed[0];
    let printed = format!("{record:?} {conn:?} {:?}", w.enroller);
    assert!(!printed.contains("argon2"), "{printed}");
    assert!(!printed.contains(&format!("{:?}", record.totp_secret)), "{printed}");
}
