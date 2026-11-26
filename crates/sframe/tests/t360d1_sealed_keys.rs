//! T360d1: sealing a sender's base key to each participant (docs/CALLS.md): only the participant it was sealed to
//! opens it, only for the context (call and key id) it was sealed for, a changed box is refused, a low-order public key
//! is refused, and the opened key drives SFrame end to end.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_sframe::seal::{CallKeyPair, OVERHEAD, open, seal};
use crewcraft_sframe::{CipherSuite, Error, Key, decrypt};

#[test]
fn only_the_recipient_opens_it_for_its_context() {
    let bob = CallKeyPair::generate().unwrap();
    let carol = CallKeyPair::generate().unwrap();
    let base_key = b"alice's base key for call 7, key id 3";
    let context = b"call 7 kid 3";
    let sealed = seal(&bob.public_key(), context, base_key).unwrap();
    assert_eq!(sealed.len(), base_key.len() + OVERHEAD);
    assert_eq!(&open(&bob, context, &sealed).unwrap()[..], base_key);
    assert_eq!(open(&carol, context, &sealed), Err(Error::Authentication), "sealed to Bob, not Carol");
    assert_eq!(open(&bob, b"call 8 kid 3", &sealed), Err(Error::Authentication), "not into another call");
    let mut changed = sealed.clone();
    changed[40] ^= 1;
    assert_eq!(open(&bob, context, &changed), Err(Error::Authentication));
    let mut other_ephemeral = sealed.clone();
    other_ephemeral[0] ^= 1;
    assert_eq!(open(&bob, context, &other_ephemeral), Err(Error::Authentication));
    assert_eq!(open(&bob, context, &sealed[..OVERHEAD - 1]), Err(Error::Truncated));
    assert_ne!(seal(&bob.public_key(), context, base_key).unwrap(), sealed, "a fresh ephemeral key for every box");
}

#[test]
fn a_key_pair_survives_being_kept() {
    let pair = CallKeyPair::generate().unwrap();
    let again = CallKeyPair::from_secret(pair.secret());
    assert_eq!(again.public_key(), pair.public_key());
    let sealed = seal(&pair.public_key(), b"ctx", b"key").unwrap();
    assert_eq!(&open(&again, b"ctx", &sealed).unwrap()[..], b"key");
    assert!(!format!("{again:?}").contains("secret"), "Debug never shows the secret");
}

#[test]
fn a_low_order_public_key_is_refused() {
    // The all-zero point and another small-order point (RFC 7748 section 6.1's warning): every shared secret is zero.
    assert_eq!(seal(&[0; 32], b"ctx", b"key"), Err(Error::BadKey));
    let mut one = [0u8; 32];
    one[0] = 1;
    assert_eq!(seal(&one, b"ctx", b"key"), Err(Error::BadKey));
}

#[test]
fn the_opened_key_drives_sframe_end_to_end() {
    let bob = CallKeyPair::generate().unwrap();
    let base_key = b"a sender key made for this call";
    let sealed = seal(&bob.public_key(), b"call 7 kid 3", base_key).unwrap();

    let alice_sends = Key::new(CipherSuite::Aes128GcmSha256, 3, base_key).unwrap();
    let frame = alice_sends.encrypt(0, b"", b"a frame of audio").unwrap();

    let opened = open(&bob, b"call 7 kid 3", &sealed).unwrap();
    let bob_receives = Key::new(CipherSuite::Aes128GcmSha256, 3, &opened).unwrap();
    let keys = |kid| (kid == 3).then_some(&bob_receives);
    assert_eq!(decrypt(keys, b"", &frame).unwrap(), b"a frame of audio");
}
