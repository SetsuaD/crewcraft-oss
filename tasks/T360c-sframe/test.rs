//! T360c: SFrame (RFC 9605) for end-to-end encrypted calls (docs/CALLS.md): the header's minimal encoding (Appendix
//! C.1 rows), the key schedule and frame encryption against the RFC's Appendix C.3 vectors for AES_128_GCM_SHA256_128,
//! and decryption that refuses changed frames, other keys and non-minimal headers.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_sframe::{CipherSuite, Error, Header, Key, Sender, TAG_LEN, decrypt, derive};

fn hex(text: &str) -> Vec<u8> {
    let text: String = text.split_whitespace().collect();
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn headers_are_minimal_and_round_trip() {
    // Rows of RFC 9605 Appendix C.1.
    for (kid, ctr, header) in [
        (0x00u64, 0x00u64, "00"),
        (0x00, 0xff, "08ff"),
        (0x00, 0x0100, "090100"),
        (0x01, 0x00, "10"),
        (0xff, 0x00, "80ff"),
        (0x0100, 0x00, "900100"),
        (0x0100_0000_0000_0000, 0xffff_ffff_ffff_ffff, "ff0100000000000000ffffffffffffffff"),
        (0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, "ffffffffffffffffffffffffffffffffff"),
    ] {
        let encoded = Header { kid, ctr }.encode();
        assert_eq!(encoded, hex(header), "kid {kid:#x} ctr {ctr:#x}");
        assert_eq!(Header::decode(&encoded).unwrap(), (Header { kid, ctr }, encoded.len()));
    }
    // Short forms for values below 8, and the example in section 4.3.
    assert_eq!(Header { kid: 7, ctr: 7 }.encode(), vec![0x77]);
    assert_eq!(Header::decode(&hex("990123 4567")).unwrap(), (Header { kid: 0x0123, ctr: 0x4567 }, 5));
    // More bytes than needed, or the long form for a short value, is refused; so is a cut header.
    assert_eq!(Header::decode(&hex("900001")), Err(Error::NotMinimal));
    assert_eq!(Header::decode(&hex("8005")), Err(Error::NotMinimal));
    assert_eq!(Header::decode(&hex("0901")), Err(Error::Truncated));
    assert_eq!(Header::decode(&[]), Err(Error::Truncated));
}

#[test]
fn the_rfc_vector_for_aes_128_gcm() {
    // RFC 9605 Appendix C.3, cipher suite 0x0004.
    let base_key = hex("000102030405060708090a0b0c0d0e0f");
    let (kid, ctr) = (0x0123, 0x4567);
    let (key, salt) = derive(CipherSuite::Aes128GcmSha256, kid, &base_key).unwrap();
    assert_eq!(key, hex("d34f547f4ca4f9a7447006fe7fcbf768"));
    assert_eq!(salt.to_vec(), hex("75234edefe07819026751816"));
    let metadata = hex("4945544620534672616d65205747");
    let plaintext = hex("64726166742d696574662d736672616d652d656e63");
    let expected = hex("9901234567b7412c2513a1b66dbb48841bbaf17f598751176ad847681a69c6d0b091c07018ce4adb34eb");
    let key = Key::new(CipherSuite::Aes128GcmSha256, kid, &base_key).unwrap();
    let frame = key.encrypt(ctr, &metadata, &plaintext).unwrap();
    assert_eq!(frame, expected);
    assert_eq!(frame.len(), 5 + plaintext.len() + TAG_LEN);
    assert_eq!(key.decrypt(&metadata, &frame).unwrap(), plaintext);
}

#[test]
fn decryption_refuses_what_it_should() {
    let alice = Key::new(CipherSuite::Aes256GcmSha512, 3, b"alice's base key for this call").unwrap();
    let bob = Key::new(CipherSuite::Aes256GcmSha512, 9, b"bob's base key for this call").unwrap();
    let mut sender = Sender::new(Key::new(CipherSuite::Aes256GcmSha512, 3, b"alice's base key for this call").unwrap());
    let first = sender.encrypt(b"meta", b"frame one").unwrap();
    let second = sender.encrypt(b"meta", b"frame two").unwrap();
    assert_ne!(first[..first.len() - TAG_LEN], second[..second.len() - TAG_LEN], "a new counter for every frame");
    assert_eq!(Header::decode(&second).unwrap().0, Header { kid: 3, ctr: 1 });

    let keys = |kid| [&alice, &bob].into_iter().find(|key| key.kid() == kid);
    assert_eq!(decrypt(keys, b"meta", &first).unwrap(), b"frame one");
    assert_eq!(decrypt(keys, b"other metadata", &first), Err(Error::Authentication), "metadata is authenticated");
    let mut changed = first.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    assert_eq!(decrypt(keys, b"meta", &changed), Err(Error::Authentication));
    let mut wrong_counter = first.clone();
    wrong_counter[0] = 0x31; // the same key id with counter 1
    assert_eq!(decrypt(keys, b"meta", &wrong_counter), Err(Error::Authentication), "the header is authenticated");
    let stranger = Key::new(CipherSuite::Aes256GcmSha512, 5, b"someone else").unwrap().encrypt(0, b"meta", b"x").unwrap();
    assert_eq!(decrypt(keys, b"meta", &stranger), Err(Error::UnknownKey(5)));
    assert_eq!(bob.decrypt(b"meta", &first), Err(Error::UnknownKey(3)));
    assert_eq!(alice.decrypt(b"meta", &first[..5]), Err(Error::Truncated));
    assert_eq!(Key::new(CipherSuite::Aes128GcmSha256, 1, b"").unwrap_err(), Error::BadKey);
}
