// The Ed25519 SignatureCheck over pinned release keys (REQUIREMENTS 2.21, M5): RFC 8032 vectors, rotation, refusals,
// and open_release end to end. Test keys only; no real release key appears anywhere.
#![allow(clippy::unwrap_used)]
use crewcraft_update::ed25519::{KeyError, MAX_RELEASE_KEYS, ReleaseKeys};
use crewcraft_update::{ReleaseError, SignatureCheck, open_release};
use ed25519_dalek::{Signer, SigningKey};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

// RFC 8032 section 7.1, TEST 1 (empty message) and TEST 2 (one byte, 0x72).
const T1_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const T1_SIG: &str =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
const T2_PUBLIC: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
const T2_SIG: &str =
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00";

fn test_key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn keys(signers: &[&SigningKey]) -> ReleaseKeys {
    let raw: Vec<[u8; 32]> = signers.iter().map(|k| k.verifying_key().to_bytes()).collect();
    ReleaseKeys::new(&raw).unwrap()
}

#[test]
fn rfc8032_vectors_verify() {
    let k1 = ReleaseKeys::from_hex(&[T1_PUBLIC]).unwrap();
    assert!(k1.verify(b"", &unhex(T1_SIG)));
    assert!(!k1.verify(b"x", &unhex(T1_SIG)));
    let k2 = ReleaseKeys::from_hex(&[T2_PUBLIC.to_uppercase().as_str()]).unwrap();
    assert!(k2.verify(&[0x72], &unhex(T2_SIG)));
    assert!(!k2.verify(&[0x73], &unhex(T2_SIG)));
    // The other vector's key does not accept it.
    assert!(!k1.verify(&[0x72], &unhex(T2_SIG)));
}

#[test]
fn any_pinned_key_is_accepted_so_keys_can_rotate() {
    let (old, new, stranger) = (test_key(1), test_key(2), test_key(3));
    let pinned = keys(&[&old, &new]);
    assert_eq!(pinned.len(), 2);
    let msg = b"manifest bytes";
    assert!(pinned.verify(msg, &old.sign(msg).to_bytes()));
    assert!(pinned.verify(msg, &new.sign(msg).to_bytes()));
    assert!(!pinned.verify(msg, &stranger.sign(msg).to_bytes()));
}

#[test]
fn malformed_signatures_are_refused() {
    let key = test_key(4);
    let pinned = keys(&[&key]);
    let msg = b"manifest bytes";
    let sig = key.sign(msg).to_bytes();
    assert!(!pinned.verify(msg, &sig[..63]));
    let mut long = sig.to_vec();
    long.push(0);
    assert!(!pinned.verify(msg, &long));
    assert!(!pinned.verify(msg, b""));
    let mut flipped = sig;
    flipped[10] ^= 1;
    assert!(!pinned.verify(msg, &flipped));
    // A non-canonical S (S + L) is refused by verify_strict.
    let l: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x10,
    ];
    let mut non_canonical = sig;
    let mut carry = 0u16;
    for i in 0..32 {
        let s = u16::from(non_canonical[32 + i]) + u16::from(l[i]) + carry;
        non_canonical[32 + i] = (s & 0xff) as u8;
        carry = s >> 8;
    }
    assert!(!pinned.verify(msg, &non_canonical));
}

#[test]
fn key_lists_are_checked() {
    assert_eq!(ReleaseKeys::new(&[]).unwrap_err(), KeyError::NoKeys);
    let many: Vec<[u8; 32]> = (1..=(MAX_RELEASE_KEYS as u8 + 1)).map(|n| test_key(n).verifying_key().to_bytes()).collect();
    assert_eq!(ReleaseKeys::new(&many).unwrap_err(), KeyError::TooMany);
    let a = test_key(5).verifying_key().to_bytes();
    assert_eq!(ReleaseKeys::new(&[a, a]).unwrap_err(), KeyError::Duplicate(1));
    // The identity point (small order) is a weak key.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert_eq!(ReleaseKeys::new(&[a, identity]).unwrap_err(), KeyError::Weak(1));
    // Not hex, wrong length.
    assert_eq!(ReleaseKeys::from_hex(&["zz"]).unwrap_err(), KeyError::NotAKey(0));
    assert_eq!(ReleaseKeys::from_hex(&[T1_PUBLIC, &T1_PUBLIC[..62]]).unwrap_err(), KeyError::NotAKey(1));
    assert_eq!(ReleaseKeys::from_hex(&[&"g".repeat(64)]).unwrap_err(), KeyError::NotAKey(0));
}

#[test]
fn open_release_end_to_end() {
    let key = test_key(6);
    let pinned = keys(&[&key]);
    let manifest = "[release]\nproduct = \"crewcraft\"\nversion = \"1.4.0\"\nchannel = \"stable\"\npublished = \"2026-11-14\"\nmin-client = \"1.0.0\"\n\n\
                    [artifact.server-linux]\nkind = \"server\"\nplatform = \"linux-x64\"\nfile = \"s.tar.zst\"\nsize = 3\n\
                    sha256 = \"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\"\n";
    let sig = key.sign(manifest.as_bytes()).to_bytes();
    assert_eq!(open_release(manifest.as_bytes(), &sig, &pinned).unwrap().version.to_string(), "1.4.0");
    // One changed byte in the manifest and the signature no longer covers it.
    let tampered = manifest.replace("1.4.0", "1.5.0");
    assert_eq!(open_release(tampered.as_bytes(), &sig, &pinned).unwrap_err(), ReleaseError::BadSignature);
    // Signed by a key that is not pinned.
    let other = test_key(7).sign(manifest.as_bytes()).to_bytes();
    assert_eq!(open_release(manifest.as_bytes(), &other, &pinned).unwrap_err(), ReleaseError::BadSignature);
}
