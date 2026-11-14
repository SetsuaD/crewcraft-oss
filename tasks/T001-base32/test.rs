// T001: RFC 4648 base32. Test vectors are RFC 4648 section 10.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_totp::{Error, base32};

const VECTORS: &[(&[u8], &str)] = &[
    (b"", ""),
    (b"f", "MY======"),
    (b"fo", "MZXQ===="),
    (b"foo", "MZXW6==="),
    (b"foob", "MZXW6YQ="),
    (b"fooba", "MZXW6YTB"),
    (b"foobar", "MZXW6YTBOI======"),
];

#[test]
fn encode_matches_rfc4648() {
    for (raw, enc) in VECTORS {
        assert_eq!(base32::encode(raw), *enc, "encode {raw:?}");
    }
}

#[test]
fn encode_nopad_strips_padding() {
    assert_eq!(base32::encode_nopad(b"foobar"), "MZXW6YTBOI");
    assert_eq!(base32::encode_nopad(b"12345678901234567890"), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
}

#[test]
fn decode_round_trips_with_and_without_padding() {
    for (raw, enc) in VECTORS {
        assert_eq!(base32::decode(enc).unwrap(), raw.to_vec(), "decode {enc}");
        assert_eq!(base32::decode(enc.trim_end_matches('=')).unwrap(), raw.to_vec(), "decode unpadded {enc}");
    }
}

#[test]
fn decode_is_forgiving_about_case_spaces_and_hyphens() {
    assert_eq!(base32::decode("mzxw 6ytb-oi").unwrap(), b"foobar".to_vec());
}

#[test]
fn decode_rejects_garbage() {
    assert_eq!(base32::decode("MZXW1"), Err(Error::BadBase32)); // '1' is not in the alphabet
    assert_eq!(base32::decode("M"), Err(Error::BadBase32)); // no encoder produces 1 character
    assert_eq!(base32::decode("MZX"), Err(Error::BadBase32)); // nor 3
    assert_eq!(base32::decode("MZXW6Y"), Err(Error::BadBase32)); // nor 6
    assert_eq!(base32::decode("MY=====A"), Err(Error::BadBase32)); // data after padding
}
