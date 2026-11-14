// T100: length-prefixed frame codec (4-byte big-endian length + payload, 1 MiB limit).
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_proto::frame::{Decoder, FrameError, MAX_FRAME, encode};

#[test]
fn encode_prefixes_a_big_endian_length() {
    assert_eq!(encode(b"hi").unwrap(), vec![0, 0, 0, 2, b'h', b'i']);
    assert_eq!(encode(b"").unwrap(), vec![0, 0, 0, 0]);
    let f = encode(&[7u8; 300]).unwrap();
    assert_eq!(&f[..4], &[0, 0, 1, 44]);
    assert_eq!(f.len(), 304);
}

#[test]
fn encode_refuses_an_oversize_payload() {
    assert_eq!(encode(&vec![0u8; MAX_FRAME]).map(|f| f.len()), Ok(MAX_FRAME + 4));
    assert_eq!(encode(&vec![0u8; MAX_FRAME + 1]), Err(FrameError::TooLarge(MAX_FRAME + 1)));
}

#[test]
fn decodes_byte_by_byte() {
    let wire = encode(b"hello").unwrap();
    let mut d = Decoder::new();
    for (i, b) in wire.iter().enumerate() {
        assert_eq!(d.next_frame(), Ok(None), "a frame before byte {i}");
        d.push(&[*b]);
    }
    assert_eq!(d.next_frame(), Ok(Some(b"hello".to_vec())));
    assert_eq!(d.next_frame(), Ok(None));
    assert_eq!(d.buffered(), 0);
}

#[test]
fn several_frames_in_one_push_and_a_partial_tail() {
    let mut wire = encode(b"a").unwrap();
    wire.extend(encode(b"").unwrap());
    wire.extend(encode(b"xyz").unwrap());
    wire.extend([0, 0, 0, 5, b'p']); // a fourth frame, only partly arrived
    let mut d = Decoder::new();
    d.push(&wire);
    assert_eq!(d.next_frame(), Ok(Some(b"a".to_vec())));
    assert_eq!(d.next_frame(), Ok(Some(vec![])));
    assert_eq!(d.next_frame(), Ok(Some(b"xyz".to_vec())));
    assert_eq!(d.next_frame(), Ok(None));
    assert_eq!(d.buffered(), 5);
    d.push(b"arty");
    assert_eq!(d.next_frame(), Ok(Some(b"party".to_vec())));
    assert_eq!(d.buffered(), 0);
}

#[test]
fn an_oversize_header_is_refused_before_its_body() {
    let mut d = Decoder::new();
    d.push(&[0x00, 0x10, 0x00, 0x01]); // 1_048_577 = MAX_FRAME + 1; no body is ever sent
    assert_eq!(d.next_frame(), Err(FrameError::TooLarge(MAX_FRAME + 1)));
}

#[test]
fn a_max_size_header_waits_for_its_body() {
    let mut d = Decoder::new();
    d.push(&[0x00, 0x10, 0x00, 0x00]);
    assert_eq!(d.next_frame(), Ok(None));
}
