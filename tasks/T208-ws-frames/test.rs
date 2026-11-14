#![allow(clippy::unwrap_used)]

use crewcraft_proto::ws_frame::{
    Frame, FrameDecoder, MAX_CONTROL_PAYLOAD, MAX_PAYLOAD, Opcode, Peer, WsError, encode_client_frame, encode_server_frame,
};

const MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

fn frame(fin: bool, opcode: Opcode, payload: &[u8]) -> Frame {
    Frame { fin, opcode, payload: payload.to_vec() }
}

fn decode_one(peer: Peer, bytes: &[u8]) -> Result<Option<Frame>, WsError> {
    let mut d = FrameDecoder::new(peer);
    d.push(bytes);
    d.next_frame()
}

#[test]
fn opcodes() {
    for (value, op) in [(0, Opcode::Continuation), (1, Opcode::Text), (2, Opcode::Binary), (8, Opcode::Close), (9, Opcode::Ping), (10, Opcode::Pong)]
    {
        assert_eq!(Opcode::from_u8(value), Some(op));
        assert_eq!(op.as_u8(), value);
    }
    for value in [3u8, 4, 5, 6, 7, 11, 12, 15, 16, 255] {
        assert_eq!(Opcode::from_u8(value), None);
    }
    assert!(Opcode::Close.is_control() && Opcode::Ping.is_control() && Opcode::Pong.is_control());
    assert!(!Opcode::Text.is_control() && !Opcode::Binary.is_control() && !Opcode::Continuation.is_control());
}

/// RFC 6455 section 5.7, the first example: an unmasked text frame containing "Hello".
#[test]
fn rfc_unmasked_text_hello() {
    let wire = [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
    let f = frame(true, Opcode::Text, b"Hello");
    assert_eq!(encode_server_frame(&f).unwrap(), wire);
    assert_eq!(decode_one(Peer::Server, &wire).unwrap(), Some(f));
}

/// RFC 6455 section 5.7: a masked text frame containing "Hello", with the example masking key.
#[test]
fn rfc_masked_text_hello() {
    let wire = [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
    let f = frame(true, Opcode::Text, b"Hello");
    assert_eq!(encode_client_frame(&f, MASK).unwrap(), wire);
    assert_eq!(decode_one(Peer::Client, &wire).unwrap(), Some(f));
}

/// RFC 6455 section 5.7: a text message fragmented into "Hel" and "lo", then an unmasked ping and a masked pong.
#[test]
fn rfc_fragments_ping_and_pong() {
    let mut d = FrameDecoder::new(Peer::Server);
    d.push(&[0x01, 0x03, 0x48, 0x65, 0x6c]);
    d.push(&[0x80, 0x02, 0x6c, 0x6f]);
    d.push(&[0x89, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f]);
    assert_eq!(d.next_frame().unwrap(), Some(frame(false, Opcode::Text, b"Hel")));
    assert_eq!(d.next_frame().unwrap(), Some(frame(true, Opcode::Continuation, b"lo")));
    assert_eq!(d.next_frame().unwrap(), Some(frame(true, Opcode::Ping, b"Hello")));
    assert_eq!(d.next_frame().unwrap(), None);

    let pong = [0x8a, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
    assert_eq!(decode_one(Peer::Client, &pong).unwrap(), Some(frame(true, Opcode::Pong, b"Hello")));
    assert_eq!(encode_server_frame(&frame(false, Opcode::Text, b"Hel")).unwrap(), vec![0x01, 0x03, 0x48, 0x65, 0x6c]);
    assert_eq!(encode_server_frame(&frame(true, Opcode::Continuation, b"lo")).unwrap(), vec![0x80, 0x02, 0x6c, 0x6f]);
}

/// RFC 6455 section 5.7: 256 bytes of binary use the 16-bit length; 65536 bytes use the 64-bit one.
#[test]
fn rfc_long_lengths() {
    let p256 = vec![0xAB; 256];
    let mut wire = vec![0x82, 0x7E, 0x01, 0x00];
    wire.extend_from_slice(&p256);
    assert_eq!(encode_server_frame(&frame(true, Opcode::Binary, &p256)).unwrap(), wire);
    assert_eq!(decode_one(Peer::Server, &wire).unwrap(), Some(frame(true, Opcode::Binary, &p256)));

    let p64k = vec![0xCD; 65_536];
    let mut wire = vec![0x82, 0x7F, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00];
    wire.extend_from_slice(&p64k);
    assert_eq!(encode_server_frame(&frame(true, Opcode::Binary, &p64k)).unwrap(), wire);
    assert_eq!(decode_one(Peer::Server, &wire).unwrap(), Some(frame(true, Opcode::Binary, &p64k)));
}

#[test]
fn length_form_boundaries() {
    let header = |n: usize| encode_server_frame(&frame(true, Opcode::Binary, &vec![0; n])).unwrap()[..4].to_vec();
    assert_eq!(header(125)[..2], [0x82, 125]);
    assert_eq!(header(126)[..4], [0x82, 126, 0x00, 126]);
    assert_eq!(header(65_535)[..4], [0x82, 126, 0xFF, 0xFF]);
    assert_eq!(encode_server_frame(&frame(true, Opcode::Binary, &vec![0; 65_536])).unwrap()[..2], [0x82, 127]);
}

#[test]
fn decoding_is_incremental() {
    let wire = encode_client_frame(&frame(true, Opcode::Text, b"hello world"), [9, 8, 7, 6]).unwrap();
    let mut d = FrameDecoder::new(Peer::Client);
    for (i, byte) in wire.iter().enumerate() {
        assert_eq!(d.next_frame().unwrap(), None, "before byte {i}");
        d.push(&[*byte]);
    }
    assert_eq!(d.next_frame().unwrap(), Some(frame(true, Opcode::Text, b"hello world")));
    assert_eq!(d.next_frame().unwrap(), None);
}

#[test]
fn several_frames_in_one_push() {
    let mut wire = Vec::new();
    for text in ["a", "bb", "ccc"] {
        wire.extend_from_slice(&encode_client_frame(&frame(true, Opcode::Text, text.as_bytes()), [1, 2, 3, 4]).unwrap());
    }
    let mut d = FrameDecoder::new(Peer::Client);
    d.push(&wire);
    for text in ["a", "bb", "ccc"] {
        assert_eq!(d.next_frame().unwrap(), Some(frame(true, Opcode::Text, text.as_bytes())));
    }
    assert_eq!(d.next_frame().unwrap(), None);
}

#[test]
fn client_frames_round_trip_with_any_mask() {
    for mask in [[0, 0, 0, 0], [0xFF, 0xFF, 0xFF, 0xFF], [1, 2, 3, 4], [0xDE, 0xAD, 0xBE, 0xEF]] {
        for len in [0usize, 1, 3, 4, 5, 125, 126, 1000] {
            let payload: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let f = frame(true, Opcode::Binary, &payload);
            let wire = encode_client_frame(&f, mask).unwrap();
            assert_eq!(decode_one(Peer::Client, &wire).unwrap(), Some(f), "mask {mask:?} len {len}");
        }
    }
}

#[test]
fn the_mask_bit_must_match_the_peer() {
    let unmasked = [0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f];
    let masked = [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58];
    assert_eq!(decode_one(Peer::Client, &unmasked).unwrap_err(), WsError::Unmasked);
    assert_eq!(decode_one(Peer::Server, &masked).unwrap_err(), WsError::Masked);
    // Refused on the two header bytes alone, without waiting for the payload.
    assert_eq!(decode_one(Peer::Client, &[0x81, 0x05]).unwrap_err(), WsError::Unmasked);
}

#[test]
fn reserved_bits_and_opcodes_are_refused_early() {
    for first in [0xC1u8, 0xA1, 0x91, 0xF1] {
        assert_eq!(decode_one(Peer::Server, &[first, 0x00]).unwrap_err(), WsError::ReservedBits, "{first:#x}");
    }
    for op in [3u8, 4, 5, 6, 7, 0x0B, 0x0C, 0x0F] {
        assert_eq!(decode_one(Peer::Server, &[0x80 | op, 0x00]).unwrap_err(), WsError::BadOpcode(op));
    }
}

#[test]
fn control_frame_rules() {
    // A ping (or close, or pong) must not be fragmented.
    for op in [0x08u8, 0x09, 0x0A] {
        assert_eq!(decode_one(Peer::Server, &[op, 0x00]).unwrap_err(), WsError::ControlFragmented);
    }
    // Nor carry more than 125 bytes: the 7-bit length alone gives it away (126 means "16-bit length follows").
    assert_eq!(decode_one(Peer::Server, &[0x89, 126, 0x00, 0x7E]).unwrap_err(), WsError::ControlTooLong);
    assert_eq!(decode_one(Peer::Server, &[0x88, 127, 0, 0, 0, 0, 0, 0, 0, 200]).unwrap_err(), WsError::ControlTooLong);
    // 125 bytes is fine.
    let mut ok = vec![0x89, 125];
    ok.extend_from_slice(&[7; 125]);
    assert_eq!(decode_one(Peer::Server, &ok).unwrap().unwrap().payload.len(), MAX_CONTROL_PAYLOAD);
}

#[test]
fn lengths_must_be_minimal_and_bounded() {
    assert_eq!(decode_one(Peer::Server, &[0x82, 126, 0x00, 0x05]).unwrap_err(), WsError::NonMinimalLength);
    assert_eq!(decode_one(Peer::Server, &[0x82, 126, 0x00, 0x7D]).unwrap_err(), WsError::NonMinimalLength);
    assert_eq!(decode_one(Peer::Server, &[0x82, 127, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]).unwrap_err(), WsError::NonMinimalLength);
    // 126 in the 16-bit form is the shortest possible, so it is fine (the payload is just not here yet).
    assert_eq!(decode_one(Peer::Server, &[0x82, 126, 0x00, 0x7E]).unwrap(), None);
    // Over the limit, refused from the header alone.
    let too_big = (MAX_PAYLOAD as u64) + 1;
    let mut header = vec![0x82, 127];
    header.extend_from_slice(&too_big.to_be_bytes());
    assert_eq!(decode_one(Peer::Server, &header).unwrap_err(), WsError::TooLarge(too_big));
    // A 64-bit length with the top bit set is invalid and also far too large.
    let mut header = vec![0x82, 127];
    header.extend_from_slice(&(1u64 << 63).to_be_bytes());
    assert!(matches!(decode_one(Peer::Server, &header).unwrap_err(), WsError::TooLarge(_)));
    // Exactly MAX_PAYLOAD is allowed: the header is accepted and the decoder waits for the payload.
    let mut header = vec![0x82, 127];
    header.extend_from_slice(&(MAX_PAYLOAD as u64).to_be_bytes());
    assert_eq!(decode_one(Peer::Server, &header).unwrap(), None);
}

#[test]
fn encoders_refuse_what_a_peer_would_refuse() {
    let big = vec![0u8; MAX_PAYLOAD + 1];
    assert_eq!(encode_server_frame(&frame(true, Opcode::Binary, &big)).unwrap_err(), WsError::TooLarge(big.len() as u64));
    assert_eq!(encode_client_frame(&frame(true, Opcode::Binary, &big), MASK).unwrap_err(), WsError::TooLarge(big.len() as u64));
    let at_limit = vec![0u8; MAX_PAYLOAD];
    let wire = encode_server_frame(&frame(true, Opcode::Binary, &at_limit)).unwrap();
    assert_eq!(wire[..10], [0x82, 127, 0, 0, 0, 0, 0, 0x10, 0, 0]);

    let long = vec![0u8; MAX_CONTROL_PAYLOAD + 1];
    for op in [Opcode::Close, Opcode::Ping, Opcode::Pong] {
        assert_eq!(encode_server_frame(&frame(true, op, &long)).unwrap_err(), WsError::ControlTooLong);
        assert_eq!(encode_server_frame(&frame(false, op, b"")).unwrap_err(), WsError::ControlFragmented);
        assert_eq!(encode_client_frame(&frame(true, op, &long), MASK).unwrap_err(), WsError::ControlTooLong);
        assert_eq!(encode_client_frame(&frame(false, op, b""), MASK).unwrap_err(), WsError::ControlFragmented);
    }
}
