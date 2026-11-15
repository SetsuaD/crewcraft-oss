use std::io::{Cursor, ErrorKind};

use crewcraft_proto::frame::{MAX_FRAME, encode, read_frame};

#[test]
fn reads_one_frame_and_preserves_the_next_frame() {
    let first = [0, 0, 0, 3, 7, 8, 9];
    let second = [0, 0, 0, 0];
    let mut wire = first.to_vec();
    wire.extend_from_slice(&second);
    let mut stream = Cursor::new(wire);

    let frame = read_frame(&mut stream, 3).unwrap().unwrap();
    assert_eq!(frame.as_bytes(), first);
    assert_eq!(frame.payload(), &[7, 8, 9]);
    assert_eq!(stream.position(), first.len() as u64);
    let empty = read_frame(&mut stream, 0).unwrap().unwrap();
    assert_eq!(empty.as_bytes(), second);
    assert!(empty.payload().is_empty());
    assert!(read_frame(&mut stream, 0).unwrap().is_none());
}

#[test]
fn detects_truncation_in_both_header_and_payload() {
    let wire = encode(&[1, 2, 3]).unwrap();
    for cut in 1..wire.len() {
        let result = read_frame(&mut &wire[..cut], 3);
        assert_eq!(result.unwrap_err().kind(), ErrorKind::UnexpectedEof);
    }
}

#[test]
fn rejects_a_large_length_before_reading_the_body() {
    for (declared, limit) in [(7, 6), (MAX_FRAME + 1, usize::MAX)] {
        let mut wire = (declared as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(&[1, 2, 3, 4]);
        let mut stream = Cursor::new(wire);
        assert_eq!(read_frame(&mut stream, limit).unwrap_err().kind(), ErrorKind::InvalidData);
        assert_eq!(stream.position(), 4);
    }
}

#[test]
fn debug_output_reports_only_the_payload_size() {
    let wire = encode(b"private").unwrap();
    let frame = read_frame(&mut wire.as_slice(), 7).unwrap().unwrap();
    assert_eq!(format!("{frame:?}"), "ReceivedFrame { payload_len: 7 }");
}
