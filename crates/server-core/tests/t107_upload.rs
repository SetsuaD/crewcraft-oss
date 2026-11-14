// T107: chunked upload reassembly (out of order, idempotent repeats, size and conflict checks).
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_server_core::upload::{Assembler, UploadError};

#[test]
fn in_order() {
    let mut a = Assembler::new(10, 4, 100).unwrap();
    assert_eq!(a.chunks(), 3);
    assert_eq!(a.put(0, b"abcd"), Ok(1));
    assert_eq!(a.put(1, b"efgh"), Ok(2));
    assert_eq!(a.put(2, b"ij"), Ok(3));
    assert_eq!(a.finish(), Ok(b"abcdefghij".to_vec()));
}

#[test]
fn out_of_order_and_repeated() {
    let mut a = Assembler::new(10, 4, 100).unwrap();
    assert_eq!(a.put(2, b"ij"), Ok(1));
    assert_eq!(a.put(0, b"abcd"), Ok(2));
    assert_eq!(a.put(0, b"abcd"), Ok(2));
    assert_eq!(a.put(0, b"abcX"), Err(UploadError::Conflict));
    assert_eq!(a.put(1, b"efgh"), Ok(3));
    assert_eq!(a.finish(), Ok(b"abcdefghij".to_vec()));
}

#[test]
fn sizes_and_ranges_are_checked() {
    let mut a = Assembler::new(10, 4, 100).unwrap();
    assert_eq!(a.put(0, b"abc"), Err(UploadError::BadSize));
    assert_eq!(a.put(2, b"ijk"), Err(UploadError::BadSize));
    assert_eq!(a.put(3, b"zz"), Err(UploadError::OutOfRange));
    assert_eq!(a.put(3, b"abcd"), Err(UploadError::OutOfRange));
}

#[test]
fn an_exact_multiple_has_no_short_chunk() {
    let mut a = Assembler::new(8, 4, 100).unwrap();
    assert_eq!(a.chunks(), 2);
    assert_eq!(a.put(1, b"efgh"), Ok(1));
    assert_eq!(a.put(1, b""), Err(UploadError::BadSize));
    assert_eq!(a.put(0, b"abcd"), Ok(2));
    assert_eq!(a.finish(), Ok(b"abcdefgh".to_vec()));
}

#[test]
fn incomplete_names_the_first_missing_chunk() {
    let mut a = Assembler::new(12, 4, 100).unwrap();
    a.put(0, b"aaaa").unwrap();
    a.put(2, b"cccc").unwrap();
    assert_eq!(a.finish(), Err(UploadError::Incomplete(1)));
}

#[test]
fn parameters() {
    assert!(matches!(Assembler::new(10, 0, 100), Err(UploadError::BadParameters)));
    assert!(matches!(Assembler::new(101, 4, 100), Err(UploadError::BadParameters)));
    assert!(Assembler::new(100, 4, 100).is_ok());
    let a = Assembler::new(0, 4, 100).unwrap();
    assert_eq!(a.chunks(), 0);
    assert_eq!(a.finish(), Ok(vec![]));
}
