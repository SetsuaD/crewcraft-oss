//! A client-chosen chunk size must not make the assembler reserve memory per chunk without bound.
use crewcraft_server_core::upload::{Assembler, MAX_CHUNKS, UploadError};

#[test]
fn too_many_chunks_is_refused_before_allocating() {
    let max = 100 * 1024 * 1024;
    assert!(matches!(Assembler::new(max, 1, max), Err(UploadError::BadParameters)));
    assert!(matches!(Assembler::new(MAX_CHUNKS + 1, 1, max), Err(UploadError::BadParameters)));
}

#[test]
fn up_to_the_cap_is_accepted() {
    let a = Assembler::new(MAX_CHUNKS * 4, 4, u64::MAX).expect("exactly MAX_CHUNKS chunks");
    assert_eq!(a.chunks(), MAX_CHUNKS);
}
