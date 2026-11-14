//! Integration tests for the T140 journal module.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use crewcraft_server_core::journal::{Journal, JournalError, MAX_RECORD};

fn path(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("t140_journal_{}_{}", name, std::process::id()));
    p
}

fn cleanup(p: &PathBuf) {
    let _ = fs::remove_file(p);
}

#[test]
fn open_nonexistent_file_creates_empty_journal() {
    let p = path("empty");
    let (j, records) = Journal::open(&p).unwrap();
    assert!(records.is_empty());
    assert_eq!(j.len(), 0);
    assert!(j.is_empty());
    assert_eq!(j.size(), 0);
    assert!(p.exists(), "file should have been created");
    cleanup(&p);
}

#[test]
fn append_single_record_updates_size_and_len() {
    let p = path("single");
    let (mut j, _) = Journal::open(&p).unwrap();
    let data: &[u8] = b"hello"; // 5 bytes
    j.append(data).unwrap();
    assert_eq!(j.len(), 1);
    assert!(!j.is_empty());
    // size = 4 (len field) + 5 (data) + 32 (hash) = 41
    assert_eq!(j.size(), 41);
    cleanup(&p);
}

#[test]
fn append_empty_record_is_allowed() {
    let p = path("empty_rec");
    let (mut j, _) = Journal::open(&p).unwrap();
    j.append(b"").unwrap();
    assert_eq!(j.len(), 1);
    assert!(!j.is_empty());
    // size = 4 + 0 + 32 = 36
    assert_eq!(j.size(), 36);
    cleanup(&p);
}

#[test]
fn append_too_large_is_rejected_and_writes_nothing() {
    let p = path("too_large");
    let (mut j, _) = Journal::open(&p).unwrap();
    let big = vec![0u8; MAX_RECORD + 1];
    let err = j.append(&big).unwrap_err();
    assert_eq!(err, JournalError::TooLarge);
    assert_eq!(j.len(), 0);
    assert!(j.is_empty());
    assert_eq!(j.size(), 0);
    cleanup(&p);
}

#[test]
fn append_exactly_max_record_succeeds() {
    let p = path("max_ok");
    let (mut j, _) = Journal::open(&p).unwrap();
    let exact = vec![0u8; MAX_RECORD];
    j.append(&exact).unwrap();
    assert_eq!(j.len(), 1);
    assert_eq!(j.size(), 4 + MAX_RECORD as u64 + 32);
    cleanup(&p);
}

#[test]
fn multiple_appends_preserve_order_on_reopen() {
    let p = path("order");
    {
        let (mut j, _) = Journal::open(&p).unwrap();
        j.append(b"A").unwrap();
        j.append(b"BB").unwrap();
        j.append(b"CCC").unwrap();
        assert_eq!(j.len(), 3);
        // size = (4+1+32) + (4+2+32) + (4+3+32) = 37 + 38 + 39 = 114
        assert_eq!(j.size(), 114);
    }
    let (j2, records) = Journal::open(&p).unwrap();
    assert_eq!(records, vec![b"A".to_vec(), b"BB".to_vec(), b"CCC".to_vec()]);
    assert_eq!(j2.len(), 3);
    assert_eq!(j2.size(), 114);
    cleanup(&p);
}

#[test]
fn reopen_truncates_record_with_bad_hash() {
    let p = path("bad_hash");
    {
        let (mut j, _) = Journal::open(&p).unwrap();
        j.append(b"good").unwrap(); // 4 bytes, frame = 4+4+32 = 40
        j.append(b"bad").unwrap(); // 3 bytes, frame = 4+3+32 = 39, starts at offset 40
    }
    // File layout:
    //   offset  0: 4-byte len (4)
    //   offset  4: "good" (4 bytes)
    //   offset  8: 32-byte SHA-256 of "good"
    //   offset 40: 4-byte len (3)
    //   offset 44: "bad" (3 bytes)
    //   offset 47: 32-byte SHA-256 of "bad"   <-- corrupt this
    let mut bytes = fs::read(&p).unwrap();
    bytes[47] ^= 0xFF;
    fs::write(&p, &bytes).unwrap();

    let (j2, records) = Journal::open(&p).unwrap();
    assert_eq!(records, vec![b"good".to_vec()]);
    assert_eq!(j2.len(), 1);
    // Truncated to end of first valid record: 4+4+32 = 40
    assert_eq!(j2.size(), 40);
    cleanup(&p);
}

#[test]
fn reopen_truncates_incomplete_record() {
    let p = path("incomplete");
    {
        let (mut j, _) = Journal::open(&p).unwrap();
        j.append(b"complete").unwrap(); // 8 bytes, frame = 4+8+32 = 44
    }
    // Append 2 stray bytes: not enough for the 4-byte length field of a new record.
    let mut bytes = fs::read(&p).unwrap();
    bytes.extend_from_slice(&[0x00, 0x01]);
    fs::write(&p, &bytes).unwrap();

    let (j2, records) = Journal::open(&p).unwrap();
    assert_eq!(records, vec![b"complete".to_vec()]);
    assert_eq!(j2.len(), 1);
    // Truncated to end of first valid record: 44
    assert_eq!(j2.size(), 44);
    cleanup(&p);
}

#[test]
fn reopen_truncates_record_longer_than_max_on_disk() {
    let p = path("disk_too_large");
    {
        let (mut j, _) = Journal::open(&p).unwrap();
        j.append(b"valid").unwrap(); // 5 bytes, frame = 4+5+32 = 41
    }
    // Append a 4-byte big-endian length of MAX_RECORD + 1 (no data or hash follows).
    let mut bytes = fs::read(&p).unwrap();
    let too_large_len: u32 = (MAX_RECORD as u32) + 1;
    bytes.extend_from_slice(&too_large_len.to_be_bytes());
    fs::write(&p, &bytes).unwrap();

    let (j2, records) = Journal::open(&p).unwrap();
    assert_eq!(records, vec![b"valid".to_vec()]);
    assert_eq!(j2.len(), 1);
    // Truncated to end of first valid record: 41
    assert_eq!(j2.size(), 41);
    cleanup(&p);
}

#[test]
fn size_accumulates_over_multiple_records() {
    let p = path("size_acc");
    let (mut j, _) = Journal::open(&p).unwrap();
    j.append(b"").unwrap(); // 0 bytes   -> 4 + 0   + 32 = 36
    j.append(b"x").unwrap(); // 1 byte    -> 4 + 1   + 32 = 37
    j.append(&[0u8; 100]).unwrap(); // 100 bytes -> 4 + 100 + 32 = 136
    assert_eq!(j.len(), 3);
    assert_eq!(j.size(), 36 + 37 + 136); // = 209
    cleanup(&p);
}

#[test]
fn len_includes_records_read_at_open_plus_appended_since() {
    let p = path("len_mix");
    {
        let (mut j, _) = Journal::open(&p).unwrap();
        j.append(b"one").unwrap();
        j.append(b"two").unwrap();
    }
    let (mut j2, records) = Journal::open(&p).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(j2.len(), 2);
    assert!(!j2.is_empty());
    j2.append(b"three").unwrap();
    assert_eq!(j2.len(), 3);
    cleanup(&p);
}

/// Added in review: recovery truncates the file itself, so a record appended afterwards follows the last valid one and
/// survives the next open.
#[test]
fn appends_after_recovery_follow_the_last_valid_record() {
    let p = path("after_recovery");
    {
        let (mut j, _) = Journal::open(&p).unwrap();
        j.append(b"good").unwrap(); // frame 40 bytes
        j.append(b"torn").unwrap(); // frame 40 bytes, at offset 40
    }
    // Tear the second record: keep its length, its data and half its hash.
    let bytes = fs::read(&p).unwrap();
    fs::write(&p, &bytes[..40 + 4 + 4 + 16]).unwrap();

    {
        let (mut j, records) = Journal::open(&p).unwrap();
        assert_eq!(records, vec![b"good".to_vec()]);
        assert_eq!(fs::metadata(&p).unwrap().len(), 40);
        j.append(b"next").unwrap();
    }

    let (j, records) = Journal::open(&p).unwrap();
    assert_eq!(records, vec![b"good".to_vec(), b"next".to_vec()]);
    assert_eq!(j.size(), 80);
    cleanup(&p);
}
