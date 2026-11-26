//! T330a: the content-addressed file store and the file records (docs/FILES.md): chunks written in any order, the
//! declared size and hash checked before the bytes are kept, one copy per content, uploads in progress removed at
//! start-up, unreferenced bytes swept, image sizes read from headers, and the journal's file records checked, kept
//! and replayed.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crewcraft_server_core::durable::{DurableServer, FileError, MAX_FILE_NAME, StoredFile, valid_file_name};
use crewcraft_server_core::file_store::{FileStore, FinishError, hex, image_size};
use crewcraft_server_core::op::{Op, decode_op, encode_op};
use crewcraft_server_core::room::Role;
use sha2::{Digest, Sha256};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("t330a-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Every finished file in the store (not counting uploads in progress).
fn finished(root: &Path) -> usize {
    fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|fan| fan.file_name() != "partial" && fan.path().is_dir())
        .map(|fan| fs::read_dir(fan.path()).unwrap().count())
        .sum()
}

#[test]
fn chunks_in_any_order_become_one_copy_per_content() {
    let root = scratch("store");
    let store = FileStore::open(&root).unwrap();
    let bytes: Vec<u8> = (0..300_000u32).map(|n| (n % 251) as u8).collect();
    let upload = [1; 16];
    store.start(&upload).unwrap();
    assert_eq!(store.start(&upload).unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
    // The second half first, then the first.
    store.write(&upload, 150_000, &bytes[150_000..]).unwrap();
    store.write(&upload, 0, &bytes[..150_000]).unwrap();
    let hash = sha(&bytes);
    assert!(!store.contains(&hash), "nothing is a finished file before finish");
    store.finish(&upload, bytes.len() as u64, &hash).unwrap();
    assert!(store.contains(&hash));
    assert_eq!(store.read(&hash, 0, bytes.len()).unwrap(), bytes);
    assert_eq!(store.read(&hash, 299_990, 100).unwrap(), &bytes[299_990..]);
    assert!(store.read(&hash, 400_000, 10).unwrap().is_empty());
    let name = hex(&hash);
    assert!(root.join(&name[..2]).join(&name).is_file(), "stored under its hash with a two-character fan-out");

    // The same bytes again are kept once.
    let again = [2; 16];
    store.start(&again).unwrap();
    store.write(&again, 0, &bytes).unwrap();
    store.finish(&again, bytes.len() as u64, &hash).unwrap();
    assert_eq!(finished(&root), 1);
    assert!(fs::read_dir(root.join("partial")).unwrap().next().is_none(), "no partial file is left");
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_wrong_size_or_hash_keeps_nothing() {
    let root = scratch("refuse");
    let store = FileStore::open(&root).unwrap();
    let bytes = b"the declared bytes".to_vec();
    let upload = [3; 16];
    store.start(&upload).unwrap();
    store.write(&upload, 0, &bytes[..5]).unwrap();
    assert!(matches!(store.finish(&upload, bytes.len() as u64, &sha(&bytes)), Err(FinishError::WrongSize { declared: 18, written: 5 })));
    let upload = [4; 16];
    store.start(&upload).unwrap();
    store.write(&upload, 0, &bytes).unwrap();
    assert!(matches!(store.finish(&upload, bytes.len() as u64, &sha(b"other bytes")), Err(FinishError::WrongHash)));
    assert_eq!(finished(&root), 0);
    assert!(fs::read_dir(root.join("partial")).unwrap().next().is_none());
    // Discarding an upload removes its partial file; discarding one that is not there is harmless.
    store.start(&[5; 16]).unwrap();
    store.discard(&[5; 16]);
    store.discard(&[6; 16]);
    assert!(fs::read_dir(root.join("partial")).unwrap().next().is_none());
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_restart_drops_uploads_in_progress_and_the_sweep_keeps_what_records_name() {
    let root = scratch("sweep");
    let store = FileStore::open(&root).unwrap();
    for (n, text) in [(7u8, b"kept bytes".as_slice()), (8, b"orphan bytes".as_slice())] {
        store.start(&[n; 16]).unwrap();
        store.write(&[n; 16], 0, text).unwrap();
        store.finish(&[n; 16], text.len() as u64, &sha(text)).unwrap();
    }
    store.start(&[9; 16]).unwrap();
    store.write(&[9; 16], 0, b"half").unwrap();
    // A stray file in the root, not a content name, is left alone.
    fs::write(root.join("README"), b"not a content file").unwrap();
    drop(store);

    let store = FileStore::open(&root).unwrap();
    assert!(fs::read_dir(root.join("partial")).unwrap().next().is_none(), "the unfinished upload is gone");
    let keep: HashSet<[u8; 32]> = [sha(b"kept bytes")].into_iter().collect();
    assert_eq!(store.sweep(&keep).unwrap(), 1);
    assert!(store.contains(&sha(b"kept bytes")) && !store.contains(&sha(b"orphan bytes")));
    assert!(root.join("README").is_file());
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn image_sizes_come_from_the_header() {
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    png.extend_from_slice(&640u32.to_be_bytes());
    png.extend_from_slice(&480u32.to_be_bytes());
    assert_eq!(image_size(&png), Some((640, 480)));

    let mut gif = b"GIF89a".to_vec();
    gif.extend_from_slice(&320u16.to_le_bytes());
    gif.extend_from_slice(&200u16.to_le_bytes());
    assert_eq!(image_size(&gif), Some((320, 200)));

    // SOI, an APP0 segment to skip, then SOF0 with height 600 and width 800.
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00, 0xFF, 0xC0, 0x00, 0x11, 0x08];
    jpeg.extend_from_slice(&600u16.to_be_bytes());
    jpeg.extend_from_slice(&800u16.to_be_bytes());
    assert_eq!(image_size(&jpeg), Some((800, 600)));
    // A DHT marker (C4) is not a frame: the size is read from the SOF2 after it.
    let mut progressive = vec![0xFF, 0xD8, 0xFF, 0xC4, 0x00, 0x02, 0xFF, 0xC2, 0x00, 0x11, 0x08];
    progressive.extend_from_slice(&10u16.to_be_bytes());
    progressive.extend_from_slice(&20u16.to_be_bytes());
    assert_eq!(image_size(&progressive), Some((20, 10)));

    let mut vp8x = b"RIFF\0\0\0\0WEBPVP8X\x0a\0\0\0\0\0\0\0".to_vec();
    vp8x.extend_from_slice(&[0x3F, 0x01, 0x00]); // 319 + 1
    vp8x.extend_from_slice(&[0xEF, 0x00, 0x00]); // 239 + 1
    assert_eq!(image_size(&vp8x), Some((320, 240)));
    let mut vp8l = b"RIFF\0\0\0\0WEBPVP8L\0\0\0\0\x2f".to_vec();
    let bits: u32 = 99 | (49 << 14); // 100 x 50
    vp8l.extend_from_slice(&bits.to_le_bytes());
    assert_eq!(image_size(&vp8l), Some((100, 50)));
    let mut vp8 = b"RIFF\0\0\0\0WEBPVP8 \0\0\0\0\0\0\0\x9d\x01\x2a".to_vec();
    vp8.extend_from_slice(&64u16.to_le_bytes());
    vp8.extend_from_slice(&48u16.to_le_bytes());
    assert_eq!(image_size(&vp8), Some((64, 48)));

    for not_an_image in [b"%PDF-1.7".as_slice(), b"plain text", b"", &png[..14], &[0xFF, 0xD8, 0x00]] {
        assert_eq!(image_size(not_an_image), None);
    }
    let mut zero = png.clone();
    zero[16..20].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(image_size(&zero), None, "a zero dimension is not an image size");
}

#[test]
fn file_records_are_checked_kept_and_replayed() {
    let path = scratch("journal");
    let _ = fs::remove_file(&path);
    let mut ds = DurableServer::open(&path).unwrap();
    let room = ds.create_room("alice", "Project").unwrap();
    ds.add_member(&room, "alice", "bob", Role::Member).unwrap();
    let hash = sha(b"report");
    ds.record_file(&room, "bob", [1; 16], hash, 6, "report.pdf", None).unwrap();
    ds.record_file(&room, "alice", [2; 16], sha(b"picture"), 7, "photo.png", Some((640, 480))).unwrap();

    assert_eq!(ds.record_file(&room, "carol", [3; 16], hash, 6, "x.pdf", None), Err(FileError::NotMember));
    assert_eq!(ds.record_file("no-such-room", "bob", [3; 16], hash, 6, "x.pdf", None), Err(FileError::NotMember));
    assert_eq!(ds.record_file(&room, "bob", [1; 16], hash, 6, "again.pdf", None), Err(FileError::DuplicateId));
    assert_eq!(ds.record_file(&room, "bob", [3; 16], hash, 0, "empty.txt", None), Err(FileError::Empty));
    for bad in ["", ".", "..", "a/b", "a\\b", "line\nbreak", &"n".repeat(MAX_FILE_NAME + 1)] {
        assert!(!valid_file_name(bad), "{bad:?}");
        assert_eq!(ds.record_file(&room, "bob", [3; 16], hash, 6, bad, None), Err(FileError::BadName), "{bad:?}");
    }
    assert!(valid_file_name("Q3 plan (final).pdf") && valid_file_name(&"n".repeat(MAX_FILE_NAME)));

    let report = StoredFile { room: room.clone(), uploader: "bob".into(), sha256: hash, size: 6, name: "report.pdf".into(), image: None };
    assert_eq!(ds.file(&[1; 16]), Some(&report));
    assert_eq!(ds.file(&[3; 16]), None);
    drop(ds);

    let ds = DurableServer::open(&path).unwrap();
    assert_eq!(ds.file(&[1; 16]), Some(&report));
    assert_eq!(ds.file(&[2; 16]).unwrap().image, Some((640, 480)));
    assert_eq!(ds.referenced_hashes(), [hash, sha(b"picture")].into_iter().collect());
    fs::remove_file(&path).unwrap();

    // The record's encoding round-trips, and refuses truncation and a bad image flag.
    let op = Op::FileStored { slug: room, uploader: "bob".into(), file: [1; 16], sha256: hash, size: 6, name: "r.pdf".into(), image: Some((1, 2)) };
    let bytes = encode_op(&op).unwrap();
    assert_eq!((bytes[0], decode_op(&bytes).unwrap()), (16, op));
    for cut in 1..bytes.len() {
        assert!(decode_op(&bytes[..cut]).is_err(), "cut at {cut}");
    }
    let mut flagged = bytes.clone();
    let flag_at = bytes.len() - 9;
    flagged[flag_at] = 2;
    assert!(decode_op(&flagged).is_err());
}
