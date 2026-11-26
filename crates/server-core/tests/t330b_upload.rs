//! T330b: uploads over the device connection (docs/FILES.md): the three requests and the id frame on the wire; the
//! durable server's checks before any byte (storage, membership, name, size, how many in progress), chunks in any
//! order, the content and membership checked again at the finish, idle uploads discarded; and the connection's
//! answers, with the in-memory server refusing for want of storage.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use crewcraft_proto::frame::encode;
use crewcraft_proto::message::CodecError;
use crewcraft_proto::request::{
    ID_TAG, MAX_CHUNK, MAX_FILE_NAME, Request, Response, decode_id, decode_request, encode_id, encode_request, encode_response,
};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::dispatch::{E_BAD_FILE, E_NO_STORAGE, E_NO_SUCH_ROOM, E_NO_SUCH_UPLOAD, E_RATE_LIMITED};
use crewcraft_server_core::durable::{DurableServer, MAX_FILE_SIZE, MAX_UPLOADS_PER_PERSON, UPLOAD_IDLE_MS, UploadError};
use crewcraft_server_core::file_store::FileStore;
use crewcraft_server_core::room::Role;
use crewcraft_server_core::server::Server;
use sha2::{Digest, Sha256};

const T0: u64 = 1_800_000_000_000;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("t330b-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// A durable server with files, a room of alice and bob, and a room of carol.
fn server(dir: &PathBuf) -> (DurableServer, String, String) {
    let mut ds = DurableServer::open(&dir.join("rooms.journal")).unwrap().with_files(FileStore::open(&dir.join("files")).unwrap()).unwrap();
    let room = ds.create_room("alice", "Project").unwrap();
    ds.add_member(&room, "alice", "bob", Role::Member).unwrap();
    let other = ds.create_room("carol", "Elsewhere").unwrap();
    (ds, room, other)
}

#[test]
fn the_requests_and_the_id_frame_have_exact_bytes() {
    let begin = Request::UploadBegin { room: "r".into(), name: "a.png".into(), size: 3, sha256: [7; 32] };
    let bytes = encode_request(1, &begin).unwrap();
    let mut expected = vec![10, 0, 0, 0, 1, 0, 1, b'r', 0, 5];
    expected.extend_from_slice(b"a.png");
    expected.extend_from_slice(&3u64.to_be_bytes());
    expected.extend_from_slice(&[7; 32]);
    assert_eq!(bytes, expected);
    assert_eq!(decode_request(&bytes).unwrap(), (1, begin));

    let chunk = Request::UploadChunk { upload: [2; 16], offset: 5, bytes: vec![9, 8] };
    let bytes = encode_request(2, &chunk).unwrap();
    let mut expected = vec![11, 0, 0, 0, 2];
    expected.extend_from_slice(&[2; 16]);
    expected.extend_from_slice(&5u64.to_be_bytes());
    expected.extend_from_slice(&2u32.to_be_bytes());
    expected.extend_from_slice(&[9, 8]);
    assert_eq!(bytes, expected);
    assert_eq!(decode_request(&bytes).unwrap(), (2, chunk));

    let finish = Request::UploadFinish { upload: [3; 16] };
    let bytes = encode_request(3, &finish).unwrap();
    let mut expected = vec![12, 0, 0, 0, 3];
    expected.extend_from_slice(&[3; 16]);
    assert_eq!(bytes, expected);
    assert_eq!(decode_request(&bytes).unwrap(), (3, finish));

    for bad in [
        Request::UploadChunk { upload: [1; 16], offset: 0, bytes: Vec::new() },
        Request::UploadChunk { upload: [1; 16], offset: 0, bytes: vec![0; MAX_CHUNK + 1] },
        Request::UploadBegin { room: "r".into(), name: "n".repeat(MAX_FILE_NAME + 1), size: 1, sha256: [0; 32] },
        Request::UploadBegin { room: "r".into(), name: String::new(), size: 1, sha256: [0; 32] },
    ] {
        assert_eq!(encode_request(1, &bad).unwrap_err(), CodecError::FieldLength);
    }
    // A chunk whose length runs past the frame is truncated; tag 13 is not a request.
    let mut short = encode_request(4, &Request::UploadChunk { upload: [1; 16], offset: 0, bytes: vec![1, 2, 3] }).unwrap();
    short.pop();
    assert_eq!(decode_request(&short).unwrap_err(), CodecError::Truncated);
    assert_eq!(decode_request(&[13, 0, 0, 0, 1]).unwrap_err(), CodecError::BadKind(13));

    let frame = encode_id(9, &[4; 16]);
    assert_eq!(frame[0], ID_TAG);
    assert_eq!(decode_id(&frame).unwrap(), (9, [4; 16]));
    assert_eq!(decode_id(&frame[..10]).unwrap_err(), CodecError::Truncated);
    let mut longer = frame.clone();
    longer.push(0);
    assert_eq!(decode_id(&longer).unwrap_err(), CodecError::TrailingBytes);
}

#[test]
fn an_upload_in_any_order_becomes_a_recorded_file_that_survives_a_restart() {
    let dir = scratch("upload");
    let (mut ds, room, _) = server(&dir);
    let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    png.extend_from_slice(&64u32.to_be_bytes());
    png.extend_from_slice(&32u32.to_be_bytes());
    png.extend(std::iter::repeat_n(0xAB, 100_000));
    let upload = ds.begin_upload("bob", &room, "picture.png", png.len() as u64, sha(&png), T0).unwrap();
    assert_eq!(ds.upload_chunk("bob", &upload, 60_000, &png[60_000..], T0 + 1).unwrap(), (png.len() - 60_000) as u64);
    assert_eq!(ds.upload_chunk("bob", &upload, 0, &png[..60_000], T0 + 2).unwrap(), png.len() as u64);
    let file = ds.finish_upload("bob", &upload, T0 + 3).unwrap();
    let stored = ds.file(&file).unwrap().clone();
    assert_eq!((stored.room.as_str(), stored.uploader.as_str(), stored.size, stored.name.as_str()), (room.as_str(), "bob", png.len() as u64, "picture.png"));
    assert_eq!(stored.image, Some((64, 32)), "the image size comes from the bytes");
    assert_eq!(ds.uploads_in_progress(), 0);
    assert_eq!(ds.upload_chunk("bob", &upload, 0, &png[..1], T0 + 4), Err(UploadError::NoSuchUpload), "a finished upload is gone");
    drop(ds);

    let ds = DurableServer::open(&dir.join("rooms.journal")).unwrap().with_files(FileStore::open(&dir.join("files")).unwrap()).unwrap();
    assert_eq!(ds.file(&file), Some(&stored));
    assert!(FileStore::open(&dir.join("files")).unwrap().contains(&stored.sha256), "the start-up sweep keeps recorded bytes");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn every_refusal_comes_before_any_byte_is_kept() {
    let dir = scratch("refuse");
    let (mut ds, room, other) = server(&dir);
    let hash = sha(b"x");
    assert_eq!(ds.begin_upload("bob", &other, "a.txt", 1, hash, T0), Err(UploadError::NotMember));
    assert_eq!(ds.begin_upload("bob", "no-such-room", "a.txt", 1, hash, T0), Err(UploadError::NotMember));
    assert_eq!(ds.begin_upload("bob", &room, "a/b.txt", 1, hash, T0), Err(UploadError::BadName));
    assert_eq!(ds.begin_upload("bob", &room, "a.txt", 0, hash, T0), Err(UploadError::BadSize));
    assert_eq!(ds.begin_upload("bob", &room, "a.txt", MAX_FILE_SIZE + 1, hash, T0), Err(UploadError::BadSize));
    for _ in 0..MAX_UPLOADS_PER_PERSON {
        ds.begin_upload("bob", &room, "a.txt", 1, hash, T0).unwrap();
    }
    assert_eq!(ds.begin_upload("bob", &room, "a.txt", 1, hash, T0), Err(UploadError::TooMany));
    assert!(ds.begin_upload("alice", &room, "a.txt", 1, hash, T0).is_ok(), "the limit is per person");

    // Idle uploads are discarded, which makes room again.
    let later = T0 + UPLOAD_IDLE_MS;
    let fresh = ds.begin_upload("bob", &room, "b.txt", 2, sha(b"ok"), later).unwrap();
    assert_eq!(ds.uploads_in_progress(), 1);

    assert_eq!(ds.upload_chunk("bob", &fresh, 1, b"ok", later), Err(UploadError::BadChunk), "past the declared size");
    assert_eq!(ds.upload_chunk("alice", &fresh, 0, b"ok", later), Err(UploadError::NoSuchUpload), "someone else's upload");
    ds.upload_chunk("bob", &fresh, 0, b"no", later).unwrap();
    assert_eq!(ds.finish_upload("bob", &fresh, later), Err(UploadError::WrongContent));
    assert_eq!(ds.uploads_in_progress(), 0, "a refused finish discards the upload");

    // Leaving the room between the start and the finish: nothing is recorded.
    let leaving = ds.begin_upload("bob", &room, "c.txt", 2, sha(b"ok"), later).unwrap();
    ds.upload_chunk("bob", &leaving, 0, b"ok", later).unwrap();
    ds.remove_member(&room, "alice", "bob").unwrap();
    assert_eq!(ds.finish_upload("bob", &leaving, later), Err(UploadError::NotMember));
    assert!(ds.referenced_hashes().is_empty());

    // A server without a file store keeps no files.
    let mut bare = DurableServer::open(&dir.join("bare.journal")).unwrap();
    let bare_room = bare.create_room("alice", "Bare").unwrap();
    assert_eq!(bare.begin_upload("alice", &bare_room, "a.txt", 1, hash, T0), Err(UploadError::NoStorage));
    fs::remove_dir_all(&dir).unwrap();
}

fn framed(id: u32, request: &Request) -> Vec<u8> {
    encode(&encode_request(id, request).unwrap()).unwrap()
}

fn ok(id: u32, cursor: u64) -> Vec<u8> {
    encode(&encode_response(id, &Response::Ok { cursor }).unwrap()).unwrap()
}

fn refused(id: u32, code: u16) -> Vec<u8> {
    encode(&encode_response(id, &Response::Error { code, detail: String::new() }).unwrap()).unwrap()
}

#[test]
fn the_connection_answers_with_ids_and_codes() {
    let dir = scratch("wire");
    let (mut ds, room, other) = server(&dir);
    let mut bob = Connection::new("bob");
    let bytes = b"hello, file".to_vec();

    let out = bob.receive_durable(&mut ds, &framed(1, &Request::UploadBegin { room: room.clone(), name: "hello.txt".into(), size: bytes.len() as u64, sha256: sha(&bytes) }), T0).unwrap();
    let answer = ok(1, 0);
    assert_eq!(&out[..answer.len()], answer.as_slice());
    let id_frame = &out[answer.len()..];
    let payload = &id_frame[4..];
    let (answered, upload) = decode_id(payload).unwrap();
    assert_eq!(answered, 1);
    assert_eq!(id_frame, encode(&encode_id(1, &upload)).unwrap().as_slice());

    assert_eq!(bob.receive_durable(&mut ds, &framed(2, &Request::UploadChunk { upload, offset: 0, bytes: bytes.clone() }), T0).unwrap(), ok(2, bytes.len() as u64));
    let out = bob.receive_durable(&mut ds, &framed(3, &Request::UploadFinish { upload }), T0).unwrap();
    let answer = ok(3, 0);
    assert_eq!(&out[..answer.len()], answer.as_slice());
    let (_, file) = decode_id(&out[answer.len() + 4..]).unwrap();
    assert_eq!(ds.file(&file).unwrap().name, "hello.txt");

    // Refusals carry their codes and no id frame.
    let begin = |room: &str, name: &str, size: u64| Request::UploadBegin { room: room.into(), name: name.into(), size, sha256: [0; 32] };
    assert_eq!(bob.receive_durable(&mut ds, &framed(4, &begin(&other, "a.txt", 1)), T0).unwrap(), refused(4, E_NO_SUCH_ROOM));
    assert_eq!(bob.receive_durable(&mut ds, &framed(5, &begin(&room, "a.txt", 0)), T0).unwrap(), refused(5, E_BAD_FILE));
    assert_eq!(bob.receive_durable(&mut ds, &framed(6, &Request::UploadFinish { upload: [9; 16] }), T0).unwrap(), refused(6, E_NO_SUCH_UPLOAD));
    for n in 0..MAX_UPLOADS_PER_PERSON as u32 {
        let out = bob.receive_durable(&mut ds, &framed(10 + n, &begin(&room, "a.txt", 1)), T0).unwrap();
        assert!(out.starts_with(&ok(10 + n, 0)));
    }
    assert_eq!(bob.receive_durable(&mut ds, &framed(20, &begin(&room, "a.txt", 1)), T0).unwrap(), refused(20, E_RATE_LIMITED));

    // The in-memory server has nowhere to keep files.
    let mut memory = Server::new();
    let memory_room = memory.create_room("bob", "Memory").unwrap();
    assert_eq!(Connection::new("bob").receive(&mut memory, &framed(1, &begin(&memory_room, "a.txt", 1)), T0).unwrap(), refused(1, E_NO_STORAGE));
    fs::remove_dir_all(&dir).unwrap();
}
