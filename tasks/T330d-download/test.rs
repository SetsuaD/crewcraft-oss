//! T330d: downloads over the device connection (docs/FILES.md): the request and the bytes frame on the wire, byte
//! ranges of a recorded file, and "not found", answered exactly alike, for a file that does not exist, one in a room
//! the person was never in, and one in a room they have left.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use crewcraft_proto::frame::encode;
use crewcraft_proto::message::CodecError;
use crewcraft_proto::request::{BYTES_TAG, MAX_CHUNK, Request, Response, decode_bytes, decode_request, encode_bytes, encode_request, encode_response};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::dispatch::{E_NO_STORAGE, E_NO_SUCH_FILE};
use crewcraft_server_core::durable::{DownloadError, DurableServer};
use crewcraft_server_core::file_store::FileStore;
use crewcraft_server_core::room::Role;
use crewcraft_server_core::server::Server;
use sha2::{Digest, Sha256};

const T0: u64 = 1_800_000_000_000;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("t330d-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A durable server with files, a room of alice and bob, and the file `bytes` uploaded there by alice.
fn with_a_file(dir: &Path, bytes: &[u8]) -> (DurableServer, String, [u8; 16]) {
    let mut ds = DurableServer::open(&dir.join("rooms.journal")).unwrap().with_files(FileStore::open(&dir.join("files")).unwrap()).unwrap();
    let room = ds.create_room("alice", "Project").unwrap();
    ds.add_member(&room, "alice", "bob", Role::Member).unwrap();
    let sha: [u8; 32] = Sha256::digest(bytes).into();
    let upload = ds.begin_upload("alice", &room, "notes.txt", bytes.len() as u64, sha, T0).unwrap();
    ds.upload_chunk("alice", &upload, 0, bytes, T0).unwrap();
    let file = ds.finish_upload("alice", &upload, T0).unwrap();
    (ds, room, file)
}

#[test]
fn the_request_and_the_bytes_frame_have_exact_bytes() {
    let request = Request::Download { file: [5; 16], offset: 7, length: 100 };
    let bytes = encode_request(3, &request).unwrap();
    let mut expected = vec![13, 0, 0, 0, 3];
    expected.extend_from_slice(&[5; 16]);
    expected.extend_from_slice(&7u64.to_be_bytes());
    expected.extend_from_slice(&100u32.to_be_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(decode_request(&bytes).unwrap(), (3, request));
    for length in [0, MAX_CHUNK as u32 + 1] {
        assert_eq!(encode_request(1, &Request::Download { file: [0; 16], offset: 0, length }).unwrap_err(), CodecError::FieldLength);
    }

    let frame = encode_bytes(4, b"abc").unwrap();
    assert_eq!(frame, vec![BYTES_TAG, 0, 0, 0, 4, 0, 0, 0, 3, b'a', b'b', b'c']);
    assert_eq!(decode_bytes(&frame).unwrap(), (4, b"abc".to_vec()));
    assert_eq!(decode_bytes(&encode_bytes(4, b"").unwrap()).unwrap(), (4, Vec::new()));
    assert_eq!(decode_bytes(&frame[..frame.len() - 1]).unwrap_err(), CodecError::Truncated);
    let mut longer = frame.clone();
    longer.push(0);
    assert_eq!(decode_bytes(&longer).unwrap_err(), CodecError::TrailingBytes);
    assert_eq!(encode_bytes(1, &vec![0; MAX_CHUNK + 1]).unwrap_err(), CodecError::FieldLength);
    assert_eq!(decode_bytes(&[133, 0, 0, 0, 1]).unwrap_err(), CodecError::BadKind(133));
}

#[test]
fn members_read_ranges_and_everyone_else_finds_nothing() {
    let dir = scratch("ranges");
    let bytes: Vec<u8> = (0..1000u32).map(|n| (n % 256) as u8).collect();
    let (mut ds, room, file) = with_a_file(&dir, &bytes);
    assert_eq!(ds.download("bob", &file, 0, 1000).unwrap(), bytes);
    assert_eq!(ds.download("bob", &file, 990, 100).unwrap(), &bytes[990..], "fewer at the end");
    assert!(ds.download("bob", &file, 5000, 10).unwrap().is_empty(), "none past it");

    assert_eq!(ds.download("carol", &file, 0, 10), Err(DownloadError::NotFound), "never in the room");
    assert_eq!(ds.download("bob", &[9; 16], 0, 10), Err(DownloadError::NotFound), "no such file");
    ds.remove_member(&room, "alice", "bob").unwrap();
    assert_eq!(ds.download("bob", &file, 0, 10), Err(DownloadError::NotFound), "left the room");
    assert_eq!(ds.download("alice", &file, 0, 3).unwrap(), &bytes[..3]);

    let bare = DurableServer::open(&dir.join("bare.journal")).unwrap();
    assert_eq!(bare.download("alice", &file, 0, 10), Err(DownloadError::NoStorage));
    fs::remove_dir_all(&dir).unwrap();
}

fn framed(id: u32, request: &Request) -> Vec<u8> {
    encode(&encode_request(id, request).unwrap()).unwrap()
}

fn refused(id: u32, code: u16) -> Vec<u8> {
    encode(&encode_response(id, &Response::Error { code, detail: String::new() }).unwrap()).unwrap()
}

#[test]
fn the_connection_answers_with_the_bytes_or_not_found() {
    let dir = scratch("wire");
    let (mut ds, _room, file) = with_a_file(&dir, b"hello, file");
    let out = Connection::new("bob").receive_durable(&mut ds, &framed(5, &Request::Download { file, offset: 7, length: 100 }), T0).unwrap();
    let mut expected = encode(&encode_response(5, &Response::Ok { cursor: 4 }).unwrap()).unwrap();
    expected.extend(encode(&encode_bytes(5, b"file").unwrap()).unwrap());
    assert_eq!(out, expected);

    let request = framed(6, &Request::Download { file, offset: 0, length: 5 });
    assert_eq!(Connection::new("carol").receive_durable(&mut ds, &request, T0).unwrap(), refused(6, E_NO_SUCH_FILE));
    let unknown = framed(7, &Request::Download { file: [9; 16], offset: 0, length: 5 });
    assert_eq!(Connection::new("bob").receive_durable(&mut ds, &unknown, T0).unwrap(), refused(7, E_NO_SUCH_FILE));

    let mut memory = Server::new();
    memory.create_room("bob", "Memory").unwrap();
    assert_eq!(Connection::new("bob").receive(&mut memory, &framed(8, &Request::Download { file, offset: 0, length: 5 }), T0).unwrap(), refused(8, E_NO_STORAGE));
    fs::remove_dir_all(&dir).unwrap();
}
