//! T332a: storage quotas (REQUIREMENTS 2.4 "showing storage use against a quota"): each person's uploads count against
//! their quota (10 GiB unless the server says otherwise), uploads in progress included; an upload that would go past it
//! is refused before any byte is received; a deleted message's files stop counting; and `StorageUse` tells a client
//! the use and the quota.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_proto::request::{Request, Response, decode_id, decode_request, decode_response, encode_request, storage_frame, storage_of};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::dispatch::E_OVER_QUOTA;
use crewcraft_server_core::durable::{DEFAULT_QUOTA, DurableServer, UploadError};
use crewcraft_server_core::file_store::FileStore;
use crewcraft_server_core::room::Role;
use sha2::{Digest, Sha256};

const T0: u64 = 1_800_000_000_000;
const ANA: &str = "ana@example.org";
const BO: &str = "bo@example.org";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("t332a-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn open(dir: &Path, quota: u64) -> DurableServer {
    DurableServer::open(&dir.join("rooms.journal")).unwrap().with_files(FileStore::open(&dir.join("files")).unwrap()).unwrap().with_quota(quota)
}

fn upload(ds: &mut DurableServer, user: &str, room: &str, name: &str, bytes: &[u8]) -> Result<[u8; 16], UploadError> {
    let sha: [u8; 32] = Sha256::digest(bytes).into();
    let upload = ds.begin_upload(user, room, name, bytes.len() as u64, sha, T0)?;
    ds.upload_chunk(user, &upload, 0, bytes, T0).unwrap();
    Ok(ds.finish_upload(user, &upload, T0).unwrap())
}

#[test]
fn the_wire() {
    let bytes = encode_request(3, &Request::StorageUse).unwrap();
    assert_eq!(bytes, vec![25, 0, 0, 0, 3]);
    assert_eq!(decode_request(&bytes).unwrap(), (3, Request::StorageUse));
    assert_eq!(storage_of(&storage_frame(1234, DEFAULT_QUOTA)), (1234, DEFAULT_QUOTA));
    assert_eq!(DEFAULT_QUOTA, 10 * 1024 * 1024 * 1024);
}

#[test]
fn uploads_count_against_the_quota() {
    let dir = scratch("quota");
    let mut ds = open(&dir, 100);
    let room = ds.create_room(ANA, "Project").unwrap();
    ds.add_member(&room, ANA, BO, Role::Member).unwrap();
    assert_eq!(ds.quota(), 100);
    let first = upload(&mut ds, ANA, &room, "a.bin", &[1; 60]).unwrap();
    assert_eq!(ds.storage_used(ANA), 60);
    assert_eq!(upload(&mut ds, ANA, &room, "b.bin", &[2; 41]), Err(UploadError::OverQuota), "60 + 41 is past 100");
    upload(&mut ds, ANA, &room, "c.bin", &[3; 40]).unwrap();
    assert_eq!(ds.storage_used(ANA), 100, "up to the quota exactly is fine");
    assert_eq!(ds.storage_used(BO), 0, "each person has their own");
    upload(&mut ds, BO, &room, "d.bin", &[4; 90]).unwrap();

    // An upload in progress is counted before its bytes arrive.
    let started = ds.begin_upload(BO, &room, "e.bin", 5, [0; 32], T0).unwrap();
    assert_eq!(ds.begin_upload(BO, &room, "f.bin", 6, [0; 32], T0), Err(UploadError::OverQuota));
    let _ = started;

    // A deleted message's files stop counting.
    let post = ds.post_files(&room, ANA, "the files", &[first], T0).unwrap();
    ds.delete(&room, ANA, post).unwrap();
    assert_eq!(ds.storage_used(ANA), 40);
    upload(&mut ds, ANA, &room, "g.bin", &[5; 60]).unwrap();
}

#[test]
fn a_client_learns_its_use_and_quota() {
    let dir = scratch("wire");
    let mut ds = open(&dir, 100);
    let room = ds.create_room(ANA, "Project").unwrap();
    upload(&mut ds, ANA, &room, "a.bin", &[1; 60]).unwrap();
    let send = |ds: &mut DurableServer, request: Request| {
        let out = Connection::new(ANA).receive_durable(ds, &encode(&encode_request(7, &request).unwrap()).unwrap(), T0).unwrap();
        let mut decoder = Decoder::new();
        decoder.push(&out);
        let mut frames = Vec::new();
        while let Some(frame) = decoder.next_frame().unwrap() {
            frames.push(frame);
        }
        frames
    };
    let frames = send(&mut ds, Request::StorageUse);
    assert_eq!(decode_response(&frames[0]).unwrap(), (7, Response::Ok { cursor: 60 }));
    let (id, frame) = decode_id(&frames[1]).unwrap();
    assert_eq!((id, storage_of(&frame)), (7, (60, 100)));

    let refused = send(&mut ds, Request::UploadBegin { room: room.clone(), name: "big.bin".into(), size: 41, sha256: [0; 32] });
    assert_eq!(decode_response(&refused[0]).unwrap(), (7, Response::Error { code: E_OVER_QUOTA, detail: String::new() }));
}
