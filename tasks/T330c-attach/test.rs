//! T330c: messages that carry files (docs/FILES.md): the `PostFiles` request and the `Attached` push on the wire; the
//! durable server attaching only the poster's own unattached uploads in that room, in one record that survives a
//! restart; a deleted message's files no longer found; attachments pushed only to a client that agreed to files; and
//! the client keeping them beside the timeline.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use crewcraft_client_core::inbox::Inbox;
use crewcraft_client_core::notify::Settings;
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_proto::message::CodecError;
use crewcraft_proto::push::{AttachedFile, MAX_ATTACHMENTS, Push, decode_push, encode_push};
use crewcraft_proto::request::{FEATURE_FILES, Request, Response, decode_request, decode_response, encode_request};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::dispatch::E_BAD_ATTACHMENT;
use crewcraft_server_core::durable::{AttachError, DownloadError, DurableServer};
use crewcraft_server_core::file_store::FileStore;
use crewcraft_server_core::room::Role;
use sha2::{Digest, Sha256};

const T0: u64 = 1_800_000_000_000;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("t330c-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn open(dir: &Path) -> DurableServer {
    DurableServer::open(&dir.join("rooms.journal")).unwrap().with_files(FileStore::open(&dir.join("files")).unwrap()).unwrap()
}

fn upload(ds: &mut DurableServer, user: &str, room: &str, name: &str, bytes: &[u8]) -> [u8; 16] {
    let sha: [u8; 32] = Sha256::digest(bytes).into();
    let upload = ds.begin_upload(user, room, name, bytes.len() as u64, sha, T0).unwrap();
    ds.upload_chunk(user, &upload, 0, bytes, T0).unwrap();
    ds.finish_upload(user, &upload, T0).unwrap()
}

fn attached(file: [u8; 16], name: &str, size: u64) -> AttachedFile {
    AttachedFile { file, name: name.into(), size, image: None }
}

#[test]
fn the_request_and_the_push_have_exact_bytes() {
    let request = Request::PostFiles { room: "r".into(), text: "hi".into(), files: vec![[1; 16], [2; 16]] };
    let bytes = encode_request(4, &request).unwrap();
    let mut expected = vec![15, 0, 0, 0, 4, 0, 1, b'r', 0, 2, b'h', b'i', 2];
    expected.extend_from_slice(&[1; 16]);
    expected.extend_from_slice(&[2; 16]);
    assert_eq!(bytes, expected);
    assert_eq!(decode_request(&bytes).unwrap(), (4, request));
    assert!(encode_request(1, &Request::PostFiles { room: "r".into(), text: String::new(), files: vec![[1; 16]] }).is_ok(), "the text may be empty");
    for files in [Vec::new(), vec![[0; 16]; 11]] {
        assert_eq!(encode_request(1, &Request::PostFiles { room: "r".into(), text: "x".into(), files }).unwrap_err(), CodecError::FieldLength);
    }

    let push = Push::Attached {
        room: "r".into(),
        cursor: 9,
        files: vec![attached([3; 16], "a.txt", 5), AttachedFile { file: [4; 16], name: "p.png".into(), size: 7, image: Some((2, 1)) }],
    };
    let bytes = encode_push(&push).unwrap();
    let mut expected = vec![70, 0, 1, b'r'];
    expected.extend_from_slice(&9u64.to_be_bytes());
    expected.push(2);
    expected.extend_from_slice(&[3; 16]);
    expected.extend_from_slice(&[0, 5]);
    expected.extend_from_slice(b"a.txt");
    expected.extend_from_slice(&5u64.to_be_bytes());
    expected.push(0);
    expected.extend_from_slice(&[4; 16]);
    expected.extend_from_slice(&[0, 5]);
    expected.extend_from_slice(b"p.png");
    expected.extend_from_slice(&7u64.to_be_bytes());
    expected.push(1);
    expected.extend_from_slice(&2u32.to_be_bytes());
    expected.extend_from_slice(&1u32.to_be_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(decode_push(&bytes).unwrap(), push);
    for cut in 1..bytes.len() {
        assert!(decode_push(&bytes[..cut]).is_err(), "cut at {cut}");
    }
    let too_many = Push::Attached { room: "r".into(), cursor: 1, files: vec![attached([0; 16], "a", 1); MAX_ATTACHMENTS + 1] };
    assert_eq!(encode_push(&too_many).unwrap_err(), CodecError::FieldLength);
    assert_eq!(encode_push(&Push::Attached { room: "r".into(), cursor: 1, files: Vec::new() }).unwrap_err(), CodecError::FieldLength);
}

#[test]
fn only_the_posters_unattached_uploads_in_that_room_attach_and_a_deletion_detaches() {
    let dir = scratch("attach");
    let mut ds = open(&dir);
    let room = ds.create_room("alice", "Project").unwrap();
    let other = ds.create_room("bob", "Elsewhere").unwrap();
    ds.add_member(&room, "alice", "bob", Role::Member).unwrap();
    let notes = upload(&mut ds, "bob", &room, "notes.txt", b"some notes");
    let plan = upload(&mut ds, "bob", &room, "plan.txt", b"the plan");
    let alices = upload(&mut ds, "alice", &room, "hers.txt", b"hers");
    let elsewhere = upload(&mut ds, "bob", &other, "there.txt", b"there");

    let cursor = ds.post_files(&room, "bob", "", &[notes, plan], T0 + 1).unwrap();
    assert_eq!(ds.attachments(&room, cursor), vec![attached(notes, "notes.txt", 10), attached(plan, "plan.txt", 8)]);
    // An empty text reads as the files' names, so a client that does not show attachments still says what it is.
    assert_eq!(ds.found("alice", "notes")[0].snippet, "Files: notes.txt, plan.txt");

    for (files, why) in [
        (vec![notes], "already attached"),
        (vec![alices], "someone else's upload"),
        (vec![elsewhere], "an upload in another room"),
        (vec![[9; 16]], "no such file"),
        (Vec::new(), "no files"),
    ] {
        assert_eq!(ds.post_files(&room, "bob", "text", &files, T0 + 2), Err(AttachError::BadAttachment), "{why}");
    }
    let fresh = upload(&mut ds, "bob", &room, "fresh.txt", b"fresh");
    assert_eq!(ds.post_files(&room, "bob", "twice", &[fresh, fresh], T0 + 2), Err(AttachError::BadAttachment), "the same file twice");
    assert_eq!(ds.download("alice", &notes, 0, 4).unwrap(), b"some");

    // Deleting the message detaches its files: they are not found any more.
    ds.delete(&room, "bob", cursor).unwrap();
    assert!(ds.attachments(&room, cursor).is_empty());
    assert_eq!(ds.download("alice", &notes, 0, 4), Err(DownloadError::NotFound));
    let second = ds.post_files(&room, "bob", "with the fresh one", &[fresh], T0 + 3).unwrap();
    drop(ds);

    // One record each: a restart replays the attachments and the deletion.
    let ds = open(&dir);
    assert!(ds.attachments(&room, cursor).is_empty());
    assert_eq!(ds.download("alice", &notes, 0, 4), Err(DownloadError::NotFound));
    assert_eq!(ds.attachments(&room, second), vec![attached(fresh, "fresh.txt", 5)]);
    fs::remove_dir_all(&dir).unwrap();
}

/// The frames `bytes` holds, decoded: responses as `Ok`, pushes as `Push`.
fn frames(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut decoder = Decoder::new();
    decoder.push(bytes);
    let mut out = Vec::new();
    while let Some(frame) = decoder.next_frame().unwrap() {
        out.push(frame);
    }
    out
}

#[test]
fn attachments_are_pushed_only_to_a_client_that_agreed_to_files() {
    let dir = scratch("push");
    let mut ds = open(&dir);
    let room = ds.create_room("alice", "Project").unwrap();
    let file = upload(&mut ds, "alice", &room, "a.txt", b"abc");
    let cursor = ds.post_files(&room, "alice", "look", &[file], T0).unwrap();
    let sync = encode(&encode_request(1, &Request::Sync { room: room.clone(), cursor: 0 }).unwrap()).unwrap();

    let with_files = frames(&Connection::with_features("alice", FEATURE_FILES).receive_durable(&mut ds, &sync, T0).unwrap());
    let pushes: Vec<Push> = with_files.iter().skip(1).map(|frame| decode_push(frame).unwrap()).collect();
    assert!(matches!(pushes.last(), Some(Push::Attached { cursor: at, files, .. }) if *at == cursor && files == &vec![attached(file, "a.txt", 3)]));
    let without = frames(&Connection::new("alice").receive_durable(&mut ds, &sync, T0).unwrap());
    assert_eq!(without.len(), with_files.len() - 1, "an older client is never sent a push it cannot read");
    assert!(without.iter().skip(1).all(|frame| !matches!(decode_push(frame), Ok(Push::Attached { .. }))));

    // A refusal over the wire.
    let bad = encode(&encode_request(2, &Request::PostFiles { room: room.clone(), text: "again".into(), files: vec![file] }).unwrap()).unwrap();
    let answer = frames(&Connection::new("alice").receive_durable(&mut ds, &bad, T0).unwrap());
    assert_eq!(decode_response(&answer[0]).unwrap(), (2, Response::Error { code: E_BAD_ATTACHMENT, detail: String::new() }));
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_client_keeps_a_messages_files_beside_the_timeline() {
    let mut inbox = Inbox::new("alice", Settings::new("alice"));
    inbox.follow("general", false);
    let files = vec![attached([1; 16], "a.txt", 3)];
    inbox
        .on_push(Push::Posted { room: "general".into(), cursor: 1, author: "bob".into(), html: "<p>look</p>".into(), mentions: Vec::new() }, T0, 0)
        .unwrap();
    inbox.on_push(Push::Attached { room: "general".into(), cursor: 1, files: files.clone() }, T0, 0).unwrap();
    let view = inbox.view("general").unwrap();
    assert_eq!(view.attachments().get(&1), Some(&files));
    assert_eq!(view.cursor(), 1, "an attachment push advances nothing");
    assert!(inbox.on_push(Push::Attached { room: "elsewhere".into(), cursor: 1, files }, T0, 0).is_none(), "a room not followed");
}
