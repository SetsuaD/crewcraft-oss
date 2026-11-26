//! T350d1: archive rooms on the wire (docs/IMPORT.md): after a `Sync` of an archive room, a client that agreed to
//! `FEATURE_ARCHIVE` is told the room is an archive (before its events) and each imported message's original time
//! (after its `Posted`); other clients and ordinary rooms get neither; and the client keeps both.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use crewcraft_client_core::inbox::Inbox;
use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::timeline::Apply;
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_proto::push::{Push, decode_push, encode_push};
use crewcraft_proto::request::{FEATURE_ARCHIVE, Request, encode_request};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::import::{Bundle, BundleMessage, BundleRoom, RoomKind};

const T0: u64 = 1_700_000_000_000;

fn journal(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("t350d1-{name}-{}", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

#[test]
fn the_pushes_have_exact_bytes() {
    let archived = Push::Archived { room: "r".into(), cursor: 0 };
    let bytes = encode_push(&archived).unwrap();
    let mut expected = vec![73, 0, 1, b'r'];
    expected.extend_from_slice(&0u64.to_be_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(decode_push(&bytes).unwrap(), archived);

    let sent = Push::Sent { room: "r".into(), cursor: 4, sent_ms: T0 };
    let bytes = encode_push(&sent).unwrap();
    let mut expected = vec![74, 0, 1, b'r'];
    expected.extend_from_slice(&4u64.to_be_bytes());
    expected.extend_from_slice(&T0.to_be_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(decode_push(&bytes).unwrap(), sent);
    for cut in 1..bytes.len() {
        assert!(decode_push(&bytes[..cut]).is_err(), "cut at {cut}");
    }
}

fn frames(bytes: &[u8]) -> Vec<Push> {
    let mut decoder = Decoder::new();
    decoder.push(bytes);
    let mut out = Vec::new();
    while let Some(frame) = decoder.next_frame().unwrap() {
        out.push(frame);
    }
    // The first frame is the response; the rest are pushes.
    out.iter().skip(1).map(|frame| decode_push(frame).unwrap()).collect()
}

fn message(key: &str, minute: u64, text: &str) -> BundleMessage {
    BundleMessage {
        room: "c1".into(),
        key: key.into(),
        author: "bo@example.org".into(),
        sent_ms: T0 + minute * 60_000,
        text: text.into(),
        reply_to: None,
        edited_ms: None,
        deleted: false,
        files: Vec::new(),
    }
}

#[test]
fn an_archive_room_and_its_times_reach_a_client_that_agreed() {
    let p = journal("sync");
    let mut ds = DurableServer::open(&p).unwrap();
    let bundle = Bundle {
        source: "test".into(),
        rooms: vec![BundleRoom { key: "c1".into(), kind: RoomKind::Group, name: "Old team".into(), members: vec!["ana@example.org".into()] }],
        messages: vec![message("m1", 1, "first"), message("m2", 2, "second")],
    };
    assert!(ds.import(&bundle, &|_| true, false).unwrap().ok());
    let archive = ds.archive_room("test", "c1").unwrap().to_owned();
    let ordinary = ds.create_room("ana@example.org", "Today").unwrap();
    ds.post(&ordinary, "ana@example.org", "a live message", T0).unwrap();

    let sync = |room: &str| encode(&encode_request(1, &Request::Sync { room: room.to_owned(), cursor: 0 }).unwrap()).unwrap();
    let pushes = frames(&Connection::with_features("ana@example.org", FEATURE_ARCHIVE).receive_durable(&mut ds, &sync(&archive), T0).unwrap());
    let shapes: Vec<&str> = pushes
        .iter()
        .map(|push| match push {
            Push::Archived { .. } => "archived",
            Push::Sent { .. } => "sent",
            Push::Posted { .. } => "posted",
            _ => "other",
        })
        .collect();
    assert_eq!(shapes, vec!["archived", "other", "posted", "sent", "posted", "sent"], "the member's join, then each message and its time");
    let times: Vec<(u64, u64)> = pushes
        .iter()
        .filter_map(|push| match push {
            Push::Sent { cursor, sent_ms, .. } => Some((*cursor, *sent_ms)),
            _ => None,
        })
        .collect();
    assert_eq!(times, vec![(2, T0 + 60_000), (3, T0 + 120_000)]);

    // An older client sees the archive as an ordinary room's messages; an ordinary room has neither push.
    let older = frames(&Connection::new("ana@example.org").receive_durable(&mut ds, &sync(&archive), T0).unwrap());
    assert!(older.iter().all(|push| !matches!(push, Push::Archived { .. } | Push::Sent { .. })));
    let live = frames(&Connection::with_features("ana@example.org", FEATURE_ARCHIVE).receive_durable(&mut ds, &sync(&ordinary), T0).unwrap());
    assert!(live.iter().all(|push| !matches!(push, Push::Archived { .. } | Push::Sent { .. })));
    fs::remove_file(&p).unwrap();
}

#[test]
fn the_client_keeps_the_flag_and_the_times() {
    let mut inbox = Inbox::new("ana", Settings::new("ana"));
    inbox.follow("old", false);
    assert_eq!(inbox.on_push(Push::Archived { room: "old".into(), cursor: 0 }, T0, 0).unwrap().0, Apply::Duplicate);
    inbox.on_push(Push::Posted { room: "old".into(), cursor: 1, author: "bo".into(), html: "hi".into(), mentions: Vec::new() }, T0, 0);
    inbox.on_push(Push::Sent { room: "old".into(), cursor: 1, sent_ms: T0 }, T0, 0);
    let view = inbox.view("old").unwrap();
    assert!(view.archived());
    assert_eq!(view.sent_times().get(&1), Some(&T0));
    assert_eq!(view.cursor(), 1, "neither push advances the cursor");
}
