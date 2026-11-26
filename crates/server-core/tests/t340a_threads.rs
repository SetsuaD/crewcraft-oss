//! T340a: threads (REQUIREMENTS 2.1): the `Reply` request and the `Threaded` push on the wire; a reply attaches only
//! to a live, top-level message in the same room (replies to replies refused), in one record that survives a restart;
//! the thread is pushed only to a client that agreed to threads; and the client keeps each reply's parent.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use crewcraft_client_core::inbox::Inbox;
use crewcraft_client_core::notify::Settings;
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_proto::push::{Push, decode_push, encode_push};
use crewcraft_proto::request::{FEATURE_THREADS, Request, Response, decode_request, decode_response, encode_request};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::dispatch::E_NO_SUCH_MESSAGE;
use crewcraft_server_core::durable::{DurableServer, ReplyError};
use crewcraft_server_core::room::Role;

const T0: u64 = 1_800_000_000_000;

fn journal(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("t340a-{name}-{}", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

#[test]
fn the_request_and_the_push_have_exact_bytes() {
    let request = Request::Reply { room: "r".into(), parent: 7, text: "ok".into() };
    let bytes = encode_request(3, &request).unwrap();
    let mut expected = vec![16, 0, 0, 0, 3, 0, 1, b'r'];
    expected.extend_from_slice(&7u64.to_be_bytes());
    expected.extend_from_slice(&[0, 2, b'o', b'k']);
    assert_eq!(bytes, expected);
    assert_eq!(decode_request(&bytes).unwrap(), (3, request));

    let push = Push::Threaded { room: "r".into(), cursor: 9, parent: 7 };
    let bytes = encode_push(&push).unwrap();
    let mut expected = vec![71, 0, 1, b'r'];
    expected.extend_from_slice(&9u64.to_be_bytes());
    expected.extend_from_slice(&7u64.to_be_bytes());
    assert_eq!(bytes, expected);
    assert_eq!(decode_push(&bytes).unwrap(), push);
    for cut in 1..bytes.len() {
        assert!(decode_push(&bytes[..cut]).is_err(), "cut at {cut}");
    }
}

#[test]
fn a_reply_attaches_only_to_a_live_top_level_message() {
    let p = journal("rules");
    let mut ds = DurableServer::open(&p).unwrap();
    let room = ds.create_room("alice", "Project").unwrap();
    let other = ds.create_room("alice", "Elsewhere").unwrap();
    ds.add_member(&room, "alice", "bob", Role::Member).unwrap();
    let post = ds.post(&room, "alice", "the plan", T0).unwrap();
    let reply = ds.reply(&room, "bob", post, "looks good", T0 + 1).unwrap();
    let second = ds.reply(&room, "alice", post, "thanks", T0 + 2).unwrap();
    assert_eq!((ds.parent_of(&room, reply), ds.parent_of(&room, second), ds.parent_of(&room, post)), (Some(post), Some(post), None));
    assert_eq!(ds.reply_count(&room, post), 2);

    assert_eq!(ds.reply(&room, "bob", reply, "a reply to a reply", T0 + 3), Err(ReplyError::NoParent));
    assert_eq!(ds.reply(&room, "bob", 999, "nothing there", T0 + 3), Err(ReplyError::NoParent));
    let other_post = ds.post(&other, "alice", "elsewhere", T0 + 3).unwrap();
    assert_eq!(ds.reply(&room, "bob", other_post + 100, "not in this room", T0 + 4), Err(ReplyError::NoParent));
    assert!(matches!(ds.reply(&room, "carol", post, "not a member", T0 + 4), Err(ReplyError::NoParent | ReplyError::Durable(_))));
    let gone = ds.post(&room, "alice", "to be deleted", T0 + 5).unwrap();
    ds.delete(&room, "alice", gone).unwrap();
    assert_eq!(ds.reply(&room, "bob", gone, "too late", T0 + 6), Err(ReplyError::NoParent), "a deleted message");
    // A reply is an ordinary message too: it can be found.
    assert_eq!(ds.found("alice", "looks")[0].cursor, reply);
    drop(ds);

    let ds = DurableServer::open(&p).unwrap();
    assert_eq!((ds.parent_of(&room, reply), ds.reply_count(&room, post)), (Some(post), 2), "replayed from one record each");
    fs::remove_file(&p).unwrap();
}

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
fn the_thread_is_pushed_only_to_a_client_that_agreed_to_threads() {
    let p = journal("push");
    let mut ds = DurableServer::open(&p).unwrap();
    let room = ds.create_room("alice", "Project").unwrap();
    let post = ds.post(&room, "alice", "the plan", T0).unwrap();
    let reply_frame = encode(&encode_request(1, &Request::Reply { room: room.clone(), parent: post, text: "agreed".into() }).unwrap()).unwrap();
    let answer = frames(&Connection::new("alice").receive_durable(&mut ds, &reply_frame, T0 + 1).unwrap());
    let (_, response) = decode_response(&answer[0]).unwrap();
    let Response::Ok { cursor: reply } = response else { panic!("not Ok: {response:?}") };

    let sync = encode(&encode_request(2, &Request::Sync { room: room.clone(), cursor: 0 }).unwrap()).unwrap();
    let with = frames(&Connection::with_features("alice", FEATURE_THREADS).receive_durable(&mut ds, &sync, T0 + 2).unwrap());
    let pushes: Vec<Push> = with.iter().skip(1).map(|frame| decode_push(frame).unwrap()).collect();
    assert!(pushes.contains(&Push::Threaded { room: room.clone(), cursor: reply, parent: post }));
    let without = frames(&Connection::new("alice").receive_durable(&mut ds, &sync, T0 + 2).unwrap());
    assert_eq!(without.len(), with.len() - 1, "an older client sees the reply as an ordinary message");

    let bad = encode(&encode_request(3, &Request::Reply { room: room.clone(), parent: reply, text: "nested".into() }).unwrap()).unwrap();
    let answer = frames(&Connection::new("alice").receive_durable(&mut ds, &bad, T0 + 3).unwrap());
    assert_eq!(decode_response(&answer[0]).unwrap(), (3, Response::Error { code: E_NO_SUCH_MESSAGE, detail: String::new() }));
    fs::remove_file(&p).unwrap();
}

#[test]
fn the_client_keeps_each_replys_parent() {
    let mut inbox = Inbox::new("alice", Settings::new("alice"));
    inbox.follow("general", false);
    inbox.on_push(Push::Posted { room: "general".into(), cursor: 1, author: "bob".into(), html: "<p>plan</p>".into(), mentions: Vec::new() }, T0, 0);
    inbox.on_push(Push::Posted { room: "general".into(), cursor: 2, author: "bob".into(), html: "<p>reply</p>".into(), mentions: Vec::new() }, T0, 0);
    inbox.on_push(Push::Threaded { room: "general".into(), cursor: 2, parent: 1 }, T0, 0).unwrap();
    let view = inbox.view("general").unwrap();
    assert_eq!(view.parents().get(&2), Some(&1));
    assert_eq!(view.cursor(), 2, "the thread push advances nothing");
}
