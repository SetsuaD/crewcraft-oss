//! T341a: reactions (REQUIREMENTS 2.1): the `React` request and the `Reacted` push on the wire, with a fixed set of
//! reactions named in words; a reaction goes only on a live message, by a member who may post, as an event of its own
//! that survives a restart; a client that did not agree to reactions is sent `Other` in its place; and the client
//! keeps who reacted with what.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use crewcraft_client_core::inbox::Inbox;
use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::timeline::Apply;
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_proto::push::{Push, REACTIONS, decode_push, encode_push, reaction_name};
use crewcraft_proto::request::{FEATURE_REACTIONS, Request, Response, decode_request, decode_response, encode_request};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::dispatch::{E_NO_SUCH_MESSAGE, E_NOT_ALLOWED};
use crewcraft_server_core::durable::{DurableError, DurableServer};
use crewcraft_server_core::room::Role;
use crewcraft_server_core::room_service::ServiceError;
use crewcraft_server_core::server::ServerError;

const T0: u64 = 1_800_000_000_000;

fn journal(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("t341a-{name}-{}", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

fn people(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn the_reactions_are_a_fixed_set_in_words() {
    assert_eq!(REACTIONS, ["Like", "Heart", "Laugh", "Surprised", "Sad", "Angry"]);
    assert_eq!((reaction_name(1), reaction_name(6), reaction_name(0), reaction_name(7)), (Some("Like"), Some("Angry"), None, None));
}

#[test]
fn the_request_and_the_push_have_exact_bytes() {
    let request = Request::React { room: "r".into(), target: 7, reaction: 2, on: true };
    let bytes = encode_request(3, &request).unwrap();
    let mut expected = vec![17, 0, 0, 0, 3, 0, 1, b'r'];
    expected.extend_from_slice(&7u64.to_be_bytes());
    expected.extend_from_slice(&[2, 1]);
    assert_eq!(bytes, expected);
    assert_eq!(decode_request(&bytes).unwrap(), (3, request));
    for bad in [[0, 1], [7, 1], [2, 2]] {
        let mut wrong = bytes.clone();
        let at = wrong.len() - 2;
        wrong[at..].copy_from_slice(&bad);
        assert!(decode_request(&wrong).is_err(), "{bad:?}");
    }
    assert!(encode_request(3, &Request::React { room: "r".into(), target: 7, reaction: 9, on: true }).is_err());

    let push = Push::Reacted { room: "r".into(), cursor: 9, target: 7, author: "bo".into(), reaction: 1, on: false };
    let bytes = encode_push(&push).unwrap();
    let mut expected = vec![72, 0, 1, b'r'];
    expected.extend_from_slice(&9u64.to_be_bytes());
    expected.extend_from_slice(&7u64.to_be_bytes());
    expected.extend_from_slice(&[0, 2, b'b', b'o', 1, 0]);
    assert_eq!(bytes, expected);
    assert_eq!(decode_push(&bytes).unwrap(), push);
    for cut in 1..bytes.len() {
        assert!(decode_push(&bytes[..cut]).is_err(), "cut at {cut}");
    }
}

#[test]
fn a_reaction_goes_only_on_a_live_message_and_survives_a_restart() {
    let p = journal("rules");
    let mut ds = DurableServer::open(&p).unwrap();
    let room = ds.create_room("alice", "Project").unwrap();
    ds.add_member(&room, "alice", "bob", Role::Member).unwrap();
    ds.add_member(&room, "alice", "gus", Role::Guest).unwrap();
    let post = ds.post(&room, "alice", "the plan", T0).unwrap();
    let liked = ds.react(&room, "bob", post, 1, true, T0 + 1).unwrap();
    assert_eq!(liked, post + 1, "an event of its own");
    ds.react(&room, "alice", post, 1, true, T0 + 2).unwrap();
    ds.react(&room, "alice", post, 2, true, T0 + 3).unwrap();
    ds.react(&room, "alice", post, 2, false, T0 + 4).unwrap();
    let reactions = ds.server().room(&room).unwrap().reactions(post);
    assert_eq!(reactions.into_iter().collect::<Vec<_>>(), vec![(1, people(&["alice", "bob"]))]);

    let refused = |error| Err(DurableError::Server(ServerError::Service(error)));
    assert_eq!(ds.react(&room, "bob", post, 7, true, T0 + 5), refused(ServiceError::BadReaction));
    assert_eq!(ds.react(&room, "bob", 999, 1, true, T0 + 5), refused(ServiceError::NoSuchMessage));
    assert_eq!(ds.react(&room, "gus", post, 1, true, T0 + 5), refused(ServiceError::NotAllowed), "a Guest");
    assert!(ds.react(&room, "carol", post, 1, true, T0 + 5).is_err(), "not a member");
    let gone = ds.post(&room, "alice", "to be deleted", T0 + 6).unwrap();
    ds.react(&room, "bob", gone, 3, true, T0 + 7).unwrap();
    ds.delete(&room, "alice", gone).unwrap();
    assert!(ds.server().room(&room).unwrap().reactions(gone).is_empty(), "a deleted message keeps none");
    assert_eq!(ds.react(&room, "bob", gone, 3, true, T0 + 8), refused(ServiceError::NoSuchMessage));
    drop(ds);

    let ds = DurableServer::open(&p).unwrap();
    let reactions = ds.server().room(&room).unwrap().reactions(post);
    assert_eq!(reactions.into_iter().collect::<Vec<_>>(), vec![(1, people(&["alice", "bob"]))], "replayed");
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
fn an_older_client_is_sent_other_in_its_place() {
    let p = journal("push");
    let mut ds = DurableServer::open(&p).unwrap();
    let room = ds.create_room("alice", "Project").unwrap();
    ds.add_member(&room, "alice", "gus", Role::Guest).unwrap();
    let post = ds.post(&room, "alice", "the plan", T0).unwrap();
    let react = encode(&encode_request(1, &Request::React { room: room.clone(), target: post, reaction: 3, on: true }).unwrap()).unwrap();
    let answer = frames(&Connection::new("alice").receive_durable(&mut ds, &react, T0 + 1).unwrap());
    let (_, response) = decode_response(&answer[0]).unwrap();
    let Response::Ok { cursor } = response else { panic!("not Ok: {response:?}") };

    let sync = encode(&encode_request(2, &Request::Sync { room: room.clone(), cursor: post }).unwrap()).unwrap();
    let with = frames(&Connection::with_features("alice", FEATURE_REACTIONS).receive_durable(&mut ds, &sync, T0 + 2).unwrap());
    let pushed: Vec<Push> = with.iter().skip(1).map(|frame| decode_push(frame).unwrap()).collect();
    assert_eq!(pushed, vec![Push::Reacted { room: room.clone(), cursor, target: post, author: "alice".into(), reaction: 3, on: true }]);
    let without = frames(&Connection::new("alice").receive_durable(&mut ds, &sync, T0 + 2).unwrap());
    let pushed: Vec<Push> = without.iter().skip(1).map(|frame| decode_push(frame).unwrap()).collect();
    assert_eq!(pushed, vec![Push::Other { room: room.clone(), cursor }], "it still advances the cursor");

    let missing = encode(&encode_request(3, &Request::React { room: room.clone(), target: 999, reaction: 1, on: true }).unwrap()).unwrap();
    let answer = frames(&Connection::new("alice").receive_durable(&mut ds, &missing, T0 + 3).unwrap());
    assert_eq!(decode_response(&answer[0]).unwrap(), (3, Response::Error { code: E_NO_SUCH_MESSAGE, detail: String::new() }));
    let guest = encode(&encode_request(4, &Request::React { room: room.clone(), target: post, reaction: 1, on: true }).unwrap()).unwrap();
    let answer = frames(&Connection::new("gus").receive_durable(&mut ds, &guest, T0 + 4).unwrap());
    assert_eq!(decode_response(&answer[0]).unwrap(), (4, Response::Error { code: E_NOT_ALLOWED, detail: String::new() }));
    fs::remove_file(&p).unwrap();
}

#[test]
fn the_client_keeps_who_reacted_with_what() {
    let mut inbox = Inbox::new("alice", Settings::new("alice"));
    inbox.follow("general", false);
    inbox.on_push(Push::Posted { room: "general".into(), cursor: 1, author: "bob".into(), html: "<p>plan</p>".into(), mentions: Vec::new() }, T0, 0);
    let react = |cursor, author: &str, reaction, on| Push::Reacted { room: "general".into(), cursor, target: 1, author: author.into(), reaction, on };
    assert_eq!(inbox.on_push(react(2, "bob", 1, true), T0, 0).unwrap().0, Apply::Applied);
    inbox.on_push(react(3, "cy", 1, true), T0, 0);
    inbox.on_push(react(4, "cy", 2, true), T0, 0);
    inbox.on_push(react(5, "cy", 2, false), T0, 0);
    // The same event twice is applied once.
    assert_eq!(inbox.on_push(react(3, "cy", 1, false), T0, 0).unwrap().0, Apply::Duplicate);
    let view = inbox.view("general").unwrap();
    assert_eq!(view.cursor(), 5, "each reaction advances the cursor");
    assert_eq!(view.reactions().get(&1).cloned().unwrap().into_iter().collect::<Vec<_>>(), vec![(1, people(&["bob", "cy"]))]);
}
