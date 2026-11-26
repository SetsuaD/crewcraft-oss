//! T360a1: calls on the chat server (docs/CALLS.md "Call records and liveness"): one open call per room, joined by
//! starting again; history lines with the duration and the people; liveness (a person with no heartbeat for 75 seconds
//! leaves at their last heartbeat, and an empty call ends then); removed means removed; missed calls; it all survives a
//! restart; the pushes reach a client that agreed to calls; and the client keeps the room's open call.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use crewcraft_client_core::inbox::Inbox;
use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::timeline::Apply;
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_proto::push::{Push, decode_push, encode_push};
use crewcraft_proto::request::{FEATURE_CALLS, Request, Response, decode_request, decode_response, encode_request};
use crewcraft_server_core::calls::{CallError, HEARTBEAT_TIMEOUT_MS, MissedCall, duration_text};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::cursor_log::Since;
use crewcraft_server_core::dispatch::E_NO_SUCH_CALL;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::import::{Bundle, BundleRoom, RoomKind};
use crewcraft_server_core::room::Role;
use crewcraft_server_core::room_service::EventKind;

const T0: u64 = 1_800_000_000_000;
const ANA: &str = "ana@example.org";
const BO: &str = "bo@example.org";
const CY: &str = "cy@example.org";

fn journal(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("t360a1-{name}-{}", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

/// The room's call history lines as `(author, text)`.
fn lines(ds: &DurableServer, slug: &str) -> Vec<(String, String)> {
    let Since::Events(events) = ds.server().room(slug).unwrap().sync(ANA, 0).unwrap() else { panic!("gap") };
    events.into_iter().filter(|(_, e)| matches!(e.kind, EventKind::CallLine { .. })).map(|(_, e)| (e.actor, e.html)).collect()
}

#[test]
fn the_requests_and_pushes_have_exact_bytes() {
    let start = Request::CallStart { room: "r".into(), video: true };
    assert_eq!(encode_request(1, &start).unwrap(), vec![18, 0, 0, 0, 1, 0, 1, b'r', 1]);
    for (request, tag) in [
        (Request::CallJoin { room: "r".into(), call: 7 }, 19u8),
        (Request::CallHeartbeat { room: "r".into(), call: 7 }, 20),
        (Request::CallLeave { room: "r".into(), call: 7 }, 21),
    ] {
        let bytes = encode_request(2, &request).unwrap();
        let mut expected = vec![tag, 0, 0, 0, 2, 0, 1, b'r'];
        expected.extend_from_slice(&7u64.to_be_bytes());
        assert_eq!(bytes, expected);
        assert_eq!(decode_request(&bytes).unwrap(), (2, request));
    }
    assert_eq!(decode_request(&encode_request(1, &start).unwrap()).unwrap(), (1, start));

    let line = Push::CallLine { room: "r".into(), cursor: 3, call: 7, ended: true, author: "a".into(), text: "call ended".into() };
    let state = Push::CallState { room: "r".into(), cursor: 0, call: 7, video: false, started_by: "a".into(), started_ms: T0, participants: vec!["a".into(), "b".into()] };
    for push in [line, state] {
        let bytes = encode_push(&push).unwrap();
        assert_eq!(decode_push(&bytes).unwrap(), push);
        for cut in 1..bytes.len() {
            assert!(decode_push(&bytes[..cut]).is_err(), "cut at {cut}");
        }
    }
}

#[test]
fn one_open_call_per_room_with_its_history() {
    let p = journal("life");
    let mut ds = DurableServer::open(&p).unwrap();
    let room = ds.create_room(ANA, "Project").unwrap();
    ds.add_member(&room, ANA, BO, Role::Member).unwrap();
    let call = ds.call_start(&room, ANA, true, T0).unwrap();
    assert_eq!(ds.call_start(&room, BO, false, T0 + 1_000).unwrap(), call, "starting again joins the open call");
    let open = ds.open_call(&room).unwrap();
    assert_eq!((open.video, open.started_by.as_str(), open.present.len()), (true, ANA, 2));
    ds.call_heartbeat(&room, BO, call, T0 + 20_000).unwrap();
    ds.call_leave(&room, BO, call, T0 + 60_000).unwrap();
    assert!(ds.open_call(&room).is_some(), "Ana is still in it");
    ds.call_leave(&room, ANA, call, T0 + 125_000).unwrap();
    assert!(ds.open_call(&room).is_none());
    assert_eq!(ds.call(call).unwrap().ended_ms, Some(T0 + 125_000));
    let history = vec![(ANA.to_owned(), "started a call".to_owned()), (ANA.to_owned(), format!("call ended after 2 min: {ANA}, {BO}"))];
    assert_eq!(lines(&ds, &room), history);
    assert_eq!(ds.call_leave(&room, ANA, call, T0 + 130_000), Err(CallError::NoSuchCall), "it ended");
    assert_eq!(ds.server().room(&room).unwrap().unread(BO), Ok(0), "history lines are not unread messages");
    drop(ds);

    let mut ds = DurableServer::open(&p).unwrap();
    assert_eq!(lines(&ds, &room), history, "replayed");
    assert!(ds.open_call(&room).is_none());
    assert_ne!(ds.call_start(&room, BO, false, T0 * 2).unwrap(), call, "the next one is a new call");
    fs::remove_file(&p).unwrap();
}

#[test]
fn people_without_a_heartbeat_leave_at_their_last_one() {
    let p = journal("live");
    let mut ds = DurableServer::open(&p).unwrap();
    let room = ds.create_room(ANA, "Project").unwrap();
    ds.add_member(&room, ANA, BO, Role::Member).unwrap();
    let call = ds.call_start(&room, ANA, false, T0).unwrap();
    ds.call_join(&room, BO, call, T0 + 10_000).unwrap();
    for second in [20, 40] {
        ds.call_heartbeat(&room, ANA, call, T0 + second * 1_000).unwrap();
    }
    ds.sweep_calls(T0 + 100_000).unwrap();
    let present: Vec<&str> = ds.open_call(&room).unwrap().present.keys().map(String::as_str).collect();
    assert_eq!(present, vec![ANA], "Bo's last heartbeat was 90 seconds ago");
    assert_eq!(ds.call_heartbeat(&room, BO, call, T0 + 100_000), Err(CallError::NoSuchCall), "so Bo's client leaves");
    ds.sweep_calls(T0 + 40_000 + HEARTBEAT_TIMEOUT_MS + 1).unwrap();
    assert_eq!(ds.call(call).unwrap().ended_ms, Some(T0 + 40_000), "closed at its last heartbeat");
    assert_eq!(lines(&ds, &room)[1].1, format!("call ended after under a minute: {ANA}, {BO}"));
    drop(ds);
    // The leaves and the end were recorded as they happened.
    let ds = DurableServer::open(&p).unwrap();
    assert_eq!(ds.call(call).unwrap().ended_ms, Some(T0 + 40_000));
    assert_eq!((duration_text(59_999), duration_text(60_000), duration_text(3_900_000)), ("under a minute".into(), "1 min".into(), "1 h 5 min".into()));
    fs::remove_file(&p).unwrap();
}

#[test]
fn who_may_start_join_and_stay() {
    let p = journal("rules");
    let mut ds = DurableServer::open(&p).unwrap();
    let room = ds.create_room(ANA, "Project").unwrap();
    ds.add_member(&room, ANA, BO, Role::Member).unwrap();
    ds.add_member(&room, ANA, "gus@example.org", Role::Guest).unwrap();
    assert_eq!(ds.call_start(&room, CY, false, T0), Err(CallError::NotMember));
    assert_eq!(ds.call_start(&room, "gus@example.org", false, T0), Err(CallError::NotAllowed), "a Guest starts none");
    let call = ds.call_start(&room, ANA, false, T0).unwrap();
    ds.call_join(&room, "gus@example.org", call, T0 + 1).unwrap();
    assert_eq!(ds.call_join(&room, BO, call + 99, T0 + 2), Err(CallError::NoSuchCall));
    ds.call_join(&room, BO, call, T0 + 3).unwrap();

    // Removed means removed: out of the call at once, and refused after.
    ds.remove_member(&room, ANA, BO).unwrap();
    assert!(!ds.open_call(&room).unwrap().present.contains_key(BO));
    assert_eq!(ds.call_heartbeat(&room, BO, call, T0 + 4), Err(CallError::NotMember));

    // An archive room has no calls.
    let bundle = Bundle {
        source: "test".into(),
        rooms: vec![BundleRoom { key: "a".into(), kind: RoomKind::Group, name: "Old".into(), members: vec![ANA.into()] }],
        messages: Vec::new(),
    };
    ds.import(&bundle, &|_| true, false).unwrap();
    let archive = ds.archive_room("test", "a").unwrap().to_owned();
    assert_eq!(ds.call_start(&archive, ANA, false, T0), Err(CallError::NotAllowed));
    fs::remove_file(&p).unwrap();
}

#[test]
fn missed_calls_follow_the_rules() {
    let p = journal("missed");
    let mut ds = DurableServer::open(&p).unwrap();
    let room = ds.create_room(ANA, "Project").unwrap();
    ds.add_member(&room, ANA, BO, Role::Member).unwrap();
    ds.add_member(&room, ANA, CY, Role::Member).unwrap();
    let call = ds.call_start(&room, ANA, false, T0).unwrap();
    ds.call_join(&room, BO, call, T0 + 1_000).unwrap();
    ds.add_member(&room, ANA, "dee@example.org", Role::Member).unwrap();
    assert!(ds.missed_calls(CY).is_empty(), "an open call is not missed yet");
    ds.call_leave(&room, BO, call, T0 + 2_000).unwrap();
    ds.call_leave(&room, ANA, call, T0 + 3_000).unwrap();
    assert_eq!(ds.missed_calls(CY), vec![MissedCall { room: room.clone(), call, started_by: ANA.into(), ended_ms: T0 + 3_000 }]);
    assert!(ds.missed_calls(ANA).is_empty(), "the one who started it");
    assert!(ds.missed_calls(BO).is_empty(), "joined it");
    assert!(ds.missed_calls("dee@example.org").is_empty(), "joined the room after it started");
    ds.remove_member(&room, ANA, CY).unwrap();
    assert!(ds.missed_calls(CY).is_empty(), "only rooms I am still in");
    fs::remove_file(&p).unwrap();
}

fn pushes(out: &[u8]) -> (Response, Vec<Push>) {
    let mut decoder = Decoder::new();
    decoder.push(out);
    let mut frames = Vec::new();
    while let Some(frame) = decoder.next_frame().unwrap() {
        frames.push(frame);
    }
    let (_, response) = decode_response(&frames[0]).unwrap();
    (response, frames[1..].iter().map(|frame| decode_push(frame).unwrap()).collect())
}

#[test]
fn the_wire_and_the_client() {
    let p = journal("wire");
    let mut ds = DurableServer::open(&p).unwrap();
    let room = ds.create_room(ANA, "Project").unwrap();
    let request = |id, request: Request| encode(&encode_request(id, &request).unwrap()).unwrap();
    let mut ana = Connection::with_features(ANA, FEATURE_CALLS);
    let (response, _) = pushes(&ana.receive_durable(&mut ds, &request(1, Request::CallStart { room: room.clone(), video: false }), T0).unwrap());
    let Response::Ok { cursor: call } = response else { panic!("{response:?}") };

    let sync = request(2, Request::Sync { room: room.clone(), cursor: 0 });
    let (_, with) = pushes(&ana.receive_durable(&mut ds, &sync, T0 + 1).unwrap());
    assert!(matches!(&with[0], Push::CallState { call: c, participants, .. } if *c == call && participants == &vec![ANA.to_owned()]), "{with:?}");
    assert!(with.iter().any(|push| matches!(push, Push::CallLine { ended: false, text, .. } if text == "started a call")));
    let (_, without) = pushes(&Connection::new(ANA).receive_durable(&mut ds, &sync, T0 + 1).unwrap());
    assert!(without.iter().all(|push| !matches!(push, Push::CallState { .. } | Push::CallLine { .. })), "an older client");

    let bad = request(3, Request::CallHeartbeat { room: room.clone(), call: call + 5 });
    let (response, _) = pushes(&ana.receive_durable(&mut ds, &bad, T0 + 2).unwrap());
    assert_eq!(response, Response::Error { code: E_NO_SUCH_CALL, detail: String::new() });

    // The client keeps the open call, and its end closes it.
    let mut inbox = Inbox::new(ANA, Settings::new(ANA));
    inbox.follow(&room, false);
    for push in with {
        inbox.on_push(push, T0, 0);
    }
    assert_eq!(inbox.view(&room).unwrap().call().map(|open| open.call), Some(call));
    let ended = Push::CallLine { room: room.clone(), cursor: 2, call, ended: true, author: ANA.into(), text: "call ended".into() };
    assert_eq!(inbox.on_push(ended, T0, 0).unwrap().0, Apply::Applied);
    let view = inbox.view(&room).unwrap();
    assert!(view.call().is_none());
    assert_eq!(view.call_lines().len(), 2);
    fs::remove_file(&p).unwrap();
}
