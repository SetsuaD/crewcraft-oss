//! T360d2: call keys through the chat server (docs/CALLS.md end-to-end encryption): participants publish their call
//! public keys, senders leave their key sealed to each other participant, and on Sync each person gets everyone's call
//! keys and only the boxes sealed to them; only people in the call may take part, rotations stay bounded, and leaving
//! or the call ending forgets their keys. The server relays boxes it cannot open: the test opens them with the real
//! seal and checks an SFrame frame end to end.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use crewcraft_client_core::inbox::Inbox;
use crewcraft_client_core::notify::Settings;
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_proto::push::{Push, decode_push, encode_push};
use crewcraft_proto::request::{FEATURE_CALLS, MAX_SEALED, Request, decode_request, encode_request};
use crewcraft_server_core::calls::{CallError, MAX_KIDS_PER_PAIR, SealedKey};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::room::Role;
use crewcraft_sframe::seal::{CallKeyPair, open, seal};
use crewcraft_sframe::{CipherSuite, Key, decrypt};

const T0: u64 = 1_800_000_000_000;
const ANA: &str = "ana@example.org";
const BO: &str = "bo@example.org";
const CY: &str = "cy@example.org";

fn journal(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("t360d2-{name}-{}", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

#[test]
fn the_wire() {
    let key = Request::CallKey { room: "r".into(), call: 7, public: [9; 32] };
    let seal = Request::CallSeal { room: "r".into(), call: 7, to: "b".into(), kid: 3, sealed: vec![1, 2, 3] };
    for request in [key, seal] {
        let bytes = encode_request(1, &request).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), (1, request));
        for cut in 1..bytes.len() {
            assert!(decode_request(&bytes[..cut]).is_err(), "cut at {cut}");
        }
    }
    assert!(encode_request(1, &Request::CallSeal { room: "r".into(), call: 7, to: "b".into(), kid: 3, sealed: vec![0; MAX_SEALED + 1] }).is_err());
    assert!(encode_request(1, &Request::CallSeal { room: "r".into(), call: 7, to: "b".into(), kid: 3, sealed: Vec::new() }).is_err());

    let keys = Push::CallKeys { room: "r".into(), cursor: 0, call: 7, keys: vec![("a".into(), [1; 32]), ("b".into(), [2; 32])] };
    let sealed = Push::CallSealed { room: "r".into(), cursor: 0, call: 7, from: "a".into(), kid: 3, sealed: vec![5; 40] };
    for push in [keys, sealed] {
        let bytes = encode_push(&push).unwrap();
        assert_eq!(decode_push(&bytes).unwrap(), push);
        for cut in 1..bytes.len() {
            assert!(decode_push(&bytes[..cut]).is_err(), "cut at {cut}");
        }
    }
}

#[test]
fn only_people_in_the_call_take_part_and_leaving_forgets() {
    let p = journal("rules");
    let mut ds = DurableServer::open(&p).unwrap();
    let room = ds.create_room(ANA, "Project").unwrap();
    ds.add_member(&room, ANA, BO, Role::Member).unwrap();
    ds.add_member(&room, ANA, CY, Role::Member).unwrap();
    let call = ds.call_start(&room, ANA, false, T0).unwrap();
    ds.call_join(&room, BO, call, T0).unwrap();
    assert_eq!(ds.call_key(&room, CY, call, [3; 32], T0), Err(CallError::NoSuchCall), "Cy is not in the call");
    ds.call_key(&room, ANA, call, [1; 32], T0).unwrap();
    ds.call_key(&room, BO, call, [2; 32], T0).unwrap();
    assert_eq!(
        ds.call_seal(&room, ANA, call, SealedKey { to: CY, kid: 1, sealed: vec![1] }, T0),
        Err(CallError::NoSuchCall),
        "not to someone outside it"
    );
    assert_eq!(ds.call_seal(&room, ANA, call, SealedKey { to: ANA, kid: 1, sealed: vec![1] }, T0), Err(CallError::NoSuchCall), "not to oneself");
    for kid in 1..=(MAX_KIDS_PER_PAIR as u64 + 3) {
        ds.call_seal(&room, ANA, call, SealedKey { to: BO, kid, sealed: vec![kid as u8] }, T0).unwrap();
    }
    let kids: Vec<u64> = ds.open_call(&room).unwrap().sealed.keys().map(|(_, _, kid)| *kid).collect();
    assert_eq!(kids, (4..=(MAX_KIDS_PER_PAIR as u64 + 3)).collect::<Vec<_>>(), "the newest {MAX_KIDS_PER_PAIR} rotations are kept");

    ds.call_leave(&room, BO, call, T0 + 1).unwrap();
    let open = ds.open_call(&room).unwrap();
    assert!(!open.keys.contains_key(BO) && open.sealed.is_empty(), "Bo's key and the keys sealed to Bo are gone");
    ds.call_leave(&room, ANA, call, T0 + 2).unwrap();
    assert!(ds.call(call).unwrap().keys.is_empty(), "an ended call keeps no keys");
    fs::remove_file(&p).unwrap();
}

fn sync_pushes(ds: &mut DurableServer, user: &str, room: &str) -> Vec<Push> {
    let sync = encode(&encode_request(1, &Request::Sync { room: room.to_owned(), cursor: 0 }).unwrap()).unwrap();
    let out = Connection::with_features(user, FEATURE_CALLS).receive_durable(ds, &sync, T0 + 5).unwrap();
    let mut decoder = Decoder::new();
    decoder.push(&out);
    let mut frames = Vec::new();
    while let Some(frame) = decoder.next_frame().unwrap() {
        frames.push(frame);
    }
    frames[1..].iter().map(|frame| decode_push(frame).unwrap()).collect()
}

#[test]
fn sealed_keys_reach_only_their_recipient_and_open_end_to_end() {
    let p = journal("e2e");
    let mut ds = DurableServer::open(&p).unwrap();
    let room = ds.create_room(ANA, "Project").unwrap();
    ds.add_member(&room, ANA, BO, Role::Member).unwrap();
    ds.add_member(&room, ANA, CY, Role::Member).unwrap();
    let call = ds.call_start(&room, ANA, false, T0).unwrap();
    for person in [BO, CY] {
        ds.call_join(&room, person, call, T0).unwrap();
    }
    let (ana, bo, cy) = (CallKeyPair::generate().unwrap(), CallKeyPair::generate().unwrap(), CallKeyPair::generate().unwrap());
    for (person, pair) in [(ANA, &ana), (BO, &bo), (CY, &cy)] {
        ds.call_key(&room, person, call, pair.public_key(), T0).unwrap();
    }

    // Ana reads the others' keys from her sync and seals her sender key to each.
    let pushes = sync_pushes(&mut ds, ANA, &room);
    let Some(Push::CallKeys { keys, .. }) = pushes.iter().find(|push| matches!(push, Push::CallKeys { .. })) else { panic!("{pushes:?}") };
    assert_eq!(keys.len(), 3);
    let base_key = b"ana's sender key for this call";
    let context = format!("call {call} kid 1");
    for (person, public) in keys.iter().filter(|(person, _)| person != ANA) {
        let sealed = seal(public, context.as_bytes(), base_key).unwrap();
        ds.call_seal(&room, ANA, call, SealedKey { to: person, kid: 1, sealed }, T0).unwrap();
    }

    // Bo gets only the box sealed to him, through his inbox, and opens it; the server could not.
    let mut inbox = Inbox::new(BO, Settings::new(BO));
    inbox.follow(&room, false);
    for push in sync_pushes(&mut ds, BO, &room) {
        inbox.on_push(push, T0, 0);
    }
    let view = inbox.view(&room).unwrap();
    assert_eq!(view.call_keys(call).unwrap().len(), 3);
    let boxes = view.sealed(call).unwrap();
    assert_eq!(boxes.keys().cloned().collect::<Vec<_>>(), vec![(ANA.to_owned(), 1)], "only Ana's box, only to Bo");
    let opened = open(&bo, context.as_bytes(), &boxes[&(ANA.to_owned(), 1)]).unwrap();
    assert!(open(&cy, context.as_bytes(), &boxes[&(ANA.to_owned(), 1)]).is_err(), "Cy cannot open Bo's box");

    let frame = Key::new(CipherSuite::Aes128GcmSha256, 1, base_key).unwrap().encrypt(0, b"", b"hello from Ana").unwrap();
    let bo_key = Key::new(CipherSuite::Aes128GcmSha256, 1, &opened).unwrap();
    assert_eq!(decrypt(|kid| (kid == 1).then_some(&bo_key), b"", &frame).unwrap(), b"hello from Ana");
    fs::remove_file(&p).unwrap();
}
