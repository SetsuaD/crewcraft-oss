//! T360b2: the chat server admits people to a call's media (docs/CALLS.md "Admission: removed means removed"). A member
//! who starts or joins a call gets a media credential for their device right after the answer, and the media server
//! (its core, in process) accepts it; nobody outside the call gets one; leaving, removal, revocation, a stopped
//! heartbeat and the end of the call each become an event that drops them from the media server at once.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use crewcraft_media::{Config, MediaServer};
use crewcraft_media_auth::{Issuer, Verifier};
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_proto::request::{FEATURE_CALLS, FEATURE_MEDIA, MEDIA_TAG, Request, Response, decode_media, decode_response, encode_media, encode_request};
use crewcraft_server_core::calls::{CallError, HEARTBEAT_TIMEOUT_MS};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::media::{MediaEvent, MediaIssuer};
use crewcraft_server_core::room::Role;
use str0m::media::{Direction, MediaKind};
use str0m::{Candidate, Rtc};

const T0: u64 = 1_800_000_000_000;
const ANA: &str = "ana@example.org";
const BO: &str = "bo@example.org";
const CY: &str = "cy@example.org";
const DAN: &str = "dan@example.org";
const MEDIA: &str = "media.example.org";
const MEDIA_ADDRESS: &str = "203.0.113.10:3478";

fn journal(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("t360b2-{name}-{}", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

/// A chat server with a room (Ana owns it; Bo and Dan are members, Cy is not) and the media key it signs with.
fn chat(name: &str) -> (DurableServer, String, [u8; 32]) {
    let mut ds = DurableServer::open(&journal(name)).unwrap();
    let room = ds.create_room(ANA, "Project").unwrap();
    ds.add_member(&room, ANA, BO, Role::Member).unwrap();
    ds.add_member(&room, ANA, DAN, Role::Member).unwrap();
    let issuer = Issuer::from_pkcs8(&Issuer::generate().unwrap()).unwrap();
    let key = issuer.public_key();
    ds.set_media(MediaIssuer::new(issuer, MEDIA, MEDIA_ADDRESS));
    (ds, room, key)
}

/// A connection for `user` on `device`, agreeing to calls and media.
fn connection(user: &str, device: u64) -> Connection {
    Connection::with_features(user, FEATURE_CALLS | FEATURE_MEDIA).with_device(Some(device))
}

/// Send `request` and return the answer and the media frame after it, if any.
fn ask(conn: &mut Connection, ds: &mut DurableServer, request: Request, now_ms: u64) -> (Response, Option<(String, Vec<u8>)>) {
    let bytes = encode(&encode_request(1, &request).unwrap()).unwrap();
    let out = conn.receive_durable(ds, &bytes, now_ms).unwrap();
    let mut decoder = Decoder::new();
    decoder.push(&out);
    let (id, response) = decode_response(&decoder.next_frame().unwrap().unwrap()).unwrap();
    assert_eq!(id, 1);
    let mut media = None;
    while let Some(frame) = decoder.next_frame().unwrap() {
        if frame.first() == Some(&MEDIA_TAG) {
            let (id, address, credential) = decode_media(&frame).unwrap();
            assert_eq!(id, 1);
            media = Some((address, credential));
        }
    }
    (response, media)
}

/// The media server's core, trusting the chat server's key.
fn media_server(key: [u8; 32]) -> MediaServer {
    let address: SocketAddr = MEDIA_ADDRESS.parse().unwrap();
    MediaServer::new(Config { server_name: MEDIA.to_owned(), trusted_key: key, address })
}

/// A WebRTC offer from a client: one audio section it sends, one it receives.
fn offer() -> String {
    let mut rtc = Rtc::builder().set_crypto_provider(Arc::new(crewcraft_media_crypto::provider())).build(Instant::now());
    rtc.add_local_candidate(Candidate::host("198.51.100.1:5000".parse().unwrap(), "udp").unwrap());
    let mut change = rtc.sdp_api();
    change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
    change.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
    change.apply().unwrap().0.to_sdp_string()
}

/// What the control connection does with the chat server's events.
fn apply(media: &mut MediaServer, events: Vec<MediaEvent>) {
    for event in events {
        match event {
            MediaEvent::DropPerson { call, person } => {
                media.drop_person(call, &person);
            }
            MediaEvent::EndCall { call } => {
                media.end_call(call);
            }
        }
    }
}

/// Ana starts a call and Bo joins it; both are admitted to the media server with the credentials they got.
fn in_a_call(ds: &mut DurableServer, room: &str, media: &mut MediaServer) -> u64 {
    let (started, ana) = ask(&mut connection(ANA, 1), ds, Request::CallStart { room: room.to_owned(), video: false }, T0);
    let Response::Ok { cursor: call } = started else { panic!("{started:?}") };
    let (joined, bo) = ask(&mut connection(BO, 2), ds, Request::CallJoin { room: room.to_owned(), call }, T0);
    assert_eq!(joined, Response::Ok { cursor: call });
    for (_, credential) in [ana.unwrap(), bo.unwrap()] {
        media.join(call, &credential, &offer(), Instant::now(), T0 + 1_000).unwrap();
    }
    assert_eq!(media.participants(call).len(), 2);
    ds.take_media_events();
    call
}

#[test]
fn the_wire() {
    let frame = encode_media(9, MEDIA_ADDRESS, &[7; 100]).unwrap();
    assert_eq!(frame[0], MEDIA_TAG);
    assert_eq!(decode_media(&frame).unwrap(), (9, MEDIA_ADDRESS.to_owned(), vec![7; 100]));
    for cut in 1..frame.len() {
        assert!(decode_media(&frame[..cut]).is_err(), "cut at {cut}");
    }
    assert!(encode_media(9, MEDIA_ADDRESS, &[]).is_err());
    assert!(encode_media(9, "", &[1]).is_err());
    assert!(encode_media(9, MEDIA_ADDRESS, &[1; crewcraft_proto::request::MAX_CREDENTIAL + 1]).is_err());
}

#[test]
fn a_member_who_joins_gets_a_credential_the_media_server_accepts() {
    let (mut ds, room, key) = chat("accepts");
    let (started, media) = ask(&mut connection(ANA, 1), &mut ds, Request::CallStart { room: room.clone(), video: false }, T0);
    let Response::Ok { cursor: call } = started else { panic!("{started:?}") };
    let (address, credential) = media.expect("a media frame follows the answer");
    assert_eq!(address, MEDIA_ADDRESS);

    // It is for this call, this person and this device, on this media server, signed by the chat server's key.
    let grant = Verifier::new(key, MEDIA).verify(&credential, T0 + 1_000).unwrap();
    assert_eq!((grant.call, grant.room.as_str(), grant.person.as_str(), grant.device), (call, room.as_str(), ANA, 1));

    let (joined, bo) = ask(&mut connection(BO, 2), &mut ds, Request::CallJoin { room: room.clone(), call }, T0 + 500);
    assert_eq!(joined, Response::Ok { cursor: call });
    let (_, bo) = bo.expect("joining is admission too");

    // The media server admits both, each once.
    let mut server = media_server(key);
    server.join(call, &credential, &offer(), Instant::now(), T0 + 1_000).unwrap();
    server.join(call, &bo, &offer(), Instant::now(), T0 + 1_000).unwrap();
    assert_eq!(server.participants(call).len(), 2);

    // Joining again (a reconnect) is a new credential; a client that did not agree to media gets none.
    let (_, again) = ask(&mut connection(BO, 2), &mut ds, Request::CallJoin { room: room.clone(), call }, T0 + 2_000);
    assert!(again.is_some_and(|(_, again)| again != bo));
    let (answer, none) = ask(&mut Connection::with_features(BO, FEATURE_CALLS).with_device(Some(2)), &mut ds, Request::CallJoin { room, call }, T0 + 3_000);
    assert_eq!(answer, Response::Ok { cursor: call });
    assert!(none.is_none());
}

#[test]
fn nobody_outside_the_call_gets_a_credential() {
    let (mut ds, room, _) = chat("outside");
    let (started, _) = ask(&mut connection(ANA, 1), &mut ds, Request::CallStart { room: room.clone(), video: false }, T0);
    let Response::Ok { cursor: call } = started else { panic!("{started:?}") };

    // Cy is not a member: refused, and no media frame.
    let (refused, media) = ask(&mut connection(CY, 3), &mut ds, Request::CallJoin { room: room.clone(), call }, T0);
    assert!(matches!(refused, Response::Error { .. }), "{refused:?}");
    assert!(media.is_none());
    assert_eq!(ds.media_credential(&room, CY, call, 3, T0), Err(CallError::NotMember));
    // Dan is a member but not in the call; nobody gets one for a call that is not open.
    assert_eq!(ds.media_credential(&room, DAN, call, 4, T0), Err(CallError::NoSuchCall));
    assert_eq!(ds.media_credential(&room, ANA, call + 1, 1, T0), Err(CallError::NoSuchCall));
    // A connection whose device is unknown gets none either.
    let (joined, media) = ask(&mut Connection::with_features(DAN, FEATURE_CALLS | FEATURE_MEDIA), &mut ds, Request::CallJoin { room: room.clone(), call }, T0);
    assert_eq!(joined, Response::Ok { cursor: call });
    assert!(media.is_none());

    // A chat server with no media server issues none, and keeps no events.
    let mut plain = DurableServer::open(&journal("plain")).unwrap();
    let room = plain.create_room(ANA, "Plain").unwrap();
    let (started, media) = ask(&mut connection(ANA, 1), &mut plain, Request::CallStart { room: room.clone(), video: false }, T0);
    let Response::Ok { cursor: call } = started else { panic!("{started:?}") };
    assert!(media.is_none());
    assert_eq!(plain.media_credential(&room, ANA, call, 1, T0), Ok(None));
    plain.call_leave(&room, ANA, call, T0 + 1).unwrap();
    assert!(plain.take_media_events().is_empty());
}

#[test]
fn a_removed_or_revoked_member_is_dropped_from_media_at_once() {
    let (mut ds, room, key) = chat("removed");
    let mut media = media_server(key);
    let call = in_a_call(&mut ds, &room, &mut media);

    // Removing Bo from the room takes him out of the call and its media now, not at a heartbeat timeout.
    ds.remove_member(&room, ANA, BO).unwrap();
    let events = ds.take_media_events();
    assert_eq!(events, vec![MediaEvent::DropPerson { call, person: BO.to_owned() }]);
    apply(&mut media, events);
    assert_eq!(media.participants(call).len(), 1, "Bo is out of the media");

    // Ana loses her access (revoked): out of every call, and the call, now empty, ends.
    assert_eq!(ds.drop_from_calls(ANA, T0 + 5_000).unwrap(), 1);
    let events = ds.take_media_events();
    assert_eq!(events, vec![MediaEvent::DropPerson { call, person: ANA.to_owned() }, MediaEvent::EndCall { call }]);
    apply(&mut media, events);
    assert!(media.participants(call).is_empty());
}

#[test]
fn the_end_of_a_call_closes_everyone() {
    // Leaving: the last to leave ends it.
    let (mut ds, room, key) = chat("ends");
    let mut media = media_server(key);
    let call = in_a_call(&mut ds, &room, &mut media);
    ds.call_leave(&room, BO, call, T0 + 10).unwrap();
    assert_eq!(ds.take_media_events(), vec![MediaEvent::DropPerson { call, person: BO.to_owned() }]);
    ds.call_leave(&room, ANA, call, T0 + 20).unwrap();
    let events = ds.take_media_events();
    assert_eq!(events.last(), Some(&MediaEvent::EndCall { call }));
    apply(&mut media, events);
    assert!(media.participants(call).is_empty());

    // Heartbeats stopping: everyone is swept out and the call ends.
    let (mut ds, room, key) = chat("heartbeats");
    let mut media = media_server(key);
    let call = in_a_call(&mut ds, &room, &mut media);
    ds.sweep_calls(T0 + HEARTBEAT_TIMEOUT_MS + 1).unwrap();
    let events = ds.take_media_events();
    assert!(events.contains(&MediaEvent::DropPerson { call, person: ANA.to_owned() }));
    assert!(events.contains(&MediaEvent::DropPerson { call, person: BO.to_owned() }));
    assert_eq!(events.last(), Some(&MediaEvent::EndCall { call }));
    apply(&mut media, events);
    assert!(media.participants(call).is_empty(), "the media server closed everyone");
    assert!(ds.open_call(&room).is_none());
}
