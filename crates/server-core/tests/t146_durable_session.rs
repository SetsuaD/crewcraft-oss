#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_proto::frame::encode;
use crewcraft_proto::handshake::{Hello, Reply, ServerSide, encode_hello, encode_reply};
use crewcraft_proto::message::CodecError;
use crewcraft_proto::push::{Push, encode_push};
use crewcraft_proto::request::{Request, Response, encode_request, encode_response};
use crewcraft_server_core::connection::ConnError;
use crewcraft_server_core::durable::{DurableError, DurableServer};
use crewcraft_server_core::journal::JournalError;
use crewcraft_server_core::op::MAX_STR;
use crewcraft_server_core::room::Role;
use crewcraft_server_core::session::{DurableSessionError, Phase, Session, SessionError};

fn journal_path(test: &str) -> PathBuf {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("t146_{test}_{}_{nonce}", std::process::id()))
}

fn server_side() -> ServerSide {
    ServerSide { min_version: 1, max_version: 3, features: 0b1010, name: "crewcraft-server".into() }
}

fn framed_hello(min_version: u16, max_version: u16) -> Vec<u8> {
    let hello = Hello { min_version, max_version, features: 0b1100, client: "test-client".into() };
    encode(&encode_hello(&hello).unwrap()).unwrap()
}

fn framed_welcome() -> Vec<u8> {
    let reply = Reply::Welcome { version: 3, features: 0b1000, server: "crewcraft-server".into() };
    encode(&encode_reply(&reply).unwrap()).unwrap()
}

fn framed_request(id: u32, request: &Request) -> Vec<u8> {
    encode(&encode_request(id, request).unwrap()).unwrap()
}

fn framed_ok(id: u32, cursor: u64) -> Vec<u8> {
    encode(&encode_response(id, &Response::Ok { cursor }).unwrap()).unwrap()
}

#[test]
fn coalesced_post_and_later_edit_replay_after_reconnecting() {
    let path = journal_path("replay");
    let room;
    {
        let mut server = DurableServer::open(&path).unwrap();
        room = server.create_room("alice", "General").unwrap();
        let mut session = Session::new("alice", server_side());
        let mut input = framed_hello(1, 3);
        input.extend(framed_request(10, &Request::Post { room: room.clone(), text: "hello".into() }));

        assert!(session.receive_durable(&mut server, &input[..3], 0).unwrap().is_empty());
        assert_eq!(session.phase(), Phase::Hello);

        let mut expected = framed_welcome();
        expected.extend(framed_ok(10, 1));
        assert_eq!(session.receive_durable(&mut server, &input[3..], 0).unwrap(), expected);
        assert_eq!(session.phase(), Phase::Open { version: 3, features: 0b1000 });

        let edit = framed_request(11, &Request::Edit { room: room.clone(), target: 1, text: "hello again".into() });
        assert_eq!(session.receive_durable(&mut server, &edit, 1).unwrap(), framed_ok(11, 2));
    }

    {
        let mut server = DurableServer::open(&path).unwrap();
        let mut session = Session::new("alice", server_side());
        let mut input = framed_hello(1, 3);
        input.extend(framed_request(12, &Request::Sync { room: room.clone(), cursor: 0 }));

        let pushes = [
            Push::Posted { room: room.clone(), cursor: 1, author: "alice".into(), html: "hello".into(), mentions: vec![] },
            Push::Edited { room, cursor: 2, target: 1, html: "hello again".into(), mentions: vec![] },
        ];
        let mut expected = framed_welcome();
        expected.extend(framed_ok(12, 2));
        for push in pushes {
            expected.extend(encode(&encode_push(&push).unwrap()).unwrap());
        }
        assert_eq!(session.receive_durable(&mut server, &input, 2).unwrap(), expected);
    }

    fs::remove_file(path).unwrap();
}

#[test]
fn refused_hello_ignores_the_coalesced_post() {
    let path = journal_path("refused");
    let room;
    {
        let mut server = DurableServer::open(&path).unwrap();
        room = server.create_room("alice", "General").unwrap();
        let mut session = Session::new("alice", server_side());
        let mut input = framed_hello(4, 5);
        input.extend(framed_request(20, &Request::Post { room: room.clone(), text: "ignore this".into() }));

        let reply = Reply::Refuse { min_version: 1, max_version: 3 };
        let expected = encode(&encode_reply(&reply).unwrap()).unwrap();
        assert_eq!(session.receive_durable(&mut server, &input, 0).unwrap(), expected);
        assert_eq!(session.phase(), Phase::Closed);
        assert_eq!(server.server().room(&room).unwrap().head(), 0);
    }

    {
        let server = DurableServer::open(&path).unwrap();
        assert_eq!(server.server().room(&room).unwrap().head(), 0);
    }

    fs::remove_file(path).unwrap();
}

#[test]
fn poison_closes_waiting_and_open_sessions() {
    let path = journal_path("poison");
    let mut server = DurableServer::open(&path).unwrap();
    let room = server.create_room("alice", "General").unwrap();
    let mut waiting = Session::new("alice", server_side());
    let mut open = Session::new("alice", server_side());
    let hello = framed_hello(1, 3);
    assert_eq!(open.receive_durable(&mut server, &hello, 0).unwrap(), framed_welcome());

    // The membership change succeeds in memory before its identity exceeds the operation codec limit.
    let oversized_member = "x".repeat(MAX_STR + 1);
    assert_eq!(server.add_member(&room, "alice", &oversized_member, Role::Member), Err(DurableError::Journal(JournalError::TooLarge)));

    let sync = framed_request(30, &Request::Sync { room, cursor: 0 });
    for (session, bytes) in [(&mut waiting, hello.as_slice()), (&mut open, sync.as_slice())] {
        let result = session.receive_durable(&mut server, bytes, 1);
        assert!(matches!(result, Err(DurableSessionError::Storage(DurableError::Poisoned))));
        assert_eq!(session.phase(), Phase::Closed);

        let result = session.receive_durable(&mut server, bytes, 2);
        assert!(matches!(result, Err(DurableSessionError::Protocol(SessionError::Closed))));
    }

    drop(server);
    fs::remove_file(path).unwrap();
}

#[test]
fn protocol_error_in_a_coalesced_request_closes_without_a_welcome() {
    let path = journal_path("protocol");
    let mut server = DurableServer::open(&path).unwrap();
    let mut session = Session::new("alice", server_side());
    let mut input = framed_hello(1, 3);
    input.extend(encode(&[99, 0, 0, 0, 40]).unwrap());

    let result = session.receive_durable(&mut server, &input, 0);
    let expected = SessionError::Conn(ConnError::Request(CodecError::BadKind(99)));
    assert!(matches!(result, Err(DurableSessionError::Protocol(error)) if error == expected));
    assert_eq!(session.phase(), Phase::Closed);

    drop(server);
    fs::remove_file(path).unwrap();
}
