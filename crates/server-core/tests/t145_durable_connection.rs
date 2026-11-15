#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use crewcraft_proto::frame::encode;
use crewcraft_proto::message::CodecError;
use crewcraft_proto::push::{Push, encode_push};
use crewcraft_proto::request::{Request, Response, encode_request, encode_response};
use crewcraft_server_core::connection::{ConnError, Connection, DurableConnError};
use crewcraft_server_core::dispatch::E_NO_SUCH_ROOM;
use crewcraft_server_core::durable::{DurableError, DurableServer};
use crewcraft_server_core::journal::JournalError;
use crewcraft_server_core::op::MAX_STR;
use crewcraft_server_core::room::Role;

fn journal_path(test: &str) -> PathBuf {
    std::env::temp_dir().join(format!("t145_{test}_{}", std::process::id()))
}

fn framed_request(id: u32, request: &Request) -> Vec<u8> {
    encode(&encode_request(id, request).unwrap()).unwrap()
}

fn framed_response(id: u32, response: &Response) -> Vec<u8> {
    encode(&encode_response(id, response).unwrap()).unwrap()
}

#[test]
fn acknowledged_changes_replay_and_sync_in_order() {
    let path = journal_path("replay");
    let room;
    {
        let mut server = DurableServer::open(&path).unwrap();
        room = server.create_room("alice", "General").unwrap();
        server.add_member(&room, "alice", "bob", Role::Member).unwrap();
        let mut alice = Connection::new("alice");

        let steps = [
            (4, Request::Post { room: room.clone(), text: "hello".into() }, 2),
            (5, Request::Edit { room: room.clone(), target: 2, text: "hello again".into() }, 3),
            (6, Request::Post { room: room.clone(), text: "temporary".into() }, 4),
            (7, Request::Delete { room: room.clone(), target: 4 }, 5),
        ];
        for (id, request, cursor) in steps {
            let output = alice.receive_durable(&mut server, &framed_request(id, &request), 0).unwrap();
            assert_eq!(output, framed_response(id, &Response::Ok { cursor }));
        }

        assert_eq!(server.server().room(&room).unwrap().unread("bob").unwrap(), 1);
        let read = Request::MarkRead { room: room.clone(), cursor: 5 };
        let mut bob = Connection::new("bob");
        let output = bob.receive_durable(&mut server, &framed_request(8, &read), 0).unwrap();
        assert_eq!(output, framed_response(8, &Response::Ok { cursor: 5 }));
    }

    {
        let mut server = DurableServer::open(&path).unwrap();
        assert_eq!(server.server().room(&room).unwrap().unread("bob").unwrap(), 0);

        let sync = Request::Sync { room: room.clone(), cursor: 1 };
        let mut bob = Connection::new("bob");
        let output = bob.receive_durable(&mut server, &framed_request(9, &sync), 1).unwrap();

        let pushes = [
            Push::Posted { room: room.clone(), cursor: 2, author: "alice".into(), html: "hello".into(), mentions: vec![] },
            Push::Edited { room: room.clone(), cursor: 3, target: 2, html: "hello again".into(), mentions: vec![] },
            Push::Other { room: room.clone(), cursor: 4 },
            Push::Deleted { room, cursor: 5, target: 4 },
        ];
        let mut expected = framed_response(9, &Response::Ok { cursor: 5 });
        for push in pushes {
            expected.extend(encode(&encode_push(&push).unwrap()).unwrap());
        }
        assert_eq!(output, expected);
    }

    fs::remove_file(path).unwrap();
}

#[test]
fn sync_refuses_nonmembers_like_missing_rooms() {
    let path = journal_path("membership");
    let mut server = DurableServer::open(&path).unwrap();
    let room = server.create_room("alice", "General").unwrap();
    server.post(&room, "alice", "members only", 0).unwrap();
    let mut eve = Connection::new("eve");
    let expected = framed_response(10, &Response::Error { code: E_NO_SUCH_ROOM, detail: String::new() });

    for room in [room, "missing".into()] {
        let sync = Request::Sync { room, cursor: 0 };
        let output = eve.receive_durable(&mut server, &framed_request(10, &sync), 0).unwrap();
        assert_eq!(output, expected);
    }

    drop(server);
    fs::remove_file(path).unwrap();
}

#[test]
fn poisoned_storage_refuses_requests_on_every_connection() {
    let path = journal_path("poison");
    let mut server = DurableServer::open(&path).unwrap();
    let room = server.create_room("alice", "General").unwrap();
    server.post(&room, "alice", "committed", 0).unwrap();
    let mut alice = Connection::new("alice");
    let ping = framed_request(11, &Request::Ping);
    assert_eq!(alice.receive_durable(&mut server, &ping, 0).unwrap(), framed_response(11, &Response::Ok { cursor: 0 }));

    // The room accepts the member, but the operation codec cannot store this identity.
    let oversized_member = "x".repeat(MAX_STR + 1);
    assert_eq!(server.add_member(&room, "alice", &oversized_member, Role::Member), Err(DurableError::Journal(JournalError::TooLarge)));

    let sync = framed_request(12, &Request::Sync { room, cursor: 0 });
    assert!(matches!(alice.receive_durable(&mut server, &sync, 0), Err(DurableConnError::Storage(DurableError::Poisoned))));

    let mut second = Connection::new("alice");
    assert!(matches!(second.receive_durable(&mut server, &ping, 0), Err(DurableConnError::Storage(DurableError::Poisoned))));

    drop(server);
    fs::remove_file(path).unwrap();
}

#[test]
fn durable_connection_preserves_fatal_protocol_errors() {
    let path = journal_path("protocol");
    let mut server = DurableServer::open(&path).unwrap();
    let mut connection = Connection::new("alice");
    let mut input = framed_request(13, &Request::Ping);
    input.extend(encode(&[99, 0, 0, 0, 14]).unwrap());

    assert!(matches!(
        connection.receive_durable(&mut server, &input, 0),
        Err(DurableConnError::Protocol(ConnError::Request(CodecError::BadKind(99))))
    ));

    drop(server);
    fs::remove_file(path).unwrap();
}
