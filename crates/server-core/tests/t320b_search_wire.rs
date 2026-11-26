//! T320b: the `Search` request and its hits frame: exact bytes, limits, and the connection's answer over a durable
//! server (each hit's room, cursor, author and the start of its current text, newest first, only the asker's rooms),
//! and nothing from a server without a journal.
#![allow(clippy::unwrap_used)]

use std::fs;

use crewcraft_proto::frame::encode;
use crewcraft_proto::message::CodecError;
use crewcraft_proto::request::{
    HITS_TAG, MAX_HITS, MAX_QUERY, MAX_SNIPPET, Request, Response, SearchHit, decode_hits, decode_request, encode_hits, encode_request,
    encode_response,
};
use crewcraft_server_core::connection::Connection;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::room::Role;
use crewcraft_server_core::server::Server;

fn hit(room: &str, cursor: u64, author: &str, snippet: &str) -> SearchHit {
    SearchHit { room: room.into(), cursor, author: author.into(), snippet: snippet.into() }
}

#[test]
fn the_request_and_the_hits_frame_have_exact_bytes() {
    let bytes = encode_request(7, &Request::Search { query: "kick".into() }).unwrap();
    assert_eq!(bytes, vec![9, 0, 0, 0, 7, 0, 4, b'k', b'i', b'c', b'k']);
    assert_eq!(decode_request(&bytes).unwrap(), (7, Request::Search { query: "kick".into() }));
    assert_eq!(encode_request(1, &Request::Search { query: String::new() }).unwrap_err(), CodecError::FieldLength);
    assert_eq!(encode_request(1, &Request::Search { query: "q".repeat(MAX_QUERY + 1) }).unwrap_err(), CodecError::FieldLength);
    assert!(encode_request(1, &Request::Search { query: "q".repeat(MAX_QUERY) }).is_ok());

    let hits = vec![hit("general", 5, "ana@example.org", "kickoff Monday"), hit("design", 2, "", "")];
    let frame = encode_hits(3, &hits).unwrap();
    let mut expected = vec![HITS_TAG, 0, 0, 0, 3, 0, 2];
    for (room, cursor, author, snippet) in [("general", 5u64, "ana@example.org", "kickoff Monday"), ("design", 2, "", "")] {
        expected.extend_from_slice(&(room.len() as u16).to_be_bytes());
        expected.extend_from_slice(room.as_bytes());
        expected.extend_from_slice(&cursor.to_be_bytes());
        expected.extend_from_slice(&(author.len() as u16).to_be_bytes());
        expected.extend_from_slice(author.as_bytes());
        expected.extend_from_slice(&(snippet.len() as u16).to_be_bytes());
        expected.extend_from_slice(snippet.as_bytes());
    }
    assert_eq!(frame, expected);
    assert_eq!(decode_hits(&frame).unwrap(), (3, hits));
    for cut in 1..frame.len() {
        assert_eq!(decode_hits(&frame[..cut]).unwrap_err(), CodecError::Truncated, "cut at {cut}");
    }
    let mut longer = frame.clone();
    longer.push(0);
    assert_eq!(decode_hits(&longer).unwrap_err(), CodecError::TrailingBytes);
    assert_eq!(decode_hits(&[131, 0, 0, 0, 1, 0, 0]).unwrap_err(), CodecError::BadKind(131));

    let too_many: Vec<SearchHit> = (0..=MAX_HITS as u64).map(|n| hit("r", n, "", "")).collect();
    assert_eq!(encode_hits(1, &too_many).unwrap_err(), CodecError::FieldLength);
    assert_eq!(encode_hits(1, &[hit("r", 1, "", &"s".repeat(MAX_SNIPPET + 1))]).unwrap_err(), CodecError::FieldLength);
    assert_eq!(encode_hits(1, &[hit("", 1, "", "")]).unwrap_err(), CodecError::FieldLength);
}

fn framed(id: u32, request: &Request) -> Vec<u8> {
    encode(&encode_request(id, request).unwrap()).unwrap()
}

#[test]
fn a_durable_connection_answers_with_the_current_text_of_the_askers_messages() {
    let path = std::env::temp_dir().join(format!("t320b_{}", std::process::id()));
    let _ = fs::remove_file(&path);
    let mut server = DurableServer::open(&path).unwrap();
    let room = server.create_room("alice", "Project").unwrap();
    let other = server.create_room("carol", "Elsewhere").unwrap();
    server.add_member(&room, "alice", "bob", Role::Member).unwrap();
    let kickoff = server.post(&room, "alice", "The **kickoff** is on Monday", 1_000).unwrap();
    let lunch = server.post(&room, "bob", "Lunch after the kickoff?", 2_000).unwrap();
    server.post(&other, "carol", "kickoff notes", 3_000).unwrap();
    server.edit(&room, "alice", kickoff, "The kickoff moved to Tuesday", 4_000).unwrap();

    let mut bob = Connection::new("bob");
    let output = bob.receive_durable(&mut server, &framed(4, &Request::Search { query: "kick".into() }), 5_000).unwrap();
    let response = encode(&encode_response(4, &Response::Ok { cursor: 2 }).unwrap()).unwrap();
    assert_eq!(&output[..response.len()], response.as_slice(), "Ok counts the hits");
    let frame = encode(&encode_hits(4, &[hit(&room, lunch, "bob", "Lunch after the kickoff?"), hit(&room, kickoff, "alice", "The kickoff moved to Tuesday")]).unwrap()).unwrap();
    assert_eq!(&output[response.len()..], frame.as_slice(), "then the hits, newest first, with the edited text");

    // A long message's snippet is cut at a character boundary within the limit.
    let long = format!("kickoff {}", "\u{e9}".repeat(MAX_SNIPPET));
    let long_cursor = server.post(&room, "alice", &long, 6_000).unwrap();
    let found = server.found("bob", "kick");
    let first = &found[0];
    assert_eq!(first.cursor, long_cursor);
    assert!(first.snippet.len() <= MAX_SNIPPET && first.snippet.starts_with("kickoff ") && long.starts_with(&first.snippet));
    fs::remove_file(&path).unwrap();
}

#[test]
fn a_server_without_a_journal_finds_nothing() {
    let mut server = Server::new();
    let room = server.create_room("alice", "Project").unwrap();
    server.post(&room, "alice", "kickoff", 1_000).unwrap();
    let mut alice = Connection::new("alice");
    let output = alice.receive(&mut server, &framed(9, &Request::Search { query: "kick".into() }), 2_000).unwrap();
    let mut expected = encode(&encode_response(9, &Response::Ok { cursor: 0 }).unwrap()).unwrap();
    expected.extend(encode(&encode_hits(9, &[]).unwrap()).unwrap());
    assert_eq!(output, expected);
}
