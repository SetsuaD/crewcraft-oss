#![allow(clippy::unwrap_used)]

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_proto::frame::encode;
use crewcraft_proto::push::{Push, encode_push};
use crewcraft_proto::request::{Request, Response, encode_request, encode_response};
use crewcraft_server_core::connection::{Connection, to_push};
use crewcraft_server_core::cursor_log::Since;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::room::Role;
use crewcraft_server_core::room_service::{EventKind, RoomService, ServiceError};
use crewcraft_server_core::server::{Server, ServerError};

fn sync_request(id: u32, room: &str, cursor: u64) -> Vec<u8> {
    let request = Request::Sync { room: room.into(), cursor };
    encode(&encode_request(id, &request).unwrap()).unwrap()
}

fn sync_reply(id: u32, head: u64, pushes: &[Push]) -> Vec<u8> {
    let mut bytes = encode(&encode_response(id, &Response::Ok { cursor: head }).unwrap()).unwrap();
    for push in pushes {
        bytes.extend(encode(&encode_push(push).unwrap()).unwrap());
    }
    bytes
}

#[test]
fn sync_preserves_cursors_and_sends_no_deleted_text() {
    let mut server = Server::new();
    let room = server.create_room("alice", "General").unwrap();
    server.add_member(&room, "alice", "bob", Role::Member).unwrap();
    let posted = server.post(&room, "alice", "original @bob", 0).unwrap();
    let edit = server.edit(&room, "alice", posted, "revised @bob", 0).unwrap();
    let kept = server.post(&room, "alice", "keep @bob", 0).unwrap();
    let kept_edit = server.edit(&room, "alice", kept, "keep revised @bob", 0).unwrap();

    assert_eq!(server.delete(&room, "bob", posted), Err(ServerError::Service(ServiceError::NotAllowed)));
    let posted_push =
        Push::Posted { room: room.clone(), cursor: posted, author: "alice".into(), html: "original @bob".into(), mentions: vec!["bob".into()] };
    let edited_push = Push::Edited { room: room.clone(), cursor: edit, target: posted, html: "revised @bob".into(), mentions: vec!["bob".into()] };
    let kept_push = Push::Posted { room: room.clone(), cursor: kept, author: "alice".into(), html: "keep @bob".into(), mentions: vec!["bob".into()] };
    let kept_edit_push =
        Push::Edited { room: room.clone(), cursor: kept_edit, target: kept, html: "keep revised @bob".into(), mentions: vec!["bob".into()] };
    let mut bob = Connection::new("bob");
    let before = bob.receive(&mut server, &sync_request(1, &room, 1), 1).unwrap();
    assert_eq!(before, sync_reply(1, 5, &[posted_push, edited_push, kept_push.clone(), kept_edit_push.clone()]));

    let tombstone = server.delete(&room, "alice", posted).unwrap();
    assert_eq!(tombstone, 6);
    let pushes = [
        Push::Other { room: room.clone(), cursor: posted },
        Push::Other { room: room.clone(), cursor: edit },
        kept_push,
        kept_edit_push,
        Push::Deleted { room: room.clone(), cursor: tombstone, target: posted },
    ];
    let full = Connection::new("bob").receive(&mut server, &sync_request(2, &room, 1), 2).unwrap();
    assert_eq!(full, sync_reply(2, tombstone, &pushes));
    let catch_up = bob.receive(&mut server, &sync_request(3, &room, posted), 2).unwrap();
    assert_eq!(catch_up, sync_reply(3, tombstone, &pushes[1..]));
    let cached = bob.receive(&mut server, &sync_request(4, &room, kept_edit), 2).unwrap();
    assert_eq!(cached, sync_reply(4, tombstone, &pushes[4..]));
}

fn assert_redacted(room: &RoomService, slug: &str) {
    let sync = room.sync("bob", 1).unwrap();
    assert!(matches!(&sync, Since::Events(_)));
    let Since::Events(events) = sync else { return };
    assert_eq!(room.head(), 6);
    assert_eq!(events.iter().map(|(cursor, _)| *cursor).collect::<Vec<_>>(), [2, 3, 4, 5, 6]);
    for cursor in [2, 3, 5] {
        let (_, event) = events.iter().find(|(held, _)| *held == cursor).unwrap();
        assert_eq!(event.cursor, cursor);
        assert!(event.html.is_empty());
        assert!(event.mentions.is_empty());
        assert_eq!(to_push(slug, cursor, event), Push::Other { room: slug.into(), cursor });
    }
    assert_eq!(events[0].1.kind, EventKind::Posted);
    assert_eq!(events[1].1.kind, EventKind::Edited { target: 2 });
    assert_eq!(events[2].1.html, "keep @bob");
    assert_eq!(events[2].1.mentions, ["bob"]);
    assert_eq!(events[3].1.kind, EventKind::Edited { target: 2 });
    assert_eq!(events[4].1.kind, EventKind::Deleted { target: 2 });
    assert_eq!(room.unread("bob").unwrap(), 1);
}

#[test]
fn replay_redacts_the_post_and_each_held_revision() {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let path = std::env::temp_dir().join(format!("t147_redaction_{}_{nonce}", std::process::id()));
    let room;
    {
        let mut server = DurableServer::open(&path).unwrap();
        room = server.create_room("alice", "General").unwrap();
        server.add_member(&room, "alice", "bob", Role::Member).unwrap();
        let posted = server.post(&room, "alice", "original @bob", 0).unwrap();
        server.edit(&room, "alice", posted, "revised @bob", 0).unwrap();
        server.post(&room, "alice", "keep @bob", 0).unwrap();
        server.edit(&room, "alice", posted, "revised again @bob", 0).unwrap();
        server.delete(&room, "alice", posted).unwrap();
        assert_redacted(server.server().room(&room).unwrap(), &room);
    }
    {
        let mut server = DurableServer::open(&path).unwrap();
        assert_redacted(server.server().room(&room).unwrap(), &room);
        let wire = Connection::new("bob").receive_durable(&mut server, &sync_request(5, &room, 1), 1).unwrap();
        let pushes = [
            Push::Other { room: room.clone(), cursor: 2 },
            Push::Other { room: room.clone(), cursor: 3 },
            Push::Posted { room: room.clone(), cursor: 4, author: "alice".into(), html: "keep @bob".into(), mentions: vec!["bob".into()] },
            Push::Other { room: room.clone(), cursor: 5 },
            Push::Deleted { room, cursor: 6, target: 2 },
        ];
        assert_eq!(wire, sync_reply(5, 6, &pushes));
    }
    fs::remove_file(path).unwrap();
}
