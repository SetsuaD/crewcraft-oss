#![allow(clippy::unwrap_used)]

use std::fs;

use crewcraft_server_core::cursor_log::{EventLog, Since};
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::room::Role;
use crewcraft_server_core::room_service::{Event, EventKind, RoomService};

fn events(since: Since<Event>) -> Vec<(u64, Event)> {
    match since {
        Since::Events(e) => e,
        Since::Gap { oldest } => panic!("unexpected gap, oldest {oldest}"),
    }
}

#[test]
fn for_each_mut_visits_held_events_oldest_first_and_keeps_the_shape() {
    let mut log: EventLog<String> = EventLog::new(3);
    for s in ["a", "b", "c", "d"] {
        log.append(s.to_string());
    }
    // Capacity 3: "a" was dropped; held are cursors 2, 3, 4.
    let mut visited = Vec::new();
    log.for_each_mut(|cursor, event| {
        visited.push(cursor);
        *event = event.to_uppercase();
    });
    assert_eq!(visited, vec![2, 3, 4]);
    assert_eq!(log.head(), 4);
    assert_eq!(log.len(), 3);
    let Since::Events(held) = log.since(1) else { panic!("expected Events") };
    assert_eq!(held, vec![(2, "B".to_string()), (3, "C".to_string()), (4, "D".to_string())]);
}

#[test]
fn deleting_a_message_redacts_it_and_its_edits_in_the_log() {
    let mut svc = RoomService::new("alice", 100);
    svc.add_member("alice", "bob", Role::Member).unwrap(); // 1
    let secret = svc.post("bob", "hello @alice the secret plan").unwrap(); // 2
    svc.edit("bob", secret, "hello @alice the SECRET plan, revised").unwrap(); // 3
    let keep = svc.post("bob", "keep this one").unwrap(); // 4
    svc.edit("bob", keep, "keep this one too").unwrap(); // 5

    // Before the delete the text is in the log.
    let before = events(svc.sync("alice", 0).unwrap());
    assert!(before[1].1.html.contains("secret plan"));
    assert_eq!(before[1].1.mentions, vec!["alice".to_string()]);

    let deleted_at = svc.delete("alice", secret).unwrap(); // 6
    assert_eq!(deleted_at, 6);

    let after = events(svc.sync("alice", 0).unwrap());
    assert_eq!(after.len(), 6);
    let by_cursor = |c: u64| &after.iter().find(|(cursor, _)| *cursor == c).unwrap().1;

    // The deleted message and its edit keep their place, author and kind, and lose their text and mentions.
    let posted = by_cursor(2);
    assert_eq!(posted.kind, EventKind::Posted);
    assert_eq!(posted.actor, "bob");
    assert_eq!(posted.html, "");
    assert!(posted.mentions.is_empty());
    let edited = by_cursor(3);
    assert_eq!(edited.kind, EventKind::Edited { target: secret });
    assert_eq!(edited.actor, "bob");
    assert_eq!(edited.html, "");
    assert!(edited.mentions.is_empty());

    // Everything else is as it was.
    assert!(by_cursor(4).html.contains("keep this one"));
    assert_eq!(by_cursor(5).kind, EventKind::Edited { target: keep });
    assert!(by_cursor(5).html.contains("keep this one too"));
    assert_eq!(by_cursor(6).kind, EventKind::Deleted { target: secret });
    assert_eq!(by_cursor(1), &before[0].1);
}

#[test]
fn a_sync_from_the_middle_also_sees_redacted_events() {
    let mut svc = RoomService::new("alice", 100);
    svc.add_member("alice", "bob", Role::Member).unwrap(); // 1
    let m = svc.post("bob", "to be removed").unwrap(); // 2
    svc.post("bob", "stays").unwrap(); // 3
    svc.delete("bob", m).unwrap(); // 4 (an author may delete their own message)
    let tail = events(svc.sync("alice", 1).unwrap());
    assert_eq!(tail.len(), 3);
    assert_eq!(tail[0].0, 2);
    assert_eq!(tail[0].1.html, "");
    assert!(tail[1].1.html.contains("stays"));
}

#[test]
fn read_state_is_not_disturbed() {
    let mut svc = RoomService::new("alice", 100);
    svc.add_member("alice", "bob", Role::Member).unwrap(); // 1
    let m = svc.post("bob", "gone soon").unwrap(); // 2
    svc.post("bob", "stays").unwrap(); // 3
    svc.delete("alice", m).unwrap(); // 4
    assert_eq!(svc.head(), 4);
    // Only the surviving post counts as unread for alice; a redacted post is not "unread text".
    assert_eq!(svc.unread("alice").unwrap(), 1);
    // A message deleted once cannot be touched again.
    assert!(svc.delete("alice", m).is_err());
    assert!(svc.edit("bob", m, "back from the dead").is_err());
}

#[test]
fn the_rebuilt_server_is_redacted_too() {
    let path = std::env::temp_dir().join("t206_redacted");
    let _ = fs::remove_file(&path);
    let slug;
    {
        let mut ds = DurableServer::open(&path).unwrap();
        slug = ds.create_room("alice", "plans").unwrap();
        ds.add_member(&slug, "alice", "bob", Role::Member).unwrap();
        let m = ds.post(&slug, "bob", "the secret plan", 0).unwrap();
        ds.delete(&slug, "bob", m).unwrap();
    }
    let ds = DurableServer::open(&path).unwrap();
    let all = events(ds.server().room(&slug).unwrap().sync("alice", 0).unwrap());
    let posted = &all.iter().find(|(_, e)| e.kind == EventKind::Posted).unwrap().1;
    assert_eq!(posted.html, "");
    assert!(posted.mentions.is_empty());
}
