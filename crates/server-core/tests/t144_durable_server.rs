#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use crewcraft_server_core::durable::{DurableError, DurableServer};
use crewcraft_server_core::journal::Journal;
use crewcraft_server_core::room::Role;
use crewcraft_server_core::server::ServerError;

fn path(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("t144_{name}"));
    let _ = fs::remove_file(&p);
    p
}

#[test]
fn open_empty_journal_gives_no_rooms() {
    let p = path("empty");
    let ds = DurableServer::open(&p).unwrap();
    assert!(ds.server().rooms_of("alice").is_empty());
    assert!(ds.server().rooms_of("bob").is_empty());
}

#[test]
fn create_room_gives_owner_membership_and_slug() {
    let p = path("create");
    let mut ds = DurableServer::open(&p).unwrap();
    let slug = ds.create_room("alice", "hello world").unwrap();
    assert!(!slug.is_empty());

    let members = ds.server().room(&slug).unwrap().members();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].0, "alice");
    assert_eq!(members[0].1, Role::Owner);

    let infos = ds.server().rooms_of("alice");
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].slug, slug);
    assert_eq!(infos[0].role, Role::Owner);
}

#[test]
fn membership_persists_across_reopen() {
    let p = path("persist");
    let slug;
    {
        let mut ds = DurableServer::open(&p).unwrap();
        slug = ds.create_room("alice", "test").unwrap();
        ds.add_member(&slug, "alice", "bob", Role::Member).unwrap();
        ds.add_member(&slug, "alice", "carol", Role::Admin).unwrap();
    }
    let ds = DurableServer::open(&p).unwrap();
    let members = ds.server().room(&slug).unwrap().members();
    assert_eq!(members.len(), 3);
    assert!(members.iter().any(|(n, r)| n == "alice" && *r == Role::Owner));
    assert!(members.iter().any(|(n, r)| n == "bob" && *r == Role::Member));
    assert!(members.iter().any(|(n, r)| n == "carol" && *r == Role::Admin));
}

#[test]
fn corrupt_undecodable_record_is_index_zero() {
    let p = path("garbage");
    {
        let (mut j, _) = Journal::open(&p).unwrap();
        j.append(&[0xFF, 0x00]).unwrap();
    }
    let result = DurableServer::open(&p);
    assert!(matches!(result, Err(DurableError::Corrupt { index: 0 })), "expected Corrupt {{ index: 0 }}");
}

#[test]
fn corrupt_server_refuses_on_replay() {
    let p = path("refused");
    {
        let (mut j, _) = Journal::open(&p).unwrap();
        // Hand-encode Post { slug: "no-room", author: "alice", text: "hi", now_ms: 0 }
        // tag 4 | str slug | str author | str text | u64 now_ms
        let mut rec = Vec::new();
        rec.push(4);
        rec.extend_from_slice(&7u32.to_be_bytes());
        rec.extend_from_slice(b"no-room");
        rec.extend_from_slice(&5u32.to_be_bytes());
        rec.extend_from_slice(b"alice");
        rec.extend_from_slice(&2u32.to_be_bytes());
        rec.extend_from_slice(b"hi");
        rec.extend_from_slice(&0u64.to_be_bytes());
        j.append(&rec).unwrap();
    }
    let result = DurableServer::open(&p);
    assert!(matches!(result, Err(DurableError::Corrupt { index: 0 })), "expected Corrupt {{ index: 0 }}");
}

#[test]
fn duplicate_names_get_incrementing_suffixes() {
    let p = path("dup");
    let mut ds = DurableServer::open(&p).unwrap();
    let s1 = ds.create_room("alice", "hello world").unwrap();
    let s2 = ds.create_room("alice", "hello world").unwrap();
    let s3 = ds.create_room("alice", "hello world").unwrap();
    assert_eq!(s2, format!("{s1}-2"));
    assert_eq!(s3, format!("{s1}-3"));

    // All three rooms exist and alice is in all of them.
    let infos = ds.server().rooms_of("alice");
    assert_eq!(infos.len(), 3);
    let slugs: Vec<&str> = infos.iter().map(|i| i.slug.as_str()).collect();
    assert!(slugs.contains(&s1.as_str()));
    assert!(slugs.contains(&s2.as_str()));
    assert!(slugs.contains(&s3.as_str()));
}

#[test]
fn rate_limit_tokens_persist_across_reopen() {
    let p = path("ratelimit");
    let slug;
    {
        let mut ds = DurableServer::open(&p).unwrap();
        slug = ds.create_room("alice", "rl").unwrap();
        ds.add_member(&slug, "alice", "bob", Role::Member).unwrap();
        // Exhaust all 20 burst tokens at t=0.
        for i in 0..20u64 {
            ds.post(&slug, "bob", &format!("m{i}"), 0).unwrap();
        }
        // 21st post is rate-limited.
        let err = ds.post(&slug, "bob", "overflow", 0).unwrap_err();
        assert!(matches!(err, DurableError::Server(ServerError::RateLimited)), "expected RateLimited, got {err:?}");
    }
    // Reopen: replayed posts rebuilt the bucket to 0 tokens.
    let mut ds = DurableServer::open(&p).unwrap();
    let err = ds.post(&slug, "bob", "after-reopen", 0).unwrap_err();
    assert!(matches!(err, DurableError::Server(ServerError::RateLimited)), "expected RateLimited after reopen, got {err:?}");
}

#[test]
fn mark_read_recorded_only_when_cursor_moves() {
    let p = path("markread");
    {
        let mut ds = DurableServer::open(&p).unwrap();
        let slug = ds.create_room("alice", "mr").unwrap();
        // Fresh cursor is 0. Moving to 1 records an op.
        assert!(ds.mark_read(&slug, "alice", 1).unwrap());
        // Already at 1; staying put does NOT record.
        assert!(!ds.mark_read(&slug, "alice", 1).unwrap());
        // Moving to 2 records another op.
        assert!(ds.mark_read(&slug, "alice", 2).unwrap());
    }
    // Journal holds: CreateRoom + MarkRead(1) + MarkRead(2) = 3 records.
    let (_, records) = Journal::open(&p).unwrap();
    assert_eq!(records.len(), 3);
}

#[test]
fn server_refusal_is_not_recorded() {
    let p = path("notrecorded");
    let mut ds = DurableServer::open(&p).unwrap();
    // Post to a room that does not exist: Server(NoSuchRoom), nothing recorded.
    let err = ds.post("ghost", "alice", "hi", 0).unwrap_err();
    assert!(matches!(err, DurableError::Server(ServerError::NoSuchRoom)), "expected Server(NoSuchRoom), got {err:?}");
    let err = ds.add_member("ghost", "alice", "bob", Role::Member).unwrap_err();
    assert!(matches!(err, DurableError::Server(ServerError::NoSuchRoom)), "expected Server(NoSuchRoom), got {err:?}");
    // Journal should be empty (no successful ops were made).
    let (_, records) = Journal::open(&p).unwrap();
    assert!(records.is_empty());
}

#[test]
fn remove_member_persists_across_reopen() {
    let p = path("remove");
    let slug;
    {
        let mut ds = DurableServer::open(&p).unwrap();
        slug = ds.create_room("alice", "rm").unwrap();
        ds.add_member(&slug, "alice", "bob", Role::Member).unwrap();
        ds.remove_member(&slug, "alice", "bob").unwrap();
    }
    let ds = DurableServer::open(&p).unwrap();
    let members = ds.server().room(&slug).unwrap().members();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].0, "alice");
    assert_eq!(members[0].1, Role::Owner);
}

#[test]
fn multiple_ops_replay_in_order() {
    let p = path("order");
    let slug;
    {
        let mut ds = DurableServer::open(&p).unwrap();
        slug = ds.create_room("alice", "seq").unwrap();
        ds.add_member(&slug, "alice", "bob", Role::Admin).unwrap();
        ds.add_member(&slug, "bob", "carol", Role::Member).unwrap();
        // bob (Admin) can post.
        ds.post(&slug, "bob", "first", 100).unwrap();
        ds.post(&slug, "bob", "second", 200).unwrap();
    }
    let ds = DurableServer::open(&p).unwrap();
    let members = ds.server().room(&slug).unwrap().members();
    assert_eq!(members.len(), 3);
    assert!(members.iter().any(|(n, r)| n == "bob" && *r == Role::Admin));
    assert!(members.iter().any(|(n, r)| n == "carol" && *r == Role::Member));

    // Verify the journal has exactly 5 records in order.
    let (_, records) = Journal::open(&p).unwrap();
    assert_eq!(records.len(), 5);
    // Record 0: CreateRoom (tag 1)
    assert_eq!(records[0][0], 1);
    // Record 1: AddMember (tag 2)
    assert_eq!(records[1][0], 2);
    // Record 2: AddMember (tag 2)
    assert_eq!(records[2][0], 2);
    // Record 3: Post (tag 4)
    assert_eq!(records[3][0], 4);
    // Record 4: Post (tag 4)
    assert_eq!(records[4][0], 4);
}

/// Added in review: edits, deletes and read markers are replayed too, so the room after a reopen is the room before it.
#[test]
fn edits_deletes_and_read_markers_survive_reopen() {
    let p = path("replay_all");
    let slug;
    let (head, events, unread_alice, unread_bob);
    {
        let mut ds = DurableServer::open(&p).unwrap();
        slug = ds.create_room("alice", "replay").unwrap();
        ds.add_member(&slug, "alice", "bob", Role::Member).unwrap(); // cursor 1
        let one = ds.post(&slug, "bob", "one", 0).unwrap(); // cursor 2
        let two = ds.post(&slug, "bob", "two", 0).unwrap(); // cursor 3
        ds.post(&slug, "bob", "three", 0).unwrap(); // cursor 4
        ds.edit(&slug, "bob", one, "uno", 10).unwrap(); // cursor 5
        ds.delete(&slug, "alice", two).unwrap(); // cursor 6
        assert!(ds.mark_read(&slug, "alice", 2).unwrap());
        let room = ds.server().room(&slug).unwrap();
        head = room.head();
        events = format!("{:?}", room.sync("alice", 0).unwrap());
        unread_alice = room.unread("alice").unwrap();
        unread_bob = room.unread("bob").unwrap();
    }
    assert_eq!(head, 6);
    // alice read up to cursor 2: of bob's live posts (2 and 4; 3 is deleted) only 4 is unread for her.
    assert_eq!(unread_alice, 1);
    assert_eq!(unread_bob, 0);

    let ds = DurableServer::open(&p).unwrap();
    let room = ds.server().room(&slug).unwrap();
    assert_eq!(room.head(), head);
    assert_eq!(format!("{:?}", room.sync("alice", 0).unwrap()), events);
    assert_eq!(room.unread("alice").unwrap(), unread_alice);
    assert_eq!(room.unread("bob").unwrap(), unread_bob);
}
