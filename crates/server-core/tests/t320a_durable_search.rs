//! T320a: the durable server keeps message search current: posts are found by any word's beginning, an edit is found
//! by its new text only, a deleted message is not found, only members of a room find its messages (and someone removed
//! from a room no longer does), and reopening the journal rebuilds the same results.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::PathBuf;

use crewcraft_server_core::durable::{DurableServer, MAX_SEARCH_HITS};
use crewcraft_server_core::room::Role;
use crewcraft_server_core::room_search::Hit;

const T0: u64 = 1_800_000_000_000;

fn path(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("t320a_{name}_{}", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

fn hits(ds: &DurableServer, user: &str, query: &str) -> Vec<(String, u64)> {
    ds.search(user, query, 10).into_iter().map(|Hit { slug, cursor }| (slug, cursor)).collect()
}

#[test]
fn search_follows_posts_edits_deletions_and_membership_and_survives_a_restart() {
    let p = path("all");
    let mut ds = DurableServer::open(&p).unwrap();
    let room = ds.create_room("alice", "Project").unwrap();
    let other = ds.create_room("carol", "Elsewhere").unwrap();
    ds.add_member(&room, "alice", "bob", Role::Member).unwrap();
    let kickoff = ds.post(&room, "alice", "Hello, the **project** kickoff is Monday", T0).unwrap();
    let lunch = ds.post(&room, "bob", "Lunch plans for the kickoff?", T0 + 1000).unwrap();
    let secret = ds.post(&other, "carol", "project notes only carol sees", T0 + 2000).unwrap();

    // Every word of the query must start a word of the message; newest first.
    assert_eq!(hits(&ds, "alice", "proj"), vec![(room.clone(), kickoff)]);
    assert_eq!(hits(&ds, "bob", "kick"), vec![(room.clone(), lunch), (room.clone(), kickoff)]);
    assert_eq!(hits(&ds, "bob", "kickoff lunch"), vec![(room.clone(), lunch)]);
    assert!(hits(&ds, "bob", "roject").is_empty(), "matches start at a word's beginning");
    assert_eq!(hits(&ds, "carol", "proj"), vec![(other.clone(), secret)], "only the rooms one is in");
    assert!(hits(&ds, "dave", "proj").is_empty());

    // An edit is found by its new text, at the message's own cursor; a deleted message is not found.
    ds.edit(&room, "alice", kickoff, "Hello, the budget review is Monday", T0 + 3000).unwrap();
    assert!(hits(&ds, "alice", "proj").is_empty());
    assert_eq!(hits(&ds, "alice", "budg"), vec![(room.clone(), kickoff)]);
    ds.delete(&room, "bob", lunch).unwrap();
    assert!(hits(&ds, "alice", "lunch").is_empty());

    // Someone removed from the room no longer finds its messages.
    ds.remove_member(&room, "alice", "bob").unwrap();
    assert!(hits(&ds, "bob", "budg").is_empty());
    assert_eq!(hits(&ds, "alice", "budg"), vec![(room.clone(), kickoff)]);
    drop(ds);

    // Reopening replays the journal into the same results.
    let ds = DurableServer::open(&p).unwrap();
    assert_eq!(hits(&ds, "alice", "budg"), vec![(room.clone(), kickoff)]);
    assert!(hits(&ds, "alice", "proj").is_empty() && hits(&ds, "alice", "lunch").is_empty());
    assert_eq!(hits(&ds, "carol", "notes"), vec![(other, secret)]);
    assert!(hits(&ds, "bob", "budg").is_empty());
    fs::remove_file(&p).unwrap();
}

#[test]
fn a_search_returns_at_most_the_cap() {
    let p = path("cap");
    let mut ds = DurableServer::open(&p).unwrap();
    let room = ds.create_room("alice", "Busy").unwrap();
    for n in 0..(MAX_SEARCH_HITS as u64 + 5) {
        ds.post(&room, "alice", &format!("status update {n}"), T0 + n * 60_000).unwrap();
    }
    assert_eq!(ds.search("alice", "status", usize::MAX).len(), MAX_SEARCH_HITS);
    assert_eq!(ds.search("alice", "status", 3).len(), 3);
    assert!(ds.search("alice", "   ", 10).is_empty(), "an empty query finds nothing");
    fs::remove_file(&p).unwrap();
}
