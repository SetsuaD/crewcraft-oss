// T108: presence from heartbeats (Online < 60 s, Away < 10 min, then Offline).
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_server_core::presence::{Presence, Status};

#[test]
fn thresholds() {
    let mut p = Presence::new();
    p.heartbeat("ana", 1_000);
    assert_eq!(p.status("ana", 1_000), Status::Online);
    assert_eq!(p.status("ana", 60_999), Status::Online);
    assert_eq!(p.status("ana", 61_000), Status::Away);
    assert_eq!(p.status("ana", 600_999), Status::Away);
    assert_eq!(p.status("ana", 601_000), Status::Offline);
    assert_eq!(p.status("nobody", 0), Status::Offline);
}

#[test]
fn older_heartbeats_are_ignored() {
    let mut p = Presence::new();
    p.heartbeat("bo", 100_000);
    p.heartbeat("bo", 5_000);
    assert_eq!(p.status("bo", 150_000), Status::Online);
}

#[test]
fn a_clock_behind_the_heartbeat_counts_as_online() {
    let mut p = Presence::new();
    p.heartbeat("cy", 10_000);
    assert_eq!(p.status("cy", 9_000), Status::Online);
}

#[test]
fn the_online_list_is_sorted() {
    let mut p = Presence::new();
    p.heartbeat("zed", 1);
    p.heartbeat("ana", 50_000);
    p.heartbeat("mo", 59_000);
    assert_eq!(p.online(60_000), vec!["ana".to_string(), "mo".to_string(), "zed".to_string()]);
    assert_eq!(p.online(61_000), vec!["ana".to_string(), "mo".to_string()]);
}

#[test]
fn prune_forgets_offline_users() {
    let mut p = Presence::new();
    p.heartbeat("a", 0);
    p.heartbeat("b", 500_000);
    assert_eq!(p.prune(700_000), 1);
    assert_eq!(p.status("b", 700_000), Status::Away);
    assert_eq!(p.prune(700_000), 0);
}
