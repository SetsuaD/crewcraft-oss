// T114: server-side sessions keyed by the SHA-256 of the token, with idle and absolute timeouts and revocation.
// Expected token and digest values were computed independently (Python base64.urlsafe_b64encode + hashlib.sha256).
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_accounts::sessions::{ABSOLUTE_MS, IDLE_MS, Session, Sessions};

const T0: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const T0_SHA256: &str = "0f007385b6f9d4b7eeb2748605afe1a984a0a3bfa3f014d09e2a784ce9e5cd1a";
const TFF: &str = "__________________________________________8";
const TFF_SHA256: &str = "225f7e75329dd45aa354975d73987319309393af3a4c6733bc13601a4f1b8796";

#[test]
fn the_token_is_base64url_of_the_random_bytes() {
    let mut s = Sessions::new();
    assert_eq!(s.create([0; 32], "ana", "laptop", 0), T0);
    assert_eq!(s.create([255; 32], "ana", "phone", 0), TFF);
    assert_eq!(s.len(), 2);
}

#[test]
fn only_the_hash_of_a_token_is_stored() {
    let mut s = Sessions::new();
    s.create([255; 32], "ana", "phone", 0);
    s.create([0; 32], "ana", "laptop", 0);
    assert_eq!(s.stored_keys(), vec![T0_SHA256.to_string(), TFF_SHA256.to_string()]);
}

#[test]
fn validate_refreshes_and_returns_the_session() {
    let mut s = Sessions::new();
    let t = s.create([3; 32], "ana", "laptop", 10);
    let want = Session { user: "ana".to_string(), device: "laptop".to_string(), created_ms: 10, last_seen_ms: 50 };
    assert_eq!(s.validate(&t, 50), Some(want));
    assert_eq!(s.validate("not-a-token", 50), None);
}

#[test]
fn an_idle_session_dies_and_is_removed() {
    let mut s = Sessions::new();
    let t = s.create([2; 32], "ana", "laptop", 1_000);
    assert!(s.validate(&t, 1_000 + IDLE_MS - 1).is_some());
    assert!(s.validate(&t, 1_000 + 2 * IDLE_MS - 1).is_none());
    assert!(s.validate(&t, 1_000 + 2 * IDLE_MS - 2).is_none()); // gone, not merely expired
    assert!(s.is_empty());
}

#[test]
fn a_busy_session_still_ends_at_the_absolute_limit() {
    let mut s = Sessions::new();
    let t = s.create([1; 32], "ana", "laptop", 0);
    let mut now = 0;
    while now + (IDLE_MS - 1) < ABSOLUTE_MS {
        now += IDLE_MS - 1;
        assert!(s.validate(&t, now).is_some(), "alive at {now}");
    }
    assert!(s.validate(&t, ABSOLUTE_MS).is_none());
    assert!(s.is_empty());
}

#[test]
fn revocation() {
    let mut s = Sessions::new();
    let a = s.create([4; 32], "ana", "laptop", 0);
    let b = s.create([5; 32], "ana", "phone", 0);
    s.create([6; 32], "ana", "phone", 0);
    s.create([7; 32], "bo", "laptop", 0);
    assert!(s.revoke(&a));
    assert!(!s.revoke(&a));
    assert!(s.validate(&a, 1).is_none());
    assert_eq!(s.revoke_device("ana", "phone"), 2);
    assert!(s.validate(&b, 1).is_none());
    assert_eq!(s.revoke_user("bo"), 1);
    assert!(s.is_empty());
}
