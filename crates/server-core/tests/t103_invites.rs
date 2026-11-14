// T103: single-use, expiring enrollment invitations keyed by bootstrap public key.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_server_core::invites::{Invite, InviteBook, InviteError};

fn inv(email: &str, k: u8, expires_ms: u64) -> Invite {
    Invite { email: email.to_string(), bootstrap_pub: [k; 32], expires_ms }
}

#[test]
fn redeem_is_single_use() {
    let mut b = InviteBook::new();
    b.issue(inv("ana@example.org", 1, 1000), 0).unwrap();
    assert!(b.is_pending(&[1; 32], 10));
    assert_eq!(b.redeem(&[1; 32], 10), Ok(inv("ana@example.org", 1, 1000)));
    assert_eq!(b.redeem(&[1; 32], 11), Err(InviteError::Unknown));
    assert!(b.is_empty());
}

#[test]
fn expiry_is_exclusive_and_an_expired_invitation_is_removed() {
    let mut b = InviteBook::new();
    b.issue(inv("a@example.org", 1, 1000), 0).unwrap();
    b.issue(inv("b@example.org", 2, 1000), 0).unwrap();
    assert!(b.is_pending(&[1; 32], 999));
    assert!(!b.is_pending(&[1; 32], 1000));
    assert_eq!(b.redeem(&[1; 32], 999).map(|i| i.email), Ok("a@example.org".to_string()));
    assert_eq!(b.redeem(&[2; 32], 1000), Err(InviteError::Expired));
    assert_eq!(b.redeem(&[2; 32], 1000), Err(InviteError::Unknown));
}

#[test]
fn a_new_invitation_replaces_the_old_one_for_that_email() {
    let mut b = InviteBook::new();
    b.issue(inv("Ana@Example.org", 1, 1000), 0).unwrap();
    b.issue(inv("ana@example.org", 2, 2000), 0).unwrap();
    assert_eq!(b.len(), 1);
    assert_eq!(b.redeem(&[1; 32], 10), Err(InviteError::Unknown));
    assert!(b.redeem(&[2; 32], 10).is_ok());
}

#[test]
fn a_bootstrap_key_cannot_serve_two_live_invitations() {
    let mut b = InviteBook::new();
    b.issue(inv("a@example.org", 7, 1000), 0).unwrap();
    assert_eq!(b.issue(inv("b@example.org", 7, 1000), 10), Err(InviteError::KeyInUse));
    assert!(b.is_pending(&[7; 32], 10)); // the refused issue changed nothing
    assert_eq!(b.issue(inv("b@example.org", 7, 5000), 1000), Ok(())); // the first one has expired by then
    assert_eq!(b.redeem(&[7; 32], 1001).map(|i| i.email), Ok("b@example.org".to_string()));
}

#[test]
fn prune_counts_what_it_removes() {
    let mut b = InviteBook::new();
    b.issue(inv("a@example.org", 1, 100), 0).unwrap();
    b.issue(inv("b@example.org", 2, 200), 0).unwrap();
    b.issue(inv("c@example.org", 3, 300), 0).unwrap();
    assert_eq!(b.prune(200), 2);
    assert_eq!(b.len(), 1);
    assert_eq!(b.prune(200), 0);
}
