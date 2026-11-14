// T111: room membership, roles and the rules for adding, removing and re-roling members.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_server_core::room::{Role, Room, RoomError};

/// olga (Owner), adam (Admin), mia (Member), gus (Guest).
fn room() -> Room {
    let mut r = Room::new("olga");
    r.add("olga", "adam", Role::Admin).unwrap();
    r.add("adam", "mia", Role::Member).unwrap();
    r.add("adam", "gus", Role::Guest).unwrap();
    r
}

fn m(name: &str, role: Role) -> (String, Role) {
    (name.to_string(), role)
}

#[test]
fn the_creator_is_the_owner() {
    let r = Room::new("olga");
    assert_eq!(r.role("olga"), Some(Role::Owner));
    assert_eq!(r.role("x"), None);
    assert_eq!(r.members(), vec![m("olga", Role::Owner)]);
}

#[test]
fn members_are_sorted_by_name() {
    assert_eq!(room().members(), vec![m("adam", Role::Admin), m("gus", Role::Guest), m("mia", Role::Member), m("olga", Role::Owner)]);
}

#[test]
fn adding_needs_an_admin_and_a_lower_role() {
    let mut r = room();
    assert_eq!(r.add("nobody", "x", Role::Guest), Err(RoomError::NotMember));
    assert_eq!(r.add("mia", "zed", Role::Guest), Err(RoomError::Forbidden));
    assert_eq!(r.add("adam", "zed", Role::Admin), Err(RoomError::Forbidden));
    assert_eq!(r.add("adam", "zed", Role::Member), Ok(()));
    assert_eq!(r.add("adam", "zed", Role::Member), Err(RoomError::AlreadyMember));
    assert_eq!(r.add("olga", "kim", Role::Owner), Ok(()));
}

#[test]
fn removing_members() {
    let mut r = room();
    assert_eq!(r.remove("mia", "gus"), Err(RoomError::Forbidden)); // a Member outranks a Guest but is not an Admin
    assert_eq!(r.remove("adam", "olga"), Err(RoomError::Forbidden));
    assert_eq!(r.remove("adam", "mia"), Ok(()));
    assert_eq!(r.role("mia"), None);
    assert_eq!(r.remove("adam", "mia"), Err(RoomError::NotMember));
    assert_eq!(r.remove("gus", "gus"), Ok(())); // anyone may leave
}

#[test]
fn the_last_owner_cannot_leave_or_be_demoted() {
    let mut r = room();
    assert_eq!(r.remove("olga", "olga"), Err(RoomError::LastOwner));
    assert_eq!(r.set_role("olga", "olga", Role::Admin), Err(RoomError::LastOwner));
    r.add("olga", "kim", Role::Owner).unwrap();
    assert_eq!(r.remove("olga", "olga"), Ok(()));
    assert_eq!(r.role("kim"), Some(Role::Owner));
}

#[test]
fn changing_roles() {
    let mut r = room();
    assert_eq!(r.set_role("adam", "mia", Role::Guest), Ok(()));
    assert_eq!(r.role("mia"), Some(Role::Guest));
    assert_eq!(r.set_role("adam", "mia", Role::Admin), Err(RoomError::Forbidden)); // not above the actor's own role
    assert_eq!(r.set_role("adam", "olga", Role::Member), Err(RoomError::Forbidden));
    assert_eq!(r.set_role("gus", "mia", Role::Member), Err(RoomError::Forbidden));
    assert_eq!(r.set_role("olga", "adam", Role::Owner), Ok(()));
    assert_eq!(r.set_role("olga", "ghost", Role::Member), Err(RoomError::NotMember));
}

#[test]
fn who_may_post() {
    let r = room();
    assert!(r.can_post("mia"));
    assert!(r.can_post("olga"));
    assert!(!r.can_post("gus"));
    assert!(!r.can_post("stranger"));
}
