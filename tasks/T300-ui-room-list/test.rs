use crewcraft_ui_model::room_list::RoomList;
use crewcraft_ui_model::{Command, RoomRow};

fn row(name: &str, unread: u32, selected: bool) -> RoomRow {
    RoomRow { name: name.to_string(), unread, selected }
}

fn sync(room: &str) -> Option<Command> {
    Some(Command::Sync { room: room.to_string() })
}

#[test]
fn adds_rooms_once_and_refuses_blank_names() {
    let mut list = RoomList::new();
    assert!(list.rows().is_empty());
    assert_eq!(list.selected(), None);
    assert!(list.add("general"));
    assert!(!list.add("general"));
    assert!(list.add("General"));
    for blank in ["", " ", "\t\n"] {
        assert!(!list.add(blank));
    }
    assert_eq!(list.rows(), vec![row("General", 0, false), row("general", 0, false)]);
}

#[test]
fn sorts_by_name_ignoring_case_with_exact_name_as_tie_break() {
    let mut list = RoomList::new();
    for name in ["zeta", "Beta", "alpha", "beta", "Alpha2"] {
        assert!(list.add(name));
    }
    let names: Vec<String> = list.rows().into_iter().map(|r| r.name).collect();
    assert_eq!(names, ["alpha", "Alpha2", "Beta", "beta", "zeta"]);
}

#[test]
fn selecting_syncs_once_and_clears_unread() {
    let mut list = RoomList::new();
    list.add("design");
    list.add("ops");
    assert!(list.set_unread("design", 3));
    assert!(list.set_unread("ops", 2));
    assert_eq!(list.total_unread(), 5);

    assert_eq!(list.select("ops"), sync("ops"));
    assert_eq!(list.selected(), Some("ops"));
    assert_eq!(list.rows(), vec![row("design", 3, false), row("ops", 0, true)]);
    assert_eq!(list.total_unread(), 3);

    assert_eq!(list.select("ops"), None, "the open room is not synced again");
    assert_eq!(list.select("missing"), None);
    assert_eq!(list.selected(), Some("ops"), "an unknown name keeps the selection");

    assert_eq!(list.select("design"), sync("design"));
    assert_eq!(list.rows(), vec![row("design", 0, true), row("ops", 0, false)]);
}

#[test]
fn unread_for_the_open_room_stays_zero_and_unknown_rooms_are_ignored() {
    let mut list = RoomList::new();
    list.add("ops");
    list.add("design");
    list.select("ops");
    assert!(list.set_unread("ops", 9));
    assert!(!list.set_unread("missing", 4));
    assert!(list.set_unread("design", 1));
    assert_eq!(list.rows(), vec![row("design", 1, false), row("ops", 0, true)]);
    assert!(list.set_unread("design", 0));
    assert_eq!(list.total_unread(), 0);
}

#[test]
fn total_unread_saturates() {
    let mut list = RoomList::new();
    list.add("a");
    list.add("b");
    list.set_unread("a", u32::MAX);
    list.set_unread("b", 7);
    assert_eq!(list.total_unread(), u32::MAX);
}
