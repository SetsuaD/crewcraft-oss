//! The room list in the list pane (REQUIREMENTS 2.20): which rooms the user follows, which one is open, and the unread
//! badges. Task T300.

use crate::{Command, RoomRow};

/// The rooms the user follows, at most one of them selected.
#[derive(Debug, Default)]
pub struct RoomList {
    _todo: (),
}

#[allow(clippy::todo, reason = "stubs until task T300 lands; remove this allow with them")]
impl RoomList {
    /// No rooms, none selected.
    pub fn new() -> Self {
        Self { _todo: () }
    }

    /// Add a room by name with 0 unread. Returns false, and changes nothing, when the name is empty or only whitespace,
    /// or when a room with exactly this name is already listed. Names are compared exactly (case matters).
    pub fn add(&mut self, name: &str) -> bool {
        let _ = name;
        todo!("T300: RoomList::add")
    }

    /// Every room, sorted by name ignoring ASCII case, then by the exact name to break ties.
    pub fn rows(&self) -> Vec<RoomRow> {
        todo!("T300: RoomList::rows")
    }

    /// Open a room. For a listed room that is not already selected: select it, set its unread count to 0, and return
    /// `Command::Sync` for it. For the room already selected, or a name not listed: change nothing and return `None`.
    pub fn select(&mut self, name: &str) -> Option<Command> {
        let _ = name;
        todo!("T300: RoomList::select")
    }

    /// The selected room's name, if any.
    pub fn selected(&self) -> Option<&str> {
        todo!("T300: RoomList::selected")
    }

    /// Record a room's unread count from the worker. Returns whether the room is listed (an unknown name changes
    /// nothing). The selected room's count stays 0, because the user is looking at it.
    pub fn set_unread(&mut self, name: &str, unread: u32) -> bool {
        let _ = (name, unread);
        todo!("T300: RoomList::set_unread")
    }

    /// The sum of every room's unread count, for the app-bar badge. Saturates at `u32::MAX`.
    pub fn total_unread(&self) -> u32 {
        todo!("T300: RoomList::total_unread")
    }
}
