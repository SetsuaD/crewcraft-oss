//! The room list in the list pane (REQUIREMENTS 2.20): which rooms the user follows, which one is open, and the unread
//! badges. Task T300.

use crate::{Command, RoomRow};

/// The rooms the user follows, at most one of them selected.
#[derive(Debug, Default)]
pub struct RoomList {
    /// (name, unread), in the order added. `rows` sorts; the list is small enough that sorting per call is cheap.
    rooms: Vec<(String, u32)>,
    selected: Option<String>,
}

impl RoomList {
    /// No rooms, none selected.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a room by name with 0 unread. Returns false, and changes nothing, when the name is empty or only whitespace,
    /// or when a room with exactly this name is already listed. Names are compared exactly (case matters).
    pub fn add(&mut self, name: &str) -> bool {
        if name.trim().is_empty() || self.position(name).is_some() {
            return false;
        }
        self.rooms.push((name.to_owned(), 0));
        true
    }

    /// Every room, sorted by name ignoring ASCII case, then by the exact name to break ties.
    pub fn rows(&self) -> Vec<RoomRow> {
        let mut rows: Vec<RoomRow> =
            self.rooms.iter().map(|(name, unread)| RoomRow { name: name.clone(), unread: *unread, selected: self.is_selected(name) }).collect();
        rows.sort_by(|a, b| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()).then_with(|| a.name.cmp(&b.name)));
        rows
    }

    /// Open a room. For a listed room that is not already selected: select it, set its unread count to 0, and return
    /// `Command::Sync` for it. For the room already selected, or a name not listed: change nothing and return `None`.
    pub fn select(&mut self, name: &str) -> Option<Command> {
        if self.is_selected(name) {
            return None;
        }
        let index = self.position(name)?;
        self.rooms[index].1 = 0;
        self.selected = Some(name.to_owned());
        Some(Command::Sync { room: name.to_owned() })
    }

    /// The selected room's name, if any.
    pub fn selected(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    /// Record a room's unread count from the worker. Returns whether the room is listed (an unknown name changes
    /// nothing). The selected room's count stays 0, because the user is looking at it.
    pub fn set_unread(&mut self, name: &str, unread: u32) -> bool {
        let Some(index) = self.position(name) else {
            return false;
        };
        if !self.is_selected(name) {
            self.rooms[index].1 = unread;
        }
        true
    }

    /// Apply an authoritative personal count, including a rewind from another device while this room is selected.
    pub fn set_read_state(&mut self, name: &str, unread: u64) -> bool {
        let Some(index) = self.position(name) else { return false };
        self.rooms[index].1 = u32::try_from(unread).unwrap_or(u32::MAX);
        true
    }

    /// Leave the conversation without clearing its authoritative unread count (T344).
    pub fn clear_selection(&mut self, name: &str) {
        if self.is_selected(name) {
            self.selected = None;
        }
    }

    /// The sum of every room's unread count, for the app-bar badge. Saturates at `u32::MAX`.
    pub fn total_unread(&self) -> u32 {
        self.rooms.iter().fold(0u32, |sum, (_, unread)| sum.saturating_add(*unread))
    }

    fn position(&self, name: &str) -> Option<usize> {
        self.rooms.iter().position(|(listed, _)| listed == name)
    }

    fn is_selected(&self, name: &str) -> bool {
        self.selected.as_deref() == Some(name)
    }
}
