//! The room list in the list pane (REQUIREMENTS 2.20): which rooms the user follows, which one is open, and the unread
//! badges. Task T300. The person's own settings (T346, REQUIREMENTS 2.2) order and filter it: pinned rooms come first,
//! hidden rooms leave the list (a room search still finds them), and muted or hidden rooms add nothing to the total.

use std::collections::BTreeMap;

use crewcraft_client_core::room_view::RoomSettings;

use crate::{Command, RoomRow};

/// The rooms the user follows, at most one of them selected.
#[derive(Debug, Default)]
pub struct RoomList {
    /// (name, unread), in the order added. `rows` sorts; the list is small enough that sorting per call is cheap.
    rooms: Vec<(String, u32)>,
    selected: Option<String>,
    /// The person's own settings, by room; a room missing here has none set (T346).
    settings: BTreeMap<String, RoomSettings>,
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

    /// Every room the person has not hidden: pinned rooms first, then the rest, each part sorted by name ignoring
    /// ASCII case, then by the exact name to break ties.
    pub fn rows(&self) -> Vec<RoomRow> {
        let mut rows = self.rows_where(|settings| !settings.hidden);
        rows.sort_by_key(|row| !self.settings(&row.name).pinned);
        rows
    }

    /// The rooms the person hid, sorted by name as `rows` sorts (T346). They are still memberships: a room search shows
    /// them, and a new message in one does not bring it back into `rows`.
    pub fn hidden_rows(&self) -> Vec<RoomRow> {
        self.rows_where(|settings| settings.hidden)
    }

    /// Record the person's own settings for a listed room (T346). Returns whether the room is listed (an unknown name
    /// changes nothing).
    pub fn set_settings(&mut self, name: &str, settings: RoomSettings) -> bool {
        if self.position(name).is_none() {
            return false;
        }
        self.settings.insert(name.to_owned(), settings);
        true
    }

    /// The person's own settings for a room; none set for a room never given any.
    pub fn settings(&self, name: &str) -> RoomSettings {
        self.settings.get(name).copied().unwrap_or_default()
    }

    fn rows_where(&self, keep: impl Fn(RoomSettings) -> bool) -> Vec<RoomRow> {
        let mut rows: Vec<RoomRow> = self
            .rooms
            .iter()
            .filter(|(name, _)| keep(self.settings(name)))
            .map(|(name, unread)| RoomRow { name: name.clone(), unread: *unread, selected: self.is_selected(name) })
            .collect();
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

    /// The sum of the unread counts of the rooms the person neither muted nor hid, for the app-bar badge (T346). Each
    /// row keeps its own count. Saturates at `u32::MAX`.
    pub fn total_unread(&self) -> u32 {
        self.rooms
            .iter()
            .filter(|(name, _)| {
                let settings = self.settings(name);
                !settings.muted && !settings.hidden
            })
            .fold(0u32, |sum, (_, unread)| sum.saturating_add(*unread))
    }

    fn position(&self, name: &str) -> Option<usize> {
        self.rooms.iter().position(|(listed, _)| listed == name)
    }

    fn is_selected(&self, name: &str) -> bool {
        self.selected.as_deref() == Some(name)
    }
}

#[cfg(test)]
mod room_settings_tests {
    use super::*;

    fn names(rows: &[RoomRow]) -> Vec<&str> {
        rows.iter().map(|row| row.name.as_str()).collect()
    }

    #[test]
    fn pinned_rooms_lead_hidden_rooms_leave_and_muted_or_hidden_unread_stays_out_of_the_total() {
        let mut list = RoomList::new();
        for name in ["alpha", "beta", "gamma", "delta"] {
            assert!(list.add(name));
            assert!(list.set_unread(name, 2));
        }
        let before = list.total_unread();
        assert!(list.set_settings("gamma", RoomSettings { pinned: true, ..RoomSettings::default() }));
        assert!(list.set_settings("beta", RoomSettings { hidden: true, ..RoomSettings::default() }));
        assert!(list.set_settings("delta", RoomSettings { muted: true, ..RoomSettings::default() }));
        assert!(!list.set_settings("unknown", RoomSettings { pinned: true, ..RoomSettings::default() }));
        let rows = list.rows();
        assert_eq!(names(&rows).first(), Some(&"gamma"));
        assert!(!names(&rows).contains(&"beta"));
        assert!(names(&rows).contains(&"delta"));
        assert_eq!(names(&list.hidden_rows()), vec!["beta"]);
        assert!(list.total_unread() < before);
        assert_eq!(rows.iter().find(|row| row.name == "delta").map(|row| row.unread), Some(2), "a muted row keeps its own count");
        // A new message in a hidden room changes its count but never brings it back into the list.
        assert!(list.set_unread("beta", 5));
        assert!(!names(&list.rows()).contains(&"beta"));
        let total = list.total_unread();
        assert!(list.set_unread("beta", 9));
        assert_eq!(list.total_unread(), total);
        // Unpinning and unhiding restore the plain order.
        list.set_settings("gamma", RoomSettings::default());
        list.set_settings("beta", RoomSettings::default());
        assert_eq!(names(&list.rows()), vec!["alpha", "beta", "delta", "gamma"]);
        assert!(list.select("beta").is_some(), "a once-hidden room can be opened again");
    }
}
