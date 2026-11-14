//! Read markers and unread counts per user and room. Task T105.

use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct ReadMarkers {
    markers: HashMap<(String, String), u64>,
}

impl ReadMarkers {
    pub fn new() -> Self {
        Self::default()
    }

    /// Move the user's read marker in a room to `cursor`. A marker never moves backwards; returns whether it moved.
    pub fn mark_read(&mut self, user: &str, room: &str, cursor: u64) -> bool {
        let key = (user.to_string(), room.to_string());
        let marker = self.markers.entry(key).or_insert(0);
        if *marker >= cursor {
            return false;
        }
        *marker = cursor;
        true
    }

    /// The user's marker in the room; 0 if never set.
    pub fn last_read(&self, user: &str, room: &str) -> u64 {
        self.markers.get(&(user.to_string(), room.to_string())).copied().unwrap_or(0)
    }

    /// How many of `messages` (cursor, author) come after the user's marker and were written by someone else.
    pub fn unread(&self, user: &str, room: &str, messages: &[(u64, &str)]) -> usize {
        let cursor = self.last_read(user, room);
        messages.iter().filter(|&&(message_cursor, author)| message_cursor > cursor && author != user).count()
    }
}
