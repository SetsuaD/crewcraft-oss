//! Read markers and unread counts per user and room. Task T105.

use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct ReadMarkers {
    markers: HashMap<(String, String), ReadPosition>,
}

#[derive(Debug, Default)]
struct ReadPosition {
    cursor: u64,
    revision: u64,
}

impl ReadMarkers {
    pub fn new() -> Self {
        Self::default()
    }

    /// Move the user's read marker in a room to `cursor`. A marker never moves backwards; returns whether it moved.
    pub fn mark_read(&mut self, user: &str, room: &str, cursor: u64) -> bool {
        let key = (user.to_string(), room.to_string());
        let marker = self.markers.entry(key).or_default();
        if marker.cursor >= cursor {
            return false;
        }
        marker.cursor = cursor;
        marker.revision = marker.revision.saturating_add(1);
        true
    }

    /// Set the position immediately before the chosen message (task T344). Unlike `mark_read`, this is exact.
    /// The personal revision changes only when the position changes, including when it moves backwards.
    pub fn mark_unread(&mut self, user: &str, room: &str, cursor: u64) -> bool {
        let marker = self.markers.entry((user.to_owned(), room.to_owned())).or_default();
        if marker.cursor == cursor {
            return false;
        }
        marker.cursor = cursor;
        marker.revision = marker.revision.saturating_add(1);
        true
    }

    /// The user's marker in the room; 0 if never set.
    pub fn last_read(&self, user: &str, room: &str) -> u64 {
        self.markers.get(&(user.to_string(), room.to_string())).map_or(0, |marker| marker.cursor)
    }

    /// The personal position's revision, independent of the room event cursor (task T344).
    pub fn revision(&self, user: &str, room: &str) -> u64 {
        self.markers.get(&(user.to_owned(), room.to_owned())).map_or(0, |marker| marker.revision)
    }

    /// How many of `messages` (cursor, author) come after the user's marker and were written by someone else.
    pub fn unread(&self, user: &str, room: &str, messages: &[(u64, &str)]) -> usize {
        let cursor = self.last_read(user, room);
        messages.iter().filter(|&&(message_cursor, author)| message_cursor > cursor && author != user).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_rewinds_and_later_reading_have_personal_effective_change_revisions() {
        let mut markers = ReadMarkers::new();
        let messages = [(2, "writer"), (4, "reader"), (6, "writer")];
        assert!(markers.mark_read("reader", "room", 6));
        assert_eq!(markers.unread("reader", "room", &messages), 0);
        assert!(markers.mark_unread("reader", "room", 1));
        assert_eq!(markers.unread("reader", "room", &messages), 2);
        assert_eq!(markers.revision("reader", "room"), 2);
        assert!(!markers.mark_unread("reader", "room", 1));
        assert!(!markers.mark_read("reader", "room", 0));
        assert_eq!(markers.revision("reader", "room"), 2);
        assert!(markers.mark_unread("reader", "room", 5));
        assert_eq!(markers.last_read("reader", "room"), 5);
        assert_eq!(markers.unread("reader", "room", &messages), 1);
        assert!(markers.mark_read("reader", "room", u64::MAX));
        assert_eq!(markers.revision("reader", "room"), 4);
        assert_eq!(markers.unread("reader", "room", &messages), 0);
        assert_eq!(markers.last_read("another", "room"), 0);
        assert_eq!(markers.revision("another", "room"), 0);
        assert_eq!(markers.last_read("reader", "another"), 0);
        assert_eq!(markers.revision("reader", "another"), 0);
    }
}
