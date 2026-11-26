//! The composer at the bottom of the main pane: one draft per room, kept while the user switches rooms, and the
//! rules for when a draft may be sent. Task T301.

use std::collections::HashMap;

use crate::{Command, DraftError, MAX_DRAFT_CHARS};

/// The user's unsent text, per room.
#[derive(Debug, Default)]
pub struct Composer {
    /// Room name -> draft exactly as typed. A room with no draft has no entry.
    drafts: HashMap<String, String>,
}

impl Composer {
    /// No drafts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the room's draft with `text`, exactly as typed (no trimming here). An empty `text` clears it.
    pub fn set(&mut self, room: &str, text: &str) {
        if text.is_empty() {
            self.drafts.remove(room);
        } else {
            self.drafts.insert(room.to_owned(), text.to_owned());
        }
    }

    /// The room's draft, or "" when it has none.
    pub fn draft(&self, room: &str) -> &str {
        self.drafts.get(room).map_or("", String::as_str)
    }

    /// Send the room's draft. The text sent is the draft with leading and trailing whitespace removed (inner
    /// newlines and spaces are kept). Refuses with `DraftError::Empty` when nothing is left, and `DraftError::TooLong`
    /// when more than `MAX_DRAFT_CHARS` characters are left; a refusal keeps the draft unchanged. On success the
    /// room's draft is cleared and `Command::Post` is returned; other rooms' drafts are untouched.
    pub fn submit(&mut self, room: &str) -> Result<Command, DraftError> {
        let text = self.checked(room)?;
        let command = Command::Post { room: room.to_owned(), text };
        self.drafts.remove(room);
        Ok(command)
    }

    /// As `submit`, but the draft replaces the text of the message at cursor `target` (task T316): `Command::Edit`,
    /// with the same trimming and the same refusals.
    pub fn submit_edit(&mut self, room: &str, target: u64) -> Result<Command, DraftError> {
        let text = self.checked(room)?;
        let command = Command::Edit { room: room.to_owned(), target, text };
        self.drafts.remove(room);
        Ok(command)
    }

    fn checked(&self, room: &str) -> Result<String, DraftError> {
        let text = self.draft(room).trim();
        if text.is_empty() {
            return Err(DraftError::Empty);
        }
        if text.chars().count() > MAX_DRAFT_CHARS {
            return Err(DraftError::TooLong);
        }
        Ok(text.to_owned())
    }
}
