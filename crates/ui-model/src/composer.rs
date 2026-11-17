//! The composer at the bottom of the main pane: one draft per room, kept while the user switches rooms, and the
//! rules for when a draft may be sent. Task T301.

use crate::{Command, DraftError};

/// The user's unsent text, per room.
#[derive(Debug, Default)]
pub struct Composer {
    _todo: (),
}

#[allow(clippy::todo, reason = "stubs until task T301 lands; remove this allow with them")]
impl Composer {
    /// No drafts.
    pub fn new() -> Self {
        Self { _todo: () }
    }

    /// Replace the room's draft with `text`, exactly as typed (no trimming here). An empty `text` clears it.
    pub fn set(&mut self, room: &str, text: &str) {
        let _ = (room, text);
        todo!("T301: Composer::set")
    }

    /// The room's draft, or "" when it has none.
    pub fn draft(&self, room: &str) -> &str {
        let _ = room;
        todo!("T301: Composer::draft")
    }

    /// Send the room's draft. The text sent is the draft with leading and trailing whitespace removed (inner
    /// newlines and spaces are kept). Refuses with `DraftError::Empty` when nothing is left, and `DraftError::TooLong`
    /// when more than `MAX_DRAFT_CHARS` characters are left; a refusal keeps the draft unchanged. On success the
    /// room's draft is cleared and `Command::Post` is returned; other rooms' drafts are untouched.
    pub fn submit(&mut self, room: &str) -> Result<Command, DraftError> {
        let _ = room;
        todo!("T301: Composer::submit")
    }
}
