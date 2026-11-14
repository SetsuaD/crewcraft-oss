//! The client's copy of one room's messages, built from the server's events in cursor order. Task T121.

/// What one server event does to the client's view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    Posted {
        author: String,
        html: String,
    },
    Edited {
        target: u64,
        html: String,
    },
    Deleted {
        target: u64,
    },
    /// Any other event (membership, settings): it only advances the cursor.
    Other,
}

/// One message as the client shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The cursor of the event that posted it.
    pub cursor: u64,
    pub author: String,
    pub html: String,
    /// Whether it has been edited since it was posted.
    pub edited: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Apply {
    /// The event was applied and the cursor moved to it.
    Applied,
    /// Its cursor is at or below the current one: ignored (events can arrive twice).
    Duplicate,
    /// Its cursor is past `cursor() + 1`: something was missed, so it is ignored and the client must resync
    /// (fetch a snapshot and call `reset`).
    NeedsResync,
}

#[derive(Debug, Default)]
pub struct Timeline {
    cursor: u64,
    lines: Vec<Line>,
}

impl Timeline {
    pub fn new() -> Self {
        Self { cursor: 0, lines: Vec::new() }
    }

    /// The cursor of the last event applied, or of the last snapshot; 0 at first.
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Apply the event at `cursor`. Only `cursor() + 1` is applied (see `Apply`). `Posted` appends a line; `Edited`
    /// replaces the target line's html and marks it edited; `Deleted` removes the target line. An `Edited` or `Deleted`
    /// whose target line is not held is still `Applied` (the cursor moves) and changes no line.
    pub fn apply(&mut self, cursor: u64, change: Change) -> Apply {
        if cursor <= self.cursor {
            return Apply::Duplicate;
        }
        if cursor > self.cursor + 1 {
            return Apply::NeedsResync;
        }

        match change {
            Change::Posted { author, html } => {
                self.lines.push(Line { cursor, author, html, edited: false });
            }
            Change::Edited { target, html } => {
                if let Some(line) = self.lines.iter_mut().find(|l| l.cursor == target) {
                    line.html = html;
                    line.edited = true;
                }
            }
            Change::Deleted { target } => {
                self.lines.retain(|l| l.cursor != target);
            }
            Change::Other => {}
        }

        self.cursor = cursor;
        Apply::Applied
    }

    /// Replace the whole view with a snapshot that is current up to `cursor`. The lines are kept sorted by cursor
    /// whatever order they arrive in.
    pub fn reset(&mut self, mut lines: Vec<Line>, cursor: u64) {
        lines.sort_by_key(|l| l.cursor);
        self.lines = lines;
        self.cursor = cursor;
    }

    /// The lines, oldest (lowest cursor) first.
    pub fn lines(&self) -> &[Line] {
        &self.lines
    }
}
