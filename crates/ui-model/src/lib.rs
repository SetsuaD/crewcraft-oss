//! What a CrewCraft client shows and what it asks the connection to do, with no drawing and no I/O.
//!
//! Owns: the room list (`room_list`, T300), the composer's drafts (`composer`, T301) and the feed rows a conversation
//! is drawn from (`feed`, T302), plus the contract types below. Called by: the desktop client (egui), and later the
//! web client and the phone shells. Calls: `crewcraft-client-core` for `room_view::Shown`.
//!
//! The UI thread owns these values. It hands each `Command` to the connection worker, which owns the chat session,
//! and gets back room snapshots (`Vec<Shown>`) and unread counts. Nothing here blocks, draws or touches the network,
//! so all of it is tested without a window.

pub mod composer;
pub mod feed;
pub mod room_list;

/// Longest message the composer submits, in characters (`char`s) after trimming. It matches the server's limit
/// (`crewcraft_server_core::room_service::MAX_TEXT_CHARS`), so a draft the composer accepts is never refused for length.
pub const MAX_DRAFT_CHARS: usize = 4000;

/// Something the UI asks the connection worker to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Fetch the room's current messages (a snapshot), for example when the room is opened.
    Sync { room: String },
    /// Post `text` to `room`. `text` is already trimmed and within `MAX_DRAFT_CHARS`.
    Post { room: String, text: String },
}

/// Why the composer did not submit. The draft is kept unchanged in every case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DraftError {
    /// Nothing but whitespace.
    Empty,
    /// Longer than `MAX_DRAFT_CHARS` after trimming.
    TooLong,
}

/// One row of a conversation feed, top to bottom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedRow {
    /// A message from the server's timeline.
    Message {
        /// The cursor of the event that posted it (stable across edits; the key for edit and delete).
        cursor: u64,
        author: String,
        /// The message's sanitised HTML, unchanged from the timeline.
        html: String,
        edited: bool,
        /// Whether this row starts a new run of messages, so the author's name and picture are drawn above it: true
        /// unless the row directly above is a `Message` from the same author.
        first_of_group: bool,
    },
    /// The user's own message that the server has not acknowledged yet. `failed` when sending gave up.
    Pending { id: u64, body: String, failed: bool },
}

/// One entry of the room list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomRow {
    pub name: String,
    /// Messages from other people the user has not seen. Always 0 for the selected room.
    pub unread: u32,
    pub selected: bool,
}
