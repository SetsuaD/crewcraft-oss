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
    /// Replace the text of one of the person's own messages, `target` being its cursor (task T316). `text` is trimmed
    /// and within `MAX_DRAFT_CHARS`, as for `Post`.
    Edit { room: String, target: u64, text: String },
    /// Delete one of the person's own messages, `target` being its cursor (task T316).
    Delete { room: String, target: u64 },
    /// Find messages in every room the person is in (task T320c). `query` is trimmed, 1 to 200 bytes.
    Search { query: String },
    /// Reply to the message at `parent` in `room`, in its thread (task T340b). `text` is trimmed and within
    /// `MAX_DRAFT_CHARS`.
    Reply { room: String, parent: u64, text: String },
    /// List the files in the person's rooms (task T331b).
    ListFiles,
    /// Start a call in `room` (with video or not), or join its open one (task T360a2).
    CallStart { room: String, video: bool },
    /// Join the open call `call` of `room` (task T360a2).
    CallJoin { room: String, call: u64 },
    /// Leave call `call` of `room` (task T360a2).
    CallLeave { room: String, call: u64 },
    /// Add (`on`) or take back the reaction with code `reaction` (see `crewcraft_proto::push::REACTIONS`) on the message
    /// at `target` in `room` (task T341b).
    React { room: String, target: u64, reaction: u8, on: bool },
    /// Upload the file at `path` to `room`, to attach to the next post there (task T330e).
    Attach { room: String, path: std::path::PathBuf },
    /// Post `text` (may be empty) with `files`, uploads made with `Attach` (task T330e).
    PostFiles { room: String, text: String, files: Vec<[u8; 16]> },
    /// Save file `file` (`size` bytes, named `name`) to `to`, or, with `None`, to a new file in the person's
    /// Downloads folder (task T330e).
    Save { file: [u8; 16], size: u64, name: String, to: Option<std::path::PathBuf> },
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

/// Who reacted to one message (task T341b): each reaction code, in order, with the people, sorted.
pub type MessageReactions = Vec<(u8, Vec<String>)>;

/// Who reacted to the messages of a room (task T341b), by cursor.
pub type RoomReactions = Vec<(u64, MessageReactions)>;
