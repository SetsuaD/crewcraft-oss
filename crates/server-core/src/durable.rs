//! A `server::Server` (T122) that survives a restart: every change it accepts is appended to a journal (`journal`, T140)
//! as an `op::Op` (T143), and opening the journal replays them into a fresh server. Presence and rate-limit state are
//! not stored (replaying the recorded times rebuilds the buckets). Task T144.
//!
//! Search (task T320a): the server keeps a `room_search::RoomSearch` up to date with every message it accepts and every
//! message it replays. Each message is indexed when it is accepted or replayed, so the index keeps messages a room's
//! in-memory log has since dropped. `search` answers only from rooms the asking person is a member of now.

use std::path::Path;

use std::collections::{HashMap, HashSet};

use crewcraft_proto::message::MAX_NAME;
use crewcraft_proto::request::{MAX_AUTHOR, MAX_HITS, MAX_SNIPPET, SearchHit};

use crate::cursor_log::Since;
use crate::html_text::html_text;
use crate::journal::{Journal, JournalError};
use crate::op::{Op, decode_op, encode_op};
use crate::room::Role;
use crate::room_search::{Hit, RoomSearch};
use crate::room_service::EventKind;
use crate::server::{Server, ServerError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableError {
    /// The server refused the change (nothing is recorded).
    Server(ServerError),
    /// The journal could not be opened or written.
    Journal(JournalError),
    /// Record `index` (0-based, in journal order) does not decode, or the server refuses it on replay.
    Corrupt { index: usize },
    /// An earlier journal write failed after the change was made in memory, so memory and disk disagree; every change
    /// is refused until the journal is opened again.
    Poisoned,
}

pub struct DurableServer {
    server: Server,
    journal: Journal,
    poisoned: bool,
    /// Every message's searchable text, by room (task T320a).
    search: RoomSearch,
    /// Every live message's author and current plain text, by room and cursor, for search results (task T320b).
    previews: HashMap<String, HashMap<u64, (String, String)>>,
    /// Every finished upload's record, by file id (docs/FILES.md, task T330a).
    files: HashMap<[u8; 16], StoredFile>,
}

/// A finished upload (task T330a): its room, uploader, bytes (by SHA-256), size, name and, for an image, its size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFile {
    pub room: String,
    pub uploader: String,
    pub sha256: [u8; 32],
    pub size: u64,
    pub name: String,
    pub image: Option<(u32, u32)>,
}

/// Why a file record was refused (task T330a). Nothing is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileError {
    /// The uploader is not a member of the room, or the room does not exist.
    NotMember,
    /// The name is empty, longer than `MAX_FILE_NAME` bytes, `.` or `..`, or holds a path separator or a control
    /// character.
    BadName,
    /// The size is 0.
    Empty,
    /// A file with this id is already recorded.
    DuplicateId,
    /// The journal refused it, or the server is poisoned.
    Durable(DurableError),
}

/// The longest file name, in bytes.
pub const MAX_FILE_NAME: usize = 255;

/// Whether `name` can name a file: 1 to `MAX_FILE_NAME` bytes, not `.` or `..`, no `/`, `\\` or control character.
pub fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_FILE_NAME
        && name != "."
        && name != ".."
        && !name.chars().any(|c| c == '/' || c == '\\' || c.is_control())
}

/// The most hits one search returns (task T320a).
pub const MAX_SEARCH_HITS: usize = 100;

impl DurableServer {
    /// Open the journal at `path` (as `Journal::open`, creating it if missing) and replay its records in order into a
    /// fresh `Server`: `CreateRoom`, `AddMember`, `RemoveMember`, `Post`, `Edit`, `Delete` and `MarkRead` call the
    /// matching `Server` method with the recorded fields. Any record that does not decode, or that the server refuses,
    /// is `Corrupt { index }`.
    pub fn open(path: &Path) -> Result<Self, DurableError> {
        let (journal, records) = Journal::open(path).map_err(DurableError::Journal)?;
        let mut server = Server::new();
        let mut search = RoomSearch::new();
        let mut previews = HashMap::new();
        let mut files = HashMap::new();
        for (index, record) in records.iter().enumerate() {
            let op = decode_op(record).map_err(|_| DurableError::Corrupt { index })?;
            if let Op::FileStored { slug, uploader, file, sha256, size, name, image } = op {
                check_file(&server, &files, &slug, &uploader, &file, size, &name).map_err(|_| DurableError::Corrupt { index })?;
                files.insert(file, StoredFile { room: slug, uploader, sha256, size, name, image });
                continue;
            }
            let indexed = searchable(&op);
            let cursor = replay(&mut server, op).map_err(|_| DurableError::Corrupt { index })?;
            if let Some((slug, actor)) = indexed {
                index_event(&server, &mut search, &mut previews, &slug, &actor, cursor);
            }
        }
        Ok(Self { server, journal, poisoned: false, search, previews, files })
    }

    /// Record a finished upload (task T330a). Call it only after `file_store::FileStore::finish` returned `Ok` for these
    /// bytes: the record is the file's existence. The uploader must be a member of `slug` now.
    #[allow(clippy::too_many_arguments)]
    pub fn record_file(
        &mut self,
        slug: &str,
        uploader: &str,
        file: [u8; 16],
        sha256: [u8; 32],
        size: u64,
        name: &str,
        image: Option<(u32, u32)>,
    ) -> Result<(), FileError> {
        self.check_alive().map_err(FileError::Durable)?;
        check_file(&self.server, &self.files, slug, uploader, &file, size, name)?;
        let op = Op::FileStored { slug: slug.to_owned(), uploader: uploader.to_owned(), file, sha256, size, name: name.to_owned(), image };
        self.record(&op).map_err(FileError::Durable)?;
        self.files.insert(file, StoredFile { room: slug.to_owned(), uploader: uploader.to_owned(), sha256, size, name: name.to_owned(), image });
        Ok(())
    }

    /// The record of file `file`, if there is one. Whether someone may read it is the caller's to decide.
    pub fn file(&self, file: &[u8; 16]) -> Option<&StoredFile> {
        self.files.get(file)
    }

    /// The SHA-256 of every recorded file's bytes: what `FileStore::sweep` must keep.
    pub fn referenced_hashes(&self) -> HashSet<[u8; 32]> {
        self.files.values().map(|file| file.sha256).collect()
    }

    /// `search`, with each hit's author and the start of its current plain text (task T320b): what a hits frame
    /// carries (`proto::request::encode_hits`), at most `request::MAX_HITS`.
    pub fn found(&self, user: &str, query: &str) -> Vec<SearchHit> {
        self.search(user, query, MAX_HITS)
            .into_iter()
            .filter(|hit| !hit.slug.is_empty() && hit.slug.len() <= MAX_NAME)
            .map(|hit| {
                let (author, text) = self.previews.get(&hit.slug).and_then(|room| room.get(&hit.cursor)).cloned().unwrap_or_default();
                SearchHit { room: hit.slug, cursor: hit.cursor, author: clip(&author, MAX_AUTHOR), snippet: clip(&text, MAX_SNIPPET) }
            })
            .collect()
    }

    /// Up to `limit` (at most `MAX_SEARCH_HITS`) messages matching `query` in the rooms `user` is a member of, newest
    /// first (`room_search::RoomSearch::search`; every word of the query must start a word of the message). Edited
    /// messages are found by their current text; deleted ones are not found.
    pub fn search(&self, user: &str, query: &str, limit: usize) -> Vec<Hit> {
        self.search.search(&self.server, user, query, limit.min(MAX_SEARCH_HITS))
    }

    /// The server, for reads (`room`, `rooms_of`, `online_in`).
    pub fn server(&self) -> &Server {
        &self.server
    }

    /// Every change below first fails with `Poisoned` if the server is poisoned. Then it calls the matching `Server`
    /// method; a refusal is `Server(e)` and nothing is recorded. If the server accepts it, the matching `Op` is encoded
    /// and appended to the journal before the call returns; if that append fails, the call returns `Journal(e)` and the
    /// server is poisoned.
    pub fn create_room(&mut self, owner: &str, name: &str) -> Result<String, DurableError> {
        self.check_alive()?;
        let slug = self.server.create_room(owner, name).map_err(DurableError::Server)?;
        self.record(&Op::CreateRoom { owner: owner.to_string(), name: name.to_string() })?;
        Ok(slug)
    }

    pub fn add_member(&mut self, slug: &str, actor: &str, user: &str, role: Role) -> Result<u64, DurableError> {
        self.check_alive()?;
        let cursor = self.server.add_member(slug, actor, user, role).map_err(DurableError::Server)?;
        self.record(&Op::AddMember { slug: slug.to_string(), actor: actor.to_string(), user: user.to_string(), role })?;
        Ok(cursor)
    }

    pub fn remove_member(&mut self, slug: &str, actor: &str, user: &str) -> Result<u64, DurableError> {
        self.check_alive()?;
        let cursor = self.server.remove_member(slug, actor, user).map_err(DurableError::Server)?;
        self.record(&Op::RemoveMember { slug: slug.to_string(), actor: actor.to_string(), user: user.to_string() })?;
        Ok(cursor)
    }

    pub fn post(&mut self, slug: &str, author: &str, text: &str, now_ms: u64) -> Result<u64, DurableError> {
        self.check_alive()?;
        let cursor = self.server.post(slug, author, text, now_ms).map_err(DurableError::Server)?;
        self.record(&Op::Post { slug: slug.to_string(), author: author.to_string(), text: text.to_string(), now_ms })?;
        index_event(&self.server, &mut self.search, &mut self.previews, slug, author, cursor);
        Ok(cursor)
    }

    pub fn edit(&mut self, slug: &str, actor: &str, target: u64, text: &str, now_ms: u64) -> Result<u64, DurableError> {
        self.check_alive()?;
        let cursor = self.server.edit(slug, actor, target, text, now_ms).map_err(DurableError::Server)?;
        self.record(&Op::Edit { slug: slug.to_string(), actor: actor.to_string(), target, text: text.to_string(), now_ms })?;
        index_event(&self.server, &mut self.search, &mut self.previews, slug, actor, cursor);
        Ok(cursor)
    }

    pub fn delete(&mut self, slug: &str, actor: &str, target: u64) -> Result<u64, DurableError> {
        self.check_alive()?;
        let cursor = self.server.delete(slug, actor, target).map_err(DurableError::Server)?;
        self.record(&Op::Delete { slug: slug.to_string(), actor: actor.to_string(), target })?;
        index_event(&self.server, &mut self.search, &mut self.previews, slug, actor, cursor);
        Ok(cursor)
    }

    /// As above, except that a `MarkRead` is recorded only when the marker moved (`Ok(true)`).
    pub fn mark_read(&mut self, slug: &str, user: &str, cursor: u64) -> Result<bool, DurableError> {
        self.check_alive()?;
        let moved = self.server.mark_read(slug, user, cursor).map_err(DurableError::Server)?;
        if moved {
            self.record(&Op::MarkRead { slug: slug.to_string(), user: user.to_string(), cursor })?;
        }
        Ok(moved)
    }

    pub(crate) fn check_alive(&self) -> Result<(), DurableError> {
        if self.poisoned { Err(DurableError::Poisoned) } else { Ok(()) }
    }

    /// Append `op` to the journal. The change is already in memory, so a failure poisons the server: memory is ahead of
    /// disk, and acting on it further would let a restart lose changes callers were told succeeded. An op the codec
    /// cannot encode is reported as `TooLarge`; `Server` limits keep every accepted change well under the codec's.
    fn record(&mut self, op: &Op) -> Result<(), DurableError> {
        let result = match encode_op(op) {
            Ok(bytes) => self.journal.append(&bytes),
            Err(_) => Err(JournalError::TooLarge),
        };
        result.map_err(|e| {
            self.poisoned = true;
            DurableError::Journal(e)
        })
    }
}

/// Apply one recorded change to `server`, as the call that made it did, and return the cursor it made (0 for changes
/// that make none).
fn replay(server: &mut Server, op: Op) -> Result<u64, ServerError> {
    match op {
        Op::CreateRoom { owner, name } => server.create_room(&owner, &name).map(|_| 0),
        Op::AddMember { slug, actor, user, role } => server.add_member(&slug, &actor, &user, role),
        Op::RemoveMember { slug, actor, user } => server.remove_member(&slug, &actor, &user),
        Op::Post { slug, author, text, now_ms } => server.post(&slug, &author, &text, now_ms),
        Op::Edit { slug, actor, target, text, now_ms } => server.edit(&slug, &actor, target, &text, now_ms),
        Op::Delete { slug, actor, target } => server.delete(&slug, &actor, target),
        Op::MarkRead { slug, user, cursor } => server.mark_read(&slug, &user, cursor).map(|_| 0),
        // Handled before `replay` is called: a file record changes no room.
        Op::FileStored { .. } => Ok(0),
    }
}

/// The checks a file record must pass, when it is made and when it is replayed.
fn check_file(
    server: &Server,
    files: &HashMap<[u8; 16], StoredFile>,
    slug: &str,
    uploader: &str,
    file: &[u8; 16],
    size: u64,
    name: &str,
) -> Result<(), FileError> {
    if !server.room(slug).is_ok_and(|room| room.role(uploader).is_some()) {
        return Err(FileError::NotMember);
    }
    if !valid_file_name(name) {
        return Err(FileError::BadName);
    }
    if size == 0 {
        return Err(FileError::Empty);
    }
    if files.contains_key(file) {
        return Err(FileError::DuplicateId);
    }
    Ok(())
}

/// The room and the person of a change that search indexes: a post, an edit or a deletion.
fn searchable(op: &Op) -> Option<(String, String)> {
    match op {
        Op::Post { slug, author, .. } => Some((slug.clone(), author.clone())),
        Op::Edit { slug, actor, .. } | Op::Delete { slug, actor, .. } => Some((slug.clone(), actor.clone())),
        _ => None,
    }
}

/// Index the event the change by `actor` just made at `cursor` in room `slug`, read back from the room's log (the
/// actor is a member: the change was accepted), and keep the message's preview: its author and current text.
fn index_event(
    server: &Server,
    search: &mut RoomSearch,
    previews: &mut HashMap<String, HashMap<u64, (String, String)>>,
    slug: &str,
    actor: &str,
    cursor: u64,
) {
    let Ok(room) = server.room(slug) else { return };
    let Ok(Since::Events(events)) = room.sync(actor, cursor.saturating_sub(1)) else { return };
    let Some((at, event)) = events.iter().find(|(at, _)| *at == cursor) else { return };
    search.index(slug, *at, event);
    let room = previews.entry(slug.to_owned()).or_default();
    match &event.kind {
        EventKind::Posted => {
            room.insert(*at, (event.actor.clone(), html_text(&event.html)));
        }
        EventKind::Edited { target } => {
            if let Some((_, text)) = room.get_mut(target) {
                *text = html_text(&event.html);
            }
        }
        EventKind::Deleted { target } => {
            room.remove(target);
        }
        EventKind::Joined { .. } | EventKind::Left { .. } => {}
    }
}

/// At most `max` bytes of `text`, cut at a character boundary.
fn clip(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}
