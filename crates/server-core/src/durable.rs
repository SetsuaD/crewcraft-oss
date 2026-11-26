//! A `server::Server` (T122) that survives a restart: every change it accepts is appended to a journal (`journal`, T140)
//! as an `op::Op` (T143), and opening the journal replays them into a fresh server. Presence and rate-limit state are
//! not stored (replaying the recorded times rebuilds the buckets). Task T144.
//!
//! Search (task T320a): the server keeps a `room_search::RoomSearch` up to date with every message it accepts and every
//! message it replays. Each message is indexed when it is accepted or replayed, so the index keeps messages a room's
//! in-memory log has since dropped. `search` answers only from rooms the asking person is a member of now.

use std::path::Path;

use crate::cursor_log::Since;
use crate::journal::{Journal, JournalError};
use crate::op::{Op, decode_op, encode_op};
use crate::room::Role;
use crate::room_search::{Hit, RoomSearch};
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
        for (index, record) in records.iter().enumerate() {
            let op = decode_op(record).map_err(|_| DurableError::Corrupt { index })?;
            let indexed = searchable(&op);
            let cursor = replay(&mut server, op).map_err(|_| DurableError::Corrupt { index })?;
            if let Some((slug, actor)) = indexed {
                index_event(&server, &mut search, &slug, &actor, cursor);
            }
        }
        Ok(Self { server, journal, poisoned: false, search })
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
        index_event(&self.server, &mut self.search, slug, author, cursor);
        Ok(cursor)
    }

    pub fn edit(&mut self, slug: &str, actor: &str, target: u64, text: &str, now_ms: u64) -> Result<u64, DurableError> {
        self.check_alive()?;
        let cursor = self.server.edit(slug, actor, target, text, now_ms).map_err(DurableError::Server)?;
        self.record(&Op::Edit { slug: slug.to_string(), actor: actor.to_string(), target, text: text.to_string(), now_ms })?;
        index_event(&self.server, &mut self.search, slug, actor, cursor);
        Ok(cursor)
    }

    pub fn delete(&mut self, slug: &str, actor: &str, target: u64) -> Result<u64, DurableError> {
        self.check_alive()?;
        let cursor = self.server.delete(slug, actor, target).map_err(DurableError::Server)?;
        self.record(&Op::Delete { slug: slug.to_string(), actor: actor.to_string(), target })?;
        index_event(&self.server, &mut self.search, slug, actor, cursor);
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
    }
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
/// actor is a member: the change was accepted).
fn index_event(server: &Server, search: &mut RoomSearch, slug: &str, actor: &str, cursor: u64) {
    let Ok(room) = server.room(slug) else { return };
    let Ok(Since::Events(events)) = room.sync(actor, cursor.saturating_sub(1)) else { return };
    if let Some((at, event)) = events.iter().find(|(at, _)| *at == cursor) {
        search.index(slug, *at, event);
    }
}
