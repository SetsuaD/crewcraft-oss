//! A `server::Server` (T122) that survives a restart: every change it accepts is appended to a journal (`journal`, T140)
//! as an `op::Op` (T143), and opening the journal replays them into a fresh server. Presence and rate-limit state are
//! not stored (replaying the recorded times rebuilds the buckets). Task T144.

use std::path::Path;

use crate::journal::JournalError;
use crate::room::Role;
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
    _todo: (),
}

impl DurableServer {
    /// Open the journal at `path` (as `Journal::open`, creating it if missing) and replay its records in order into a
    /// fresh `Server`: `CreateRoom`, `AddMember`, `RemoveMember`, `Post`, `Edit`, `Delete` and `MarkRead` call the
    /// matching `Server` method with the recorded fields. Any record that does not decode, or that the server refuses,
    /// is `Corrupt { index }`.
    pub fn open(path: &Path) -> Result<Self, DurableError> {
        let _ = path;
        todo!("T144: durable server")
    }

    /// The server, for reads (`room`, `rooms_of`, `online_in`).
    pub fn server(&self) -> &Server {
        todo!("T144: durable server")
    }

    /// Every change below first fails with `Poisoned` if the server is poisoned. Then it calls the matching `Server`
    /// method; a refusal is `Server(e)` and nothing is recorded. If the server accepts it, the matching `Op` is encoded
    /// and appended to the journal before the call returns; if that append fails, the call returns `Journal(e)` and the
    /// server is poisoned.
    pub fn create_room(&mut self, owner: &str, name: &str) -> Result<String, DurableError> {
        let _ = (owner, name);
        todo!("T144: durable server")
    }

    pub fn add_member(&mut self, slug: &str, actor: &str, user: &str, role: Role) -> Result<u64, DurableError> {
        let _ = (slug, actor, user, role);
        todo!("T144: durable server")
    }

    pub fn remove_member(&mut self, slug: &str, actor: &str, user: &str) -> Result<u64, DurableError> {
        let _ = (slug, actor, user);
        todo!("T144: durable server")
    }

    pub fn post(&mut self, slug: &str, author: &str, text: &str, now_ms: u64) -> Result<u64, DurableError> {
        let _ = (slug, author, text, now_ms);
        todo!("T144: durable server")
    }

    pub fn edit(&mut self, slug: &str, actor: &str, target: u64, text: &str, now_ms: u64) -> Result<u64, DurableError> {
        let _ = (slug, actor, target, text, now_ms);
        todo!("T144: durable server")
    }

    pub fn delete(&mut self, slug: &str, actor: &str, target: u64) -> Result<u64, DurableError> {
        let _ = (slug, actor, target);
        todo!("T144: durable server")
    }

    /// As above, except that a `MarkRead` is recorded only when the marker moved (`Ok(true)`).
    pub fn mark_read(&mut self, slug: &str, user: &str, cursor: u64) -> Result<bool, DurableError> {
        let _ = (slug, user, cursor);
        todo!("T144: durable server")
    }
}
