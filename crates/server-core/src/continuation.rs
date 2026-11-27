//! Continuing an archived conversation (docs/REQUIREMENTS.md "Continuing a conversation", docs/IMPORT.md, task T352).
//! An archived one-to-one conversation between two people who both have accounts now continues in their direct
//! message: the one they already have, or a new one, never a second. Any other archive continues in one new group room
//! with the archive's linked people. Either way the room gets a line, built here, that links back to the archive.
//!
//! Owns: `Continuations` (rebuilt from the journal), the continuation records' replay (`replay`, called by
//! `DurableServer::open`), `DurableServer::continue_archive`, and `DurableServer::mark_direct` (called by the import
//! for each one-to-one conversation). Calls `server::Server` (rooms, members, the line) and `durable` (records).
//!
//! An archive's linked people are its members other than `import::ARCHIVE_OWNER`: an import adds only people who have
//! accounts, and a later run adds the rest once they do (deferred author linking). So an author without an account is
//! never a member of the archive, and continuing it never adds them anywhere. Only someone who can read the archive (a
//! member) may continue it.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::durable::{DurableError, DurableServer};
use crate::import::ARCHIVE_OWNER;
use crate::op::Op;
use crate::room::Role;
use crate::server::{Server, ServerError};

/// What continuing archives has made, rebuilt from the continuation records on every start.
#[derive(Debug, Clone, Default)]
pub struct Continuations {
    /// Archive rooms that were one-to-one conversations in their source.
    direct: HashSet<String>,
    /// The room each continued archive continues in.
    continued: HashMap<String, String>,
    /// Each pair's direct message, by their two addresses in order.
    directs: BTreeMap<(String, String), String>,
}

/// Why an archive was not continued. Nothing changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinueError {
    /// No such room, or the person is not one who can read it.
    NotReadable,
    /// The room is not an archive.
    NotArchive,
    /// The room could not be made, or the journal failed (the server is then poisoned).
    Durable(DurableError),
}

/// Apply a continuation record at start-up, as the change that wrote it did: `None` once applied, any other record
/// handed back untouched. `Err` means the journal does not match (corrupt).
pub(crate) fn replay(server: &mut Server, state: &mut Continuations, op: Op) -> Result<Option<Op>, ()> {
    match op {
        Op::ArchiveDirect { slug } => {
            if !server.room(&slug).is_ok_and(|room| room.is_read_only()) {
                return Err(());
            }
            state.direct.insert(slug);
            Ok(None)
        }
        Op::Continue { archive, actor, direct, people, .. } => {
            apply(server, state, &archive, &actor, direct, &people).map_err(|_| ())?;
            Ok(None)
        }
        other => Ok(Some(other)),
    }
}

/// Make the change one `Continue` record describes, on a live request and on replay alike, and return the room the
/// archive continues in. For a direct conversation that is the pair's direct message while both are still in it, or a
/// new one; otherwise the archive's continuation room, made with `people` the first time and given any of `people` it
/// lacks later. The room gets the line that links back to the archive the first time it continues that archive.
fn apply(server: &mut Server, state: &mut Continuations, archive: &str, actor: &str, direct: bool, people: &[String]) -> Result<String, ServerError> {
    let name = server.room_name(archive).ok_or(ServerError::NoSuchRoom)?.to_owned();
    let room = match (direct, people) {
        (true, [first, second]) => {
            let pair = (first.clone(), second.clone());
            match state.directs.get(&pair).filter(|room| has_all(server, room, people)).cloned() {
                Some(room) => room,
                None => {
                    let room = server.create_room(first, &pair_name(first, second))?;
                    server.add_member(&room, first, second, Role::Owner)?;
                    state.directs.insert(pair, room.clone());
                    room
                }
            }
        }
        (true, _) => return Err(ServerError::NoSuchRoom),
        (false, _) => match state.continued.get(archive).cloned() {
            Some(room) => {
                let owner = owner_of(server, &room)?;
                for person in people {
                    if server.room(&room)?.role(person).is_none() {
                        server.add_member(&room, &owner, person, Role::Member)?;
                    }
                }
                room
            }
            None => {
                let room = server.create_room(actor, &name)?;
                for person in people.iter().filter(|person| *person != actor) {
                    server.add_member(&room, actor, person, Role::Member)?;
                }
                room
            }
        },
    };
    if state.continued.get(archive) != Some(&room) {
        let text = format!("{actor} continued the archived conversation \"{name}\" here.");
        server.continued_line(&room, actor, archive, &text)?;
        state.continued.insert(archive.to_owned(), room.clone());
    }
    Ok(room)
}

/// Whether every one of `people` is a member of `room`.
fn has_all(server: &Server, room: &str, people: &[String]) -> bool {
    server.room(room).is_ok_and(|service| people.iter().all(|person| service.role(person).is_some()))
}

/// An Owner of `room`: every room has one.
fn owner_of(server: &Server, room: &str) -> Result<String, ServerError> {
    let members = server.room(room)?.members();
    members.into_iter().find(|(_, role)| *role == Role::Owner).map(|(member, _)| member).ok_or(ServerError::NoSuchRoom)
}

/// A direct message's name: its two people, by the part of their address before the `@`.
fn pair_name(first: &str, second: &str) -> String {
    let local = |email: &str| email.split('@').next().unwrap_or(email).to_owned();
    let name: String = format!("{} and {}", local(first), local(second)).chars().take(64).collect();
    if crate::room_name::validate(&name).is_ok() { name } else { "Direct message".to_owned() }
}

impl DurableServer {
    /// Continue the archive room `archive` for `actor` (REQUIREMENTS "Continuing a conversation", task T352) and
    /// return the room it continues in. `actor` must be able to read the archive (`NotReadable` otherwise, exactly as
    /// for a room that does not exist). An archived one-to-one conversation whose two people are both linked
    /// continues in their direct message; any other archive in its own group room with its linked people, and a
    /// linked person who continues it later is added to that room. Asking again answers the same room and changes
    /// nothing.
    pub fn continue_archive(&mut self, archive: &str, actor: &str, now_ms: u64) -> Result<String, ContinueError> {
        self.check_alive().map_err(ContinueError::Durable)?;
        let service = self.server.room(archive).map_err(|_| ContinueError::NotReadable)?;
        if service.role(actor).is_none() {
            return Err(ContinueError::NotReadable);
        }
        if !service.is_read_only() {
            return Err(ContinueError::NotArchive);
        }
        let linked: Vec<String> = service.members().into_iter().map(|(member, _)| member).filter(|member| member != ARCHIVE_OWNER).collect();
        let direct = linked.len() == 2 && self.continuations.direct.contains(archive);
        let continued = self.continuations.continued.get(archive).cloned();
        let people = if direct || continued.is_none() { linked } else { vec![actor.to_owned()] };
        // Already done: the same room, and nobody to add.
        let settled = match people.as_slice() {
            [first, second] if direct => self.continuations.directs.get(&(first.clone(), second.clone())).cloned(),
            _ => continued.clone(),
        };
        if let Some(room) = settled
            && continued.as_deref() == Some(room.as_str())
            && has_all(&self.server, &room, &people)
        {
            return Ok(room);
        }
        let room = apply(&mut self.server, &mut self.continuations, archive, actor, direct, &people)
            .map_err(|error| ContinueError::Durable(DurableError::Server(error)))?;
        self.record(&Op::Continue { archive: archive.to_owned(), actor: actor.to_owned(), direct, people, now_ms })
            .map_err(ContinueError::Durable)?;
        Ok(room)
    }

    /// The room the archive room `archive` continues in, once someone has continued it (task T352).
    pub fn continued_in(&self, archive: &str) -> Option<&str> {
        self.continuations.continued.get(archive).map(String::as_str)
    }

    /// Note that the archive room `slug` was a one-to-one conversation in its source (task T352), once: a later
    /// import of the same conversation records nothing.
    pub(crate) fn mark_direct(&mut self, slug: &str) -> Result<(), DurableError> {
        if self.continuations.direct.contains(slug) {
            return Ok(());
        }
        self.record(&Op::ArchiveDirect { slug: slug.to_owned() })?;
        self.continuations.direct.insert(slug.to_owned());
        Ok(())
    }
}
