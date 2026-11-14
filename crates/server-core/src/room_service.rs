//! One room's server-side behaviour, composed from the room rules (`room`, T111), the cursor log (`cursor_log`, T101),
//! read markers (`unread`, T105), mentions (`mentions`, T104) and the safe renderer (`render`, T115). Task T120.

use std::collections::HashSet;

use crate::cursor_log::{EventLog, Since};
use crate::mentions::mentions;
use crate::render::render;
use crate::room::{Role, Room, RoomError};
use crate::unread::ReadMarkers;

/// Longest message, in chars after trimming.
pub const MAX_TEXT_CHARS: usize = 4000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    Posted,
    Edited { target: u64 },
    Deleted { target: u64 },
    Joined { user: String, role: Role },
    Left { user: String },
}

/// One entry of the room's log. Every successful change appends exactly one event; its cursor is the log's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub cursor: u64,
    /// Who made the change.
    pub actor: String,
    pub kind: EventKind,
    /// `render::render` of the trimmed text for `Posted` and `Edited`; empty for every other kind.
    pub html: String,
    /// For `Posted` and `Edited`: `mentions::mentions` of the trimmed text, keeping only names that are members of the
    /// room at that moment and are not the actor, in the order `mentions` returns them. Empty for every other kind.
    pub mentions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceError {
    /// A membership rule refused it (passed through from `room::Room`).
    Room(RoomError),
    /// The actor is a member but may not do this.
    NotAllowed,
    /// Nothing left after trimming.
    EmptyText,
    /// More than `MAX_TEXT_CHARS` chars after trimming.
    TooLong,
    /// The target is not a `Posted` event still held in the log, or it was already deleted.
    NoSuchMessage,
}

const ROOM_ID: &str = "room";

pub struct RoomService {
    room: Room,
    log: EventLog<Event>,
    markers: ReadMarkers,
    deleted: HashSet<u64>,
}

impl RoomService {
    /// A room owned by `owner` whose log keeps the newest `capacity` events. Creating it appends no event.
    pub fn new(owner: &str, capacity: usize) -> Self {
        Self { room: Room::new(owner), log: EventLog::new(capacity), markers: ReadMarkers::new(), deleted: HashSet::new() }
    }

    /// `Room::add`, then a `Joined { user, role }` event by `actor`. Returns its cursor.
    pub fn add_member(&mut self, actor: &str, user: &str, role: Role) -> Result<u64, ServiceError> {
        self.room.add(actor, user, role).map_err(ServiceError::Room)?;
        let event = Event {
            cursor: self.log.head() + 1,
            actor: actor.to_string(),
            kind: EventKind::Joined { user: user.to_string(), role },
            html: String::new(),
            mentions: Vec::new(),
        };
        Ok(self.log.append(event))
    }

    /// `Room::remove`, then a `Left { user }` event by `actor`. Returns its cursor.
    pub fn remove_member(&mut self, actor: &str, user: &str) -> Result<u64, ServiceError> {
        self.room.remove(actor, user).map_err(ServiceError::Room)?;
        let event = Event {
            cursor: self.log.head() + 1,
            actor: actor.to_string(),
            kind: EventKind::Left { user: user.to_string() },
            html: String::new(),
            mentions: Vec::new(),
        };
        Ok(self.log.append(event))
    }

    /// Post a message. Checks, in order: a non-member is `Room(NotMember)`; a member who cannot post (a Guest) is
    /// `NotAllowed`; the trimmed text is `EmptyText` or `TooLong`. Returns the new event's cursor.
    pub fn post(&mut self, author: &str, text: &str) -> Result<u64, ServiceError> {
        if self.room.role(author).is_none() {
            return Err(ServiceError::Room(RoomError::NotMember));
        }
        if !self.room.can_post(author) {
            return Err(ServiceError::NotAllowed);
        }
        let trimmed = Self::check_text(text)?;
        let html = render(&trimmed);
        let mention_list = mentions(&trimmed);
        let mentions: Vec<String> = mention_list.into_iter().filter(|m| self.room.role(m).is_some()).filter(|m| m != author).collect();
        let event = Event { cursor: self.log.head() + 1, actor: author.to_string(), kind: EventKind::Posted, html, mentions };
        Ok(self.log.append(event))
    }

    /// Replace the text of the message posted at `target`. Checks, in order: a non-member is `Room(NotMember)`; the
    /// target must be a live (held, not deleted) `Posted` event, else `NoSuchMessage`; only its author may edit it, even
    /// an Owner may not (`NotAllowed`); then the text rules of `post`. Appends `Edited { target }`.
    pub fn edit(&mut self, actor: &str, target: u64, text: &str) -> Result<u64, ServiceError> {
        if self.room.role(actor).is_none() {
            return Err(ServiceError::Room(RoomError::NotMember));
        }
        let event = self.find_posted(target).ok_or(ServiceError::NoSuchMessage)?;
        if event.actor != actor {
            return Err(ServiceError::NotAllowed);
        }
        let trimmed = Self::check_text(text)?;
        let html = render(&trimmed);
        let mention_list = mentions(&trimmed);
        let mentions: Vec<String> = mention_list.into_iter().filter(|m| self.room.role(m).is_some()).filter(|m| m != actor).collect();
        let new_event = Event { cursor: self.log.head() + 1, actor: actor.to_string(), kind: EventKind::Edited { target }, html, mentions };
        Ok(self.log.append(new_event))
    }

    /// Delete the message posted at `target`. Checks, in order: a non-member is `Room(NotMember)`; the target must be a
    /// live `Posted` event (`NoSuchMessage`); its author, an Admin or an Owner may delete it, anyone else is `NotAllowed`.
    /// Appends `Deleted { target }`; the target can then be neither edited nor deleted again.
    pub fn delete(&mut self, actor: &str, target: u64) -> Result<u64, ServiceError> {
        let role = match self.room.role(actor) {
            Some(r) => r,
            None => return Err(ServiceError::Room(RoomError::NotMember)),
        };
        let event = self.find_posted(target).ok_or(ServiceError::NoSuchMessage)?;
        if event.actor != actor && role < Role::Admin {
            return Err(ServiceError::NotAllowed);
        }
        self.deleted.insert(target);
        let new_event = Event {
            cursor: self.log.head() + 1,
            actor: actor.to_string(),
            kind: EventKind::Deleted { target },
            html: String::new(),
            mentions: Vec::new(),
        };
        Ok(self.log.append(new_event))
    }

    /// The events after `cursor` (as `EventLog::since`), for members only (`Room(NotMember)` otherwise).
    pub fn sync(&self, user: &str, cursor: u64) -> Result<Since<Event>, ServiceError> {
        if self.room.role(user).is_none() {
            return Err(ServiceError::Room(RoomError::NotMember));
        }
        Ok(self.log.since(cursor))
    }

    /// Move the member's read marker (as `ReadMarkers::mark_read`); `Room(NotMember)` for a non-member.
    pub fn mark_read(&mut self, user: &str, cursor: u64) -> Result<bool, ServiceError> {
        if self.room.role(user).is_none() {
            return Err(ServiceError::Room(RoomError::NotMember));
        }
        Ok(self.markers.mark_read(user, ROOM_ID, cursor))
    }

    /// How many `Posted` events still held, not deleted, after the member's read marker, were posted by someone else.
    /// Edits, deletions and membership events never count. `Room(NotMember)` for a non-member.
    pub fn unread(&self, user: &str) -> Result<usize, ServiceError> {
        if self.room.role(user).is_none() {
            return Err(ServiceError::Room(RoomError::NotMember));
        }
        let all = self.all_events();
        let mut owned: Vec<(u64, String)> = Vec::new();
        for (c, e) in all {
            if matches!(e.kind, EventKind::Posted) && !self.deleted.contains(&c) {
                owned.push((c, e.actor));
            }
        }
        let refs: Vec<(u64, &str)> = owned.iter().map(|(c, a)| (*c, a.as_str())).collect();
        Ok(self.markers.unread(user, ROOM_ID, &refs))
    }

    /// The newest cursor (0 before the first event).
    pub fn head(&self) -> u64 {
        self.log.head()
    }

    /// The user's role in the room; `None` for a non-member.
    pub fn role(&self, user: &str) -> Option<Role> {
        self.room.role(user)
    }

    /// Every member and role, sorted by name (as `Room::members`).
    pub fn members(&self) -> Vec<(String, Role)> {
        self.room.members()
    }

    fn check_text(text: &str) -> Result<String, ServiceError> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(ServiceError::EmptyText);
        }
        if trimmed.chars().count() > MAX_TEXT_CHARS {
            return Err(ServiceError::TooLong);
        }
        Ok(trimmed.to_string())
    }

    fn find_posted(&self, target: u64) -> Option<Event> {
        if self.deleted.contains(&target) {
            return None;
        }
        let all = self.all_events();
        all.into_iter().find(|(c, e)| *c == target && e.kind == EventKind::Posted).map(|(_, e)| e)
    }

    fn all_events(&self) -> Vec<(u64, Event)> {
        match self.log.since(0) {
            Since::Events(e) => e,
            Since::Gap { oldest } => match self.log.since(oldest.saturating_sub(1)) {
                Since::Events(e) => e,
                Since::Gap { .. } => Vec::new(),
            },
        }
    }
}
