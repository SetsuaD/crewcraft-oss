//! One room's server-side behaviour, composed from the room rules (`room`, T111), the cursor log (`cursor_log`, T101),
//! read markers (`unread`, T105), mentions (`mentions`, T104) and the safe renderer (`render`, T115). Task T120.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

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
    Edited {
        target: u64,
    },
    Deleted {
        target: u64,
    },
    Joined {
        user: String,
        role: Role,
    },
    Left {
        user: String,
    },
    /// The actor added (`on`) or took back `reaction` (a code, see `push::REACTIONS`) on the message at `target`
    /// (task T341a).
    Reacted {
        target: u64,
        reaction: u8,
        on: bool,
    },
    /// A call's history line (task T360a1): its start, or its end (`ended`). The text is in the event's `html`.
    CallLine { call: u64, ended: bool },
}

/// Who reacted to one message: by reaction code, the people, sorted (task T341a).
pub type Reactions = BTreeMap<u8, BTreeSet<String>>;

/// One entry of the room's log. Every successful change appends exactly one event; its cursor is the log's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub cursor: u64,
    /// Who made the change.
    pub actor: String,
    pub kind: EventKind,
    /// `render::render` of the trimmed text for live `Posted` and `Edited` events.
    /// Empty after redaction or for other kinds.
    pub html: String,
    /// Mentions in live `Posted` and `Edited` events, in the order returned by `mentions::mentions`.
    /// Includes only room members other than the actor at the time of the event.
    /// Empty after redaction or for other kinds.
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
    /// A reaction code outside `push::REACTIONS` (task T341a).
    BadReaction,
}

const ROOM_ID: &str = "room";

pub struct RoomService {
    room: Room,
    log: EventLog<Event>,
    markers: ReadMarkers,
    deleted: HashSet<u64>,
    /// Who reacted to each message, by its cursor (task T341a).
    reactions: HashMap<u64, Reactions>,
    /// An archive room (docs/IMPORT.md, task T350a): it never accepts writes again.
    read_only: bool,
}

impl RoomService {
    /// A room owned by `owner` whose log keeps the newest `capacity` events. Creating it appends no event.
    pub fn new(owner: &str, capacity: usize) -> Self {
        Self {
            room: Room::new(owner),
            log: EventLog::new(capacity),
            markers: ReadMarkers::new(),
            deleted: HashSet::new(),
            reactions: HashMap::new(),
            read_only: false,
        }
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
        if !self.room.can_post(author) || self.read_only {
            return Err(ServiceError::NotAllowed);
        }
        let trimmed = Self::check_text(text)?;
        Ok(self.append_post(author, &trimmed))
    }

    fn append_post(&mut self, author: &str, trimmed: &str) -> u64 {
        let html = render(trimmed);
        let mention_list = mentions(trimmed);
        let mentions: Vec<String> = mention_list.into_iter().filter(|m| self.room.role(m).is_some()).filter(|m| m != author).collect();
        let event = Event { cursor: self.log.head() + 1, actor: author.to_string(), kind: EventKind::Posted, html, mentions };
        self.log.append(event)
    }

    /// Make this an archive room (task T350a): from now on posting, editing, deleting and reacting are `NotAllowed`
    /// for everyone, and nothing in it counts as unread. Membership can still change. There is no way back.
    pub fn set_read_only(&mut self) {
        self.read_only = true;
    }

    /// Whether this is an archive room (task T350a).
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Add an imported message by `author` (task T350a), who need not be a member or have an account. Only in an
    /// archive room (`NotAllowed` otherwise). The text rules of `post` apply, except that a message the source deleted
    /// (`deleted`) has no text and is held as redacted from the start.
    pub fn import_post(&mut self, author: &str, text: &str, deleted: bool) -> Result<u64, ServiceError> {
        if !self.read_only {
            return Err(ServiceError::NotAllowed);
        }
        if deleted {
            let event =
                Event { cursor: self.log.head() + 1, actor: author.to_string(), kind: EventKind::Posted, html: String::new(), mentions: Vec::new() };
            let cursor = self.log.append(event);
            self.deleted.insert(cursor);
            return Ok(cursor);
        }
        let trimmed = Self::check_text(text)?;
        Ok(self.append_post(author, &trimmed))
    }

    /// Replace an imported message's text with what the source now says (task T350a), as its author. Only in an
    /// archive room; the target must be a live `Posted` event (`NoSuchMessage`).
    pub fn import_edit(&mut self, target: u64, text: &str) -> Result<u64, ServiceError> {
        if !self.read_only {
            return Err(ServiceError::NotAllowed);
        }
        let event = self.find_posted(target).ok_or(ServiceError::NoSuchMessage)?;
        let trimmed = Self::check_text(text)?;
        let html = render(&trimmed);
        let mentions: Vec<String> = mentions(&trimmed).into_iter().filter(|m| self.room.role(m).is_some()).filter(|m| *m != event.actor).collect();
        let new_event = Event { cursor: self.log.head() + 1, actor: event.actor, kind: EventKind::Edited { target }, html, mentions };
        Ok(self.log.append(new_event))
    }

    /// Redact an imported message the source has since deleted (task T350a), by `actor`. Only in an archive room; the
    /// target must be a live `Posted` event (`NoSuchMessage`).
    pub fn import_delete(&mut self, actor: &str, target: u64) -> Result<u64, ServiceError> {
        if !self.read_only {
            return Err(ServiceError::NotAllowed);
        }
        self.find_posted(target).ok_or(ServiceError::NoSuchMessage)?;
        Ok(self.redact(actor, target))
    }

    /// Replace the text of the message posted at `target`. Checks, in order: a non-member is `Room(NotMember)`; the
    /// target must be a live (held, not deleted) `Posted` event, else `NoSuchMessage`; only its author may edit it, even
    /// an Owner may not (`NotAllowed`); then the text rules of `post`. Appends `Edited { target }`.
    pub fn edit(&mut self, actor: &str, target: u64, text: &str) -> Result<u64, ServiceError> {
        if self.room.role(actor).is_none() {
            return Err(ServiceError::Room(RoomError::NotMember));
        }
        let event = self.find_posted(target).ok_or(ServiceError::NoSuchMessage)?;
        if event.actor != actor || self.read_only {
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
    /// Clears the target and every held revision in place, then appends `Deleted { target }`.
    /// The target can then be neither edited nor deleted again.
    pub fn delete(&mut self, actor: &str, target: u64) -> Result<u64, ServiceError> {
        let role = match self.room.role(actor) {
            Some(r) => r,
            None => return Err(ServiceError::Room(RoomError::NotMember)),
        };
        let event = self.find_posted(target).ok_or(ServiceError::NoSuchMessage)?;
        if (event.actor != actor && role < Role::Admin) || self.read_only {
            return Err(ServiceError::NotAllowed);
        }
        Ok(self.redact(actor, target))
    }

    /// Clear the target and every held revision in place, forget its reactions, and append `Deleted { target }`.
    fn redact(&mut self, actor: &str, target: u64) -> u64 {
        for (cursor, event) in self.log.events_mut() {
            let redact = match event.kind {
                EventKind::Posted => cursor == target,
                EventKind::Edited { target: edited } => edited == target,
                _ => false,
            };
            if redact {
                event.html.clear();
                event.mentions.clear();
            }
        }
        self.deleted.insert(target);
        self.reactions.remove(&target);
        let new_event = Event {
            cursor: self.log.head() + 1,
            actor: actor.to_string(),
            kind: EventKind::Deleted { target },
            html: String::new(),
            mentions: Vec::new(),
        };
        self.log.append(new_event)
    }

    /// Add (`on`) or take back the actor's `reaction` on the message posted at `target` (task T341a). Checks, in order: a
    /// non-member is `Room(NotMember)`; a member who cannot post (a Guest) is `NotAllowed`; a code outside
    /// `push::REACTIONS` is `BadReaction`; the target must be a live `Posted` event (`NoSuchMessage`). Appends
    /// `Reacted { target, reaction, on }` even when it changes nothing (adding a reaction twice), so every request is
    /// answered with an event of its own.
    pub fn react(&mut self, actor: &str, target: u64, reaction: u8, on: bool) -> Result<u64, ServiceError> {
        if self.room.role(actor).is_none() {
            return Err(ServiceError::Room(RoomError::NotMember));
        }
        if !self.room.can_post(actor) || self.read_only {
            return Err(ServiceError::NotAllowed);
        }
        if crewcraft_proto::push::reaction_name(reaction).is_none() {
            return Err(ServiceError::BadReaction);
        }
        self.find_posted(target).ok_or(ServiceError::NoSuchMessage)?;
        let people = self.reactions.entry(target).or_default();
        if on {
            people.entry(reaction).or_default().insert(actor.to_string());
        } else if let Some(who) = people.get_mut(&reaction) {
            who.remove(actor);
            if who.is_empty() {
                people.remove(&reaction);
            }
        }
        if people.is_empty() {
            self.reactions.remove(&target);
        }
        let event = Event {
            cursor: self.log.head() + 1,
            actor: actor.to_string(),
            kind: EventKind::Reacted { target, reaction, on },
            html: String::new(),
            mentions: Vec::new(),
        };
        Ok(self.log.append(event))
    }

    /// Append a call's history line by `actor` (task T360a1), rendered from `text`. The call rules are the caller's
    /// (`calls`); a history line never counts as unread.
    pub fn call_line(&mut self, actor: &str, call: u64, ended: bool, text: &str) -> u64 {
        let event = Event {
            cursor: self.log.head() + 1,
            actor: actor.to_string(),
            kind: EventKind::CallLine { call, ended },
            html: render(text),
            mentions: Vec::new(),
        };
        self.log.append(event)
    }

    /// Who reacted to the message at `target` (task T341a); empty when no one has.
    pub fn reactions(&self, target: u64) -> Reactions {
        self.reactions.get(&target).cloned().unwrap_or_default()
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
        // An archive room never counts towards unread totals (task T350a).
        if self.read_only {
            return Ok(0);
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
