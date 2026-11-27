//! One room's server-side behaviour, composed from the room rules (`room`, T111), the cursor log (`cursor_log`, T101),
//! read markers (`unread`, T105), mentions (`mentions`, T104) and the safe renderer (`render`, T115). Task T120.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::cursor_log::{EventLog, Since};
use crate::mentions::mentions;
use crate::render::render;
use crate::room::{Role, Room, RoomError};
use crate::unread::ReadMarkers;
use crewcraft_proto::room_settings::{RoomSetting, RoomSettings};

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
    /// The room's pin after a change; zero means unpinned. Its snapshot is sent separately (task T343).
    Pinned {
        target: u64,
    },
    /// A call's history line (task T360a1): its start, or its end (`ended`). The text is in the event's `html`.
    CallLine {
        call: u64,
        ended: bool,
    },
    /// The line that says this room continues the archive room `archive` (task T352). The text is in the event's
    /// `html`.
    Continued {
        archive: String,
    },
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
    pinned: Option<u64>,
    /// The memory-only server keeps its pin's body after the bounded event log advances.
    pin_body: Option<(String, String, bool)>,
    /// An archive room (docs/IMPORT.md, task T350a): it never accepts writes again.
    read_only: bool,
    /// Each member's own pin, mute and hide settings and their revision (task T346).
    settings: HashMap<String, (RoomSettings, u64)>,
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
            pinned: None,
            pin_body: None,
            read_only: false,
            settings: HashMap::new(),
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
        self.edit_validated(actor, target, &event.actor, text)
    }

    /// The durable caller supplies the author from its live full-history projection.
    pub(crate) fn edit_validated(&mut self, actor: &str, target: u64, author: &str, text: &str) -> Result<u64, ServiceError> {
        if self.room.role(actor).is_none() {
            return Err(ServiceError::Room(RoomError::NotMember));
        }
        if author != actor || self.read_only {
            return Err(ServiceError::NotAllowed);
        }
        let trimmed = Self::check_text(text)?;
        let html = render(&trimmed);
        let mention_list = mentions(&trimmed);
        let mentions: Vec<String> = mention_list.into_iter().filter(|m| self.room.role(m).is_some()).filter(|m| m != actor).collect();
        let new_event = Event { cursor: self.log.head() + 1, actor: actor.to_string(), kind: EventKind::Edited { target }, html, mentions };
        if self.pinned == Some(target) {
            self.pin_body = Some((actor.to_owned(), new_event.html.clone(), true));
        }
        Ok(self.log.append(new_event))
    }

    /// Delete the message posted at `target`. Checks, in order: a non-member is `Room(NotMember)`; the target must be a
    /// live `Posted` event (`NoSuchMessage`); its author, an Admin or an Owner may delete it, anyone else is `NotAllowed`.
    /// Clears the target and every held revision in place, then appends `Deleted { target }`.
    /// The target can then be neither edited nor deleted again.
    pub fn delete(&mut self, actor: &str, target: u64) -> Result<u64, ServiceError> {
        if self.room.role(actor).is_none() {
            return Err(ServiceError::Room(RoomError::NotMember));
        }
        let event = self.find_posted(target).ok_or(ServiceError::NoSuchMessage)?;
        self.delete_validated(actor, target, &event.actor)
    }

    /// The durable caller supplies the author from its live full-history projection.
    pub(crate) fn delete_validated(&mut self, actor: &str, target: u64, author: &str) -> Result<u64, ServiceError> {
        let role = match self.room.role(actor) {
            Some(r) => r,
            None => return Err(ServiceError::Room(RoomError::NotMember)),
        };
        if (author != actor && role < Role::Admin) || self.read_only {
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
        if self.pinned == Some(target) {
            self.pinned = None;
            self.pin_body = None;
        }
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
        self.check_reaction_access(actor, reaction)?;
        self.find_posted(target).ok_or(ServiceError::NoSuchMessage)?;
        Ok(self.append_reaction(actor, target, reaction, on))
    }

    /// The durable caller resolved the optional live target from the complete current-message projection (T345).
    pub(crate) fn react_validated(&mut self, actor: &str, target: Option<u64>, reaction: u8, on: bool) -> Result<u64, ServiceError> {
        self.check_reaction_access(actor, reaction)?;
        let target = target.ok_or(ServiceError::NoSuchMessage)?;
        Ok(self.append_reaction(actor, target, reaction, on))
    }

    fn check_reaction_access(&self, actor: &str, reaction: u8) -> Result<(), ServiceError> {
        if self.room.role(actor).is_none() {
            return Err(ServiceError::Room(RoomError::NotMember));
        }
        if !self.room.can_post(actor) || self.read_only {
            return Err(ServiceError::NotAllowed);
        }
        if crewcraft_proto::push::reaction_name(reaction).is_none() {
            return Err(ServiceError::BadReaction);
        }
        Ok(())
    }

    fn append_reaction(&mut self, actor: &str, target: u64, reaction: u8, on: bool) -> u64 {
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
        self.log.append(event)
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

    /// Append the line by `actor` that says this room continues the archive room `archive` (task T352), rendered from
    /// `text`, which the caller builds. Like a call's history line, it never counts as unread.
    pub fn continued_line(&mut self, actor: &str, archive: &str, text: &str) -> u64 {
        let event = Event {
            cursor: self.log.head() + 1,
            actor: actor.to_string(),
            kind: EventKind::Continued { archive: archive.to_owned() },
            html: render(text),
            mentions: Vec::new(),
        };
        self.log.append(event)
    }

    /// Who reacted to the message at `target` (task T341a); empty when no one has.
    pub fn reactions(&self, target: u64) -> Reactions {
        self.reactions.get(&target).cloned().unwrap_or_default()
    }

    /// Borrow individual sorted reaction edges so bounded recovery never clones an unbounded reactor set (T345).
    pub(crate) fn reaction_edges(&self, target: u64) -> impl Iterator<Item = (u8, &str)> {
        self.reactions
            .get(&target)
            .into_iter()
            .flat_map(|reactions| reactions.iter())
            .flat_map(|(code, people)| people.iter().map(move |person| (*code, person.as_str())))
    }

    /// Replace the room's pin, or clear it only when it still points at `target` (task T343).
    pub fn pin(&mut self, actor: &str, target: u64, on: bool) -> Result<u64, ServiceError> {
        self.check_pin_access(actor)?;
        if on {
            self.find_posted(target).ok_or(ServiceError::NoSuchMessage)?;
            self.pin_body = self.message_content(target);
        }
        Ok(self.set_pin(actor, target, on))
    }

    /// For a durable caller that checked the live target against its full-history current-message projection.
    pub(crate) fn pin_validated(&mut self, actor: &str, target: u64, on: bool) -> Result<u64, ServiceError> {
        self.check_pin_access(actor)?;
        if on {
            self.pin_body = self.message_content(target);
        }
        Ok(self.set_pin(actor, target, on))
    }

    pub(crate) fn check_pin_access(&self, actor: &str) -> Result<(), ServiceError> {
        if self.room.role(actor).is_none() {
            return Err(ServiceError::Room(RoomError::NotMember));
        }
        if !self.room.can_post(actor) || self.read_only {
            return Err(ServiceError::NotAllowed);
        }
        Ok(())
    }

    fn set_pin(&mut self, actor: &str, target: u64, on: bool) -> u64 {
        if on {
            self.pinned = Some(target);
        } else if self.pinned == Some(target) {
            self.pinned = None;
            self.pin_body = None;
        }
        let event = Event {
            cursor: self.log.head() + 1,
            actor: actor.to_owned(),
            kind: EventKind::Pinned { target: self.pinned.unwrap_or(0) },
            html: String::new(),
            mentions: Vec::new(),
        };
        self.log.append(event)
    }

    /// The current pinned message, independently of the bounded room event log.
    pub fn pinned(&self) -> Option<u64> {
        self.pinned
    }

    /// The pinned body for a memory-only connection; durable connections use their full-history projection.
    pub(crate) fn pinned_content(&self) -> Option<(u64, String, String, bool)> {
        let target = self.pinned?;
        let (author, html, edited) = self.pin_body.as_ref()?;
        Some((target, author.clone(), html.clone(), *edited))
    }

    fn message_content(&self, target: u64) -> Option<(String, String, bool)> {
        let post = self.find_posted(target)?;
        let mut html = post.html;
        let mut edited = false;
        for (_, event) in self.all_events() {
            if matches!(event.kind, EventKind::Edited { target: at } if at == target) {
                html = event.html;
                edited = true;
            }
        }
        Some((post.actor, html, edited))
    }

    /// Whether this cursor was redacted, including an imported deletion (task T343).
    pub(crate) fn is_deleted(&self, target: u64) -> bool {
        self.deleted.contains(&target)
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

    /// The asking member's read position and personal revision (task T344).
    pub fn read_position(&self, user: &str) -> Result<(u64, u64), ServiceError> {
        if self.room.role(user).is_none() {
            return Err(ServiceError::Room(RoomError::NotMember));
        }
        Ok((self.markers.last_read(user, ROOM_ID), self.markers.revision(user, ROOM_ID)))
    }

    /// Move just before the selected live message, or the newest live message by someone else for target zero.
    pub fn mark_unread(&mut self, user: &str, target: u64) -> Result<u64, ServiceError> {
        self.read_position(user)?;
        let target = if target == 0 {
            self.all_events()
                .into_iter()
                .filter(|(cursor, event)| matches!(event.kind, EventKind::Posted) && event.actor != user && !self.deleted.contains(cursor))
                .map(|(cursor, _)| cursor)
                .max()
        } else {
            self.find_posted(target).ok_or(ServiceError::NoSuchMessage)?;
            Some(target)
        };
        if let Some(target) = target {
            self.mark_unread_validated(user, target)?;
        }
        Ok(self.markers.last_read(user, ROOM_ID))
    }

    /// The durable caller has checked this nonzero target in its full current-message projection.
    pub(crate) fn mark_unread_validated(&mut self, user: &str, target: u64) -> Result<bool, ServiceError> {
        self.read_position(user)?;
        let cursor = target.checked_sub(1).ok_or(ServiceError::NoSuchMessage)?;
        Ok(self.markers.mark_unread(user, ROOM_ID, cursor))
    }

    /// The member's own settings for this room and their revision, zero before the first change (task T346).
    /// `Room(NotMember)` for anyone else, so nobody can read another person's settings.
    pub fn room_settings(&self, user: &str) -> Result<(RoomSettings, u64), ServiceError> {
        if self.room.role(user).is_none() {
            return Err(ServiceError::Room(RoomError::NotMember));
        }
        Ok(self.settings.get(user).copied().unwrap_or_default())
    }

    /// Turn one of the member's own settings on or off (task T346); returns whether it changed. The revision moves only
    /// on a change. Personal settings change no room event and are accepted in archive rooms too.
    pub fn set_room_setting(&mut self, user: &str, setting: RoomSetting, on: bool) -> Result<bool, ServiceError> {
        let (settings, revision) = self.room_settings(user)?;
        if settings.get(setting) == on {
            return Ok(false);
        }
        self.settings.insert(user.to_owned(), (settings.with(setting, on), revision.saturating_add(1)));
        Ok(true)
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod pins_saved_tests {
    use super::*;

    #[test]
    fn validated_old_reactions_keep_guest_read_only_and_bad_code_refusals() {
        let mut room = RoomService::new("owner", 2);
        let old = room.post("owner", "old").unwrap();
        room.add_member("owner", "member", Role::Member).unwrap();
        room.add_member("owner", "guest", Role::Guest).unwrap();
        assert_eq!(room.react("member", old, 1, true), Err(ServiceError::NoSuchMessage));
        room.react_validated("member", Some(old), 1, true).unwrap();
        assert!(room.reactions(old).get(&1).is_some_and(|people| people.contains("member")));
        assert_eq!(room.react_validated("outsider", None, 0, true), Err(ServiceError::Room(RoomError::NotMember)));
        assert_eq!(room.react_validated("guest", None, 0, true), Err(ServiceError::NotAllowed));
        assert_eq!(room.react_validated("member", None, 0, true), Err(ServiceError::BadReaction));
        assert_eq!(room.react_validated("member", None, 1, true), Err(ServiceError::NoSuchMessage));
        room.set_read_only();
        assert_eq!(room.react_validated("member", Some(old), 1, false), Err(ServiceError::NotAllowed));
        assert!(room.reactions(old).get(&1).is_some_and(|people| people.contains("member")));
    }

    #[test]
    fn stale_unpin_and_deleted_targets_cannot_replace_a_newer_pin() {
        let mut room = RoomService::new("owner", 8);
        let first = room.post("owner", "first").unwrap();
        let second = room.post("owner", "second").unwrap();
        room.pin("owner", first, true).unwrap();
        room.pin("owner", second, true).unwrap();
        room.delete("owner", first).unwrap();
        room.pin("owner", first, false).unwrap();
        assert_eq!(room.pinned(), Some(second));
        assert_eq!(room.pin("owner", first, true), Err(ServiceError::NoSuchMessage));
        assert_eq!(room.pinned(), Some(second));
        room.delete("owner", second).unwrap();
        assert_eq!(room.pinned(), None);
        assert_eq!(room.pinned_content(), None);
    }

    #[test]
    fn an_old_pin_keeps_current_text_and_validated_operations_keep_authorization() {
        let mut room = RoomService::new("owner", 2);
        room.add_member("owner", "member", Role::Member).unwrap();
        let old = room.post("owner", "old text").unwrap();
        room.pin("owner", old, true).unwrap();
        room.post("owner", "a later post").unwrap();
        room.post("owner", "another later post").unwrap();
        assert!(matches!(room.sync("owner", 0).unwrap(), Since::Gap { .. }));
        assert_eq!(room.pinned(), Some(old));
        assert_eq!(room.edit_validated("member", old, "owner", "forged"), Err(ServiceError::NotAllowed));
        assert_eq!(room.delete_validated("member", old, "owner"), Err(ServiceError::NotAllowed));
        room.edit_validated("owner", old, "owner", "current text").unwrap();
        let (target, author, html, edited) = room.pinned_content().unwrap();
        assert_eq!((target, author, edited), (old, "owner".to_owned(), true));
        assert!(html.contains("current text"));
        room.delete_validated("owner", old, "owner").unwrap();
        assert_eq!(room.pinned(), None);
    }
}
