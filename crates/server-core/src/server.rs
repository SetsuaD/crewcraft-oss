//! Many rooms on one server: creating and finding rooms, one message rate limit per user across all rooms, and who in
//! a room is online. Composed from `room_service` (T120), `room_name` (T106), `rate_limit` (T102) and `presence`
//! (T108). Task T122.

use std::collections::HashMap;

use crate::presence::Presence;
use crate::rate_limit::Limiter;
use crate::room::Role;
use crate::room::RoomError;
use crate::room_name::{self, NameError};
use crate::room_service::{RoomService, ServiceError};

/// Events each room's log keeps.
pub const ROOM_LOG_CAPACITY: usize = 10_000;
/// Each user's message bucket: `POST_BURST` tokens, refilled at `POST_PER_SEC` a second (`rate_limit::Limiter`). One
/// bucket per user, shared by `post` and `edit` in every room.
pub const POST_BURST: u32 = 20;
pub const POST_PER_SEC: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoomInfo {
    pub slug: String,
    /// The cleaned display name.
    pub name: String,
    /// The asking user's role in the room.
    pub role: Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerError {
    /// `room_name::validate` refused the name.
    BadName(NameError),
    /// No room has this slug.
    NoSuchRoom,
    /// The user's message bucket is empty; the room is unchanged.
    RateLimited,
    /// The room refused it (passed through from `RoomService`).
    Service(ServiceError),
}

pub struct Server {
    rooms: HashMap<String, RoomService>,
    room_names: HashMap<String, String>,
    limiter: Limiter<String>,
    presence: Presence,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    /// A server with no rooms.
    pub fn new() -> Self {
        Self { rooms: HashMap::new(), room_names: HashMap::new(), limiter: Limiter::new(POST_BURST, POST_PER_SEC), presence: Presence::new() }
    }

    /// Create a room named `name`, owned by `owner`, with a log of `ROOM_LOG_CAPACITY`. The name is cleaned by
    /// `room_name::validate` (`BadName` if refused). The slug is `room_name::slug` of the cleaned name; when a room
    /// already has that slug, `-2` is appended, else `-3`, and so on: the first one free (the suffix may take a slug past
    /// 48 characters). Returns the slug.
    pub fn create_room(&mut self, owner: &str, name: &str) -> Result<String, ServerError> {
        let cleaned = room_name::validate(name).map_err(ServerError::BadName)?;
        let base_slug = room_name::slug(&cleaned);

        let slug = if !self.rooms.contains_key(&base_slug) {
            base_slug
        } else {
            let mut i = 2u32;
            loop {
                let candidate = format!("{}-{}", base_slug, i);
                if !self.rooms.contains_key(&candidate) {
                    break candidate;
                }
                i += 1;
            }
        };

        let service = RoomService::new(owner, ROOM_LOG_CAPACITY);
        self.rooms.insert(slug.clone(), service);
        self.room_names.insert(slug.clone(), cleaned);
        Ok(slug)
    }

    /// Create an archive room named `name` (task T350a): owned by `ARCHIVE_OWNER`, which no account can be, and
    /// read-only from the start (`RoomService::set_read_only`). Named and slugged as `create_room`.
    pub fn create_archive_room(&mut self, name: &str) -> Result<String, ServerError> {
        let slug = self.create_room(crate::import::ARCHIVE_OWNER, name)?;
        if let Some(service) = self.rooms.get_mut(&slug) {
            service.set_read_only();
        }
        Ok(slug)
    }

    /// `RoomService::call_line` in the room (task T360a1). `NoSuchRoom` first.
    pub fn call_line(&mut self, slug: &str, actor: &str, call: u64, ended: bool, text: &str) -> Result<u64, ServerError> {
        let service = self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?;
        Ok(service.call_line(actor, call, ended, text))
    }

    /// `RoomService::import_post` in the room (task T350a). `NoSuchRoom` first; no rate limit.
    pub fn import_post(&mut self, slug: &str, author: &str, text: &str, deleted: bool) -> Result<u64, ServerError> {
        let service = self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?;
        service.import_post(author, text, deleted).map_err(ServerError::Service)
    }

    /// `RoomService::import_edit` in the room (task T350a).
    pub fn import_edit(&mut self, slug: &str, target: u64, text: &str) -> Result<u64, ServerError> {
        let service = self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?;
        service.import_edit(target, text).map_err(ServerError::Service)
    }

    /// `RoomService::import_delete` in the room, by `ARCHIVE_OWNER` (task T350a).
    pub fn import_delete(&mut self, slug: &str, target: u64) -> Result<u64, ServerError> {
        let service = self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?;
        service.import_delete(crate::import::ARCHIVE_OWNER, target).map_err(ServerError::Service)
    }

    /// The room with this slug, for reads (`sync`, `unread`, `head`); `NoSuchRoom` if none.
    pub fn room(&self, slug: &str) -> Result<&RoomService, ServerError> {
        self.rooms.get(slug).ok_or(ServerError::NoSuchRoom)
    }

    /// The rooms `user` is a member of, sorted by slug.
    pub fn rooms_of(&self, user: &str) -> Vec<RoomInfo> {
        let mut result: Vec<RoomInfo> = Vec::new();
        for (slug, service) in &self.rooms {
            if let Some(role) = service.role(user) {
                result.push(RoomInfo { slug: slug.clone(), name: self.room_names[slug].clone(), role });
            }
        }
        result.sort_by(|a, b| a.slug.cmp(&b.slug));
        result
    }

    /// `RoomService::add_member` in the room. `NoSuchRoom` first. No rate limit.
    pub fn add_member(&mut self, slug: &str, actor: &str, user: &str, role: Role) -> Result<u64, ServerError> {
        let service = self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?;
        service.add_member(actor, user, role).map_err(ServerError::Service)
    }

    /// `RoomService::remove_member` in the room. `NoSuchRoom` first. No rate limit.
    pub fn remove_member(&mut self, slug: &str, actor: &str, user: &str) -> Result<u64, ServerError> {
        let service = self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?;
        service.remove_member(actor, user).map_err(ServerError::Service)
    }

    /// `Ok` when `user` is a member of the room. A missing room is `NoSuchRoom`; a room `user` is not in is
    /// `Service(Room(NotMember))`, which the wire answers exactly like `NoSuchRoom`. Checked before any rate-limit
    /// token is taken, so the limiter cannot be used to learn that a room exists.
    fn require_member(&self, slug: &str, user: &str) -> Result<(), ServerError> {
        let service = self.rooms.get(slug).ok_or(ServerError::NoSuchRoom)?;
        if service.members().iter().any(|(member, _)| member == user) {
            Ok(())
        } else {
            Err(ServerError::Service(ServiceError::Room(RoomError::NotMember)))
        }
    }

    /// Post in the room. Checks, in order: `NoSuchRoom`; membership (`Service(Room(NotMember))`, no token used);
    /// then one token is taken from `author`'s bucket at `now_ms` (`RateLimited` if there is none); then
    /// `RoomService::post`. A member's post the room refuses has still used its token.
    pub fn post(&mut self, slug: &str, author: &str, text: &str, now_ms: u64) -> Result<u64, ServerError> {
        self.require_member(slug, author)?;
        let key = author.to_string();
        if !self.limiter.check(&key, now_ms) {
            return Err(ServerError::RateLimited);
        }
        let service = self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?;
        service.post(author, text).map_err(ServerError::Service)
    }

    /// As `post`, for `RoomService::edit`, from the same bucket.
    pub fn edit(&mut self, slug: &str, actor: &str, target: u64, text: &str, now_ms: u64) -> Result<u64, ServerError> {
        self.require_member(slug, actor)?;
        let key = actor.to_string();
        if !self.limiter.check(&key, now_ms) {
            return Err(ServerError::RateLimited);
        }
        let service = self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?;
        service.edit(actor, target, text).map_err(ServerError::Service)
    }

    /// Edit a live message whose author was read from the durable full-history projection.
    pub(crate) fn edit_validated(
        &mut self,
        slug: &str,
        actor: &str,
        target: u64,
        author: Option<&str>,
        text: &str,
        now_ms: u64,
    ) -> Result<u64, ServerError> {
        self.require_member(slug, actor)?;
        if !self.limiter.check(&actor.to_owned(), now_ms) {
            return Err(ServerError::RateLimited);
        }
        let author = author.ok_or(ServerError::Service(ServiceError::NoSuchMessage))?;
        self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?.edit_validated(actor, target, author, text).map_err(ServerError::Service)
    }

    /// `RoomService::delete` in the room. `NoSuchRoom` first. No rate limit.
    /// `RoomService::react` in the room (task T341a), rate limited as `edit` is. `NoSuchRoom` first.
    pub fn react(&mut self, slug: &str, actor: &str, target: u64, reaction: u8, on: bool, now_ms: u64) -> Result<u64, ServerError> {
        self.require_member(slug, actor)?;
        if !self.limiter.check(&actor.to_string(), now_ms) {
            return Err(ServerError::RateLimited);
        }
        let service = self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?;
        service.react(actor, target, reaction, on).map_err(ServerError::Service)
    }

    pub fn delete(&mut self, slug: &str, actor: &str, target: u64) -> Result<u64, ServerError> {
        let service = self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?;
        service.delete(actor, target).map_err(ServerError::Service)
    }

    /// Delete a live message whose author was read from the durable full-history projection.
    pub(crate) fn delete_validated(&mut self, slug: &str, actor: &str, target: u64, author: &str) -> Result<u64, ServerError> {
        self.require_member(slug, actor)?;
        self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?.delete_validated(actor, target, author).map_err(ServerError::Service)
    }

    /// Change the room's pin, with the same membership and rate limit as an edit (task T343).
    pub fn pin(&mut self, slug: &str, actor: &str, target: u64, on: bool, now_ms: u64) -> Result<u64, ServerError> {
        self.require_member(slug, actor)?;
        if !self.limiter.check(&actor.to_owned(), now_ms) {
            return Err(ServerError::RateLimited);
        }
        self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?.pin(actor, target, on).map_err(ServerError::Service)
    }

    /// The durable server has validated a live target using its full-history projection.
    pub(crate) fn pin_validated(&mut self, slug: &str, actor: &str, target: u64, on: bool, now_ms: u64) -> Result<u64, ServerError> {
        self.require_member(slug, actor)?;
        if !self.limiter.check(&actor.to_owned(), now_ms) {
            return Err(ServerError::RateLimited);
        }
        self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?.pin_validated(actor, target, on).map_err(ServerError::Service)
    }

    /// `RoomService::mark_read` in the room. `NoSuchRoom` first.
    pub fn mark_read(&mut self, slug: &str, user: &str, cursor: u64) -> Result<bool, ServerError> {
        let service = self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?;
        service.mark_read(user, cursor).map_err(ServerError::Service)
    }

    /// The asking member marks a live message as unread (task T344). Personal metadata accepts read-only members.
    pub fn mark_unread(&mut self, slug: &str, user: &str, target: u64) -> Result<u64, ServerError> {
        self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?.mark_unread(user, target).map_err(ServerError::Service)
    }

    /// The durable caller has resolved and checked this target using its complete current-message projection.
    pub(crate) fn mark_unread_validated(&mut self, slug: &str, user: &str, target: u64) -> Result<bool, ServerError> {
        self.rooms.get_mut(slug).ok_or(ServerError::NoSuchRoom)?.mark_unread_validated(user, target).map_err(ServerError::Service)
    }

    /// Record a heartbeat from `user` (as `Presence::heartbeat`). Presence is per server, not per room.
    pub fn heartbeat(&mut self, user: &str, now_ms: u64) {
        self.presence.heartbeat(user, now_ms);
    }

    /// The room's members who are `Online` at `now_ms`, sorted. Checks, in order: `NoSuchRoom`; `user` must be a member
    /// (`Service(Room(NotMember))`).
    pub fn online_in(&self, slug: &str, user: &str, now_ms: u64) -> Result<Vec<String>, ServerError> {
        let service = self.rooms.get(slug).ok_or(ServerError::NoSuchRoom)?;
        if service.role(user).is_none() {
            return Err(ServerError::Service(ServiceError::Room(RoomError::NotMember)));
        }
        let members = service.members();
        let member_names: Vec<&str> = members.iter().map(|(name, _)| name.as_str()).collect();
        let online = self.presence.online(now_ms);
        Ok(online.into_iter().filter(|name| member_names.contains(&name.as_str())).collect())
    }
}
