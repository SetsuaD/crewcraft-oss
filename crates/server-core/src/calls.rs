//! Calls on the chat server, the control plane (docs/CALLS.md "Call records and liveness", task T360a1): who started
//! and joined each call, who is in it now, liveness, the room's history lines, and missed calls. No media: that is the
//! media server's (later tasks).
//!
//! Owns: `Calls` (the state, rebuilt from the journal), the call journal records' replay (`replay`, called by
//! `DurableServer::open`), and `DurableServer::call_start/join/heartbeat/leave`, `sweep_calls`, `drop_from_calls`,
//! `open_call`, `missed_calls`. Calls `server::Server` (membership, history lines), `durable` (records) and `media`
//! (every leave and end is a `MediaEvent` for the media server, task T360b2).
//!
//! Heartbeats are not journaled (one every 20 seconds per person would fill the journal); after a restart each person
//! still in an open call counts from their last journaled join, so a call nobody returns to is closed then.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::cursor_log::Since;
use crate::durable::{DurableError, DurableServer};
use crate::media::MediaEvent;
use crate::op::Op;
use crate::room_service::EventKind;
use crate::server::Server;

/// A person with no heartbeat for this long has left the call, at their last heartbeat (REQUIREMENTS 2.5).
pub const HEARTBEAT_TIMEOUT_MS: u64 = 75_000;

/// One call, open or ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    pub id: u64,
    pub room: String,
    pub video: bool,
    pub started_by: String,
    pub started_ms: u64,
    /// The cursor of the room's "started a call" line.
    pub start_cursor: u64,
    pub ended_ms: Option<u64>,
    /// Everyone who was ever in it.
    pub joined: BTreeSet<String>,
    /// Who is in it now, with their last heartbeat.
    pub present: BTreeMap<String, u64>,
    /// The call key each present person published (task T360d2). Not journaled: after a restart clients publish again.
    pub keys: BTreeMap<String, [u8; 32]>,
    /// Sealed sender keys waiting for their recipient, by (recipient, sender, kid) (task T360d2).
    pub sealed: BTreeMap<(String, String, u64), Vec<u8>>,
}

/// The most key ids a sender keeps sealed for one recipient: older ones are dropped as new ones arrive (rotation).
pub const MAX_KIDS_PER_PAIR: usize = 8;

/// Every call, by id, and each room's open call.
#[derive(Debug, Clone, Default)]
pub struct Calls {
    next: u64,
    calls: BTreeMap<u64, Call>,
    open: HashMap<String, u64>,
}

/// A call I missed (REQUIREMENTS 2.5): dated by when it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissedCall {
    pub room: String,
    pub call: u64,
    pub started_by: String,
    pub ended_ms: u64,
}

/// Why a call request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// Not a member of the room, or no such room.
    NotMember,
    /// A Guest starting a call, or an archive room.
    NotAllowed,
    /// No such open call in this room, or the person is not in it (for a heartbeat or leave): the client leaves.
    NoSuchCall,
    Durable(DurableError),
}

impl Calls {
    fn start(&mut self, room: &str, actor: &str, video: bool, now_ms: u64, start_cursor: u64) -> u64 {
        self.next += 1;
        let id = self.next;
        let call = Call {
            id,
            room: room.to_owned(),
            video,
            started_by: actor.to_owned(),
            started_ms: now_ms,
            start_cursor,
            ended_ms: None,
            joined: BTreeSet::from([actor.to_owned()]),
            present: BTreeMap::from([(actor.to_owned(), now_ms)]),
            keys: BTreeMap::new(),
            sealed: BTreeMap::new(),
        };
        self.calls.insert(id, call);
        self.open.insert(room.to_owned(), id);
        id
    }

    fn open_in(&self, room: &str, call: u64) -> Option<&Call> {
        self.open.get(room).filter(|id| **id == call).and_then(|id| self.calls.get(id))
    }

    fn open_in_mut(&mut self, room: &str, call: u64) -> Option<&mut Call> {
        let id = *self.open.get(room).filter(|id| **id == call)?;
        self.calls.get_mut(&id)
    }

    fn end(&mut self, call: u64, ended_ms: u64) {
        if let Some(record) = self.calls.get_mut(&call) {
            record.ended_ms = Some(ended_ms);
            record.present.clear();
            record.keys.clear();
            record.sealed.clear();
            self.open.remove(&record.room);
        }
    }
}

/// How long a call lasted, as the history line says it: "under a minute", "1 min", "12 min", "1 h 5 min".
pub fn duration_text(ms: u64) -> String {
    let minutes = ms / 60_000;
    match minutes {
        0 => "under a minute".to_owned(),
        1..=59 => format!("{minutes} min"),
        _ => format!("{} h {} min", minutes / 60, minutes % 60),
    }
}

fn end_line(call: &Call, ended_ms: u64) -> String {
    let people: Vec<&str> = call.joined.iter().map(String::as_str).collect();
    format!("call ended after {}: {}", duration_text(ended_ms.saturating_sub(call.started_ms)), people.join(", "))
}

/// Take `person` out of `call`, with their key and every sealed key to or from them (task T360d2).
fn forget(call: &mut Call, person: &str) {
    call.present.remove(person);
    call.keys.remove(person);
    call.sealed.retain(|(to, from, _), _| to != person && from != person);
}

/// The result of `replay`: a call record applied, or any other record, handed back untouched.
pub(crate) enum Replayed {
    Done,
    NotCall(Op),
}

/// Apply a call record at start-up, as the call that wrote it did. `Err` means the journal does not match (corrupt).
pub(crate) fn replay(server: &mut Server, calls: &mut Calls, op: Op) -> Result<Replayed, ()> {
    match op {
        Op::CallStart { slug, call, actor, video, now_ms } => {
            let cursor = server.call_line(&slug, &actor, call, false, "started a call").map_err(|_| ())?;
            if calls.start(&slug, &actor, video, now_ms, cursor) != call {
                return Err(());
            }
            Ok(Replayed::Done)
        }
        Op::CallJoin { slug, call, actor, now_ms } => {
            let record = calls.open_in_mut(&slug, call).ok_or(())?;
            record.joined.insert(actor.clone());
            record.present.insert(actor, now_ms);
            Ok(Replayed::Done)
        }
        Op::CallLeave { slug, call, actor, .. } => {
            let record = calls.open_in_mut(&slug, call).ok_or(())?;
            forget(record, &actor);
            Ok(Replayed::Done)
        }
        Op::CallEnd { slug, call, ended_ms } => {
            let record = calls.open_in(&slug, call).ok_or(())?.clone();
            server.call_line(&slug, &record.started_by, call, true, &end_line(&record, ended_ms)).map_err(|_| ())?;
            calls.end(call, ended_ms);
            Ok(Replayed::Done)
        }
        other => Ok(Replayed::NotCall(other)),
    }
}

impl DurableServer {
    /// Start a call in `slug`, or join its open call (task T360a1). A member who may post starts one; an archive room
    /// has none. Returns the call's id.
    pub fn call_start(&mut self, slug: &str, actor: &str, video: bool, now_ms: u64) -> Result<u64, CallError> {
        self.check_alive().map_err(CallError::Durable)?;
        self.sweep_calls(now_ms).map_err(CallError::Durable)?;
        let room = self.server.room(slug).map_err(|_| CallError::NotMember)?;
        if room.role(actor).is_none() {
            return Err(CallError::NotMember);
        }
        if let Some(&open) = self.calls.open.get(slug) {
            return self.call_join(slug, actor, open, now_ms).map(|()| open);
        }
        if room.is_read_only() || room.role(actor) == Some(crate::room::Role::Guest) {
            return Err(CallError::NotAllowed);
        }
        let call = self.calls.next + 1;
        let cursor = self.server.call_line(slug, actor, call, false, "started a call").map_err(|e| CallError::Durable(DurableError::Server(e)))?;
        self.record(&Op::CallStart { slug: slug.to_owned(), call, actor: actor.to_owned(), video, now_ms }).map_err(CallError::Durable)?;
        self.calls.start(slug, actor, video, now_ms, cursor);
        Ok(call)
    }

    /// Join the open call `call` of `slug` (task T360a1). Joining a call one is already in is a heartbeat.
    pub fn call_join(&mut self, slug: &str, actor: &str, call: u64, now_ms: u64) -> Result<(), CallError> {
        self.check_alive().map_err(CallError::Durable)?;
        self.member(slug, actor)?;
        let record = self.calls.open_in(slug, call).ok_or(CallError::NoSuchCall)?;
        if record.present.contains_key(actor) {
            return self.call_heartbeat(slug, actor, call, now_ms);
        }
        self.record(&Op::CallJoin { slug: slug.to_owned(), call, actor: actor.to_owned(), now_ms }).map_err(CallError::Durable)?;
        if let Some(record) = self.calls.open_in_mut(slug, call) {
            record.joined.insert(actor.to_owned());
            record.present.insert(actor.to_owned(), now_ms);
        }
        Ok(())
    }

    /// A heartbeat from `actor` in call `call` of `slug` (task T360a1). `NoSuchCall` when the call ended or the person
    /// is no longer in it; `NotMember` when they are no longer in the room. Either way the client leaves and says why.
    pub fn call_heartbeat(&mut self, slug: &str, actor: &str, call: u64, now_ms: u64) -> Result<(), CallError> {
        self.check_alive().map_err(CallError::Durable)?;
        self.sweep_calls(now_ms).map_err(CallError::Durable)?;
        self.member(slug, actor)?;
        let record = self.calls.open_in_mut(slug, call).ok_or(CallError::NoSuchCall)?;
        let seen = record.present.get_mut(actor).ok_or(CallError::NoSuchCall)?;
        *seen = (*seen).max(now_ms);
        Ok(())
    }

    /// `actor` leaves call `call` of `slug` at `now_ms` (task T360a1). The call ends when the last person leaves.
    pub fn call_leave(&mut self, slug: &str, actor: &str, call: u64, now_ms: u64) -> Result<(), CallError> {
        self.check_alive().map_err(CallError::Durable)?;
        let record = self.calls.open_in(slug, call).ok_or(CallError::NoSuchCall)?;
        if !record.present.contains_key(actor) {
            return Err(CallError::NoSuchCall);
        }
        self.leave_at(slug, actor, call, now_ms).map_err(CallError::Durable)
    }

    fn leave_at(&mut self, slug: &str, actor: &str, call: u64, at_ms: u64) -> Result<(), DurableError> {
        self.record(&Op::CallLeave { slug: slug.to_owned(), call, actor: actor.to_owned(), now_ms: at_ms })?;
        let Some(record) = self.calls.open_in_mut(slug, call) else { return Ok(()) };
        forget(record, actor);
        let ended = record.present.is_empty().then(|| record.clone());
        // Out of the call means out of its media at once (task T360b2).
        self.media.push(MediaEvent::DropPerson { call, person: actor.to_owned() });
        if let Some(record) = ended {
            self.server.call_line(slug, &record.started_by, call, true, &end_line(&record, at_ms)).map_err(DurableError::Server)?;
            self.record(&Op::CallEnd { slug: slug.to_owned(), call, ended_ms: at_ms })?;
            self.calls.end(call, at_ms);
            self.media.push(MediaEvent::EndCall { call });
        }
        Ok(())
    }

    /// Take everyone whose last heartbeat is older than `HEARTBEAT_TIMEOUT_MS` out of their call, at that heartbeat;
    /// a call left empty ends at its last heartbeat (REQUIREMENTS 2.5). Also takes out anyone no longer in the room.
    pub fn sweep_calls(&mut self, now_ms: u64) -> Result<(), DurableError> {
        let mut gone: Vec<(String, String, u64, u64)> = Vec::new();
        for call in self.calls.calls.values().filter(|call| call.ended_ms.is_none()) {
            let room = self.server.room(&call.room).ok();
            for (person, seen) in &call.present {
                let left_room = room.is_none_or(|room| room.role(person).is_none());
                if left_room || now_ms.saturating_sub(*seen) > HEARTBEAT_TIMEOUT_MS {
                    gone.push((call.room.clone(), person.clone(), call.id, *seen));
                }
            }
        }
        // Oldest first, so a call's end is the last heartbeat of the last to go.
        gone.sort_by_key(|(_, _, _, seen)| *seen);
        for (slug, person, call, seen) in gone {
            self.leave_at(&slug, &person, call, seen)?;
        }
        Ok(())
    }

    /// Take `person` out of every open call now (task T360b2): they lost the right to be in any, such as when their
    /// devices are revoked or the authorizer withdraws their access. Returns how many calls they left.
    pub fn drop_from_calls(&mut self, person: &str, now_ms: u64) -> Result<usize, DurableError> {
        self.check_alive()?;
        let calls: Vec<(String, u64)> = self
            .calls
            .calls
            .values()
            .filter(|call| call.ended_ms.is_none() && call.present.contains_key(person))
            .map(|call| (call.room.clone(), call.id))
            .collect();
        for (slug, call) in &calls {
            self.leave_at(slug, person, *call, now_ms)?;
        }
        Ok(calls.len())
    }

    /// Publish `actor`'s call key for `call` (task T360d2): only someone in the call.
    pub fn call_key(&mut self, slug: &str, actor: &str, call: u64, public: [u8; 32], now_ms: u64) -> Result<(), CallError> {
        self.call_heartbeat(slug, actor, call, now_ms)?;
        if let Some(record) = self.calls.open_in_mut(slug, call) {
            record.keys.insert(actor.to_owned(), public);
        }
        Ok(())
    }

    /// Leave `actor`'s key `kid`, sealed to `to`, for `to` to collect (task T360d2). Both must be in the call; a
    /// sender keeps at most `MAX_KIDS_PER_PAIR` keys for one recipient, the oldest dropped first.
    #[allow(clippy::too_many_arguments)]
    pub fn call_seal(&mut self, slug: &str, actor: &str, call: u64, to: &str, kid: u64, sealed: Vec<u8>, now_ms: u64) -> Result<(), CallError> {
        self.call_heartbeat(slug, actor, call, now_ms)?;
        let record = self.calls.open_in_mut(slug, call).ok_or(CallError::NoSuchCall)?;
        if !record.present.contains_key(to) || to == actor {
            return Err(CallError::NoSuchCall);
        }
        record.sealed.insert((to.to_owned(), actor.to_owned(), kid), sealed);
        let mine: Vec<u64> = record.sealed.keys().filter(|(t, f, _)| t == to && f == actor).map(|(_, _, k)| *k).collect();
        for old in mine.iter().take(mine.len().saturating_sub(MAX_KIDS_PER_PAIR)) {
            record.sealed.remove(&(to.to_owned(), actor.to_owned(), *old));
        }
        Ok(())
    }

    /// The open call of `slug`, if any.
    pub fn open_call(&self, slug: &str) -> Option<&Call> {
        self.calls.open.get(slug).and_then(|id| self.calls.calls.get(id))
    }

    /// The call with this id, open or ended.
    pub fn call(&self, call: u64) -> Option<&Call> {
        self.calls.calls.get(&call)
    }

    /// The calls `user` missed (REQUIREMENTS 2.5), newest end first: in a room they are still in, started by someone
    /// else after they joined the room, ended, and never joined by them.
    pub fn missed_calls(&self, user: &str) -> Vec<MissedCall> {
        let mut missed: Vec<MissedCall> = self
            .calls
            .calls
            .values()
            .filter(|call| call.started_by != user && !call.joined.contains(user))
            .filter_map(|call| {
                let ended_ms = call.ended_ms?;
                let joined_room = self.joined_room_at(&call.room, user)?;
                (joined_room < call.start_cursor).then(|| MissedCall {
                    room: call.room.clone(),
                    call: call.id,
                    started_by: call.started_by.clone(),
                    ended_ms,
                })
            })
            .collect();
        missed.sort_by(|a, b| b.ended_ms.cmp(&a.ended_ms).then(a.call.cmp(&b.call)));
        missed
    }

    /// The cursor at which `user` (still a member) last joined `slug`: their latest `Joined` event, or 0 when the log
    /// shows none (the room's creator, or a join older than the log holds). `None` when not a member.
    fn joined_room_at(&self, slug: &str, user: &str) -> Option<u64> {
        let room = self.server.room(slug).ok()?;
        room.role(user)?;
        let events = match room.sync(user, 0).ok()? {
            Since::Events(events) => events,
            Since::Gap { .. } => return Some(0),
        };
        Some(
            events.iter().rev().find(|(_, event)| matches!(&event.kind, EventKind::Joined { user: who, .. } if who == user)).map_or(0, |(at, _)| *at),
        )
    }

    fn member(&self, slug: &str, actor: &str) -> Result<(), CallError> {
        match self.server.room(slug) {
            Ok(room) if room.role(actor).is_some() => Ok(()),
            _ => Err(CallError::NotMember),
        }
    }
}
