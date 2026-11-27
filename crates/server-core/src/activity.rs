//! Personal activity derived from accepted room operations (T347). Only the seen watermark is journaled separately.
//! References retain no message body. Every response resolves current live content and current room access; a
//! person's bounded reference queue survives event-tail eviction by rebuilding from all journal operations.

use std::collections::{BTreeMap, HashMap, VecDeque};

use crewcraft_proto::activity::{ActivityFilter, ActivityItem, ActivityKind, ActivitySnapshot, MAX_ACTIVITY_HISTORY, MAX_ACTIVITY_ITEMS};
use crewcraft_proto::request::{MAX_AUTHOR, MAX_SNIPPET};

use crate::calls::Calls;
use crate::guests::Guests;
use crate::durable::{CurrentMessage, DurableError, DurableServer};
use crate::html_text::html_text;
use crate::mentions::{mentions, resolve_tokens};
use crate::op::Op;
use crate::server::Server;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityError {
    PastHead,
    Storage(DurableError),
}

#[derive(Default)]
pub(crate) struct Activity {
    people: HashMap<String, Personal>,
}

#[derive(Default)]
struct Personal {
    head: u64,
    seen: u64,
    items: VecDeque<Reference>,
}

#[derive(Clone)]
struct Reference {
    id: u64,
    room: String,
    actor: String,
    at_ms: u64,
    target: u64,
    parent: Option<u64>,
    kind: ActivityKind,
}

pub(crate) struct ActivityView<'a> {
    pub server: &'a Server,
    pub messages: &'a HashMap<String, BTreeMap<u64, CurrentMessage>>,
    pub parents: &'a HashMap<(String, u64), u64>,
    pub calls: &'a Calls,
    pub guests: &'a Guests,
}

struct MessageEvent<'a> {
    slug: &'a str,
    actor: &'a str,
    target: u64,
    parent: Option<u64>,
    text: &'a str,
    at_ms: u64,
}

impl Activity {
    pub(crate) fn replayed(&mut self, op: Option<&Op>, view: ActivityView<'_>, was_reacting: bool) {
        if let Some(op) = op {
            self.observe(op, view, was_reacting);
        }
    }
    pub(crate) fn position(&self, user: &str) -> (u64, u64) {
        self.people.get(user).map_or((0, 0), |person| (person.head, person.seen))
    }

    pub(crate) fn mark_seen(&mut self, user: &str, through: u64) -> Result<u64, ActivityError> {
        let (head, seen) = self.position(user);
        if through > head {
            return Err(ActivityError::PastHead);
        }
        if through <= seen {
            return Ok(seen);
        }
        let person = self.people.entry(user.to_owned()).or_default();
        person.seen = through;
        Ok(through)
    }

    /// Observe after acceptance and before the current-message index changes. React additionally carries its
    /// pre-mutation edge state, since an accepted repeated on=true operation is not new personal activity.
    pub(crate) fn observe(&mut self, op: &Op, view: ActivityView<'_>, was_reacting: bool) {
        match op {
            Op::Post { slug, author, text, now_ms } | Op::PostFiles { slug, author, text, now_ms, .. } => {
                if let Ok(room) = view.server.room(slug) {
                    self.message(&view, MessageEvent { slug, actor: author, target: room.head(), parent: None, text, at_ms: *now_ms });
                }
            }
            Op::Reply { slug, author, parent, text, now_ms } => {
                if let Ok(room) = view.server.room(slug) {
                    self.message(&view, MessageEvent { slug, actor: author, target: room.head(), parent: Some(*parent), text, at_ms: *now_ms });
                }
            }
            Op::Edit { slug, actor, target, text, now_ms } => {
                self.edited_mentions(&view, MessageEvent { slug, actor, target: *target, parent: None, text, at_ms: *now_ms });
            }
            Op::React { .. } => self.reaction(&view, op, was_reacting),
            Op::RemoveMember { slug, user, .. } => {
                if let Some(person) = self.people.get_mut(user) {
                    person.items.retain(|item| &item.room != slug);
                }
            }
            Op::Delete { slug, target, .. } => {
                if let Ok(room) = view.server.room(slug) {
                    for (member, _) in room.members() {
                        if let Some(person) = self.people.get_mut(&member) {
                            person.items.retain(|item| &item.room != slug || matches!(item.kind, ActivityKind::MissedCall) || item.target != *target);
                        }
                    }
                }
            }
            Op::CallEnd { slug, call, ended_ms } => self.missed_call(&view, slug, *call, *ended_ms),
            Op::MarkActivitySeen { user, through } => {
                let _ = self.mark_seen(user, *through);
            }
            _ => {}
        }
    }

    fn message(&mut self, view: &ActivityView<'_>, event: MessageEvent<'_>) {
        let MessageEvent { slug, actor, target, parent, text, at_ms } = event;
        let Ok(room) = view.server.room(slug) else { return };
        if room.is_read_only() || actor.is_empty() || actor.len() > MAX_AUTHOR {
            return;
        }
        let tokens = mentions(text);
        let mut recipients: BTreeMap<String, (bool, bool)> = BTreeMap::new();
        if !tokens.is_empty() {
            let members: Vec<_> = room.members().into_iter().map(|(member, _)| member).collect();
            for member in resolve_tokens(tokens, &members) {
                if member != actor {
                    recipients.insert(member, (true, false));
                }
            }
        }
        if let Some(author) = parent.and_then(|parent| view.messages.get(slug)?.get(&parent)).map(|message| &message.author)
            && author != actor
            && room.role(author).is_some()
        {
            recipients.entry(author.clone()).or_default().1 = true;
        }
        for (user, (mentioned, replied)) in recipients {
            self.push(
                &user,
                Reference {
                    id: 0,
                    room: slug.to_owned(),
                    actor: actor.to_owned(),
                    at_ms,
                    target,
                    parent,
                    kind: ActivityKind::Message { mentioned, replied },
                },
            );
        }
    }

    fn edited_mentions(&mut self, view: &ActivityView<'_>, event: MessageEvent<'_>) {
        let MessageEvent { slug, actor, target, text, at_ms, .. } = event;
        let Some(previous) = view.messages.get(slug).and_then(|messages| messages.get(&target)) else { return };
        let tokens: Vec<_> = mentions(text).into_iter().filter(|token| !previous.mention_tokens.contains(token)).collect();
        if tokens.is_empty() || actor.is_empty() || actor.len() > MAX_AUTHOR {
            return;
        }
        let Ok(room) = view.server.room(slug) else { return };
        if room.is_read_only() {
            return;
        }
        let parent = view.parents.get(&(slug.to_owned(), target)).copied();
        let members: Vec<_> = room.members().into_iter().map(|(member, _)| member).collect();
        for user in resolve_tokens(tokens, &members).into_iter().filter(|member| member != actor) {
            let old = self.people.get_mut(&user).and_then(|person| {
                let index = person
                    .items
                    .iter()
                    .position(|item| item.room == slug && item.target == target && matches!(item.kind, ActivityKind::Message { .. }))?;
                person.items.remove(index)
            });
            let replied = old.as_ref().is_some_and(|item| matches!(item.kind, ActivityKind::Message { replied: true, .. }));
            self.push(
                &user,
                Reference {
                    id: 0,
                    room: slug.to_owned(),
                    actor: actor.to_owned(),
                    at_ms,
                    target,
                    parent,
                    kind: ActivityKind::Message { mentioned: true, replied },
                },
            );
        }
    }

    fn reaction(&mut self, view: &ActivityView<'_>, op: &Op, was_reacting: bool) {
        let Op::React { slug, actor, target, reaction, on, now_ms } = op else { return };
        let (target, reaction, on, at_ms) = (*target, *reaction, *on, *now_ms);
        let (slug, actor) = (slug.as_str(), actor.as_str());
        let Some(message) = view.messages.get(slug).and_then(|messages| messages.get(&target)) else { return };
        let Ok(room) = view.server.room(slug) else { return };
        if !on {
            if let Some(person) = self.people.get_mut(&message.author) {
                person.items.retain(|item| {
                    !(item.room == slug && item.target == target && item.actor == actor && item.kind == ActivityKind::Reaction { reaction })
                });
            }
            return;
        }
        if was_reacting
            || room.is_read_only()
            || message.author == actor
            || room.role(&message.author).is_none()
            || actor.is_empty()
            || actor.len() > MAX_AUTHOR
        {
            return;
        }
        self.push(
            &message.author,
            Reference {
                id: 0,
                room: slug.to_owned(),
                actor: actor.to_owned(),
                at_ms,
                target,
                parent: None,
                kind: ActivityKind::Reaction { reaction },
            },
        );
    }

    fn missed_call(&mut self, view: &ActivityView<'_>, slug: &str, call: u64, ended_ms: u64) {
        if view.guests.bound_to(call).is_some() { return; }
        let Some(call) = view.calls.get(call) else { return };
        let Ok(room) = view.server.room(slug) else { return };
        if room.is_read_only() || call.started_by.is_empty() || call.started_by.len() > MAX_AUTHOR {
            return;
        }
        for (person, _) in room.members() {
            if person != call.started_by && !call.joined.contains(&person) && room.joined_at(&person).is_some_and(|joined| joined < call.start_cursor)
            {
                self.push(
                    &person,
                    Reference {
                        id: 0,
                        room: slug.to_owned(),
                        actor: call.started_by.clone(),
                        at_ms: ended_ms,
                        target: call.id,
                        parent: None,
                        kind: ActivityKind::MissedCall,
                    },
                );
            }
        }
    }

    fn push(&mut self, user: &str, mut item: Reference) {
        let person = self.people.entry(user.to_owned()).or_default();
        let Some(id) = person.head.checked_add(1) else { return };
        person.head = id;
        item.id = id;
        person.items.push_back(item);
        while person.items.len() > MAX_ACTIVITY_HISTORY {
            person.items.pop_front();
        }
    }

    pub(crate) fn snapshot(&self, user: &str, filter: ActivityFilter, view: ActivityView<'_>, saved: impl Fn(&str, u64) -> bool) -> ActivitySnapshot {
        let Some(person) = self.people.get(user) else { return ActivitySnapshot::default() };
        let mut unread = 0;
        let mut matching = 0;
        let mut items = Vec::new();
        for item in person.items.iter().rev().filter(|item| item.eligible(user, &view)) {
            if item.id > person.seen {
                unread += 1;
            }
            let matches = match filter {
                ActivityFilter::All => true,
                ActivityFilter::Unread => item.id > person.seen,
                ActivityFilter::Mentions => matches!(item.kind, ActivityKind::Message { mentioned: true, .. }),
                ActivityFilter::Saved => !matches!(item.kind, ActivityKind::MissedCall) && saved(&item.room, item.target),
                ActivityFilter::Badge => false,
            };
            if matches {
                matching += 1;
                if items.len() < MAX_ACTIVITY_ITEMS {
                    items.push(item.render(&view));
                }
            }
        }
        ActivitySnapshot { head: person.head, seen: person.seen, unread, more: matching > MAX_ACTIVITY_ITEMS, items }
    }
}

impl Reference {
    fn eligible(&self, user: &str, view: &ActivityView<'_>) -> bool {
        let Ok(room) = view.server.room(&self.room) else { return false };
        if room.is_read_only() || room.role(user).is_none() || self.actor == user {
            return false;
        }
        match self.kind {
            ActivityKind::MissedCall => view.calls.get(self.target).is_some_and(|call| {
                call.room == self.room
                    && call.ended_ms.is_some()
                    && !call.joined.contains(user)
                    && room.joined_at(user).is_some_and(|joined| joined < call.start_cursor)
            }),
            ActivityKind::Message { .. } | ActivityKind::Reaction { .. } => {
                let Some(message) = view.messages.get(&self.room).and_then(|messages| messages.get(&self.target)) else { return false };
                match self.kind {
                    ActivityKind::Reaction { reaction } => {
                        message.author == user && room.reaction_edges(self.target).any(|(code, actor)| code == reaction && actor == self.actor)
                    }
                    _ => true,
                }
            }
        }
    }

    fn render(&self, view: &ActivityView<'_>) -> ActivityItem {
        let snippet = if matches!(self.kind, ActivityKind::MissedCall) {
            String::new()
        } else {
            view.messages
                .get(&self.room)
                .and_then(|messages| messages.get(&self.target))
                .map_or_else(String::new, |message| clip(&html_text(&message.html), MAX_SNIPPET))
        };
        ActivityItem {
            id: self.id,
            room: self.room.clone(),
            actor: self.actor.clone(),
            at_ms: self.at_ms,
            target: self.target,
            parent: self.parent,
            kind: self.kind,
            snippet,
        }
    }
}

pub(crate) fn was_reacting(server: &Server, op: &Op) -> bool {
    let Op::React { slug, actor, target, reaction, .. } = op else { return false };
    server.room(slug).is_ok_and(|room| room.reaction_edges(*target).any(|(code, person)| code == *reaction && person == actor))
}

pub(crate) fn message_source(op: &Op) -> Option<&str> {
    match op {
        Op::Post { text, .. } | Op::PostFiles { text, .. } | Op::Reply { text, .. } | Op::Edit { text, .. } => Some(text),
        _ => None,
    }
}

pub(crate) fn observed_op(op: &Op) -> Option<Op> {
    match op {
        Op::Post { .. }
        | Op::PostFiles { .. }
        | Op::Reply { .. }
        | Op::Edit { .. }
        | Op::React { .. }
        | Op::RemoveMember { .. }
        | Op::Delete { .. }
        | Op::CallEnd { .. }
        | Op::MarkActivitySeen { .. } => Some(op.clone()),
        _ => None,
    }
}

fn clip(text: &str, limit: usize) -> String {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

impl DurableServer {
    pub fn activity(&self, user: &str, filter: ActivityFilter) -> ActivitySnapshot {
        self.activity.snapshot(
            user,
            filter,
            ActivityView { server: &self.server, messages: &self.previews, parents: &self.parents, calls: &self.calls, guests: &self.guests },
            |room, target| self.has_saved(user, room, target),
        )
    }

    pub fn mark_activity_seen(&mut self, user: &str, through: u64) -> Result<u64, ActivityError> {
        self.check_alive().map_err(ActivityError::Storage)?;
        let (head, seen) = self.activity.position(user);
        if through > head {
            return Err(ActivityError::PastHead);
        }
        if through > seen {
            self.record(&Op::MarkActivitySeen { user: user.to_owned(), through }).map_err(ActivityError::Storage)?;
        }
        Ok(self.activity.position(user).1)
    }
}
