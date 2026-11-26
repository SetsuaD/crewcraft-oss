//! One room as the client app draws it: the server's timeline, then the user's own messages still on their way.
//! Composed from `timeline` (T121) and `outbox` (T113). Task T123.

use std::collections::{BTreeMap, BTreeSet};

use crate::outbox::{Outbox, State};
use crate::timeline::{Apply, Change, Line, Timeline};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    /// A message from the server's timeline.
    Line(Line),
    /// One of the user's own messages that is not in the timeline yet, by its outbox id. `failed` when the outbox has
    /// given up on it (`State::Dead`).
    Pending { id: u64, body: String, failed: bool },
}

/// A room's open call, as the server last said (task T360a1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenCall {
    pub call: u64,
    pub video: bool,
    pub started_by: String,
    pub started_ms: u64,
    pub participants: Vec<String>,
}

/// A call's history line (task T360a1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallLineRow {
    pub call: u64,
    pub ended: bool,
    pub author: String,
    pub text: String,
}

pub struct RoomView {
    timeline: Timeline,
    outbox: Outbox,
    /// Outbox ids currently in the outbox (not yet acked).
    outbox_ids: BTreeSet<u64>,
    /// Acked messages: outbox id -> (server cursor, body).
    acked: BTreeMap<u64, (u64, String)>,
    needs_resync: bool,
    /// The files each message carries, by its cursor (task T330c).
    attachments: BTreeMap<u64, Vec<crewcraft_proto::push::AttachedFile>>,
    /// Each reply's parent, by the reply's cursor (task T340a).
    parents: BTreeMap<u64, u64>,
    /// Who reacted to each message, by its cursor, then by reaction code (task T341a).
    reactions: BTreeMap<u64, BTreeMap<u8, BTreeSet<String>>>,
    /// An archive room: read-only, imported (task T350d1).
    archived: bool,
    /// Imported messages' original times, by cursor (task T350d1).
    sent: BTreeMap<u64, u64>,
    /// The room's open call (task T360a1).
    call: Option<OpenCall>,
    /// Call history lines, by cursor (task T360a1).
    call_lines: BTreeMap<u64, CallLineRow>,
    /// The open call's participants' call keys, for the call they belong to (task T360d2).
    call_keys: Option<(u64, BTreeMap<String, [u8; 32]>)>,
    /// Sender keys sealed to me, by call, then (sender, kid) (task T360d2).
    sealed: BTreeMap<u64, BTreeMap<(String, u64), Vec<u8>>>,
}

impl Default for RoomView {
    fn default() -> Self {
        Self::new()
    }
}

impl RoomView {
    /// An empty view at cursor 0 with an empty outbox.
    pub fn new() -> Self {
        Self {
            timeline: Timeline::new(),
            outbox: Outbox::new(),
            outbox_ids: BTreeSet::new(),
            acked: BTreeMap::new(),
            needs_resync: false,
            attachments: BTreeMap::new(),
            parents: BTreeMap::new(),
            reactions: BTreeMap::new(),
            archived: false,
            sent: BTreeMap::new(),
            call: None,
            call_lines: BTreeMap::new(),
            call_keys: None,
            sealed: BTreeMap::new(),
        }
    }

    /// Queue a message to send (as `Outbox::push`); returns its outbox id.
    pub fn send(&mut self, text: &str, now_ms: u64) -> u64 {
        let id = self.outbox.push(text, now_ms);
        self.outbox_ids.insert(id);
        id
    }

    /// The outbox ids to send now (as `Outbox::due`).
    pub fn due(&self, now_ms: u64) -> Vec<u64> {
        self.outbox.due(now_ms)
    }

    /// The text to send for an outbox id; `None` once it has left the outbox, or if unknown.
    pub fn body(&self, id: u64) -> Option<String> {
        self.outbox.get(id).map(|e| e.body)
    }

    /// Sending `id` failed at `now_ms` (as `Outbox::fail`).
    pub fn send_failed(&mut self, id: u64, now_ms: u64) -> bool {
        self.outbox.fail(id, now_ms)
    }

    /// The server accepted outbox message `id` as its event at `cursor`. The entry leaves the outbox, but it is still
    /// shown as `Pending` (not failed) until the view's cursor reaches `cursor`; from then on the timeline's posted line
    /// stands in for it and it is no longer shown. If the view's cursor is already at or past `cursor`, it is never
    /// shown again. False (and nothing changes) if `id` is not in the outbox.
    pub fn acked(&mut self, id: u64, cursor: u64) -> bool {
        let body = match self.outbox.get(id) {
            Some(entry) => entry.body,
            None => return false,
        };
        self.outbox.ack(id);
        self.outbox_ids.remove(&id);
        if cursor > self.timeline.cursor() {
            self.acked.insert(id, (cursor, body));
        }
        true
    }

    /// Forget the acked messages the timeline has reached: they are never shown again, even if a later snapshot is
    /// older.
    fn drop_reached(&mut self) {
        let reached = self.timeline.cursor();
        self.acked.retain(|_, (cursor, _)| *cursor > reached);
    }

    /// Apply a server event (as `Timeline::apply`). When that returns `NeedsResync`, `needs_resync()` is true until the
    /// next `snapshot`.
    /// Keep the files the message at `cursor` carries (task T330c).
    pub fn attach(&mut self, cursor: u64, files: Vec<crewcraft_proto::push::AttachedFile>) {
        self.attachments.insert(cursor, files);
    }

    /// Keep that the message at `cursor` is a reply to the message at `parent` (task T340a).
    pub fn thread(&mut self, cursor: u64, parent: u64) {
        self.parents.insert(cursor, parent);
    }

    /// Each reply's parent, by the reply's cursor (task T340a).
    pub fn parents(&self) -> &BTreeMap<u64, u64> {
        &self.parents
    }

    /// Keep that `author` added (`on`) or took back `reaction` on the message at `target` (task T341a).
    pub fn react(&mut self, target: u64, author: &str, reaction: u8, on: bool) {
        let people = self.reactions.entry(target).or_default();
        if on {
            people.entry(reaction).or_default().insert(author.to_owned());
        } else if let Some(who) = people.get_mut(&reaction) {
            who.remove(author);
            if who.is_empty() {
                people.remove(&reaction);
            }
        }
        if people.is_empty() {
            self.reactions.remove(&target);
        }
    }

    /// Keep that this is an archive room (task T350d1).
    pub fn set_archived(&mut self) {
        self.archived = true;
    }

    /// Whether this is an archive room (task T350d1).
    pub fn archived(&self) -> bool {
        self.archived
    }

    /// Keep the original time of the imported message at `cursor` (task T350d1).
    pub fn sent(&mut self, cursor: u64, sent_ms: u64) {
        self.sent.insert(cursor, sent_ms);
    }

    /// Imported messages' original times, by cursor (task T350d1).
    pub fn sent_times(&self) -> &BTreeMap<u64, u64> {
        &self.sent
    }

    /// Keep the room's open call, or that it has none (task T360a1).
    pub fn set_call(&mut self, call: Option<OpenCall>) {
        self.call = call;
    }

    /// The room's open call, if any (task T360a1).
    pub fn call(&self) -> Option<&OpenCall> {
        self.call.as_ref()
    }

    /// Keep a call's history line at `cursor`; the end of the open call closes it (task T360a1).
    pub fn call_line(&mut self, cursor: u64, line: CallLineRow) {
        if line.ended && self.call.as_ref().is_some_and(|open| open.call == line.call) {
            self.call = None;
        }
        if line.ended {
            self.sealed.remove(&line.call);
            if self.call_keys.as_ref().is_some_and(|(call, _)| *call == line.call) {
                self.call_keys = None;
            }
        }
        self.call_lines.insert(cursor, line);
    }

    /// Call history lines, by cursor (task T360a1).
    pub fn call_lines(&self) -> &BTreeMap<u64, CallLineRow> {
        &self.call_lines
    }

    /// Keep the participants' call keys for `call` (task T360d2): the latest list replaces the last.
    pub fn set_call_keys(&mut self, call: u64, keys: Vec<(String, [u8; 32])>) {
        self.call_keys = Some((call, keys.into_iter().collect()));
    }

    /// The participants' call keys, when they are for `call`.
    pub fn call_keys(&self, call: u64) -> Option<&BTreeMap<String, [u8; 32]>> {
        self.call_keys.as_ref().filter(|(of, _)| *of == call).map(|(_, keys)| keys)
    }

    /// Keep `from`'s key `kid` for `call`, sealed to me (task T360d2).
    pub fn add_sealed(&mut self, call: u64, from: String, kid: u64, sealed: Vec<u8>) {
        self.sealed.entry(call).or_default().insert((from, kid), sealed);
    }

    /// The sender keys sealed to me for `call`, by (sender, kid).
    pub fn sealed(&self, call: u64) -> Option<&BTreeMap<(String, u64), Vec<u8>>> {
        self.sealed.get(&call)
    }

    /// Who reacted to each message that has reactions, by cursor, then by reaction code (task T341a).
    pub fn reactions(&self) -> &BTreeMap<u64, BTreeMap<u8, BTreeSet<String>>> {
        &self.reactions
    }

    /// The files of each message that has any, by cursor (task T330c).
    pub fn attachments(&self) -> &BTreeMap<u64, Vec<crewcraft_proto::push::AttachedFile>> {
        &self.attachments
    }

    pub fn event(&mut self, cursor: u64, change: Change) -> Apply {
        let result = self.timeline.apply(cursor, change);
        if result == Apply::NeedsResync {
            self.needs_resync = true;
        }
        self.drop_reached();
        result
    }

    pub fn needs_resync(&self) -> bool {
        self.needs_resync
    }

    /// Replace the timeline with a snapshot (as `Timeline::reset`) and clear `needs_resync`. The outbox is untouched; an
    /// acked message whose cursor is at or below the snapshot's is no longer shown.
    pub fn snapshot(&mut self, lines: Vec<Line>, cursor: u64) {
        self.timeline.reset(lines, cursor);
        self.needs_resync = false;
        self.drop_reached();
    }

    /// The timeline's cursor.
    pub fn cursor(&self) -> u64 {
        self.timeline.cursor()
    }

    /// Everything to draw, in order: the timeline's lines (oldest first); then the acked messages still shown, by
    /// their cursor; then every outbox entry, by id, `failed` for the dead ones.
    pub fn shown(&self) -> Vec<Shown> {
        let mut result = Vec::new();

        // Timeline lines (oldest first)
        for line in self.timeline.lines() {
            result.push(Shown::Line(line.clone()));
        }

        // Acked messages still shown (acked cursor > timeline cursor), sorted by cursor
        let mut acked_shown: Vec<(u64, u64, &String)> =
            self.acked.iter().filter(|(_, (cursor, _))| *cursor > self.timeline.cursor()).map(|(id, (cursor, body))| (*cursor, *id, body)).collect();
        acked_shown.sort_by_key(|(cursor, _, _)| *cursor);
        for (_cursor, id, body) in acked_shown {
            result.push(Shown::Pending { id, body: body.clone(), failed: false });
        }

        // Outbox entries by id
        for id in &self.outbox_ids {
            if let Some(entry) = self.outbox.get(*id) {
                result.push(Shown::Pending { id: *id, body: entry.body, failed: entry.state == State::Dead });
            }
        }

        result
    }
}
