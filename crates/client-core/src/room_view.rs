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
