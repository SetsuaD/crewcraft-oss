//! One room as the client app draws it: the server's timeline, then the user's own messages still on their way.
//! Composed from `timeline` (T121) and `outbox` (T113). Task T123.

use std::collections::{BTreeMap, BTreeSet};

use crewcraft_proto::current::{CurrentPage, CurrentRecord, MAX_CURRENT_BYTES, MAX_CURRENT_MESSAGES, MAX_CURRENT_PAGE_RECORDS, MAX_CURRENT_RECORDS};
use crewcraft_proto::message::CodecError;

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

#[cfg(test)]
mod current_window_tests {
    use super::*;
    use crewcraft_proto::current::encode_page;
    use crewcraft_proto::push::AttachedFile;

    fn page(index: u32, last: bool, records: Vec<CurrentRecord>) -> CurrentPage {
        CurrentPage { room: "room".into(), head: 40, index, last, older: true, archived: false, records }
    }

    fn stage(window: &mut CurrentWindow, page: CurrentPage) -> Result<bool, CodecError> {
        let bytes = encode_page(7, &page)?.len() + 4;
        window.page(page, bytes)
    }

    fn message() -> CurrentRecord {
        CurrentRecord::Message {
            cursor: 30,
            author: "writer@example.org".into(),
            html: "<p>Current edited reply</p>".into(),
            edited: true,
            parent: Some(2),
            sent_ms: Some(0),
        }
    }

    #[test]
    fn replacement_is_atomic_and_replaces_sidecars_without_losing_pending_sends() -> Result<(), CodecError> {
        let mut view = RoomView::new();
        view.snapshot(vec![Line { cursor: 1, author: "writer@example.org".into(), html: "old body".into(), edited: false }], 1);
        let pending = view.send("still sending", 0);
        let reached_ack = view.send("already accepted", 0);
        let future_ack = view.send("accepted beyond capture", 0);
        assert!(view.acked(reached_ack, 10));
        assert!(view.acked(future_ack, 100));
        view.attach(1, vec![AttachedFile { file: [1; 16], name: "old.txt".into(), size: 3, image: None }]);
        view.thread(1, 9);
        view.react(1, "reader@example.org", 1, true);
        view.set_archived();
        view.sent(1, 12);
        view.set_call(Some(OpenCall { call: 8, video: false, started_by: "reader@example.org".into(), started_ms: 1, participants: Vec::new() }));
        view.call_line(2, CallLineRow { call: 8, ended: false, author: "reader@example.org".into(), text: "old call".into() });
        view.set_call_keys(8, vec![("reader@example.org".into(), [4; 32])]);
        view.add_sealed(8, "reader@example.org".into(), 2, vec![5]);
        view.pin_state(40, Some(PinnedMessage { target: 1, author: "writer@example.org".into(), html: "pin".into(), edited: false }));
        view.set_read_state(ReadState { head: 40, position: 20, revision: 3, unread: 1 });
        view.note_gap(40, 1, 20);
        let before = view.shown();
        let mut incomplete = CurrentWindow::new("room", 40);
        assert!(!stage(&mut incomplete, page(0, false, vec![message()]))?);
        assert!(view.install_current(incomplete).is_err());
        assert_eq!(view.shown(), before);
        assert!(view.attachments().contains_key(&1));

        let mut complete = CurrentWindow::new("room", 40);
        assert!(!stage(&mut complete, page(0, false, vec![message()]))?);
        assert!(stage(
            &mut complete,
            page(
                1,
                true,
                vec![
                    CurrentRecord::File {
                        cursor: 30,
                        index: 0,
                        file: AttachedFile { file: [2; 16], name: "current.txt".into(), size: 6, image: None }
                    },
                    CurrentRecord::Reaction { cursor: 30, reaction: 1, author: "reader@example.org".into() },
                ]
            )
        )?);
        view.install_current(complete)?;
        assert_eq!(view.cursor(), 40);
        let shown = view.shown();
        assert!(shown.iter().any(|row| matches!(row, Shown::Line(line) if line.cursor == 30 && line.edited)));
        assert!(!shown.iter().any(|row| matches!(row, Shown::Line(line) if line.cursor == 1)));
        assert!(shown.iter().any(|row| matches!(row, Shown::Pending { id, .. } if *id == pending)));
        assert!(shown.iter().any(|row| matches!(row, Shown::Pending { id, .. } if *id == future_ack)));
        assert!(!shown.iter().any(|row| matches!(row, Shown::Pending { id, .. } if *id == reached_ack)));
        assert!(!view.attachments().contains_key(&1));
        assert!(view.attachments().contains_key(&30));
        assert_eq!(view.parents().get(&30), Some(&2));
        assert!(!view.parents().contains_key(&1));
        assert!(!view.reactions().contains_key(&1));
        assert!(view.reactions().contains_key(&30));
        assert_eq!(view.sent_times().get(&30), Some(&0));
        assert!(!view.sent_times().contains_key(&1));
        assert!(!view.archived());
        assert!(view.call().is_none() && view.call_lines().is_empty() && view.call_keys(8).is_none() && view.sealed(8).is_none());
        assert_eq!(view.pin_revision(), Some(40));
        assert!(view.read_state().is_some_and(|state| state.revision == 3));
        assert!(view.gap_notice().is_some_and(|gap| gap.recovered && gap.older));
        assert!(!view.needs_resync());

        let mut empty = CurrentWindow::new("room", 45);
        let page = CurrentPage { room: "room".into(), head: 45, index: 0, last: true, older: false, archived: true, records: Vec::new() };
        let bytes = encode_page(9, &page)?.len() + 4;
        empty.page(page, bytes)?;
        view.install_current(empty)?;
        assert!(!view.shown().iter().any(|row| matches!(row, Shown::Line(_))));
        assert!(view.attachments().is_empty() && view.parents().is_empty() && view.reactions().is_empty() && view.sent_times().is_empty());
        assert!(view.shown().iter().any(|row| matches!(row, Shown::Pending { id, .. } if *id == pending)));
        assert!(view.archived());
        assert!(view.gap_notice().is_some_and(|gap| gap.recovered && !gap.older));
        Ok(())
    }
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

/// The current pinned message, including its current body even when it is outside the held history page (T343).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedMessage {
    pub target: u64,
    pub author: String,
    pub html: String,
    pub edited: bool,
}

/// The signed-in person's authoritative room read position and unread count (T344).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadState {
    pub head: u64,
    pub position: u64,
    pub revision: u64,
    pub unread: u64,
}

/// A missing event interval, distinct from older current messages outside a recovered window (T345).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GapNotice {
    pub after: u64,
    pub oldest: u64,
    pub head: u64,
    pub older: bool,
    pub recovered: bool,
}

/// A bounded current-state stream staged away from the visible room until its last page validates (T345).
pub struct CurrentWindow {
    room: String,
    head: u64,
    next: u32,
    bytes: usize,
    records: usize,
    flags: Option<(bool, bool)>,
    last_key: Option<(u64, u8, u8, String)>,
    complete: bool,
    lines: Vec<Line>,
    attachments: BTreeMap<u64, Vec<crewcraft_proto::push::AttachedFile>>,
    parents: BTreeMap<u64, u64>,
    reactions: BTreeMap<u64, BTreeMap<u8, BTreeSet<String>>>,
    sent: BTreeMap<u64, u64>,
}

impl CurrentWindow {
    pub fn new(room: &str, head: u64) -> Self {
        Self {
            room: room.to_owned(),
            head,
            next: 0,
            bytes: 0,
            records: 0,
            flags: None,
            last_key: None,
            complete: false,
            lines: Vec::new(),
            attachments: BTreeMap::new(),
            parents: BTreeMap::new(),
            reactions: BTreeMap::new(),
            sent: BTreeMap::new(),
        }
    }

    /// Validate one decoded page and its actual framed byte count. A refused stream must be discarded.
    pub fn page(&mut self, page: CurrentPage, framed_bytes: usize) -> Result<bool, CodecError> {
        let bytes = self.bytes.checked_add(framed_bytes).ok_or(CodecError::FieldLength)?;
        let records = self.records.checked_add(page.records.len()).ok_or(CodecError::FieldLength)?;
        if self.complete
            || page.room != self.room
            || page.head != self.head
            || page.index != self.next
            || page.records.len() > MAX_CURRENT_PAGE_RECORDS
            || bytes > MAX_CURRENT_BYTES
            || records > MAX_CURRENT_RECORDS
            || self.flags.is_some_and(|flags| flags != (page.older, page.archived))
            || (page.records.is_empty() && !(page.index == 0 && page.last))
        {
            return Err(CodecError::FieldLength);
        }
        self.flags = Some((page.older, page.archived));
        for record in page.records {
            let (cursor, kind, index, actor) = record.key();
            let key = (cursor, kind, index, actor.to_owned());
            if cursor == 0 || cursor > self.head || self.last_key.as_ref().is_some_and(|last| &key <= last) {
                return Err(CodecError::FieldLength);
            }
            self.last_key = Some(key);
            match record {
                CurrentRecord::Message { cursor, author, html, edited, parent, sent_ms } => {
                    if self.lines.len() >= MAX_CURRENT_MESSAGES || parent == Some(0) {
                        return Err(CodecError::FieldLength);
                    }
                    self.lines.push(Line { cursor, author, html, edited });
                    if let Some(parent) = parent {
                        self.parents.insert(cursor, parent);
                    }
                    if let Some(sent_ms) = sent_ms {
                        self.sent.insert(cursor, sent_ms);
                    }
                }
                CurrentRecord::File { cursor, index, file } => {
                    if self.lines.last().is_none_or(|line| line.cursor != cursor) {
                        return Err(CodecError::FieldLength);
                    }
                    let files = self.attachments.entry(cursor).or_default();
                    if usize::from(index) != files.len() {
                        return Err(CodecError::FieldLength);
                    }
                    files.push(file);
                }
                CurrentRecord::Reaction { cursor, reaction, author } => {
                    if self.lines.last().is_none_or(|line| line.cursor != cursor) {
                        return Err(CodecError::FieldLength);
                    }
                    self.reactions.entry(cursor).or_default().entry(reaction).or_default().insert(author);
                }
            }
        }
        self.bytes = bytes;
        self.records = records;
        self.next = self.next.checked_add(1).ok_or(CodecError::FieldLength)?;
        self.complete = page.last;
        Ok(self.complete)
    }
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
    /// Authoritative pin state and the room-head revision that supplied it (T343).
    pinned: Option<PinnedMessage>,
    pin_revision: Option<u64>,
    awaiting_pin: bool,
    read_state: Option<ReadState>,
    awaiting_read_state: bool,
    gap_notice: Option<GapNotice>,
    recovery_epoch: u64,
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
            pinned: None,
            pin_revision: None,
            awaiting_pin: false,
            read_state: None,
            awaiting_read_state: false,
            gap_notice: None,
            recovery_epoch: 0,
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

    /// Apply current room pin metadata without advancing the message timeline (T343). An older snapshot cannot
    /// restore a pin after a newer deletion or pin snapshot.
    pub fn pin_state(&mut self, revision: u64, pinned: Option<PinnedMessage>) {
        if revision >= self.pin_revision.unwrap_or(0) && revision >= self.timeline.cursor() {
            self.pin_revision = Some(revision);
            self.pinned = pinned;
            self.awaiting_pin = false;
        }
    }

    /// The last authoritative pin snapshot's room head, including an explicit empty pin (T343).
    pub fn pin_revision(&self) -> Option<u64> {
        self.pin_revision
    }

    /// A matched sync answer must be followed by its own pin snapshot, even at the same head (T343).
    pub fn expect_pin_state(&mut self) {
        self.awaiting_pin = true;
    }

    /// Whether the current sync still needs its authoritative pin snapshot (T343).
    pub fn awaiting_pin(&self) -> bool {
        self.awaiting_pin
    }

    /// The cursor of the room's current pinned message (T343).
    pub fn pinned(&self) -> Option<u64> {
        self.pinned.as_ref().map(|message| message.target)
    }

    /// The authoritative current body of the room's pinned message (T343).
    pub fn pinned_message(&self) -> Option<&PinnedMessage> {
        self.pinned.as_ref()
    }

    /// Apply personal read metadata without advancing the message timeline (T344). Personal revisions order rewinds
    /// at an unchanged room head; a later room head may change the count without changing that revision.
    pub fn set_read_state(&mut self, state: ReadState) {
        let current = self.read_state.as_ref();
        if current.is_none_or(|current| (state.revision, state.head) >= (current.revision, current.head)) {
            self.read_state = Some(state);
            self.awaiting_read_state = false;
        }
    }

    pub fn read_state(&self) -> Option<&ReadState> {
        self.read_state.as_ref()
    }

    pub fn expect_read_state(&mut self) {
        self.awaiting_read_state = true;
    }

    pub fn awaiting_read_state(&self) -> bool {
        self.awaiting_read_state
    }

    /// The files of each message that has any, by cursor (task T330c).
    pub fn attachments(&self) -> &BTreeMap<u64, Vec<crewcraft_proto::push::AttachedFile>> {
        &self.attachments
    }

    pub fn event(&mut self, cursor: u64, change: Change) -> Apply {
        let deleted = match &change {
            Change::Deleted { target } => Some(*target),
            _ => None,
        };
        let result = self.timeline.apply(cursor, change);
        if result == Apply::Applied && deleted.is_some_and(|target| self.pinned() == Some(target)) {
            self.pinned = None;
        }
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

    /// Record the missing event interval without moving the timeline or discarding pending sends.
    pub fn note_gap(&mut self, head: u64, after: u64, oldest: u64) {
        let previous = self.gap_notice.as_ref();
        self.gap_notice = Some(GapNotice {
            after: previous.map_or(after, |gap| gap.after.min(after)),
            oldest: previous.map_or(oldest, |gap| gap.oldest.max(oldest)),
            head: previous.map_or(head, |gap| gap.head.max(head)),
            older: previous.is_some_and(|gap| gap.older),
            recovered: previous.is_some_and(|gap| gap.recovered),
        });
        self.needs_resync = true;
    }

    pub fn gap_notice(&self) -> Option<&GapNotice> {
        self.gap_notice.as_ref()
    }

    pub fn recovery_epoch(&self) -> u64 {
        self.recovery_epoch
    }

    /// Install only a complete current window. No message notifications are produced; pending sends survive.
    pub fn install_current(&mut self, window: CurrentWindow) -> Result<(), CodecError> {
        if !window.complete || window.head < self.cursor() || self.gap_notice.as_ref().is_some_and(|gap| window.head < gap.head) {
            return Err(CodecError::FieldLength);
        }
        let (older, archived) = window.flags.ok_or(CodecError::FieldLength)?;
        self.snapshot(window.lines, window.head);
        self.attachments = window.attachments;
        self.parents = window.parents;
        self.reactions = window.reactions;
        self.sent = window.sent;
        self.archived = archived;
        self.call = None;
        self.call_lines.clear();
        self.call_keys = None;
        self.sealed.clear();
        self.recovery_epoch = self.recovery_epoch.saturating_add(1);
        if let Some(gap) = self.gap_notice.as_mut() {
            gap.older = older;
            gap.recovered = true;
            gap.head = window.head;
        }
        Ok(())
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
