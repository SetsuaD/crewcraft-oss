//! Every room the client follows: each server push goes to its room's view, and a new message from someone else may
//! notify. Composed from `room_view` (T123), `notify` (T126) and the `proto::push` types (T131). Task T132.

use std::collections::{BTreeMap, BTreeSet};

use crewcraft_proto::push::Push;

use crate::notify::{Incoming, Notify, Settings};
use crate::room_view::RoomView;
use crate::timeline::{Apply, Change};

pub struct Inbox {
    me: String,
    settings: Settings,
    views: BTreeMap<String, RoomView>,
    direct: BTreeMap<String, bool>,
    /// Rooms the person muted (T346): a new message there never notifies.
    muted: BTreeSet<String>,
}

impl Inbox {
    /// An inbox for `me`, following no rooms, deciding notifications with `settings`.
    pub fn new(me: &str, settings: Settings) -> Self {
        Self { me: me.to_owned(), settings, views: BTreeMap::new(), direct: BTreeMap::new(), muted: BTreeSet::new() }
    }

    /// Start following `room` with an empty view; `direct` marks a direct conversation. False (and nothing changes) if
    /// it is already followed.
    pub fn follow(&mut self, room: &str, direct: bool) -> bool {
        if self.views.contains_key(room) {
            return false;
        }
        self.views.insert(room.to_owned(), RoomView::new());
        self.direct.insert(room.to_owned(), direct);
        true
    }

    /// Stop following `room` and drop its view. False if it was not followed.
    pub fn unfollow(&mut self, room: &str) -> bool {
        if self.views.remove(room).is_some() {
            self.direct.remove(room);
            true
        } else {
            false
        }
    }

    /// Apply a push to its room's view with `RoomView::event` at the push's cursor, as the matching `timeline::Change`
    /// (`Posted { author, html }`, `Edited { target, html }`, `Deleted { target }`, `Other`).
    ///
    /// Returns `None` for a room not followed (nothing changes). Otherwise the `Apply` result and a notification
    /// decision: only a `Posted` push that was `Applied` is decided, with `Settings::decide` on an `Incoming` whose
    /// `mentioned` is whether the push's mentions contain `me` (ASCII case-insensitively) and whose `direct` is the room's
    /// flag; every other push is `Notify::None`.
    pub fn on_push(&mut self, push: Push, now_ms: u64, local_minute: u16) -> Option<(Apply, Notify)> {
        if let Push::Gap { room, cursor, after, oldest } = push {
            self.views.get_mut(&room)?.note_gap(cursor, after, oldest);
            return Some((Apply::Duplicate, Notify::None));
        }
        if let Push::RoomSettings { room, cursor, revision, settings } = push {
            let view = self.views.get_mut(&room)?;
            if view.set_room_settings(crate::room_view::RoomSettingsState { head: cursor, revision, settings }) {
                self.set_muted(&room, settings.muted);
            }
            return Some((Apply::Duplicate, Notify::None));
        }
        if let Push::ReadState { room, cursor, position, revision, unread } = push {
            self.views.get_mut(&room)?.set_read_state(crate::room_view::ReadState { head: cursor, position, revision, unread });
            return Some((Apply::Duplicate, Notify::None));
        }
        if let Push::GuestLobbyState { room, cursor, revision, waiting } = push {
            self.views.get_mut(&room)?.set_guest_lobby_state(crate::room_view::GuestLobbyState { head: cursor, revision, waiting });
            return Some((Apply::Duplicate, Notify::None));
        }
        // A room-head pin snapshot also arrives after an empty sync or a history gap (T343).
        if let Push::Pinned { room, cursor, target, author, html, edited } = push {
            let pinned = (target != 0).then_some(crate::room_view::PinnedMessage { target, author, html, edited });
            self.views.get_mut(&room)?.pin_state(cursor, pinned);
            return Some((Apply::Duplicate, Notify::None));
        }
        // A message's files (task T330c) advance nothing: they are kept beside the timeline.
        if let Push::Attached { room, cursor, files } = push {
            self.views.get_mut(&room)?.attach(cursor, files);
            return Some((Apply::Duplicate, Notify::None));
        }
        // An archive room's flag and an imported message's original time advance nothing either (task T350d1).
        if let Push::Archived { room, .. } = push {
            self.views.get_mut(&room)?.set_archived();
            return Some((Apply::Duplicate, Notify::None));
        }
        if let Push::Sent { room, cursor, sent_ms } = push {
            self.views.get_mut(&room)?.sent(cursor, sent_ms);
            return Some((Apply::Duplicate, Notify::None));
        }
        // A room's open call advances nothing (task T360a1).
        if let Push::CallState { room, call, video, started_by, started_ms, participants, .. } = push {
            let open = crate::room_view::OpenCall { call, video, started_by, started_ms, participants };
            self.views.get_mut(&room)?.set_call(Some(open));
            return Some((Apply::Duplicate, Notify::None));
        }
        // The participants' call keys and the keys sealed to me advance nothing (task T360d2).
        if let Push::CallKeys { room, call, keys, .. } = push {
            self.views.get_mut(&room)?.set_call_keys(call, keys);
            return Some((Apply::Duplicate, Notify::None));
        }
        if let Push::CallSealed { room, call, from, kid, sealed, .. } = push {
            self.views.get_mut(&room)?.add_sealed(call, from, kid, sealed);
            return Some((Apply::Duplicate, Notify::None));
        }
        // A call's history line is an event of its own; its end closes the room's open call (task T360a1).
        if let Push::CallLine { room, cursor, call, ended, author, text } = push {
            let view = self.views.get_mut(&room)?;
            let apply = view.event(cursor, Change::Other);
            if apply == Apply::Applied {
                view.call_line(cursor, crate::room_view::CallLineRow { call, ended, author, text });
            }
            return Some((apply, Notify::None));
        }
        // So is the line that links back to the archive a room continues (task T352).
        if let Push::Continued { room, cursor, archive, author, text } = push {
            let view = self.views.get_mut(&room)?;
            let apply = view.event(cursor, Change::Other);
            if apply == Apply::Applied {
                view.continued(cursor, crate::room_view::ContinuedLine { archive, author, text });
            }
            return Some((apply, Notify::None));
        }
        // So is a meeting's system line (task T370a); the client reports it as its own event.
        if let Push::MeetingLine { room, cursor, .. } = push {
            let apply = self.views.get_mut(&room)?.event(cursor, Change::Other);
            return Some((apply, Notify::None));
        }
        // So does a reply's thread (task T340a).
        if let Push::Threaded { room, cursor, parent } = push {
            self.views.get_mut(&room)?.thread(cursor, parent);
            return Some((Apply::Duplicate, Notify::None));
        }
        // A reaction is an event of its own (task T341a): it advances the cursor, and is kept once it is applied.
        if let Push::Reacted { room, cursor, target, author, reaction, on } = push {
            let view = self.views.get_mut(&room)?;
            let apply = view.event(cursor, Change::Other);
            if apply == Apply::Applied {
                view.react(target, &author, reaction, on);
            }
            return Some((apply, Notify::None));
        }
        let (room, cursor, change, is_posted, author, mentions) = match &push {
            Push::Posted { room, cursor, author, html, mentions } => (
                room.as_str(),
                *cursor,
                Change::Posted { author: author.clone(), html: html.clone() },
                true,
                Some(author.as_str()),
                Some(mentions.as_slice()),
            ),
            Push::Edited { room, cursor, target, html, .. } => {
                (room.as_str(), *cursor, Change::Edited { target: *target, html: html.clone() }, false, None, None)
            }
            Push::Deleted { room, cursor, target } => (room.as_str(), *cursor, Change::Deleted { target: *target }, false, None, None),
            Push::Other { room, cursor } => (room.as_str(), *cursor, Change::Other, false, None, None),
            Push::Attached { .. } | Push::Threaded { .. } | Push::Reacted { .. } | Push::Archived { .. } | Push::Sent { .. } => return None,
            Push::CallLine { .. }
            | Push::CallState { .. }
            | Push::CallKeys { .. }
            | Push::CallSealed { .. }
            | Push::Pinned { .. }
            | Push::ReadState { .. }
            | Push::GuestLobbyState { .. }
            | Push::RoomSettings { .. } => return None,
            Push::Gap { .. } | Push::Continued { .. } | Push::MeetingLine { .. } => return None,
        };

        let is_direct = self.direct.get(room).copied().unwrap_or(false);

        let apply = self.views.get_mut(room)?.event(cursor, change);

        let notify = if is_posted && apply == Apply::Applied && !self.muted.contains(room) {
            let mentioned = mentions.map(|m| m.iter().any(|name| name.eq_ignore_ascii_case(&self.me))).unwrap_or(false);
            let incoming = Incoming { room, author: author.unwrap_or(""), mentioned, direct: is_direct };
            self.settings.decide(&incoming, now_ms, local_minute)
        } else {
            Notify::None
        };

        Some((apply, notify))
    }

    /// Mute or unmute a room's notifications, as the person's own setting says (T346).
    pub fn set_muted(&mut self, room: &str, muted: bool) {
        if muted {
            self.muted.insert(room.to_owned());
        } else {
            self.muted.remove(room);
        }
    }

    /// A followed room's view.
    pub fn view(&self, room: &str) -> Option<&RoomView> {
        self.views.get(room)
    }

    /// A followed room's view, to send, acknowledge or apply a snapshot.
    pub fn view_mut(&mut self, room: &str) -> Option<&mut RoomView> {
        self.views.get_mut(room)
    }

    /// The followed rooms whose view needs a resync (`RoomView::needs_resync`), sorted.
    pub fn needs_resync(&self) -> Vec<String> {
        self.views.iter().filter(|(_, v)| v.needs_resync()).map(|(room, _)| room.clone()).collect()
    }

    /// The followed rooms, sorted.
    pub fn rooms(&self) -> Vec<String> {
        self.views.keys().cloned().collect()
    }
}

#[cfg(test)]
mod room_settings_tests {
    use super::*;
    use crewcraft_proto::room_settings::RoomSettings;

    fn posted(cursor: u64) -> Push {
        Push::Posted { room: "room".into(), cursor, author: "bo@example.org".into(), html: "<p>hi</p>".into(), mentions: Vec::new() }
    }

    fn settings(revision: u64, muted: bool) -> Push {
        Push::RoomSettings { room: "room".into(), cursor: 1, revision, settings: RoomSettings { muted, ..RoomSettings::default() } }
    }

    #[test]
    fn a_muted_room_never_notifies_its_member_and_a_stale_snapshot_cannot_unmute_it() {
        let mut muting = Inbox::new("ana@example.org", Settings::new("ana@example.org"));
        let mut other = Inbox::new("cy@example.org", Settings::new("cy@example.org"));
        muting.follow("room", false);
        other.follow("room", false);
        assert_eq!(muting.on_push(posted(1), 0, 0).map(|(_, notify)| notify), Some(Notify::Sound));
        muting.on_push(settings(2, true), 0, 0);
        assert_eq!(muting.on_push(posted(2), 0, 0).map(|(_, notify)| notify), Some(Notify::None));
        assert_eq!(other.on_push(posted(1), 0, 0).map(|(_, notify)| notify), Some(Notify::Sound));
        assert_eq!(other.on_push(posted(2), 0, 0).map(|(_, notify)| notify), Some(Notify::Sound));
        muting.on_push(settings(1, false), 0, 0);
        assert_eq!(muting.on_push(posted(3), 0, 0).map(|(_, notify)| notify), Some(Notify::None));
        muting.on_push(settings(3, false), 0, 0);
        assert_eq!(muting.on_push(posted(4), 0, 0).map(|(_, notify)| notify), Some(Notify::Sound));
    }
}
