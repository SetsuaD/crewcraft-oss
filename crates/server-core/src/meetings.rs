//! Meetings on the chat server (docs/MEETINGS.md, task T370a): scheduled calls in a room, with a staff audience that
//! never changes, version checks on every change, a freeze once the meeting has any call, system lines built from the
//! record, and the calendar's window query. A meeting's call is the room's ordinary call (`calls`), so call records,
//! liveness, media credentials and removal stay there.
//!
//! Owns: `Meetings` (the state, rebuilt from the journal), the meeting records' replay (`replay`, called by
//! `DurableServer::open`), and `DurableServer::schedule_meeting/edit_meeting/cancel_meeting/join_meeting`,
//! `meetings_between`, `meeting`, `meeting_for`. Calls `server::Server` (membership, system lines), `durable`
//! (records) and `calls` (`DurableServer::call_start`, which joins the room's open call or starts one).

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Datelike, Timelike};
use crewcraft_proto::meeting::{
    Audience, FRAME_HEADER, MAX_AGENDA, MAX_DURATION, MAX_LISTED_MEETINGS, MAX_TITLE, MAX_WINDOW_MS, MeetingChange, MeetingPage, MeetingState,
    wire_len,
};

use crate::calls::{CallError, duration_text};
use crate::durable::{DurableError, DurableServer};
use crate::op::{MeetingOp, Op};
use crate::room::Role;
use crate::server::Server;

const MINUTE_MS: u64 = 60_000;

/// One meeting, as the server keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meeting {
    pub id: u64,
    pub room: String,
    pub owner: String,
    /// Always `Staff` in this slice; no request changes it.
    pub audience: Audience,
    pub title: String,
    /// UTC, Unix milliseconds.
    pub start_ms: u64,
    /// Minutes.
    pub duration: u16,
    pub agenda: String,
    /// 1 when made; every saved edit or cancel adds one.
    pub version: u64,
    pub cancelled: bool,
    /// The calls joined through the meeting, open or ended. Any call freezes the meeting.
    pub calls: BTreeSet<u64>,
}

impl Meeting {
    pub(crate) fn end_ms(&self) -> u64 {
        self.start_ms.saturating_add(u64::from(self.duration) * MINUTE_MS)
    }
}

/// Every meeting, by id.
#[derive(Debug, Clone, Default)]
pub struct Meetings {
    pub(crate) next: u64,
    pub(crate) meetings: BTreeMap<u64, Meeting>,
}

/// A meeting's fields as a client sends them, before trimming and checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Draft<'a> {
    pub title: &'a str,
    pub start_ms: u64,
    pub duration: u16,
    pub agenda: &'a str,
}

/// Why a meeting request was refused. Nothing is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeetingError {
    /// Scheduling in a room that does not exist or the person is not in.
    NoSuchRoom,
    /// No such meeting, or it belongs to a room the person is not in (the same answer, so existence is not revealed).
    NoSuchMeeting,
    /// Not allowed: a Guest-role member or an archive room, someone who is neither the owner nor a room admin, a
    /// meeting that has a call or is cancelled, or a Guest-role member joining a meeting whose room has no open call.
    NotAllowed,
    /// The version the client sent is not the current one: reload.
    Conflict,
    /// A title, agenda, start, duration or window outside its limits, or a meeting that would end in the past.
    BadField,
    Durable(DurableError),
}

/// The title and agenda of `draft` after trimming, if every field is within its limits.
pub(crate) fn checked(draft: &Draft<'_>) -> Result<(String, String), MeetingError> {
    let title = draft.title.trim();
    let agenda = draft.agenda.trim();
    let title_ok = (1..=MAX_TITLE).contains(&title.chars().count()) && !title.chars().any(char::is_control);
    let agenda_ok = agenda.chars().count() <= MAX_AGENDA && !agenda.chars().any(|c| c.is_control() && c != '\n' && c != '\t');
    let duration_ok = (1..=MAX_DURATION).contains(&draft.duration);
    let start_ok = draft.start_ms > 0 && when(draft.start_ms).is_some();
    if title_ok && agenda_ok && duration_ok && start_ok { Ok((title.to_owned(), agenda.to_owned())) } else { Err(MeetingError::BadField) }
}

/// A start as the system lines say it: `2026-12-01 14:00 UTC`. The server has no time zone database (chrono, default
/// features off), so lines are in UTC; clients show times in their own zone.
fn when(start_ms: u64) -> Option<String> {
    let at = DateTime::from_timestamp(i64::try_from(start_ms / 1000).ok()?, 0)?;
    Some(format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", at.year(), at.month(), at.day(), at.hour(), at.minute()))
}

/// The system line for `change` to `meeting`, built from the record alone.
pub(crate) fn line(meeting: &Meeting, change: MeetingChange) -> String {
    let schedule = || {
        let start = when(meeting.start_ms).unwrap_or_default();
        format!("{}, {start}, {}", meeting.title, duration_text(u64::from(meeting.duration) * MINUTE_MS))
    };
    match change {
        MeetingChange::Scheduled => format!("scheduled a meeting: {}", schedule()),
        MeetingChange::Edited => format!("edited the meeting: {}", schedule()),
        MeetingChange::Cancelled => format!("cancelled the meeting: {}", meeting.title),
        MeetingChange::Lobby => "updated the meeting lobby".to_owned(),
    }
}

/// The result of `replay`: a meeting record applied, or any other record, handed back untouched.
pub(crate) enum Replayed {
    Done,
    NotMeeting(Op),
}

/// Apply a meeting record at start-up, as the request that wrote it did. `Err` means the journal does not match.
pub(crate) fn replay(server: &mut Server, meetings: &mut Meetings, op: Op) -> Result<Replayed, ()> {
    let Op::Meeting(record) = op else { return Ok(Replayed::NotMeeting(op)) };
    match record {
        MeetingOp::Scheduled { slug, meeting, actor, start_ms, duration, title, agenda, .. } => {
            if meeting != meetings.next + 1 {
                return Err(());
            }
            let made = Meeting {
                id: meeting,
                room: slug,
                owner: actor,
                audience: Audience::Staff,
                title,
                start_ms,
                duration,
                agenda,
                version: 1,
                cancelled: false,
                calls: BTreeSet::new(),
            };
            let text = line(&made, MeetingChange::Scheduled);
            server.meeting_line(&made.room, &made.owner, meeting, MeetingChange::Scheduled, 1, &text).map_err(|_| ())?;
            meetings.next = meeting;
            meetings.meetings.insert(meeting, made);
        }
        MeetingOp::Edited { slug, meeting, actor, version, start_ms, duration, title, agenda, .. } => {
            let record = changeable(meetings, &slug, meeting, version)?;
            record.title = title;
            record.start_ms = start_ms;
            record.duration = duration;
            record.agenda = agenda;
            record.version = version;
            let text = line(record, MeetingChange::Edited);
            server.meeting_line(&slug, &actor, meeting, MeetingChange::Edited, version, &text).map_err(|_| ())?;
        }
        MeetingOp::Cancelled { slug, meeting, actor, version, .. } => {
            let record = changeable(meetings, &slug, meeting, version)?;
            record.cancelled = true;
            record.version = version;
            let text = line(record, MeetingChange::Cancelled);
            server.meeting_line(&slug, &actor, meeting, MeetingChange::Cancelled, version, &text).map_err(|_| ())?;
        }
        MeetingOp::Call { slug, meeting, call } => {
            let record = meetings.meetings.get_mut(&meeting).filter(|record| record.room == slug && !record.cancelled).ok_or(())?;
            record.calls.insert(call);
        }
    }
    Ok(Replayed::Done)
}

/// The meeting a replayed edit or cancel at `version` applies to: in `slug`, one version behind, not frozen.
fn changeable<'a>(meetings: &'a mut Meetings, slug: &str, meeting: u64, version: u64) -> Result<&'a mut Meeting, ()> {
    meetings
        .meetings
        .get_mut(&meeting)
        .filter(|record| record.room == slug && record.version + 1 == version && !record.cancelled && record.calls.is_empty())
        .ok_or(())
}

impl DurableServer {
    /// Schedule a staff meeting in `slug` (task T370a): a member who may start a call, a title, start, duration and
    /// agenda within their limits, ending after `now_ms`. Returns the meeting's id; it is at version 1.
    pub fn schedule_meeting(&mut self, slug: &str, actor: &str, draft: &Draft<'_>, now_ms: u64) -> Result<u64, MeetingError> {
        self.check_alive().map_err(MeetingError::Durable)?;
        let room = self.server.room(slug).map_err(|_| MeetingError::NoSuchRoom)?;
        let role = room.role(actor).ok_or(MeetingError::NoSuchRoom)?;
        if room.is_read_only() || role == Role::Guest {
            return Err(MeetingError::NotAllowed);
        }
        let (title, agenda) = checked(draft)?;
        let made = Meeting {
            id: self.meetings.next + 1,
            room: slug.to_owned(),
            owner: actor.to_owned(),
            audience: Audience::Staff,
            title,
            start_ms: draft.start_ms,
            duration: draft.duration,
            agenda,
            version: 1,
            cancelled: false,
            calls: BTreeSet::new(),
        };
        if made.end_ms() <= now_ms {
            return Err(MeetingError::BadField);
        }
        self.post_meeting_line(&made, actor, MeetingChange::Scheduled)?;
        self.record(&Op::Meeting(MeetingOp::Scheduled {
            slug: made.room.clone(),
            meeting: made.id,
            actor: actor.to_owned(),
            now_ms,
            start_ms: made.start_ms,
            duration: made.duration,
            title: made.title.clone(),
            agenda: made.agenda.clone(),
        }))
        .map_err(MeetingError::Durable)?;
        let id = made.id;
        self.meetings.next = id;
        self.meetings.meetings.insert(id, made);
        Ok(id)
    }

    /// Edit or reschedule meeting `meeting` of `slug`, last seen at `version` (task T370a). Only its owner or a room
    /// admin or owner; a stale version is `Conflict`; a meeting with any call, or cancelled, is `NotAllowed`. An edit
    /// that changes nothing records nothing and keeps the version. Returns the meeting's version after the edit.
    pub fn edit_meeting(&mut self, slug: &str, actor: &str, meeting: u64, version: u64, draft: &Draft<'_>, now_ms: u64) -> Result<u64, MeetingError> {
        self.check_alive().map_err(MeetingError::Durable)?;
        let current = self.changeable_by(slug, actor, meeting, version)?.clone();
        let (title, agenda) = checked(draft)?;
        if title == current.title && agenda == current.agenda && draft.start_ms == current.start_ms && draft.duration == current.duration {
            return Ok(version);
        }
        let edited = Meeting { title, agenda, start_ms: draft.start_ms, duration: draft.duration, version: version + 1, ..current };
        if edited.end_ms() <= now_ms {
            return Err(MeetingError::BadField);
        }
        self.post_meeting_line(&edited, actor, MeetingChange::Edited)?;
        self.record(&Op::Meeting(MeetingOp::Edited {
            slug: edited.room.clone(),
            meeting,
            actor: actor.to_owned(),
            now_ms,
            version: edited.version,
            start_ms: edited.start_ms,
            duration: edited.duration,
            title: edited.title.clone(),
            agenda: edited.agenda.clone(),
        }))
        .map_err(MeetingError::Durable)?;
        let new_version = edited.version;
        self.meetings.meetings.insert(meeting, edited);
        Ok(new_version)
    }

    /// Cancel meeting `meeting` of `slug`, last seen at `version` (task T370a), with the same checks as an edit.
    /// Returns the new version.
    pub fn cancel_meeting(&mut self, slug: &str, actor: &str, meeting: u64, version: u64, now_ms: u64) -> Result<u64, MeetingError> {
        self.check_alive().map_err(MeetingError::Durable)?;
        let current = self.changeable_by(slug, actor, meeting, version)?.clone();
        if current.audience == Audience::Guests {
            return self.cancel_guest_schedule(actor, meeting, now_ms).map_err(|error| match error {
                crate::guests::GuestError::Durable(error) => MeetingError::Durable(error),
                _ => MeetingError::NotAllowed,
            });
        }
        let cancelled = Meeting { cancelled: true, version: version + 1, ..current };
        self.post_meeting_line(&cancelled, actor, MeetingChange::Cancelled)?;
        let record = MeetingOp::Cancelled { slug: slug.to_owned(), meeting, actor: actor.to_owned(), now_ms, version: cancelled.version };
        self.record(&Op::Meeting(record)).map_err(MeetingError::Durable)?;
        let new_version = cancelled.version;
        self.meetings.meetings.insert(meeting, cancelled);
        Ok(new_version)
    }

    /// Join meeting `meeting` by its id alone (task T370a): a member of its room joins the room's open call, or starts
    /// one (a video call; a Guest-role member cannot start one), and that call joins the meeting's calls. A cancelled
    /// meeting cannot be joined. Returns the room and the call's id.
    pub fn join_meeting(&mut self, actor: &str, meeting: u64, now_ms: u64) -> Result<(String, u64), MeetingError> {
        self.check_alive().map_err(MeetingError::Durable)?;
        self.sweep_guest_links(now_ms).map_err(MeetingError::Durable)?;
        let record = self.visible(actor, meeting).ok_or(MeetingError::NoSuchMeeting)?;
        if record.cancelled {
            return Err(MeetingError::NotAllowed);
        }
        if record.audience == Audience::Guests {
            return self.join_guest_meeting(actor, meeting, now_ms);
        }
        let (room, linked) = (record.room.clone(), record.calls.clone());
        let call = self.call_start(&room, actor, true, now_ms).map_err(|error| match error {
            CallError::NotMember => MeetingError::NoSuchMeeting,
            CallError::Durable(error) => MeetingError::Durable(error),
            CallError::NotAllowed | CallError::NoSuchCall | CallError::MediaUnusable => MeetingError::NotAllowed,
        })?;
        if !linked.contains(&call) {
            self.record(&Op::Meeting(MeetingOp::Call { slug: room.clone(), meeting, call })).map_err(MeetingError::Durable)?;
            if let Some(record) = self.meetings.meetings.get_mut(&meeting) {
                record.calls.insert(call);
            }
        }
        Ok((room, call))
    }

    /// The meeting with this id, whoever may see it.
    pub fn meeting(&self, meeting: u64) -> Option<&Meeting> {
        self.meetings.meetings.get(&meeting)
    }

    /// Meeting `meeting` as `user` sees it on the wire, if they are in its room.
    pub fn meeting_for(&self, user: &str, meeting: u64) -> Option<crewcraft_proto::meeting::Meeting> {
        self.visible(user, meeting).map(|record| self.described(record))
    }

    /// The meetings in `user`'s rooms that overlap `from_ms` to `to_ms` (task T370a), cancelled ones included, by start
    /// then id: at most `MAX_LISTED_MEETINGS` and one frame's worth, with `more` when some were left out. A window that
    /// is empty, backwards or wider than `MAX_WINDOW_MS` is `BadField`.
    pub fn meetings_between(&self, user: &str, from_ms: u64, to_ms: u64) -> Result<MeetingPage, MeetingError> {
        self.meetings_between_with_guests(user, from_ms, to_ms, true)
    }

    pub fn meetings_between_with_guests(&self, user: &str, from_ms: u64, to_ms: u64, include_guests: bool) -> Result<MeetingPage, MeetingError> {
        if to_ms <= from_ms || to_ms - from_ms > MAX_WINDOW_MS {
            return Err(MeetingError::BadField);
        }
        let mut found: Vec<&Meeting> = self
            .meetings
            .meetings
            .values()
            .filter(|record| include_guests || record.audience == Audience::Staff)
            .filter(|record| record.start_ms < to_ms && record.end_ms() > from_ms)
            .filter(|record| self.server.room(&record.room).is_ok_and(|room| room.role(user).is_some()))
            .collect();
        found.sort_by_key(|record| (record.start_ms, record.id));
        let mut page = MeetingPage::default();
        let mut bytes = FRAME_HEADER;
        for record in found {
            let described = self.described(record);
            bytes += wire_len(&described);
            if page.meetings.len() == MAX_LISTED_MEETINGS || bytes > crewcraft_proto::frame::MAX_FRAME {
                page.more = true;
                break;
            }
            page.meetings.push(described);
        }
        Ok(page)
    }

    fn described(&self, record: &Meeting) -> crewcraft_proto::meeting::Meeting {
        let open = self.open_call(&record.room).is_some_and(|call| record.calls.contains(&call.id));
        let state = if record.cancelled {
            MeetingState::Cancelled
        } else if open {
            MeetingState::InProgress
        } else if record.calls.is_empty() {
            MeetingState::Scheduled
        } else {
            MeetingState::Held
        };
        crewcraft_proto::meeting::Meeting {
            id: record.id,
            room: record.room.clone(),
            version: record.version,
            owner: record.owner.clone(),
            audience: record.audience,
            start_ms: record.start_ms,
            duration: record.duration,
            title: record.title.clone(),
            agenda: record.agenda.clone(),
            state,
        }
    }

    /// The meeting, if `user` is a member of its room now.
    pub(crate) fn visible(&self, user: &str, meeting: u64) -> Option<&Meeting> {
        let record = self.meetings.meetings.get(&meeting)?;
        self.server.room(&record.room).ok()?.role(user)?;
        Some(record)
    }

    /// The meeting `actor` may change at `version`: in `slug` and visible to them; they may start calls there and are
    /// its owner or a room admin or owner; the version is current; it has no call and is not cancelled.
    fn changeable_by(&self, slug: &str, actor: &str, meeting: u64, version: u64) -> Result<&Meeting, MeetingError> {
        let record = self.visible(actor, meeting).filter(|record| record.room == slug).ok_or(MeetingError::NoSuchMeeting)?;
        let room = self.server.room(slug).map_err(|_| MeetingError::NoSuchMeeting)?;
        let role = room.role(actor).ok_or(MeetingError::NoSuchMeeting)?;
        let may = record.owner == actor || matches!(role, Role::Admin | Role::Owner);
        if room.is_read_only() || role == Role::Guest || !may {
            return Err(MeetingError::NotAllowed);
        }
        if record.version != version {
            return Err(MeetingError::Conflict);
        }
        if record.cancelled || !record.calls.is_empty() {
            return Err(MeetingError::NotAllowed);
        }
        Ok(record)
    }

    fn post_meeting_line(&mut self, record: &Meeting, actor: &str, change: MeetingChange) -> Result<u64, MeetingError> {
        self.server
            .meeting_line(&record.room, actor, record.id, change, record.version, &line(record, change))
            .map_err(|error| MeetingError::Durable(DurableError::Server(error)))
    }
}
