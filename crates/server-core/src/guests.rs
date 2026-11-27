//! Durable guest links and lobby decisions (T370c). The typed entrance is deliberately separate from staff
//! authentication. A future network adapter supplies a verified peer address and the server's clock, and must
//! enforce relay-time revocation before exposing live media. No raw link or bearer is retained by this projection.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use crewcraft_proto::guest::{GuestCode, GuestDecision, GuestEntry, GuestLobby, GuestMeetingChange, GuestMeetingDraft, GuestReply, GuestState};
use crewcraft_proto::meeting::{Audience, MeetingChange};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::calls::{CallError, Calls};
use crate::durable::{DurableError, DurableServer};
use crate::media::MediaEvent;
use crate::meetings::{Draft, Meeting, MeetingError, Meetings};
use crate::op::Op;
use crate::rate_limit::{Limiter, TokenBucket};
use crate::room::Role;
use crate::server::Server;

pub const MIN_LINK_MS: u64 = 3 * 60 * 60 * 1000;
pub const MAX_LINK_MS: u64 = 30 * 24 * 60 * 60 * 1000;
pub const MAX_WAITING: usize = 25;
pub const MAX_GUESTS: usize = 64;
const MAX_SOURCES: usize = 4096;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestError {
    NoSuchGuest,
    LinkClosed,
    NotAllowed,
    BadText,
    Conflict,
    RateLimited,
    Full,
    MediaUnavailable,
    Durable(DurableError),
}

/// The guest's credential is never included in diagnostic output.
#[derive(Clone, PartialEq, Eq)]
pub struct GuestBearer(pub [u8; 32]);

impl Drop for GuestBearer {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for GuestBearer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GuestBearer([redacted])")
    }
}

#[derive(Debug, Clone)]
pub struct GuestProof {
    pub meeting: u64,
    pub guest: u64,
    pub bearer: GuestBearer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestPreview {
    pub title: String,
    pub host_name: String,
}

#[derive(Debug, Clone)]
pub struct GuestKnock {
    pub proof: GuestProof,
    pub state: GuestState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestStatus {
    pub meeting: u64,
    pub guest: u64,
    pub name: String,
    pub state: GuestState,
    pub revision: u64,
}

pub struct GuestMedia {
    pub call: u64,
    pub room: String,
    pub person: String,
    pub label: String,
    pub address: String,
    pub credential: Vec<u8>,
}

impl fmt::Debug for GuestMedia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestMedia").field("call", &self.call).field("credential", &"[redacted]").finish_non_exhaustive()
    }
}

pub trait GuestEntrance {
    fn lookup(&mut self, peer: IpAddr, code: &str) -> Result<GuestPreview, GuestError>;
    fn knock(&mut self, peer: IpAddr, code: &str, name: &str) -> Result<GuestKnock, GuestError>;
    fn status(&mut self, peer: IpAddr, proof: &GuestProof) -> Result<GuestStatus, GuestError>;
    fn media(&mut self, peer: IpAddr, proof: &GuestProof) -> Result<GuestMedia, GuestError>;
}

pub struct GuestAccess<'a, C> {
    server: &'a mut DurableServer,
    clock: C,
}

#[derive(Debug, Clone)]
struct Visitor {
    name: String,
    digest: [u8; 32],
    state: GuestState,
    revision: u64,
}

#[derive(Debug, Clone)]
struct Link {
    code: [u8; 32],
    expires_ms: u64,
    lobby: bool,
    closed: bool,
    revision: u64,
    host_name: String,
    visitors: BTreeMap<u64, Visitor>,
}

pub(crate) struct Guests {
    next: u64,
    links: BTreeMap<u64, Link>,
    codes: BTreeMap<[u8; 32], u64>,
    bound: BTreeMap<u64, u64>,
    rooms: BTreeMap<String, u64>,
    waiting: BTreeMap<String, u32>,
    deadlines: BTreeSet<(u64, u64)>,
    sources: Limiter<IpAddr>,
    global: TokenBucket,
}

impl Default for Guests {
    fn default() -> Self {
        Self {
            next: 0,
            links: BTreeMap::new(),
            codes: BTreeMap::new(),
            bound: BTreeMap::new(),
            rooms: BTreeMap::new(),
            waiting: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            sources: Limiter::new(30, 2),
            global: TokenBucket::new(200, 20, 0),
        }
    }
}

/// One complete guest transition under journal family 42. Digests have distinct domains; no secret is journaled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestOp {
    Create { meeting: u64, owner: String, draft: GuestMeetingDraft, code: [u8; 32], now_ms: u64 },
    Lobby { meeting: u64, actor: String, revision: u64, lobby: bool, now_ms: u64 },
    Knock { meeting: u64, guest: u64, name: String, digest: [u8; 32], now_ms: u64 },
    Decide { meeting: u64, guest: u64, actor: String, revision: u64, decision: GuestDecision, now_ms: u64 },
    Close { meeting: u64, actor: String, revision: u64, now_ms: u64, cancel: bool },
    Bind { meeting: u64, call: u64, actor: String, now_ms: u64 },
}

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    hash.finalize().into()
}

fn name(text: &str) -> Result<String, GuestError> {
    if text.len() > 1024 {
        return Err(GuestError::BadText);
    }
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_control() && !matches!(*c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
        .collect();
    let normalized = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if !(1..=60).contains(&normalized.chars().count()) {
        return Err(GuestError::BadText);
    }
    Ok(normalized)
}

fn random<const N: usize>() -> Result<[u8; N], GuestError> {
    let mut bytes = [0; N];
    OsRng.try_fill_bytes(&mut bytes).map_err(|_| GuestError::MediaUnavailable)?;
    Ok(bytes)
}

fn code() -> Result<String, GuestError> {
    let bytes = random::<15>()?;
    let mut out = String::with_capacity(24);
    let mut bits = 0u32;
    let mut held = 0u32;
    for byte in bytes {
        bits = (bits << 8) | u32::from(byte);
        held += 8;
        while held >= 5 {
            held -= 5;
            out.push(char::from(ALPHABET[((bits >> held) & 31) as usize]));
        }
    }
    Ok(out)
}

fn staff(server: &Server, meetings: &Meetings, user: &str, id: u64, manage: bool) -> Result<(), GuestError> {
    let meeting = meetings.meetings.get(&id).filter(|meeting| meeting.audience == Audience::Guests).ok_or(GuestError::NoSuchGuest)?;
    let room = server.room(&meeting.room).map_err(|_| GuestError::NoSuchGuest)?;
    let role = room.role(user).ok_or(GuestError::NoSuchGuest)?;
    if room.is_read_only() || role == Role::Guest || (manage && user != meeting.owner && !matches!(role, Role::Admin | Role::Owner)) {
        return Err(GuestError::NotAllowed);
    }
    Ok(())
}

impl Guests {
    fn live(&self, id: u64, now_ms: u64) -> Result<&Link, GuestError> {
        self.links.get(&id).filter(|link| !link.closed && now_ms < link.expires_ms).ok_or(GuestError::LinkClosed)
    }

    fn lobby(&self, id: u64) -> Result<GuestLobby, GuestError> {
        let link = self.links.get(&id).ok_or(GuestError::NoSuchGuest)?;
        Ok(GuestLobby {
            meeting: id,
            revision: link.revision,
            expires_ms: link.expires_ms,
            lobby: link.lobby,
            closed: link.closed,
            entries: link
                .visitors
                .iter()
                .map(|(&guest, visitor)| GuestEntry { guest, name: visitor.name.clone(), state: visitor.state, revision: visitor.revision })
                .collect(),
        })
    }

    fn limit(&mut self, peer: IpAddr, now_ms: u64) -> Result<(), GuestError> {
        self.sources.prune(now_ms);
        if !self.global.try_take(now_ms) || self.sources.len() >= MAX_SOURCES || !self.sources.check(&peer, now_ms) {
            return Err(GuestError::RateLimited);
        }
        Ok(())
    }

    fn authenticate(&self, proof: &GuestProof) -> Result<&Visitor, GuestError> {
        let visitor = self.links.get(&proof.meeting).and_then(|link| link.visitors.get(&proof.guest)).ok_or(GuestError::NoSuchGuest)?;
        if visitor.digest != digest(b"crewcraft.guest.bearer.v1\0", &proof.bearer.0) {
            return Err(GuestError::NoSuchGuest);
        }
        Ok(visitor)
    }

    pub(crate) fn bound_to(&self, call: u64) -> Option<u64> {
        self.bound.get(&call).copied()
    }
}

/// Apply exactly one journal transition. Called only after validation and durable append, or while replaying.
pub(crate) fn apply(server: &mut Server, meetings: &mut Meetings, calls: &mut Calls, guests: &mut Guests, op: &GuestOp) -> Result<(), GuestError> {
    let id = match op {
        GuestOp::Create { meeting, .. }
        | GuestOp::Lobby { meeting, .. }
        | GuestOp::Knock { meeting, .. }
        | GuestOp::Decide { meeting, .. }
        | GuestOp::Close { meeting, .. }
        | GuestOp::Bind { meeting, .. } => *meeting,
    };
    let before_waiting =
        guests.links.get(&id).map_or(0, |link| link.visitors.values().filter(|visitor| visitor.state == GuestState::Waiting).count() as u32);
    let (id, actor, text) = match op {
        GuestOp::Create { meeting, owner, draft, code, now_ms } => {
            let room = server.room(&draft.room).map_err(|_| GuestError::NoSuchGuest)?;
            let role = room.role(owner).ok_or(GuestError::NoSuchGuest)?;
            if room.is_read_only() || role == Role::Guest || meetings.next.checked_add(1) != Some(*meeting) || guests.codes.contains_key(code) {
                return Err(GuestError::NotAllowed);
            }
            let normalized_host = name(&draft.host_name)?;
            let (title, agenda) =
                crate::meetings::checked(&Draft { title: &draft.title, start_ms: draft.start_ms, duration: draft.duration, agenda: &draft.agenda })
                    .map_err(|_| GuestError::BadText)?;
            let lifetime = draft.expires_ms.checked_sub(*now_ms).ok_or(GuestError::BadText)?;
            if !(MIN_LINK_MS..=MAX_LINK_MS).contains(&lifetime) || (!draft.lobby && !draft.confirm_direct) {
                return Err(GuestError::BadText);
            }
            let made = Meeting {
                id: *meeting,
                room: draft.room.clone(),
                owner: owner.clone(),
                audience: Audience::Guests,
                title,
                start_ms: draft.start_ms,
                duration: draft.duration,
                agenda,
                version: 1,
                cancelled: false,
                calls: BTreeSet::new(),
            };
            if made.end_ms() <= *now_ms {
                return Err(GuestError::BadText);
            }
            let text = crate::meetings::line(&made, MeetingChange::Scheduled);
            meetings.next = *meeting;
            meetings.meetings.insert(*meeting, made);
            guests.links.insert(
                *meeting,
                Link {
                    code: *code,
                    expires_ms: draft.expires_ms,
                    lobby: draft.lobby,
                    closed: false,
                    revision: 1,
                    host_name: normalized_host,
                    visitors: BTreeMap::new(),
                },
            );
            guests.codes.insert(*code, *meeting);
            guests.deadlines.insert((draft.expires_ms, *meeting));
            (*meeting, owner.as_str(), text)
        }
        GuestOp::Lobby { meeting, actor, revision, lobby, now_ms } => {
            staff(server, meetings, actor, *meeting, true)?;
            let link = guests.live(*meeting, *now_ms)?;
            if link.revision != *revision || link.lobby == *lobby {
                return Err(GuestError::Conflict);
            }
            let link = guests.links.get_mut(meeting).ok_or(GuestError::NoSuchGuest)?;
            link.lobby = *lobby;
            link.revision = link.revision.checked_add(1).ok_or(GuestError::NotAllowed)?;
            (*meeting, actor.as_str(), "changed the meeting lobby".to_owned())
        }
        GuestOp::Knock { meeting, guest, name: display, digest, now_ms } => {
            let link = guests.live(*meeting, *now_ms)?;
            if guests.next.checked_add(1) != Some(*guest)
                || link.visitors.len() >= MAX_GUESTS
                || (link.lobby && link.visitors.values().filter(|visitor| visitor.state == GuestState::Waiting).count() >= MAX_WAITING)
            {
                return Err(GuestError::Full);
            }
            let display = name(display)?;
            let link = guests.links.get_mut(meeting).ok_or(GuestError::NoSuchGuest)?;
            let state = if link.lobby { GuestState::Waiting } else { GuestState::Admitted };
            link.visitors.insert(*guest, Visitor { name: display.clone(), digest: *digest, state, revision: 1 });
            link.revision = link.revision.checked_add(1).ok_or(GuestError::NotAllowed)?;
            guests.next = *guest;
            let text = if state == GuestState::Admitted {
                format!("admitted {display} (guest) automatically")
            } else {
                format!("{display} (guest) asked to join")
            };
            (*meeting, "guest", text)
        }
        GuestOp::Decide { meeting, guest, actor, revision, decision, now_ms } => {
            staff(server, meetings, actor, *meeting, false)?;
            guests.live(*meeting, *now_ms)?;
            let link = guests.links.get_mut(meeting).ok_or(GuestError::NoSuchGuest)?;
            if link.revision != *revision {
                return Err(GuestError::Conflict);
            }
            let visitor = link.visitors.get_mut(guest).ok_or(GuestError::NoSuchGuest)?;
            let (state, action) = match (visitor.state, decision) {
                (GuestState::Waiting, GuestDecision::Admit) => (GuestState::Admitted, "admitted"),
                (GuestState::Waiting, GuestDecision::Decline) => (GuestState::Declined, "declined"),
                (GuestState::Admitted, GuestDecision::Remove) => (GuestState::Removed, "removed"),
                _ => return Err(GuestError::NotAllowed),
            };
            visitor.state = state;
            visitor.revision = visitor.revision.checked_add(1).ok_or(GuestError::NotAllowed)?;
            link.revision = link.revision.checked_add(1).ok_or(GuestError::NotAllowed)?;
            (*meeting, actor.as_str(), format!("{action} {} (guest)", visitor.name))
        }
        GuestOp::Close { meeting, actor, revision, now_ms, cancel } => {
            let link = guests.links.get(meeting).ok_or(GuestError::NoSuchGuest)?;
            if actor.is_empty() {
                if *now_ms < link.expires_ms || *cancel {
                    return Err(GuestError::NotAllowed);
                }
            } else {
                staff(server, meetings, actor, *meeting, true)?;
            }
            if link.revision != *revision || (link.closed && !cancel) {
                return Err(GuestError::Conflict);
            }
            let record = meetings.meetings.get_mut(meeting).ok_or(GuestError::NoSuchGuest)?;
            if *cancel {
                if record.cancelled || !record.calls.is_empty() {
                    return Err(GuestError::NotAllowed);
                }
                record.cancelled = true;
                record.version = record.version.checked_add(1).ok_or(GuestError::NotAllowed)?;
            }
            let link = guests.links.get_mut(meeting).ok_or(GuestError::NoSuchGuest)?;
            link.closed = true;
            guests.deadlines.remove(&(link.expires_ms, *meeting));
            link.revision = link.revision.checked_add(1).ok_or(GuestError::NotAllowed)?;
            for visitor in link.visitors.values_mut() {
                let state = match visitor.state {
                    GuestState::Waiting => GuestState::Declined,
                    GuestState::Admitted => GuestState::Removed,
                    state => state,
                };
                if state != visitor.state {
                    visitor.state = state;
                    visitor.revision = visitor.revision.checked_add(1).ok_or(GuestError::NotAllowed)?;
                }
            }
            (
                *meeting,
                if actor.is_empty() { "system" } else { actor.as_str() },
                if *cancel { "cancelled the guest meeting and closed its link" } else { "closed the meeting link" }.to_owned(),
            )
        }
        GuestOp::Bind { meeting, call, actor, now_ms } => {
            staff(server, meetings, actor, *meeting, false)?;
            if !guests.links.contains_key(meeting) {
                return Err(GuestError::NoSuchGuest);
            }
            let record = meetings.meetings.get_mut(meeting).ok_or(GuestError::NoSuchGuest)?;
            if record.cancelled
                || calls.open_in(&record.room, *call).is_some()
                || calls.next.checked_add(1) != Some(*call)
                || calls.has_open(&record.room)
            {
                return Err(GuestError::NotAllowed);
            }
            let cursor = server
                .call_line(&record.room, actor, *call, false, "started a call")
                .map_err(|error| GuestError::Durable(DurableError::Server(error)))?;
            calls.start(&record.room, actor, true, *now_ms, cursor);
            record.calls.insert(*call);
            guests.bound.insert(*call, *meeting);
            return Ok(());
        }
    };
    let record = meetings.meetings.get(&id).ok_or(GuestError::NoSuchGuest)?;
    let after_waiting =
        guests.links.get(&id).map_or(0, |link| link.visitors.values().filter(|visitor| visitor.state == GuestState::Waiting).count() as u32);
    let waiting = guests.waiting.entry(record.room.clone()).or_default();
    *waiting = waiting.saturating_sub(before_waiting).saturating_add(after_waiting);
    let revision = guests.rooms.entry(record.room.clone()).or_default();
    *revision = revision.checked_add(1).ok_or(GuestError::NotAllowed)?;
    if matches!(op, GuestOp::Knock { .. }) && guests.links.get(&id).is_some_and(|link| link.lobby) {
        return Ok(());
    }
    let change = if matches!(op, GuestOp::Create { .. }) {
        MeetingChange::Scheduled
    } else if matches!(op, GuestOp::Close { cancel: true, .. }) {
        MeetingChange::Cancelled
    } else {
        MeetingChange::Lobby
    };
    server.meeting_line(&record.room, actor, id, change, record.version, &text).map_err(|error| GuestError::Durable(DurableError::Server(error)))?;
    Ok(())
}

impl DurableServer {
    pub fn guest_entrance<C: Fn() -> u64>(&mut self, clock: C) -> GuestAccess<'_, C> {
        GuestAccess { server: self, clock }
    }

    pub fn guest_meeting_save(&mut self, user: &str, change: &GuestMeetingChange, now_ms: u64) -> Result<GuestReply, GuestError> {
        self.check_alive().map_err(GuestError::Durable)?;
        self.sweep_guest_links(now_ms).map_err(GuestError::Durable)?;
        match change {
            GuestMeetingChange::Create(draft) => {
                let room = self.server.room(&draft.room).map_err(|_| GuestError::NoSuchGuest)?;
                let role = room.role(user).ok_or(GuestError::NoSuchGuest)?;
                if role == Role::Guest || room.is_read_only() {
                    return Err(GuestError::NotAllowed);
                }
                let (title, agenda) = crate::meetings::checked(&Draft {
                    title: &draft.title,
                    start_ms: draft.start_ms,
                    duration: draft.duration,
                    agenda: &draft.agenda,
                })
                .map_err(|_| GuestError::BadText)?;
                let host_name = name(&draft.host_name)?;
                let duration = draft.expires_ms.checked_sub(now_ms).ok_or(GuestError::BadText)?;
                if !draft.lobby && !draft.confirm_direct {
                    return Err(GuestError::NotAllowed);
                }
                if !(MIN_LINK_MS..=MAX_LINK_MS).contains(&duration) || draft.start_ms.saturating_add(u64::from(draft.duration) * 60_000) <= now_ms {
                    return Err(GuestError::BadText);
                }
                let code = code()?;
                let code_hash = digest(b"crewcraft.guest.link.v1\0", code.as_bytes());
                if self.guests.codes.contains_key(&code_hash) {
                    return Err(GuestError::MediaUnavailable);
                }
                let id = self.meetings.next.checked_add(1).ok_or(GuestError::NotAllowed)?;
                let draft = GuestMeetingDraft { title, agenda, host_name, ..draft.clone() };
                self.record_guest(&GuestOp::Create { meeting: id, owner: user.to_owned(), draft, code: code_hash, now_ms })
                    .map_err(GuestError::Durable)?;
                Ok(GuestReply::Created { lobby: self.guests.lobby(id)?, code: GuestCode(code) })
            }
            GuestMeetingChange::SetLobby { meeting, revision, lobby, confirm_direct } => {
                staff(&self.server, &self.meetings, user, *meeting, true)?;
                let link = self.guests.live(*meeting, now_ms)?;
                if link.revision != *revision {
                    return Err(GuestError::Conflict);
                }
                if !lobby && !confirm_direct {
                    return Err(GuestError::NotAllowed);
                }
                if link.lobby != *lobby {
                    self.record_guest(&GuestOp::Lobby { meeting: *meeting, actor: user.to_owned(), revision: *revision, lobby: *lobby, now_ms })
                        .map_err(GuestError::Durable)?;
                }
                Ok(GuestReply::Lobby(self.guests.lobby(*meeting)?))
            }
        }
    }

    pub fn guest_link_close(&mut self, user: &str, meeting: u64, revision: u64, now_ms: u64) -> Result<GuestLobby, GuestError> {
        self.check_alive().map_err(GuestError::Durable)?;
        self.sweep_guest_links(now_ms).map_err(GuestError::Durable)?;
        staff(&self.server, &self.meetings, user, meeting, true)?;
        let link = self.guests.links.get(&meeting).ok_or(GuestError::NoSuchGuest)?;
        if revision != link.revision {
            return Err(GuestError::Conflict);
        }
        if !link.closed {
            let dropping = self.admitted_guests(meeting);
            self.record_guest(&GuestOp::Close { meeting, actor: user.to_owned(), revision, now_ms, cancel: false }).map_err(GuestError::Durable)?;
            self.drop_guest_ids(meeting, &dropping);
        }
        self.guests.lobby(meeting)
    }

    pub fn guest_lobby(&mut self, user: &str, meeting: u64, now_ms: u64) -> Result<GuestLobby, GuestError> {
        self.check_alive().map_err(GuestError::Durable)?;
        self.sweep_guest_links(now_ms).map_err(GuestError::Durable)?;
        staff(&self.server, &self.meetings, user, meeting, false)?;
        self.guests.lobby(meeting)
    }

    pub fn guest_lobby_decide(
        &mut self,
        user: &str,
        meeting: u64,
        guest: u64,
        revision: u64,
        decision: GuestDecision,
        now_ms: u64,
    ) -> Result<GuestLobby, GuestError> {
        self.check_alive().map_err(GuestError::Durable)?;
        self.sweep_guest_links(now_ms).map_err(GuestError::Durable)?;
        staff(&self.server, &self.meetings, user, meeting, false)?;
        let link = self.guests.live(meeting, now_ms)?;
        if link.revision != revision {
            return Err(GuestError::Conflict);
        }
        let visitor = link.visitors.get(&guest).ok_or(GuestError::NoSuchGuest)?;
        if !matches!(
            (visitor.state, decision),
            (GuestState::Waiting, GuestDecision::Admit | GuestDecision::Decline) | (GuestState::Admitted, GuestDecision::Remove)
        ) {
            return Err(GuestError::NotAllowed);
        }
        self.record_guest(&GuestOp::Decide { meeting, guest, actor: user.to_owned(), revision, decision, now_ms }).map_err(GuestError::Durable)?;
        if decision == GuestDecision::Remove {
            self.drop_guest_ids(meeting, &[guest]);
        }
        self.guests.lobby(meeting)
    }

    pub fn sweep_guest_links(&mut self, now_ms: u64) -> Result<(), DurableError> {
        self.check_alive()?;
        let expired: Vec<_> = self
            .guests
            .deadlines
            .range(..=(now_ms, u64::MAX))
            .filter_map(|&(at, meeting)| self.guests.links.get(&meeting).map(|link| (meeting, link.revision, at)))
            .collect();
        for (meeting, revision, at) in expired {
            let dropping = self.admitted_guests(meeting);
            self.record_guest(&GuestOp::Close { meeting, actor: String::new(), revision, now_ms: at, cancel: false })?;
            self.drop_guest_ids(meeting, &dropping);
        }
        Ok(())
    }

    pub fn guest_lobby_state(&self, room: &str, user: &str) -> Option<(u64, u32)> {
        let service = self.server.room(room).ok()?;
        if service.role(user)? == Role::Guest || service.is_read_only() {
            return None;
        }
        let waiting = self.guests.waiting.get(room).copied().unwrap_or(0);
        Some((self.guests.rooms.get(room).copied().unwrap_or(0), waiting))
    }

    pub fn guest_meeting_for(&self, user: &str, id: u64) -> bool {
        self.visible(user, id).is_some_and(|record| record.audience == Audience::Guests)
    }
    pub fn is_guest_call(&self, call: u64) -> bool {
        self.guests.bound.contains_key(&call)
    }

    pub(crate) fn cancel_guest_schedule(&mut self, actor: &str, meeting: u64, now_ms: u64) -> Result<u64, GuestError> {
        let revision = self.guests.links.get(&meeting).ok_or(GuestError::NoSuchGuest)?.revision;
        let dropping = self.admitted_guests(meeting);
        self.record_guest(&GuestOp::Close { meeting, actor: actor.to_owned(), revision, now_ms, cancel: true }).map_err(GuestError::Durable)?;
        self.drop_guest_ids(meeting, &dropping);
        self.meeting(meeting).map(|record| record.version).ok_or(GuestError::NoSuchGuest)
    }

    pub(crate) fn join_guest_meeting(&mut self, actor: &str, meeting: u64, now_ms: u64) -> Result<(String, u64), MeetingError> {
        self.sweep_calls(now_ms).map_err(MeetingError::Durable)?;
        if !self.guests.links.contains_key(&meeting) {
            return Err(MeetingError::NoSuchMeeting);
        }
        let room = self.meeting(meeting).ok_or(MeetingError::NoSuchMeeting)?.room.clone();
        if self.server.room(&room).is_ok_and(|room| room.is_read_only()) {
            return Err(MeetingError::NotAllowed);
        }
        if let Some(call) = self.open_call(&room).map(|call| call.id) {
            if self.guests.bound_to(call) != Some(meeting) {
                return Err(MeetingError::NotAllowed);
            }
            self.call_join_for_meeting(&room, actor, call, now_ms).map_err(|error| match error {
                CallError::Durable(error) => MeetingError::Durable(error),
                _ => MeetingError::NotAllowed,
            })?;
            return Ok((room, call));
        }
        let call = self.calls.next.checked_add(1).ok_or(MeetingError::NotAllowed)?;
        staff(&self.server, &self.meetings, actor, meeting, false).map_err(|_| MeetingError::NotAllowed)?;
        self.record_guest(&GuestOp::Bind { meeting, call, actor: actor.to_owned(), now_ms }).map_err(MeetingError::Durable)?;
        Ok((room, call))
    }

    fn admitted_guests(&self, meeting: u64) -> Vec<u64> {
        self.guests
            .links
            .get(&meeting)
            .map(|link| link.visitors.iter().filter(|(_, visitor)| visitor.state == GuestState::Admitted).map(|(&id, _)| id).collect())
            .unwrap_or_default()
    }

    fn drop_guest_ids(&mut self, meeting: u64, ids: &[u64]) {
        let Some(record) = self.meeting(meeting) else { return };
        let Some(call) = self.open_call(&record.room).filter(|call| record.calls.contains(&call.id)).map(|call| call.id) else { return };
        for id in ids {
            self.media.push(MediaEvent::DropPerson { call, person: format!("guest:{id}") });
        }
    }

    pub(crate) fn reconcile_guest_drops(&mut self) {
        let ids: Vec<_> = self
            .guests
            .links
            .iter()
            .map(|(&meeting, link)| {
                (meeting, link.visitors.iter().filter(|(_, visitor)| visitor.state == GuestState::Removed).map(|(&id, _)| id).collect::<Vec<_>>())
            })
            .collect();
        for (meeting, guests) in ids {
            self.drop_guest_ids(meeting, &guests);
        }
    }
}

impl<C: Fn() -> u64> GuestAccess<'_, C> {
    fn begin(&mut self, peer: IpAddr) -> Result<u64, GuestError> {
        self.server.check_alive().map_err(GuestError::Durable)?;
        let now = (self.clock)();
        self.server.guests.limit(peer, now)?;
        self.server.sweep_calls(now).map_err(GuestError::Durable)?;
        Ok(now)
    }

    fn meeting(&self, code: &str, now_ms: u64) -> Result<u64, GuestError> {
        if code.len() != 24 || !code.bytes().all(|byte| ALPHABET.contains(&byte)) {
            return Err(GuestError::LinkClosed);
        }
        let id = *self.server.guests.codes.get(&digest(b"crewcraft.guest.link.v1\0", code.as_bytes())).ok_or(GuestError::LinkClosed)?;
        self.server.guests.live(id, now_ms)?;
        Ok(id)
    }
}

impl<C: Fn() -> u64> GuestEntrance for GuestAccess<'_, C> {
    fn lookup(&mut self, peer: IpAddr, code: &str) -> Result<GuestPreview, GuestError> {
        let now = self.begin(peer)?;
        let id = self.meeting(code, now)?;
        let meeting = self.server.meeting(id).ok_or(GuestError::LinkClosed)?;
        let link = self.server.guests.live(id, now)?;
        Ok(GuestPreview { title: meeting.title.clone(), host_name: link.host_name.clone() })
    }

    fn knock(&mut self, peer: IpAddr, code: &str, display: &str) -> Result<GuestKnock, GuestError> {
        let now_ms = self.begin(peer)?;
        let meeting = self.meeting(code, now_ms)?;
        let display = name(display)?;
        let link = self.server.guests.live(meeting, now_ms)?;
        if link.visitors.len() >= MAX_GUESTS
            || (link.lobby && link.visitors.values().filter(|visitor| visitor.state == GuestState::Waiting).count() >= MAX_WAITING)
        {
            return Err(GuestError::Full);
        }
        let bearer = GuestBearer(random::<32>()?);
        let guest = self.server.guests.next.checked_add(1).ok_or(GuestError::Full)?;
        self.server
            .record_guest(&GuestOp::Knock { meeting, guest, name: display, digest: digest(b"crewcraft.guest.bearer.v1\0", &bearer.0), now_ms })
            .map_err(GuestError::Durable)?;
        let state = self.server.guests.authenticate(&GuestProof { meeting, guest, bearer: bearer.clone() })?.state;
        Ok(GuestKnock { proof: GuestProof { meeting, guest, bearer }, state })
    }

    fn status(&mut self, peer: IpAddr, proof: &GuestProof) -> Result<GuestStatus, GuestError> {
        let now = self.begin(peer)?;
        let visitor = self.server.guests.authenticate(proof)?;
        self.server.guests.live(proof.meeting, now)?;
        Ok(GuestStatus { meeting: proof.meeting, guest: proof.guest, name: visitor.name.clone(), state: visitor.state, revision: visitor.revision })
    }

    fn media(&mut self, peer: IpAddr, proof: &GuestProof) -> Result<GuestMedia, GuestError> {
        let now = self.begin(peer)?;
        let visitor = self.server.guests.authenticate(proof)?;
        let link = self.server.guests.live(proof.meeting, now)?;
        if visitor.state != GuestState::Admitted {
            return Err(GuestError::NotAllowed);
        }
        let meeting = self.server.meeting(proof.meeting).ok_or(GuestError::NoSuchGuest)?;
        let call = self
            .server
            .open_call(&meeting.room)
            .filter(|call| self.server.guests.bound_to(call.id) == Some(proof.meeting))
            .ok_or(GuestError::LinkClosed)?;
        let person = format!("guest:{}", proof.guest);
        let credential = self.server.guest_media_credential(call.id, &meeting.room, &person, proof.guest, now, link.expires_ms)?;
        let address = self.server.media_address().ok_or(GuestError::MediaUnavailable)?.to_owned();
        Ok(GuestMedia { call: call.id, room: meeting.room.clone(), person, label: format!("{} (guest)", visitor.name), address, credential })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const NOW: u64 = 1_800_000_000_000;
    const OWNER: &str = "host@example.org";

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn fixture() -> Result<(Scratch, DurableServer, String), GuestError> {
        let path = std::env::temp_dir().join(format!("crewcraft-guest-{}-{}", std::process::id(), u64::from_be_bytes(random::<8>()?)));
        fs::create_dir(&path).map_err(|_| GuestError::MediaUnavailable)?;
        let scratch = Scratch(path);
        let mut server = DurableServer::open(&scratch.0.join("rooms.log")).map_err(GuestError::Durable)?;
        let room = server.create_room(OWNER, "Meeting fixture").map_err(GuestError::Durable)?;
        Ok((scratch, server, room))
    }

    fn create(server: &mut DurableServer, room: &str, lobby: bool) -> Result<(GuestLobby, GuestCode), GuestError> {
        let draft = GuestMeetingDraft {
            room: room.to_owned(),
            start_ms: NOW + 60_000,
            duration: 30,
            title: "A meeting".into(),
            agenda: String::new(),
            host_name: "Host".into(),
            expires_ms: NOW + MIN_LINK_MS,
            lobby,
            confirm_direct: !lobby,
        };
        match server.guest_meeting_save(OWNER, &GuestMeetingChange::Create(draft), NOW)? {
            GuestReply::Created { lobby, code } => Ok((lobby, code)),
            GuestReply::Lobby(_) => Err(GuestError::NoSuchGuest),
        }
    }

    fn peer() -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 20))
    }

    #[test]
    fn lobby_revision_controls_decisions_and_waiting_knocks_leave_room_head_unchanged() -> Result<(), GuestError> {
        let (_scratch, mut server, room) = fixture()?;
        let (lobby, code) = create(&mut server, &room, true)?;
        let head = server.server.room(&room).map_err(|_| GuestError::NoSuchGuest)?.head();
        let knock = server.guest_entrance(|| NOW + 1).knock(peer(), &code.0, "  \u{202e}Visitor\u{0001} One  ")?;
        assert_eq!(server.server.room(&room).map_err(|_| GuestError::NoSuchGuest)?.head(), head);
        let state = server.guest_lobby(OWNER, lobby.meeting, NOW + 2)?;
        assert_eq!(state.entries[0].name, "Visitor One");
        assert!(state.revision > lobby.revision);
        assert_eq!(server.guest_lobby_state(&room, OWNER), Some((state.revision, 1)));
        assert_eq!(
            server.guest_lobby_decide(OWNER, lobby.meeting, knock.proof.guest, lobby.revision, GuestDecision::Admit, NOW + 3),
            Err(GuestError::Conflict)
        );
        let admitted = server.guest_lobby_decide(OWNER, lobby.meeting, knock.proof.guest, state.revision, GuestDecision::Admit, NOW + 3)?;
        assert_eq!(admitted.entries[0].state, GuestState::Admitted);
        let declined = server.guest_lobby_decide(OWNER, lobby.meeting, knock.proof.guest, admitted.revision, GuestDecision::Remove, NOW + 4)?;
        assert_eq!(
            server.guest_lobby_decide(OWNER, lobby.meeting, knock.proof.guest, declined.revision, GuestDecision::Admit, NOW + 5),
            Err(GuestError::NotAllowed)
        );
        Ok(())
    }

    #[test]
    fn restart_preserves_hashed_authority_and_expiry_closes_at_the_boundary() -> Result<(), GuestError> {
        let (scratch, mut server, room) = fixture()?;
        let (lobby, code) = create(&mut server, &room, false)?;
        let knock = server.guest_entrance(|| NOW + 1).knock(peer(), &code.0, "Visitor")?;
        drop(server);
        let bytes = fs::read(scratch.0.join("rooms.log")).map_err(|_| GuestError::MediaUnavailable)?;
        assert!(!bytes.windows(code.0.len()).any(|part| part == code.0.as_bytes()));
        assert!(!bytes.windows(knock.proof.bearer.0.len()).any(|part| part == knock.proof.bearer.0));
        let mut server = DurableServer::open(&scratch.0.join("rooms.log")).map_err(GuestError::Durable)?;
        assert_eq!(server.guest_entrance(|| lobby.expires_ms - 1).status(peer(), &knock.proof)?.state, GuestState::Admitted);
        assert_eq!(server.guest_entrance(|| lobby.expires_ms).status(peer(), &knock.proof), Err(GuestError::LinkClosed));
        let closed = server.guest_lobby(OWNER, lobby.meeting, lobby.expires_ms)?;
        assert!(closed.closed);
        assert_eq!(closed.entries[0].state, GuestState::Removed);
        assert_eq!(server.guest_lobby_state(&room, OWNER), Some((closed.revision, 0)));
        drop(server);
        let mut server = DurableServer::open(&scratch.0.join("rooms.log")).map_err(GuestError::Durable)?;
        assert_eq!(server.guest_lobby(OWNER, lobby.meeting, lobby.expires_ms)?, closed);
        Ok(())
    }

    #[test]
    fn cancelling_the_schedule_and_link_is_one_atomic_guest_record() -> Result<(), GuestError> {
        let (scratch, mut server, room) = fixture()?;
        let (lobby, code) = create(&mut server, &room, true)?;
        let knock = server.guest_entrance(|| NOW + 1).knock(peer(), &code.0, "Visitor")?;
        server.cancel_meeting(&room, OWNER, lobby.meeting, 1, NOW + 2).map_err(|_| GuestError::NotAllowed)?;
        drop(server);
        let (journal, records) = crate::journal::Journal::open(&scratch.0.join("rooms.log")).map_err(|_| GuestError::MediaUnavailable)?;
        let last = records.last().ok_or(GuestError::NoSuchGuest)?;
        assert!(matches!(crate::op::decode_op(last), Ok(Op::Guest(GuestOp::Close { cancel: true, .. }))));
        drop(journal);
        let mut server = DurableServer::open(&scratch.0.join("rooms.log")).map_err(GuestError::Durable)?;
        assert!(server.meeting(lobby.meeting).is_some_and(|meeting| meeting.cancelled));
        assert!(server.guest_lobby(OWNER, lobby.meeting, NOW + 3)?.closed);
        assert_eq!(server.guest_entrance(|| NOW + 3).status(peer(), &knock.proof), Err(GuestError::LinkClosed));
        Ok(())
    }
}
