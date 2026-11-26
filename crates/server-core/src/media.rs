//! The chat server's side of media admission (docs/CALLS.md "Admission: removed means removed", task T360b2): media
//! credentials for people in a call, and what the media server must be told when someone leaves a call or it ends.
//!
//! Owns: `MediaIssuer` (the chat server's media key, the media server's name and address), `MediaEvent`, and
//! `DurableServer::set_media`, `media_address`, `media_credential` and `take_media_events`. The events are made where
//! people leave calls (`calls::leave_at`: leaving, removal, a stopped heartbeat, a revoked person) and where calls end;
//! the server binary sends them to the media server over its control connection. Calls `crewcraft-media-auth`.

use std::collections::VecDeque;

use crewcraft_media_auth::Issuer;

use crate::calls::CallError;
use crate::durable::DurableServer;

/// How many events wait for the control connection at most. Past that the oldest are dropped: a media server out of
/// reach that long is told nothing about them, and everyone it still holds is dropped when their credential's call
/// ends or their connection goes.
pub const MAX_MEDIA_EVENTS: usize = 65_536;

/// The media server this chat server admits people to.
pub struct MediaIssuer {
    issuer: Issuer,
    server_name: String,
    address: String,
}

impl MediaIssuer {
    /// Credentials signed with `issuer`'s key, for the media server named `server_name` (what it checks), which
    /// participants reach at `address` (what clients are told).
    pub fn new(issuer: Issuer, server_name: &str, address: &str) -> Self {
        Self { issuer, server_name: server_name.to_owned(), address: address.to_owned() }
    }

    /// The public key the media server must trust.
    pub fn public_key(&self) -> [u8; 32] {
        self.issuer.public_key()
    }
}

/// What the media server must do now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaEvent {
    /// Drop every session of `person` in `call`: they left, were removed, lost permission or stopped their heartbeat.
    DropPerson { call: u64, person: String },
    /// Drop everyone in `call`: it ended.
    EndCall { call: u64 },
}

/// The media server, when there is one, and the events waiting for it.
#[derive(Default)]
pub(crate) struct Media {
    issuer: Option<MediaIssuer>,
    events: VecDeque<MediaEvent>,
}

impl Media {
    /// Note `event` for the media server; nothing is kept when there is none.
    pub(crate) fn push(&mut self, event: MediaEvent) {
        if self.issuer.is_none() {
            return;
        }
        if self.events.len() >= MAX_MEDIA_EVENTS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }
}

impl DurableServer {
    /// Issue media credentials for `media` from now on (task T360b2).
    pub fn set_media(&mut self, media: MediaIssuer) {
        self.media.issuer = Some(media);
    }

    /// The address participants reach the media server at, when one is set.
    pub fn media_address(&self) -> Option<&str> {
        self.media.issuer.as_ref().map(|media| media.address.as_str())
    }

    /// A media credential for `device` of `actor` to join `call` of `slug`, good for `crewcraft_media_auth::LIFETIME_MS`
    /// from `now_ms`. Only for someone who is a member of the room and in the open call now (`NotMember`,
    /// `NoSuchCall`). `Ok(None)` when no media server is set, or a name is too long to carry.
    pub fn media_credential(&self, slug: &str, actor: &str, call: u64, device: u64, now_ms: u64) -> Result<Option<Vec<u8>>, CallError> {
        match self.server.room(slug) {
            Ok(room) if room.role(actor).is_some() => {}
            _ => return Err(CallError::NotMember),
        }
        let open = self.open_call(slug).filter(|open| open.id == call).ok_or(CallError::NoSuchCall)?;
        if !open.present.contains_key(actor) {
            return Err(CallError::NoSuchCall);
        }
        let Some(media) = &self.media.issuer else { return Ok(None) };
        Ok(media.issuer.issue(call, slug, actor, device, &media.server_name, now_ms).ok())
    }

    /// The events for the media server since the last call, oldest first.
    pub fn take_media_events(&mut self) -> Vec<MediaEvent> {
        self.media.events.drain(..).collect()
    }
}
