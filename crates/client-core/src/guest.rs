//! Staff guest-meeting requests (T370c, docs/MEETINGS.md). These helpers frame a request through an open
//! `ClientSession` and correlate its acknowledgement with the creation-only code or lobby result. The caller owns
//! transport, deadlines and feeding `ClientSession::receive` events to the returned request; this module opens no
//! guest entrance or listener. A transport advertising the feature must also wait for each Sync's fresh lobby state.

pub use crewcraft_proto::guest::{GuestCode, GuestDecision, GuestEntry, GuestLobby, GuestMeetingChange, GuestMeetingDraft, GuestReply, GuestState};
use crewcraft_proto::message::CodecError;
use crewcraft_proto::request::{FEATURE_GUEST_MEETINGS, FEATURE_MEETINGS, Request, Response};

use crate::client::ClientEvent;
use crate::requests::Reply;
use crate::session::{ClientSession, Phase};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestRequestError {
    /// The session has not completed its handshake, or has closed.
    WrongPhase,
    /// Both the meetings and guest-meetings features must have been negotiated.
    Unsupported,
    Codec(CodecError),
    Refused {
        code: u16,
        detail: String,
    },
    /// A result's id, kind, meeting or revision does not match the acknowledged request.
    Malformed,
}

/// One staff request awaiting its acknowledgement and then exactly one guest result. Unrelated events return
/// `Ok(None)`; completion returns the result once. A malformed matching event or refusal ends the request.
#[derive(Debug)]
pub struct GuestRequest {
    id: u32,
    request: Request,
    cursor: Option<u64>,
    finished: bool,
}

impl GuestRequest {
    pub fn save(session: &mut ClientSession, change: GuestMeetingChange, now_ms: u64) -> Result<(Self, Vec<u8>), GuestRequestError> {
        Self::send(session, Request::GuestMeetingSave { change }, now_ms)
    }

    pub fn close(session: &mut ClientSession, meeting: u64, revision: u64, now_ms: u64) -> Result<(Self, Vec<u8>), GuestRequestError> {
        Self::send(session, Request::GuestLinkClose { meeting, revision }, now_ms)
    }

    pub fn list(session: &mut ClientSession, meeting: u64, now_ms: u64) -> Result<(Self, Vec<u8>), GuestRequestError> {
        Self::send(session, Request::GuestLobbyList { meeting }, now_ms)
    }

    pub fn decide(
        session: &mut ClientSession,
        meeting: u64,
        guest: u64,
        revision: u64,
        decision: GuestDecision,
        now_ms: u64,
    ) -> Result<(Self, Vec<u8>), GuestRequestError> {
        Self::send(session, Request::GuestLobbyDecide { meeting, guest, revision, decision }, now_ms)
    }

    fn send(session: &mut ClientSession, request: Request, now_ms: u64) -> Result<(Self, Vec<u8>), GuestRequestError> {
        let Phase::Open { features, .. } = session.phase() else {
            return Err(GuestRequestError::WrongPhase);
        };
        let required = FEATURE_MEETINGS | FEATURE_GUEST_MEETINGS;
        if features & required != required {
            return Err(GuestRequestError::Unsupported);
        }
        let (id, frame) = session.client_mut().send_tracked(request.clone(), now_ms).map_err(GuestRequestError::Codec)?;
        Ok((Self { id, request, cursor: None, finished: false }, frame))
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn on_event(&mut self, event: &ClientEvent) -> Result<Option<GuestReply>, GuestRequestError> {
        match event {
            ClientEvent::Reply(Reply::Done { id, request, response }) if *id == self.id => {
                if self.finished || self.cursor.is_some() || request != &self.request {
                    self.finished = true;
                    return Err(GuestRequestError::Malformed);
                }
                match response {
                    Response::Ok { cursor } => {
                        self.cursor = Some(*cursor);
                        Ok(None)
                    }
                    Response::Error { code, detail } => {
                        self.finished = true;
                        Err(GuestRequestError::Refused { code: *code, detail: detail.clone() })
                    }
                }
            }
            ClientEvent::Guest { id, reply } if *id == self.id => {
                let valid = !self.finished && self.cursor.is_some_and(|cursor| self.matches(reply, cursor));
                self.finished = true;
                if valid { Ok(Some(reply.clone())) } else { Err(GuestRequestError::Malformed) }
            }
            _ => Ok(None),
        }
    }

    fn matches(&self, reply: &GuestReply, cursor: u64) -> bool {
        match (&self.request, reply) {
            (Request::GuestMeetingSave { change: GuestMeetingChange::Create(_) }, GuestReply::Created { lobby, .. }) => lobby.meeting == cursor,
            (Request::GuestMeetingSave { change: GuestMeetingChange::SetLobby { meeting, .. } }, GuestReply::Lobby(lobby))
            | (Request::GuestLinkClose { meeting, .. }, GuestReply::Lobby(lobby))
            | (Request::GuestLobbyList { meeting }, GuestReply::Lobby(lobby))
            | (Request::GuestLobbyDecide { meeting, .. }, GuestReply::Lobby(lobby)) => lobby.meeting == *meeting && lobby.revision == cursor,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crewcraft_proto::frame::encode as frame;
    use crewcraft_proto::guest::{GuestLobby, encode_guest};
    use crewcraft_proto::handshake::{Hello, Reply as HandshakeReply, encode_reply};
    use crewcraft_proto::push::{Push, encode_push};
    use crewcraft_proto::request::encode_response;

    use crate::client::Client;
    use crate::notify::{Notify, Settings};
    use crate::timeline::Apply;

    fn error(error: impl std::fmt::Debug) -> String {
        format!("{error:?}")
    }

    fn session(features: u32) -> Result<ClientSession, String> {
        let hello = Hello { min_version: 1, max_version: 1, features, client: "guest-test".into() };
        let mut session = ClientSession::new(hello, Client::new("staff@example.org", Settings::default()));
        session.start().map_err(error)?;
        let welcome = encode_reply(&HandshakeReply::Welcome { version: 1, features, server: "test".into() }).map_err(error)?;
        session.receive(&frame(&welcome).map_err(error)?, 0, 0).map_err(error)?;
        Ok(session)
    }

    fn lobby(meeting: u64, revision: u64) -> GuestReply {
        GuestReply::Lobby(GuestLobby { meeting, revision, expires_ms: 1_800_000_000_000, lobby: true, closed: false, entries: Vec::new() })
    }

    fn answer(id: u32, cursor: u64, reply: &GuestReply) -> Result<Vec<u8>, String> {
        let mut bytes = frame(&encode_response(id, &Response::Ok { cursor }).map_err(error)?).map_err(error)?;
        bytes.extend(frame(&encode_guest(id, reply).map_err(error)?).map_err(error)?);
        Ok(bytes)
    }

    #[test]
    fn simultaneous_staff_requests_match_their_own_acknowledgements_and_lobby_snapshots() -> Result<(), String> {
        let mut session = session(FEATURE_MEETINGS | FEATURE_GUEST_MEETINGS)?;
        session.client_mut().inbox_mut().follow("room", false);
        session.client_mut().inbox_mut().view_mut("room").ok_or("missing room")?.expect_guest_lobby_state();
        let (mut first, _) = GuestRequest::list(&mut session, 7, 0).map_err(error)?;
        let (mut second, _) = GuestRequest::list(&mut session, 8, 0).map_err(error)?;
        let mut bytes = answer(second.id(), 5, &lobby(8, 5))?;
        bytes.extend(
            frame(&encode_push(&Push::GuestLobbyState { room: "room".into(), cursor: 40, revision: 6, waiting: 2 }).map_err(error)?)
                .map_err(error)?,
        );
        bytes.extend(answer(first.id(), 4, &lobby(7, 4))?);
        let mut first_result = None;
        let mut second_result = None;
        let events = session.receive(&bytes, 0, 0).map_err(error)?;
        assert!(events.iter().any(|event| matches!(event, ClientEvent::Pushed { apply: Apply::Duplicate, notify: Notify::None, .. })));
        for event in events {
            first_result = first.on_event(&event).map_err(error)?.or(first_result);
            second_result = second.on_event(&event).map_err(error)?.or(second_result);
        }
        assert_eq!(first_result, Some(lobby(7, 4)));
        assert_eq!(second_result, Some(lobby(8, 5)));
        let view = session.client_mut().inbox().view("room").ok_or("missing room")?;
        assert_eq!(view.cursor(), 0);
        assert_eq!(view.guest_lobby_state().map(|state| state.waiting), Some(2));
        assert!(!view.awaiting_guest_lobby_state());
        Ok(())
    }

    #[test]
    fn a_wrong_meeting_or_acknowledged_revision_cannot_complete_a_staff_request() -> Result<(), String> {
        for (meeting, revision) in [(8, 5), (7, 6)] {
            let mut session = session(FEATURE_MEETINGS | FEATURE_GUEST_MEETINGS)?;
            let (mut pending, _) = GuestRequest::list(&mut session, 7, 0).map_err(error)?;
            let events = session.receive(&answer(pending.id(), 5, &lobby(meeting, revision))?, 0, 0).map_err(error)?;
            assert_eq!(pending.on_event(&events[0]), Ok(None));
            assert_eq!(pending.on_event(&events[1]), Err(GuestRequestError::Malformed));
            assert_eq!(pending.on_event(&ClientEvent::Guest { id: pending.id(), reply: lobby(7, 5) }), Err(GuestRequestError::Malformed));
        }
        Ok(())
    }

    #[test]
    fn guest_management_requires_both_negotiated_features() -> Result<(), String> {
        for features in [0, FEATURE_MEETINGS, FEATURE_GUEST_MEETINGS] {
            let mut session = session(features)?;
            assert!(matches!(GuestRequest::list(&mut session, 7, 0), Err(GuestRequestError::Unsupported)));
        }
        Ok(())
    }
}
