//! Serve one CrewCraft connection after the transport has verified its enrolled device. Task T214.

use std::io::{self, Read, Write};
use std::sync::Mutex;

use crewcraft_proto::frame::{self, MAX_FRAME};
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::request::{Response, encode_answer, encode_response};
use crewcraft_proto::signin::{
    self, CODE_LEN, MAX_AUTH_CODE_BYTES, MAX_EMAIL_BYTES, MAX_PASSWORD_BYTES, MAX_REDIRECT_BYTES, MAX_VERIFIER_LEN, Opening, SignIn,
};
use crewcraft_server_core::connection::PendingOffer;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::session::{DurableSessionError, Phase, Session};

const PASSWORD_SIGN_IN_FRAME: usize = 1 + 2 + MAX_EMAIL_BYTES + 2 + MAX_PASSWORD_BYTES + CODE_LEN;
/// The largest `FinishExternal` opening (task T611a): code, verifier and redirect URI, each with a `u16` length.
const FINISH_EXTERNAL_FRAME: usize = 1 + 2 + MAX_AUTH_CODE_BYTES + 2 + MAX_VERIFIER_LEN + 2 + MAX_REDIRECT_BYTES;
const MAX_SIGN_IN_FRAME: usize = if PASSWORD_SIGN_IN_FRAME > FINISH_EXTERNAL_FRAME { PASSWORD_SIGN_IN_FRAME } else { FINISH_EXTERNAL_FRAME };

/// An account session committed to durable storage by the server.
pub struct CommittedSignIn<Handle> {
    pub user: String,
    pub token: String,
    pub session: Handle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    Unavailable,
    UnauthorizedDevice,
}

/// Authentication bound to the device identity verified by the transport. The wire supplies only the T152 fields.
pub trait DeviceAuth {
    type Session;

    /// Return the canonical user, token, and handle only after the account session is committed.
    /// An ordinary credential failure returns `Ok(None)`; an ineligible device or unavailable store returns an error.
    fn sign_in(&self, credentials: SignIn<'_>, now_ms: u64) -> Result<Option<CommittedSignIn<Self::Session>>, AuthError>;

    /// Reopen the session `token` belongs to, for this same device (task T240): the session must still be within its
    /// absolute lifetime, however long it was idle. `Ok(None)` refuses it. The default refuses every resume.
    fn resume(&self, token: &str, now_ms: u64) -> Result<Option<CommittedSignIn<Self::Session>>, AuthError> {
        let _ = (token, now_ms);
        Ok(None)
    }

    /// End the session `token` belongs to, if it is this device's (task T240). False if there was none to end. The
    /// default ends nothing.
    fn end(&self, token: &str, now_ms: u64) -> Result<bool, AuthError> {
        let _ = (token, now_ms);
        Ok(false)
    }

    /// Begin a sign-in through the server's external identity provider for this device (task T611e). `Ok(None)` when
    /// the server has none, or refuses; the default has none.
    fn begin_external(&self, now_ms: u64) -> Result<Option<crate::external_signin::Start>, AuthError> {
        let _ = now_ms;
        Ok(None)
    }

    /// Finish it with the code from the loopback redirect, the PKCE verifier and that redirect URI (task T611e).
    /// `Ok(None)` refuses; the default refuses.
    fn finish_external(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        now_ms: u64,
    ) -> Result<Option<CommittedSignIn<Self::Session>>, AuthError> {
        let _ = (code, verifier, redirect_uri, now_ms);
        Ok(None)
    }

    /// Check that this session and its device remain authorized at `now_ms` and hold that authorization throughout
    /// `action`. A revoked or expired session returns `Ok(None)` without calling `action`.
    fn with_live_session<T>(&self, session: &Self::Session, now_ms: u64, action: impl FnOnce() -> T) -> Result<Option<T>, AuthError>;

    /// The enrolled device the transport verified, when known: media credentials name it (task T360b2).
    fn device(&self) -> Option<u64> {
        None
    }

    /// Whether a session ended because the person's access was withdrawn (the authorizer refused them, task T611j),
    /// rather than for an ordinary reason such as signing out or an expired certificate (task T360b4).
    fn revoked(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceSessionError {
    Transport(io::ErrorKind),
    InvalidSignIn,
    Auth(AuthError),
    InvalidSignInReply,
    SessionEnded,
    RoomsUnavailable,
    Chat(DurableSessionError),
    /// A relayed offer's answer could not be encoded (task T360b6).
    InvalidOfferReply,
}

impl From<io::Error> for DeviceSessionError {
    fn from(error: io::Error) -> Self {
        Self::Transport(error.kind())
    }
}

/// Where a participant's WebRTC offer goes (task T360b6): the media server, over the chat server's control connection.
pub trait MediaRelay: Send + Sync {
    /// Relay `offer` with its `credential` for `call` and wait for the media server's SDP answer, or why there is none.
    fn join(&self, call: u64, credential: &[u8], offer: &str) -> Result<String, RelayRefusal>;
}

/// Why a relayed offer has no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRefusal {
    /// The media server refused it, with one of `crewcraft_proto::media_control::REFUSED_*`.
    Refused(u8),
    /// The media server could not be reached in time.
    Unavailable,
}

/// The frames answering `offer`: `Ok` with the call's id and the answer frame, or an `Error` that says why not.
fn answer_offer(relay: Option<&dyn MediaRelay>, offer: &PendingOffer) -> Result<Vec<u8>, DeviceSessionError> {
    use crewcraft_proto::media_control::{REFUSED_CALL_FULL, REFUSED_CREDENTIAL, REFUSED_OFFER, REFUSED_WRONG_CALL};
    use crewcraft_server_core::dispatch::{E_NOT_ALLOWED, E_OTHER};
    let relayed = relay.map_or(Err(RelayRefusal::Unavailable), |relay| relay.join(offer.call, &offer.credential, &offer.offer));
    let frame = |payload: Result<Vec<u8>, crewcraft_proto::message::CodecError>| -> Result<Vec<u8>, DeviceSessionError> {
        frame::encode(&payload.map_err(|_| DeviceSessionError::InvalidOfferReply)?).map_err(|_| DeviceSessionError::InvalidOfferReply)
    };
    let refusal = |code: u16, detail: &str| frame(encode_response(offer.id, &Response::Error { code, detail: detail.to_owned() }));
    match relayed {
        Ok(answer) => {
            let mut out = frame(encode_response(offer.id, &Response::Ok { cursor: offer.call }))?;
            out.extend(frame(encode_answer(offer.id, &answer))?);
            Ok(out)
        }
        Err(RelayRefusal::Refused(reason)) => refusal(
            E_NOT_ALLOWED,
            match reason {
                REFUSED_CREDENTIAL => "the media server refused the credential",
                REFUSED_OFFER => "the media server refused the offer",
                REFUSED_WRONG_CALL => "the credential is for another call",
                REFUSED_CALL_FULL => "the call is full",
                _ => "the media server is stopping",
            },
        ),
        Err(RelayRefusal::Unavailable) => refusal(E_OTHER, "the media server cannot be reached"),
    }
}

/// Require one sign-in before reading any chat frame. A live account guard covers each subsequent room operation,
/// with locks acquired account first, then rooms. All stream I/O runs outside those guards.
///
/// `reset_deadline` starts a bounded interval for the next complete frame read or reply write. The transport enforces
/// that deadline across its reads and writes. `now_ms` supplies Unix time in milliseconds after inbound frames arrive.
pub fn serve<S: Read + Write, A: DeviceAuth>(
    stream: &mut S,
    auth: &A,
    rooms: &Mutex<DurableServer>,
    server_side: ServerSide,
    reset_deadline: impl FnMut(&mut S) -> io::Result<()>,
    now_ms: impl FnMut() -> u64,
) -> Result<(), DeviceSessionError> {
    serve_with_media(stream, auth, rooms, None, server_side, reset_deadline, now_ms)
}

/// As `serve`, relaying participants' WebRTC offers through `relay` (task T360b6). An offer is checked under the room
/// lock (only someone in the call), then relayed with no lock held, and its answer written in request order.
pub fn serve_with_media<S: Read + Write, A: DeviceAuth>(
    stream: &mut S,
    auth: &A,
    rooms: &Mutex<DurableServer>,
    relay: Option<&dyn MediaRelay>,
    server_side: ServerSide,
    mut reset_deadline: impl FnMut(&mut S) -> io::Result<()>,
    mut now_ms: impl FnMut() -> u64,
) -> Result<(), DeviceSessionError> {
    reset_deadline(stream)?;
    let (user, handle) = {
        let signed_in = {
            let Some(first) = frame::read_frame(stream, MAX_SIGN_IN_FRAME)? else {
                return Ok(());
            };
            match signin::decode_opening(first.payload()).map_err(|_| DeviceSessionError::InvalidSignIn)? {
                Opening::SignIn(credentials) => auth.sign_in(credentials, now_ms()).map_err(DeviceSessionError::Auth)?,
                Opening::Resume { token } => auth.resume(token, now_ms()).map_err(DeviceSessionError::Auth)?,
                // External sign-in (tasks T611a, T611e). Beginning is its own short exchange: the app then leaves for the
                // browser and finishes on a new connection. A server without an identity provider refuses both, exactly
                // like a failed sign-in, so the reply reveals nothing.
                Opening::BeginExternal => {
                    let start = auth.begin_external(now_ms()).map_err(DeviceSessionError::Auth)?;
                    let reply = match &start {
                        Some(s) => signin::Reply::ExternalStart {
                            issuer: &s.issuer,
                            client_id: &s.client_id,
                            authorization_endpoint: &s.authorization_endpoint,
                            nonce: &s.nonce,
                        },
                        None => signin::Reply::Refused,
                    };
                    let payload = signin::encode_reply(&reply).map_err(|_| DeviceSessionError::InvalidSignInReply)?;
                    let frame = frame::encode(&payload).map_err(|_| DeviceSessionError::InvalidSignInReply)?;
                    reset_deadline(stream)?;
                    stream.write_all(&frame)?;
                    stream.flush()?;
                    return Ok(());
                }
                Opening::FinishExternal { code, verifier, redirect_uri } => {
                    auth.finish_external(code, verifier, redirect_uri, now_ms()).map_err(DeviceSessionError::Auth)?
                }
                Opening::End { token } => {
                    auth.end(token, now_ms()).map_err(DeviceSessionError::Auth)?;
                    let payload = signin::encode_reply(&signin::Reply::Ended).map_err(|_| DeviceSessionError::InvalidSignInReply)?;
                    let reply = frame::encode(&payload).map_err(|_| DeviceSessionError::InvalidSignInReply)?;
                    reset_deadline(stream)?;
                    stream.write_all(&reply)?;
                    stream.flush()?;
                    return Ok(());
                }
            }
        };

        let reply = match &signed_in {
            Some(session) => signin::Reply::Accepted { token: &session.token },
            None => signin::Reply::Refused,
        };
        let payload = signin::encode_reply(&reply).map_err(|_| DeviceSessionError::InvalidSignInReply)?;
        let reply = frame::encode(&payload).map_err(|_| DeviceSessionError::InvalidSignInReply)?;
        reset_deadline(stream)?;
        stream.write_all(&reply)?;
        stream.flush()?;

        let Some(CommittedSignIn { user, session, .. }) = signed_in else {
            return Ok(());
        };
        (user, session)
    };
    let mut session = Session::new(&user, server_side).with_device(auth.device());
    loop {
        reset_deadline(stream)?;
        let Some(request) = frame::read_frame(stream, MAX_FRAME)? else {
            return Ok(());
        };
        let received_at = now_ms();
        let live = auth
            .with_live_session(&handle, received_at, || {
                let mut rooms = rooms.lock().map_err(|_| DeviceSessionError::RoomsUnavailable)?;
                session.receive_durable(&mut rooms, request.as_bytes(), received_at).map_err(DeviceSessionError::Chat)
            })
            .map_err(DeviceSessionError::Auth)?;
        let Some(output) = live else {
            // Withdrawn access also means out of every call now, so the media server drops this person at once (task
            // T360b4). A storage failure here is reported by the next request that needs the store.
            if auth.revoked()
                && let Ok(mut rooms) = rooms.lock()
            {
                let _ = rooms.drop_from_calls(&user, received_at);
            }
            return Err(DeviceSessionError::SessionEnded);
        };
        let output = output?;
        if !output.is_empty() {
            reset_deadline(stream)?;
            stream.write_all(&output)?;
            stream.flush()?;
        }
        if let Some(offer) = session.take_offer() {
            let answer = answer_offer(relay, &offer)?;
            reset_deadline(stream)?;
            stream.write_all(&answer)?;
            stream.flush()?;
        }
        if session.phase() == Phase::Closed {
            return Ok(());
        }
    }
}
