//! Serve one CrewCraft connection after the transport has verified its enrolled device. Task T214.

use std::io::{self, Read, Write};
use std::sync::Mutex;

use crewcraft_proto::frame::{self, MAX_FRAME};
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::signin::{self, CODE_LEN, MAX_EMAIL_BYTES, MAX_PASSWORD_BYTES, SignIn};
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::session::{DurableSessionError, Phase, Session};

const MAX_SIGN_IN_FRAME: usize = 1 + 2 + MAX_EMAIL_BYTES + 2 + MAX_PASSWORD_BYTES + CODE_LEN;

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

    /// Check that this session and its device remain authorized at `now_ms` and hold that authorization throughout
    /// `action`. A revoked or expired session returns `Ok(None)` without calling `action`.
    fn with_live_session<T>(&self, session: &Self::Session, now_ms: u64, action: impl FnOnce() -> T) -> Result<Option<T>, AuthError>;
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
}

impl From<io::Error> for DeviceSessionError {
    fn from(error: io::Error) -> Self {
        Self::Transport(error.kind())
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
    mut reset_deadline: impl FnMut(&mut S) -> io::Result<()>,
    mut now_ms: impl FnMut() -> u64,
) -> Result<(), DeviceSessionError> {
    reset_deadline(stream)?;
    let (user, handle) = {
        let signed_in = {
            let Some(first) = frame::read_frame(stream, MAX_SIGN_IN_FRAME)? else {
                return Ok(());
            };
            let credentials = signin::decode_request(first.payload()).map_err(|_| DeviceSessionError::InvalidSignIn)?;
            auth.sign_in(credentials, now_ms()).map_err(DeviceSessionError::Auth)?
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
    let mut session = Session::new(&user, server_side);
    loop {
        reset_deadline(stream)?;
        let Some(request) = frame::read_frame(stream, MAX_FRAME)? else {
            return Ok(());
        };
        let received_at = now_ms();
        let output = auth
            .with_live_session(&handle, received_at, || {
                let mut rooms = rooms.lock().map_err(|_| DeviceSessionError::RoomsUnavailable)?;
                session.receive_durable(&mut rooms, request.as_bytes(), received_at).map_err(DeviceSessionError::Chat)
            })
            .map_err(DeviceSessionError::Auth)?
            .ok_or(DeviceSessionError::SessionEnded)??;
        if !output.is_empty() {
            reset_deadline(stream)?;
            stream.write_all(&output)?;
            stream.flush()?;
        }
        if session.phase() == Phase::Closed {
            return Ok(());
        }
    }
}
