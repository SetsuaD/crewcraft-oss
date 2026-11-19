//! A signed-in chat connection, and the credentials that open one.
//!
//! Owns: `Credentials` (email, password and a current TOTP code, checked for shape and never printed),
//! `SignedInSession` (post, edit, delete, sync and the room list over one connection) and the sign-in step itself. Called by the lab
//! endpoint (`lab_client`), the server endpoint (`server_endpoint`) and the connection worker (`worker`). Calls
//! `chat_session` for the protocol.

use std::fmt;
use std::time::{Duration, Instant};

use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::room_view::Shown;
use crewcraft_proto::handshake::Hello;
use crewcraft_proto::message::MAX_NAME;
use crewcraft_proto::request::FEATURE_LIST_ROOMS;
use crewcraft_proto::signin::{CODE_LEN, MAX_EMAIL_BYTES, MAX_PASSWORD_BYTES, SignIn};
use zeroize::Zeroizing;

use crate::chat_session::ChatSession;
use crate::connect::Transport;
use crate::lab_client::LabError;

const FRAME_TIMEOUT: Duration = Duration::from_secs(3);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

type SetDeadline = fn(&mut Transport, Instant);

/// The person's email, password and a current authenticator code, for exactly one sign-in. The password and code are
/// wiped from memory when this is dropped, and `Debug` prints none of the fields.
pub struct Credentials {
    email: String,
    password: Zeroizing<String>,
    code: Zeroizing<String>,
}

impl Credentials {
    /// `None` unless the email is 1 to 320 bytes, the password 1 to 1024 bytes, neither holds a control character,
    /// and the code is exactly six ASCII digits.
    pub fn new(email: &str, password: &str, code: &str) -> Option<Self> {
        let text_ok = |text: &str, max: usize| !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control);
        let code_ok = code.len() == CODE_LEN && code.bytes().all(|byte| byte.is_ascii_digit());
        (text_ok(email, MAX_EMAIL_BYTES) && text_ok(password, MAX_PASSWORD_BYTES) && code_ok).then(|| Self {
            email: email.to_owned(),
            password: Zeroizing::new(password.to_owned()),
            code: Zeroizing::new(code.to_owned()),
        })
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    pub(crate) fn sign_in(&self) -> SignIn<'_> {
        SignIn { email: &self.email, password: &self.password, code: &self.code }
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("Credentials { .. }")
    }
}

pub(crate) fn valid_room(room: &str) -> bool {
    !room.is_empty() && room.len() <= MAX_NAME && room.chars().all(|ch| !ch.is_control() && !ch.is_whitespace())
}

/// Sign in over a verified device connection and negotiate the chat protocol, all within one operation deadline. The
/// client offers `FEATURE_LIST_ROOMS`; a server that does not agree to it is still used, without the room list.
pub(crate) fn sign_in(stream: Transport, credentials: &SignIn<'_>, client: &str) -> Result<SignedInSession, LabError> {
    let hello = Hello { min_version: 1, max_version: 1, features: FEATURE_LIST_ROOMS, client: client.into() };
    let settings = Settings::new(credentials.email);
    let set_deadline: SetDeadline = |stream, deadline| stream.get_mut().set_deadline(deadline);
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    let chat = ChatSession::connect(stream, set_deadline, credentials, hello, settings, FRAME_TIMEOUT, deadline).map_err(LabError::Chat)?;
    Ok(SignedInSession { chat })
}

/// An authenticated connection. Dropping it ends the local session. Commands use the same connection and the same
/// room views until the connection closes.
pub struct SignedInSession {
    chat: ChatSession<Transport, SetDeadline>,
}

impl SignedInSession {
    /// `text` comes from the caller's protected input and is sent only on this connection.
    pub fn post(&mut self, room: &str, text: &str) -> Result<u64, LabError> {
        if !valid_room(room) {
            return Err(LabError::Usage);
        }
        self.chat.post(room, text, 0, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    pub fn edit(&mut self, room: &str, target: u64, text: &str) -> Result<u64, LabError> {
        if !valid_room(room) || target == 0 {
            return Err(LabError::Usage);
        }
        self.chat.edit(room, target, text, 0, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    pub fn delete(&mut self, room: &str, target: u64) -> Result<u64, LabError> {
        if !valid_room(room) || target == 0 {
            return Err(LabError::Usage);
        }
        self.chat.delete(room, target, 0, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Ask the server to answer, which keeps an idle connection open.
    pub fn ping(&mut self) -> Result<(), LabError> {
        self.chat.ping(0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// The rooms the signed-in person is a member of, sorted, or `None` when the server is too old to list them (it did
    /// not agree to `FEATURE_LIST_ROOMS` in the handshake; nothing is sent then).
    pub fn list_rooms(&mut self) -> Result<Option<Vec<String>>, LabError> {
        if !self.chat.lists_rooms() {
            return Ok(None);
        }
        self.chat.list_rooms(0, Instant::now() + OPERATION_TIMEOUT).map(Some).map_err(LabError::Chat)
    }

    /// Fetch the room's events after the cursor already held and return the acknowledged head and the whole room as
    /// it is drawn.
    pub fn sync(&mut self, room: &str) -> Result<(u64, Vec<Shown>), LabError> {
        if !valid_room(room) {
            return Err(LabError::Usage);
        }
        let head = self.chat.sync(room, false, 0, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)?;
        let lines = self.chat.view(room).ok_or(LabError::MissingTimeline)?.shown();
        Ok((head, lines))
    }
}
