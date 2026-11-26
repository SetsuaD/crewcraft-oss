//! A signed-in chat connection, and the credentials that open one.
//!
//! Owns: `Credentials` (email, password and a current TOTP code, checked for shape and never printed),
//! `SignedInSession` (post, edit, delete, sync and the room list over one connection) and the sign-in step itself. Called by the lab
//! endpoint (`lab_client`), the server endpoint (`server_endpoint`) and the connection worker (`worker`). Calls
//! `chat_session` for the protocol.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use crewcraft_client_core::notify::Settings;
use crewcraft_client_core::room_view::Shown;
use crewcraft_proto::handshake::Hello;
use crewcraft_proto::message::MAX_NAME;
use crewcraft_proto::push::AttachedFile;
use crewcraft_proto::request::{FEATURE_FILES, FEATURE_LIST_ROOMS, FEATURE_SEARCH, FEATURE_THREADS, MAX_CHUNK, SearchHit};
use crewcraft_proto::signin::{CODE_LEN, MAX_EMAIL_BYTES, MAX_PASSWORD_BYTES, SignIn, TOKEN_LEN};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::chat_session::{ChatError, ChatSession};
use crate::connect::Transport;
use crate::lab_client::LabError;

const FRAME_TIMEOUT: Duration = Duration::from_secs(3);
const OPERATION_TIMEOUT: Duration = Duration::from_secs(10);

type SetDeadline = fn(&mut Transport, Instant);

/// A file just uploaded (task T330e).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uploaded {
    pub file: [u8; 16],
    pub name: String,
    pub size: u64,
}

/// Why a file could not be uploaded or downloaded (task T330e): this computer's file, or the server.
#[derive(Debug)]
pub enum FileOpError {
    Local(io::ErrorKind),
    Lab(LabError),
}

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

/// Whether `email` can name the person in a sign-in: 1 to 320 bytes with no control character, the rule
/// `Credentials::new` applies (used for the external sign-in, task T611h).
pub fn valid_email(email: &str) -> bool {
    !email.is_empty() && email.len() <= MAX_EMAIL_BYTES && !email.chars().any(char::is_control)
}

/// What reopens a signed-in session without a password or code (task T240): the person's email and the session token
/// the server returned. The server accepts it only from the same device, within 12 hours of the sign-in. Wiped from
/// memory when dropped; `Debug` shows neither field.
#[derive(Clone, PartialEq, Eq)]
pub struct ResumeTicket {
    email: String,
    token: Zeroizing<String>,
}

impl ResumeTicket {
    /// `None` unless the email is valid for a sign-in and the token has the form the server issues.
    pub fn new(email: &str, token: &str) -> Option<Self> {
        let email_ok = !email.is_empty() && email.len() <= MAX_EMAIL_BYTES && !email.chars().any(char::is_control);
        let token_ok = token.len() == TOKEN_LEN && token.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
        (email_ok && token_ok).then(|| Self { email: email.to_owned(), token: Zeroizing::new(token.to_owned()) })
    }

    pub fn email(&self) -> &str {
        &self.email
    }

    /// The session token: a secret, to be stored only where the device record is.
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl fmt::Debug for ResumeTicket {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("ResumeTicket { .. }")
    }
}

pub(crate) fn valid_room(room: &str) -> bool {
    !room.is_empty() && room.len() <= MAX_NAME && room.chars().all(|ch| !ch.is_control() && !ch.is_whitespace())
}

/// Sign in over a verified device connection and negotiate the chat protocol, all within one operation deadline. The
/// client offers `FEATURE_LIST_ROOMS`; a server that does not agree to it is still used, without the room list.
pub(crate) fn sign_in(stream: Transport, credentials: &SignIn<'_>, client: &str) -> Result<SignedInSession, LabError> {
    let hello = Hello { min_version: 1, max_version: 1, features: FEATURE_LIST_ROOMS | FEATURE_SEARCH | FEATURE_FILES | FEATURE_THREADS, client: client.into() };
    let settings = Settings::new(credentials.email);
    let set_deadline: SetDeadline = |stream, deadline| stream.get_mut().set_deadline(deadline);
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    let chat = ChatSession::connect(stream, set_deadline, credentials, hello, settings, FRAME_TIMEOUT, deadline).map_err(LabError::Chat)?;
    Ok(SignedInSession { chat, email: credentials.email.to_owned() })
}

/// As `sign_in`, reopening the session `ticket` names instead (task T240). A ticket the server no longer accepts is
/// `LabError::Chat(ChatError::SignInRefused)`.
pub(crate) fn resume(stream: Transport, ticket: &ResumeTicket, client: &str) -> Result<SignedInSession, LabError> {
    let hello = Hello { min_version: 1, max_version: 1, features: FEATURE_LIST_ROOMS | FEATURE_SEARCH | FEATURE_FILES | FEATURE_THREADS, client: client.into() };
    let settings = Settings::new(ticket.email());
    let set_deadline: SetDeadline = |stream, deadline| stream.get_mut().set_deadline(deadline);
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    let chat = ChatSession::resume(stream, set_deadline, ticket.email(), ticket.token(), hello, settings, FRAME_TIMEOUT, deadline)
        .map_err(LabError::Chat)?;
    Ok(SignedInSession { chat, email: ticket.email().to_owned() })
}

/// Begin an external sign-in over a fresh device connection (task T611g). `None` when the server offers none.
pub(crate) fn begin_external(mut stream: Transport) -> Result<Option<crate::chat_session::ExternalStart>, LabError> {
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    crate::chat_session::begin_external(&mut stream, |stream: &mut Transport, deadline| stream.get_mut().set_deadline(deadline), deadline)
        .map_err(LabError::Chat)
}

/// Finish an external sign-in over a fresh device connection and negotiate the chat protocol (task T611g). `email` is
/// the person this device is enrolled for.
pub(crate) fn finish_external(
    stream: Transport,
    email: &str,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
    client: &str,
) -> Result<SignedInSession, LabError> {
    let hello = Hello { min_version: 1, max_version: 1, features: FEATURE_LIST_ROOMS | FEATURE_SEARCH | FEATURE_FILES | FEATURE_THREADS, client: client.into() };
    let settings = Settings::new(email);
    let set_deadline: SetDeadline = |stream, deadline| stream.get_mut().set_deadline(deadline);
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    let chat = ChatSession::finish_external(stream, set_deadline, email, code, verifier, redirect_uri, hello, settings, FRAME_TIMEOUT, deadline)
        .map_err(LabError::Chat)?;
    Ok(SignedInSession { chat, email: email.to_owned() })
}

/// Ask the server to end the session `ticket` names (task T240), over a fresh device connection.
pub(crate) fn end(mut stream: Transport, ticket: &ResumeTicket) -> Result<(), LabError> {
    let deadline = Instant::now() + OPERATION_TIMEOUT;
    crate::chat_session::end_session(
        &mut stream,
        |stream: &mut Transport, deadline| stream.get_mut().set_deadline(deadline),
        ticket.token(),
        deadline,
    )
    .map_err(LabError::Chat)
}

/// An authenticated connection. Dropping it ends the local session. Commands use the same connection and the same
/// room views until the connection closes.
pub struct SignedInSession {
    chat: ChatSession<Transport, SetDeadline>,
    email: String,
}

impl SignedInSession {
    /// The ticket that reopens this session later from this device without a new code (task T240).
    pub fn resume_ticket(&self) -> Option<ResumeTicket> {
        ResumeTicket::new(&self.email, self.chat.token())
    }

    /// `text` comes from the caller's protected input and is sent only on this connection.
    pub fn post(&mut self, room: &str, text: &str) -> Result<u64, LabError> {
        if !valid_room(room) {
            return Err(LabError::Usage);
        }
        self.chat.post(room, text, 0, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Upload the file at `path` to `room` under its own name (task T330e): hash it, then send it in `MAX_CHUNK`
    /// chunks, calling `progress(sent, size)` after each. Returns the uploaded file.
    pub fn upload(&mut self, room: &str, path: &Path, progress: &mut dyn FnMut(u64, u64)) -> Result<Uploaded, FileOpError> {
        if !valid_room(room) {
            return Err(FileOpError::Lab(LabError::Usage));
        }
        let name = path.file_name().and_then(|name| name.to_str()).map(str::to_owned).ok_or(FileOpError::Local(io::ErrorKind::InvalidInput))?;
        let local = |error: io::Error| FileOpError::Local(error.kind());
        let size = std::fs::metadata(path).map_err(local)?.len();
        let mut hasher = Sha256::new();
        let mut file = File::open(path).map_err(local)?;
        let mut buffer = vec![0u8; MAX_CHUNK];
        loop {
            let n = file.read(&mut buffer).map_err(local)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        let sha256: [u8; 32] = hasher.finalize().into();
        let lab = |error: ChatError| FileOpError::Lab(LabError::Chat(error));
        let upload = self.chat.upload_begin(room, &name, size, sha256, 0, Instant::now() + OPERATION_TIMEOUT).map_err(lab)?;
        let mut file = File::open(path).map_err(local)?;
        let mut offset = 0u64;
        loop {
            let n = file.read(&mut buffer).map_err(local)?;
            if n == 0 {
                break;
            }
            self.chat.upload_chunk(upload, offset, buffer[..n].to_vec(), 0, Instant::now() + OPERATION_TIMEOUT).map_err(lab)?;
            offset += n as u64;
            progress(offset, size);
        }
        let file = self.chat.upload_finish(upload, 0, Instant::now() + OPERATION_TIMEOUT).map_err(lab)?;
        Ok(Uploaded { file, name, size })
    }

    /// Post `text` with `files` to `room` (task T330e). `text` may be empty.
    pub fn post_files(&mut self, room: &str, text: &str, files: Vec<[u8; 16]>) -> Result<u64, LabError> {
        if !valid_room(room) || files.is_empty() {
            return Err(LabError::Usage);
        }
        self.chat.post_files(room, text, files, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Download file `file` (`size` bytes) to a new file at `to` (task T330e). `to` must not exist; a failed download
    /// removes what it wrote.
    pub fn download_to(&mut self, file: [u8; 16], size: u64, to: &Path) -> Result<(), FileOpError> {
        let local = |error: io::Error| FileOpError::Local(error.kind());
        let mut out = OpenOptions::new().write(true).create_new(true).open(to).map_err(local)?;
        let result = (|| {
            let mut offset = 0u64;
            while offset < size {
                let length = u32::try_from((size - offset).min(MAX_CHUNK as u64)).unwrap_or(MAX_CHUNK as u32);
                let data = self
                    .chat
                    .download(file, offset, length, 0, Instant::now() + OPERATION_TIMEOUT)
                    .map_err(|e| FileOpError::Lab(LabError::Chat(e)))?;
                if data.is_empty() {
                    return Err(FileOpError::Lab(LabError::Chat(ChatError::UnexpectedResponse)));
                }
                out.write_all(&data).map_err(local)?;
                offset += data.len() as u64;
            }
            out.sync_all().map_err(local)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(to);
        }
        result
    }

    /// Reply to the message at `parent` in `room`, in its thread (task T340b).
    pub fn reply(&mut self, room: &str, parent: u64, text: &str) -> Result<u64, LabError> {
        if !valid_room(room) || parent == 0 {
            return Err(LabError::Usage);
        }
        self.chat.reply(room, parent, text, 0, Instant::now() + OPERATION_TIMEOUT).map_err(LabError::Chat)
    }

    /// Each reply's parent in `room`, by the reply's cursor, as the server pushed them (task T340b).
    pub fn parents(&mut self, room: &str) -> BTreeMap<u64, u64> {
        self.chat.view(room).map(|view| view.parents().clone()).unwrap_or_default()
    }

    /// The files each message in `room` carries, as the server pushed them (task T330e).
    pub fn attachments(&mut self, room: &str) -> BTreeMap<u64, Vec<AttachedFile>> {
        self.chat.view(room).map(|view| view.attachments().clone()).unwrap_or_default()
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

    /// The messages the person can read that match `query`, newest first (task T320c). `None` when the server did not
    /// agree to `FEATURE_SEARCH` (nothing is sent then). `query` must be 1 to `request::MAX_QUERY` bytes.
    pub fn search(&mut self, query: &str) -> Result<Option<Vec<SearchHit>>, LabError> {
        if query.is_empty() || query.len() > crewcraft_proto::request::MAX_QUERY {
            return Err(LabError::Usage);
        }
        if !self.chat.searches() {
            return Ok(None);
        }
        self.chat.search(query, 0, Instant::now() + OPERATION_TIMEOUT).map(Some).map_err(LabError::Chat)
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
