//! The local control channel: `invite`, `room` and `add-member` while `serve` runs (Unix). Task T238.
//!
//! Owns: the control socket in the data directory (`control.sock`): creating it owner-only, replacing one a crash left
//! behind, removing it when serving stops; the small framed request/response format spoken over it; and applying a
//! request to the running server's live account store and room journal, under the same locks the device sessions use,
//! so a change is durable and visible to clients at once. Also the command's side: finding a server that answers, and
//! sending it a request.
//! Does not own: what the commands do (`lab_admin::invite`, `DurableServer`), how an invitation is shown or written
//! (`main`), the state directory lock (`lab_state`).
//!
//! Who may connect: only the account the server runs as (and the superuser, who can read the data directory anyway).
//! The data directory must be private (0700; `LabState::open` refuses anything else), the socket is created inside it
//! and made 0600, and the socket must belong to the directory's owner. Connecting needs search permission on the
//! directory and write permission on the socket, so the kernel refuses every other account before a byte is read. The
//! standard library has no stable way to read the peer's credentials, so the server does not check them itself: the
//! file permissions are the whole gate.
//!
//! Wire format, both ways: `frame = length:u32 (big-endian, 1..=MAX_FRAME) payload`, and
//! `payload = count:u8 (1..=MAX_FIELDS), then count times (length:u16 big-endian, UTF-8 bytes)`. A request's first
//! field is `VERSION`. One exchange per connection, inside `EXCHANGE_TIMEOUT`:
//!
//! - `[VERSION, "room", owner, name]` is answered `["ok", slug]`;
//! - `[VERSION, "add-member", room, owner, member]` is answered `["ok"]`;
//! - `[VERSION, "invite", email]` is answered `["code", email, code]`; the command shows or writes the code and
//!   answers `["shown"]` (anything else, or silence, withdraws the invitation, as a failed display does offline),
//!   and the server ends with `["ok"]`.
//!
//! Any request the server cannot carry out is answered `["error", text]`, with the text the offline command prints.
//!
//! Secrets: an invitation's code is sent once, from the server to the command, over this owner-only socket. Nothing
//! here prints or logs it, or any request.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use crewcraft_accounts::identity::normalize_email;
use crewcraft_server_core::account_store::AccountStore;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_server_core::room::Role;

use crate::lab_admin::{self, AdminError, DisplayFailed, IssuedCode, ProtectedDisplay};

/// The control socket's name in the data directory.
pub const SOCKET_FILE: &str = "control.sock";
/// The first field of every request. A server refuses another version rather than guessing at it.
pub const VERSION: &str = "crewcraft-control 1";
/// The largest payload either side sends or accepts.
pub const MAX_FRAME: usize = 4096;
/// The most fields in one message.
pub const MAX_FIELDS: usize = 8;
/// One absolute budget for a whole exchange, on the server.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
/// The command's budget: the server's, plus a moment to show the invitation and hear the server's last word.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const IDLE_POLL: Duration = Duration::from_millis(20);

/// The server listening on its data directory's control socket. Dropping it removes the socket file, if it is still
/// the one this server made.
pub struct ControlSocket {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
}

impl ControlSocket {
    /// Listen on `<data>/control.sock`, owner-only. Call it while holding the data directory (the running server's
    /// `LabState`), so no other server can be using it. A socket left by a server that crashed is replaced once a
    /// connection to it is refused; a socket that answers, or anything at that path that is not a socket, is left
    /// alone and refused.
    pub fn bind(data: &Path) -> io::Result<Self> {
        let folder = fs::symlink_metadata(data)?;
        if !folder.is_dir() || folder.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the data directory must be a private directory"));
        }
        let path = data.join(SOCKET_FILE);
        match fs::symlink_metadata(&path) {
            Ok(existing) if existing.file_type().is_socket() => match UnixStream::connect(&path) {
                Ok(_) => return Err(io::Error::new(io::ErrorKind::AddrInUse, "another process answers on the control socket")),
                // Nothing listens: left behind by a server that did not stop cleanly.
                Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => fs::remove_file(&path)?,
                Err(error) => return Err(error),
            },
            Ok(_) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, "something that is not a socket is where the control socket goes")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let listener = UnixListener::bind(&path)?;
        let created = fs::symlink_metadata(&path)?;
        // From here on, dropping `socket` removes the file again.
        let socket = Self { listener, path, identity: (created.dev(), created.ino()) };
        // The directory already keeps every other account out; the socket's own mode does too.
        fs::set_permissions(&socket.path, fs::Permissions::from_mode(0o600))?;
        if created.uid() != folder.uid() {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the data directory belongs to another account"));
        }
        socket.listener.set_nonblocking(true)?;
        Ok(socket)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Answer requests one at a time until `stopped` says so, then remove the socket. Each request runs under the lock
    /// of the store it changes (the same locks as the device sessions), and nothing waits on the peer while holding one.
    pub fn serve(self, stopped: &dyn Fn() -> bool, accounts: &Mutex<AccountStore>, rooms: &Mutex<DurableServer>, now_ms: &dyn Fn() -> u64) {
        while !stopped() {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    let _ = answer(stream, accounts, rooms, now_ms);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(IDLE_POLL),
                Err(error) if matches!(error.kind(), io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted) => {}
                // Out of descriptors or similar: keep serving chat, and try again shortly.
                Err(_) => thread::sleep(IDLE_POLL),
            }
        }
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        let ours = fs::symlink_metadata(&self.path).is_ok_and(|now| (now.dev(), now.ino()) == self.identity);
        if ours {
            let _ = fs::remove_file(&self.path);
        }
    }
}

const STORE_UNAVAILABLE: &str = "the running server's state is unavailable; restart it";

fn answer(stream: UnixStream, accounts: &Mutex<AccountStore>, rooms: &Mutex<DurableServer>, now_ms: &dyn Fn() -> u64) -> io::Result<()> {
    // An accepted socket may inherit the listener's non-blocking mode.
    stream.set_nonblocking(false)?;
    let mut peer = Deadlined { stream, deadline: Instant::now() + EXCHANGE_TIMEOUT };
    let request = read_message(&mut peer)?;
    let fields: Vec<&str> = request.iter().map(String::as_str).collect();
    let outcome = match fields.as_slice() {
        [VERSION, "invite", email] => return invite(&mut peer, accounts, email, now_ms()),
        [VERSION, "room", owner, name] => {
            rooms_change(rooms, |rooms| rooms.create_room(&canonical(owner)?, name).map_err(debug_text)).map(|slug| vec!["ok".to_owned(), slug])
        }
        [VERSION, "add-member", room, owner, member] => {
            rooms_change(rooms, |rooms| rooms.add_member(room, &canonical(owner)?, &canonical(member)?, Role::Member).map_err(debug_text))
                .map(|_| vec!["ok".to_owned()])
        }
        [version, ..] if *version != VERSION => Err("the running server speaks another control version; use the crewcraft-server it runs".to_owned()),
        _ => Err("the running server does not know that request".to_owned()),
    };
    match outcome {
        Ok(reply) => write_message(&mut peer, &reply.iter().map(String::as_str).collect::<Vec<_>>()),
        Err(text) => write_message(&mut peer, &["error", &text]),
    }
}

fn rooms_change<T>(rooms: &Mutex<DurableServer>, change: impl FnOnce(&mut DurableServer) -> Result<T, String>) -> Result<T, String> {
    let mut rooms = rooms.lock().map_err(|_| STORE_UNAVAILABLE.to_owned())?;
    change(&mut rooms)
}

/// The command canonicalises addresses before it sends them; the server does again rather than trust that.
fn canonical(email: &str) -> Result<String, String> {
    normalize_email(email).map_err(debug_text)
}

/// The offline commands print a refusal's `Debug` form; the server sends the same text.
fn debug_text(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}

/// Takes the issued code out of `lab_admin::invite`, so the store's lock is not held while the peer is waited on.
struct Captured(Option<(String, String)>);

impl ProtectedDisplay for Captured {
    fn show(&mut self, issued: &IssuedCode<'_>) -> Result<(), DisplayFailed> {
        self.0 = Some((issued.email().to_owned(), issued.code().to_owned()));
        Ok(())
    }
}

fn invite(peer: &mut Deadlined, accounts: &Mutex<AccountStore>, email: &str, now_ms: u64) -> io::Result<()> {
    let mut captured = Captured(None);
    let issued = match accounts.lock() {
        Ok(mut accounts) => lab_admin::invite(&mut accounts, email, None, now_ms, &mut captured).map_err(debug_text),
        Err(_) => Err(STORE_UNAVAILABLE.to_owned()),
    };
    let receipt = match issued {
        Ok(receipt) => receipt,
        Err(text) => return write_message(peer, &["error", &text]),
    };
    let shown = match captured.0.take() {
        Some((email, code)) => {
            write_message(peer, &["code", &email, &code]).and_then(|()| read_message(peer)).is_ok_and(|answer| answer == ["shown"])
        }
        None => false,
    };
    if shown {
        return write_message(peer, &["ok"]);
    }
    // Nobody saw the code: take the invitation back, as the offline command does when its display fails.
    let withdrawn = accounts.lock().is_ok_and(|mut accounts| matches!(accounts.revoke_invite(&receipt.bootstrap_pub), Ok(true)));
    write_message(peer, &["error", &debug_text(AdminError::DisplayFailed { withdrawn })])
}

/// A command's connection to the server running on a data directory.
pub struct ControlClient(Deadlined);

impl ControlClient {
    /// Connect to the server running on `data`, or `None` when none answers there (the command then opens the
    /// directory itself, as it does with no server running). Only a private directory, and a socket that belongs to
    /// the directory's owner, is trusted.
    pub fn connect(data: &Path) -> Option<Self> {
        let folder = fs::symlink_metadata(data).ok()?;
        if !folder.is_dir() || folder.permissions().mode() & 0o077 != 0 {
            return None;
        }
        let path = data.join(SOCKET_FILE);
        let socket = fs::symlink_metadata(&path).ok()?;
        if !socket.file_type().is_socket() || socket.uid() != folder.uid() {
            return None;
        }
        let stream = UnixStream::connect(&path).ok()?;
        Some(Self(Deadlined { stream, deadline: Instant::now() + COMMAND_TIMEOUT }))
    }

    /// Create a room owned by `owner` (a canonical address) and return its name, as `room` prints it.
    pub fn create_room(mut self, owner: &str, name: &str) -> io::Result<String> {
        write_message(&mut self.0, &[VERSION, "room", owner, name])?;
        let reply = read_message(&mut self.0)?;
        match reply.as_slice() {
            [ok, slug] if ok == "ok" => Ok(slug.clone()),
            other => Err(refused(other)),
        }
    }

    /// Add `member` to `room` on behalf of `owner` (canonical addresses).
    pub fn add_member(mut self, room: &str, owner: &str, member: &str) -> io::Result<()> {
        write_message(&mut self.0, &[VERSION, "add-member", room, owner, member])?;
        finished(read_message(&mut self.0)?)
    }

    /// Invite `email`. The server records the invitation, then sends its code to `show` (with the canonical address);
    /// `show` returns whether the code was shown. If it was not, the server withdraws the invitation and the error
    /// says so, as offline.
    pub fn invite(mut self, email: &str, show: impl FnOnce(&str, &str) -> bool) -> io::Result<()> {
        write_message(&mut self.0, &[VERSION, "invite", email])?;
        let reply = read_message(&mut self.0)?;
        let shown = match reply.as_slice() {
            [tag, email, code] if tag == "code" => show(email, code),
            other => return Err(refused(other)),
        };
        drop(reply);
        let confirmed = write_message(&mut self.0, &[if shown { "shown" } else { "not shown" }]).and_then(|()| read_message(&mut self.0));
        match confirmed {
            Ok(last) => finished(last),
            Err(_) if shown => {
                Err(io::Error::other("the running server did not confirm the invitation, so it may have been withdrawn; invite again"))
            }
            Err(error) => Err(error),
        }
    }
}

fn finished(reply: Vec<String>) -> io::Result<()> {
    match reply.as_slice() {
        [ok] if ok == "ok" => Ok(()),
        other => Err(refused(other)),
    }
}

fn refused(reply: &[String]) -> io::Error {
    match reply {
        [tag, text] if tag == "error" => io::Error::other(text.clone()),
        _ => invalid("the running server sent an unexpected control reply"),
    }
}

/// A stream whose every read and write must finish before one absolute deadline.
struct Deadlined {
    stream: UnixStream,
    deadline: Instant,
}

impl Deadlined {
    fn remaining(&self) -> io::Result<Duration> {
        match self.deadline.checked_duration_since(Instant::now()) {
            Some(left) if !left.is_zero() => Ok(left),
            _ => Err(io::ErrorKind::TimedOut.into()),
        }
    }
}

impl Read for Deadlined {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.remaining()?;
        self.stream.set_read_timeout(Some(left))?;
        self.stream.read(buf)
    }
}

impl Write for Deadlined {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let left = self.remaining()?;
        self.stream.set_write_timeout(Some(left))?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// A message's payload, without its length prefix. Refuses no fields, too many, a field over 65535 bytes, or a
/// payload over `MAX_FRAME`.
pub fn encode(fields: &[&str]) -> io::Result<Vec<u8>> {
    let count = u8::try_from(fields.len()).ok().filter(|count| *count != 0 && usize::from(*count) <= MAX_FIELDS);
    let count = count.ok_or_else(|| invalid("a control message has between 1 and 8 fields"))?;
    let mut payload = vec![count];
    for field in fields {
        let length = u16::try_from(field.len()).map_err(|_| invalid("a control message field is too long"))?;
        payload.extend_from_slice(&length.to_be_bytes());
        payload.extend_from_slice(field.as_bytes());
    }
    if payload.len() > MAX_FRAME {
        return Err(invalid("a control message is too long"));
    }
    Ok(payload)
}

/// The fields of a payload `encode` made. Anything else is refused: a wrong count, a field running past the end,
/// bytes left over, or text that is not UTF-8.
pub fn decode(payload: &[u8]) -> io::Result<Vec<String>> {
    let malformed = || invalid("a control message is malformed");
    if payload.len() > MAX_FRAME {
        return Err(invalid("a control message is too long"));
    }
    let (&count, mut rest) = payload.split_first().ok_or_else(malformed)?;
    if count == 0 || usize::from(count) > MAX_FIELDS {
        return Err(malformed());
    }
    let mut fields = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let (length, after) = rest.split_first_chunk::<2>().ok_or_else(malformed)?;
        let (field, after) = after.split_at_checked(usize::from(u16::from_be_bytes(*length))).ok_or_else(malformed)?;
        fields.push(String::from_utf8(field.to_vec()).map_err(|_| malformed())?);
        rest = after;
    }
    if !rest.is_empty() {
        return Err(malformed());
    }
    Ok(fields)
}

fn write_message(out: &mut impl Write, fields: &[&str]) -> io::Result<()> {
    let payload = encode(fields)?;
    let length = u32::try_from(payload.len()).map_err(|_| invalid("a control message is too long"))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&payload);
    out.write_all(&frame)?;
    out.flush()
}

fn read_message(input: &mut impl Read) -> io::Result<Vec<String>> {
    let mut length = [0; 4];
    input.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| invalid("a control message is too long"))?;
    if length == 0 || length > MAX_FRAME {
        return Err(invalid("a control message is empty or too long"));
    }
    let mut payload = vec![0; length];
    input.read_exact(&mut payload)?;
    decode(&payload)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
