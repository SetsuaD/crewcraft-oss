//! The connection worker: the chat session on its own thread, so the window never waits on the network. Task T303.
//!
//! Owns: the thread, the one signed-in session, which rooms are followed and which is open, polling them, unread
//! counts, and finding the server again after the connection is lost. Called by the window: it sends sign-ins and
//! `crewcraft_ui_model::Command`s through `Worker`'s methods and reads `Event`s from the channel `Worker::start`
//! returns. Calls `server_endpoint` and `signed_in`.
//!
//! Every sign-in needs a fresh authenticator code, so the worker cannot sign in again by itself. What it can do is
//! resume (task T240): a sign-in returns a resume ticket, which the worker keeps (and hands to its `TicketKeeper` to
//! keep between runs), and which reopens the same session from this device without a code for up to 12 hours. After a
//! lost connection it reports `Failed`, retries the mutual TLS connection with exponential backoff and, holding a
//! ticket, resumes and reports `SignedIn` again; the window stays where it was. Without a ticket, or when the server
//! refuses it (`SessionEnded`), it reports `Disconnected`, then `Connected` once the server answers; the window then
//! asks for a new code and calls `sign_in`. Signing out asks the server to end the session and forgets the ticket.
//!
//! Live updates: the server answers requests and does not push between them, so the worker polls each followed room
//! every `WorkerConfig::poll_interval`.
//!
//! The person's rooms: right after a sign-in the worker asks the server which rooms the person is a member of
//! (`ListRooms`, task T233) and follows exactly those, so `Event::SignedIn` lists them and each gets an unread count.
//! A server too old to list rooms is still used: the worker then keeps the rooms it already followed.
//!
//! Sign-in through an organization's identity provider (task T611h): `sign_in_external` runs `external_flow` on this
//! thread. The provider's page opens in the system browser (`Event::WaitingForBrowser`); the wait for it ends when the
//! browser comes back, on `cancel_sign_in`, at `external_flow::BROWSER_TIMEOUT`, or when the worker is dropped. The
//! session it opens is kept and resumed exactly like one from a password sign-in.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crewcraft_client_core::room_view::{GapNotice, PinnedMessage, ReadState, Shown};
use crewcraft_proto::activity::{ActivityFilter, ActivitySnapshot};
use crewcraft_ui_model::Command;
use rand_core::{OsRng, RngCore};
use rustls::client::ResolvesClientCert;

use crate::chat_session::{ChatError, ExternalStart};
use crate::connect::{Connection, interrupt};
use crate::external_flow::{BROWSER_TIMEOUT, ExternalServer, FlowError, run_unless};
use crate::lab_client::LabError;
use crate::loopback::LoopbackError;
use crate::server_endpoint::ServerEndpoint;
use crate::signed_in::{Credentials, MeetingSave, ResumeTicket, SignedInSession, valid_room};

/// The most rooms one worker follows (and polls).
pub const MAX_FOLLOWED: usize = 64;

/// Opens a URL (the provider's https sign-in page) in the system browser (task T611h): `loopback::open_browser`, or a
/// test's or a phone's own.
pub type Browser = Arc<dyn Fn(&str) -> io::Result<()> + Send + Sync>;

/// A room's open call and its call history lines by cursor (task T360a2).
type RoomCalls = (Option<crewcraft_client_core::room_view::OpenCall>, Vec<(u64, String)>);

/// How often a call heartbeat is sent (REQUIREMENTS 2.5).
pub const CALL_HEARTBEAT: Duration = Duration::from_secs(20);

/// How often the worker polls, and how it backs off while the server cannot be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerConfig {
    /// Time between polls of the followed rooms while signed in.
    pub poll_interval: Duration,
    /// Wait before the first reconnection attempt; it doubles after each failure.
    pub first_retry: Duration,
    /// The longest wait between reconnection attempts.
    pub max_retry: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self { poll_interval: Duration::from_secs(2), first_retry: Duration::from_secs(1), max_retry: Duration::from_secs(60) }
    }
}

/// What the worker tells the window. No variant carries a password, code, token or key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Mutual TLS with the server succeeded: during a sign-in, or when the server answers again after a lost
    /// connection (then sign in again with a fresh code).
    Connected,
    /// The sign-in was accepted for `email`. `rooms` are the rooms the person is a member of, as the server listed
    /// them (at most `MAX_FOLLOWED`), sorted; they are followed, synced and polled from now on. From a server too old
    /// to list rooms, `rooms` are the rooms this worker already follows (opened or posted to earlier).
    SignedIn {
        email: String,
        rooms: Vec<String>,
    },
    Activity {
        filter: ActivityFilter,
        snapshot: ActivitySnapshot,
    },
    ActivityFailed {
        problem: Problem,
        refresh: bool,
    },
    ActivityReset,
    /// The open room as it is drawn now. Sent when the room is opened and whenever it changes.
    Room {
        room: String,
        shown: Vec<Shown>,
    },
    /// An atomic recovered window replaced this room's side metadata, including empty lists (T345).
    Recovered {
        room: String,
    },
    Gap {
        room: String,
        notice: GapNotice,
    },
    /// A followed room's count. With personal read-state support, a remote rewind can leave an open room unread.
    Unread {
        room: String,
        count: u32,
    },
    /// Authoritative personal state, including a rewind made on another device (T344).
    ReadState {
        room: String,
        state: ReadState,
    },
    /// The confirmed unread action leaves its room's conversation without clearing the count (T344).
    MarkedUnread {
        room: String,
    },
    /// The server acknowledged a post at `cursor`.
    Posted {
        room: String,
        cursor: u64,
    },
    /// The server accepted an edit or a deletion, recorded at `cursor` (task T316). The room's next snapshot shows it.
    Changed {
        room: String,
        cursor: u64,
    },
    /// What a search for `query` found, newest first (task T320c).
    SearchResults {
        query: String,
        hits: Vec<Found>,
    },
    /// A file uploaded to `room`, ready to attach to the next post there (task T330e).
    Uploaded {
        room: String,
        file: [u8; 16],
        name: String,
        size: u64,
    },
    /// The files each message of `room` carries, by cursor, whenever they change (task T330e).
    Attachments {
        room: String,
        files: Vec<(u64, Vec<crewcraft_proto::push::AttachedFile>)>,
    },
    /// A file was saved at `path` (task T330e).
    Saved {
        path: std::path::PathBuf,
    },
    /// Each reply's parent in `room`, by the reply's cursor, whenever they change (task T340b).
    Threads {
        room: String,
        parents: Vec<(u64, u64)>,
    },
    /// `room` is an archive room, with its imported messages' original times by cursor (task T350d2).
    Archive {
        room: String,
        times: Vec<(u64, u64)>,
    },
    /// The archive room `archive` continues in `room`, which is followed from now on (task T352).
    Continued {
        archive: String,
        room: String,
    },
    /// The lines in `room` that link back to the archives it continues, `(cursor, archive, text)`, whenever they
    /// change (task T352).
    Continuations {
        room: String,
        lines: Vec<(u64, String, String)>,
    },
    /// The calendar's work week (task T370b): its UTC window, when the worker read it, and the meetings in my rooms
    /// that overlap it, cancelled ones included; `more` when the server had more than it sent.
    Meetings {
        from_ms: u64,
        to_ms: u64,
        now_ms: u64,
        meetings: Vec<crewcraft_proto::meeting::Meeting>,
        more: bool,
    },
    /// A meeting was saved, scheduled or edited (task T370b).
    MeetingSaved {
        meeting: crewcraft_proto::meeting::Meeting,
    },
    /// Saving or cancelling meeting `meeting` (0: a new one) was refused; `conflict` when someone changed it since it
    /// was read (task T370b). Nothing was resent.
    MeetingRefused {
        meeting: u64,
        conflict: bool,
        reason: String,
    },
    /// The files in the person's rooms, newest message first (task T331b).
    Files {
        files: Vec<crewcraft_proto::request::ListedFile>,
    },
    /// The bytes the person's files take, and their quota (task T332b).
    Storage {
        used: u64,
        quota: u64,
    },
    /// An image file's bytes for its preview (task T333); empty when it could not be fetched.
    Preview {
        file: [u8; 16],
        bytes: Vec<u8>,
    },
    /// `room`'s open call (or none) and its call history lines by cursor, whenever they change (task T360a2).
    Calls {
        room: String,
        open: Option<crewcraft_client_core::room_view::OpenCall>,
        lines: Vec<(u64, String)>,
    },
    /// This app is now in call `call` of `room` (task T360a2).
    InCall {
        room: String,
        call: u64,
    },
    /// This app's call in `room` is end-to-end encrypted: it sends under key id `kid`, and the sender keys of `from` have
    /// reached it (task T360d3).
    CallSecurity {
        room: String,
        call: u64,
        kid: u64,
        from: Vec<String>,
    },
    /// This app left its call in `room`; `reason` says why when it did not choose to (task T360a2).
    LeftCall {
        room: String,
        reason: Option<String>,
    },
    /// Who reacted to each message in `room` with what, whenever it changes (task T341b).
    Reactions {
        room: String,
        reactions: crewcraft_ui_model::RoomReactions,
    },
    /// The person's own settings for a room (pinned, muted, hidden), at sign-in and whenever they change, including a
    /// change made on another of the person's devices (T346).
    RoomSettings {
        room: String,
        settings: crewcraft_proto::room_settings::RoomSettings,
    },
    /// The authoritative room pin, including a body outside the current history page (T343).
    Pin {
        room: String,
        pinned: Option<PinnedMessage>,
    },
    /// The person's readable saved messages in their current state (T343).
    SavedMessages {
        messages: Vec<crewcraft_proto::request::SavedMessage>,
    },
    /// A post that was not acknowledged; `text` is returned so the window can restore the draft. After
    /// `Problem::Lost` the post may still have arrived: the room's next snapshot shows it if so.
    PostFailed {
        room: String,
        text: String,
        problem: Problem,
    },
    /// Something the window can show. See `Problem`.
    Failed(Problem),
    /// The signed-in session ended (lost, or signed out).
    Disconnected,
    /// The server no longer accepts the resume ticket (more than 12 hours since the sign-in, signed out elsewhere, or
    /// the device was revoked): sign in again with a new code (task T240).
    SessionEnded,
    /// An external sign-in opened the provider's page in the browser and waits for the person there (task T611h).
    WaitingForBrowser,
}

/// One message a search found (task T320c): its room, its cursor, its author and the start of its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub room: String,
    pub cursor: u64,
    pub author: String,
    pub snippet: String,
}

/// Where the worker keeps its session's resume ticket between runs (task T240). The app keeps it next to the device
/// record; `Worker::start` keeps it in memory only.
pub trait TicketKeeper: Send {
    /// The ticket saved by an earlier run, if any.
    fn load(&self) -> Option<ResumeTicket>;
    /// Keep `ticket`, replacing any earlier one.
    fn save(&self, ticket: &ResumeTicket);
    /// Forget the ticket.
    fn clear(&self);
}

/// Keeps nothing between runs.
struct MemoryOnly;

impl TicketKeeper for MemoryOnly {
    fn load(&self) -> Option<ResumeTicket> {
        None
    }

    fn save(&self, _: &ResumeTicket) {}

    fn clear(&self) {}
}

/// Why something did not work, without detail that could identify a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// The command needs a signed-in session.
    NotSignedIn,
    /// The room name is empty, too long, or contains spaces or control characters.
    InvalidRoom,
    /// The worker already follows `MAX_FOLLOWED` rooms.
    TooManyRooms,
    /// The request could not be encoded, for example a message too long for the protocol.
    InvalidRequest,
    /// The server could not be reached (the address did not resolve or the connection failed).
    Unreachable(io::ErrorKind),
    /// The TLS handshake failed: the server's certificate is not the pinned one, or the server refused this device.
    Handshake,
    /// The stored device identity is unusable.
    Device,
    /// Email, password or code not accepted. Ask for a fresh code.
    SignInRefused,
    /// The server refused one request with this status (for example 404 for a room the person is not in).
    Refused(u16),
    /// The connection failed or closed.
    Lost(io::ErrorKind),
    /// The server's reply did not follow the protocol; the connection was closed.
    Protocol,
    /// The server does not offer sign-in through an organization's identity provider (task T611h).
    ExternalNotOffered,
    /// The server did not accept the organization's sign-in for this device's person.
    ExternalRefused,
    /// The system browser could not be opened at the sign-in page.
    Browser,
    /// The app could not listen on this computer for the browser to come back.
    NoRedirect,
    /// The sign-in was not finished in the browser in time.
    BrowserTimedOut,
    /// The organization's sign-in page ended the sign-in without signing in (the person declined, for example).
    ProviderRefused,
    /// The person cancelled the sign-in.
    Cancelled,
    /// The server does not offer message search (task T320c).
    SearchNotOffered,
    /// The server does not keep files (task T330e).
    FilesNotOffered,
    /// The server did not negotiate pins and saved messages (T343).
    PinsSavedNotOffered,
    /// The server supplied current pin metadata while its retained history could not replay this room (T343).
    HistoryGap,
    ReadStateNotOffered,
    /// The server does not offer continuing archived conversations (task T352).
    ContinueNotOffered,
    /// The server does not offer meetings (task T370b).
    MeetingsNotOffered,
    /// The server does not keep personal room settings (T346).
    RoomSettingsNotOffered,
    ActivityNotOffered,
    /// A file on this computer could not be read or written (task T330e).
    LocalFile(io::ErrorKind),
}

/// A short sentence for the window, with no detail about which credential failed.
impl std::fmt::Display for Problem {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(match self {
            Self::NotSignedIn => "Sign in first.",
            Self::InvalidRoom => "That room name is not valid.",
            Self::TooManyRooms => "Too many rooms are open.",
            Self::InvalidRequest => "That message cannot be sent.",
            Self::Unreachable(_) => "The server cannot be reached.",
            Self::Handshake => "The server's identity could not be verified, or it did not accept this device.",
            Self::Device => "This device's saved identity cannot be used. Enroll it again.",
            Self::SignInRefused => "Email, password or code not accepted. Wait for a new code and try again.",
            Self::Refused(404) => "That room was not found.",
            Self::Refused(_) => "The server refused that request.",
            Self::Lost(_) => "The connection to the server was lost.",
            Self::Protocol => "The server's reply could not be understood.",
            Self::ExternalNotOffered => "This server does not offer sign-in with your organization.",
            Self::ExternalRefused => "The server did not accept that sign-in: another person's account, or no access to this chat.",
            Self::Browser => "The browser could not be opened for the sign-in.",
            Self::NoRedirect => "CrewCraft could not wait for the sign-in to come back from the browser.",
            Self::BrowserTimedOut => "The sign-in in the browser was not finished in time. Try again.",
            Self::ProviderRefused => "The sign-in page did not sign you in. Try again.",
            Self::Cancelled => "Sign-in cancelled.",
            Self::SearchNotOffered => "This server does not offer message search.",
            Self::FilesNotOffered => "This server does not keep files.",
            Self::PinsSavedNotOffered => "This server does not offer pins and saved messages.",
            Self::HistoryGap => "Some earlier messages are outside the server's retained history.",
            Self::ReadStateNotOffered => "This server does not offer shared unread positions.",
            Self::ContinueNotOffered => "This server does not offer continuing archived conversations.",
            Self::MeetingsNotOffered => "This server does not offer meetings.",
            Self::RoomSettingsNotOffered => "This server does not keep pinned, muted or hidden rooms.",
            Self::ActivityNotOffered => "This server does not offer Activity.",
            Self::LocalFile(_) => "CrewCraft could not read or write that file on this computer.",
        })
    }
}

impl Problem {
    /// Whether the connection is gone after this problem.
    fn ends_session(self) -> bool {
        !matches!(
            self,
            Self::NotSignedIn
                | Self::InvalidRoom
                | Self::TooManyRooms
                | Self::InvalidRequest
                | Self::Refused(_)
                | Self::ExternalNotOffered
                | Self::Browser
                | Self::NoRedirect
                | Self::BrowserTimedOut
                | Self::ProviderRefused
                | Self::Cancelled
                | Self::SearchNotOffered
                | Self::FilesNotOffered
                | Self::PinsSavedNotOffered
                | Self::HistoryGap
                | Self::ReadStateNotOffered
                | Self::ContinueNotOffered
                | Self::MeetingsNotOffered
                | Self::RoomSettingsNotOffered
                | Self::ActivityNotOffered
                | Self::LocalFile(_)
        )
    }

    /// Whether trying the connection again later can help.
    fn retryable(self) -> bool {
        matches!(self, Self::Unreachable(_) | Self::Lost(_) | Self::Protocol)
    }
}

/// A stale meeting version (docs/MEETINGS.md "Wire": `E_CONFLICT`).
const E_CONFLICT: u16 = 13;

/// What to tell the person when the server refuses a meeting change with `code` (docs/MEETINGS.md "Wire").
fn meeting_refusal(code: u16) -> &'static str {
    match code {
        E_CONFLICT => "Someone changed this meeting since you opened it.",
        1 => "That room was not found.",
        3 => "This meeting can no longer be changed, or you may not change it.",
        4 => "Check the title, start, length and agenda: the meeting must not end in the past.",
        14 => "That meeting was not found.",
        _ => "The server refused that change.",
    }
}

/// The time now, Unix milliseconds (0 if the clock is before 1970).
fn wall_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}

fn problem(error: LabError) -> Problem {
    match error {
        LabError::Usage => Problem::InvalidRoom,
        LabError::Address => Problem::Unreachable(io::ErrorKind::NotFound),
        LabError::Connect(kind) => Problem::Unreachable(kind),
        LabError::Trust | LabError::Handshake => Problem::Handshake,
        LabError::Device => Problem::Device,
        LabError::Input | LabError::MissingTimeline => Problem::Protocol,
        LabError::Chat(error) => match error {
            ChatError::Io(kind) | ChatError::SyncIncomplete { reason: kind, .. } => Problem::Lost(kind),
            ChatError::Closed => Problem::Lost(io::ErrorKind::NotConnected),
            ChatError::SignInRefused => Problem::SignInRefused,
            ChatError::Request(_) => Problem::InvalidRequest,
            ChatError::Rejected(code) => Problem::Refused(code),
            ChatError::SignInProtocol
            | ChatError::HandshakeRefused
            | ChatError::Session(_)
            | ChatError::HistoryGap { .. }
            | ChatError::Unsupported
            | ChatError::UnexpectedResponse => Problem::Protocol,
        },
    }
}

enum Input {
    SignIn(Credentials),
    /// An external sign-in for the person with this email (task T611h).
    SignInExternal(String),
    Command(Command),
    SignOut,
}

/// State shared with the thread so that dropping the `Worker` can end blocking I/O at once.
struct Shared {
    stop: AtomicBool,
    /// The window asked to stop waiting for the browser (task T611h).
    cancel: AtomicBool,
    socket: Mutex<Option<TcpStream>>,
}

impl Shared {
    fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    fn cancelled(&self) -> bool {
        self.stopped() || self.cancel.load(Ordering::Acquire)
    }

    fn set_socket(&self, socket: Option<TcpStream>) {
        if let Ok(mut held) = self.socket.lock() {
            *held = socket;
            if self.stopped()
                && let Some(socket) = held.as_ref()
            {
                interrupt(socket);
            }
        }
    }

    fn close(&self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(mut held) = self.socket.lock()
            && let Some(socket) = held.take()
        {
            interrupt(&socket);
        }
    }
}

/// The window's handle on the connection worker. Every method returns at once; results arrive as `Event`s.
///
/// Dropping it stops the thread: the open connection is shut down, so a blocked read or write ends at once, and the
/// drop waits for the thread to finish. The longest that can take is one TCP connection attempt (3 seconds) or a
/// host-name lookup, which cannot be interrupted.
pub struct Worker {
    inputs: Option<Sender<Input>>,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("Worker { .. }")
    }
}

impl Worker {
    /// Start the worker for one enrolled device at one server, not yet signed in. `wake` is called after each event
    /// is queued (for example to ask the window to repaint); it must not block. For a saved device, pass
    /// `StoredDevice::endpoint().clone()` and `StoredDevice::identity()`.
    pub fn start(
        endpoint: ServerEndpoint,
        device: Arc<dyn ResolvesClientCert>,
        config: WorkerConfig,
        wake: impl Fn() + Send + 'static,
    ) -> io::Result<(Self, Receiver<Event>)> {
        Self::start_with_keeper(endpoint, device, config, Box::new(MemoryOnly), wake)
    }

    /// As `start`, keeping the resume ticket with `keeper` (task T240). A ticket `keeper` already holds is tried at
    /// once: the worker resumes that session without a sign-in, or reports `SessionEnded` if the server refuses it.
    pub fn start_with_keeper(
        endpoint: ServerEndpoint,
        device: Arc<dyn ResolvesClientCert>,
        config: WorkerConfig,
        keeper: Box<dyn TicketKeeper>,
        wake: impl Fn() + Send + 'static,
    ) -> io::Result<(Self, Receiver<Event>)> {
        Self::start_with_browser(endpoint, device, config, keeper, Arc::new(crate::loopback::open_browser), wake)
    }

    /// As `start_with_keeper`, opening external sign-in pages with `browser` (task T611h; tests pass their own).
    pub fn start_with_browser(
        endpoint: ServerEndpoint,
        device: Arc<dyn ResolvesClientCert>,
        config: WorkerConfig,
        keeper: Box<dyn TicketKeeper>,
        browser: Browser,
        wake: impl Fn() + Send + 'static,
    ) -> io::Result<(Self, Receiver<Event>)> {
        let ticket = keeper.load();
        let retry = ticket.as_ref().map(|_| Retry { at: Instant::now(), wait: config.first_retry });
        let (inputs, input_queue) = mpsc::channel();
        let (events, event_queue) = mpsc::channel();
        let shared = Arc::new(Shared { stop: AtomicBool::new(false), cancel: AtomicBool::new(false), socket: Mutex::new(None) });
        let run = Run {
            endpoint,
            device,
            config,
            events,
            wake: Box::new(wake),
            shared: shared.clone(),
            gone: false,
            session: None,
            me: String::new(),
            open: None,
            followed: BTreeSet::new(),
            shown: BTreeMap::new(),
            seen: BTreeMap::new(),
            unread: BTreeMap::new(),
            read_states_sent: BTreeMap::new(),
            gaps_sent: BTreeMap::new(),
            recovery_epochs: BTreeMap::new(),
            files_sent: BTreeMap::new(),
            threads_sent: BTreeMap::new(),
            reactions_sent: BTreeMap::new(),
            pins_sent: BTreeMap::new(),
            room_settings_sent: BTreeMap::new(),
            saved_sent: None,
            saved_requested: false,
            activity_filter: None,
            activity_badge_sent: None,
            activity_sent: None,
            activity_polling: false,
            archive_sent: BTreeMap::new(),
            continued_sent: BTreeMap::new(),
            calendar_weeks: None,
            meeting_changes_seen: 0,
            in_call: None,
            next_heartbeat: Instant::now(),
            crypto: None,
            security_sent: None,
            calls_sent: BTreeMap::new(),
            next_poll: Instant::now(),
            retry,
            keeper,
            ticket,
            browser,
        };
        let thread = thread::Builder::new().name("crewcraft-connection".into()).spawn(move || run.run(&input_queue))?;
        Ok((Self { inputs: Some(inputs), shared, thread: Some(thread) }, event_queue))
    }

    /// Sign in with fresh credentials, replacing any current session. False if the worker has stopped.
    pub fn sign_in(&self, credentials: Credentials) -> bool {
        self.input(Input::SignIn(credentials))
    }

    /// Sign in through the server's external identity provider (task T611h), replacing any current session: the
    /// worker opens the provider's page in the browser and reports `WaitingForBrowser`, then `SignedIn` or `Failed`.
    /// `email` names the person this device is enrolled for. False if the worker has stopped.
    pub fn sign_in_external(&self, email: &str) -> bool {
        // Cleared here, not on the worker's thread, so a cancel right after this call is never lost.
        self.shared.cancel.store(false, Ordering::Release);
        self.input(Input::SignInExternal(email.to_owned()))
    }

    /// Stop waiting for the browser in an external sign-in (task T611h): the worker reports `Failed(Cancelled)`. A
    /// code the browser already handed back is not used. Nothing happens when no sign-in is waiting.
    pub fn cancel_sign_in(&self) {
        self.shared.cancel.store(true, Ordering::Release);
    }

    /// Hand a command from the window to the worker. `Sync` also makes that room the open room. False if the worker
    /// has stopped.
    pub fn send(&self, command: Command) -> bool {
        self.input(Input::Command(command))
    }

    /// End the session. Followed rooms are kept for the next sign-in. False if the worker has stopped.
    pub fn sign_out(&self) -> bool {
        self.input(Input::SignOut)
    }

    fn input(&self, input: Input) -> bool {
        self.inputs.as_ref().is_some_and(|inputs| inputs.send(input).is_ok())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.shared.close();
        self.inputs.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Retry {
    at: Instant,
    wait: Duration,
}

struct Run {
    endpoint: ServerEndpoint,
    device: Arc<dyn ResolvesClientCert>,
    config: WorkerConfig,
    events: Sender<Event>,
    wake: Box<dyn Fn() + Send>,
    shared: Arc<Shared>,
    /// The window dropped the event receiver.
    gone: bool,
    session: Option<SignedInSession>,
    me: String,
    open: Option<String>,
    followed: BTreeSet<String>,
    /// The open room's last snapshot sent, per room.
    shown: BTreeMap<String, Vec<Shown>>,
    /// The highest message cursor shown while each room was open.
    seen: BTreeMap<String, u64>,
    /// The last unread count sent, per room.
    unread: BTreeMap<String, u32>,
    read_states_sent: BTreeMap<String, ReadState>,
    gaps_sent: BTreeMap<String, GapNotice>,
    recovery_epochs: BTreeMap<String, u64>,
    /// The last attachments sent, per room (task T330e).
    files_sent: BTreeMap<String, Vec<(u64, Vec<crewcraft_proto::push::AttachedFile>)>>,
    /// The last threads sent, per room (task T340b).
    threads_sent: BTreeMap<String, Vec<(u64, u64)>>,
    /// The call this app is in, `(room, call)`, and when its next heartbeat is due (task T360a2).
    in_call: Option<(String, u64)>,
    next_heartbeat: Instant,
    /// This app's keys for the call it is in, and what was last said about them (task T360d3).
    crypto: Option<crate::call_crypto::CallCrypto>,
    security_sent: Option<(u64, u64, Vec<String>)>,
    /// The last calls state sent, per room (task T360a2).
    calls_sent: BTreeMap<String, RoomCalls>,
    /// The last archive times sent, per archive room (task T350d2).
    archive_sent: BTreeMap<String, Vec<(u64, u64)>>,
    /// The last continuation lines sent, per room (task T352).
    continued_sent: BTreeMap<String, Vec<(u64, String, String)>>,
    /// The calendar week the window shows, in weeks from this one, once it has asked for one (task T370b).
    calendar_weeks: Option<i64>,
    /// The session's meeting line count when the calendar was last read (task T370b2).
    meeting_changes_seen: u64,
    /// The last reactions sent, per room (task T341b).
    reactions_sent: BTreeMap<String, crewcraft_ui_model::RoomReactions>,
    /// Pin metadata is sent even when the room's message snapshot stays unchanged (T343).
    pins_sent: BTreeMap<String, Option<PinnedMessage>>,
    /// The person's own room settings last sent, per room (T346).
    room_settings_sent: BTreeMap<String, crewcraft_proto::room_settings::RoomSettings>,
    saved_sent: Option<Vec<crewcraft_proto::request::SavedMessage>>,
    /// Refresh personal bookmarks after the window first opens or changes the saved list (T343).
    saved_requested: bool,
    activity_filter: Option<ActivityFilter>,
    activity_badge_sent: Option<ActivitySnapshot>,
    activity_sent: Option<(ActivityFilter, ActivitySnapshot)>,
    activity_polling: bool,
    next_poll: Instant,
    retry: Option<Retry>,
    keeper: Box<dyn TicketKeeper>,
    /// The current session's resume ticket (task T240).
    ticket: Option<ResumeTicket>,
    browser: Browser,
}

/// Fresh random bytes for the external sign-in's PKCE verifier and state.
fn random_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// The external sign-in's two server calls over the worker's endpoint and device (task T611h). Each connection is
/// registered with `Shared`, so dropping the worker ends it at once.
struct Via<'a> {
    endpoint: &'a ServerEndpoint,
    device: &'a Arc<dyn ResolvesClientCert>,
    shared: &'a Shared,
    email: &'a str,
}

impl ExternalServer for Via<'_> {
    type Session = SignedInSession;

    fn begin(&self) -> Result<Option<ExternalStart>, LabError> {
        let mut connection = self.endpoint.connect(self.device.clone())?;
        self.shared.set_socket(connection.interrupt.take());
        let start = self.endpoint.begin_external_over(connection.transport);
        self.shared.set_socket(None);
        start
    }

    fn finish(&self, code: &str, verifier: &str, redirect_uri: &str) -> Result<SignedInSession, LabError> {
        let mut connection = self.endpoint.connect(self.device.clone())?;
        self.shared.set_socket(connection.interrupt.take());
        self.endpoint.finish_external_over(connection.transport, self.email, code, verifier, redirect_uri)
    }
}

impl Run {
    fn run(mut self, inputs: &Receiver<Input>) {
        while !self.gone && !self.shared.stopped() {
            let due = if self.session.is_some() { Some(self.next_poll) } else { self.retry.as_ref().map(|retry| retry.at) };
            let input = match due {
                None => match inputs.recv() {
                    Ok(input) => Some(input),
                    Err(_) => break,
                },
                Some(at) => match inputs.recv_timeout(at.saturating_duration_since(Instant::now())) {
                    Ok(input) => Some(input),
                    Err(RecvTimeoutError::Timeout) => None,
                    Err(RecvTimeoutError::Disconnected) => break,
                },
            };
            match input {
                Some(Input::SignIn(credentials)) => self.sign_in(&credentials),
                Some(Input::SignInExternal(email)) => self.sign_in_external(&email),
                Some(Input::Command(Command::Sync { room })) => self.open_room(room),
                Some(Input::Command(Command::Read { room })) => self.read_room(room),
                Some(Input::Command(Command::MarkUnread { room, target })) => self.mark_unread(room, target),
                Some(Input::Command(Command::SetRoomSetting { room, setting, on })) => self.set_room_setting(room, setting, on),
                Some(Input::Command(Command::Post { room, text })) => self.post(room, text),
                Some(Input::Command(Command::Edit { room, target, text })) => {
                    self.change(room, |session, room| session.edit(room, target, &text));
                }
                Some(Input::Command(Command::Delete { room, target })) => self.change(room, |session, room| session.delete(room, target)),
                Some(Input::Command(Command::Search { query })) => self.search(query),
                Some(Input::Command(Command::ListFiles)) => self.list_files(),
                Some(Input::Command(Command::ListSaved)) => {
                    self.saved_requested = true;
                    self.refresh_saved(true);
                }
                Some(Input::Command(Command::ListActivity { filter })) => {
                    self.activity_filter = (filter != ActivityFilter::Badge).then_some(filter);
                    self.activity_polling = true;
                    self.refresh_activity(true, filter != ActivityFilter::Badge);
                }
                Some(Input::Command(Command::MarkActivitySeen { through })) => self.mark_activity_seen(through),
                Some(Input::Command(Command::Pin { room, target, on })) => self.pin_message(room, target, on),
                Some(Input::Command(Command::SaveMessage { room, target, on })) => self.save_message(room, target, on),
                Some(Input::Command(Command::Preview { file, size })) => {
                    // A preview that cannot be fetched is shown as the file chip it already is.
                    let bytes = self
                        .session
                        .as_mut()
                        .and_then(|session| session.download_bytes(file, size, crewcraft_ui_model::MAX_PREVIEW_BYTES).ok())
                        .unwrap_or_default();
                    self.emit(Event::Preview { file, bytes });
                }
                Some(Input::Command(Command::Attach { room, path })) => self.attach(room, path),
                Some(Input::Command(Command::Reply { room, parent, text })) => self.reply(room, parent, text),
                Some(Input::Command(Command::CallStart { room, video })) => self.call_start(room, video),
                Some(Input::Command(Command::CallJoin { room, call })) => self.call_join(room, call),
                Some(Input::Command(Command::CallLeave { room, call })) => self.call_leave(room, call),
                Some(Input::Command(Command::React { room, target, reaction, on })) => {
                    self.change(room, |session, room| session.react(room, target, reaction, on));
                }
                Some(Input::Command(Command::PostFiles { room, text, files })) => self.post_files(room, text, files),
                Some(Input::Command(Command::Save { file, size, name, to })) => self.save(file, size, &name, to),
                Some(Input::Command(Command::Continue { archive })) => self.continue_archive(archive),
                Some(Input::Command(Command::ListMeetings { weeks })) => {
                    self.calendar_weeks = Some(weeks);
                    self.refresh_meetings();
                }
                Some(Input::Command(Command::SaveMeeting { room, meeting, version, start_ms, duration, title, agenda })) => {
                    self.save_meeting(MeetingSave { room, meeting, version, start_ms, duration, title, agenda }, false);
                }
                Some(Input::Command(Command::CancelMeeting { room, meeting, version })) => self.cancel_meeting(&room, meeting, version),
                Some(Input::Command(Command::JoinMeeting { room, meeting })) => {
                    let result = self.session.as_mut().map(|session| session.meeting_join(meeting));
                    self.entered_call(room, result);
                    self.refresh_meetings();
                }
                Some(Input::Command(Command::StartMeetingNow { room, title, duration, agenda })) => {
                    let save = MeetingSave { room, meeting: 0, version: 0, start_ms: wall_ms(), duration, title, agenda };
                    self.save_meeting(save, true);
                }
                Some(Input::SignOut) => {
                    self.retry = None;
                    let was_signed_in = self.session.is_some();
                    self.end_session();
                    self.end_remote_session();
                    if was_signed_in {
                        self.emit(Event::Disconnected);
                    }
                }
                None if self.session.is_some() => self.poll(false),
                None => self.probe(),
            }
        }
        self.end_session();
    }

    fn emit(&mut self, event: Event) {
        if self.events.send(event).is_err() {
            self.gone = true;
        } else {
            (self.wake)();
        }
    }

    fn end_session(&mut self) {
        let had_session = self.session.is_some();
        self.session = None;
        self.activity_filter = None;
        self.activity_badge_sent = None;
        self.activity_sent = None;
        self.activity_polling = false;
        self.shared.set_socket(None);
        if had_session {
            self.emit(Event::ActivityReset);
        }
    }

    fn connect(&mut self) -> Result<Connection, Problem> {
        let mut connection = self.endpoint.connect(self.device.clone()).map_err(problem)?;
        self.shared.set_socket(connection.interrupt.take());
        Ok(connection)
    }

    fn sign_in(&mut self, credentials: &Credentials) {
        self.end_session();
        self.retry = None;
        let connection = match self.connect() {
            Ok(connection) => connection,
            Err(problem) => return self.fail_connection(problem, false),
        };
        self.emit(Event::Connected);
        match self.endpoint.sign_in_over(connection.transport, credentials) {
            Ok(session) => self.start_session(session, credentials.email()),
            Err(error) => self.fail_connection(problem(error), false),
        }
    }

    /// An external sign-in (task T611h): begin on one connection, the browser and its loopback redirect, finish on
    /// another. Problems the server causes are handled like a failed password sign-in; the others are only reported.
    fn sign_in_external(&mut self, email: &str) {
        self.end_session();
        self.retry = None;
        let outcome = {
            let via = Via { endpoint: &self.endpoint, device: &self.device, shared: &self.shared, email };
            let (events, wake, browser, shared) = (&self.events, &self.wake, &self.browser, &self.shared);
            let open = |url: &str| {
                browser(url)?;
                if events.send(Event::WaitingForBrowser).is_ok() {
                    wake();
                }
                Ok(())
            };
            run_unless(&via, random_bytes, open, BROWSER_TIMEOUT, &|| shared.cancelled())
        };
        let problem = match outcome {
            Ok(session) => return self.start_session(session, email),
            Err(FlowError::Server(error)) => {
                let problem = match problem(error) {
                    Problem::SignInRefused => Problem::ExternalRefused,
                    other => other,
                };
                return self.fail_connection(problem, false);
            }
            Err(FlowError::NotOffered) => Problem::ExternalNotOffered,
            Err(FlowError::Browser(_)) => Problem::Browser,
            Err(FlowError::Loopback(LoopbackError::Bind(_))) => Problem::NoRedirect,
            Err(FlowError::Loopback(LoopbackError::TimedOut)) => Problem::BrowserTimedOut,
            Err(FlowError::Loopback(LoopbackError::Provider(_))) => Problem::ProviderRefused,
            Err(FlowError::Loopback(LoopbackError::Cancelled)) => Problem::Cancelled,
        };
        self.emit(Event::Failed(problem));
    }

    /// Take over a session that was just signed in or resumed: keep its resume ticket, list the person's rooms, report
    /// `SignedIn` and poll.
    fn start_session(&mut self, mut session: SignedInSession, email: &str) {
        self.activity_filter = None;
        self.activity_badge_sent = None;
        self.activity_sent = None;
        self.activity_polling = session.activities();
        self.pins_sent.clear();
        self.room_settings_sent.clear();
        self.read_states_sent.clear();
        self.gaps_sent.clear();
        self.recovery_epochs.clear();
        self.saved_sent = None;
        self.saved_requested = false;
        if let Some(ticket) = session.resume_ticket() {
            self.keeper.save(&ticket);
            self.ticket = Some(ticket);
        }
        let listed = match session.list_rooms() {
            Ok(listed) => listed,
            Err(error) => {
                let problem = problem(error);
                if problem.ends_session() {
                    return self.fail_connection(problem, false);
                }
                // A refusal leaves the session usable; carry on with the rooms already followed.
                self.emit(Event::Failed(problem));
                None
            }
        };
        // The person's own room settings arrive before SignedIn, so the first room list is already in their order.
        let settings = match session.list_room_settings() {
            Ok(settings) => settings.unwrap_or_default(),
            Err(error) => {
                let problem = problem(error);
                if problem.ends_session() {
                    return self.fail_connection(problem, false);
                }
                self.emit(Event::Failed(problem));
                Vec::new()
            }
        };
        self.session = Some(session);
        self.me = email.to_owned();
        if let Some(rooms) = listed {
            self.adopt(rooms);
        }
        for row in settings {
            if self.followed.contains(&row.room) {
                self.room_settings_sent.insert(row.room.clone(), row.settings);
                self.emit(Event::RoomSettings { room: row.room, settings: row.settings });
            }
        }
        let rooms = self.followed.iter().cloned().collect();
        self.emit(Event::SignedIn { email: self.me.clone(), rooms });
        self.poll(true);
    }

    /// Report a connection-ending problem and, when it can help, schedule a reconnection attempt. With a resume ticket
    /// and a problem that retrying can fix, the session is not reported as ended: the retry resumes it.
    fn fail_connection(&mut self, problem: Problem, was_signed_in: bool) {
        self.end_session();
        self.emit(Event::Failed(problem));
        let resumable = self.ticket.is_some() && problem.retryable();
        if was_signed_in && !resumable {
            self.emit(Event::Disconnected);
        }
        self.retry = problem.retryable().then(|| Retry { at: Instant::now() + self.config.first_retry, wait: self.config.first_retry });
    }

    /// Forget the resume ticket, asking the server to end its session first (best effort: an unreachable server
    /// lets the session run out on its own).
    fn end_remote_session(&mut self) {
        let Some(ticket) = self.ticket.take() else {
            return;
        };
        self.keeper.clear();
        let _ = self.endpoint.end_session(self.device.clone(), &ticket);
        self.shared.set_socket(None);
    }

    /// Handle a failed request: a connection-ending one ends the session, any other is only reported.
    fn request_failed(&mut self, error: LabError) -> Problem {
        let problem = problem(error);
        if problem.ends_session() {
            self.fail_connection(problem, true);
        } else {
            self.emit(Event::Failed(problem));
        }
        problem
    }

    fn probe(&mut self) {
        let Some(retry) = self.retry.take() else {
            return;
        };
        match self.connect() {
            Ok(connection) => {
                if let Some(ticket) = self.ticket.clone() {
                    match self.endpoint.resume_over(connection.transport, &ticket) {
                        Ok(session) => return self.start_session(session, ticket.email()),
                        Err(_) => {
                            // The server answered the TLS handshake but did not reopen the session: it refused the
                            // ticket, or it is too old to resume and closed the connection. Either way retrying will
                            // not help: forget the ticket and sign in again with a code.
                            self.ticket = None;
                            self.keeper.clear();
                            self.shared.set_socket(None);
                            self.emit(Event::SessionEnded);
                            self.emit(Event::Connected);
                            return;
                        }
                    }
                }
                drop(connection);
                self.shared.set_socket(None);
                self.emit(Event::Connected);
            }
            Err(problem) if problem.retryable() => {
                let wait = retry.wait.saturating_mul(2).min(self.config.max_retry);
                self.retry = Some(Retry { at: Instant::now() + wait, wait });
            }
            Err(problem) => self.emit(Event::Failed(problem)),
        }
    }

    /// Follow exactly the rooms the server listed for the person (valid names, at most `MAX_FOLLOWED`), and forget
    /// what was kept for any other room.
    fn adopt(&mut self, rooms: Vec<String>) {
        self.followed = rooms.into_iter().filter(|room| valid_room(room)).take(MAX_FOLLOWED).collect();
        if self.open.as_ref().is_some_and(|open| !self.followed.contains(open)) {
            self.open = None;
        }
        let followed = &self.followed;
        self.shown.retain(|room, _| followed.contains(room));
        self.seen.retain(|room, _| followed.contains(room));
        self.unread.retain(|room, _| followed.contains(room));
        self.read_states_sent.retain(|room, _| followed.contains(room));
        self.room_settings_sent.retain(|room, _| followed.contains(room));
        self.gaps_sent.retain(|room, _| followed.contains(room));
        self.recovery_epochs.retain(|room, _| followed.contains(room));
    }

    fn follow(&mut self, room: &str) -> Result<(), Problem> {
        if !valid_room(room) {
            return Err(Problem::InvalidRoom);
        }
        if !self.followed.contains(room) {
            if self.followed.len() >= MAX_FOLLOWED {
                return Err(Problem::TooManyRooms);
            }
            self.followed.insert(room.to_owned());
        }
        Ok(())
    }

    fn open_room(&mut self, room: String) {
        if let Err(problem) = self.follow(&room) {
            return self.emit(Event::Failed(problem));
        }
        self.open = Some(room.clone());
        if self.session.is_none() {
            return self.emit(Event::Failed(Problem::NotSignedIn));
        }
        self.sync_room(&room, true);
    }

    /// Only a deliberate room-open or Mark as read command writes a read marker. Polling and automatic startup
    /// selection keep another device's explicit rewind intact (T344).
    fn read_room(&mut self, room: String) {
        self.open_room(room.clone());
        let Some(session) = self.session.as_mut() else { return };
        if !session.read_states() {
            return;
        }
        let Some(state) = session.read_state(&room) else { return };
        match session.mark_read(&room, state.head) {
            Ok(_) => self.sync_room(&room, true),
            Err(error) => {
                self.request_failed(error);
            }
        }
    }

    fn mark_unread(&mut self, room: String, target: u64) {
        if let Err(problem) = self.follow(&room) {
            return self.emit(Event::Failed(problem));
        }
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::Failed(Problem::NotSignedIn));
        };
        if !session.read_states() {
            return self.emit(Event::Failed(Problem::ReadStateNotOffered));
        }
        let before = session.read_state(&room);
        let position = match session.mark_unread(&room, target) {
            Ok(position) => position,
            Err(error) => {
                self.request_failed(error);
                return;
            }
        };
        self.sync_room(&room, false);
        let after = self.session.as_mut().and_then(|session| session.read_state(&room));
        if let Some(after) = after
            && after.position == position
            && (target != 0 || after.unread != 0 || before.as_ref().is_some_and(|before| before.position != after.position))
        {
            if self.open.as_deref() == Some(room.as_str()) {
                self.open = None;
            }
            self.emit(Event::MarkedUnread { room });
        }
    }

    /// Continue an archive room (task T352). The room it continues in is followed; the window opens it.
    /// Read the calendar's week again, when the window shows one (task T370b).
    fn refresh_meetings(&mut self) {
        let Some(weeks) = self.calendar_weeks else { return };
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::Failed(Problem::NotSignedIn));
        };
        if !session.meetings() {
            return self.emit(Event::Failed(Problem::MeetingsNotOffered));
        }
        let now_ms = wall_ms();
        // The app reads no time zone yet: the week and its times are UTC (docs/MEETINGS.md, slice T370b).
        let Some((from_ms, to_ms)) = crewcraft_client_core::calendar::work_week_at(now_ms, 0, weeks) else {
            return self.emit(Event::Failed(Problem::InvalidRequest));
        };
        match session.meeting_list(from_ms, to_ms) {
            Ok(page) => self.emit(Event::Meetings { from_ms, to_ms, now_ms, meetings: page.meetings, more: page.more }),
            Err(error) => {
                self.request_failed(error);
            }
        }
    }

    /// Schedule or edit a meeting (task T370b), and with `join`, join it once it is scheduled ("start now").
    fn save_meeting(&mut self, save: MeetingSave, join: bool) {
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::Failed(Problem::NotSignedIn));
        };
        if !session.meetings() {
            return self.emit(Event::Failed(Problem::MeetingsNotOffered));
        }
        let (room, edited) = (save.room.clone(), save.meeting);
        match session.meeting_save(save) {
            Ok(meeting) => {
                let id = meeting.id;
                self.emit(Event::MeetingSaved { meeting });
                if join {
                    let result = self.session.as_mut().map(|session| session.meeting_join(id));
                    self.entered_call(room, result);
                }
                self.refresh_meetings();
            }
            Err(error) => self.meeting_refused(edited, error),
        }
    }

    fn cancel_meeting(&mut self, room: &str, meeting: u64, version: u64) {
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::Failed(Problem::NotSignedIn));
        };
        if let Err(error) = session.meeting_cancel(room, meeting, version) {
            self.meeting_refused(meeting, error);
        }
        // Cancelled or not, the week shows the meeting as it is now.
        self.refresh_meetings();
    }

    /// Report a refused meeting change (task T370b). A stale version is a conflict: the window keeps the person's
    /// edits and asks them to reload; nothing is sent again.
    fn meeting_refused(&mut self, meeting: u64, error: LabError) {
        let (conflict, reason) = match error {
            LabError::Chat(ChatError::Rejected(code)) => (code == E_CONFLICT, meeting_refusal(code).to_owned()),
            error => (false, self.request_failed(error).to_string()),
        };
        self.emit(Event::MeetingRefused { meeting, conflict, reason });
    }

    fn continue_archive(&mut self, archive: String) {
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::Failed(Problem::NotSignedIn));
        };
        if !session.continues() {
            return self.emit(Event::Failed(Problem::ContinueNotOffered));
        }
        match session.continue_archive(&archive) {
            Ok(room) => match self.follow(&room) {
                Ok(()) => self.emit(Event::Continued { archive, room }),
                Err(problem) => self.emit(Event::Failed(problem)),
            },
            Err(error) => {
                self.request_failed(error);
            }
        }
    }

    /// Turn one of the person's own settings for a room on or off (T346). The room's next sync reads the result back
    /// from the server, so the window shows what the server stored, not what was asked.
    fn set_room_setting(&mut self, room: String, setting: crewcraft_proto::room_settings::RoomSetting, on: bool) {
        if let Err(problem) = self.follow(&room) {
            return self.emit(Event::Failed(problem));
        }
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::Failed(Problem::NotSignedIn));
        };
        if !session.room_settings_offered() {
            return self.emit(Event::Failed(Problem::RoomSettingsNotOffered));
        }
        match session.set_room_setting(&room, setting, on) {
            Ok(_) => self.sync_room(&room, false),
            Err(error) => {
                self.request_failed(error);
            }
        }
    }

    /// Send the room's settings when they differ from the last ones sent (or always with `force`).
    fn publish_room_settings(&mut self, room: &str, force: bool) {
        let state = self.session.as_mut().and_then(|session| session.room_settings(room));
        let Some(state) = state else { return };
        if force || self.room_settings_sent.get(room) != Some(&state.settings) {
            self.room_settings_sent.insert(room.to_owned(), state.settings);
            self.emit(Event::RoomSettings { room: room.to_owned(), settings: state.settings });
        }
    }

    fn publish_read_state(&mut self, room: &str, force: bool) -> bool {
        let state = self.session.as_mut().and_then(|session| session.read_state(room));
        let Some(state) = state else { return false };
        let count = u32::try_from(state.unread).unwrap_or(u32::MAX);
        if self.unread.get(room) != Some(&count) {
            self.unread.insert(room.to_owned(), count);
            self.emit(Event::Unread { room: room.to_owned(), count });
        }
        if force || self.read_states_sent.get(room) != Some(&state) {
            self.read_states_sent.insert(room.to_owned(), state.clone());
            self.emit(Event::ReadState { room: room.to_owned(), state });
        }
        true
    }

    fn post(&mut self, room: String, text: String) {
        if let Err(problem) = self.follow(&room) {
            return self.emit(Event::PostFailed { room, text, problem });
        }
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::PostFailed { room, text, problem: Problem::NotSignedIn });
        };
        match session.post(&room, &text) {
            Ok(cursor) => {
                self.emit(Event::Posted { room: room.clone(), cursor });
                self.sync_room(&room, false);
            }
            Err(error) => {
                let problem = problem(error);
                self.emit(Event::PostFailed { room, text, problem });
                if problem.ends_session() {
                    self.fail_connection(problem, true);
                }
            }
        }
    }

    /// Upload a file to attach (task T330e): `Uploaded`, or `Failed`.
    fn attach(&mut self, room: String, path: std::path::PathBuf) {
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::Failed(Problem::NotSignedIn));
        };
        match session.upload(&room, &path, &mut |_, _| {}) {
            Ok(uploaded) => self.emit(Event::Uploaded { room, file: uploaded.file, name: uploaded.name, size: uploaded.size }),
            Err(crate::signed_in::FileOpError::Local(kind)) => self.emit(Event::Failed(Problem::LocalFile(kind))),
            Err(crate::signed_in::FileOpError::Lab(LabError::Chat(ChatError::Unsupported))) => self.emit(Event::Failed(Problem::FilesNotOffered)),
            Err(crate::signed_in::FileOpError::Lab(error)) => {
                self.request_failed(error);
            }
        }
    }

    /// Start or join a call (task T360a2).
    fn call_start(&mut self, room: String, video: bool) {
        let result = self.session.as_mut().map(|session| session.call_start(&room, video));
        self.entered_call(room, result);
    }

    fn call_join(&mut self, room: String, call: u64) {
        let result =
            self.session.as_mut().map(|session| session.call(&room, call, |room, call| crewcraft_proto::request::Request::CallJoin { room, call }));
        self.entered_call(room, result);
    }

    fn entered_call(&mut self, room: String, result: Option<Result<u64, LabError>>) {
        match result {
            None => self.emit(Event::Failed(Problem::NotSignedIn)),
            Some(Ok(call)) => {
                // One call at a time: leave the one this app was in.
                if let Some((old_room, old_call)) = self.in_call.take().filter(|(r, c)| (r.as_str(), *c) != (room.as_str(), call))
                    && let Some(session) = self.session.as_mut()
                {
                    let _ = session.call(&old_room, old_call, |room, call| crewcraft_proto::request::Request::CallLeave { room, call });
                    self.emit(Event::LeftCall { room: old_room, reason: None });
                }
                self.in_call = Some((room.clone(), call));
                self.next_heartbeat = Instant::now() + CALL_HEARTBEAT;
                self.emit(Event::InCall { room: room.clone(), call });
                self.sync_room(&room, false);
            }
            Some(Err(error)) => {
                self.request_failed(error);
            }
        }
    }

    /// One step of this app's call keys (task T360d3): publish and seal what the server's view asks for, open what was
    /// sealed to this person, and say when the call's security changed.
    fn step_call_keys(&mut self) {
        let Some((room, call)) = self.in_call.clone() else { return };
        let me = self.me.clone();
        if self.crypto.as_ref().is_none_or(|crypto| crypto.call() != call) {
            self.crypto = crate::call_crypto::CallCrypto::new(call, &me).ok();
            self.security_sent = None;
        }
        let (Some(session), Some(crypto)) = (self.session.as_mut(), self.crypto.as_mut()) else { return };
        let (keys, boxes) = session.call_inputs(&room, call);
        let Ok(sends) = crypto.step(&keys, &boxes) else { return };
        for send in sends {
            let request = match send {
                crate::call_crypto::Send::Publish(public) => crewcraft_proto::request::Request::CallKey { room: room.clone(), call, public },
                crate::call_crypto::Send::Seal { to, kid, sealed } => {
                    crewcraft_proto::request::Request::CallSeal { room: room.clone(), call, to, kid, sealed }
                }
            };
            // A refusal (someone left meanwhile) is settled by the next step; a lost connection by the retry.
            let _ = session.call_send(request);
        }
        let state = (call, crypto.sending_kid(), crypto.received_from());
        if self.security_sent.as_ref() != Some(&state) {
            self.security_sent = Some(state.clone());
            self.emit(Event::CallSecurity { room, call: state.0, kid: state.1, from: state.2 });
        }
    }

    fn call_leave(&mut self, room: String, call: u64) {
        if self.in_call.as_ref() == Some(&(room.clone(), call)) {
            self.in_call = None;
            self.crypto = None;
        }
        // A refusal means the call already ended or this person had left it: either way they are out.
        let result =
            self.session.as_mut().map(|session| session.call(&room, call, |room, call| crewcraft_proto::request::Request::CallLeave { room, call }));
        if let Some(Err(error)) = result {
            let problem = problem(error);
            if problem.ends_session() {
                self.fail_connection(problem, true);
            }
        }
        self.emit(Event::LeftCall { room: room.clone(), reason: None });
        self.sync_room(&room, false);
    }

    /// Send the call heartbeat when it is due (REQUIREMENTS 2.5, every 20 seconds). A refusal means the call ended or
    /// this person may no longer be in it: leave and say why. A network error keeps the call and tries again.
    fn heartbeat(&mut self) {
        let Some((room, call)) = self.in_call.clone() else { return };
        if Instant::now() < self.next_heartbeat {
            return;
        }
        self.next_heartbeat = Instant::now() + CALL_HEARTBEAT;
        let Some(session) = self.session.as_mut() else { return };
        match session.call(&room, call, |room, call| crewcraft_proto::request::Request::CallHeartbeat { room, call }) {
            Ok(_) => {}
            Err(error) => match problem(error) {
                Problem::Refused(code) => {
                    self.in_call = None;
                    self.crypto = None;
                    let reason = if code == 1 { "You are no longer in this room, so you left the call." } else { "The call ended." };
                    self.emit(Event::LeftCall { room, reason: Some(reason.to_owned()) });
                }
                other => {
                    if other.ends_session() {
                        self.fail_connection(other, true);
                    }
                }
            },
        }
    }

    /// A reply in a thread (task T340b): as `post`.
    fn reply(&mut self, room: String, parent: u64, text: String) {
        if let Err(problem) = self.follow(&room) {
            return self.emit(Event::PostFailed { room, text, problem });
        }
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::PostFailed { room, text, problem: Problem::NotSignedIn });
        };
        match session.reply(&room, parent, &text) {
            Ok(cursor) => {
                self.emit(Event::Posted { room: room.clone(), cursor });
                self.sync_room(&room, false);
            }
            Err(error) => {
                let problem = problem(error);
                self.emit(Event::PostFailed { room, text, problem });
                if problem.ends_session() {
                    self.fail_connection(problem, true);
                }
            }
        }
    }

    /// A post with files (task T330e): as `post`.
    fn post_files(&mut self, room: String, text: String, files: Vec<[u8; 16]>) {
        if let Err(problem) = self.follow(&room) {
            return self.emit(Event::PostFailed { room, text, problem });
        }
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::PostFailed { room, text, problem: Problem::NotSignedIn });
        };
        match session.post_files(&room, &text, files) {
            Ok(cursor) => {
                self.emit(Event::Posted { room: room.clone(), cursor });
                self.sync_room(&room, false);
            }
            Err(error) => {
                let problem = problem(error);
                self.emit(Event::PostFailed { room, text, problem });
                if problem.ends_session() {
                    self.fail_connection(problem, true);
                }
            }
        }
    }

    /// Save a file (task T330e): `Saved`, or `Failed`. With no `to`, a new file in the Downloads folder.
    fn save(&mut self, file: [u8; 16], size: u64, name: &str, to: Option<std::path::PathBuf>) {
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::Failed(Problem::NotSignedIn));
        };
        let Some(path) = to.or_else(|| downloads_path(name)) else {
            return self.emit(Event::Failed(Problem::LocalFile(io::ErrorKind::NotFound)));
        };
        match session.download_to(file, size, &path) {
            Ok(()) => self.emit(Event::Saved { path }),
            Err(crate::signed_in::FileOpError::Local(kind)) => self.emit(Event::Failed(Problem::LocalFile(kind))),
            Err(crate::signed_in::FileOpError::Lab(error)) => {
                self.request_failed(error);
            }
        }
    }

    /// A message search (task T320c): `SearchResults`, or `Failed` (`SearchNotOffered` from a server without search).
    fn search(&mut self, query: String) {
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::Failed(Problem::NotSignedIn));
        };
        match session.search(&query) {
            Ok(Some(hits)) => {
                let hits =
                    hits.into_iter().map(|hit| Found { room: hit.room, cursor: hit.cursor, author: hit.author, snippet: hit.snippet }).collect();
                self.emit(Event::SearchResults { query, hits });
            }
            Ok(None) => self.emit(Event::Failed(Problem::SearchNotOffered)),
            Err(error) => {
                self.request_failed(error);
            }
        }
    }

    /// The file list (task T331b).
    fn list_files(&mut self) {
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::Failed(Problem::NotSignedIn));
        };
        // How much of the quota the files take, with the list (task T332b).
        if let Ok(Some((used, quota))) = session.storage_use() {
            self.emit(Event::Storage { used, quota });
        }
        let Some(session) = self.session.as_mut() else { return };
        match session.list_files() {
            Ok(Some(files)) => self.emit(Event::Files { files }),
            Ok(None) => self.emit(Event::Failed(Problem::FilesNotOffered)),
            Err(error) => {
                self.request_failed(error);
            }
        }
    }

    fn pin_message(&mut self, room: String, target: u64, on: bool) {
        if self.session.as_ref().is_some_and(|session| !session.pins_saved()) {
            return self.emit(Event::Failed(Problem::PinsSavedNotOffered));
        }
        self.change(room, |session, room| session.pin(room, target, on));
    }

    fn save_message(&mut self, room: String, target: u64, on: bool) {
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::Failed(Problem::NotSignedIn));
        };
        if !session.pins_saved() {
            return self.emit(Event::Failed(Problem::PinsSavedNotOffered));
        }
        match session.save_message(&room, target, on) {
            Ok(_) => {
                self.saved_requested = true;
                self.refresh_saved(true);
            }
            Err(error) => {
                self.request_failed(error);
            }
        }
    }

    /// Refresh references against the server's current messages and memberships (T343), including an empty result
    /// after the last saved message was deleted or the person lost access to its room.
    fn refresh_saved(&mut self, force: bool) {
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::Failed(Problem::NotSignedIn));
        };
        if !session.pins_saved() {
            self.saved_requested = false;
            return self.emit(Event::Failed(Problem::PinsSavedNotOffered));
        }
        match session.saved_messages() {
            Ok(messages) => {
                if force || self.saved_sent.as_ref() != Some(&messages) {
                    self.saved_sent = Some(messages.clone());
                    self.emit(Event::SavedMessages { messages });
                }
            }
            Err(error) => {
                self.saved_requested = false;
                self.saved_sent = None;
                self.emit(Event::SavedMessages { messages: Vec::new() });
                self.request_failed(error);
            }
        }
    }

    fn refresh_activity(&mut self, force: bool, explicit: bool) {
        let Some(session) = self.session.as_ref() else {
            if explicit {
                self.emit(Event::ActivityFailed { problem: Problem::NotSignedIn, refresh: true });
            }
            return;
        };
        if !session.activities() {
            self.activity_polling = false;
            if explicit {
                self.emit(Event::ActivityFailed { problem: Problem::ActivityNotOffered, refresh: true });
            }
            return;
        }
        if !self.activity_polling {
            return;
        }
        let filter = self.activity_filter.unwrap_or(ActivityFilter::Badge);
        self.fetch_activity(filter, force);
    }

    fn fetch_activity(&mut self, filter: ActivityFilter, force: bool) -> bool {
        let Some(session) = self.session.as_mut() else { return false };
        match session.activity(filter) {
            Ok(snapshot) => {
                let changed = if filter == ActivityFilter::Badge {
                    self.activity_badge_sent.as_ref() != Some(&snapshot)
                } else {
                    self.activity_sent.as_ref().is_none_or(|(of, old)| *of != filter || old != &snapshot)
                };
                if force || changed {
                    if filter == ActivityFilter::Badge {
                        self.activity_badge_sent = Some(snapshot.clone());
                    } else {
                        self.activity_sent = Some((filter, snapshot.clone()));
                    }
                    self.emit(Event::Activity { filter, snapshot });
                }
                true
            }
            Err(error) => {
                self.activity_polling = false;
                self.activity_sent = None;
                self.emit(Event::ActivityFailed { problem: problem(error), refresh: true });
                self.request_failed(error);
                false
            }
        }
    }

    fn mark_activity_seen(&mut self, through: u64) {
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::ActivityFailed { problem: Problem::NotSignedIn, refresh: false });
        };
        match session.mark_activity_seen(through) {
            Ok(_) => {
                self.activity_polling = true;
                self.refresh_activity(true, true);
            }
            Err(error) => {
                let issue = if error == LabError::Chat(ChatError::Unsupported) { Problem::ActivityNotOffered } else { problem(error) };
                self.emit(Event::ActivityFailed { problem: issue, refresh: false });
                if error != LabError::Chat(ChatError::Unsupported) {
                    self.request_failed(error);
                }
            }
        }
    }

    /// An edit or a deletion of one of the person's own messages (task T316): report `Changed`, then sync the room.
    /// A refusal (someone else's message, say) is reported and leaves the session open.
    fn change(&mut self, room: String, apply: impl FnOnce(&mut SignedInSession, &str) -> Result<u64, LabError>) {
        if let Err(problem) = self.follow(&room) {
            return self.emit(Event::Failed(problem));
        }
        let Some(session) = self.session.as_mut() else {
            return self.emit(Event::Failed(Problem::NotSignedIn));
        };
        match apply(session, &room) {
            Ok(cursor) => {
                self.emit(Event::Changed { room: room.clone(), cursor });
                self.sync_room(&room, false);
            }
            Err(error) => {
                self.request_failed(error);
            }
        }
    }

    /// Sync every followed room, the open one first. With no room followed, ping so the server does not close the
    /// idle connection.
    fn poll(&mut self, force: bool) {
        self.next_poll = Instant::now() + self.config.poll_interval;
        self.heartbeat();
        self.refresh_activity(force, false);
        if self.saved_requested {
            self.refresh_saved(force);
        }
        if self.followed.is_empty() {
            if let Some(session) = self.session.as_mut()
                && let Err(error) = session.ping()
            {
                self.request_failed(error);
            }
            return;
        }
        let mut rooms: Vec<String> = self.open.iter().cloned().collect();
        rooms.extend(self.followed.iter().filter(|room| Some(*room) != self.open.as_ref()).cloned());
        for room in rooms {
            if self.session.is_none() || self.gone || self.shared.stopped() {
                return;
            }
            self.sync_room(&room, force);
        }
        self.next_poll = Instant::now() + self.config.poll_interval;
    }

    /// Sync one room. The open room's snapshot is sent when it changed (or always with `force`); every followed
    /// room's unread count is sent when it changed.
    fn sync_room(&mut self, room: &str, force: bool) {
        let Some(session) = self.session.as_mut() else {
            return;
        };
        let result = session.sync(room);
        let epoch = session.recovery_epoch(room);
        let recovered = epoch > self.recovery_epochs.get(room).copied().unwrap_or(0);
        let recovered_lines = if recovered { session.room_shown(room) } else { None };
        let notice = session.gap_notice(room);
        if let Some(notice) = notice
            && self.gaps_sent.get(room) != Some(&notice)
        {
            self.gaps_sent.insert(room.to_owned(), notice.clone());
            self.emit(Event::Gap { room: room.to_owned(), notice });
        }
        if recovered {
            self.recovery_epochs.insert(room.to_owned(), epoch);
            self.emit(Event::Recovered { room: room.to_owned() });
        }
        // Personal settings are complete even when the room's history has a gap (T346).
        self.publish_room_settings(room, force);
        let mut failure = None;
        let lines = match result {
            Ok((_, lines)) => lines,
            Err(error) if recovered => {
                failure = Some(error);
                recovered_lines.unwrap_or_default()
            }
            Err(LabError::Chat(ChatError::HistoryGap { reached, head })) if reached < head => {
                let pinned = self.session.as_mut().and_then(|session| session.pinned(room));
                if force || self.pins_sent.get(room) != Some(&pinned) {
                    self.pins_sent.insert(room.to_owned(), pinned.clone());
                    self.emit(Event::Pin { room: room.to_owned(), pinned });
                }
                self.publish_read_state(room, force);
                self.emit(Event::Failed(Problem::HistoryGap));
                return;
            }
            Err(error) => {
                // A room the server refuses (for example one the person is not in) is not polled again.
                if let Problem::Refused(_) = self.request_failed(error) {
                    self.followed.remove(room);
                    if self.open.as_deref() == Some(room) {
                        self.open = None;
                    }
                }
                return;
            }
        };
        let is_open = self.open.as_deref() == Some(room);
        if let Some(session) = self.session.as_mut() {
            let pinned = session.pinned(room);
            if force || recovered || self.pins_sent.get(room) != Some(&pinned) {
                self.pins_sent.insert(room.to_owned(), pinned.clone());
                self.emit(Event::Pin { room: room.to_owned(), pinned });
            }
        }
        // The files the room's messages carry, when they change (task T330e).
        if let Some(session) = self.session.as_mut() {
            let files: Vec<(u64, Vec<crewcraft_proto::push::AttachedFile>)> = session.attachments(room).into_iter().collect();
            if recovered || (!files.is_empty() && self.files_sent.get(room) != Some(&files)) {
                self.files_sent.insert(room.to_owned(), files.clone());
                self.emit(Event::Attachments { room: room.to_owned(), files });
            }
        }
        // The room's open call and its history lines, when they change (task T360a2).
        if let Some(session) = self.session.as_mut() {
            let calls = session.calls(room);
            let changed = recovered
                || match self.calls_sent.get(room) {
                    Some(last) => *last != calls,
                    None => calls.0.is_some() || !calls.1.is_empty(),
                };
            if changed {
                self.calls_sent.insert(room.to_owned(), calls.clone());
                self.emit(Event::Calls { room: room.to_owned(), open: calls.0, lines: calls.1 });
            }
        }
        // The lines that link back to the archives the room continues, when they change (task T352).
        if let Some(session) = self.session.as_mut() {
            let lines = session.continued_lines(room);
            let changed = recovered || self.continued_sent.get(room).map_or(!lines.is_empty(), |last| *last != lines);
            if changed {
                self.continued_sent.insert(room.to_owned(), lines.clone());
                self.emit(Event::Continuations { room: room.to_owned(), lines });
            }
        }
        // A meeting line means a meeting changed, perhaps on another device: the calendar reads its week again (T370b2).
        let changes = self.session.as_ref().map_or(self.meeting_changes_seen, SignedInSession::meeting_changes);
        if changes != self.meeting_changes_seen {
            self.meeting_changes_seen = changes;
            self.refresh_meetings();
        }
        // The call's keys, for the call this app is in (task T360d3).
        if failure.is_none() && self.in_call.as_ref().is_some_and(|(in_room, _)| in_room == room) {
            self.step_call_keys();
        }
        // An archive room, and its original times when they change (task T350d2).
        if let Some(session) = self.session.as_mut()
            && let Some(times) = session.archive(room)
            && (recovered || self.archive_sent.get(room) != Some(&times))
        {
            self.archive_sent.insert(room.to_owned(), times.clone());
            self.emit(Event::Archive { room: room.to_owned(), times });
        }
        // Who reacted with what, when it changes; an empty list once the last reaction goes (task T341b).
        if let Some(session) = self.session.as_mut() {
            let reactions = session.reactions(room);
            let changed = recovered
                || match self.reactions_sent.get(room) {
                    Some(last) => *last != reactions,
                    None => !reactions.is_empty(),
                };
            if changed {
                self.reactions_sent.insert(room.to_owned(), reactions.clone());
                self.emit(Event::Reactions { room: room.to_owned(), reactions });
            }
        }
        // The room's threads, when they change (task T340b).
        if let Some(session) = self.session.as_mut() {
            let parents: Vec<(u64, u64)> = session.parents(room).into_iter().collect();
            if recovered || (!parents.is_empty() && self.threads_sent.get(room) != Some(&parents)) {
                self.threads_sent.insert(room.to_owned(), parents.clone());
                self.emit(Event::Threads { room: room.to_owned(), parents });
            }
        }
        if is_open || recovered {
            if is_open {
                let newest = lines.iter().filter_map(|entry| if let Shown::Line(line) = entry { Some(line.cursor) } else { None }).max();
                let seen = self.seen.entry(room.to_owned()).or_insert(0);
                *seen = newest.map_or(*seen, |newest| newest.max(*seen));
            }
            if force || recovered || self.shown.get(room) != Some(&lines) {
                self.shown.insert(room.to_owned(), lines.clone());
                self.emit(Event::Room { room: room.to_owned(), shown: lines.clone() });
            }
        }
        let authoritative = self.publish_read_state(room, force || recovered);
        if let Some(error) = failure {
            self.request_failed(error);
            return;
        }
        if recovered && self.saved_requested {
            self.refresh_saved(true);
        }
        if authoritative {
            return;
        }
        let seen = self.seen.get(room).copied().unwrap_or(0);
        let count = if is_open {
            0
        } else {
            let unread = lines
                .iter()
                .filter(|entry| matches!(entry, Shown::Line(line) if line.cursor > seen && !line.author.eq_ignore_ascii_case(&self.me)))
                .count();
            u32::try_from(unread).unwrap_or(u32::MAX)
        };
        if self.unread.get(room) != Some(&count) {
            self.unread.insert(room.to_owned(), count);
            self.emit(Event::Unread { room: room.to_owned(), count });
        }
    }
}

/// A new file named `name` in the person's Downloads folder (task T330e): `name`, or `name (2)`, `name (3)`... when it
/// is taken. `None` when the system names no home folder.
pub fn downloads_path(name: &str) -> Option<std::path::PathBuf> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" }).filter(|home| !home.is_empty())?;
    let dir = std::path::PathBuf::from(home).join("Downloads");
    let _ = std::fs::create_dir_all(&dir);
    let safe: String = name.chars().map(|c| if c == '/' || c == '\\' || c.is_control() { '_' } else { c }).collect();
    let (stem, extension) = match safe.rsplit_once('.') {
        Some((stem, extension)) if !stem.is_empty() => (stem.to_owned(), format!(".{extension}")),
        _ => (safe.clone(), String::new()),
    };
    (1..1000).map(|n| if n == 1 { dir.join(&safe) } else { dir.join(format!("{stem} ({n}){extension}")) }).find(|path| !path.exists())
}
