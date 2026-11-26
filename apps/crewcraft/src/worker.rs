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

use crewcraft_client_core::room_view::Shown;
use crewcraft_ui_model::Command;
use rand_core::{OsRng, RngCore};
use rustls::client::ResolvesClientCert;

use crate::chat_session::{ChatError, ExternalStart};
use crate::connect::{Connection, interrupt};
use crate::external_flow::{BROWSER_TIMEOUT, ExternalServer, FlowError, run_unless};
use crate::lab_client::LabError;
use crate::loopback::LoopbackError;
use crate::server_endpoint::ServerEndpoint;
use crate::signed_in::{Credentials, ResumeTicket, SignedInSession, valid_room};

/// The most rooms one worker follows (and polls).
pub const MAX_FOLLOWED: usize = 64;

/// Opens a URL (the provider's https sign-in page) in the system browser (task T611h): `loopback::open_browser`, or a
/// test's or a phone's own.
pub type Browser = Arc<dyn Fn(&str) -> io::Result<()> + Send + Sync>;

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
    SignedIn { email: String, rooms: Vec<String> },
    /// The open room as it is drawn now. Sent when the room is opened and whenever it changes.
    Room { room: String, shown: Vec<Shown> },
    /// A followed room's count of messages from other people since it was last open. The open room is always 0.
    Unread { room: String, count: u32 },
    /// The server acknowledged a post at `cursor`.
    Posted { room: String, cursor: u64 },
    /// A post that was not acknowledged; `text` is returned so the window can restore the draft. After
    /// `Problem::Lost` the post may still have arrived: the room's next snapshot shows it if so.
    PostFailed { room: String, text: String, problem: Problem },
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
        )
    }

    /// Whether trying the connection again later can help.
    fn retryable(self) -> bool {
        matches!(self, Self::Unreachable(_) | Self::Lost(_) | Self::Protocol)
    }
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
                Some(Input::Command(Command::Post { room, text })) => self.post(room, text),
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
        self.session = None;
        self.shared.set_socket(None);
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
        self.session = Some(session);
        self.me = email.to_owned();
        if let Some(rooms) = listed {
            self.adopt(rooms);
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

    /// Sync every followed room, the open one first. With no room followed, ping so the server does not close the
    /// idle connection.
    fn poll(&mut self, force: bool) {
        self.next_poll = Instant::now() + self.config.poll_interval;
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
        let lines = match session.sync(room) {
            Ok((_, lines)) => lines,
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
        if is_open {
            let newest = lines.iter().filter_map(|entry| if let Shown::Line(line) = entry { Some(line.cursor) } else { None }).max();
            let seen = self.seen.entry(room.to_owned()).or_insert(0);
            *seen = newest.map_or(*seen, |newest| newest.max(*seen));
            if force || self.shown.get(room) != Some(&lines) {
                self.shown.insert(room.to_owned(), lines.clone());
                self.emit(Event::Room { room: room.to_owned(), shown: lines.clone() });
            }
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
