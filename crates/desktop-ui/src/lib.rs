//! The CrewCraft desktop window, drawn with egui. Task T305.
//!
//! Owns: the screens (enroll, authenticator setup, sign in, chat), what each one draws, and the bundled font. The
//! wide chat screen follows the familiar team-chat layout (REQUIREMENTS 2.20, task T315): a title bar with room
//! search, an app bar, the room list pane, and a main pane with the conversation header, the feed as bubbles and the
//! composer. Called
//! by: the desktop app (`apps/crewcraft`), which runs this inside an eframe window, forwards every `Action` to the
//! connection worker and hands its results back as `Update`s. Calls: `crewcraft-ui-model` for the room list, composer
//! and feed rows. Nothing here touches the network, the disk or a clock, so every screen is tested without a window.
//!
//! Secrets typed into the window (password, invitation link, authenticator code) live in `Zeroizing` buffers, are
//! moved into the `Action` that needs them, and are cleared from the form when it is submitted.

pub mod appearance;
pub mod text;

use std::collections::HashMap;
use std::fmt;

use chrono::{DateTime, Datelike};
use crewcraft_client_core::room_view::Shown;
use crewcraft_proto::activity::{ActivityFilter, ActivityItem, ActivityKind, ActivitySnapshot};
use crewcraft_ui_model::composer::Composer;
use crewcraft_ui_model::feed::feed_rows;
use crewcraft_ui_model::room_list::RoomList;
use crewcraft_ui_model::{Command, DraftError, FeedRow};
use egui::{Align, FontData, FontDefinitions, FontFamily, Key, Layout, Modifiers, RichText, ScrollArea, TextEdit, Ui};
use zeroize::Zeroizing;

/// The width of the enrollment and sign-in forms, or the window's width when that is narrower (a phone).
const FORM_WIDTH: f32 = 460.0;

/// Inter (OFL-1.1, assets/fonts/OFL.txt), the window's only font.
const INTER: &[u8] = include_bytes!("../../../assets/fonts/InterVariable.ttf");

/// The window's fonts: Inter for every family. Install with `egui::Context::set_fonts` before the first frame.
pub fn fonts() -> FontDefinitions {
    let mut fonts = FontDefinitions::empty();
    fonts.font_data.insert("Inter".to_owned(), FontData::from_static(INTER).into());
    for family in [FontFamily::Proportional, FontFamily::Monospace] {
        fonts.families.insert(family, vec!["Inter".to_owned()]);
    }
    fonts
}

/// Something the window asks the app to do. Secrets are moved in and cleared from the form; `Debug` never shows them.
#[derive(PartialEq, Eq)]
pub enum Action {
    /// Enroll this device from an invitation link, setting the account's password.
    Enroll {
        link: Zeroizing<String>,
        password: Zeroizing<String>,
    },
    /// Enroll this device from an invitation link through the organization's sign-in page in the system browser (task
    /// T611i): no password and no authenticator in CrewCraft.
    EnrollExternal {
        link: Zeroizing<String>,
    },
    /// Finish enrollment with the first code from the authenticator the person just set up.
    ConfirmAuthenticator {
        code: Zeroizing<String>,
    },
    /// Sign in with the enrolled device.
    SignIn {
        email: String,
        password: Zeroizing<String>,
        code: Zeroizing<String>,
    },
    /// Sign in through the organization's sign-in page in the system browser (task T611h). `email` names the person
    /// this device is enrolled for.
    SignInExternal {
        email: String,
    },
    /// Stop waiting for the browser in that sign-in.
    CancelSignIn,
    /// A room action for the connection worker.
    Room(Command),
    SignOut,
}

impl fmt::Debug for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enroll { .. } => f.write_str("Enroll { .. }"),
            Self::EnrollExternal { .. } => f.write_str("EnrollExternal { .. }"),
            Self::ConfirmAuthenticator { .. } => f.write_str("ConfirmAuthenticator { .. }"),
            Self::SignIn { email, .. } => f.debug_struct("SignIn").field("email", email).finish_non_exhaustive(),
            Self::SignInExternal { email } => f.debug_struct("SignInExternal").field("email", email).finish(),
            Self::CancelSignIn => f.write_str("CancelSignIn"),
            Self::Room(command) => f.debug_tuple("Room").field(command).finish(),
            Self::SignOut => f.write_str("SignOut"),
        }
    }
}

/// Something the app tells the window. `Debug` never shows the authenticator secret.
#[derive(Clone, PartialEq, Eq)]
pub enum Update {
    /// No device is enrolled yet: show the enrollment screen.
    NeedsEnrollment,
    /// The server accepted the invitation; the person adds this authenticator entry, then types its first code.
    AuthenticatorSetup {
        otpauth_uri: String,
    },
    /// The device is enrolled (or already was): show sign-in for this server.
    Enrolled {
        server: String,
    },
    /// Signed in; the rooms the person follows.
    SignedIn {
        email: String,
        rooms: Vec<String>,
    },
    /// The current messages of a room.
    Snapshot {
        room: String,
        shown: Vec<Shown>,
    },
    Recovered {
        room: String,
    },
    Gap {
        room: String,
        notice: crewcraft_client_core::room_view::GapNotice,
    },
    Unread {
        room: String,
        unread: u32,
    },
    /// The server's count can remain nonzero for the selected room after another device rewinds it (T344).
    ReadState {
        room: String,
        unread: u64,
    },
    /// An unread action was confirmed and read back; leave the conversation without clearing its badge (T344).
    MarkedUnread {
        room: String,
    },
    /// The email address last used to sign in on this device, to fill in the sign-in form.
    LastEmail(String),
    /// What a message search found (task T320c), newest first.
    SearchResults {
        query: String,
        results: Vec<SearchResult>,
    },
    /// A file uploaded to `room`, to attach to the next post there (task T330e).
    Uploaded {
        room: String,
        file: FileChip,
    },
    /// The files each message of `room` carries, by cursor (task T330e).
    Attachments {
        room: String,
        files: Vec<(u64, Vec<FileChip>)>,
    },
    /// Each reply's parent in `room`, by the reply's cursor (task T340b).
    Threads {
        room: String,
        parents: Vec<(u64, u64)>,
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
    /// An image file's bytes for its preview; empty when they could not be fetched (task T333).
    Preview {
        file: [u8; 16],
        bytes: Vec<u8>,
    },
    /// `room`'s open call (or none) and its call history lines by cursor (task T360a2).
    Calls {
        room: String,
        open: Option<crewcraft_client_core::room_view::OpenCall>,
        lines: Vec<(u64, String)>,
    },
    /// This app joined call `call` of `room` (`Some`), or left its call there (`None`), with why when it did not choose
    /// to (task T360a2).
    InCall {
        room: String,
        call: Option<u64>,
        reason: Option<String>,
    },
    /// This app's call in `room` is end-to-end encrypted under key id `kid`, with the sender keys of `from` received
    /// (task T360d3).
    CallSecurity {
        room: String,
        call: u64,
        kid: u64,
        from: Vec<String>,
    },
    /// `room` is an archive room (task T350d2): read-only, with its imported messages' original times by cursor.
    Archive {
        room: String,
        times: Vec<(u64, u64)>,
    },
    /// The archive room `archive` continues in `room` (task T352): list it and open it.
    Continued {
        archive: String,
        room: String,
    },
    /// The lines in `room` that link back to the archives it continues: `(cursor, archive, text)` (task T352).
    Continuations {
        room: String,
        lines: Vec<(u64, String, String)>,
    },
    /// Who reacted to each message of `room` with what (task T341b): by cursor, each reaction code with the people.
    Reactions {
        room: String,
        reactions: crewcraft_ui_model::RoomReactions,
    },
    /// The person's own settings for a room: pinned to the top, muted, hidden (T346).
    RoomSettings {
        room: String,
        settings: crewcraft_client_core::room_view::RoomSettings,
    },
    /// Current pin metadata, including a body outside the held room history page (T343).
    Pin {
        room: String,
        pinned: Option<crewcraft_client_core::room_view::PinnedMessage>,
    },
    /// Every readable saved message, resolved against its current state (T343).
    SavedMessages {
        messages: Vec<crewcraft_proto::request::SavedMessage>,
    },
    /// Activity counters or a filtered snapshot, tagged with the selection that requested it (T347).
    Activity {
        filter: ActivityFilter,
        snapshot: ActivitySnapshot,
    },
    ActivityFailed {
        text: String,
        refresh: bool,
    },
    ActivityReset,
    /// The app was opened from an invitation link (task T405): fill in the enrollment form's link field. Ignored
    /// unless the enrollment screen is showing. `Debug` does not show the link, which holds a one-time secret.
    InvitationLink(Zeroizing<String>),
    /// The organization's sign-in page is open in the browser (task T611h): say so, with a way to cancel. Ignored
    /// unless a sign-in is in progress.
    WaitingForBrowser,
    /// Something failed; the text is shown to the person as written.
    Failed(String),
    SignedOut,
}

impl fmt::Debug for Update {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeedsEnrollment => f.write_str("NeedsEnrollment"),
            Self::AuthenticatorSetup { .. } => f.write_str("AuthenticatorSetup { .. }"),
            Self::Enrolled { server } => f.debug_struct("Enrolled").field("server", server).finish(),
            Self::SignedIn { email, rooms } => f.debug_struct("SignedIn").field("email", email).field("rooms", rooms).finish(),
            Self::Snapshot { room, shown } => f.debug_struct("Snapshot").field("room", room).field("rows", &shown.len()).finish(),
            Self::Unread { room, unread } => f.debug_struct("Unread").field("room", room).field("unread", unread).finish(),
            Self::ReadState { room, unread } => f.debug_struct("ReadState").field("room", room).field("unread", unread).finish(),
            Self::Recovered { room } => f.debug_struct("Recovered").field("room", room).finish(),
            Self::Gap { room, notice } => f.debug_struct("Gap").field("room", room).field("notice", notice).finish(),
            Self::MarkedUnread { room } => f.debug_struct("MarkedUnread").field("room", room).finish(),
            Self::LastEmail(email) => f.debug_tuple("LastEmail").field(email).finish(),
            Self::SearchResults { query, results } => f.debug_struct("SearchResults").field("query", query).field("results", &results.len()).finish(),
            Self::Uploaded { room, file } => f.debug_struct("Uploaded").field("room", room).field("name", &file.name).finish(),
            Self::Attachments { room, files } => f.debug_struct("Attachments").field("room", room).field("messages", &files.len()).finish(),
            Self::Threads { room, parents } => f.debug_struct("Threads").field("room", room).field("replies", &parents.len()).finish(),
            Self::Files { files } => f.debug_struct("Files").field("files", &files.len()).finish(),
            Self::Preview { file, bytes } => f.debug_struct("Preview").field("file", &file[0]).field("bytes", &bytes.len()).finish(),
            Self::Storage { used, quota } => f.debug_struct("Storage").field("used", used).field("quota", quota).finish(),
            Self::Calls { room, open, lines } => {
                f.debug_struct("Calls").field("room", room).field("open", &open.as_ref().map(|c| c.call)).field("lines", &lines.len()).finish()
            }
            Self::CallSecurity { room, call, kid, from } => {
                f.debug_struct("CallSecurity").field("room", room).field("call", call).field("kid", kid).field("from", &from.len()).finish()
            }
            Self::InCall { room, call, .. } => f.debug_struct("InCall").field("room", room).field("call", call).finish(),
            Self::Archive { room, times } => f.debug_struct("Archive").field("room", room).field("times", &times.len()).finish(),
            Self::Continued { archive, room } => f.debug_struct("Continued").field("archive", archive).field("room", room).finish(),
            Self::Continuations { room, lines } => f.debug_struct("Continuations").field("room", room).field("lines", &lines.len()).finish(),
            Self::Reactions { room, reactions } => f.debug_struct("Reactions").field("room", room).field("messages", &reactions.len()).finish(),
            Self::RoomSettings { room, settings } => f.debug_struct("RoomSettings").field("room", room).field("settings", settings).finish(),
            Self::Pin { room, pinned } => f.debug_struct("Pin").field("room", room).field("target", &pinned.as_ref().map(|pin| pin.target)).finish(),
            Self::SavedMessages { messages } => f.debug_struct("SavedMessages").field("messages", &messages.len()).finish(),
            Self::Activity { filter, snapshot } => {
                f.debug_struct("Activity").field("filter", filter).field("head", &snapshot.head).field("items", &snapshot.items.len()).finish()
            }
            Self::ActivityFailed { text, refresh } => f.debug_struct("ActivityFailed").field("text", text).field("refresh", refresh).finish(),
            Self::ActivityReset => f.write_str("ActivityReset"),
            Self::InvitationLink(_) => f.write_str("InvitationLink(..)"),
            Self::WaitingForBrowser => f.write_str("WaitingForBrowser"),
            Self::Failed(text) => f.debug_tuple("Failed").field(text).finish(),
            Self::SignedOut => f.write_str("SignedOut"),
        }
    }
}

/// A file, as a message or the composer shows it (task T330e).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChip {
    pub file: [u8; 16],
    pub name: String,
    pub size: u64,
}

impl FileChip {
    /// The chip's text: the name and a short size, such as `report.pdf (1.2 MB)`. No emoji: the bundled font has
    /// none, and a missing glyph would draw as a box.
    pub fn label(&self) -> String {
        format!("{} ({})", self.name, short_size(self.size))
    }
}

/// A size in bytes, KB or MB, one decimal for the larger units.
pub fn short_size(bytes: u64) -> String {
    match bytes {
        0..1024 => format!("{bytes} B"),
        1024..1_048_576 => format!("{:.1} KB", bytes as f64 / 1024.0),
        1_048_576..1_073_741_824 => format!("{:.1} MB", bytes as f64 / 1_048_576.0),
        _ => format!("{:.1} GB", bytes as f64 / 1_073_741_824.0),
    }
}

/// One message a search found (task T320c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    pub room: String,
    pub cursor: u64,
    pub author: String,
    pub snippet: String,
}

/// Below this width (in points) the title bar leaves out the server's name, so its search boxes and Sign out fit.
pub const TITLE_BAR_SERVER_WIDTH: f32 = 1050.0;

/// The longest message search the window sends, in bytes (`proto::request::MAX_QUERY`).
pub const MAX_SEARCH_BYTES: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Enroll,
    Authenticator,
    SignIn,
    Chat,
}

/// The whole window's state.
#[derive(Default)]
pub struct Window {
    screen: Option<Screen>,
    server: String,
    email: String,
    otpauth_uri: String,
    link: Zeroizing<String>,
    password: Zeroizing<String>,
    code: Zeroizing<String>,
    rooms: RoomList,
    composer: Composer,
    feeds: HashMap<String, Vec<FeedRow>>,
    /// The text box's copy of the open room's draft; synced into `composer` every frame.
    draft: String,
    notice: Option<String>,
    /// A change that happened away from focus (a new message in another room, the connection coming back), shown in
    /// the status line and announced by screen readers through a live region.
    announcement: Option<String>,
    busy: bool,
    /// An external sign-in is waiting for the person to finish in the browser (T611h).
    waiting_for_browser: bool,
    actions: Vec<Action>,
    /// Which pane a phone-width window shows (one at a time, T402).
    phone_pane: PhonePane,
    /// The title-bar name: the organization's, or empty for "CrewCraft" (T314).
    title: String,
    /// The room search box's text: the list pane shows only rooms whose name contains it (T315).
    room_filter: String,
    /// The bubble colours from the theme, or `None` to derive them from egui's visuals (T315).
    bubbles: Option<appearance::BubbleColors>,
    /// The person's own message they clicked, by cursor: its Edit and Delete show under it (T316).
    selected_message: Option<u64>,
    /// Return real keyboard focus to the room after a confirmed unread action closes its conversation (T344).
    focus_room: Option<String>,
    /// The person's own room settings as the worker last reported them, kept across a new room list (T346).
    room_settings: HashMap<String, crewcraft_client_core::room_view::RoomSettings>,
    /// Asking "Delete this message?" for this selected message (T316).
    confirm_delete: bool,
    /// The composer is replacing the text of this message, `(room, cursor)` (T316).
    editing: Option<(String, u64)>,
    /// The message search box's text (T320c).
    message_query: String,
    /// The last search's query and what it found; while set, the main pane shows the results (T320c).
    results: Option<(String, Vec<SearchResult>)>,
    /// Files uploaded to attach to the next post, per room (T330e).
    pending_files: HashMap<String, Vec<FileChip>>,
    /// The typed path of a file to attach, while the composer's path entry is open: attaching without dragging.
    attach_path: Option<String>,
    /// Give keyboard focus to the path entry (`Some(true)`) or back to the Attach file button (`Some(false)`) when they
    /// are next drawn.
    attach_focus: Option<bool>,
    /// The files each message carries, per room and cursor (T330e).
    message_files: HashMap<String, std::collections::BTreeMap<u64, Vec<FileChip>>>,
    /// Each reply's parent, per room, by the reply's cursor (T340b).
    threads: HashMap<String, std::collections::BTreeMap<u64, u64>>,
    /// The thread shown beside the conversation: `(room, parent)` (T340b).
    open_thread: Option<(String, u64)>,
    /// The thread composer's text (T340b).
    thread_draft: String,
    /// The message a search result opened, `(room, cursor)`: highlighted, and scrolled to once (T321).
    focus: Option<(String, u64)>,
    focus_scrolled: bool,
    /// Who reacted to each message with what, per room and cursor (T341b).
    reactions: HashMap<String, std::collections::BTreeMap<u64, crewcraft_ui_model::MessageReactions>>,
    /// The Files area (T331b): `Some` while it is open, with the list once it arrived.
    files_view: Option<Option<Vec<crewcraft_proto::request::ListedFile>>>,
    /// The room's authoritative pinned message (T343).
    pins: HashMap<String, crewcraft_client_core::room_view::PinnedMessage>,
    /// Current saved-message references, with no stale copies of edited or deleted bodies (T343).
    saved_messages: Option<Vec<crewcraft_proto::request::SavedMessage>>,
    saved_view: bool,
    activity_filter: Option<ActivityFilter>,
    activity_snapshot: Option<ActivitySnapshot>,
    activity_counters: Option<(u64, u64)>,
    activity_unread: u16,
    activity_marking: Option<u64>,
    activity_failed: bool,
    gaps: HashMap<String, crewcraft_client_core::room_view::GapNotice>,
    /// The bytes the person's files take, and their quota (T332b).
    storage: Option<(u64, u64)>,
    /// Image previews (T333): asked for, decoded and waiting for a texture, shown, or given up on.
    previews: HashMap<[u8; 16], Preview>,
    /// Each room's open call (T360a2).
    open_calls: HashMap<String, crewcraft_client_core::room_view::OpenCall>,
    /// Each room's call history lines by cursor (T360a2).
    call_lines: HashMap<String, std::collections::BTreeMap<u64, String>>,
    /// The call this app is in: `(room, call)` (T360a2).
    in_call: Option<(String, u64)>,
    /// Whose sender keys reached this app in the call it is in (T360d3).
    call_security: Option<(u64, Vec<String>)>,
    /// Archive rooms (T350d2): listed under Archive, read-only.
    archived: std::collections::HashSet<String>,
    /// Imported messages' original times, per archive room and cursor (T350d2).
    sent_times: HashMap<String, std::collections::BTreeMap<u64, u64>>,
    /// The lines that link back to the archives each room continues: by cursor, the archive and the text (T352).
    continued: HashMap<String, std::collections::BTreeMap<u64, (String, String)>>,
}

/// What a message is drawn with (T340b): who is reading, the theme's colours, which message is selected, the files and
/// the reply counts of the room.
struct Bubbles<'a> {
    me: &'a str,
    colors: Option<appearance::BubbleColors>,
    selected: Option<u64>,
    confirming: bool,
    files: &'a std::collections::BTreeMap<u64, Vec<FileChip>>,
    /// Image previews by file id (T333).
    previews: &'a HashMap<[u8; 16], egui::TextureHandle>,
    replies: &'a std::collections::BTreeMap<u64, usize>,
    /// Who reacted to each message with what (T341b).
    reactions: &'a std::collections::BTreeMap<u64, crewcraft_ui_model::MessageReactions>,
    pinned: Option<u64>,
    saved: &'a std::collections::BTreeSet<u64>,
    /// Whether reply, edit and delete controls are offered here (not inside the thread pane).
    actions: bool,
    /// An archive room (T350d2): nothing can be selected, replied to or reacted to.
    read_only: bool,
    /// Imported messages' original times, by cursor (T350d2).
    times: &'a std::collections::BTreeMap<u64, u64>,
    /// The message to highlight (a search result), and whether to scroll to it (T321).
    focus: Option<u64>,
    scroll: bool,
}

/// What the person did to a message in the feed (T316).
enum MessageAction {
    /// Clicked one of their own messages: select it, or clear the selection.
    Select(u64),
    /// Save a message's file (T330e).
    Save(FileChip),
    /// Open the thread of the message at this cursor (T340b).
    OpenThread(u64),
    /// Add (`true`) or take back a reaction on the message at this cursor (T341b).
    React(u64, u8, bool),
    Pin(u64, bool),
    SaveMessage(u64, bool),
    MarkUnread(u64),
    Edit(u64, String),
    AskDelete,
    Delete(u64),
    Keep,
}

/// The panes of the phone layout (REQUIREMENTS 2.9): the room list, one conversation, and the account.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PhonePane {
    #[default]
    Chats,
    Conversation,
    Account,
}

/// Below this width (in points) the chat screen uses the phone layout.
pub const PHONE_MAX_WIDTH: f32 = 600.0;
/// The smallest height of anything tapped in the phone layout, in points.
pub const TOUCH_TARGET: f32 = 44.0;

impl Window {
    /// The enrollment screen until the app says otherwise.
    pub fn new() -> Self {
        Self::default()
    }

    /// Show `name` in the title bar and on the sign-in screen instead of "CrewCraft" (an organization's name, T314).
    /// Empty restores "CrewCraft".
    pub fn set_title(&mut self, name: &str) {
        self.title = name.trim().to_owned();
    }

    /// Draw message bubbles in the theme's `bubble-mine` and `bubble-other` colours (T315).
    pub fn set_bubble_colors(&mut self, colors: appearance::BubbleColors) {
        self.bubbles = Some(colors);
    }

    /// The title-bar name.
    pub fn title(&self) -> &str {
        if self.title.is_empty() { "CrewCraft" } else { &self.title }
    }

    /// The pane the phone layout shows.
    pub fn phone_pane(&self) -> PhonePane {
        self.phone_pane
    }

    pub fn screen(&self) -> Screen {
        self.screen.unwrap_or(Screen::Enroll)
    }

    /// The message the composer is editing, `(room, cursor)` (T316).
    pub fn editing(&self) -> Option<(&str, u64)> {
        self.editing.as_ref().map(|(room, cursor)| (room.as_str(), *cursor))
    }

    /// Whether the sign-in screen is waiting for the person to finish signing in in the browser (T611h).
    pub fn waiting_for_browser(&self) -> bool {
        self.waiting_for_browser
    }

    /// The text shown above the current screen (the last failure or hint), if any.
    pub fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    /// Everything the window asked for since the last call, oldest first.
    pub fn take_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.actions)
    }

    pub fn apply(&mut self, update: Update) {
        // A link to fill in changes nothing else: an enrollment in progress stays in progress.
        if let Update::InvitationLink(link) = update {
            if self.screen() == Screen::Enroll && !self.busy {
                self.link = link;
            }
            return;
        }
        // The browser page opening changes nothing but what the sign-in screen says: the sign-in is still in progress.
        if update == Update::WaitingForBrowser {
            self.waiting_for_browser = self.busy && matches!(self.screen(), Screen::SignIn | Screen::Enroll);
            return;
        }
        self.busy = false;
        self.waiting_for_browser = false;
        match update {
            Update::NeedsEnrollment => self.go(Screen::Enroll),
            Update::AuthenticatorSetup { otpauth_uri } => {
                self.otpauth_uri = otpauth_uri;
                self.go(Screen::Authenticator);
            }
            Update::Enrolled { server } => {
                self.server = server;
                self.otpauth_uri.clear();
                self.go(Screen::SignIn);
            }
            Update::SignedIn { email, rooms } => {
                // Signed in again while the chat was showing: the worker resumed the session after a lost connection.
                if self.screen() == Screen::Chat {
                    self.announce("Connected to the server again.".to_owned());
                }
                self.email = email;
                self.pins.clear();
                self.saved_messages = None;
                self.saved_view = false;
                self.activity_filter = None;
                self.activity_snapshot = None;
                self.activity_counters = None;
                self.activity_unread = 0;
                self.activity_marking = None;
                self.activity_failed = false;
                self.rooms = RoomList::new();
                for room in &rooms {
                    self.rooms.add(room);
                    if let Some(settings) = self.room_settings.get(room) {
                        self.rooms.set_settings(room, *settings);
                    }
                }
                self.go(Screen::Chat);
                if let Some(first) = self.rooms.rows().first().map(|row| row.name.clone()) {
                    self.open_room(&first, false);
                }
            }
            Update::Snapshot { room, shown } => {
                self.feeds.insert(room, feed_rows(&shown));
            }
            Update::Gap { room, notice } => {
                self.gaps.insert(room, notice);
            }
            Update::Recovered { room } => {
                self.message_files.remove(&room);
                self.threads.remove(&room);
                self.reactions.remove(&room);
                self.archived.remove(&room);
                self.sent_times.remove(&room);
                self.open_calls.remove(&room);
                self.call_lines.remove(&room);
                self.continued.remove(&room);
                if self.rooms.selected() == Some(room.as_str()) {
                    self.selected_message = None;
                }
                if self.open_thread.as_ref().is_some_and(|(of, _)| of == &room) {
                    self.open_thread = None;
                }
            }
            Update::Unread { room, unread } => {
                let before = self.rooms.rows().into_iter().find(|row| row.name == room).map(|row| row.unread);
                let away = self.rooms.selected() != Some(room.as_str()) && !self.archived.contains(&room);
                if self.rooms.set_unread(&room, unread) && away && before.is_some_and(|before| unread > before) {
                    self.announce(format!("New messages in {room}: {unread} unread"));
                }
            }
            Update::ReadState { room, unread } => {
                self.rooms.set_read_state(&room, unread);
            }
            Update::RoomSettings { room, settings } => {
                let was_hidden = self.rooms.settings(&room).hidden;
                self.room_settings.insert(room.clone(), settings);
                self.rooms.set_settings(&room, settings);
                // A room the person hides leaves the list, and its conversation closes with it. A room already hidden
                // and opened from the room search stays open when its settings are reported again.
                if settings.hidden && !was_hidden && self.rooms.selected() == Some(room.as_str()) {
                    self.rooms.clear_selection(&room);
                    self.selected_message = None;
                    self.open_thread = None;
                    self.phone_pane = PhonePane::Chats;
                }
            }
            Update::MarkedUnread { room } => {
                if self.rooms.selected() == Some(room.as_str()) {
                    self.rooms.clear_selection(&room);
                    self.selected_message = None;
                    self.open_thread = None;
                    self.phone_pane = PhonePane::Chats;
                    self.focus_room = Some(room);
                }
            }
            Update::SearchResults { query, results } => self.results = Some((query, results)),
            Update::Uploaded { room, file } => self.pending_files.entry(room).or_default().push(file),
            Update::Attachments { room, files } => {
                self.message_files.insert(room, files.into_iter().collect());
            }
            Update::Threads { room, parents } => {
                self.threads.insert(room, parents.into_iter().collect());
            }
            Update::Storage { used, quota } => self.storage = Some((used, quota)),
            Update::Preview { file, bytes } => {
                let state = match decode_preview(&bytes) {
                    Some(image) => Preview::Decoded(image),
                    None => Preview::Failed,
                };
                self.previews.insert(file, state);
            }
            Update::Files { files } => {
                if self.files_view.is_some() {
                    self.files_view = Some(Some(files));
                }
            }
            Update::Calls { room, open, lines } => {
                // Ring: a call someone else started that this app did not know about (T360a2).
                if let Some(open) = &open
                    && open.started_by != self.email
                    && self.open_calls.get(&room).is_none_or(|known| known.call != open.call)
                    && self.in_call.as_ref().is_none_or(|(_, call)| *call != open.call)
                {
                    self.notice = Some(format!("{} started a call in {room}.", open.started_by));
                }
                match open {
                    Some(open) => {
                        self.open_calls.insert(room.clone(), open);
                    }
                    None => {
                        self.open_calls.remove(&room);
                    }
                }
                self.call_lines.insert(room, lines.into_iter().collect());
            }
            Update::CallSecurity { room, call, from, .. } => {
                if self.in_call.as_ref().is_some_and(|(r, c)| *r == room && *c == call) {
                    self.call_security = Some((call, from));
                }
            }
            Update::InCall { room, call, reason } => {
                if call.is_none() {
                    self.call_security = None;
                }
                self.in_call = call.map(|call| (room, call));
                if let Some(reason) = reason {
                    self.notice = Some(reason);
                }
            }
            Update::Archive { room, times } => {
                self.archived.insert(room.clone());
                self.sent_times.insert(room, times.into_iter().collect());
            }
            Update::Continued { room, .. } => {
                self.rooms.add(&room);
                self.phone_pane = PhonePane::Conversation;
                self.open_room(&room, true);
            }
            Update::Continuations { room, lines } => {
                self.continued.insert(room, lines.into_iter().map(|(cursor, archive, text)| (cursor, (archive, text))).collect());
            }
            Update::Reactions { room, reactions } => {
                self.reactions.insert(room, reactions.into_iter().collect());
            }
            Update::Pin { room, pinned } => match pinned {
                Some(pinned) => {
                    self.pins.insert(room, pinned);
                }
                None => {
                    self.pins.remove(&room);
                }
            },
            Update::SavedMessages { messages } => self.saved_messages = Some(messages),
            Update::Activity { filter, snapshot } => {
                if self.screen() != Screen::Chat {
                    return;
                }
                let fresh = self.activity_counters.is_none_or(|(head, seen)| snapshot.head >= head && snapshot.seen >= seen);
                if fresh {
                    self.activity_counters = Some((snapshot.head, snapshot.seen));
                    self.activity_unread = snapshot.unread;
                    if self.activity_marking.is_some_and(|through| snapshot.seen >= through) {
                        self.activity_marking = None;
                    }
                    if self.activity_filter == Some(filter) {
                        self.activity_snapshot = Some(snapshot);
                        self.activity_failed = false;
                    }
                }
            }
            Update::ActivityFailed { text, refresh } => {
                self.notice = Some(text);
                self.activity_marking = None;
                if refresh {
                    self.activity_snapshot = None;
                    self.activity_failed = self.activity_filter.is_some();
                }
            }
            Update::ActivityReset => {
                self.activity_filter = None;
                self.activity_snapshot = None;
                self.activity_counters = None;
                self.activity_unread = 0;
                self.activity_marking = None;
                self.activity_failed = false;
            }
            Update::LastEmail(email) => {
                if self.email.is_empty() {
                    self.email = email;
                }
            }
            Update::InvitationLink(_) | Update::WaitingForBrowser => {}
            Update::Failed(text) => self.notice = Some(text),
            Update::SignedOut => {
                self.announcement = None;
                self.activity_filter = None;
                self.activity_snapshot = None;
                self.activity_counters = None;
                self.activity_unread = 0;
                self.activity_marking = None;
                self.activity_failed = false;
                self.phone_pane = PhonePane::Chats;
                self.selected_message = None;
                self.focus_room = None;
                self.room_settings.clear();
                self.editing = None;
                self.results = None;
                self.message_query.clear();
                self.pending_files.clear();
                self.attach_path = None;
                self.attach_focus = None;
                self.message_files.clear();
                self.threads.clear();
                self.reactions.clear();
                self.archived.clear();
                self.sent_times.clear();
                self.open_calls.clear();
                self.files_view = None;
                self.pins.clear();
                self.saved_messages = None;
                self.saved_view = false;
                self.storage = None;
                self.previews.clear();
                self.call_lines.clear();
                self.continued.clear();
                self.in_call = None;
                self.open_thread = None;
                self.thread_draft.clear();
                self.feeds.clear();
                self.gaps.clear();
                self.rooms = RoomList::new();
                self.composer = Composer::new();
                self.draft.clear();
                self.go(Screen::SignIn);
            }
        }
    }

    /// Draw the current screen. Call once per frame.
    /// The app hands over the whole window area; each screen paints its own panels.
    pub fn ui(&mut self, ui: &mut Ui) {
        self.prepare_previews(ui.ctx());
        let screen = self.screen();
        if screen == Screen::Chat {
            // The status line: the last problem or hint, and the last change away from focus. Both are live regions,
            // so a screen reader speaks them when they appear or change, wherever focus is.
            if self.notice.is_some() || self.announcement.is_some() {
                egui::Panel::top("crewcraft-notice").show(ui, |ui| {
                    if let Some(notice) = &self.notice {
                        live_label(ui, "crewcraft-notice-text", RichText::new(notice).color(ui.visuals().warn_fg_color));
                    }
                    if let Some(announcement) = &self.announcement {
                        live_label(ui, "crewcraft-announcement", RichText::new(announcement));
                    }
                });
            }
            self.chat_ui(ui);
            return;
        }
        egui::CentralPanel::default_margins().show(ui, |ui| {
            ui.add_space((ui.available_height() * 0.12).min(80.0));
            ui.vertical_centered(|ui| {
                // On a phone the form is as wide as the screen: a wider one would push its fields past both edges,
                // where egui shows no text cursor and so never asks for the on-screen keyboard.
                ui.set_max_width(ui.available_width().min(FORM_WIDTH));
                egui::Frame::group(ui.style()).inner_margin(24.0).corner_radius(8.0).show(ui, |ui| {
                    ui.set_width(ui.available_width().min(FORM_WIDTH - 48.0));
                    ui.with_layout(Layout::top_down(Align::Min), |ui| {
                        ui.spacing_mut().item_spacing.y = 8.0;
                        if let Some(notice) = &self.notice {
                            live_label(ui, "crewcraft-notice-text", RichText::new(notice).color(ui.visuals().warn_fg_color));
                        }
                        match screen {
                            Screen::Enroll => self.enroll_ui(ui),
                            Screen::Authenticator => self.authenticator_ui(ui),
                            Screen::SignIn | Screen::Chat => self.sign_in_ui(ui),
                        }
                    });
                });
            });
        });
    }

    /// Say `text` through the status line's live region (rule 4 of the Craft accessibility standard).
    fn announce(&mut self, text: String) {
        self.announcement = Some(text);
    }

    /// What the status line last announced, while it shows.
    pub fn announcement(&self) -> Option<&str> {
        self.announcement.as_deref()
    }

    fn go(&mut self, screen: Screen) {
        self.screen = Some(screen);
        self.notice = None;
        self.code = Zeroizing::default();
    }

    fn enroll_ui(&mut self, ui: &mut Ui) {
        ui.heading("Join a CrewCraft server");
        ui.label("Paste the invitation link your administrator sent you, and choose a password.");
        secret_field(ui, "Invitation link", &mut self.link, false);
        // A link that names the way in offers only that way (T611k); otherwise both are offered.
        let way = crewcraft_enroll::InvitationLink::parse(self.link.trim()).ok().and_then(|link| link.signin());
        if way != Some(crewcraft_enroll::SignInWay::Organization) {
            secret_field(ui, "New password", &mut self.password, true);
            let ready = !self.busy && !self.link.trim().is_empty() && !self.password.is_empty();
            if ui.add_enabled(ready, egui::Button::new("Enroll this device")).clicked() {
                let link = Zeroizing::new(self.link.trim().to_owned());
                self.link = Zeroizing::default();
                let password = std::mem::take(&mut self.password);
                self.busy = true;
                self.actions.push(Action::Enroll { link, password });
            }
        } else {
            ui.label("Your organization signs you in: no password is needed here.");
        }
        if way == Some(crewcraft_enroll::SignInWay::Password) {
            return;
        }
        // An organization whose server signs people in with its own accounts (T611i): only the link is needed; the
        // sign-in, and any second factor, happen on the organization's page in the browser.
        ui.separator();
        if self.waiting_for_browser {
            ui.label("Finish signing in on the page that opened in your browser.");
            if ui.button("Cancel").clicked() {
                self.actions.push(Action::CancelSignIn);
            }
        } else {
            let ready = !self.busy && !self.link.trim().is_empty();
            if ui.add_enabled(ready, egui::Button::new("Enroll with your organization")).clicked() {
                let link = Zeroizing::new(self.link.trim().to_owned());
                self.link = Zeroizing::default();
                self.password = Zeroizing::default();
                self.busy = true;
                self.actions.push(Action::EnrollExternal { link });
            }
        }
    }

    fn authenticator_ui(&mut self, ui: &mut Ui) {
        ui.heading("Set up your authenticator");
        ui.label("Add this entry to your authenticator app, then type the code it shows.");
        let mut uri = self.otpauth_uri.as_str();
        ui.add(TextEdit::singleline(&mut uri).desired_width(f32::INFINITY));
        if ui.button("Copy entry").clicked() {
            ui.ctx().copy_text(self.otpauth_uri.clone());
        }
        secret_field(ui, "Authenticator code", &mut self.code, false);
        let ready = !self.busy && is_code(&self.code);
        if ui.add_enabled(ready, egui::Button::new("Confirm")).clicked() {
            let code = std::mem::take(&mut self.code);
            self.busy = true;
            self.actions.push(Action::ConfirmAuthenticator { code });
        }
    }

    fn sign_in_ui(&mut self, ui: &mut Ui) {
        ui.heading(format!("Sign in to {}", self.title()));
        if !self.server.is_empty() {
            ui.label(format!("Server: {}", self.server));
        }
        let label = ui.label("Email");
        ui.add(TextEdit::singleline(&mut self.email)).labelled_by(label.id);
        secret_field(ui, "Password", &mut self.password, true);
        secret_field(ui, "Authenticator code", &mut self.code, false);
        let ready = !self.busy && !self.email.trim().is_empty() && !self.password.is_empty() && is_code(&self.code);
        if ui.add_enabled(ready, egui::Button::new("Sign in")).clicked() {
            let password = std::mem::take(&mut self.password);
            let code = std::mem::take(&mut self.code);
            self.busy = true;
            self.actions.push(Action::SignIn { email: self.email.trim().to_owned(), password, code });
        }
        // Sign-in through the organization's own page (T611h): only the email is needed here; the password and any
        // second factor are typed on that page, in the browser, never in CrewCraft.
        ui.separator();
        if self.waiting_for_browser {
            ui.label("Finish signing in on the page that opened in your browser.");
            if ui.button("Cancel").clicked() {
                self.actions.push(Action::CancelSignIn);
            }
        } else {
            let ready = !self.busy && !self.email.trim().is_empty();
            if ui.add_enabled(ready, egui::Button::new("Sign in with your organization")).clicked() {
                self.busy = true;
                self.actions.push(Action::SignInExternal { email: self.email.trim().to_owned() });
            }
        }
    }

    fn chat_ui(&mut self, ui: &mut Ui) {
        if ui.available_width() < PHONE_MAX_WIDTH {
            self.phone_chat_ui(ui);
            return;
        }
        egui::Panel::top("crewcraft-title-bar").show(ui, |ui| {
            // In a narrow window the server's name gives way, so the search boxes and Sign out always fit (T320c).
            let show_server = ui.available_width() >= TITLE_BAR_SERVER_WIDTH;
            ui.horizontal(|ui| {
                ui.strong(self.title().to_owned());
                ui.add_space(16.0);
                let label = ui.label("Search rooms");
                ui.add(TextEdit::singleline(&mut self.room_filter).hint_text("Type to filter").desired_width(160.0)).labelled_by(label.id);
                ui.add_space(16.0);
                // Message search (T320c): Enter or the button sends it; the main pane then shows what it found.
                let label = ui.label("Search messages");
                let search =
                    ui.add(TextEdit::singleline(&mut self.message_query).hint_text("Find a message").desired_width(180.0)).labelled_by(label.id);
                let enter = search.lost_focus() && ui.input(|input| input.key_pressed(Key::Enter));
                if ui.button("Search").clicked() || enter {
                    let query = self.message_query.trim();
                    if !query.is_empty() && query.len() <= MAX_SEARCH_BYTES {
                        self.actions.push(Action::Room(Command::Search { query: query.to_owned() }));
                    }
                }
                let total = self.rooms.total_unread();
                if total > 0 {
                    ui.label(format!("{total} unread"));
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Sign out").clicked() {
                        self.actions.push(Action::SignOut);
                    }
                    ui.label(&self.email);
                    if show_server && !self.server.is_empty() {
                        ui.weak(&self.server);
                    }
                });
            });
        });
        // The app bar. Chat is the one area so far; Teams, Calendar, Calls, Files and Apps join it as they ship, so the
        // bar never offers a button that does nothing.
        egui::Panel::left("crewcraft-app-bar").resizable(false).exact_size(72.0).show(ui, |ui| {
            ui.add_space(8.0);
            let activity = self.activity_label();
            if ui.add_sized([ui.available_width(), TOUCH_TARGET], egui::Button::selectable(self.activity_filter.is_some(), activity)).clicked()
                && self.activity_filter.is_none()
            {
                self.open_activity(ActivityFilter::All);
            }
            let total = self.rooms.total_unread();
            let chat = if total > 0 { format!("Chat ({total})") } else { "Chat".to_owned() };
            if ui
                .add_sized(
                    [ui.available_width(), 40.0],
                    egui::Button::selectable(self.files_view.is_none() && !self.saved_view && self.activity_filter.is_none(), chat),
                )
                .clicked()
            {
                self.close_activity();
                self.files_view = None;
                self.saved_view = false;
            }
            // The Files area (T331b): every file in my rooms.
            if ui.add_sized([ui.available_width(), 40.0], egui::Button::selectable(self.files_view.is_some(), "Files")).clicked()
                && self.files_view.is_none()
            {
                self.close_activity();
                self.files_view = Some(None);
                self.saved_view = false;
                self.actions.push(Action::Room(Command::ListFiles));
            }
            if ui.add_sized([ui.available_width(), 40.0], egui::Button::selectable(self.saved_view, "Saved")).clicked() && !self.saved_view {
                self.open_saved();
            }
        });
        if self.activity_filter.is_some() {
            self.activity_ui(ui);
            return;
        }
        if self.saved_view {
            self.saved_ui(ui);
            return;
        }
        if self.files_view.is_some() {
            self.files_ui(ui);
            return;
        }
        egui::Panel::left("crewcraft-rooms").resizable(true).default_size(220.0).show(ui, |ui| {
            ui.add_space(4.0);
            ui.strong("Rooms");
            ui.add_space(4.0);
            let mut open = None;
            let rows = visible_rooms(self.rooms.rows(), &self.room_filter);
            // A room search also finds the rooms the person hid (T346).
            let hidden = if self.room_filter.trim().is_empty() { Vec::new() } else { visible_rooms(self.rooms.hidden_rows(), &self.room_filter) };
            if rows.is_empty() && hidden.is_empty() {
                ui.weak(if self.room_filter.trim().is_empty() { "No rooms yet." } else { "No room matches." });
            }
            let (archive, rows): (Vec<_>, Vec<_>) = rows.into_iter().partition(|row| self.archived.contains(&row.name));
            ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                for row in rows {
                    let settings = self.rooms.settings(&row.name);
                    let text = room_label(&row, settings);
                    let text = if row.unread > 0 && !settings.muted { RichText::new(text).strong() } else { RichText::new(text) };
                    let response = ui.add_sized([ui.available_width(), 28.0], egui::Button::selectable(row.selected, text));
                    if self.focus_room.as_deref() == Some(row.name.as_str()) {
                        response.request_focus();
                        self.focus_room = None;
                    }
                    if response.clicked() {
                        open = Some(row.name);
                    }
                }
                // Archive rooms, under their own heading (T350d2).
                if !archive.is_empty() {
                    ui.add_space(10.0);
                    ui.strong("Archive");
                    for row in archive {
                        let response = ui.add_sized([ui.available_width(), 28.0], egui::Button::selectable(row.selected, row.name.clone()));
                        if self.focus_room.as_deref() == Some(row.name.as_str()) {
                            response.request_focus();
                            self.focus_room = None;
                        }
                        if response.clicked() {
                            open = Some(row.name);
                        }
                    }
                }
                // Hidden rooms the room search found, under their own heading (T346).
                if !hidden.is_empty() {
                    ui.add_space(10.0);
                    ui.strong("Hidden");
                    for row in hidden {
                        let text = room_label(&row, self.rooms.settings(&row.name));
                        if ui.add_sized([ui.available_width(), 28.0], egui::Button::selectable(row.selected, text)).clicked() {
                            open = Some(row.name);
                        }
                    }
                }
            });
            if let Some(room) = open {
                self.open_room(&room, true);
            }
        });
        let Some(room) = self.rooms.selected().map(str::to_owned) else {
            egui::CentralPanel::default_margins().show(ui, |ui| {
                ui.label(if self.rooms.rows().is_empty() { "You are not in any rooms yet." } else { "Choose a room to read." });
            });
            return;
        };
        if self.results.is_some() {
            self.results_ui(ui);
            return;
        }
        egui::Panel::top("crewcraft-conversation-header").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading(&room);
                self.call_controls(ui, &room);
            });
            self.pin_bar(ui, &room);
            self.read_controls(ui, &room);
            self.room_settings_controls(ui, &room);
            self.gap_ui(ui, &room);
        });
        egui::Panel::bottom("crewcraft-composer").show(ui, |ui| self.composer_ui(ui, &room));
        // A thread opens beside the conversation (T340b).
        if let Some(parent) = self.open_thread.as_ref().filter(|(thread_room, _)| *thread_room == room).map(|(_, parent)| *parent) {
            egui::Panel::right("crewcraft-thread").resizable(true).default_size(340.0).show(ui, |ui| self.thread_ui(ui, &room, parent));
        }
        let me = self.email.clone();
        let mut action = None;
        let files = self.message_files.get(&room).cloned().unwrap_or_default();
        let previews = self.shown_previews();
        let replies = self.reply_counts(&room);
        let reactions = self.reactions.get(&room).cloned().unwrap_or_default();
        let saved = self.saved_in(&room);
        let times = self.sent_times.get(&room).cloned().unwrap_or_default();
        let focus = self.focus.as_ref().filter(|(r, _)| *r == room).map(|(_, cursor)| *cursor);
        let mut focus_found = false;
        let read_only = self.archived.contains(&room);
        let threads = self.threads.get(&room).cloned().unwrap_or_default();
        let present = self.message_cursors(&room);
        let call_lines = self.system_lines(&room);
        let look = Bubbles {
            me: &me,
            colors: self.bubbles,
            selected: self.selected_message,
            confirming: self.confirm_delete,
            files: &files,
            previews: &previews,
            replies: &replies,
            reactions: &reactions,
            pinned: self.pins.get(&room).map(|pin| pin.target),
            saved: &saved,
            read_only,
            times: &times,
            actions: true,
            focus,
            scroll: !self.focus_scrolled,
        };
        egui::CentralPanel::default_margins().show(ui, |ui| {
            ScrollArea::vertical().stick_to_bottom(focus.is_none() || self.focus_scrolled).auto_shrink(false).show(ui, |ui| {
                // Replies live in their thread, not in the conversation (T340b).
                let mut shown_lines = 0;
                let mut previous_orphan = None;
                for row in self.feeds.get(&room).map(Vec::as_slice).unwrap_or_default() {
                    if let FeedRow::Message { cursor, .. } = row {
                        shown_lines = call_lines_ui(ui, &call_lines, shown_lines, *cursor);
                    }
                    let parent = match row {
                        FeedRow::Message { cursor, .. } => threads.get(cursor).copied(),
                        _ => None,
                    };
                    if parent.is_some_and(|parent| present.contains(&parent)) {
                        continue;
                    }
                    action = orphan_thread_ui(ui, parent, &mut previous_orphan).or(action.take());
                    if matches!(row, FeedRow::Message { cursor, .. } if Some(*cursor) == focus) {
                        focus_found = true;
                    }
                    action = bubble_ui(ui, row, &look).or(action.take());
                }
                call_lines_ui(ui, &call_lines, shown_lines, u64::MAX);
            });
        });
        self.message_action(&room, action);
        if focus_found {
            self.focus_scrolled = true;
        }
        if !self.archived.contains(&room) {
            self.take_dropped_files(ui, &room);
        }
    }

    /// Files dropped onto the window are uploaded to the open room, to attach to the next post (T330e).
    fn take_dropped_files(&mut self, ui: &Ui, room: &str) {
        let dropped = ui.ctx().input(|input| input.raw.dropped_files.clone());
        for file in dropped {
            let path = file.path().to_path_buf();
            // A file dropped on the web has only its name; the desktop app uploads from a real path.
            if path.is_absolute() {
                self.actions.push(Action::Room(Command::Attach { room: room.to_owned(), path }));
            }
        }
    }

    /// The phone layout: one pane at a time, a bottom tab bar, and larger touch targets (T402).
    fn phone_chat_ui(&mut self, ui: &mut Ui) {
        ui.spacing_mut().interact_size.y = TOUCH_TARGET;
        let in_conversation = self.activity_filter.is_none() && self.phone_pane == PhonePane::Conversation && self.rooms.selected().is_some();
        if !in_conversation {
            egui::Panel::bottom("crewcraft-tabs").show(ui, |ui| {
                ui.columns(3, |columns| {
                    let total = self.rooms.total_unread();
                    let chats = if total > 0 { format!("Chats ({total})") } else { "Chats".to_owned() };
                    let size = [columns[0].available_width(), TOUCH_TARGET];
                    let activity = self.activity_label();
                    if columns[0].add_sized(size, egui::Button::selectable(self.activity_filter.is_some(), activity)).clicked()
                        && self.activity_filter.is_none()
                    {
                        self.open_activity(ActivityFilter::All);
                    }
                    if columns[1]
                        .add_sized(size, egui::Button::selectable(self.phone_pane == PhonePane::Chats && self.activity_filter.is_none(), chats))
                        .clicked()
                    {
                        self.close_activity();
                        self.phone_pane = PhonePane::Chats;
                        self.saved_view = false;
                    }
                    if columns[2]
                        .add_sized(size, egui::Button::selectable(self.phone_pane == PhonePane::Account && self.activity_filter.is_none(), "Account"))
                        .clicked()
                    {
                        self.close_activity();
                        self.phone_pane = PhonePane::Account;
                        self.saved_view = false;
                    }
                });
            });
        }
        if self.activity_filter.is_some() {
            self.activity_ui(ui);
            return;
        }
        if self.saved_view {
            self.saved_ui(ui);
            return;
        }
        match self.phone_pane {
            PhonePane::Conversation if in_conversation => {
                let room = self.rooms.selected().map(str::to_owned).unwrap_or_default();
                egui::Panel::top("crewcraft-conversation-bar").show(ui, |ui| {
                    ui.horizontal(|ui| {
                        if ui.add_sized([96.0, TOUCH_TARGET], egui::Button::new("< Chats")).clicked() {
                            self.phone_pane = PhonePane::Chats;
                        }
                        ui.strong(&room);
                        self.call_controls(ui, &room);
                    });
                    self.pin_bar(ui, &room);
                    self.read_controls(ui, &room);
                    self.room_settings_controls(ui, &room);
                    self.gap_ui(ui, &room);
                });
                egui::Panel::bottom("crewcraft-composer").show(ui, |ui| self.composer_ui(ui, &room));
                // On a phone an open thread takes the conversation's place (T340b).
                if let Some(parent) = self.open_thread.as_ref().filter(|(thread_room, _)| *thread_room == room).map(|(_, parent)| *parent) {
                    egui::CentralPanel::default_margins().show(ui, |ui| self.thread_ui(ui, &room, parent));
                    return;
                }
                let me = self.email.clone();
                let mut action = None;
                let files = self.message_files.get(&room).cloned().unwrap_or_default();
                let previews = self.shown_previews();
                let replies = self.reply_counts(&room);
                let reactions = self.reactions.get(&room).cloned().unwrap_or_default();
                let saved = self.saved_in(&room);
                let times = self.sent_times.get(&room).cloned().unwrap_or_default();
                let focus = self.focus.as_ref().filter(|(r, _)| *r == room).map(|(_, cursor)| *cursor);
                let mut focus_found = false;
                let read_only = self.archived.contains(&room);
                let threads = self.threads.get(&room).cloned().unwrap_or_default();
                let present = self.message_cursors(&room);
                let call_lines = self.system_lines(&room);
                let look = Bubbles {
                    me: &me,
                    colors: self.bubbles,
                    selected: self.selected_message,
                    confirming: self.confirm_delete,
                    files: &files,
                    previews: &previews,
                    replies: &replies,
                    reactions: &reactions,
                    pinned: self.pins.get(&room).map(|pin| pin.target),
                    saved: &saved,
                    read_only,
                    times: &times,
                    actions: true,
                    focus,
                    scroll: !self.focus_scrolled,
                };
                egui::CentralPanel::default_margins().show(ui, |ui| {
                    ScrollArea::vertical().stick_to_bottom(focus.is_none() || self.focus_scrolled).auto_shrink(false).show(ui, |ui| {
                        let mut shown_lines = 0;
                        let mut previous_orphan = None;
                        for row in self.feeds.get(&room).map(Vec::as_slice).unwrap_or_default() {
                            if let FeedRow::Message { cursor, .. } = row {
                                shown_lines = call_lines_ui(ui, &call_lines, shown_lines, *cursor);
                            }
                            let parent = match row {
                                FeedRow::Message { cursor, .. } => threads.get(cursor).copied(),
                                _ => None,
                            };
                            if parent.is_some_and(|parent| present.contains(&parent)) {
                                continue;
                            }
                            action = orphan_thread_ui(ui, parent, &mut previous_orphan).or(action.take());
                            if matches!(row, FeedRow::Message { cursor, .. } if Some(*cursor) == focus) {
                                focus_found = true;
                            }
                            action = bubble_ui(ui, row, &look).or(action.take());
                        }
                        call_lines_ui(ui, &call_lines, shown_lines, u64::MAX);
                    });
                });
                self.message_action(&room, action);
                if focus_found {
                    self.focus_scrolled = true;
                }
            }
            PhonePane::Account => {
                egui::CentralPanel::default_margins().show(ui, |ui| {
                    ui.heading("Account");
                    ui.label(format!("Signed in as {}", self.email));
                    if !self.server.is_empty() {
                        ui.label(format!("Server: {}", self.server));
                    }
                    ui.add_space(12.0);
                    if ui.add_sized([ui.available_width(), TOUCH_TARGET], egui::Button::new("Sign out")).clicked() {
                        self.actions.push(Action::SignOut);
                    }
                });
            }
            _ => {
                self.phone_pane = PhonePane::Chats;
                egui::CentralPanel::default_margins().show(ui, |ui| {
                    ui.heading("Your rooms");
                    if ui.add_sized([ui.available_width(), TOUCH_TARGET], egui::Button::new("Saved")).clicked() {
                        self.open_saved();
                    }
                    let rows = self.rooms.rows();
                    if rows.is_empty() {
                        ui.label("You are not in any rooms yet.");
                    }
                    ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                        let mut open = None;
                        let (archive, rows): (Vec<_>, Vec<_>) = rows.into_iter().partition(|row| self.archived.contains(&row.name));
                        for row in rows {
                            let text = room_label(&row, self.rooms.settings(&row.name));
                            let response = ui.add_sized([ui.available_width(), TOUCH_TARGET], egui::Button::selectable(row.selected, text));
                            if self.focus_room.as_deref() == Some(row.name.as_str()) {
                                response.request_focus();
                                self.focus_room = None;
                            }
                            if response.clicked() {
                                open = Some(row.name);
                            }
                        }
                        if !archive.is_empty() {
                            ui.add_space(10.0);
                            ui.strong("Archive");
                            for row in archive {
                                let response =
                                    ui.add_sized([ui.available_width(), TOUCH_TARGET], egui::Button::selectable(row.selected, row.name.clone()));
                                if self.focus_room.as_deref() == Some(row.name.as_str()) {
                                    response.request_focus();
                                    self.focus_room = None;
                                }
                                if response.clicked() {
                                    open = Some(row.name);
                                }
                            }
                        }
                        if let Some(room) = open {
                            self.open_room(&room, true);
                            self.phone_pane = PhonePane::Conversation;
                        }
                    });
                });
            }
        }
    }

    /// What the last message search found, in the main pane (T320c). Opening a result opens its room and closes the
    /// results.
    fn results_ui(&mut self, ui: &mut Ui) {
        let Some((query, results)) = self.results.clone() else { return };
        let mut open = None;
        egui::Panel::top("crewcraft-results-header").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading(format!("Messages matching \"{query}\""));
                if ui.button("Close search").clicked() {
                    self.results = None;
                }
            });
        });
        egui::CentralPanel::default_margins().show(ui, |ui| {
            if results.is_empty() {
                ui.label("No messages match.");
            }
            ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                for result in &results {
                    let who = if result.author.is_empty() { String::new() } else { format!("{} ", result.author) };
                    let text = format!("{who}in {}: {}", result.room, result.snippet);
                    if ui.add(egui::Button::new(text).wrap()).clicked() {
                        open = Some((result.room.clone(), result.cursor));
                    }
                }
            });
        });
        // The room opens on the result's message (T321): a reply opens its thread, on its parent.
        if let Some((room, cursor)) = open {
            self.open_message(&room, cursor);
        }
    }

    fn open_message(&mut self, room: &str, cursor: u64) {
        self.close_activity();
        self.results = None;
        self.saved_view = false;
        self.open_room(room, true);
        let parent = self.threads.get(room).and_then(|threads| threads.get(&cursor)).copied();
        self.open_thread = parent.map(|parent| (room.to_owned(), parent));
        self.focus = Some((room.to_owned(), parent.unwrap_or(cursor)));
        self.focus_scrolled = false;
        self.phone_pane = PhonePane::Conversation;
    }

    fn saved_in(&self, room: &str) -> std::collections::BTreeSet<u64> {
        self.saved_messages.iter().flatten().filter(|message| message.room == room).map(|message| message.cursor).collect()
    }

    fn message_cursors(&self, room: &str) -> std::collections::BTreeSet<u64> {
        self.feeds
            .get(room)
            .into_iter()
            .flatten()
            .filter_map(|row| match row {
                FeedRow::Message { cursor, .. } => Some(*cursor),
                FeedRow::Pending { .. } => None,
            })
            .collect()
    }

    fn gap_ui(&self, ui: &mut Ui, room: &str) {
        if let Some(gap) = self.gaps.get(room) {
            ui.label("Earlier event history could not be replayed.");
            if gap.recovered {
                ui.label("Showing recovered current messages.");
                ui.weak("Earlier call history is unavailable in this window.");
            } else {
                ui.label("Current-state recovery is incomplete; the previous view is shown.");
            }
            if gap.older {
                ui.label("Earlier current messages are not loaded in this window.");
            }
        }
    }

    fn open_saved(&mut self) {
        self.close_activity();
        self.files_view = None;
        self.saved_view = true;
        self.actions.push(Action::Room(Command::ListSaved));
    }

    fn activity_label(&self) -> String {
        if self.activity_unread == 0 { "Activity".to_owned() } else { format!("Activity ({})", self.activity_unread) }
    }

    fn open_activity(&mut self, filter: ActivityFilter) {
        self.activity_filter = Some(filter);
        self.activity_snapshot = None;
        self.activity_failed = false;
        self.files_view = None;
        self.saved_view = false;
        self.phone_pane = PhonePane::Chats;
        self.actions.push(Action::Room(Command::ListActivity { filter }));
    }

    fn close_activity(&mut self) {
        if self.activity_filter.take().is_some() {
            self.activity_snapshot = None;
            self.activity_failed = false;
            self.actions.push(Action::Room(Command::ListActivity { filter: ActivityFilter::Badge }));
        }
    }

    /// Whether the Activity pane is open, and which authoritative selection it is displaying (T347).
    pub fn activity_filter(&self) -> Option<ActivityFilter> {
        self.activity_filter
    }

    fn activity_ui(&mut self, ui: &mut Ui) {
        let Some(filter) = self.activity_filter else { return };
        let mut selection = None;
        let mut mark = None;
        egui::Panel::top("crewcraft-activity-header").show(ui, |ui| {
            ui.heading("Activity");
            ui.horizontal_wrapped(|ui| {
                for (choice, label) in [
                    (ActivityFilter::All, "All activity"),
                    (ActivityFilter::Unread, "Unread"),
                    (ActivityFilter::Mentions, "Mentions"),
                    (ActivityFilter::Saved, "Saved activity"),
                ] {
                    if ui.add(egui::Button::selectable(filter == choice, label).min_size(egui::vec2(0.0, TOUCH_TARGET))).clicked() && filter != choice
                    {
                        selection = Some(choice);
                    }
                }
            });
            ui.horizontal_wrapped(|ui| {
                if ui.button("Refresh activity").clicked() {
                    selection = Some(filter);
                }
                let captured = self.activity_snapshot.as_ref().map(|snapshot| snapshot.head);
                let seen = self.activity_counters.map_or(0, |(_, seen)| seen);
                let enabled = captured.is_some_and(|head| head > seen) && self.activity_marking.is_none();
                if ui.add_enabled(enabled, egui::Button::new("Mark seen")).clicked() {
                    mark = captured;
                }
                if self.activity_marking.is_some() {
                    ui.label("Waiting for confirmation...");
                }
            });
        });
        if let Some(filter) = selection {
            self.open_activity(filter);
        }
        if let Some(through) = mark {
            self.activity_marking = Some(through);
            self.actions.push(Action::Room(Command::MarkActivitySeen { through }));
        }
        let mut destination = None;
        egui::CentralPanel::default_margins().show(ui, |ui| match &self.activity_snapshot {
            None => {
                ui.label(if self.activity_failed {
                    "Activity could not be loaded. Use Refresh activity to try again."
                } else {
                    "Loading activity..."
                });
            }
            Some(snapshot) => {
                if snapshot.items.is_empty() {
                    ui.label("No matching activity.");
                }
                if snapshot.more {
                    ui.weak("Showing the newest matching activity.");
                }
                let seen = self.activity_counters.map_or(snapshot.seen, |(_, seen)| seen);
                ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                    for item in &snapshot.items {
                        egui::Frame::group(ui.style()).show(ui, |ui| {
                            let kind = match &item.kind {
                                ActivityKind::Message { mentioned: true, replied: true } => "Mention and reply".to_owned(),
                                ActivityKind::Message { mentioned: true, .. } => "Mention".to_owned(),
                                ActivityKind::Message { .. } => "Reply to your message".to_owned(),
                                ActivityKind::Reaction { reaction } => {
                                    format!("Reaction: {}", crewcraft_proto::push::reaction_name(*reaction).unwrap_or("Reaction"))
                                }
                                ActivityKind::MissedCall => "Missed call".to_owned(),
                            };
                            ui.strong(kind);
                            ui.label(format!("{} in {}", item.actor, item.room));
                            ui.weak(utc_time(item.at_ms));
                            if item.id > seen {
                                ui.label("New activity");
                            }
                            ui.label(if matches!(item.kind, ActivityKind::MissedCall) {
                                "You missed this call."
                            } else if item.snippet.is_empty() {
                                "Message with attachments"
                            } else {
                                &item.snippet
                            });
                            ui.horizontal_wrapped(|ui| {
                                if ui.add(egui::Button::new("Open room").min_size(egui::vec2(0.0, TOUCH_TARGET))).clicked() {
                                    destination = Some((item.clone(), false));
                                }
                                if item.parent.is_some() && ui.add(egui::Button::new("View thread").min_size(egui::vec2(0.0, TOUCH_TARGET))).clicked()
                                {
                                    destination = Some((item.clone(), true));
                                }
                            });
                        });
                    }
                });
            }
        });
        if let Some((item, thread)) = destination {
            self.open_activity_item(&item, thread);
        }
    }

    fn open_activity_item(&mut self, item: &ActivityItem, thread: bool) {
        self.close_activity();
        self.results = None;
        self.open_room(&item.room, true);
        self.open_thread = if thread { item.parent.map(|parent| (item.room.clone(), parent)) } else { None };
        self.focus = None;
        self.phone_pane = PhonePane::Conversation;
    }

    /// Whether the person's Saved area is open (T343).
    pub fn saved_open(&self) -> bool {
        self.saved_view
    }

    pub fn selected_room(&self) -> Option<&str> {
        self.rooms.selected()
    }

    /// The room's own menu of personal settings (T346): each button says what it will do, so the state never rests on
    /// colour alone. The list changes when the server confirms, through `Update::RoomSettings`.
    fn room_settings_controls(&mut self, ui: &mut Ui, room: &str) {
        use crewcraft_client_core::room_view::RoomSetting;
        let settings = self.rooms.settings(room);
        ui.horizontal_wrapped(|ui| {
            for (setting, on_label, off_label) in [
                (RoomSetting::Pinned, "Pin to top", "Unpin from top"),
                (RoomSetting::Muted, "Mute", "Unmute"),
                (RoomSetting::Hidden, "Hide from list", "Show in list"),
            ] {
                let on = settings.get(setting);
                if ui.button(if on { off_label } else { on_label }).clicked() {
                    self.actions.push(Action::Room(Command::SetRoomSetting { room: room.to_owned(), setting, on: !on }));
                }
            }
        });
    }

    fn read_controls(&mut self, ui: &mut Ui, room: &str) {
        ui.horizontal_wrapped(|ui| {
            if ui.button("Mark as unread").clicked() {
                self.actions.push(Action::Room(Command::MarkUnread { room: room.to_owned(), target: 0 }));
            }
            if ui.button("Mark as read").clicked() {
                self.actions.push(Action::Room(Command::Read { room: room.to_owned() }));
            }
        });
    }

    /// The pin's body comes from the current authoritative snapshot, including pins outside the loaded page (T343).
    fn pin_bar(&mut self, ui: &mut Ui, room: &str) {
        let Some(pin) = self.pins.get(room).cloned() else { return };
        let text = message_text(&pin.html);
        let preview: String = text.chars().take(160).collect();
        let mut open = false;
        let mut unpin = false;
        ui.horizontal_wrapped(|ui| {
            open = ui.add(egui::Button::new(format!("Pinned: {preview}")).wrap()).clicked();
            if !self.archived.contains(room) {
                unpin = ui.small_button("Unpin").clicked();
            }
        });
        if open {
            self.open_message(room, pin.target);
        }
        if unpin {
            self.actions.push(Action::Room(Command::Pin { room: room.to_owned(), target: pin.target, on: false }));
        }
    }

    fn saved_ui(&mut self, ui: &mut Ui) {
        egui::Panel::top("crewcraft-saved-header").show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading("Saved messages");
                if ui.button("Refresh saved messages").clicked() {
                    self.actions.push(Action::Room(Command::ListSaved));
                }
                if ui.button("Close saved messages").clicked() {
                    self.saved_view = false;
                }
            });
        });
        let messages = self.saved_messages.clone();
        let mut open = None;
        let mut remove = None;
        egui::CentralPanel::default_margins().show(ui, |ui| match messages {
            None => {
                ui.label("Loading saved messages...");
            }
            Some(messages) if messages.is_empty() => {
                ui.label("No saved messages yet.");
            }
            Some(messages) => {
                ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                    for message in &messages {
                        ui.push_id((&message.room, message.cursor), |ui| {
                            ui.horizontal(|ui| {
                                ui.strong(&message.author);
                                ui.weak(format!("in {}", message.room));
                                if message.edited {
                                    ui.weak("Edited");
                                }
                            });
                            ui.add(egui::Label::new(message_text(&message.html)).wrap());
                            ui.horizontal(|ui| {
                                if ui.button("Open message").clicked() {
                                    open = Some((message.room.clone(), message.cursor));
                                }
                                if ui.button("Remove from saved").clicked() {
                                    remove = Some((message.room.clone(), message.cursor));
                                }
                            });
                            ui.separator();
                        });
                    }
                });
            }
        });
        if let Some((room, cursor)) = open {
            self.open_message(&room, cursor);
        }
        if let Some((room, target)) = remove {
            self.actions.push(Action::Room(Command::SaveMessage { room, target, on: false }));
        }
    }

    /// The message a search result opened, `(room, cursor)` (T321).
    pub fn focus(&self) -> Option<(&str, u64)> {
        self.focus.as_ref().map(|(room, cursor)| (room.as_str(), *cursor))
    }

    /// Ask for the previews of the open room's images, and turn decoded ones into textures (T333).
    fn prepare_previews(&mut self, ctx: &egui::Context) {
        for (file, state) in self.previews.iter_mut() {
            if let Preview::Decoded(image) = state {
                let texture = ctx.load_texture(format!("preview-{}", file[0]), std::mem::take(image), egui::TextureOptions::LINEAR);
                *state = Preview::Shown(texture);
            }
        }
        let Some(room) = self.rooms.selected().map(str::to_owned) else { return };
        let wanted: Vec<FileChip> = self
            .message_files
            .get(&room)
            .into_iter()
            .flat_map(|files| files.values().flatten())
            .filter(|chip| previewable(chip) && !self.previews.contains_key(&chip.file))
            .cloned()
            .collect();
        for chip in wanted {
            self.previews.insert(chip.file, Preview::Requested);
            self.actions.push(Action::Room(Command::Preview { file: chip.file, size: chip.size }));
        }
    }

    /// The previews ready to draw, by file id (T333).
    fn shown_previews(&self) -> HashMap<[u8; 16], egui::TextureHandle> {
        self.previews
            .iter()
            .filter_map(|(file, state)| match state {
                Preview::Shown(texture) => Some((*file, texture.clone())),
                _ => None,
            })
            .collect()
    }

    /// Whether the image `file` is shown as a preview (T333).
    pub fn previewed(&self, file: &[u8; 16]) -> bool {
        matches!(self.previews.get(file), Some(Preview::Shown(_)))
    }

    /// Whether the Files area is open (T331b).
    pub fn files_open(&self) -> bool {
        self.files_view.is_some()
    }

    /// The Files area (T331b): every file in my rooms, newest first, each with Save and the room it is in.
    fn files_ui(&mut self, ui: &mut Ui) {
        let mut save = None;
        let mut refresh = false;
        egui::Panel::top("crewcraft-files-header").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Files");
                if ui.button("Refresh files").clicked() {
                    refresh = true;
                }
                // Storage use against the quota (T332b).
                if let Some((used, quota)) = self.storage {
                    ui.weak(format!("Storage: {} of {}", short_size(used), short_size(quota)));
                }
            });
        });
        let files = self.files_view.clone().flatten();
        egui::CentralPanel::default_margins().show(ui, |ui| match &files {
            None => {
                ui.label("Loading files...");
            }
            Some(files) if files.is_empty() => {
                ui.label("No files in your rooms yet.");
            }
            Some(files) => {
                ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                    for file in files {
                        ui.horizontal(|ui| {
                            if ui.small_button(format!("Save {}", file.name)).clicked() {
                                save = Some(file.clone());
                            }
                            ui.label(format!("{} ({})", file.name, short_size(file.size)));
                            ui.weak(format!("in {}", file.room));
                        });
                    }
                });
            }
        });
        if refresh {
            self.actions.push(Action::Room(Command::ListFiles));
        }
        if let Some(file) = save {
            self.actions.push(Action::Room(Command::Save { file: file.file, size: file.size, name: file.name, to: None }));
        }
    }

    /// The call this app is in, `(room, call)` (T360a2).
    pub fn in_call(&self) -> Option<(&str, u64)> {
        self.in_call.as_ref().map(|(room, call)| (room.as_str(), *call))
    }

    /// The room header's call controls (T360a2): Call and Video call when the room has no call; "Call in progress"
    /// with Join when it has one this app is not in; "In call" with Leave when it is. An archive room has none.
    fn call_controls(&mut self, ui: &mut Ui, room: &str) {
        if self.archived.contains(room) {
            return;
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| match self.open_calls.get(room) {
            Some(open) if self.in_call.as_ref().is_some_and(|(r, c)| r == room && *c == open.call) => {
                if ui.button("Leave call").clicked() {
                    self.actions.push(Action::Room(Command::CallLeave { room: room.to_owned(), call: open.call }));
                }
                ui.label(format!("In call ({})", open.participants.len()));
                // End-to-end encryption (T360d3): whose keys have arrived, of the others in the call.
                if let Some((_, from)) = self.call_security.as_ref().filter(|(c, _)| *c == open.call) {
                    let others = open.participants.len().saturating_sub(1);
                    ui.weak(format!("End-to-end encrypted: keys from {} of {others}", from.len().min(others)));
                }
            }
            Some(open) => {
                if ui.button("Join call").clicked() {
                    self.actions.push(Action::Room(Command::CallJoin { room: room.to_owned(), call: open.call }));
                }
                ui.label(format!("Call in progress ({})", open.participants.len()));
            }
            None => {
                if ui.button("Video call").clicked() {
                    self.actions.push(Action::Room(Command::CallStart { room: room.to_owned(), video: true }));
                }
                if ui.button("Call").clicked() {
                    self.actions.push(Action::Room(Command::CallStart { room: room.to_owned(), video: false }));
                }
            }
        });
    }

    /// The thread shown beside the conversation, `(room, parent)` (T340b).
    pub fn open_thread(&self) -> Option<(&str, u64)> {
        self.open_thread.as_ref().map(|(room, parent)| (room.as_str(), *parent))
    }

    /// The reply counts of `room`'s messages, by the parent's cursor.
    fn reply_counts(&self, room: &str) -> std::collections::BTreeMap<u64, usize> {
        let mut counts = std::collections::BTreeMap::new();
        for parent in self.threads.get(room).map(|threads| threads.values()).into_iter().flatten() {
            *counts.entry(*parent).or_insert(0) += 1;
        }
        counts
    }

    /// The thread of `parent` in `room`, beside the conversation (T340b): the message, its replies, and a composer.
    fn thread_ui(&mut self, ui: &mut Ui, room: &str, parent: u64) {
        let threads = self.threads.get(room).cloned().unwrap_or_default();
        let rows: Vec<FeedRow> = self
            .feeds
            .get(room)
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter(|row| matches!(row, FeedRow::Message { cursor, .. } if *cursor == parent || threads.get(cursor) == Some(&parent)))
            .cloned()
            .collect();
        ui.horizontal(|ui| {
            ui.strong("Thread");
            if ui.button("Close thread").clicked() {
                self.open_thread = None;
            }
        });
        if !rows.iter().any(|row| matches!(row, FeedRow::Message { cursor, .. } if *cursor == parent)) {
            ui.label("The original message is unavailable in this view.");
        }
        let me = self.email.clone();
        let files = self.message_files.get(room).cloned().unwrap_or_default();
        let previews = self.shown_previews();
        let replies = std::collections::BTreeMap::new();
        let reactions = self.reactions.get(room).cloned().unwrap_or_default();
        let saved = self.saved_in(room);
        let times = self.sent_times.get(room).cloned().unwrap_or_default();
        let read_only = self.archived.contains(room);
        let look = Bubbles {
            me: &me,
            colors: self.bubbles,
            selected: self.selected_message,
            confirming: false,
            files: &files,
            previews: &previews,
            replies: &replies,
            reactions: &reactions,
            pinned: self.pins.get(room).map(|pin| pin.target),
            saved: &saved,
            read_only,
            times: &times,
            actions: false,
            focus: None,
            scroll: false,
        };
        let mut action = None;
        ScrollArea::vertical().max_height(ui.available_height() - 90.0).auto_shrink(false).show(ui, |ui| {
            for row in &rows {
                action = bubble_ui(ui, row, &look).or(action.take());
            }
        });
        self.message_action(room, action);
        if self.archived.contains(room) {
            ui.weak("Archive: read only");
            return;
        }
        let label = ui.label("Reply in thread");
        ui.add(TextEdit::multiline(&mut self.thread_draft).desired_rows(2).desired_width(f32::INFINITY)).labelled_by(label.id);
        if ui.button("Send reply").clicked() {
            let text = self.thread_draft.trim().to_owned();
            if text.chars().count() > crewcraft_ui_model::MAX_DRAFT_CHARS {
                self.notice = Some(format!("Messages can be up to {} characters.", crewcraft_ui_model::MAX_DRAFT_CHARS));
            } else if !text.is_empty() {
                self.thread_draft.clear();
                self.actions.push(Action::Room(Command::Reply { room: room.to_owned(), parent, text }));
            }
        }
    }

    /// The files waiting to be attached to the next post in `room` (T330e).
    pub fn pending_files(&self, room: &str) -> &[FileChip] {
        self.pending_files.get(room).map_or(&[], Vec::as_slice)
    }

    /// The last message search's query and how many messages it found, while the results are showing (T320c).
    pub fn search_results(&self) -> Option<(&str, usize)> {
        self.results.as_ref().map(|(query, results)| (query.as_str(), results.len()))
    }

    /// Apply what the person did to a message (T316).
    fn message_action(&mut self, room: &str, action: Option<MessageAction>) {
        match action {
            None => {}
            Some(MessageAction::Select(cursor)) => {
                self.selected_message = (self.selected_message != Some(cursor)).then_some(cursor);
                self.confirm_delete = false;
            }
            Some(MessageAction::Edit(cursor, text)) => {
                self.editing = Some((room.to_owned(), cursor));
                self.draft = text;
                self.selected_message = None;
            }
            Some(MessageAction::AskDelete) => self.confirm_delete = true,
            Some(MessageAction::Delete(cursor)) => {
                self.actions.push(Action::Room(Command::Delete { room: room.to_owned(), target: cursor }));
                self.selected_message = None;
                self.confirm_delete = false;
            }
            Some(MessageAction::Keep) => self.confirm_delete = false,
            Some(MessageAction::React(target, reaction, on)) => {
                self.selected_message = None;
                self.actions.push(Action::Room(Command::React { room: room.to_owned(), target, reaction, on }));
            }
            Some(MessageAction::Pin(target, on)) => {
                self.selected_message = None;
                self.actions.push(Action::Room(Command::Pin { room: room.to_owned(), target, on }));
            }
            Some(MessageAction::SaveMessage(target, on)) => {
                self.selected_message = None;
                self.actions.push(Action::Room(Command::SaveMessage { room: room.to_owned(), target, on }));
            }
            Some(MessageAction::MarkUnread(target)) => {
                self.actions.push(Action::Room(Command::MarkUnread { room: room.to_owned(), target }));
            }
            Some(MessageAction::OpenThread(parent)) => {
                self.open_thread = Some((room.to_owned(), parent));
                self.selected_message = None;
            }
            Some(MessageAction::Save(chip)) => {
                self.actions.push(Action::Room(Command::Save { file: chip.file, size: chip.size, name: chip.name, to: None }));
            }
        }
    }

    /// A room's quiet lines between its messages, by cursor: its call history (T360a2) and the lines that link back to
    /// the archives it continues (T352).
    fn system_lines(&self, room: &str) -> std::collections::BTreeMap<u64, String> {
        let mut lines = self.call_lines.get(room).cloned().unwrap_or_default();
        if let Some(continued) = self.continued.get(room) {
            lines.extend(continued.iter().map(|(cursor, (_, text))| (*cursor, text.clone())));
        }
        lines
    }

    fn composer_ui(&mut self, ui: &mut Ui, room: &str) {
        // An archive room takes no messages (T350d2); it can be continued as an active conversation (T352).
        if self.archived.contains(room) {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.weak("Archive: read only");
                if ui.button("Continue this conversation").clicked() {
                    self.actions.push(Action::Room(Command::Continue { archive: room.to_owned() }));
                }
            });
            ui.add_space(6.0);
            return;
        }
        // A room that continues an archive links back to it (T352).
        let archives: std::collections::BTreeSet<String> =
            self.continued.get(room).map(|lines| lines.values().map(|(archive, _)| archive.clone()).collect()).unwrap_or_default();
        for archive in archives {
            if ui.button(format!("Open the archive {archive}")).clicked() {
                self.rooms.add(&archive);
                self.open_room(&archive, true);
            }
        }
        let editing = self.editing.as_ref().filter(|(edited_room, _)| edited_room == room).map(|(_, cursor)| *cursor);
        if editing.is_some() {
            ui.horizontal(|ui| {
                ui.label("Editing your message");
                if ui.button("Cancel editing").clicked() {
                    self.editing = None;
                    self.draft.clear();
                }
            });
        }
        let editing = self.editing.as_ref().filter(|(edited_room, _)| edited_room == room).map(|(_, cursor)| *cursor);
        // Files to attach to this post (T330e): each with a way to take it off again.
        let pending = self.pending_files(room).to_vec();
        if !pending.is_empty() {
            ui.horizontal_wrapped(|ui| {
                for chip in &pending {
                    ui.label(chip.label());
                    if ui.small_button(format!("Remove {}", chip.name)).clicked()
                        && let Some(files) = self.pending_files.get_mut(room)
                    {
                        files.retain(|file| file.file != chip.file);
                    }
                }
            });
        }
        if editing.is_none() {
            self.attach_ui(ui, room, pending.is_empty());
        }
        ui.horizontal(|ui| {
            let label = ui.label("Message");
            // Enter sends, as in other chat apps; Shift+Enter starts a new line. The key is taken before the text box
            // sees it, so the draft never gets a stray newline. Ctrl+Enter (Cmd+Enter on macOS) also sends.
            let id = ui.make_persistent_id("crewcraft-composer");
            let focused = ui.memory(|memory| memory.has_focus(id));
            // `consume_key` compares modifiers loosely (it ignores Shift), so Shift is checked here first.
            let enter = focused
                && ui.input_mut(|input| {
                    !input.modifiers.shift && (input.consume_key(Modifiers::NONE, Key::Enter) || input.consume_key(Modifiers::COMMAND, Key::Enter))
                });
            let edit = TextEdit::multiline(&mut self.draft)
                .id(id)
                .desired_rows(2)
                .hint_text("Write a message (Enter sends, Shift+Enter for a new line)")
                .desired_width(ui.available_width() - 80.0);
            ui.add(edit).labelled_by(label.id);
            self.composer.set(room, &self.draft);
            let send = if editing.is_some() { "Save" } else { "Send" };
            if ui.button(send).clicked() || enter {
                // A post with files may have no text (T330e).
                let files: Vec<[u8; 16]> = self.pending_files(room).iter().map(|chip| chip.file).collect();
                if editing.is_none() && !files.is_empty() {
                    let text = self.draft.trim().to_owned();
                    if text.chars().count() > crewcraft_ui_model::MAX_DRAFT_CHARS {
                        self.notice = Some(format!("Messages can be up to {} characters.", crewcraft_ui_model::MAX_DRAFT_CHARS));
                        return;
                    }
                    self.draft.clear();
                    self.composer.set(room, "");
                    self.pending_files.remove(room);
                    self.notice = None;
                    self.actions.push(Action::Room(Command::PostFiles { room: room.to_owned(), text, files }));
                    return;
                }
                let submitted = match editing {
                    Some(cursor) => self.composer.submit_edit(room, cursor),
                    None => self.composer.submit(room),
                };
                match submitted {
                    Ok(command) => {
                        self.draft.clear();
                        self.notice = None;
                        self.editing = None;
                        self.actions.push(Action::Room(command));
                    }
                    Err(DraftError::Empty) => {}
                    Err(DraftError::TooLong) => {
                        self.notice = Some(format!("Messages can be up to {} characters.", crewcraft_ui_model::MAX_DRAFT_CHARS));
                    }
                }
            }
        });
    }

    /// Attach a file without dragging: the Attach file button opens a path entry in the composer, and Enter or Attach
    /// uploads the file through the same command a dropped file uses. Esc or Cancel closes it. Focus moves into the
    /// entry when it opens and back to the button when it closes, so the whole path works from the keyboard.
    fn attach_ui(&mut self, ui: &mut Ui, room: &str, nothing_pending: bool) {
        let Some(mut typed) = self.attach_path.take() else {
            ui.horizontal(|ui| {
                let button = ui.button("Attach file");
                if self.attach_focus == Some(false) {
                    button.request_focus();
                    self.attach_focus = None;
                }
                if button.clicked() {
                    self.attach_path = Some(String::new());
                    self.attach_focus = Some(true);
                }
                if nothing_pending {
                    ui.weak("Drop a file onto the window to attach it.");
                }
            });
            return;
        };
        let mut close = false;
        ui.horizontal(|ui| {
            let label = ui.label("Path of the file to attach");
            let id = ui.make_persistent_id("crewcraft-attach-path");
            let entry = ui.add(TextEdit::singleline(&mut typed).id(id).desired_width(320.0)).labelled_by(label.id);
            if self.attach_focus == Some(true) {
                entry.request_focus();
                self.attach_focus = None;
            }
            let (enter, escape) = ui.input(|input| (input.key_pressed(Key::Enter), input.key_pressed(Key::Escape)));
            let attach = ui.button("Attach").clicked() || (entry.lost_focus() && enter);
            if ui.button("Cancel").clicked() || (entry.lost_focus() && escape) {
                close = true;
            } else if attach {
                match attach_path(&typed) {
                    Ok(path) => {
                        self.notice = None;
                        self.actions.push(Action::Room(Command::Attach { room: room.to_owned(), path }));
                        close = true;
                    }
                    Err(problem) => {
                        // Say what is wrong and leave the text there to fix, with focus back in it.
                        self.notice = Some(problem.to_owned());
                        self.attach_focus = Some(true);
                    }
                }
            }
        });
        if close {
            self.attach_focus = Some(false);
        } else {
            self.attach_path = Some(typed);
        }
    }

    fn open_room(&mut self, room: &str, deliberate: bool) {
        // The person has moved on: the last announcement no longer describes what they are looking at.
        if deliberate {
            self.announcement = None;
        }
        if let Some(command) = self.rooms.select(room) {
            self.focus = None;
            self.selected_message = None;
            self.confirm_delete = false;
            self.editing = None;
            self.draft = self.composer.draft(room).to_owned();
            self.actions.push(Action::Room(if deliberate { Command::Read { room: room.to_owned() } } else { command }));
        } else if deliberate && self.rooms.selected() == Some(room) {
            self.actions.push(Action::Room(Command::Read { room: room.to_owned() }));
        }
    }
}

/// The file a path typed into the composer's path entry names, or what is wrong with it. Surrounding space and
/// quotes (as a file manager's "copy as path" adds them) are dropped. It must be a full path, and not end in a folder
/// separator; whether the file exists and can be read is checked when it is uploaded, outside the window.
pub fn attach_path(typed: &str) -> Result<std::path::PathBuf, &'static str> {
    let trimmed = typed.trim();
    let unquoted = trimmed.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')).unwrap_or(trimmed).trim();
    if unquoted.is_empty() {
        return Err("Type the path of the file to attach.");
    }
    if unquoted.ends_with(['/', '\\']) {
        return Err("That path ends in a folder separator. Type the path of a file.");
    }
    let path = std::path::PathBuf::from(unquoted);
    if !path.is_absolute() {
        return Err("Type the file's full path, starting from the drive or the top folder.");
    }
    Ok(path)
}

/// Which side of the feed a row is drawn on: the person's own messages on the right, everyone else's on the left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Mine,
    Theirs,
}

/// The side for a feed row, given the signed-in person's email. Pending rows are always the person's own. Authors are
/// compared ignoring case and surrounding space, as email addresses are.
pub fn side(row: &FeedRow, me: &str) -> Side {
    match row {
        FeedRow::Pending { .. } => Side::Mine,
        FeedRow::Message { author, .. } if !me.trim().is_empty() && author.trim().eq_ignore_ascii_case(me.trim()) => Side::Mine,
        FeedRow::Message { .. } => Side::Theirs,
    }
}

/// A room row's text: its name, its unread count, and which of the person's own settings are on (T346), so pinned,
/// muted and hidden read as words and never rest on colour alone. A room with none set reads as before.
pub fn room_label(row: &crewcraft_ui_model::RoomRow, settings: crewcraft_client_core::room_view::RoomSettings) -> String {
    let mut text = if row.unread > 0 { format!("{}  ({})", row.name, row.unread) } else { row.name.clone() };
    let marks: Vec<&str> = [(settings.pinned, "pinned"), (settings.muted, "muted"), (settings.hidden, "hidden")]
        .into_iter()
        .filter_map(|(on, mark)| on.then_some(mark))
        .collect();
    if !marks.is_empty() {
        text.push_str("  ");
        text.push_str(&marks.join(", "));
    }
    text
}

/// The rooms the list pane shows for the search box's text: those whose name contains it, ignoring case.
pub fn visible_rooms(rows: Vec<crewcraft_ui_model::RoomRow>, filter: &str) -> Vec<crewcraft_ui_model::RoomRow> {
    let needle = filter.trim().to_lowercase();
    if needle.is_empty() {
        return rows;
    }
    rows.into_iter().filter(|row| row.name.to_lowercase().contains(&needle)).collect()
}

/// A text label for a live message, including valid file-only messages (T343).
fn message_text(html: &str) -> String {
    let text = text::html_to_text(html);
    if text.trim().is_empty() { "Message with attachments".to_owned() } else { text }
}

/// Keep orphaned replies visible with their true parent and an ordinary accessible thread action (T345).
fn orphan_thread_ui(ui: &mut Ui, parent: Option<u64>, previous: &mut Option<u64>) -> Option<MessageAction> {
    let show = parent.is_some() && parent != *previous;
    *previous = parent;
    if show {
        ui.label("Replies to an unavailable message");
        if ui.add(egui::Button::new("View thread").min_size(egui::vec2(0.0, TOUCH_TARGET))).clicked() {
            return parent.map(MessageAction::OpenThread);
        }
    }
    None
}

/// One feed row as a bubble (T315): the person's own on the right, everyone else's on the left. Selected messages
/// offer personal bookmarks, room pins and the message's allowed editing/reply actions.
fn bubble_ui(ui: &mut Ui, row: &FeedRow, look: &Bubbles<'_>) -> Option<MessageAction> {
    let (me, colors, selected, confirming, files) = (look.me, look.colors, look.selected, look.confirming, look.files);
    let mine = side(row, me) == Side::Mine;
    // Any message can be selected to reply to it; one's own also to edit or delete it (T340b).
    let message_cursor = match row {
        FeedRow::Message { cursor, .. } => Some(*cursor),
        _ => None,
    };
    // Personal bookmarks work in an archive too; room-changing actions remain read-only (T343).
    let selectable = message_cursor;
    let chips = match row {
        FeedRow::Message { cursor, .. } => files.get(cursor).cloned().unwrap_or_default(),
        FeedRow::Pending { .. } => Vec::new(),
    };
    let own_message = match row {
        FeedRow::Message { cursor, html, .. } if mine => Some((*cursor, text::html_to_text(html))),
        _ => None,
    };
    let mut action = None;
    let fill = match colors {
        Some(colors) => colors.pick(mine, ui.visuals().dark_mode),
        None if mine => ui.visuals().selection.bg_fill,
        None => ui.visuals().faint_bg_color,
    };
    let (text, pending, failed) = match row {
        FeedRow::Message { author, html, edited, first_of_group, .. } => {
            let mut text = message_text(html);
            if *edited {
                text.push_str("  (edited)");
            }
            if *first_of_group {
                ui.add_space(6.0);
                if !mine {
                    ui.strong(author);
                }
            }
            (text, false, false)
        }
        FeedRow::Pending { body, failed, .. } => (format!("{body}  ({})", if *failed { "Not sent" } else { "Sending" }), true, *failed),
    };
    let layout = if mine { Layout::right_to_left(Align::Min) } else { Layout::left_to_right(Align::Min) };
    ui.with_layout(layout, |ui| {
        let max = (ui.available_width() * 0.72).max(120.0);
        let radius = ui.visuals().window_corner_radius;
        let focused = matches!(row, FeedRow::Message { cursor, .. } if Some(*cursor) == look.focus);
        let stroke = if focused { egui::Stroke::new(2.0, ui.visuals().selection.stroke.color) } else { egui::Stroke::NONE };
        let shown = egui::Frame::new().fill(fill).stroke(stroke).corner_radius(radius).inner_margin(egui::Margin::symmetric(10, 6)).show(ui, |ui| {
            ui.set_max_width(max);
            let rich = RichText::new(text);
            let rich = if failed {
                rich.color(ui.visuals().error_fg_color)
            } else if pending {
                rich.color(ui.visuals().weak_text_color())
            } else {
                rich
            };
            let label = egui::Label::new(rich).wrap();
            let label = if selectable.is_some() { label.sense(egui::Sense::click()) } else { label };
            if ui.add(label).clicked()
                && let Some(cursor) = selectable
            {
                action = Some(MessageAction::Select(cursor));
            }
        });
        // A search result's message comes into view once (T321).
        if focused && look.scroll {
            shown.response.scroll_to_me(Some(Align::Center));
        }
    });
    // When an imported message was first sent (T350d2).
    if let FeedRow::Message { cursor, .. } = row
        && let Some(&sent_ms) = look.times.get(cursor)
    {
        let layout = if mine { Layout::right_to_left(Align::Min) } else { Layout::left_to_right(Align::Min) };
        ui.with_layout(layout, |ui| ui.weak(utc_time(sent_ms)));
    }
    // The message's files, each with Save (T330e); an image above its chip (T333), named by its file name so a screen
    // reader meets "photo.png, image" rather than an unnamed image.
    for chip in chips {
        let layout = if mine { Layout::right_to_left(Align::Min) } else { Layout::left_to_right(Align::Min) };
        if let Some(texture) = look.previews.get(&chip.file) {
            let size = texture.size_vec2();
            let scale = (PREVIEW_WIDTH / size.x).min(1.0);
            ui.with_layout(layout, |ui| ui.add(egui::Image::new((texture.id(), size * scale)).alt_text(chip.name.clone())));
        }
        ui.with_layout(layout, |ui| {
            // A file an import could not capture has no bytes to save (T350e).
            if chip.file == [0; 16] {
                ui.weak(format!("{} (not archived)", chip.name));
                return;
            }
            if ui.small_button(format!("Save {}", chip.name)).clicked() {
                action = Some(MessageAction::Save(chip.clone()));
            }
            ui.label(chip.label());
        });
    }
    // Who reacted with what, under the message (T341b): one chip per reaction, highlighted when it includes you; a
    // click adds yours or takes it back. Words, not emoji: the bundled font has none.
    if let FeedRow::Message { cursor, .. } = row
        && let Some(by_code) = look.reactions.get(cursor)
    {
        let layout = if mine { Layout::right_to_left(Align::Min) } else { Layout::left_to_right(Align::Min) };
        ui.with_layout(layout, |ui| {
            for (code, people) in by_code {
                let Some(name) = crewcraft_proto::push::reaction_name(*code) else { continue };
                let yours = people.iter().any(|person| person == me);
                let chip = ui.add(egui::Button::selectable(yours, format!("{name} {}", people.len())).small());
                if chip.on_hover_text(people.join(", ")).clicked() && !look.read_only {
                    action = Some(MessageAction::React(*cursor, *code, !yours));
                }
            }
        });
    }
    // The reactions to choose from, for a selected message (T341b).
    if let Some(cursor) = selectable.filter(|cursor| Some(*cursor) == selected && look.actions && !look.read_only) {
        let yours = |code: u8| {
            look.reactions
                .get(&cursor)
                .and_then(|by_code| by_code.iter().find(|(c, _)| *c == code))
                .is_some_and(|(_, people)| people.iter().any(|p| p == me))
        };
        let layout = if mine { Layout::right_to_left(Align::Min) } else { Layout::left_to_right(Align::Min) };
        ui.with_layout(layout, |ui| {
            for (index, name) in crewcraft_proto::push::REACTIONS.iter().enumerate() {
                let code = index as u8 + 1;
                if ui.small_button(*name).clicked() {
                    action = Some(MessageAction::React(cursor, code, !yours(code)));
                }
            }
        });
    }
    if let Some(cursor) = selectable.filter(|cursor| Some(*cursor) == selected) {
        let saved = look.saved.contains(&cursor);
        let layout = if mine { Layout::right_to_left(Align::Min) } else { Layout::left_to_right(Align::Min) };
        ui.with_layout(layout, |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.small_button(if saved { "Remove from saved" } else { "Save message" }).clicked() {
                    action = Some(MessageAction::SaveMessage(cursor, !saved));
                }
                if ui.button("Mark unread from here").clicked() {
                    action = Some(MessageAction::MarkUnread(cursor));
                }
                if !look.read_only {
                    let pinned = look.pinned == Some(cursor);
                    if ui.small_button(if pinned { "Unpin message" } else { "Pin message" }).clicked() {
                        action = Some(MessageAction::Pin(cursor, !pinned));
                    }
                }
            });
        });
    }
    // The thread under a message that has replies (T340b).
    if let Some(cursor) = message_cursor
        && let Some(&count) = look.replies.get(&cursor)
    {
        let layout = if mine { Layout::right_to_left(Align::Min) } else { Layout::left_to_right(Align::Min) };
        ui.with_layout(layout, |ui| {
            let text = if count == 1 { "1 reply".to_owned() } else { format!("{count} replies") };
            if ui.small_button(text).clicked() {
                action = Some(MessageAction::OpenThread(cursor));
            }
        });
    }
    // Reply, for any selected message (T340b).
    if let Some(cursor) = selectable.filter(|cursor| Some(*cursor) == selected)
        && own_message.is_none()
        && look.actions
        && !look.read_only
    {
        ui.with_layout(Layout::left_to_right(Align::Min), |ui| {
            if ui.button("Reply").clicked() {
                action = Some(MessageAction::OpenThread(cursor));
            }
        });
    }
    if let Some((cursor, text)) = own_message.filter(|(cursor, _)| Some(*cursor) == selected && look.actions && !look.read_only) {
        ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
            if confirming {
                if ui.button("Keep").clicked() {
                    action = Some(MessageAction::Keep);
                }
                if ui.button("Delete").clicked() {
                    action = Some(MessageAction::Delete(cursor));
                }
                ui.label("Delete this message?");
            } else {
                if ui.button("Delete").clicked() {
                    action = Some(MessageAction::AskDelete);
                }
                if ui.button("Edit").clicked() {
                    action = Some(MessageAction::Edit(cursor, text));
                }
                if ui.button("Reply").clicked() {
                    action = Some(MessageAction::OpenThread(cursor));
                }
            }
        });
    }
    ui.add_space(2.0);
    action
}

/// Draw the call history lines with cursors from `from` up to (not including) `upto`, centred and quiet, and return
/// `upto` (T360a2).
fn call_lines_ui(ui: &mut Ui, lines: &std::collections::BTreeMap<u64, String>, from: u64, upto: u64) -> u64 {
    for text in lines.range(from..upto).map(|(_, text)| text) {
        ui.vertical_centered(|ui| ui.weak(text));
    }
    upto
}

/// The widest a preview is drawn, in points (T333).
const PREVIEW_WIDTH: f32 = 320.0;

/// An image preview's state (T333).
enum Preview {
    Requested,
    Decoded(egui::ColorImage),
    Shown(egui::TextureHandle),
    Failed,
}

/// Whether a file is an image worth a preview (T333): a PNG, JPEG, GIF or WebP name, not over `MAX_PREVIEW_BYTES`, and
/// not a file an import could not capture.
pub fn previewable(chip: &FileChip) -> bool {
    let name = chip.name.to_ascii_lowercase();
    let image = [".png", ".jpg", ".jpeg", ".gif", ".webp"].iter().any(|ext| name.ends_with(ext));
    image && chip.size > 0 && chip.size <= crewcraft_ui_model::MAX_PREVIEW_BYTES && chip.file != [0; 16]
}

/// Decode an image for a preview (T333), within limits (8192 pixels a side, 256 MiB while decoding), scaled down to
/// `PREVIEW_WIDTH` pixels wide. `None` for anything that is not such an image.
pub fn decode_preview(bytes: &[u8]) -> Option<egui::ColorImage> {
    let mut reader = image::ImageReader::new(std::io::Cursor::new(bytes)).with_guessed_format().ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8192);
    limits.max_image_height = Some(8192);
    limits.max_alloc = Some(256 * 1024 * 1024);
    reader.limits(limits);
    let decoded = reader.decode().ok()?;
    let width = PREVIEW_WIDTH as u32;
    let small = if decoded.width() > width { decoded.thumbnail(width, u32::MAX) } else { decoded };
    let rgba = small.to_rgba8();
    Some(egui::ColorImage::from_rgba_unmultiplied([rgba.width() as usize, rgba.height() as usize], rgba.as_raw()))
}

/// A time as `2024-03-05 14:07 UTC` (T350d2). Imported times are shown in UTC: the window has no time zone database.
pub fn utc_time(ms: u64) -> String {
    /// Days in 400 Gregorian years, after which the calendar repeats.
    const CYCLE_DAYS: u64 = 146_097;
    let seconds = ms / 1000;
    let (days, of_day) = (seconds / 86_400, seconds % 86_400);
    // chrono gives the date (Craft standard time.md). A time past chrono's range is first moved back by whole 400-year
    // cycles, which keeps the month and day, and the cycles go back on the year.
    let (cycles, rest) = (days / CYCLE_DAYS, days % CYCLE_DAYS);
    let Some(date) = i64::try_from(rest * 86_400).ok().and_then(|at| DateTime::from_timestamp(at, 0)) else { return String::new() };
    let year = u64::from(date.year().unsigned_abs()) + 400 * cycles;
    format!("{year:04}-{:02}-{:02} {:02}:{:02} UTC", date.month(), date.day(), of_day / 3600, of_day % 3600 / 60)
}

/// A label that is a polite live region: screen readers speak it when it appears and whenever its text changes, without
/// moving focus. `id` keeps it the same node from frame to frame.
fn live_label(ui: &mut Ui, id: &str, text: RichText) {
    ui.push_id(id, |ui| {
        let response = ui.label(text);
        ui.ctx().accesskit_node_builder(response.id, |node| node.set_live(egui::accesskit::Live::Polite));
    });
}

/// A labelled one-line field whose text is zeroed when dropped. `hidden` draws it as a password field.
fn secret_field(ui: &mut Ui, label: &str, value: &mut Zeroizing<String>, hidden: bool) {
    let label = ui.label(label);
    ui.add(TextEdit::singleline(&mut **value).password(hidden).desired_width(f32::INFINITY)).labelled_by(label.id);
}

/// Six to eight digits, the shape of an authenticator code.
fn is_code(code: &str) -> bool {
    let code = code.trim();
    (6..=8).contains(&code.len()) && code.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::utc_time;

    #[test]
    fn utc_times_past_one_400_year_cycle_keep_the_calendar() {
        // 2400-02-29 12:34 UTC: past 2370, so the date comes back from one 400-year cycle, on a century leap day.
        assert_eq!(utc_time(13_574_608_440_000), "2400-02-29 12:34 UTC");
        // Far past chrono's range: a date, not a panic.
        assert!(utc_time(u64::MAX).ends_with(" UTC"));
    }
}
