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

use crewcraft_client_core::room_view::Shown;
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
    Unread {
        room: String,
        unread: u32,
    },
    /// The email address last used to sign in on this device, to fill in the sign-in form.
    LastEmail(String),
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
            Self::LastEmail(email) => f.debug_tuple("LastEmail").field(email).finish(),
            Self::InvitationLink(_) => f.write_str("InvitationLink(..)"),
            Self::WaitingForBrowser => f.write_str("WaitingForBrowser"),
            Self::Failed(text) => f.debug_tuple("Failed").field(text).finish(),
            Self::SignedOut => f.write_str("SignedOut"),
        }
    }
}

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
            self.waiting_for_browser = self.busy && self.screen() == Screen::SignIn;
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
                self.email = email;
                self.rooms = RoomList::new();
                for room in &rooms {
                    self.rooms.add(room);
                }
                self.go(Screen::Chat);
                if let Some(first) = self.rooms.rows().first().map(|row| row.name.clone()) {
                    self.open_room(&first);
                }
            }
            Update::Snapshot { room, shown } => {
                self.feeds.insert(room, feed_rows(&shown));
            }
            Update::Unread { room, unread } => {
                self.rooms.set_unread(&room, unread);
            }
            Update::LastEmail(email) => {
                if self.email.is_empty() {
                    self.email = email;
                }
            }
            Update::InvitationLink(_) | Update::WaitingForBrowser => {}
            Update::Failed(text) => self.notice = Some(text),
            Update::SignedOut => {
                self.phone_pane = PhonePane::Chats;
                self.feeds.clear();
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
        let screen = self.screen();
        if screen == Screen::Chat {
            if let Some(notice) = self.notice.clone() {
                egui::Panel::top("crewcraft-notice").show(ui, |ui| {
                    ui.colored_label(ui.visuals().warn_fg_color, notice);
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
                            ui.colored_label(ui.visuals().warn_fg_color, notice.as_str());
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

    fn go(&mut self, screen: Screen) {
        self.screen = Some(screen);
        self.notice = None;
        self.code = Zeroizing::default();
    }

    fn enroll_ui(&mut self, ui: &mut Ui) {
        ui.heading("Join a CrewCraft server");
        ui.label("Paste the invitation link your administrator sent you, and choose a password.");
        secret_field(ui, "Invitation link", &mut self.link, false);
        secret_field(ui, "New password", &mut self.password, true);
        let ready = !self.busy && !self.link.trim().is_empty() && !self.password.is_empty();
        if ui.add_enabled(ready, egui::Button::new("Enroll this device")).clicked() {
            let link = Zeroizing::new(self.link.trim().to_owned());
            self.link = Zeroizing::default();
            let password = std::mem::take(&mut self.password);
            self.busy = true;
            self.actions.push(Action::Enroll { link, password });
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
            ui.horizontal(|ui| {
                ui.strong(self.title().to_owned());
                ui.add_space(16.0);
                let label = ui.label("Search rooms");
                ui.add(TextEdit::singleline(&mut self.room_filter).hint_text("Type to filter").desired_width(220.0)).labelled_by(label.id);
                let total = self.rooms.total_unread();
                if total > 0 {
                    ui.label(format!("{total} unread"));
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Sign out").clicked() {
                        self.actions.push(Action::SignOut);
                    }
                    ui.label(&self.email);
                    if !self.server.is_empty() {
                        ui.weak(&self.server);
                    }
                });
            });
        });
        // The app bar. Chat is the one area so far; Teams, Calendar, Calls, Files and Apps join it as they ship, so the
        // bar never offers a button that does nothing.
        egui::Panel::left("crewcraft-app-bar").resizable(false).exact_size(72.0).show(ui, |ui| {
            ui.add_space(8.0);
            let total = self.rooms.total_unread();
            let chat = if total > 0 { format!("Chat ({total})") } else { "Chat".to_owned() };
            let _ = ui.add_sized([ui.available_width(), 40.0], egui::Button::selectable(true, chat));
        });
        egui::Panel::left("crewcraft-rooms").resizable(true).default_size(220.0).show(ui, |ui| {
            ui.add_space(4.0);
            ui.strong("Rooms");
            ui.add_space(4.0);
            let mut open = None;
            let rows = visible_rooms(self.rooms.rows(), &self.room_filter);
            if rows.is_empty() {
                ui.weak(if self.room_filter.trim().is_empty() { "No rooms yet." } else { "No room matches." });
            }
            ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                for row in rows {
                    let text = if row.unread > 0 { format!("{}  ({})", row.name, row.unread) } else { row.name.clone() };
                    let text = if row.unread > 0 { RichText::new(text).strong() } else { RichText::new(text) };
                    if ui.add_sized([ui.available_width(), 28.0], egui::Button::selectable(row.selected, text)).clicked() {
                        open = Some(row.name);
                    }
                }
            });
            if let Some(room) = open {
                self.open_room(&room);
            }
        });
        let Some(room) = self.rooms.selected().map(str::to_owned) else {
            egui::CentralPanel::default_margins().show(ui, |ui| {
                ui.label("You are not in any rooms yet.");
            });
            return;
        };
        egui::Panel::top("crewcraft-conversation-header").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading(&room);
            });
        });
        egui::Panel::bottom("crewcraft-composer").show(ui, |ui| self.composer_ui(ui, &room));
        let me = self.email.clone();
        let bubbles = self.bubbles;
        egui::CentralPanel::default_margins().show(ui, |ui| {
            ScrollArea::vertical().stick_to_bottom(true).auto_shrink(false).show(ui, |ui| {
                for row in self.feeds.get(&room).map(Vec::as_slice).unwrap_or_default() {
                    bubble_ui(ui, row, &me, bubbles);
                }
            });
        });
    }

    /// The phone layout: one pane at a time, a bottom tab bar, and larger touch targets (T402).
    fn phone_chat_ui(&mut self, ui: &mut Ui) {
        ui.spacing_mut().interact_size.y = TOUCH_TARGET;
        let in_conversation = self.phone_pane == PhonePane::Conversation && self.rooms.selected().is_some();
        if !in_conversation {
            egui::Panel::bottom("crewcraft-tabs").show(ui, |ui| {
                ui.columns(2, |columns| {
                    let total = self.rooms.total_unread();
                    let chats = if total > 0 { format!("Chats ({total})") } else { "Chats".to_owned() };
                    let size = [columns[0].available_width(), TOUCH_TARGET];
                    if columns[0].add_sized(size, egui::Button::selectable(self.phone_pane == PhonePane::Chats, chats)).clicked() {
                        self.phone_pane = PhonePane::Chats;
                    }
                    if columns[1].add_sized(size, egui::Button::selectable(self.phone_pane == PhonePane::Account, "Account")).clicked() {
                        self.phone_pane = PhonePane::Account;
                    }
                });
            });
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
                    });
                });
                egui::Panel::bottom("crewcraft-composer").show(ui, |ui| self.composer_ui(ui, &room));
                let me = self.email.clone();
                let bubbles = self.bubbles;
                egui::CentralPanel::default_margins().show(ui, |ui| {
                    ScrollArea::vertical().stick_to_bottom(true).auto_shrink(false).show(ui, |ui| {
                        for row in self.feeds.get(&room).map(Vec::as_slice).unwrap_or_default() {
                            bubble_ui(ui, row, &me, bubbles);
                        }
                    });
                });
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
                    let rows = self.rooms.rows();
                    if rows.is_empty() {
                        ui.label("You are not in any rooms yet.");
                    }
                    ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                        let mut open = None;
                        for row in rows {
                            let text = if row.unread > 0 { format!("{}  ({})", row.name, row.unread) } else { row.name.clone() };
                            if ui.add_sized([ui.available_width(), TOUCH_TARGET], egui::Button::selectable(row.selected, text)).clicked() {
                                open = Some(row.name);
                            }
                        }
                        if let Some(room) = open {
                            self.open_room(&room);
                            self.phone_pane = PhonePane::Conversation;
                        }
                    });
                });
            }
        }
    }

    fn composer_ui(&mut self, ui: &mut Ui, room: &str) {
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
            if ui.button("Send").clicked() || enter {
                match self.composer.submit(room) {
                    Ok(command) => {
                        self.draft.clear();
                        self.notice = None;
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

    fn open_room(&mut self, room: &str) {
        if let Some(command) = self.rooms.select(room) {
            self.draft = self.composer.draft(room).to_owned();
            self.actions.push(Action::Room(command));
        }
    }
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

/// The rooms the list pane shows for the search box's text: those whose name contains it, ignoring case.
pub fn visible_rooms(rows: Vec<crewcraft_ui_model::RoomRow>, filter: &str) -> Vec<crewcraft_ui_model::RoomRow> {
    let needle = filter.trim().to_lowercase();
    if needle.is_empty() {
        return rows;
    }
    rows.into_iter().filter(|row| row.name.to_lowercase().contains(&needle)).collect()
}

/// One feed row as a bubble (T315): the person's own on the right in `bubble-mine`, others on the left in
/// `bubble-other` with the author's name above the first of a run.
fn bubble_ui(ui: &mut Ui, row: &FeedRow, me: &str, colors: Option<appearance::BubbleColors>) {
    let mine = side(row, me) == Side::Mine;
    let fill = match colors {
        Some(colors) => colors.pick(mine, ui.visuals().dark_mode),
        None if mine => ui.visuals().selection.bg_fill,
        None => ui.visuals().faint_bg_color,
    };
    let (text, pending, failed) = match row {
        FeedRow::Message { author, html, edited, first_of_group, .. } => {
            let mut text = text::html_to_text(html);
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
        egui::Frame::new().fill(fill).corner_radius(radius).inner_margin(egui::Margin::symmetric(10, 6)).show(ui, |ui| {
            ui.set_max_width(max);
            let rich = RichText::new(text);
            let rich = if failed {
                rich.color(ui.visuals().error_fg_color)
            } else if pending {
                rich.color(ui.visuals().weak_text_color())
            } else {
                rich
            };
            ui.add(egui::Label::new(rich).wrap());
        });
    });
    ui.add_space(2.0);
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
