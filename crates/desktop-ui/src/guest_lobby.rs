//! The staff guest lobby in Calendar (T370d). Controls emit commands and only confirmed snapshots update the roster.

use std::collections::HashMap;

use crewcraft_ui_model::Command;
use crewcraft_ui_model::guest::{GuestCommand, GuestDecision, GuestLobby, GuestState, GuestUpdate};
use egui::{Button, Ui};
use zeroize::Zeroizing;

use crate::{Action, Screen, Window, utc_time};

#[derive(Default)]
pub(crate) struct LobbyUi {
    pub(crate) available: bool,
    pub(crate) panel: Option<Panel>,
    /// A second creation cannot use a tardy result of the first one, even if its form was discarded.
    pub(crate) creating: bool,
    waiting: HashMap<String, u32>,
    attention: Option<String>,
}

pub(crate) struct Panel {
    room: String,
    meeting: u64,
    title: String,
    snapshot: Option<GuestLobby>,
    code: Option<Zeroizing<String>>,
    phase: Phase,
    confirm: Option<(u64, Confirm)>,
    notice: Option<String>,
    /// Give keyboard focus to Back to calendar when it is next drawn: the lobby just opened, or a decision was just
    /// sent and the control that sent it (an answer of a confirmation, or a button that waits for the change) is gone
    /// or disabled (T407).
    focus: bool,
    /// Give keyboard focus to the confirmation's Keep button when it is next drawn: it just opened.
    focus_keep: bool,
    /// Give keyboard focus back to the control that asked for a confirmation that was just dismissed.
    focus_ask: Option<Ask>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Loading,
    Ready,
    Changing,
    Conflict,
}

enum Confirm {
    DirectEntry,
    CloseLink,
    Remove { guest: u64, name: String },
}

/// The control that asked for a confirmation.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ask {
    Toggle,
    CloseLink,
    Remove(u64),
}

impl Confirm {
    fn asked_by(&self) -> Ask {
        match self {
            Self::DirectEntry => Ask::Toggle,
            Self::CloseLink => Ask::CloseLink,
            Self::Remove { guest, .. } => Ask::Remove(*guest),
        }
    }
}

/// Focus `response` if it is the control `focus_ask` names, once.
fn focus_if(focus_ask: &mut Option<Ask>, control: Ask, response: &egui::Response) {
    if *focus_ask == Some(control) {
        response.request_focus();
        *focus_ask = None;
    }
}

enum Pick {
    Back,
    Send(GuestCommand),
}

impl Panel {
    fn open(room: String, meeting: u64, title: String) -> Self {
        Self {
            room,
            meeting,
            title,
            snapshot: None,
            code: None,
            phase: Phase::Loading,
            confirm: None,
            notice: None,
            focus: true,
            focus_keep: false,
            focus_ask: None,
        }
    }

    /// Esc: dismiss the confirmation, with focus back on the control that asked for it, or else leave the lobby
    /// (`true`).
    fn escape(&mut self) -> bool {
        match self.confirm.take() {
            Some((_, confirm)) => {
                self.focus_ask = Some(confirm.asked_by());
                false
            }
            None => true,
        }
    }

    fn update(&mut self, lobby: GuestLobby) -> Option<String> {
        if self
            .snapshot
            .as_ref()
            .is_some_and(|old| lobby.revision < old.revision || (self.phase == Phase::Changing && lobby.revision == old.revision))
        {
            return None;
        }
        if self.confirm.as_ref().is_some_and(|(revision, _)| *revision != lobby.revision) {
            self.confirm = None;
        }
        if lobby.closed {
            self.code = None;
            self.confirm = None;
        }
        self.snapshot = Some(lobby);
        // A later background snapshot does not turn a failed decision into a retry.
        if self.phase != Phase::Conflict {
            self.phase = Phase::Ready;
            return self.notice.take();
        }
        None
    }

    fn ui(&mut self, ui: &mut Ui) -> Option<Pick> {
        let back = ui.button("Back to calendar");
        if std::mem::take(&mut self.focus) {
            back.request_focus();
        }
        if back.clicked() {
            return Some(Pick::Back);
        }

        ui.heading("Lobby");
        ui.label(&self.title);
        if let Some(code) = &self.code {
            ui.label("Copy the guest code before leaving this lobby. It is shown only after scheduling.");
            ui.monospace(code.as_str());
            if ui.button("Copy guest code").clicked() {
                ui.ctx().copy_text(code.to_string());
            }
            if ui.button("Hide guest code").clicked() {
                self.code = None;
            }
        }

        let busy = matches!(self.phase, Phase::Loading | Phase::Changing);
        if self.phase == Phase::Conflict {
            ui.label("The lobby changed. Reload it before making another decision.");
        }
        if ui.add_enabled(!busy, Button::new("Reload lobby")).clicked() {
            self.phase = Phase::Loading;
            self.confirm = None;
            return Some(Pick::Send(GuestCommand::Open { room: self.room.clone(), meeting: self.meeting }));
        }
        let Some(snapshot) = &self.snapshot else {
            if busy {
                ui.label("Loading the lobby…");
            }
            return None;
        };
        ui.label(format!("Link expires {}", utc_time(snapshot.expires_ms)));
        if snapshot.closed {
            ui.label("Guest link closed");
        } else if snapshot.lobby {
            ui.label("Lobby on");
        } else {
            ui.label("Lobby off. New guests enter directly.");
        }

        let ready = self.phase == Phase::Ready && !snapshot.closed;
        let mut command = None;
        if let Some((revision, confirm)) = &self.confirm {
            let ask = confirm.asked_by();
            let (text, accept, cancel, action) = match confirm {
                Confirm::DirectEntry => (
                    "New guests will enter directly. Anyone already waiting still needs a decision.".to_owned(),
                    "Allow direct entry",
                    "Keep lobby on",
                    GuestCommand::SetLobby { meeting: self.meeting, revision: *revision, lobby: false, confirm_direct: true },
                ),
                Confirm::CloseLink => (
                    "Closing the link turns away waiting guests and removes admitted guests. The staff call stays open.".to_owned(),
                    "Close link and remove guests",
                    "Keep link open",
                    GuestCommand::CloseLink { meeting: self.meeting, revision: *revision },
                ),
                Confirm::Remove { guest, name } => (
                    format!("Remove {name} from the meeting?"),
                    "Remove this guest",
                    "Keep guest",
                    GuestCommand::Decide { meeting: self.meeting, guest: *guest, revision: *revision, decision: GuestDecision::Remove },
                ),
            };
            ui.label(text);
            ui.horizontal_wrapped(|ui| {
                if ui.add_enabled(ready, Button::new(accept)).clicked() {
                    command = Some(action);
                }
                // The confirmation opens with focus on the safe answer, and focus goes back to what asked for it.
                let keep = ui.button(cancel);
                if std::mem::take(&mut self.focus_keep) {
                    keep.request_focus();
                }
                if keep.clicked() {
                    self.confirm = None;
                    self.focus_ask = Some(ask);
                }
            });
        } else if !snapshot.closed {
            ui.horizontal_wrapped(|ui| {
                let toggle = if snapshot.lobby { "Turn off lobby" } else { "Turn on lobby" };
                let toggle = ui.add_enabled(ready, Button::new(toggle));
                focus_if(&mut self.focus_ask, Ask::Toggle, &toggle);
                if toggle.clicked() {
                    if snapshot.lobby {
                        self.confirm = Some((snapshot.revision, Confirm::DirectEntry));
                        self.focus_keep = true;
                    } else {
                        command =
                            Some(GuestCommand::SetLobby { meeting: self.meeting, revision: snapshot.revision, lobby: true, confirm_direct: false });
                    }
                }
                let close = ui.add_enabled(ready, Button::new("Close guest link"));
                focus_if(&mut self.focus_ask, Ask::CloseLink, &close);
                if close.clicked() {
                    self.confirm = Some((snapshot.revision, Confirm::CloseLink));
                    self.focus_keep = true;
                }
            });
        }

        if snapshot.entries.is_empty() {
            ui.label("No guests have asked to join.");
        }
        for entry in &snapshot.entries {
            let label = match entry.state {
                GuestState::Waiting => "Waiting",
                GuestState::Admitted => "Admitted",
                GuestState::Declined => "Declined",
                GuestState::Removed => "Removed",
            };
            ui.push_id(entry.guest, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(&entry.name);
                    ui.label(label);
                    let enabled = ready && self.confirm.is_none();
                    let decide = |decision| GuestCommand::Decide { meeting: self.meeting, guest: entry.guest, revision: snapshot.revision, decision };
                    match entry.state {
                        GuestState::Waiting => {
                            if ui.add_enabled(enabled, Button::new(format!("Admit {}", entry.name))).clicked() {
                                command = Some(decide(GuestDecision::Admit));
                            }
                            if ui.add_enabled(enabled, Button::new(format!("Decline {}", entry.name))).clicked() {
                                command = Some(decide(GuestDecision::Decline));
                            }
                        }
                        GuestState::Admitted => {
                            let remove = ui.add_enabled(enabled, Button::new(format!("Remove {}", entry.name)));
                            focus_if(&mut self.focus_ask, Ask::Remove(entry.guest), &remove);
                            if remove.clicked() {
                                self.confirm = Some((snapshot.revision, Confirm::Remove { guest: entry.guest, name: entry.name.clone() }));
                                self.focus_keep = true;
                            }
                        }
                        GuestState::Declined | GuestState::Removed => {}
                    }
                });
            });
        }
        command.map(|command| {
            self.confirm = None;
            self.phase = Phase::Changing;
            self.focus = true;
            Pick::Send(command)
        })
    }
}

impl Window {
    pub(crate) fn reset_guest_lobby(&mut self) {
        if self.guest_lobby.waiting.iter().any(|(room, waiting)| self.announcement.as_deref() == Some(waiting_announcement(room, *waiting).as_str()))
        {
            self.announcement = None;
        }
        let notice = self.guest_lobby.panel.as_mut().and_then(|panel| panel.notice.take());
        self.clear_lobby_notice(notice);
        self.guest_lobby = LobbyUi::default();
        self.calendar.clear_guest_form();
        self.calendar.focus_lobby = None;
    }

    pub(crate) fn open_guest_lobby(&mut self, room: String, meeting: u64, title: String) {
        self.guest_lobby.panel = Some(Panel::open(room.clone(), meeting, title));
        self.actions.push(Action::Room(Command::GuestLobby(GuestCommand::Open { room, meeting })));
    }

    pub(crate) fn close_guest_lobby(&mut self) {
        if let Some(panel) = self.guest_lobby.panel.take() {
            self.clear_lobby_notice(panel.notice);
            self.calendar.focus_lobby = Some(panel.meeting);
            self.actions.push(Action::Room(Command::GuestLobby(GuestCommand::ClosePanel)));
        }
    }

    /// Esc in the lobby (from the Calendar area): dismiss its confirmation, or else leave it.
    pub(crate) fn guest_lobby_escape(&mut self) {
        if self.guest_lobby.panel.as_mut().is_some_and(|panel| panel.escape()) {
            self.close_guest_lobby();
        }
    }

    pub(crate) fn guest_lobby_ui(&mut self, ui: &mut Ui) {
        match self.guest_lobby.panel.as_mut().and_then(|panel| panel.ui(ui)) {
            Some(Pick::Back) => self.close_guest_lobby(),
            Some(Pick::Send(command)) => self.actions.push(Action::Room(Command::GuestLobby(command))),
            None => {}
        }
    }

    pub(crate) fn apply_guest_lobby(&mut self, update: GuestUpdate) {
        if self.screen() != Screen::Chat {
            return;
        }
        match update {
            GuestUpdate::Available(true) => self.guest_lobby.available = true,
            GuestUpdate::Available(false) => self.reset_guest_lobby(),
            _ if !self.guest_lobby.available => {}
            GuestUpdate::Waiting { room, waiting, notify } => {
                let before = self.guest_lobby.waiting.insert(room.clone(), waiting);
                if let Some(before) = before
                    && waiting < before
                {
                    self.clear_waiting_announcement(&room, before);
                }
                let settings = self.rooms.settings(&room);
                if notify && before.is_some_and(|before| waiting > before) && !settings.muted && !settings.hidden {
                    self.announce(waiting_announcement(&room, waiting));
                    self.guest_lobby.attention = Some(room);
                }
            }
            GuestUpdate::ClearRoom { room } => self.clear_guest_room(&room),
            GuestUpdate::Snapshot { room, lobby, code } => {
                if let Some(code) = code {
                    let code = Zeroizing::new(code.0);
                    if !std::mem::take(&mut self.guest_lobby.creating) {
                        return;
                    }
                    if self.calendar.open
                        && let Some(title) = self.calendar.finish_guest_creation(&room)
                    {
                        let mut panel = Panel::open(room, lobby.meeting, title);
                        panel.code = Some(code);
                        let _ = panel.update(lobby);
                        self.guest_lobby.panel = Some(panel);
                        self.announce("Guest meeting scheduled.".to_owned());
                    } else {
                        self.announce(
                            "Guest meeting scheduled. Its code was not shown. Close its guest link in Calendar and schedule another guest meeting to get a new code."
                                .to_owned(),
                        );
                    }
                } else if let Some(panel) = self.guest_lobby.panel.as_mut().filter(|panel| panel.room == room && panel.meeting == lobby.meeting) {
                    let notice = panel.update(lobby);
                    self.clear_lobby_notice(notice);
                }
            }
            GuestUpdate::Refused { meeting, reason, conflict, access_lost, panel_unavailable } => {
                if let Some(meeting) = meeting {
                    let Some(panel) = self.guest_lobby.panel.as_mut().filter(|panel| panel.meeting == meeting) else { return };
                    if access_lost {
                        let room = panel.room.clone();
                        self.clear_guest_room(&room);
                    } else if panel_unavailable {
                        self.close_guest_lobby();
                    } else {
                        panel.phase = if conflict { Phase::Conflict } else { Phase::Ready };
                        panel.confirm = None;
                        panel.notice = Some(reason.clone());
                    }
                    self.notice = Some(reason);
                } else if std::mem::take(&mut self.guest_lobby.creating) && self.calendar.refuse_guest_creation(&reason) {
                    self.announce(reason);
                }
            }
        }
    }

    fn clear_guest_room(&mut self, room: &str) {
        if let Some(waiting) = self.guest_lobby.waiting.remove(room) {
            self.clear_waiting_announcement(room, waiting);
        }
        if self.guest_lobby.panel.as_ref().is_some_and(|panel| panel.room == room) {
            self.close_guest_lobby();
        }
    }

    fn clear_waiting_announcement(&mut self, room: &str, waiting: u32) {
        if self.announcement.as_deref() == Some(waiting_announcement(room, waiting).as_str()) {
            self.announcement = None;
        }
        if self.guest_lobby.attention.as_deref() == Some(room) {
            self.guest_lobby.attention = None;
        }
    }

    fn clear_lobby_notice(&mut self, notice: Option<String>) {
        if notice.is_some() && self.notice == notice {
            self.notice = None;
        }
    }

    pub(crate) fn lobby_attention(&mut self, ui: &Ui) {
        if self.guest_lobby.attention.take().is_some()
            && cfg!(any(target_os = "windows", target_os = "macos", target_os = "linux"))
            && ui.input(|input| !input.focused)
        {
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(egui::UserAttentionType::Informational));
        }
    }

    pub(crate) fn lobby_room_label(&self, room: &str, mut label: String) -> String {
        if let Some(waiting) = self.guest_lobby.waiting.get(room).filter(|waiting| **waiting > 0) {
            label.push_str(&format!(" · {waiting} waiting"));
        }
        label
    }
}

fn waiting_announcement(room: &str, waiting: u32) -> String {
    let noun = if waiting == 1 { "guest" } else { "guests" };
    format!("{waiting} {noun} waiting in {room}.")
}
