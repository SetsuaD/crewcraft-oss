//! The Calendar area (docs/MEETINGS.md slice T370b): the work week's meetings in my rooms, a form to schedule or edit
//! one, Cancel with a confirmation, Join, and Start now.
//!
//! Owns: `Calendar` (the area's state) and the `Window` methods that draw and update it. Called by: `Window` (the app
//! bar's Calendar button, the phone's Calendar button, `Window::apply`). Calls: `crewcraft-ui-model` commands, which the
//! app's worker turns into meeting requests; it computes the week from its clock, so this area touches no clock.
//!
//! Times are UTC: the app reads no time zone yet, and the area says so. A save the server refuses keeps everything typed
//! in the form. A conflict (someone saved the meeting first) shows a notice and disables Save until the person chooses
//! Reload, which shows the meeting as it is now; nothing is ever sent again on its own.

use crewcraft_proto::guest::MAX_GUEST_NAME;
use crewcraft_proto::meeting::{Audience, MAX_AGENDA, MAX_DURATION, MAX_TITLE, Meeting, MeetingState};
use crewcraft_ui_model::Command;
use crewcraft_ui_model::guest::{GuestCommand, GuestMeetingDraft};
use egui::{Button, ComboBox, Key, RichText, ScrollArea, TextEdit, Ui};

use crate::{Action, Update, Window, utc_time};

/// The length a new meeting starts with, in minutes.
const DEFAULT_MINUTES: u16 = 30;
const HOUR_MS: u64 = 60 * 60 * 1000;
const DAY_MS: u64 = 24 * HOUR_MS;
const GUEST_EXPIRY_DAYS: [u64; 3] = [1, 7, 14];

/// The Calendar area's state.
#[derive(Default)]
pub(crate) struct Calendar {
    pub(crate) open: bool,
    /// The week shown, in weeks from this one.
    weeks: i64,
    week: Option<Week>,
    form: Option<Form>,
    /// The meeting whose Cancel waits for a confirmation.
    confirm_cancel: Option<u64>,
    /// Restore keyboard focus when leaving a lobby.
    pub(crate) focus_lobby: Option<u64>,
}

/// A week as the worker last read it.
struct Week {
    from_ms: u64,
    now_ms: u64,
    meetings: Vec<Meeting>,
    more: bool,
}

/// The schedule or edit form. What is typed stays here until it is saved, discarded or reloaded.
struct Form {
    /// 0 for a new meeting.
    meeting: u64,
    version: u64,
    room: String,
    title: String,
    start: String,
    minutes: String,
    agenda: String,
    guest: Option<GuestDraft>,
    /// The server said someone saved the meeting first: Save waits for Reload.
    conflict: bool,
    /// Reload was asked for: the next week the worker sends refills the form.
    reloading: bool,
    /// A save or start is on its way.
    saving: bool,
    error: Option<String>,
    focus: bool,
}

struct GuestDraft {
    host_name: String,
    expiry_days: u64,
}

impl Form {
    fn of(meeting: &Meeting) -> Self {
        Self {
            meeting: meeting.id,
            version: meeting.version,
            room: meeting.room.clone(),
            title: meeting.title.clone(),
            start: start_text(meeting.start_ms),
            minutes: meeting.duration.to_string(),
            agenda: meeting.agenda.clone(),
            guest: None,
            conflict: false,
            reloading: false,
            saving: false,
            error: None,
            focus: true,
        }
    }
}

/// A meeting's fields as the form says them, checked.
struct Checked {
    room: String,
    start_ms: u64,
    duration: u16,
    title: String,
    agenda: String,
}

/// What the person did in the agenda or the form this frame.
enum Pick {
    Join(String, u64),
    Lobby(String, u64, String),
    Edit(Meeting),
    AskCancel(u64),
    Cancel(String, u64, u64),
    Keep,
    Save,
    StartNow,
    Reload,
    Discard,
}

fn expiry_label(days: u64) -> String {
    if days == 1 { "1 day".to_owned() } else { format!("{days} days") }
}

/// `ms` as the form's start field writes it: `YYYY-MM-DD HH:MM`, UTC.
fn start_text(ms: u64) -> String {
    utc_time(ms).trim_end_matches(" UTC").to_owned()
}

/// The UTC time a start field names: `YYYY-MM-DD HH:MM`, surrounding space ignored.
pub fn parse_start(text: &str) -> Option<u64> {
    let (date, time) = text.trim().split_once(' ')?;
    let mut date = date.split('-').map(str::parse::<u32>);
    let (year, month, day) = (date.next()?.ok()?, date.next()?.ok()?, date.next()?.ok()?);
    let (hour, minute) = time.trim().split_once(':')?;
    let at = chrono::NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, month, day)?.and_hms_opt(hour.parse().ok()?, minute.parse().ok()?, 0)?;
    if date.next().is_some() {
        return None;
    }
    u64::try_from(at.and_utc().timestamp_millis()).ok()
}

fn check(form: &Form) -> Result<Checked, String> {
    let room = form.room.trim();
    let title = form.title.trim();
    let agenda = form.agenda.trim();
    if room.is_empty() {
        return Err("Choose the room the meeting is in.".to_owned());
    }
    if title.is_empty() || title.chars().count() > MAX_TITLE || title.chars().any(char::is_control) {
        return Err(format!("A meeting needs a title of 1 to {MAX_TITLE} characters on one line."));
    }
    let Some(start_ms) = parse_start(&form.start) else {
        return Err("Write the start as YYYY-MM-DD HH:MM, in UTC.".to_owned());
    };
    let duration = match form.minutes.trim().parse::<u16>() {
        Ok(minutes) if (1..=MAX_DURATION).contains(&minutes) => minutes,
        _ => return Err(format!("A meeting lasts 1 to {MAX_DURATION} minutes.")),
    };
    if agenda.chars().count() > MAX_AGENDA {
        return Err(format!("The agenda can be up to {MAX_AGENDA} characters."));
    }
    Ok(Checked { room: room.to_owned(), start_ms, duration, title: title.to_owned(), agenda: agenda.to_owned() })
}

impl Window {
    /// Open the Calendar area and ask for its week.
    pub(crate) fn open_calendar(&mut self) {
        self.close_activity();
        self.files_view = None;
        self.saved_view = false;
        self.calendar.open = true;
        self.actions.push(Action::Room(Command::ListMeetings { weeks: self.calendar.weeks }));
    }

    /// Whether the Calendar area is open (T370b).
    pub fn calendar_open(&self) -> bool {
        self.calendar.open
    }

    pub(crate) fn close_calendar(&mut self) {
        self.close_guest_lobby();
        if self.calendar.clear_guest_form() {
            self.actions.push(Action::Room(Command::GuestLobby(GuestCommand::ClosePanel)));
        }
        self.calendar.focus_lobby = None;
        self.calendar.open = false;
    }

    /// A week, a saved meeting or a refusal from the worker.
    pub(crate) fn apply_calendar(&mut self, update: Update) {
        match update {
            Update::Meetings { from_ms, now_ms, meetings, more, .. } => {
                if let Some(form) = self.calendar.form.as_mut().filter(|form| form.reloading) {
                    match meetings.iter().find(|meeting| meeting.id == form.meeting) {
                        Some(meeting) if meeting.state == MeetingState::Scheduled => *form = Form::of(meeting),
                        Some(_) => {
                            self.calendar.form = None;
                            self.notice = Some("That meeting has started or was cancelled, so it can no longer be changed.".to_owned());
                        }
                        None => {
                            self.calendar.form = None;
                            self.notice = Some("That meeting is not in this week any more.".to_owned());
                        }
                    }
                }
                let cancellable = |id: u64| meetings.iter().any(|meeting| meeting.id == id && meeting.state == MeetingState::Scheduled);
                if self.calendar.confirm_cancel.is_some_and(|id| !cancellable(id)) {
                    self.calendar.confirm_cancel = None;
                }
                self.calendar.week = Some(Week { from_ms, now_ms, meetings, more });
            }
            Update::MeetingSaved { meeting } => {
                if self.calendar.form.as_ref().is_some_and(|form| form.saving && (form.meeting == meeting.id || form.meeting == 0)) {
                    self.calendar.form = None;
                }
                self.announcement = Some(format!("Saved the meeting {}.", meeting.title));
                if let Some(week) = self.calendar.week.as_mut()
                    && let Some(known) = week.meetings.iter_mut().find(|known| known.id == meeting.id)
                {
                    *known = meeting;
                }
            }
            Update::MeetingRefused { meeting, conflict, reason } => {
                match self.calendar.form.as_mut().filter(|form| form.saving && form.meeting == meeting) {
                    Some(form) => {
                        form.saving = false;
                        if conflict {
                            form.conflict = true;
                        } else {
                            form.error = Some(reason.clone());
                        }
                    }
                    None => self.calendar.confirm_cancel = None,
                }
                self.notice = Some(reason);
            }
            _ => {}
        }
    }

    /// The Calendar area: its header, then the form when one is open, else the week's agenda.
    pub(crate) fn calendar_ui(&mut self, ui: &mut Ui) {
        let mut weeks = None;
        egui::Panel::top("crewcraft-calendar-header").show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading("Calendar");
                if self.guest_lobby.panel.is_none() {
                    if ui.button("Previous week").clicked() {
                        weeks = Some(self.calendar.weeks - 1);
                    }
                    if ui.button("This week").clicked() {
                        weeks = Some(0);
                    }
                    if ui.button("Next week").clicked() {
                        weeks = Some(self.calendar.weeks + 1);
                    }
                    if self.calendar.form.is_none() {
                        if ui.button("Schedule a meeting").clicked() {
                            self.new_meeting_form(None);
                        }
                        if self.guest_lobby.available && ui.add_enabled(!self.guest_lobby.creating, Button::new("Schedule guest meeting")).clicked() {
                            self.new_meeting_form(Some(GuestDraft { host_name: String::new(), expiry_days: 1 }));
                        }
                    }
                }
                if ui.button("Close calendar").clicked() {
                    self.close_calendar();
                }
            });
        });
        if !self.calendar.open {
            return;
        }
        if let Some(weeks) = weeks {
            self.calendar.weeks = weeks;
            self.calendar.confirm_cancel = None;
            self.actions.push(Action::Room(Command::ListMeetings { weeks }));
        }
        egui::CentralPanel::default_margins().show(ui, |ui| {
            ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                if self.guest_lobby.panel.is_some() {
                    self.guest_lobby_ui(ui);
                    return;
                }
                let pick = if self.calendar.form.is_some() { self.meeting_form_ui(ui) } else { self.agenda_ui(ui) };
                if let Some(pick) = pick {
                    self.calendar_pick(pick);
                }
            });
        });
    }

    fn new_meeting_form(&mut self, guest: Option<GuestDraft>) {
        let start = self.calendar.week.as_ref().map(|week| start_text((week.now_ms / HOUR_MS + 1) * HOUR_MS)).unwrap_or_default();
        let room = self.rooms.selected().map(str::to_owned).or_else(|| self.rooms.rows().first().map(|row| row.name.clone())).unwrap_or_default();
        self.calendar.form = Some(Form {
            meeting: 0,
            version: 0,
            room,
            title: String::new(),
            start,
            minutes: DEFAULT_MINUTES.to_string(),
            agenda: String::new(),
            guest,
            conflict: false,
            reloading: false,
            saving: false,
            error: None,
            focus: true,
        });
        self.calendar.confirm_cancel = None;
    }

    fn agenda_ui(&mut self, ui: &mut Ui) -> Option<Pick> {
        let Some(week) = &self.calendar.week else {
            ui.label("Loading the calendar...");
            return None;
        };
        let monday = utc_time(week.from_ms);
        ui.label(format!("Week of {} (times are UTC)", monday.split(' ').next().unwrap_or_default()));
        if week.meetings.is_empty() {
            ui.label("No meetings this week.");
        }
        if week.more {
            ui.label("This week has more meetings than the calendar can show at once.");
        }
        let mut pick = None;
        for meeting in &week.meetings {
            let cancelled = meeting.state == MeetingState::Cancelled;
            let title = if cancelled { format!("{} (cancelled)", meeting.title) } else { meeting.title.clone() };
            ui.add_space(6.0);
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(RichText::new(&title).strong());
                ui.label(format!("{}, {} min, in {}", utc_time(meeting.start_ms), meeting.duration, meeting.room));
                match meeting.state {
                    MeetingState::InProgress => {
                        ui.label("In progress");
                    }
                    MeetingState::Held => {
                        ui.label("Held");
                    }
                    MeetingState::Scheduled | MeetingState::Cancelled => {}
                }
                if !meeting.agenda.is_empty() {
                    ui.label(meeting.agenda.as_str());
                }
                if self.calendar.confirm_cancel == Some(meeting.id) {
                    ui.label(format!("Cancel {} for everyone in {}?", meeting.title, meeting.room));
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Yes, cancel the meeting").clicked() {
                            pick = Some(Pick::Cancel(meeting.room.clone(), meeting.id, meeting.version));
                        }
                        if ui.button("Keep the meeting").clicked() {
                            pick = Some(Pick::Keep);
                        }
                    });
                    return;
                }
                ui.horizontal_wrapped(|ui| {
                    if !cancelled && ui.button(format!("Join {}", meeting.title)).clicked() {
                        pick = Some(Pick::Join(meeting.room.clone(), meeting.id));
                    }
                    if self.guest_lobby.available && !cancelled && meeting.audience == Audience::Guests {
                        let lobby = ui.button(format!("Lobby {}", meeting.title));
                        if self.calendar.focus_lobby == Some(meeting.id) {
                            lobby.request_focus();
                            self.calendar.focus_lobby = None;
                        }
                        if lobby.clicked() {
                            pick = Some(Pick::Lobby(meeting.room.clone(), meeting.id, meeting.title.clone()));
                        }
                    }
                    if meeting.state == MeetingState::Scheduled {
                        if ui.button(format!("Edit {}", meeting.title)).clicked() {
                            pick = Some(Pick::Edit(meeting.clone()));
                        }
                        if ui.button(format!("Cancel {}", meeting.title)).clicked() {
                            pick = Some(Pick::AskCancel(meeting.id));
                        }
                    }
                });
            });
        }
        pick
    }

    fn meeting_form_ui(&mut self, ui: &mut Ui) -> Option<Pick> {
        let form = self.calendar.form.as_mut()?;
        let mut pick = None;
        ui.heading(if form.guest.is_some() {
            "Schedule guest meeting"
        } else if form.meeting == 0 {
            "Schedule a meeting"
        } else {
            "Edit the meeting"
        });
        let edit = form.guest.is_none() || !form.saving;
        // Enter in any one-line field saves, as Save does (T370b2); the agenda takes several lines.
        let mut fields = Vec::new();
        if form.meeting == 0 {
            let label = ui.label("Room");
            fields.push(ui.add(TextEdit::singleline(&mut form.room).desired_width(320.0).interactive(edit)).labelled_by(label.id));
        } else {
            ui.label(format!("Room: {}", form.room));
        }
        let label = ui.label("Title");
        let title = ui.add(TextEdit::singleline(&mut form.title).desired_width(320.0).interactive(edit)).labelled_by(label.id);
        if form.focus {
            title.request_focus();
            form.focus = false;
        }
        fields.push(title);
        let label = ui.label("Start (UTC, YYYY-MM-DD HH:MM)");
        fields.push(ui.add(TextEdit::singleline(&mut form.start).desired_width(320.0).interactive(edit)).labelled_by(label.id));
        let label = ui.label("Length in minutes");
        fields.push(ui.add(TextEdit::singleline(&mut form.minutes).desired_width(80.0).interactive(edit)).labelled_by(label.id));
        let label = ui.label("Agenda");
        ui.add(TextEdit::multiline(&mut form.agenda).desired_rows(4).desired_width(f32::INFINITY).interactive(edit)).labelled_by(label.id);
        if let Some(guest) = &mut form.guest {
            let label = ui.label("Host name");
            fields.push(ui.add(TextEdit::singleline(&mut guest.host_name).desired_width(320.0).interactive(edit)).labelled_by(label.id));
            let label = ui.label("Link expires after");
            ui.add_enabled_ui(edit, |ui| {
                ComboBox::from_id_salt("guest-link-expiry")
                    .selected_text(expiry_label(guest.expiry_days))
                    .show_ui(ui, |ui| {
                        for days in GUEST_EXPIRY_DAYS {
                            ui.selectable_value(&mut guest.expiry_days, days, expiry_label(days));
                        }
                    })
                    .response
                    .labelled_by(label.id);
            });
        }
        let enter = fields.iter().any(|field| field.lost_focus()) && ui.input(|input| input.key_pressed(Key::Enter));
        if form.conflict {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                "Someone changed this meeting since you opened it, so nothing was saved. Your changes are still here. Reload shows the meeting as it is now, without your changes.",
            );
            if ui.add_enabled(!form.reloading, egui::Button::new("Reload")).clicked() {
                pick = Some(Pick::Reload);
            }
        }
        if let Some(error) = &form.error {
            ui.colored_label(ui.visuals().warn_fg_color, error.as_str());
        }
        let ready = !form.conflict && !form.saving && !form.reloading;
        if enter && ready {
            pick = Some(Pick::Save);
        }
        ui.horizontal_wrapped(|ui| {
            if ui.add_enabled(ready, egui::Button::new("Save")).clicked() {
                pick = Some(Pick::Save);
            }
            if form.meeting == 0 && form.guest.is_none() && ui.add_enabled(ready, egui::Button::new("Start now")).clicked() {
                pick = Some(Pick::StartNow);
            }
            if ui.button("Discard changes").clicked() {
                pick = Some(Pick::Discard);
            }
        });
        pick
    }

    fn calendar_pick(&mut self, pick: Pick) {
        let start_now = matches!(pick, Pick::StartNow);
        match pick {
            Pick::Join(room, meeting) => self.actions.push(Action::Room(Command::JoinMeeting { room, meeting })),
            Pick::Lobby(room, meeting, title) => self.open_guest_lobby(room, meeting, title),
            Pick::Edit(meeting) => {
                self.calendar.form = Some(Form::of(&meeting));
                self.calendar.confirm_cancel = None;
            }
            Pick::AskCancel(meeting) => self.calendar.confirm_cancel = Some(meeting),
            Pick::Keep => self.calendar.confirm_cancel = None,
            Pick::Cancel(room, meeting, version) => {
                self.calendar.confirm_cancel = None;
                self.actions.push(Action::Room(Command::CancelMeeting { room, meeting, version }));
            }
            Pick::Discard => {
                if self.calendar.clear_guest_form() {
                    self.actions.push(Action::Room(Command::GuestLobby(GuestCommand::ClosePanel)));
                }
                self.calendar.form = None;
            }
            Pick::Reload => {
                if let Some(form) = self.calendar.form.as_mut() {
                    form.reloading = true;
                }
                self.actions.push(Action::Room(Command::ListMeetings { weeks: self.calendar.weeks }));
            }
            Pick::Save | Pick::StartNow => {
                let now_ms = self.calendar.week.as_ref().map(|week| week.now_ms);
                let Some(form) = self.calendar.form.as_mut() else { return };
                match check(form) {
                    Err(error) => form.error = Some(error),
                    Ok(Checked { room, start_ms, duration, title, agenda }) => {
                        if let Some(guest) = &form.guest {
                            let host_name = guest.host_name.trim();
                            if !(1..=MAX_GUEST_NAME).contains(&host_name.chars().count()) || host_name.chars().any(char::is_control) {
                                form.error = Some(format!("Enter a host name of 1 to {MAX_GUEST_NAME} characters."));
                                return;
                            }
                            let Some(expires_ms) = now_ms.and_then(|now| now.checked_add(guest.expiry_days * DAY_MS)) else {
                                form.error = Some("Reload the calendar to calculate the link expiry.".to_owned());
                                return;
                            };
                            let draft = GuestMeetingDraft {
                                room,
                                start_ms,
                                duration,
                                title,
                                agenda,
                                host_name: host_name.to_owned(),
                                expires_ms,
                                lobby: true,
                                confirm_direct: false,
                            };
                            form.error = None;
                            form.saving = true;
                            self.guest_lobby.creating = true;
                            self.actions.push(Action::Room(Command::GuestLobby(GuestCommand::Create(draft))));
                            return;
                        }
                        form.error = None;
                        form.saving = true;
                        let command = if start_now {
                            Command::StartMeetingNow { room, title, duration, agenda }
                        } else {
                            Command::SaveMeeting { room, meeting: form.meeting, version: form.version, start_ms, duration, title, agenda }
                        };
                        self.actions.push(Action::Room(command));
                    }
                }
            }
        }
    }
}

impl Calendar {
    pub(crate) fn clear_guest_form(&mut self) -> bool {
        if self.form.as_ref().is_some_and(|form| form.guest.is_some()) {
            return self.form.take().is_some_and(|form| form.saving);
        }
        false
    }

    pub(crate) fn finish_guest_creation(&mut self, room: &str) -> Option<String> {
        let form = self.form.as_ref().filter(|form| form.guest.is_some() && form.saving && form.room.trim() == room)?;
        let title = form.title.trim().to_owned();
        self.form = None;
        Some(title)
    }

    pub(crate) fn refuse_guest_creation(&mut self, reason: &str) -> bool {
        let Some(form) = self.form.as_mut().filter(|form| form.guest.is_some() && form.saving) else { return false };
        form.saving = false;
        form.error = Some(reason.to_owned());
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_start_field_reads_back_what_it_writes_and_refuses_anything_else() {
        let at = 1_795_694_400_000;
        assert_eq!(parse_start(&start_text(at)), Some(at));
        assert_eq!(parse_start("  2026-11-26 12:00 "), Some(at));
        for bad in ["", "2026-11-26", "2026-13-01 10:00", "2026-11-26 25:00", "2026-11-26-1 10:00", "tomorrow 10:00"] {
            assert_eq!(parse_start(bad), None, "{bad:?}");
        }
    }
}
