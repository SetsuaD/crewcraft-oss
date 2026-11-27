//! T370b: the Calendar area in the window, driven headless through egui's accessibility tree (docs/MEETINGS.md slice
//! T370b). A meeting scheduled in the form shows up in the week's agenda; a save refused as a conflict shows a notice,
//! keeps what was typed and sends nothing more until Reload, which shows the meeting as it is now; Cancel asks first and
//! the cancelled meeting is marked; Join sends the join command; the phone reaches the calendar too.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_desktop_ui::{Action, Update, Window, fonts, parse_start};
use crewcraft_proto::meeting::{Audience, Meeting, MeetingState};
use crewcraft_ui_model::Command;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const ME: &str = "ana@example.org";
const ROOM: &str = "general";
/// Monday 2026-11-23 00:00 UTC, and Thursday of that week at 12:20 UTC.
const MONDAY: u64 = 1_795_392_000_000;
const NOW: u64 = 1_795_695_600_000;
const DAY: u64 = 24 * 60 * 60 * 1000;

fn window(size: [f32; 2]) -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size(size)
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: ME.to_owned(), rooms: vec![ROOM.to_owned()] });
    h.run();
    h.state_mut().take_actions();
    h
}

fn listed(id: u64, version: u64, title: &str, state: MeetingState) -> Meeting {
    Meeting {
        id,
        room: ROOM.into(),
        version,
        owner: ME.into(),
        audience: Audience::Staff,
        start_ms: MONDAY + 3 * DAY + 15 * 60 * 60 * 1000,
        duration: 45,
        title: title.into(),
        agenda: String::new(),
        state,
    }
}

fn week(meetings: Vec<Meeting>) -> Update {
    Update::Meetings { from_ms: MONDAY, to_ms: MONDAY + 5 * DAY, now_ms: NOW, meetings, more: false }
}

/// Open the Calendar from the app bar and give it this week with `meetings`.
fn calendar(meetings: Vec<Meeting>) -> Harness<'static, Window> {
    let mut h = window([1100.0, 760.0]);
    h.get_by_label("Calendar").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::ListMeetings { weeks: 0 })]);
    h.state_mut().apply(week(meetings));
    h.run();
    h
}

/// Click into the field named `label` and type `text` there.
fn type_into(h: &mut Harness<'_, Window>, label: &str, text: &str) {
    h.get_by_label(label).click();
    h.run();
    h.get_by_label(label).type_text(text);
    h.run();
}

fn field(h: &Harness<'_, Window>, label: &str) -> String {
    h.get_by_label(label).value().unwrap_or_default()
}

#[test]
fn a_scheduled_meeting_shows_up_in_the_week() {
    let mut h = calendar(Vec::new());
    assert!(h.state().calendar_open());
    h.get_by_label("No meetings this week.");
    h.get_by_label("Schedule a meeting").click();
    h.run();
    // The form opens with focus in its title.
    h.run();
    assert!(h.get_by_label("Title").is_focused(), "focus did not move into the title");
    h.get_by_label("Title").type_text("Weekly review");
    h.run();
    type_into(&mut h, "Agenda", "Numbers, then plans");
    h.get_by_label("Save").click();
    h.run();
    let actions = h.state_mut().take_actions();
    let [Action::Room(Command::SaveMeeting { room, meeting, version, start_ms, duration, title, agenda })] = actions.as_slice() else {
        panic!("not one save: {actions:?}");
    };
    assert_eq!((room.as_str(), *meeting, *version), (ROOM, 0, 0), "a new meeting in the open room");
    assert!(*start_ms > NOW && *start_ms - NOW <= 60 * 60 * 1000, "the start offered is the next full hour");
    assert!(*duration > 0);
    assert_eq!((title.as_str(), agenda.as_str()), ("Weekly review", "Numbers, then plans"));

    // The server saved it; the form closes and the week the worker reads next holds it.
    let saved =
        Meeting { start_ms: *start_ms, duration: *duration, agenda: agenda.clone(), ..listed(7, 1, "Weekly review", MeetingState::Scheduled) };
    h.state_mut().apply(Update::MeetingSaved { meeting: saved.clone() });
    h.state_mut().apply(week(vec![saved]));
    h.run();
    assert!(h.query_by_label("Title").is_none(), "the form closed");
    h.get_by_label("Weekly review");
    h.get_by_label("Join Weekly review");
}

#[test]
fn a_form_that_cannot_be_saved_says_why_and_sends_nothing() {
    let mut h = calendar(Vec::new());
    h.get_by_label("Schedule a meeting").click();
    h.run();
    h.get_by_label("Save").click();
    h.run();
    assert!(h.state_mut().take_actions().is_empty(), "no title: nothing is sent");
    h.get_by_label_contains("needs a title");
    assert!(parse_start("2026-11-26 12:00").is_some() && parse_start("26.11.2026 12:00").is_none());
}

#[test]
fn a_stale_edit_shows_the_conflict_and_keeps_the_typed_text_until_reload() {
    let mut h = calendar(vec![listed(7, 1, "Weekly review", MeetingState::Scheduled)]);
    h.get_by_label("Edit Weekly review").click();
    h.run();
    assert_eq!(field(&h, "Title"), "Weekly review");
    h.get_by_label("Title").type_text(" (moved)");
    h.run();
    h.get_by_label("Save").click();
    h.run();
    let actions = h.state_mut().take_actions();
    assert!(
        matches!(actions.as_slice(), [Action::Room(Command::SaveMeeting { meeting: 7, version: 1, title, .. })] if title.contains("(moved)")),
        "{actions:?}"
    );

    // Someone saved it first: the notice shows, the typed title stays, and Save sends nothing again.
    let reason = "Someone changed this meeting since you opened it.";
    h.state_mut().apply(Update::MeetingRefused { meeting: 7, conflict: true, reason: reason.into() });
    h.run();
    h.get_by_label_contains("nothing was saved");
    assert!(field(&h, "Title").contains("(moved)"), "the typed title is kept");
    h.get_by_label("Save").click();
    h.run();
    assert!(h.state_mut().take_actions().is_empty(), "a conflict is never resent");

    // Reload asks for the week again; the meeting as it is now replaces the form's text.
    h.get_by_label("Reload").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::ListMeetings { weeks: 0 })]);
    h.state_mut().apply(week(vec![listed(7, 2, "Weekly sync", MeetingState::Scheduled)]));
    h.run();
    assert_eq!(field(&h, "Title"), "Weekly sync");
    assert!(h.query_by_label_contains("nothing was saved").is_none(), "the conflict is settled");
    h.get_by_label("Save").click();
    h.run();
    let actions = h.state_mut().take_actions();
    assert!(matches!(actions.as_slice(), [Action::Room(Command::SaveMeeting { meeting: 7, version: 2, .. })]), "{actions:?}");
}

#[test]
fn cancel_asks_first_and_the_cancelled_meeting_is_marked() {
    let mut h = calendar(vec![listed(7, 1, "Weekly review", MeetingState::Scheduled)]);
    h.get_by_label("Cancel Weekly review").click();
    h.run();
    assert!(h.state_mut().take_actions().is_empty(), "nothing is cancelled before the confirmation");
    h.get_by_label("Keep the meeting").click();
    h.run();
    assert!(h.state_mut().take_actions().is_empty());
    h.get_by_label("Cancel Weekly review").click();
    h.run();
    h.get_by_label("Yes, cancel the meeting").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::CancelMeeting { room: ROOM.into(), meeting: 7, version: 1 })]);
    h.state_mut().apply(week(vec![listed(7, 2, "Weekly review", MeetingState::Cancelled)]));
    h.run();
    h.get_by_label("Weekly review (cancelled)");
    assert!(h.query_by_label("Join Weekly review").is_none() && h.query_by_label("Edit Weekly review").is_none(), "a cancelled meeting is done");
}

#[test]
fn join_sends_the_join_command_and_start_now_schedules_and_joins() {
    let mut h = calendar(vec![listed(7, 1, "Weekly review", MeetingState::InProgress)]);
    h.get_by_label("In progress");
    assert!(h.query_by_label("Edit Weekly review").is_none(), "a meeting under way can no longer be edited");
    h.get_by_label("Join Weekly review").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::JoinMeeting { room: ROOM.into(), meeting: 7 })]);

    h.get_by_label("Schedule a meeting").click();
    h.run();
    h.get_by_label("Title").type_text("Quick question");
    h.run();
    h.get_by_label("Start now").click();
    h.run();
    let actions = h.state_mut().take_actions();
    assert!(
        matches!(actions.as_slice(), [Action::Room(Command::StartMeetingNow { room, title, .. })] if room == ROOM && title == "Quick question"),
        "{actions:?}"
    );
}

#[test]
fn a_phone_reaches_the_calendar_from_its_rooms() {
    let mut h = window([390.0, 844.0]);
    h.get_by_label("Calendar").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::ListMeetings { weeks: 0 })]);
    h.state_mut().apply(week(vec![listed(7, 1, "Weekly review", MeetingState::Scheduled)]));
    h.run();
    h.get_by_label("Join Weekly review");
    h.get_by_label("Next week").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::ListMeetings { weeks: 1 })]);
}
