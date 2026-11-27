//! T370b2: the calendar's form by keyboard (docs/ACCESSIBILITY.md, rule 1 of the Craft accessibility standard). It
//! opens with focus in its title; Tab moves through title, start, length, agenda, Save and Discard changes in that
//! order; Enter on the focused Discard changes closes the form; Enter in a one-line field saves.
#![allow(clippy::unwrap_used)]

use crewcraft_desktop_ui::{Action, Update, Window, fonts};
use crewcraft_proto::meeting::{Audience, Meeting, MeetingState};
use crewcraft_ui_model::Command;
use egui::Key;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const ROOM: &str = "general";
/// Monday 2026-11-23 00:00 UTC, and Thursday of that week at 12:20 UTC.
const MONDAY: u64 = 1_795_392_000_000;
const NOW: u64 = 1_795_695_600_000;
const DAY: u64 = 24 * 60 * 60 * 1000;

fn calendar() -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size([1100.0, 760.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".to_owned(), rooms: vec![ROOM.to_owned()] });
    h.run();
    h.get_by_label("Calendar").click();
    h.run();
    h.state_mut().take_actions();
    let meeting = Meeting {
        id: 7,
        room: ROOM.into(),
        version: 1,
        owner: "ana@example.org".into(),
        audience: Audience::Staff,
        start_ms: MONDAY + 3 * DAY + 15 * 60 * 60 * 1000,
        duration: 45,
        title: "Weekly review".into(),
        agenda: "Numbers".into(),
        state: MeetingState::Scheduled,
    };
    h.state_mut().apply(Update::Meetings { from_ms: MONDAY, to_ms: MONDAY + 5 * DAY, now_ms: NOW, meetings: vec![meeting], more: false });
    h.run();
    h
}

/// Press `key` and let the window settle (a focus request lands on the next frame).
fn press(h: &mut Harness<'_, Window>, key: Key) {
    h.key_press(key);
    h.run();
    h.run();
}

fn open_edit(h: &mut Harness<'_, Window>) {
    h.get_by_label("Edit Weekly review").click();
    h.run();
    h.run();
    assert!(h.get_by_label("Title").is_focused(), "the form did not open with focus in its title");
}

#[test]
fn tab_walks_the_form_in_reading_order_and_enter_saves() {
    let mut h = calendar();
    open_edit(&mut h);
    for next in ["Start (UTC, YYYY-MM-DD HH:MM)", "Length in minutes", "Agenda", "Save", "Discard changes"] {
        press(&mut h, Key::Tab);
        assert!(h.get_by_label(next).is_focused(), "Tab did not reach {next}");
    }
    // Enter on the focused button does what a click does: the form closes and nothing is sent.
    press(&mut h, Key::Enter);
    assert!(h.query_by_label("Title").is_none(), "Discard changes did not close the form");
    assert!(h.state_mut().take_actions().is_empty());

    // Enter in a one-line field saves the form as it is.
    open_edit(&mut h);
    h.get_by_label("Title").type_text(" (moved)");
    press(&mut h, Key::Enter);
    let actions = h.state_mut().take_actions();
    assert!(
        matches!(actions.as_slice(), [Action::Room(Command::SaveMeeting { meeting: 7, version: 1, title, .. })] if title.contains("(moved)")),
        "{actions:?}"
    );
}
