//! T352: continuing an archive in the window, driven headless through egui's accessibility tree. An open archive room
//! offers "Continue this conversation" beside "Archive: read only"; the room it continues in is listed and opened; its
//! line that links back to the archive shows between its messages, with a way to open the archive.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::{Action, Update, Window, fonts};
use crewcraft_ui_model::Command;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const ME: &str = "ana@example.org";

fn chat() -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size([1100.0, 700.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: ME.to_owned(), rooms: vec!["general".to_owned(), "old-team".to_owned()] });
    h.state_mut().apply(Update::Archive { room: "old-team".into(), times: Vec::new() });
    let line = Shown::Line(Line { cursor: 4, author: "bo@example.org".into(), html: "the plan from last year".into(), edited: false });
    h.state_mut().apply(Update::Snapshot { room: "old-team".into(), shown: vec![line] });
    h.run();
    h.state_mut().take_actions();
    h
}

#[test]
fn an_archive_is_continued_and_the_new_room_links_back_to_it() {
    let mut h = chat();
    h.get_by_label("old-team").click();
    h.run();
    h.state_mut().take_actions();
    h.get_by_label("Archive: read only");
    h.get_by_label("Continue this conversation").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Continue { archive: "old-team".into() })]);

    // The server answered: the new room is listed, opened and read, and it is an active room with a composer.
    h.state_mut().apply(Update::Continued { archive: "old-team".into(), room: "old-team-2".into() });
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Read { room: "old-team-2".into() })]);
    let text = "ana@example.org continued the archived conversation \"Old team\" here.";
    h.state_mut().apply(Update::Continuations { room: "old-team-2".into(), lines: vec![(2, "old-team".into(), text.into())] });
    h.run();
    h.get_by_label("Send");
    h.get_by_label(text);
    h.get_by_label("Open the archive old-team").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Read { room: "old-team".into() })]);
    h.get_by_label("Archive: read only");
}
