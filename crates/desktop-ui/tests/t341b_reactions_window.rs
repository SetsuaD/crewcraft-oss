//! T341b: reactions in the window, driven headless through egui's accessibility tree: a selected message offers the six
//! reactions; who reacted shows under a message as one chip per reaction ("Like 2"), and a click on a chip adds your
//! reaction or takes it back.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::{Action, Update, Window, fonts};
use crewcraft_ui_model::Command;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const ME: &str = "ana@example.org";
const ROOM: &str = "general";

fn chat() -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size([1100.0, 700.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: ME.to_owned(), rooms: vec![ROOM.to_owned()] });
    let line = Shown::Line(Line { cursor: 5, author: "bo@example.org".into(), html: "<p>lunch at noon</p>".into(), edited: false });
    h.state_mut().apply(Update::Snapshot { room: ROOM.to_owned(), shown: vec![line] });
    h.run();
    h.state_mut().take_actions();
    h
}

#[test]
fn a_selected_message_offers_the_reactions() {
    let mut h = chat();
    assert!(h.query_by_label("Heart").is_none(), "not before the message is selected");
    h.get_by_label("lunch at noon").click();
    h.run();
    for name in ["Like", "Heart", "Laugh", "Surprised", "Sad", "Angry"] {
        h.get_by_label(name);
    }
    h.get_by_label("Heart").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::React { room: ROOM.into(), target: 5, reaction: 2, on: true })]);
    assert!(h.query_by_label("Heart").is_none(), "choosing one closes the choice");
}

#[test]
fn chips_show_who_reacted_and_toggle_yours() {
    let mut h = chat();
    let reactions = vec![(5, vec![(1, vec![ME.to_owned(), "cy@example.org".to_owned()]), (3, vec!["cy@example.org".to_owned()])])];
    h.state_mut().apply(Update::Reactions { room: ROOM.into(), reactions });
    h.run();
    h.get_by_label("Like 2").click();
    h.run();
    assert_eq!(
        h.state_mut().take_actions(),
        vec![Action::Room(Command::React { room: ROOM.into(), target: 5, reaction: 1, on: false })],
        "yours is in it: take it back"
    );
    h.get_by_label("Laugh 1").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::React { room: ROOM.into(), target: 5, reaction: 3, on: true })]);
    // The last reaction gone, the chips go too.
    h.state_mut().apply(Update::Reactions { room: ROOM.into(), reactions: Vec::new() });
    h.run();
    assert!(h.query_by_label("Like 2").is_none() && h.query_by_label("Laugh 1").is_none());
}
