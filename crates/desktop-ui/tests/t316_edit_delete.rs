//! T316: editing and deleting your own messages in the window, driven headless through egui's accessibility tree:
//! clicking your own message selects it and shows Edit and Delete; Edit puts its text in the composer, which then
//! saves instead of sending; Delete asks first. Other people's messages cannot be selected.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::{Action, Update, Window, fonts};
use crewcraft_ui_model::Command;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const ME: &str = "ana@example.org";
const ROOM: &str = "general";

fn line(cursor: u64, author: &str, html: &str) -> Shown {
    Shown::Line(Line { cursor, author: author.to_owned(), html: html.to_owned(), edited: false })
}

fn chat() -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size([900.0, 600.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: ME.to_owned(), rooms: vec![ROOM.to_owned()] });
    h.state_mut().apply(Update::Snapshot {
        room: ROOM.to_owned(),
        shown: vec![line(5, ME, "<p>my first try</p>"), line(6, "bo@example.org", "<p>from Bo</p>")],
    });
    h.run();
    h.state_mut().take_actions();
    h
}

#[test]
fn only_your_own_message_can_be_selected() {
    let mut h = chat();
    h.get_by_label("from Bo").click();
    h.run();
    assert!(h.query_by_label("Edit").is_none() && h.query_by_label("Delete").is_none());
    h.get_by_label("my first try").click();
    h.run();
    h.get_by_label("Edit");
    h.get_by_label("Delete");
    // A second click clears the selection.
    h.get_by_label("my first try").click();
    h.run();
    assert!(h.query_by_label("Edit").is_none());
    assert!(h.state_mut().take_actions().is_empty());
}

#[test]
fn edit_puts_the_text_in_the_composer_and_saves() {
    let mut h = chat();
    h.get_by_label("my first try").click();
    h.run();
    h.get_by_label("Edit").click();
    h.run();
    assert_eq!(h.state().editing(), Some((ROOM, 5)));
    h.get_by_label("Editing your message");
    assert!(h.query_by_label("Send").is_none());
    h.get_by_label("Message").click();
    h.run();
    h.get_by_label("Message").type_text(", fixed");
    h.run();
    h.get_by_label("Save").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Edit { room: ROOM.into(), target: 5, text: "my first try, fixed".into() })]);
    assert_eq!(h.state().editing(), None);
    h.get_by_label("Send");

    // Cancel editing leaves the message as it was and empties the composer.
    h.get_by_label("my first try").click();
    h.run();
    h.get_by_label("Edit").click();
    h.run();
    h.get_by_label("Cancel editing").click();
    h.run();
    assert_eq!(h.state().editing(), None);
    assert!(h.state_mut().take_actions().is_empty());
}

#[test]
fn delete_asks_first() {
    let mut h = chat();
    h.get_by_label("my first try").click();
    h.run();
    h.get_by_label("Delete").click();
    h.run();
    h.get_by_label("Delete this message?");
    h.get_by_label("Keep").click();
    h.run();
    assert!(h.state_mut().take_actions().is_empty());
    assert!(h.query_by_label("Delete this message?").is_none());

    h.get_by_label("Delete").click();
    h.run();
    h.get_by_label("Delete").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Delete { room: ROOM.into(), target: 5 })]);
    assert!(h.query_by_label("Delete").is_none(), "the selection is cleared");
}
