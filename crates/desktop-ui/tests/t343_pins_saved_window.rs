//! T343: pin and saved-message actions through the window's accessible controls.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_client_core::room_view::{PinnedMessage, Shown};
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::{Action, Update, Window, fonts};
use crewcraft_proto::request::SavedMessage;
use crewcraft_ui_model::Command;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const ROOM: &str = "general";
const ME: &str = "ana@example.org";

fn chat(size: [f32; 2]) -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size(size)
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: ME.into(), rooms: vec![ROOM.into()] });
    h.state_mut().apply(Update::Snapshot {
        room: ROOM.into(),
        shown: vec![Shown::Line(Line { cursor: 5, author: "bo@example.org".into(), html: "<p>Lunch at noon</p>".into(), edited: false })],
    });
    h.run();
    h.state_mut().take_actions();
    h
}

fn pin(target: u64, html: &str) -> PinnedMessage {
    PinnedMessage { target, author: "bo@example.org".into(), html: html.into(), edited: false }
}

fn saved(html: &str, edited: bool) -> SavedMessage {
    SavedMessage { room: ROOM.into(), cursor: 5, author: "bo@example.org".into(), html: html.into(), edited }
}

#[test]
fn selecting_a_message_offers_pin_and_save_actions() {
    let mut h = chat([1100.0, 700.0]);
    h.get_by_label("Lunch at noon").click();
    h.run();
    h.get_by_label("Pin message").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Pin { room: ROOM.into(), target: 5, on: true })]);
    h.get_by_label("Lunch at noon").click();
    h.run();
    h.get_by_label("Save message").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::SaveMessage { room: ROOM.into(), target: 5, on: true })]);
}

#[test]
fn pin_bar_uses_the_authoritative_body_and_unpins_that_target() {
    let mut h = chat([1100.0, 700.0]);
    // The target is outside the held message page, but the server supplies its current body.
    h.state_mut().apply(Update::Pin { room: ROOM.into(), pinned: Some(pin(90, "<p>Current pinned text</p>")) });
    h.run();
    h.get_by_label("Pinned: Current pinned text");
    h.get_by_label("Unpin").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Pin { room: ROOM.into(), target: 90, on: false })]);
    h.state_mut().apply(Update::Pin { room: ROOM.into(), pinned: None });
    h.run();
    assert!(h.query_by_label("Pinned: Current pinned text").is_none());
}

#[test]
fn saved_area_shows_current_edits_and_removes_deleted_messages() {
    let mut h = chat([1100.0, 700.0]);
    h.get_by_label("Saved").click();
    h.run();
    assert!(h.state().saved_open());
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::ListSaved)]);
    h.state_mut().apply(Update::SavedMessages { messages: vec![saved("<p>Before the edit</p>", false)] });
    h.run();
    h.get_by_label("Before the edit");
    h.state_mut().apply(Update::SavedMessages { messages: vec![saved("<p>After the edit</p>", true)] });
    h.run();
    h.get_by_label("After the edit");
    h.get_by_label("Edited");
    assert!(h.query_by_label("Before the edit").is_none());
    h.state_mut().apply(Update::SavedMessages { messages: Vec::new() });
    h.run();
    h.get_by_label("No saved messages yet.");
    assert!(h.query_by_label("After the edit").is_none());
}

#[test]
fn a_saved_message_can_be_removed_or_opened_in_its_room() {
    let mut h = chat([1100.0, 700.0]);
    h.get_by_label("Saved").click();
    h.run();
    h.state_mut().take_actions();
    h.state_mut().apply(Update::SavedMessages { messages: vec![saved("<p>Saved current text</p>", false)] });
    h.run();
    h.get_by_label("Remove from saved").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::SaveMessage { room: ROOM.into(), target: 5, on: false })]);
    h.get_by_label("Open message").click();
    h.run();
    assert!(!h.state().saved_open());
    assert_eq!(h.state().focus(), Some((ROOM, 5)));
}

#[test]
fn file_only_saved_and_pinned_messages_stay_actionable() {
    let mut h = chat([1100.0, 700.0]);
    h.state_mut().apply(Update::Snapshot {
        room: ROOM.into(),
        shown: vec![Shown::Line(Line { cursor: 5, author: "bo@example.org".into(), html: String::new(), edited: false })],
    });
    h.run();
    h.get_by_label("Message with attachments").click();
    h.run();
    h.get_by_label("Pin message").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Pin { room: ROOM.into(), target: 5, on: true })]);
    h.get_by_label("Message with attachments").click();
    h.run();
    h.get_by_label("Save message").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::SaveMessage { room: ROOM.into(), target: 5, on: true })]);
    h.state_mut().apply(Update::Pin { room: ROOM.into(), pinned: Some(pin(5, "")) });
    h.run();
    h.get_by_label("Pinned: Message with attachments");
    h.get_by_label("Saved").click();
    h.run();
    h.state_mut().take_actions();
    h.state_mut().apply(Update::SavedMessages { messages: vec![saved("", false)] });
    h.run();
    h.get_by_label("Message with attachments");
    h.get_by_label("Remove from saved").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::SaveMessage { room: ROOM.into(), target: 5, on: false })]);
}

#[test]
fn archive_messages_offer_personal_saving_without_room_pin_actions() {
    let mut h = chat([1100.0, 700.0]);
    h.state_mut().apply(Update::Archive { room: ROOM.into(), times: Vec::new() });
    h.run();
    h.get_by_label("Lunch at noon").click();
    h.run();
    assert!(h.query_by_label("Pin message").is_none());
    assert!(h.query_by_label("Heart").is_none());
    h.get_by_label("Save message").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::SaveMessage { room: ROOM.into(), target: 5, on: true })]);
}

#[test]
fn phone_room_list_opens_saved_messages() {
    let mut h = chat([390.0, 844.0]);
    h.get_by_label("Saved").click();
    h.run();
    assert!(h.state().saved_open());
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::ListSaved)]);
    h.state_mut().apply(Update::SavedMessages { messages: vec![saved("<p>Saved on the phone</p>", false)] });
    h.run();
    h.get_by_label("Saved on the phone");
}

#[test]
fn a_reply_in_its_thread_can_be_pinned() {
    let mut h = chat([1100.0, 700.0]);
    h.state_mut().apply(Update::Snapshot {
        room: ROOM.into(),
        shown: vec![
            Shown::Line(Line { cursor: 5, author: "bo@example.org".into(), html: "<p>Lunch at noon</p>".into(), edited: false }),
            Shown::Line(Line { cursor: 6, author: "cy@example.org".into(), html: "<p>Reply worth keeping</p>".into(), edited: false }),
        ],
    });
    h.state_mut().apply(Update::Threads { room: ROOM.into(), parents: vec![(6, 5)] });
    h.run();
    h.get_by_label("1 reply").click();
    h.run();
    h.get_by_label("Reply worth keeping").click();
    h.run();
    h.get_by_label("Pin message").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Pin { room: ROOM.into(), target: 6, on: true })]);
}

#[test]
fn signing_out_clears_personal_saved_messages_and_room_pins() {
    let mut h = chat([1100.0, 700.0]);
    h.state_mut().apply(Update::Pin { room: ROOM.into(), pinned: Some(pin(5, "<p>A former pin</p>")) });
    h.state_mut().apply(Update::SavedMessages { messages: vec![saved("<p>A former saved message</p>", false)] });
    h.state_mut().apply(Update::SignedOut);
    h.state_mut().apply(Update::SignedIn { email: "cy@example.org".into(), rooms: vec![ROOM.into()] });
    h.run();
    assert!(h.query_by_label("Pinned: A former pin").is_none());
    h.state_mut().take_actions();
    h.get_by_label("Saved").click();
    h.run();
    h.get_by_label("Loading saved messages...");
    assert!(h.query_by_label("A former saved message").is_none());
}
