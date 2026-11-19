//! T402: the phone layout. At phone width the chat screen shows one pane at a time with a bottom tab bar: the room
//! list (Chats), a conversation with a way back, and the account with sign-out. Desktop width keeps the side-by-side
//! layout.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::{Action, PhonePane, Update, Window, fonts};
use crewcraft_ui_model::Command;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

fn harness(width: f32, height: f32) -> Harness<'static, Window> {
    Harness::builder()
        .with_size([width, height])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new())
}

fn signed_in(h: &mut Harness<'_, Window>) {
    h.state_mut().apply(Update::Enrolled { server: "chat.example.org".to_owned() });
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".to_owned(), rooms: vec!["general".to_owned(), "design".to_owned()] });
    h.run();
    let _ = h.state_mut().take_actions();
}

#[test]
fn a_phone_shows_the_room_list_first_with_a_tab_bar() {
    let mut h = harness(390.0, 844.0);
    signed_in(&mut h);
    assert_eq!(h.state().phone_pane(), PhonePane::Chats);
    h.get_by_label("Chats");
    h.get_by_label("Account");
    h.get_by_label("general");
    h.get_by_label("design");
    // The desktop's side panel is not drawn on a phone.
    assert!(h.query_by_label("Rooms").is_none());
}

#[test]
fn tapping_a_room_opens_it_full_screen_and_back_returns_to_the_list() {
    let mut h = harness(390.0, 844.0);
    signed_in(&mut h);
    h.state_mut().apply(Update::Unread { room: "general".to_owned(), unread: 2 });
    h.run();
    h.get_by_label("Chats (2)");
    h.get_by_label("general  (2)").click();
    h.run();
    assert_eq!(h.state().phone_pane(), PhonePane::Conversation);
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Sync { room: "general".to_owned() })]);
    // In a conversation the tab bar gives way to the composer.
    assert!(h.query_by_label("Account").is_none());
    h.get_by_label("Message");
    h.state_mut().apply(Update::Snapshot {
        room: "general".to_owned(),
        shown: vec![Shown::Line(Line { cursor: 1, author: "bo@example.org".to_owned(), html: "<p>hi from the desk</p>".to_owned(), edited: false })],
    });
    h.run();
    h.get_by_label("hi from the desk");
    h.get_by_label("< Chats").click();
    h.run();
    assert_eq!(h.state().phone_pane(), PhonePane::Chats);
    h.get_by_label("Account");
}

#[test]
fn the_account_tab_signs_out() {
    let mut h = harness(390.0, 844.0);
    signed_in(&mut h);
    h.get_by_label("Account").click();
    h.run();
    assert_eq!(h.state().phone_pane(), PhonePane::Account);
    h.get_by_label("Signed in as ana@example.org");
    h.get_by_label("Sign out").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::SignOut]);
    h.state_mut().apply(Update::SignedOut);
    h.run();
    assert_eq!(h.state().phone_pane(), PhonePane::Chats);
}

#[test]
fn a_desktop_width_keeps_the_side_by_side_layout() {
    let mut h = harness(1000.0, 700.0);
    signed_in(&mut h);
    h.get_by_label("Rooms");
    h.get_by_label("Sign out");
    assert!(h.query_by_label("Account").is_none());
}
