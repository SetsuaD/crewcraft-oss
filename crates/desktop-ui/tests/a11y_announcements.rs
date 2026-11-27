//! Changes that happen away from focus are announced through a live region, read back from the accessibility tree
//! (docs/ACCESSIBILITY.md, gap 1): a new message in another room, a call someone starts, the connection lost and back.
//! Each is a polite live region, so a screen reader speaks it without moving focus, and focus stays where it was.
#![allow(clippy::unwrap_used)]

use crewcraft_client_core::room_view::OpenCall;
use crewcraft_desktop_ui::{Update, Window, fonts};
use egui::accesskit::Live;
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};

const ME: &str = "ana@example.org";

fn chat() -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size([1100.0, 700.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: ME.to_owned(), rooms: vec!["general".to_owned(), "design".to_owned()] });
    h.run();
    h.state_mut().take_actions();
    h
}

/// The node showing `text` is a polite live region.
fn announced(h: &Harness<'_, Window>, text: &str) {
    let node = h.get_by_label(text);
    assert_eq!(node.accesskit_node().live(), Live::Polite, "{text:?} is shown but not in a live region");
}

#[test]
fn a_new_message_in_another_room_is_announced_without_moving_focus() {
    let mut h = chat();
    assert_eq!(h.state().selected_room(), Some("design"), "the first room by name is open");
    h.get_by_label("Message").focus();
    h.run();
    assert!(h.get_by_label("Message").is_focused());

    h.state_mut().apply(Update::Unread { room: "general".into(), unread: 2 });
    h.run();
    announced(&h, "New messages in general: 2 unread");
    assert!(h.get_by_label("Message").is_focused(), "the announcement took focus");

    // More messages there: a new announcement replaces the old one.
    h.state_mut().apply(Update::Unread { room: "general".into(), unread: 3 });
    h.run();
    announced(&h, "New messages in general: 3 unread");
    assert!(h.query_by_label("New messages in general: 2 unread").is_none());

    // The open room's own count, and a count going down, announce nothing new.
    h.state_mut().apply(Update::Unread { room: "design".into(), unread: 4 });
    h.state_mut().apply(Update::Unread { room: "general".into(), unread: 1 });
    h.run();
    assert_eq!(h.state().announcement(), Some("New messages in general: 3 unread"));

    // Opening that room deliberately: the announcement no longer describes what the person sees, and goes.
    h.get_by_label("general  (1)").click();
    h.run();
    assert_eq!(h.state().announcement(), None);
    assert!(h.query_by_label("New messages in general: 3 unread").is_none());
}

#[test]
fn a_call_someone_starts_is_announced() {
    let mut h = chat();
    let bo = "bo@example.org";
    let open = OpenCall { call: 7, video: false, started_by: bo.into(), started_ms: 0, participants: vec![bo.into()] };
    h.state_mut().apply(Update::Calls { room: "general".into(), open: Some(open), lines: Vec::new() });
    h.run();
    announced(&h, "bo@example.org started a call in general.");
}

#[test]
fn losing_and_regaining_the_connection_is_announced() {
    let mut h = chat();
    h.state_mut().apply(Update::Failed("The connection to the server was lost.".into()));
    h.run();
    announced(&h, "The connection to the server was lost.");

    // The worker resumes the session: the window says so, and the old problem goes.
    h.state_mut().apply(Update::SignedIn { email: ME.to_owned(), rooms: vec!["general".to_owned(), "design".to_owned()] });
    h.run();
    announced(&h, "Connected to the server again.");
    assert!(h.query_by_label("The connection to the server was lost.").is_none());

    // Without a way to resume, the person is signed out and the sign-in screen says why, also as a live region.
    h.state_mut().apply(Update::SignedOut);
    h.state_mut().apply(Update::Failed("The connection was lost. Sign in again with a new code.".into()));
    h.run();
    announced(&h, "The connection was lost. Sign in again with a new code.");
    assert_eq!(h.state().announcement(), None);
}
