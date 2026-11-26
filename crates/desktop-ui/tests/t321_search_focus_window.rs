//! T321: opening a search result opens its room on the message (REQUIREMENTS 2.1 "opening a result opens the room
//! around it"): the message is the window's focus (highlighted and scrolled to once), a reply opens its thread on its
//! parent, and opening another room drops the focus.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::{SearchResult, Update, Window, fonts};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

fn line(cursor: u64, html: &str) -> Shown {
    Shown::Line(Line { cursor, author: "bo@example.org".into(), html: html.into(), edited: false })
}

fn chat() -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size([1100.0, 700.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".to_owned(), rooms: vec!["general".to_owned(), "design".to_owned()] });
    // Many messages, so the one found is far from the bottom.
    let mut shown: Vec<Shown> = (1..=60).map(|n| line(n, &format!("message number {n}"))).collect();
    shown.push(line(61, "a reply in a thread"));
    h.state_mut().apply(Update::Snapshot { room: "design".into(), shown });
    h.state_mut().apply(Update::Threads { room: "design".into(), parents: vec![(61, 5)] });
    h.run();
    h.state_mut().take_actions();
    h
}

fn result(cursor: u64, snippet: &str) -> SearchResult {
    SearchResult { room: "design".into(), cursor, author: "bo@example.org".into(), snippet: snippet.into() }
}

#[test]
fn a_result_opens_its_room_on_the_message() {
    let mut h = chat();
    h.state_mut().apply(Update::SearchResults { query: "number 7".into(), results: vec![result(7, "message number 7")] });
    h.run();
    h.get_by_label("bo@example.org in design: message number 7").click();
    h.run();
    h.run();
    assert_eq!(h.state().focus(), Some(("design", 7)));
    h.get_by_label("message number 7");
    // Opening another room drops it.
    h.get_by_label("general").click();
    h.run();
    assert_eq!(h.state().focus(), None);
}

#[test]
fn a_reply_opens_its_thread() {
    let mut h = chat();
    h.state_mut().apply(Update::SearchResults { query: "reply".into(), results: vec![result(61, "a reply in a thread")] });
    h.run();
    h.get_by_label("bo@example.org in design: a reply in a thread").click();
    h.run();
    assert_eq!(h.state().open_thread(), Some(("design", 5)));
    assert_eq!(h.state().focus(), Some(("design", 5)), "the conversation shows the reply's parent");
    h.get_by_label("a reply in a thread");
}
