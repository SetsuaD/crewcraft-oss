//! T320c: message search in the window, driven headless through egui's accessibility tree: the search box sends a
//! trimmed query, the results replace the conversation, opening a result opens its room, and Close search returns.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_desktop_ui::{Action, SearchResult, Update, Window, fonts};
use crewcraft_ui_model::Command;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

fn chat() -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size([1200.0, 700.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".to_owned(), rooms: vec!["general".to_owned(), "design".to_owned()] });
    h.run();
    h.state_mut().take_actions();
    h
}

fn search_for(h: &mut Harness<'_, Window>, text: &str) {
    h.get_by_label("Search messages").click();
    h.run();
    h.get_by_label("Search messages").type_text(text);
    h.run();
    h.get_by_label("Search").click();
    h.run();
}

fn result(room: &str, cursor: u64, author: &str, snippet: &str) -> SearchResult {
    SearchResult { room: room.into(), cursor, author: author.into(), snippet: snippet.into() }
}

#[test]
fn the_search_box_sends_a_trimmed_query() {
    let mut h = chat();
    h.get_by_label("Search").click();
    h.run();
    assert!(h.state_mut().take_actions().is_empty(), "nothing to search for");
    search_for(&mut h, "  kickoff  ");
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Search { query: "kickoff".into() })]);
}

#[test]
fn results_replace_the_conversation_and_open_their_room() {
    let mut h = chat();
    h.state_mut().apply(Update::SearchResults {
        query: "kickoff".into(),
        results: vec![result("general", 7, "bo@example.org", "kickoff moved to Tuesday"), result("design", 3, "", "kickoff slides")],
    });
    h.run();
    assert_eq!(h.state().search_results(), Some(("kickoff", 2)));
    h.get_by_label("Messages matching \"kickoff\"");
    h.get_by_label("in design: kickoff slides");
    h.get_by_label("bo@example.org in general: kickoff moved to Tuesday").click();
    h.run();
    assert_eq!(h.state().search_results(), None, "opening a result closes the results");
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Sync { room: "general".into() })]);

    h.state_mut().apply(Update::SearchResults { query: "nothing".into(), results: Vec::new() });
    h.run();
    h.get_by_label("No messages match.");
    h.get_by_label("Close search").click();
    h.run();
    assert_eq!(h.state().search_results(), None);
    assert!(h.query_by_label("No messages match.").is_none());
    assert_eq!(format!("{:?}", Update::SearchResults { query: "q".into(), results: vec![result("r", 1, "", "s")] }), "SearchResults { query: \"q\", results: 1 }");
}
