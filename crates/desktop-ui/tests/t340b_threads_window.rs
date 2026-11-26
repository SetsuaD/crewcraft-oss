//! T340b: threads in the window, driven headless through egui's accessibility tree: any message can be selected to
//! reply to it; a reply lives in its thread, not in the conversation, and "N replies" under the parent opens the
//! thread beside it, with its own composer that sends a reply.
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

fn chat(size: [f32; 2]) -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size(size)
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: ME.to_owned(), rooms: vec![ROOM.to_owned()] });
    h.state_mut().apply(Update::Snapshot {
        room: ROOM.to_owned(),
        shown: vec![line(5, "bo@example.org", "<p>the plan</p>"), line(6, ME, "<p>first reply</p>"), line(7, "cy@example.org", "<p>second reply</p>")],
    });
    h.run();
    h.state_mut().take_actions();
    h
}

#[test]
fn any_message_can_be_replied_to() {
    let mut h = chat([1100.0, 700.0]);
    h.get_by_label("the plan").click();
    h.run();
    assert!(h.query_by_label("Edit").is_none(), "someone else's message");
    h.get_by_label("Reply").click();
    h.run();
    assert_eq!(h.state().open_thread(), Some((ROOM, 5)));
    h.get_by_label("Close thread");
    h.get_by_label("Reply in thread").click();
    h.run();
    h.get_by_label("Reply in thread").type_text("  on it  ");
    h.run();
    h.get_by_label("Send reply").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Reply { room: ROOM.into(), parent: 5, text: "on it".into() })]);
    h.get_by_label("Close thread").click();
    h.run();
    assert_eq!(h.state().open_thread(), None);
}

#[test]
fn replies_live_in_their_thread() {
    let mut h = chat([1100.0, 700.0]);
    h.state_mut().apply(Update::Threads { room: ROOM.into(), parents: vec![(6, 5), (7, 5)] });
    h.run();
    assert!(h.query_by_label("first reply").is_none() && h.query_by_label("second reply").is_none(), "not in the conversation");
    h.get_by_label("2 replies").click();
    h.run();
    assert_eq!(h.state().open_thread(), Some((ROOM, 5)));
    h.get_by_label("first reply");
    h.get_by_label("second reply");
    // An empty reply is not sent.
    h.get_by_label("Send reply").click();
    h.run();
    assert!(h.state_mut().take_actions().is_empty());
}

#[test]
fn on_a_phone_the_thread_takes_the_conversations_place() {
    let mut h = chat([380.0, 760.0]);
    h.state_mut().apply(Update::Threads { room: ROOM.into(), parents: vec![(6, 5)] });
    h.run();
    // Open the conversation.
    h.get_by_label(ROOM).click();
    h.run();
    h.get_by_label("1 reply").click();
    h.run();
    h.get_by_label("first reply");
    h.get_by_label("Close thread").click();
    h.run();
    h.get_by_label("the plan");
    assert!(h.query_by_label("first reply").is_none());
}
