//! T360a2: calls in the window, driven headless through egui's accessibility tree: the room header offers Call and
//! Video call; a call someone else started rings (a notice) and shows "Call in progress" with Join; in the call it shows
//! "In call" with Leave; the call's history lines sit in the feed among the messages; an archive room has no calls.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_client_core::room_view::{OpenCall, Shown};
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::{Action, Update, Window, fonts};
use crewcraft_ui_model::Command;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const ME: &str = "ana@example.org";
const BO: &str = "bo@example.org";
const ROOM: &str = "general";

fn chat() -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size([1100.0, 700.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: ME.to_owned(), rooms: vec![ROOM.to_owned(), "old-team".to_owned()] });
    let line = |cursor, html: &str| Shown::Line(Line { cursor, author: BO.into(), html: html.into(), edited: false });
    h.state_mut().apply(Update::Snapshot { room: ROOM.into(), shown: vec![line(1, "before the call"), line(4, "after the call")] });
    h.run();
    h.state_mut().take_actions();
    h
}

fn open_call(participants: &[&str]) -> OpenCall {
    OpenCall { call: 7, video: false, started_by: BO.into(), started_ms: 0, participants: participants.iter().map(|p| (*p).to_owned()).collect() }
}

#[test]
fn the_header_starts_calls() {
    let mut h = chat();
    h.get_by_label("Call").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::CallStart { room: ROOM.into(), video: false })]);
    h.get_by_label("Video call").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::CallStart { room: ROOM.into(), video: true })]);
}

#[test]
fn a_call_rings_offers_join_and_leave_and_leaves_its_lines() {
    let mut h = chat();
    h.state_mut().apply(Update::Calls { room: ROOM.into(), open: Some(open_call(&[BO])), lines: vec![(2, "started a call".into())] });
    h.run();
    h.get_by_label("bo@example.org started a call in general.");
    h.get_by_label("Call in progress (1)");
    h.get_by_label("started a call");
    assert!(h.query_by_label("Call").is_none(), "one call at a time");
    h.get_by_label("Join call").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::CallJoin { room: ROOM.into(), call: 7 })]);

    h.state_mut().apply(Update::InCall { room: ROOM.into(), call: Some(7), reason: None });
    h.state_mut().apply(Update::Calls { room: ROOM.into(), open: Some(open_call(&[BO, ME])), lines: vec![(2, "started a call".into())] });
    h.run();
    assert_eq!(h.state().in_call(), Some((ROOM, 7)));
    h.get_by_label("In call (2)");
    h.get_by_label("Leave call").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::CallLeave { room: ROOM.into(), call: 7 })]);

    // The call ends: both lines stay in the feed, and the header offers new calls again.
    let lines = vec![(2, "started a call".into()), (3, "call ended after 2 min: ana@example.org, bo@example.org".into())];
    h.state_mut().apply(Update::InCall { room: ROOM.into(), call: None, reason: Some("The call ended.".into()) });
    h.state_mut().apply(Update::Calls { room: ROOM.into(), open: None, lines });
    h.run();
    h.get_by_label("The call ended.");
    h.get_by_label("call ended after 2 min: ana@example.org, bo@example.org");
    h.get_by_label("before the call");
    h.get_by_label("after the call");
    h.get_by_label("Call");
}

#[test]
fn an_archive_room_has_no_calls() {
    let mut h = chat();
    h.state_mut().apply(Update::Archive { room: "old-team".into(), times: Vec::new() });
    h.get_by_label("old-team").click();
    h.run();
    assert!(h.query_by_label("Call").is_none() && h.query_by_label("Video call").is_none());
}
