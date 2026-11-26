//! T345: recovered room state clears stale metadata and keeps missing-parent replies reachable.

use crewcraft_client_core::room_view::{GapNotice, OpenCall, Shown};
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::{FileChip, Update, Window, fonts};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const ROOM: &str = "general";

fn line(cursor: u64, text: &str) -> Shown {
    Shown::Line(Line { cursor, author: "writer@example.org".into(), html: format!("<p>{text}</p>"), edited: false })
}

fn chat(size: [f32; 2]) -> Harness<'static, Window> {
    let mut h = Harness::builder().with_size(size).with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: "reader@example.org".into(), rooms: vec![ROOM.into(), "other".into()] });
    h.state_mut().apply(Update::Snapshot { room: ROOM.into(), shown: vec![line(5, "Previous body")] });
    h.run();
    if size[0] < 600.0 { h.get_by_label(ROOM).click(); h.run(); }
    h.state_mut().take_actions();
    h
}

fn gap() -> GapNotice {
    GapNotice { after: 5, oldest: 100, head: 200, older: true, recovered: true }
}

#[test]
fn recovery_clears_stale_sidecars_and_the_history_notice_survives_later_snapshots() {
    let mut h = chat([1100.0, 800.0]);
    h.state_mut().apply(Update::Archive { room: ROOM.into(), times: vec![(5, 1)] });
    h.state_mut().apply(Update::Threads { room: ROOM.into(), parents: vec![(5, 1)] });
    h.state_mut().apply(Update::Attachments { room: ROOM.into(), files: vec![(5, vec![FileChip { file: [1; 16], name: "old.txt".into(), size: 3 }])] });
    h.state_mut().apply(Update::Reactions { room: ROOM.into(), reactions: vec![(5, vec![(1, vec!["reader@example.org".into()])])] });
    h.state_mut().apply(Update::Calls {
        room: ROOM.into(),
        open: Some(OpenCall { call: 9, video: false, started_by: "writer@example.org".into(), started_ms: 0, participants: Vec::new() }),
        lines: vec![(4, "Previous call history".into())],
    });
    h.run();
    assert!(h.query_all_by_label_contains("old.txt").count() > 0);
    h.get_by_label("Replies to an unavailable message");

    h.state_mut().apply(Update::Gap { room: ROOM.into(), notice: gap() });
    h.state_mut().apply(Update::Recovered { room: ROOM.into() });
    h.state_mut().apply(Update::Snapshot { room: ROOM.into(), shown: vec![line(150, "Recovered body")] });
    h.run();
    h.get_by_label("Recovered body");
    h.get_by_label("Showing recovered current messages.");
    h.get_by_label("Earlier current messages are not loaded in this window.");
    assert_eq!(h.query_all_by_label_contains("old.txt").count(), 0);
    assert!(h.query_by_label("Previous body").is_none());
    assert!(h.query_by_label("Previous call history").is_none());
    assert!(h.query_by_label("Replies to an unavailable message").is_none());
    assert!(h.query_by_label("Archive: read only").is_none());
    h.get_by_label("Call");

    h.state_mut().apply(Update::Snapshot { room: ROOM.into(), shown: vec![line(150, "Recovered body"), line(201, "Later incremental message")] });
    h.run();
    h.get_by_label("Later incremental message");
    h.get_by_label("Showing recovered current messages.");
    h.get_by_label("other").click();
    h.run();
    assert!(h.query_by_label("Showing recovered current messages.").is_none());
    h.get_by_label(ROOM).click();
    h.run();
    h.get_by_label("Showing recovered current messages.");
}

#[test]
fn an_all_reply_window_keeps_its_true_missing_parent_and_opens_the_available_thread() {
    for size in [[1100.0, 800.0], [390.0, 844.0]] {
        let mut h = chat(size);
        // The previously cached parent must not be reused as the current parent after replacement.
        h.state_mut().apply(Update::Snapshot { room: ROOM.into(), shown: vec![line(1, "Old parent body"), line(5, "Previous body")] });
        h.state_mut().apply(Update::Threads { room: ROOM.into(), parents: vec![(5, 1)] });
        h.run();
        h.get_by_label("Old parent body");
        h.state_mut().apply(Update::Recovered { room: ROOM.into() });
        h.state_mut().apply(Update::Snapshot { room: ROOM.into(), shown: vec![line(150, "First recovered reply"), line(151, "Latest recovered reply")] });
        h.state_mut().apply(Update::Threads { room: ROOM.into(), parents: vec![(150, 1), (151, 1)] });
        h.run();
        assert!(h.query_by_label("Old parent body").is_none());
        h.get_by_label("First recovered reply");
        h.get_by_label("Latest recovered reply");
        h.get_by_label("Replies to an unavailable message");
        h.get_by_label("View thread").click();
        h.run();
        assert_eq!(h.state().open_thread(), Some((ROOM, 1)));
        h.get_by_label("The original message is unavailable in this view.");
        h.get_by_label("Close thread").click();
        h.run();
        assert!(h.state().open_thread().is_none());
        h.get_by_label("Latest recovered reply");
    }
}
