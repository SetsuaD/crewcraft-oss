//! T347: confirmed Activity state, stale filter replies and truthful room/thread navigation.

use crewcraft_desktop_ui::{Action, Update, Window, fonts};
use crewcraft_proto::activity::{ActivityFilter, ActivityItem, ActivityKind, ActivitySnapshot};
use crewcraft_ui_model::Command;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const ROOM: &str = "general";

fn chat(size: [f32; 2]) -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size(size)
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: "reader@example.org".into(), rooms: vec![ROOM.into()] });
    h.run();
    h.state_mut().take_actions();
    h
}

fn item(id: u64, snippet: &str, replied: bool) -> ActivityItem {
    ActivityItem {
        id,
        room: ROOM.into(),
        actor: "writer@example.org".into(),
        at_ms: 1,
        target: id + 10,
        parent: replied.then_some(1),
        kind: ActivityKind::Message { mentioned: !replied, replied },
        snippet: snippet.into(),
    }
}

fn snapshot(head: u64, seen: u64, unread: u16, items: Vec<ActivityItem>) -> ActivitySnapshot {
    ActivitySnapshot { head, seen, unread, more: false, items }
}

#[test]
fn mark_seen_waits_for_confirmation_and_an_arrival_after_the_displayed_head_stays_new() {
    let mut h = chat([1100.0, 800.0]);
    h.state_mut().apply(Update::Activity { filter: ActivityFilter::Badge, snapshot: snapshot(10, 8, 2, Vec::new()) });
    h.run();
    h.get_by_label("Activity (2)").click();
    h.run();
    h.state_mut().take_actions();
    h.state_mut().apply(Update::Activity {
        filter: ActivityFilter::All,
        snapshot: snapshot(10, 8, 2, vec![item(10, "A mention", false), item(9, "A thread reply", true)]),
    });
    h.run();
    h.get_by_label("Mark seen").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::MarkActivitySeen { through: 10 })]);
    h.get_by_label("Activity (2)");
    h.get_by_label("Waiting for confirmation...");
    h.state_mut().apply(Update::Failed("An unrelated room action failed.".into()));
    h.run();
    h.get_by_label("Waiting for confirmation...");
    h.state_mut().apply(Update::ActivityFailed { text: "The seen request was refused.".into(), refresh: false });
    h.run();
    h.get_by_label("Activity (2)");
    h.get_by_label("A mention");
    assert!(h.query_by_label("Waiting for confirmation...").is_none());
    h.get_by_label("Mark seen").click();
    h.run();
    h.state_mut().take_actions();

    h.state_mut().apply(Update::Activity { filter: ActivityFilter::Badge, snapshot: snapshot(11, 8, 3, Vec::new()) });
    h.state_mut().apply(Update::Activity {
        filter: ActivityFilter::All,
        snapshot: snapshot(11, 10, 1, vec![item(11, "Newer activity", false), item(10, "A mention", false), item(9, "A thread reply", true)]),
    });
    h.run();
    h.get_by_label("Activity (1)");
    h.get_by_label("Newer activity");
    assert!(h.query_by_label("Waiting for confirmation...").is_none());
    h.state_mut().apply(Update::Activity { filter: ActivityFilter::All, snapshot: snapshot(10, 10, 0, Vec::new()) });
    h.run();
    h.get_by_label("Activity (1)");
    h.get_by_label("Newer activity");

    h.state_mut().apply(Update::ActivityReset);
    h.run();
    h.get_by_role_and_label(egui::accesskit::Role::Button, "Activity").click();
    h.run();
    h.get_by_label("Loading activity...");
    assert!(h.query_by_label("Newer activity").is_none());
}

#[test]
fn changing_filter_ignores_late_rows_and_a_saved_reply_opens_its_real_thread_on_both_layouts() {
    for size in [[1100.0, 800.0], [390.0, 844.0]] {
        let mut h = chat(size);
        h.get_by_role_and_label(egui::accesskit::Role::Button, "Activity").click();
        h.run();
        h.state_mut().take_actions();
        let reply = item(7, "A saved reply outside the room window", true);
        h.state_mut().apply(Update::Activity { filter: ActivityFilter::All, snapshot: snapshot(7, 0, 1, vec![reply.clone()]) });
        h.run();
        h.get_by_label("Mentions").click();
        h.run();
        h.state_mut().take_actions();
        h.state_mut().apply(Update::Activity { filter: ActivityFilter::All, snapshot: snapshot(7, 0, 1, vec![reply.clone()]) });
        h.run();
        h.get_by_label("Loading activity...");
        assert!(h.query_by_label(&reply.snippet).is_none());
        h.state_mut().apply(Update::Activity { filter: ActivityFilter::Mentions, snapshot: snapshot(7, 0, 1, Vec::new()) });
        h.run();
        h.get_by_label("No matching activity.");
        h.get_by_label("Saved activity").click();
        h.run();
        h.state_mut().take_actions();
        h.state_mut().apply(Update::Activity { filter: ActivityFilter::Saved, snapshot: snapshot(7, 0, 1, vec![reply.clone()]) });
        h.run();
        h.get_by_label(&reply.snippet);
        h.get_by_label("View thread").click();
        h.run();
        assert_eq!(h.state().activity_filter(), None);
        assert_eq!(h.state().open_thread(), Some((ROOM, 1)));
        assert_eq!(
            h.state_mut().take_actions(),
            vec![Action::Room(Command::ListActivity { filter: ActivityFilter::Badge }), Action::Room(Command::Read { room: ROOM.into() }),]
        );
        h.get_by_label("The original message is unavailable in this view.");
    }
}
