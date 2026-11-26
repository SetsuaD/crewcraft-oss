//! T315: the wide chat screen in the familiar team-chat layout (REQUIREMENTS 2.20): a title bar with room search and
//! the unread total, an app bar with Chat, the room list pane, a conversation header, and the feed as bubbles (the
//! person's own on the right, others on the left with the author's name) in the theme's bubble colours.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::appearance::BubbleColors;
use crewcraft_desktop_ui::{Side, Update, Window, fonts, side, visible_rooms};
use crewcraft_ui_model::{FeedRow, RoomRow};
use egui::Color32;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

fn harness() -> Harness<'static, Window> {
    Harness::builder()
        .with_size([1100.0, 700.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new())
}

fn line(cursor: u64, author: &str, html: &str) -> Shown {
    Shown::Line(Line { cursor, author: author.to_owned(), html: html.to_owned(), edited: false })
}

fn message(author: &str) -> FeedRow {
    FeedRow::Message { cursor: 1, author: author.to_owned(), html: "<p>x</p>".to_owned(), edited: false, first_of_group: true }
}

fn row(name: &str) -> RoomRow {
    RoomRow { name: name.to_owned(), unread: 0, selected: false }
}

#[test]
fn own_messages_are_on_the_right() {
    assert_eq!(side(&message("ana@example.org"), "ana@example.org"), Side::Mine);
    assert_eq!(side(&message(" Ana@Example.org "), "ana@example.org"), Side::Mine, "email case and spaces");
    assert_eq!(side(&message("bo@example.org"), "ana@example.org"), Side::Theirs);
    assert_eq!(side(&message("ana@example.org"), ""), Side::Theirs, "nobody signed in owns nothing");
    assert_eq!(side(&FeedRow::Pending { id: 1, body: "x".to_owned(), failed: false }, "ana@example.org"), Side::Mine);
}

#[test]
fn the_search_box_filters_the_room_list() {
    let rows = vec![row("general"), row("Design"), row("design-review")];
    let names = |rows: Vec<RoomRow>| rows.into_iter().map(|r| r.name).collect::<Vec<_>>();
    assert_eq!(names(visible_rooms(rows.clone(), "  DES ")), ["Design", "design-review"]);
    assert_eq!(names(visible_rooms(rows.clone(), "")), ["general", "Design", "design-review"]);
    assert!(visible_rooms(rows, "zzz").is_empty());
}

#[test]
fn bubble_colours_come_from_the_theme() {
    let theme = crewcraft_theme::builtin_themes().into_iter().next().unwrap();
    let colors = BubbleColors::from_theme(&theme);
    let token = |variant, name| {
        let c = theme.palette(variant).get(name).unwrap();
        Color32::from_rgb(c.r, c.g, c.b)
    };
    assert_eq!(colors.pick(true, false), token(crewcraft_theme::Variant::Light, "bubble-mine"));
    assert_eq!(colors.pick(false, false), token(crewcraft_theme::Variant::Light, "bubble-other"));
    assert_eq!(colors.pick(true, true), token(crewcraft_theme::Variant::Dark, "bubble-mine"));
    assert_eq!(colors.pick(false, true), token(crewcraft_theme::Variant::Dark, "bubble-other"));
}

#[test]
fn the_wide_layout_has_its_bars_panes_and_bubbles() {
    let mut h = harness();
    h.state_mut().set_title("Example Org");
    h.state_mut().apply(Update::Enrolled { server: "chat.example.org:7443".to_owned() });
    h.state_mut()
        .apply(Update::SignedIn { email: "ana@example.org".to_owned(), rooms: vec!["general".to_owned(), "Design".to_owned(), "Sales".to_owned()] });
    h.run();
    let _ = h.state_mut().take_actions();
    // Title bar: the organization, the search box, the account; app bar: Chat; list pane: the rooms.
    h.get_by_label("Example Org");
    h.get_by_label("Search rooms");
    h.get_by_label("chat.example.org:7443");
    h.get_by_label("Chat");
    h.get_by_label("Rooms");
    // "Design" is open (rooms sort ignoring case): once in the list, once as the conversation header.
    assert_eq!(h.get_all_by_label("Design").count(), 2);

    h.state_mut().apply(Update::Snapshot {
        room: "Design".to_owned(),
        shown: vec![
            line(1, "bo@example.org", "<p>Morning</p>"),
            line(2, "ana@example.org", "<p>Hi Bo</p>"),
            Shown::Pending { id: 9, body: "on my way".to_owned(), failed: false },
        ],
    });
    h.run();
    h.get_by_label("Morning");
    h.get_by_label("Hi Bo");
    h.get_by_label("on my way  (Sending)");
    h.get_by_label("bo@example.org");
    // Ana's own name is not drawn over her bubble: the only "ana@example.org" is the account in the title bar.
    assert_eq!(h.get_all_by_label("ana@example.org").count(), 1);

    // Unread shows in the title bar, on the app bar and on the room.
    h.state_mut().apply(Update::Unread { room: "Sales".to_owned(), unread: 2 });
    h.run();
    h.get_by_label("2 unread");
    h.get_by_label("Chat (2)");
    h.get_by_label("Sales  (2)");

    // Searching narrows the list; a search with no match says so.
    h.get_by_label("Search rooms").click();
    h.run();
    h.get_by_label("Search rooms").type_text("sal");
    h.run();
    assert!(h.query_by_label("general").is_none());
    h.get_by_label("Sales  (2)");
    h.get_by_label("Search rooms").type_text("zzz");
    h.run();
    h.get_by_label("No room matches.");
}

#[test]
fn bubble_colours_reach_the_window_without_changing_its_labels() {
    let mut h = harness();
    let theme = crewcraft_theme::builtin_themes().into_iter().next().unwrap();
    h.state_mut().set_bubble_colors(BubbleColors::from_theme(&theme));
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".to_owned(), rooms: vec!["general".to_owned()] });
    h.state_mut().apply(Update::Snapshot { room: "general".to_owned(), shown: vec![line(1, "ana@example.org", "<p>Mine</p>")] });
    h.run();
    h.get_by_label("Mine");
}
