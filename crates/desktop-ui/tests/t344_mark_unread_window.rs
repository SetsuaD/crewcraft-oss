//! T344: personal unread state survives display updates and changes navigation only after confirmation.

use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::{Action, PhonePane, Update, Window, fonts};
use crewcraft_ui_model::Command;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const ROOM: &str = "general";

fn line(cursor: u64, text: &str) -> Shown {
    Shown::Line(Line { cursor, author: "bo@example.org".into(), html: format!("<p>{text}</p>"), edited: false })
}

fn chat(size: [f32; 2]) -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size(size)
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".into(), rooms: vec![ROOM.into()] });
    h.state_mut().apply(Update::Snapshot { room: ROOM.into(), shown: vec![line(5, "Follow up tomorrow")] });
    h.run();
    if size[0] < 600.0 {
        h.get_by_label(ROOM).click();
        h.run();
    }
    h.state_mut().take_actions();
    h
}

#[test]
fn only_a_confirmed_unread_action_leaves_the_room_and_keyboard_reopens_it() {
    let mut h = chat([1100.0, 700.0]);
    h.get_by_label("Follow up tomorrow").click();
    h.run();
    h.get_by_label("Mark unread from here").click();
    h.run();
    assert_eq!(h.state().selected_room(), Some(ROOM));
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::MarkUnread { room: ROOM.into(), target: 5 })]);

    h.state_mut().apply(Update::Failed("The server refused that request.".into()));
    h.run();
    assert_eq!(h.state().selected_room(), Some(ROOM));
    h.get_by_label("Follow up tomorrow");

    h.state_mut().apply(Update::ReadState { room: ROOM.into(), unread: 3 });
    h.state_mut().apply(Update::MarkedUnread { room: ROOM.into() });
    h.run();
    assert_eq!(h.state().selected_room(), None);
    h.get_by_label("general  (3)");
    h.get_by_label("Choose a room to read.");

    // Confirmation restores real focus to the room button, so Enter deliberately reads it again.
    h.key_press(egui::Key::Enter);
    h.run();
    assert_eq!(h.state().selected_room(), Some(ROOM));
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Read { room: ROOM.into() })]);
}

#[test]
fn a_remote_rewind_stays_visible_in_the_selected_room_until_read_back_as_read() {
    let mut h = chat([1100.0, 700.0]);
    h.state_mut().apply(Update::ReadState { room: ROOM.into(), unread: 2 });
    h.run();
    assert_eq!(h.state().selected_room(), Some(ROOM));
    h.get_by_label("Chat (2)");
    h.get_by_label("general  (2)");

    h.state_mut().apply(Update::Snapshot { room: ROOM.into(), shown: vec![line(5, "Follow up tomorrow"), line(6, "Another message")] });
    h.run();
    h.get_by_label("general  (2)");
    assert!(h.state_mut().take_actions().is_empty());

    h.get_by_label("Mark as read").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Read { room: ROOM.into() })]);
    h.get_by_label("general  (2)");
    h.state_mut().apply(Update::ReadState { room: ROOM.into(), unread: 0 });
    h.run();
    assert_eq!(h.state().selected_room(), Some(ROOM));
    assert!(h.query_by_label("Chat (2)").is_none());
    h.get_by_role_and_label(egui::accesskit::Role::Button, ROOM);
}

#[test]
fn phone_confirmation_returns_to_the_badged_room_and_tapping_reads_it() {
    let mut h = chat([390.0, 844.0]);
    h.get_by_label("Mark as unread").click();
    h.run();
    assert_eq!(h.state().phone_pane(), PhonePane::Conversation);
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::MarkUnread { room: ROOM.into(), target: 0 })]);

    h.state_mut().apply(Update::ReadState { room: ROOM.into(), unread: 4 });
    h.state_mut().apply(Update::MarkedUnread { room: ROOM.into() });
    h.run();
    assert_eq!(h.state().phone_pane(), PhonePane::Chats);
    assert_eq!(h.state().selected_room(), None);
    h.get_by_label("Chats (4)");
    h.get_by_label("general  (4)").click();
    h.run();
    assert_eq!(h.state().phone_pane(), PhonePane::Conversation);
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Read { room: ROOM.into() })]);
}
