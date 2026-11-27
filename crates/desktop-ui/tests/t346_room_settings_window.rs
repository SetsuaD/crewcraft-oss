//! T346: the person's own room settings order, mark and filter the room list, and the room menu changes them only
//! through commands the worker confirms.

use crewcraft_client_core::room_view::{RoomSetting, RoomSettings};
use crewcraft_desktop_ui::{Action, PhonePane, Update, Window, fonts};
use crewcraft_ui_model::Command;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

fn harness(size: [f32; 2]) -> Harness<'static, Window> {
    Harness::builder()
        .with_size(size)
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new())
}

fn set(h: &mut Harness<'static, Window>, room: &str, settings: RoomSettings) {
    h.state_mut().apply(Update::RoomSettings { room: room.into(), settings });
}

fn signed_in(h: &mut Harness<'static, Window>) {
    let rooms = ["alpha", "beta", "gamma", "delta"].map(str::to_owned).to_vec();
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".into(), rooms });
    h.run();
}

#[test]
fn settings_known_at_sign_in_lead_with_the_pinned_room_mark_muted_rooms_and_hide_hidden_ones_until_searched() {
    let mut h = harness([1100.0, 700.0]);
    // The worker reports the person's settings before SignedIn, so the first room opened is the pinned one.
    set(&mut h, "gamma", RoomSettings { pinned: true, ..RoomSettings::default() });
    set(&mut h, "beta", RoomSettings { hidden: true, ..RoomSettings::default() });
    set(&mut h, "delta", RoomSettings { muted: true, ..RoomSettings::default() });
    signed_in(&mut h);
    assert_eq!(h.state().selected_room(), Some("gamma"));
    h.state_mut().take_actions();
    h.get_by_label("gamma  pinned");
    assert!(h.query_by_label("beta").is_none(), "a hidden room is not in the list");

    // A muted room shows its own count and says it is muted, but adds nothing to the total; a new message in the
    // hidden room does not bring it back.
    h.state_mut().apply(Update::Unread { room: "alpha".into(), unread: 2 });
    h.state_mut().apply(Update::Unread { room: "delta".into(), unread: 3 });
    h.state_mut().apply(Update::Unread { room: "beta".into(), unread: 4 });
    h.run();
    h.get_by_label("delta  (3)  muted");
    h.get_by_label("Chat (2)");
    assert!(h.query_by_label("beta  (4)  hidden").is_none());

    // The room search still finds the hidden room, under its own heading, and opens it.
    h.get_by_label("Search rooms").click();
    h.run();
    h.get_by_label("Search rooms").type_text("bet");
    h.run();
    h.get_by_label("Hidden");
    h.get_by_label("beta  (4)  hidden").click();
    h.run();
    assert_eq!(h.state().selected_room(), Some("beta"));
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Read { room: "beta".into() })]);
    // Opening it makes the worker report its unchanged settings again; that does not close it.
    set(&mut h, "beta", RoomSettings { hidden: true, ..RoomSettings::default() });
    h.run();
    assert_eq!(h.state().selected_room(), Some("beta"));
    h.get_by_label("Show in list");
}

#[test]
fn the_room_menu_asks_the_worker_and_the_list_follows_only_the_confirmed_settings() {
    let mut h = harness([1100.0, 700.0]);
    signed_in(&mut h);
    assert_eq!(h.state().selected_room(), Some("alpha"));
    h.state_mut().take_actions();

    h.get_by_label("Pin to top").click();
    h.run();
    h.get_by_label("Mute").click();
    h.run();
    assert_eq!(
        h.state_mut().take_actions(),
        vec![
            Action::Room(Command::SetRoomSetting { room: "alpha".into(), setting: RoomSetting::Pinned, on: true }),
            Action::Room(Command::SetRoomSetting { room: "alpha".into(), setting: RoomSetting::Muted, on: true }),
        ]
    );
    // Nothing changes until the worker reports what the server stored.
    h.get_by_role_and_label(egui::accesskit::Role::Button, "alpha");
    set(&mut h, "alpha", RoomSettings { pinned: true, muted: true, hidden: false });
    h.run();
    h.get_by_label("alpha  pinned, muted");
    h.get_by_label("Unpin from top");
    h.get_by_label("Unmute").click();
    h.run();
    assert_eq!(
        h.state_mut().take_actions(),
        vec![Action::Room(Command::SetRoomSetting { room: "alpha".into(), setting: RoomSetting::Muted, on: false })]
    );

    // Hiding the open room closes its conversation along with its row.
    h.get_by_label("Hide from list").click();
    h.run();
    assert_eq!(
        h.state_mut().take_actions(),
        vec![Action::Room(Command::SetRoomSetting { room: "alpha".into(), setting: RoomSetting::Hidden, on: true })]
    );
    set(&mut h, "alpha", RoomSettings { pinned: true, muted: true, hidden: true });
    h.run();
    assert_eq!(h.state().selected_room(), None);
    assert!(h.query_by_label("alpha  pinned, muted, hidden").is_none());
    h.get_by_label("Choose a room to read.");
}

#[test]
fn a_phone_lists_pinned_rooms_first_and_hiding_the_open_room_returns_to_the_list() {
    let mut h = harness([390.0, 844.0]);
    set(&mut h, "delta", RoomSettings { pinned: true, ..RoomSettings::default() });
    signed_in(&mut h);
    h.get_by_label("delta  pinned").click();
    h.run();
    assert_eq!(h.state().phone_pane(), PhonePane::Conversation);
    h.get_by_label("Hide from list").click();
    h.run();
    assert_eq!(
        h.state_mut().take_actions().last(),
        Some(&Action::Room(Command::SetRoomSetting { room: "delta".into(), setting: RoomSetting::Hidden, on: true }))
    );
    set(&mut h, "delta", RoomSettings { pinned: true, hidden: true, ..RoomSettings::default() });
    h.run();
    assert_eq!(h.state().phone_pane(), PhonePane::Chats);
    assert!(h.query_by_label("delta  pinned, hidden").is_none());
    h.get_by_label("alpha");
}
