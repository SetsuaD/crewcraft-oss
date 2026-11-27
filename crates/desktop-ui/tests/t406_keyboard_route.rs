//! T406: the keyboard-only route through the desktop window (docs/ACCESSIBILITY.md, rule 1 of the Craft accessibility
//! standard). With Tab, Shift+Tab, Enter, Esc and typed text only, never the pointer: join from an invitation link, set up
//! the authenticator, sign in, open a room, write and send a message. Then the Calendar's form, its Cancel confirmation,
//! the guest lobby and the lobby's confirmations: each opens from a control, closes with Esc or its own button, and
//! focus goes back to the control that opened it.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_desktop_ui::{Action, Screen, Update, Window, fonts};
use crewcraft_proto::guest::{GuestEntry, GuestLobby, GuestState};
use crewcraft_proto::meeting::{Audience, Meeting, MeetingState};
use crewcraft_ui_model::Command;
use crewcraft_ui_model::guest::{GuestCommand, GuestUpdate};
use egui::{Event, Key, Modifiers};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const LINK: &str = "crewcraft://enroll?server=chat.example.org:7443&code=ABCD";
const URI: &str = "otpauth://totp/CrewCraft:ana%40example.org?issuer=CrewCraft";
const ME: &str = "ana@example.org";
/// Monday 2026-11-23 00:00 UTC, and Wednesday of that week.
const MONDAY: u64 = 1_795_392_000_000;
const DAY: u64 = 24 * 60 * 60 * 1000;
const NOW: u64 = MONDAY + 2 * DAY;

fn window() -> Harness<'static, Window> {
    Harness::builder()
        .with_size([1100.0, 760.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new())
}

/// Let the window settle: a focus request lands on the next frame.
fn settle(h: &mut Harness<'_, Window>) {
    h.run();
    h.run();
}

fn press(h: &mut Harness<'_, Window>, key: Key) {
    h.key_press(key);
    settle(h);
}

fn shift_tab(h: &mut Harness<'_, Window>) {
    h.key_press_modifiers(Modifiers::SHIFT, Key::Tab);
    settle(h);
}

/// Type into whatever has keyboard focus, as a keyboard does.
fn typed(h: &mut Harness<'_, Window>, text: &str) {
    h.event(Event::Text(text.to_owned()));
    settle(h);
}

fn apply(h: &mut Harness<'_, Window>, update: Update) {
    h.state_mut().apply(update);
    settle(h);
}

#[track_caller]
fn assert_focused(h: &Harness<'_, Window>, label: &str) {
    assert!(h.get_by_label(label).is_focused(), "focus is not on {label:?}");
}

/// Press Tab until `label` has focus, at most `most` times: the control can be reached from the keyboard.
#[track_caller]
fn tab_to(h: &mut Harness<'_, Window>, label: &str, most: usize) {
    for _ in 0..most {
        press(h, Key::Tab);
        if h.query_by_label(label).is_some_and(|node| node.is_focused()) {
            return;
        }
    }
    panic!("{most} presses of Tab did not reach {label:?}");
}

fn signed_in(rooms: &[&str]) -> Harness<'static, Window> {
    let mut h = window();
    apply(&mut h, Update::SignedIn { email: ME.to_owned(), rooms: rooms.iter().map(|room| (*room).to_owned()).collect() });
    h.state_mut().take_actions();
    h
}

fn meeting(id: u64, room: &str, title: &str, audience: Audience) -> Meeting {
    Meeting {
        id,
        room: room.into(),
        version: 1,
        owner: ME.into(),
        audience,
        start_ms: NOW + 60 * 60 * 1000,
        duration: 30,
        title: title.into(),
        agenda: String::new(),
        state: MeetingState::Scheduled,
    }
}

/// Open the Calendar from its app-bar button by keyboard, and give it a week with `meetings`.
fn open_calendar(h: &mut Harness<'_, Window>, meetings: Vec<Meeting>) {
    tab_to(h, "Calendar", 30);
    press(h, Key::Enter);
    assert!(h.state().calendar_open(), "Enter on Calendar did not open it");
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::ListMeetings { weeks: 0 })]);
    apply(h, Update::Meetings { from_ms: MONDAY, to_ms: MONDAY + 5 * DAY, now_ms: NOW, meetings, more: false });
}

#[test]
fn join_set_up_the_authenticator_sign_in_open_a_room_and_send_by_keyboard() {
    let mut h = window();
    settle(&mut h);
    assert_eq!(h.state().screen(), Screen::Enroll);

    // Join: the first Tab reaches the invitation link, the next the password, Shift+Tab goes back, and Enter on the
    // focused button enrolls.
    press(&mut h, Key::Tab);
    assert_focused(&h, "Invitation link");
    typed(&mut h, LINK);
    press(&mut h, Key::Tab);
    assert_focused(&h, "New password");
    typed(&mut h, "typed in a test");
    shift_tab(&mut h);
    assert_focused(&h, "Invitation link");
    press(&mut h, Key::Tab);
    press(&mut h, Key::Tab);
    assert_focused(&h, "Enroll this device");
    press(&mut h, Key::Enter);
    match h.state_mut().take_actions().as_slice() {
        [Action::Enroll { link, password }] => {
            assert_eq!(link.as_str(), LINK);
            assert_eq!(password.as_str(), "typed in a test");
        }
        other => panic!("unexpected {other:?}"),
    }

    // The authenticator: a new screen starts with nothing focused, and Tab walks the entry (named, so it can be found
    // and read), Copy entry and the code. Enter in the code field confirms once it is a code, and keeps focus there
    // until then.
    apply(&mut h, Update::AuthenticatorSetup { otpauth_uri: URI.to_owned() });
    assert_eq!(h.state().screen(), Screen::Authenticator);
    press(&mut h, Key::Tab);
    assert_focused(&h, "Authenticator entry");
    assert_eq!(h.get_by_label("Authenticator entry").value().as_deref(), Some(URI));
    press(&mut h, Key::Tab);
    assert_focused(&h, "Copy entry");
    press(&mut h, Key::Tab);
    assert_focused(&h, "Authenticator code");
    typed(&mut h, "12345");
    press(&mut h, Key::Enter);
    assert!(h.state_mut().take_actions().is_empty(), "five digits is not a code");
    assert_focused(&h, "Authenticator code");
    typed(&mut h, "6");
    press(&mut h, Key::Enter);
    match h.state_mut().take_actions().as_slice() {
        [Action::ConfirmAuthenticator { code }] => assert_eq!(code.as_str(), "123456"),
        other => panic!("unexpected {other:?}"),
    }

    // Sign in: email, password, code, then Enter on Sign in.
    apply(&mut h, Update::Enrolled { server: "chat.example.org".to_owned() });
    assert_eq!(h.state().screen(), Screen::SignIn);
    press(&mut h, Key::Tab);
    assert_focused(&h, "Email");
    typed(&mut h, ME);
    press(&mut h, Key::Tab);
    assert_focused(&h, "Password");
    typed(&mut h, "pw");
    press(&mut h, Key::Tab);
    assert_focused(&h, "Authenticator code");
    typed(&mut h, "654321");
    press(&mut h, Key::Tab);
    assert_focused(&h, "Sign in");
    press(&mut h, Key::Enter);
    match h.state_mut().take_actions().as_slice() {
        [Action::SignIn { email, password, code }] => {
            assert_eq!(email, ME);
            assert_eq!(password.as_str(), "pw");
            assert_eq!(code.as_str(), "654321");
        }
        other => panic!("unexpected {other:?}"),
    }

    // The chat: Tab reaches the second room's button, and Enter opens it deliberately.
    apply(&mut h, Update::SignedIn { email: ME.to_owned(), rooms: vec!["general".to_owned(), "random".to_owned()] });
    assert_eq!(h.state().screen(), Screen::Chat);
    assert_eq!(h.state().selected_room(), Some("general"));
    h.state_mut().take_actions();
    tab_to(&mut h, "random", 30);
    press(&mut h, Key::Enter);
    assert_eq!(h.state().selected_room(), Some("random"));
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Read { room: "random".to_owned() })]);

    // Tab on to the message box, type, and Enter sends; focus stays in the box for the next message.
    tab_to(&mut h, "Message", 30);
    typed(&mut h, "ship it");
    press(&mut h, Key::Enter);
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Post { room: "random".to_owned(), text: "ship it".to_owned() })]);
    assert_focused(&h, "Message");
    assert_eq!(h.get_by_label("Message").value().unwrap_or_default(), "");
}

#[test]
fn enter_in_the_password_field_enrolls() {
    let mut h = window();
    settle(&mut h);
    press(&mut h, Key::Tab);
    typed(&mut h, LINK);
    press(&mut h, Key::Tab);
    assert_focused(&h, "New password");
    typed(&mut h, "typed in a test");
    press(&mut h, Key::Enter);
    assert!(matches!(h.state_mut().take_actions().as_slice(), [Action::Enroll { .. }]));
}

#[test]
fn closing_the_calendar_form_and_its_confirmation_brings_focus_back() {
    let mut h = signed_in(&["general"]);
    open_calendar(&mut h, vec![meeting(7, "general", "Weekly review", Audience::Staff)]);

    // The edit form opens with focus in its title; Esc closes it unsaved and focus is back on Edit.
    tab_to(&mut h, "Edit Weekly review", 30);
    press(&mut h, Key::Enter);
    assert_focused(&h, "Title");
    press(&mut h, Key::Escape);
    assert!(h.query_by_label("Title").is_none(), "Esc did not close the form");
    assert!(h.state_mut().take_actions().is_empty(), "Esc saved the form");
    assert_focused(&h, "Edit Weekly review");

    // The form's own Discard changes, by keyboard, does the same.
    press(&mut h, Key::Enter);
    assert_focused(&h, "Title");
    tab_to(&mut h, "Discard changes", 10);
    press(&mut h, Key::Enter);
    assert!(h.query_by_label("Title").is_none());
    assert_focused(&h, "Edit Weekly review");

    // Cancel asks first, with focus on the safe answer. Esc keeps the meeting, and so does Enter on Keep; either way
    // focus is back on Cancel and nothing is sent.
    press(&mut h, Key::Tab);
    assert_focused(&h, "Cancel Weekly review");
    press(&mut h, Key::Enter);
    assert_focused(&h, "Keep the meeting");
    press(&mut h, Key::Escape);
    assert!(h.query_by_label("Keep the meeting").is_none(), "Esc did not close the confirmation");
    assert_focused(&h, "Cancel Weekly review");
    press(&mut h, Key::Enter);
    assert_focused(&h, "Keep the meeting");
    press(&mut h, Key::Enter);
    assert!(h.query_by_label("Keep the meeting").is_none());
    assert_focused(&h, "Cancel Weekly review");
    assert!(h.state_mut().take_actions().is_empty(), "keeping the meeting sent something");

    // A new meeting's form returns focus to Schedule a meeting.
    tab_to(&mut h, "Schedule a meeting", 40);
    press(&mut h, Key::Enter);
    assert_focused(&h, "Title");
    press(&mut h, Key::Escape);
    assert_focused(&h, "Schedule a meeting");

    // With nothing open inside it, Esc closes the Calendar and focus is back on the Calendar button.
    press(&mut h, Key::Escape);
    assert!(!h.state().calendar_open(), "Esc did not close the Calendar");
    assert_focused(&h, "Calendar");

    // Close calendar, by keyboard, does the same.
    press(&mut h, Key::Enter);
    assert!(h.state().calendar_open());
    h.state_mut().take_actions();
    tab_to(&mut h, "Close calendar", 40);
    press(&mut h, Key::Enter);
    assert!(!h.state().calendar_open());
    assert_focused(&h, "Calendar");
}

#[test]
fn leaving_the_guest_lobby_and_its_confirmations_brings_focus_back() {
    const ROOM: &str = "planning";
    let mut h = signed_in(&[ROOM]);
    apply(&mut h, Update::GuestLobby(GuestUpdate::Available(true)));
    open_calendar(&mut h, vec![meeting(7, ROOM, "Guest review", Audience::Guests)]);

    // The lobby opens with focus on Back to calendar.
    tab_to(&mut h, "Lobby Guest review", 30);
    press(&mut h, Key::Enter);
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::GuestLobby(GuestCommand::Open { room: ROOM.into(), meeting: 7 }))]);
    assert_focused(&h, "Back to calendar");
    let lobby = GuestLobby {
        meeting: 7,
        revision: 2,
        expires_ms: NOW + DAY,
        lobby: true,
        closed: false,
        entries: vec![
            GuestEntry { guest: 11, name: "Alex".into(), state: GuestState::Waiting, revision: 1 },
            GuestEntry { guest: 12, name: "Sam".into(), state: GuestState::Admitted, revision: 2 },
        ],
    };
    apply(&mut h, Update::GuestLobby(GuestUpdate::Snapshot { room: ROOM.into(), lobby, code: None }));

    // Close guest link asks first, with focus on the safe answer; Esc or Enter on Keep link open dismisses it, and
    // focus is back on Close guest link.
    tab_to(&mut h, "Close guest link", 10);
    press(&mut h, Key::Enter);
    assert_focused(&h, "Keep link open");
    press(&mut h, Key::Escape);
    assert!(h.query_by_label("Keep link open").is_none(), "Esc did not dismiss the confirmation");
    assert_focused(&h, "Close guest link");
    press(&mut h, Key::Enter);
    assert_focused(&h, "Keep link open");
    press(&mut h, Key::Enter);
    assert_focused(&h, "Close guest link");

    // Removing a guest asks the same way.
    tab_to(&mut h, "Remove Sam", 10);
    press(&mut h, Key::Enter);
    assert_focused(&h, "Keep guest");
    press(&mut h, Key::Escape);
    assert_focused(&h, "Remove Sam");
    assert!(h.state_mut().take_actions().is_empty(), "a dismissed confirmation sent something");

    // With no confirmation showing, Esc leaves the lobby, and focus is back on the button that opened it.
    press(&mut h, Key::Escape);
    assert!(h.query_by_label("Back to calendar").is_none(), "Esc did not leave the lobby");
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::GuestLobby(GuestCommand::ClosePanel))]);
    assert_focused(&h, "Lobby Guest review");
}
