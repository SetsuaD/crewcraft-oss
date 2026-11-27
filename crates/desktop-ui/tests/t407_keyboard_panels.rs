//! T407: closing the chat's panes and confirmations by keyboard, and hearing a new screen (docs/ACCESSIBILITY.md, gaps 6
//! and 11; rules 1 and 4 of the Craft accessibility standard). With Tab, Shift+Tab, Enter, Esc and typed text only: a
//! message's Delete confirmation opens with focus on Keep, and Esc or Keep puts focus back on Delete; the thread pane,
//! Files, Saved, Activity and the search results close on Esc and on their own close button, with focus back on the
//! control that opened them; after a confirmed change in the guest lobby focus is on Back to calendar, not nowhere. Each
//! new screen on the way in is said through a polite live region while focus stays on nothing, so no field is focused
//! for the person and a phone raises no keyboard on its own.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::{Action, SearchResult, Update, Window, fonts};
use crewcraft_proto::guest::{GuestEntry, GuestLobby, GuestState};
use crewcraft_proto::meeting::{Audience, Meeting, MeetingState};
use crewcraft_ui_model::Command;
use crewcraft_ui_model::guest::{GuestCommand, GuestDecision, GuestUpdate};
use egui::accesskit::Live;
use egui::{Event, Key, Modifiers};
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};

const LINK: &str = "crewcraft://enroll?server=chat.example.org:7443&code=ABCD";
const URI: &str = "otpauth://totp/CrewCraft:ana%40example.org?issuer=CrewCraft";
const ME: &str = "ana@example.org";
const BO: &str = "bo@example.org";
const ROOM: &str = "general";
const LOBBY_ROOM: &str = "planning";
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

#[track_caller]
fn assert_nothing_focused(h: &Harness<'_, Window>) {
    assert_eq!(h.ctx.memory(|memory| memory.focused()), None, "something has keyboard focus");
}

/// `text` is shown in a polite live region, so a screen reader says it without focus moving there.
#[track_caller]
fn assert_live(h: &Harness<'_, Window>, text: &str) {
    assert_eq!(h.get_by_label(text).accesskit_node().live(), Live::Polite, "{text:?} is not in a live region");
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

fn line(cursor: u64, author: &str, html: &str) -> Shown {
    Shown::Line(Line { cursor, author: author.to_owned(), html: html.to_owned(), edited: false })
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

/// Whether a pane of the window is open.
type IsOpen = fn(&Window) -> bool;

fn activity_open(window: &Window) -> bool {
    window.activity_filter().is_some()
}

#[test]
fn the_delete_confirmation_opens_on_keep_and_closing_it_brings_focus_back_to_delete() {
    let mut h = signed_in(&[ROOM]);
    apply(&mut h, Update::Snapshot { room: ROOM.into(), shown: vec![line(5, ME, "<p>my note</p>")] });

    // A message takes focus, and Enter selects it; its Delete asks first, with focus on the safe answer.
    tab_to(&mut h, "my note", 40);
    press(&mut h, Key::Enter);
    tab_to(&mut h, "Delete", 20);
    press(&mut h, Key::Enter);
    h.get_by_label("Delete this message?");
    assert_focused(&h, "Keep");

    // Esc keeps the message, and focus is back on Delete.
    press(&mut h, Key::Escape);
    assert!(h.query_by_label("Delete this message?").is_none(), "Esc did not close the confirmation");
    assert_focused(&h, "Delete");

    // Enter on Keep does the same.
    press(&mut h, Key::Enter);
    assert_focused(&h, "Keep");
    press(&mut h, Key::Enter);
    assert!(h.query_by_label("Delete this message?").is_none());
    assert_focused(&h, "Delete");
    assert!(h.state_mut().take_actions().is_empty(), "keeping the message sent something");
}

#[test]
fn the_thread_pane_closes_with_focus_back_on_what_opened_it() {
    let mut h = signed_in(&[ROOM]);
    apply(
        &mut h,
        Update::Snapshot {
            room: ROOM.into(),
            shown: vec![line(5, BO, "<p>the plan</p>"), line(6, ME, "<p>on it</p>"), line(7, BO, "<p>a question</p>")],
        },
    );
    apply(&mut h, Update::Threads { room: ROOM.into(), parents: vec![(6, 5)] });

    // The reply count opens the thread; Esc closes it and focus is back on the reply count.
    tab_to(&mut h, "1 reply", 40);
    press(&mut h, Key::Enter);
    assert_eq!(h.state().open_thread(), Some((ROOM, 5)));
    press(&mut h, Key::Escape);
    assert_eq!(h.state().open_thread(), None, "Esc did not close the thread");
    assert_focused(&h, "1 reply");

    // Close thread, by keyboard, does the same.
    press(&mut h, Key::Enter);
    assert_eq!(h.state().open_thread(), Some((ROOM, 5)));
    tab_to(&mut h, "Close thread", 40);
    press(&mut h, Key::Enter);
    assert_eq!(h.state().open_thread(), None);
    assert_focused(&h, "1 reply");

    // Reply under a selected message goes away with the selection, so focus comes back to the message itself.
    tab_to(&mut h, "a question", 40);
    press(&mut h, Key::Enter);
    tab_to(&mut h, "Reply", 20);
    press(&mut h, Key::Enter);
    assert_eq!(h.state().open_thread(), Some((ROOM, 7)));
    press(&mut h, Key::Escape);
    assert_eq!(h.state().open_thread(), None);
    assert_focused(&h, "a question");
}

#[test]
fn files_saved_and_activity_close_on_esc_with_focus_back_on_their_button() {
    let mut h = signed_in(&[ROOM]);
    let panes: [(&str, IsOpen); 3] = [("Files", Window::files_open), ("Saved", Window::saved_open), ("Activity", activity_open)];
    for (button, open) in panes {
        tab_to(&mut h, button, 30);
        press(&mut h, Key::Enter);
        assert!(open(h.state()), "Enter on {button} did not open it");
        press(&mut h, Key::Escape);
        assert!(!open(h.state()), "Esc did not close {button}");
        assert_focused(&h, button);
        h.state_mut().take_actions();
    }

    // Saved's own close button, by keyboard, does the same.
    tab_to(&mut h, "Saved", 30);
    press(&mut h, Key::Enter);
    assert!(h.state().saved_open());
    tab_to(&mut h, "Close saved messages", 30);
    press(&mut h, Key::Enter);
    assert!(!h.state().saved_open());
    assert_focused(&h, "Saved");
}

#[test]
fn search_results_close_with_focus_back_on_what_sent_the_search() {
    let mut h = signed_in(&[ROOM]);
    let found = || Update::SearchResults {
        query: "plan".into(),
        results: vec![SearchResult { room: ROOM.into(), cursor: 5, author: BO.into(), snippet: "the plan".into() }],
    };
    let search = || vec![Action::Room(Command::Search { query: "plan".into() })];

    // Enter in the search box searches; Esc closes the results and focus is back in the box.
    tab_to(&mut h, "Search messages", 30);
    typed(&mut h, "plan");
    press(&mut h, Key::Enter);
    assert_eq!(h.state_mut().take_actions(), search());
    apply(&mut h, found());
    assert_eq!(h.state().search_results(), Some(("plan", 1)));
    press(&mut h, Key::Escape);
    assert_eq!(h.state().search_results(), None, "Esc did not close the results");
    assert_focused(&h, "Search messages");

    // The Search button searches; Close search closes the results and focus is back on the button.
    press(&mut h, Key::Tab);
    assert_focused(&h, "Search");
    press(&mut h, Key::Enter);
    assert_eq!(h.state_mut().take_actions(), search());
    apply(&mut h, found());
    tab_to(&mut h, "Close search", 30);
    press(&mut h, Key::Enter);
    assert_eq!(h.state().search_results(), None);
    assert_focused(&h, "Search");
}

#[test]
fn after_a_confirmed_lobby_change_focus_is_on_back_to_calendar() {
    let mut h = signed_in(&[LOBBY_ROOM]);
    apply(&mut h, Update::GuestLobby(GuestUpdate::Available(true)));
    tab_to(&mut h, "Calendar", 30);
    press(&mut h, Key::Enter);
    h.state_mut().take_actions();
    let meetings = vec![meeting(7, LOBBY_ROOM, "Guest review", Audience::Guests)];
    apply(&mut h, Update::Meetings { from_ms: MONDAY, to_ms: MONDAY + 5 * DAY, now_ms: NOW, meetings, more: false });
    tab_to(&mut h, "Lobby Guest review", 30);
    press(&mut h, Key::Enter);
    h.state_mut().take_actions();
    let lobby = |revision, sam| GuestLobby {
        meeting: 7,
        revision,
        expires_ms: NOW + DAY,
        lobby: true,
        closed: false,
        entries: vec![
            GuestEntry { guest: 11, name: "Alex".into(), state: GuestState::Waiting, revision: 1 },
            GuestEntry { guest: 12, name: "Sam".into(), state: sam, revision },
        ],
    };
    apply(&mut h, Update::GuestLobby(GuestUpdate::Snapshot { room: LOBBY_ROOM.into(), lobby: lobby(2, GuestState::Admitted), code: None }));

    // Removing a guest, confirmed by keyboard: the row's button and the confirmation go, and focus is on Back to
    // calendar, also once the lobby reports the change.
    tab_to(&mut h, "Remove Sam", 10);
    press(&mut h, Key::Enter);
    assert_focused(&h, "Keep guest");
    shift_tab(&mut h);
    assert_focused(&h, "Remove this guest");
    press(&mut h, Key::Enter);
    let sent = h.state_mut().take_actions();
    assert!(
        matches!(sent.as_slice(), [Action::Room(Command::GuestLobby(GuestCommand::Decide { guest: 12, decision: GuestDecision::Remove, .. }))]),
        "unexpected {sent:?}"
    );
    assert_focused(&h, "Back to calendar");
    apply(&mut h, Update::GuestLobby(GuestUpdate::Snapshot { room: LOBBY_ROOM.into(), lobby: lobby(3, GuestState::Removed), code: None }));
    assert_focused(&h, "Back to calendar");

    // Closing the link, confirmed by keyboard: the same.
    tab_to(&mut h, "Close guest link", 10);
    press(&mut h, Key::Enter);
    assert_focused(&h, "Keep link open");
    shift_tab(&mut h);
    assert_focused(&h, "Close link and remove guests");
    press(&mut h, Key::Enter);
    let sent = h.state_mut().take_actions();
    assert!(matches!(sent.as_slice(), [Action::Room(Command::GuestLobby(GuestCommand::CloseLink { .. }))]), "unexpected {sent:?}");
    assert_focused(&h, "Back to calendar");
}

#[test]
fn each_new_screen_on_the_way_in_is_announced_and_nothing_is_focused() {
    let mut h = window();
    settle(&mut h);
    assert_live(&h, "Join a CrewCraft server");

    // Join: the authenticator screen is said, and focus is on nothing, so no field raises a phone's keyboard.
    press(&mut h, Key::Tab);
    typed(&mut h, LINK);
    press(&mut h, Key::Tab);
    typed(&mut h, "typed in a test");
    press(&mut h, Key::Enter);
    assert!(matches!(h.state_mut().take_actions().as_slice(), [Action::Enroll { .. }]));
    apply(&mut h, Update::AuthenticatorSetup { otpauth_uri: URI.to_owned() });
    assert_live(&h, "Set up your authenticator");
    assert!(h.query_by_label("Join a CrewCraft server").is_none());
    assert_nothing_focused(&h);

    // The authenticator: the sign-in screen is said.
    press(&mut h, Key::Tab);
    press(&mut h, Key::Tab);
    press(&mut h, Key::Tab);
    assert_focused(&h, "Authenticator code");
    typed(&mut h, "123456");
    press(&mut h, Key::Enter);
    assert!(matches!(h.state_mut().take_actions().as_slice(), [Action::ConfirmAuthenticator { .. }]));
    apply(&mut h, Update::Enrolled { server: "chat.example.org".to_owned() });
    assert_live(&h, "Sign in to CrewCraft");
    assert!(h.query_by_label("Set up your authenticator").is_none());
    assert_nothing_focused(&h);

    // Sign in: the chat is said in the status line.
    press(&mut h, Key::Tab);
    typed(&mut h, ME);
    press(&mut h, Key::Tab);
    typed(&mut h, "pw");
    press(&mut h, Key::Tab);
    typed(&mut h, "654321");
    press(&mut h, Key::Enter);
    assert!(matches!(h.state_mut().take_actions().as_slice(), [Action::SignIn { .. }]));
    apply(&mut h, Update::SignedIn { email: ME.to_owned(), rooms: vec![ROOM.to_owned()] });
    assert_live(&h, "Signed in to CrewCraft.");
    assert_nothing_focused(&h);

    // Once focus lands on a control the person is working on the new screen, and the line goes: the status line is
    // left for changes away from focus.
    press(&mut h, Key::Tab);
    assert!(h.query_by_label("Signed in to CrewCraft.").is_none());
    assert_eq!(h.state().announcement(), None);
}
