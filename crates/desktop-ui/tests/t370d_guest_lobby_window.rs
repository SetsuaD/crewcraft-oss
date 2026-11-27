//! T370d: staff use the guest lobby through the real window's accessibility tree.
//! The egui fixture follows the T370b calendar and announcement tests.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_client_core::room_view::RoomSettings;
use crewcraft_desktop_ui::{Action, Update, Window, fonts};
use crewcraft_proto::guest::{GuestCode, GuestDecision, GuestEntry, GuestLobby, GuestMeetingDraft, GuestState};
use crewcraft_proto::meeting::{Audience, Meeting, MeetingState};
use crewcraft_ui_model::Command;
use crewcraft_ui_model::guest::{GuestCommand, GuestUpdate};
use egui::accesskit::Live;
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};

const STAFF: &str = "staff@example.org";
const ROOM: &str = "planning";
const MEETING: u64 = 7;
const DAY: u64 = 24 * 60 * 60 * 1_000;
const MONDAY: u64 = 1_795_392_000_000;
const NOW: u64 = MONDAY + 2 * DAY;

fn window() -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size([1100.0, 760.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: STAFF.into(), rooms: vec!["general".into(), ROOM.into()] });
    h.run();
    h.state_mut().take_actions();
    h
}

fn update(h: &mut Harness<'_, Window>, update: GuestUpdate) {
    h.state_mut().apply(Update::GuestLobby(update));
    h.run();
}

fn click(h: &mut Harness<'_, Window>, label: &str) {
    h.get_by_label(label).click();
    h.run();
}

fn meeting(id: u64, title: &str, audience: Audience) -> Meeting {
    Meeting {
        id,
        room: ROOM.into(),
        version: 1,
        owner: STAFF.into(),
        audience,
        start_ms: NOW + 60 * 60 * 1_000,
        duration: 30,
        title: title.into(),
        agenda: String::new(),
        state: MeetingState::Scheduled,
    }
}

fn calendar(available: bool) -> Harness<'static, Window> {
    let mut h = window();
    update(&mut h, GuestUpdate::Available(available));
    click(&mut h, "Calendar");
    h.state_mut().take_actions();
    h.state_mut().apply(Update::Meetings {
        from_ms: MONDAY,
        to_ms: MONDAY + 5 * DAY,
        now_ms: NOW,
        meetings: vec![meeting(5, "Staff review", Audience::Staff), meeting(MEETING, "Guest review", Audience::Guests)],
        more: false,
    });
    h.run();
    h
}

fn snapshot(revision: u64, lobby: bool) -> GuestLobby {
    GuestLobby {
        meeting: MEETING,
        revision,
        expires_ms: NOW + DAY,
        lobby,
        closed: false,
        entries: vec![
            GuestEntry { guest: 11, name: "Alex".into(), state: GuestState::Waiting, revision: 1 },
            GuestEntry { guest: 12, name: "Sam".into(), state: GuestState::Admitted, revision: 2 },
        ],
    }
}

fn assert_action(h: &mut Harness<'_, Window>, command: GuestCommand) {
    let commands: Vec<_> = h
        .state_mut()
        .take_actions()
        .into_iter()
        .filter_map(|action| match action {
            Action::Room(Command::GuestLobby(command)) => Some(command),
            _ => None,
        })
        .collect();
    assert_eq!(commands, vec![command]);
}

#[test]
fn only_guest_meetings_offer_lobby_controls_and_direct_entry_requires_confirmation() {
    let old = calendar(false);
    assert!(old.query_by_label("Lobby Guest review").is_none());
    assert!(old.query_by_label("Schedule guest meeting").is_none());
    old.get_by_label("Join Staff review");

    let mut h = calendar(true);
    assert!(h.query_by_label("Lobby Staff review").is_none());
    click(&mut h, "Lobby Guest review");
    assert_action(&mut h, GuestCommand::Open { room: ROOM.into(), meeting: MEETING });
    update(&mut h, GuestUpdate::Snapshot { room: ROOM.into(), lobby: snapshot(2, true), code: None });
    h.get_by_label("Admit Alex");
    h.get_by_label("Decline Alex");
    h.get_by_label("Remove Sam");
    assert!(h.query_by_label("Remove Alex").is_none());
    assert!(h.query_by_label("Admit Sam").is_none());

    click(&mut h, "Turn off lobby");
    assert!(h.state_mut().take_actions().is_empty());
    click(&mut h, "Keep lobby on");
    assert!(h.state_mut().take_actions().is_empty());
    click(&mut h, "Turn off lobby");
    click(&mut h, "Allow direct entry");
    assert_action(&mut h, GuestCommand::SetLobby { meeting: MEETING, revision: 2, lobby: false, confirm_direct: true });

    update(
        &mut h,
        GuestUpdate::Refused {
            meeting: Some(MEETING),
            reason: "The lobby changed.".into(),
            conflict: true,
            access_lost: false,
            panel_unavailable: false,
        },
    );
    h.get_by_label("The lobby changed. Reload it before making another decision.");
    assert!(h.state_mut().take_actions().is_empty(), "the failed change is never repeated automatically");
    click(&mut h, "Admit Alex");
    assert!(h.state_mut().take_actions().is_empty(), "stale roster actions stay disabled");
    click(&mut h, "Reload lobby");
    assert_action(&mut h, GuestCommand::Open { room: ROOM.into(), meeting: MEETING });
    update(&mut h, GuestUpdate::Snapshot { room: ROOM.into(), lobby: snapshot(3, true), code: None });
    click(&mut h, "Admit Alex");
    assert_action(&mut h, GuestCommand::Decide { meeting: MEETING, guest: 11, revision: 3, decision: GuestDecision::Admit });

    let mut changed = snapshot(4, true);
    changed.entries[0].state = GuestState::Admitted;
    update(&mut h, GuestUpdate::Snapshot { room: ROOM.into(), lobby: changed, code: None });
    click(&mut h, "Close guest link");
    assert!(h.state_mut().take_actions().is_empty());
    click(&mut h, "Close link and remove guests");
    assert_action(&mut h, GuestCommand::CloseLink { meeting: MEETING, revision: 4 });

    update(&mut h, GuestUpdate::Waiting { room: ROOM.into(), waiting: 1, notify: false });
    update(
        &mut h,
        GuestUpdate::Refused {
            meeting: Some(MEETING),
            reason: "The lobby is unavailable.".into(),
            conflict: false,
            access_lost: true,
            panel_unavailable: false,
        },
    );
    assert!(h.query_by_label("Lobby").is_none());
    assert_action(&mut h, GuestCommand::ClosePanel);
    click(&mut h, "Chat");
    assert!(h.query_by_label_contains("1 waiting").is_none(), "lost room access clears the badge");
}

fn submit_guest_meeting(h: &mut Harness<'_, Window>) -> GuestMeetingDraft {
    click(h, "Schedule guest meeting");
    click(h, "Title");
    h.get_by_label("Title").type_text("External review");
    h.run();
    click(h, "Host name");
    h.get_by_label("Host name").type_text("Host");
    h.run();
    click(h, "Save");
    let actions = h.state_mut().take_actions();
    let [Action::Room(Command::GuestLobby(GuestCommand::Create(draft)))] = actions.as_slice() else {
        panic!("expected one guest meeting creation: {actions:?}");
    };
    draft.clone()
}

#[test]
fn creation_uses_the_expiring_guest_form_and_its_code_is_not_retained_on_reopen() {
    let mut h = calendar(true);
    let draft = submit_guest_meeting(&mut h);
    assert_eq!((draft.title.as_str(), draft.host_name.as_str()), ("External review", "Host"));
    assert!(draft.lobby && !draft.confirm_direct && draft.expires_ms > NOW);

    let lobby = GuestLobby { entries: Vec::new(), ..snapshot(1, true) };
    update(&mut h, GuestUpdate::Snapshot { room: draft.room.clone(), lobby: lobby.clone(), code: Some(GuestCode("ABCD".repeat(6))) });
    h.get_by_label("Copy guest code");
    click(&mut h, "Hide guest code");
    assert!(h.query_by_label("Copy guest code").is_none());
    click(&mut h, "Back to calendar");
    assert_action(&mut h, GuestCommand::ClosePanel);
    click(&mut h, "Lobby Guest review");
    assert_action(&mut h, GuestCommand::Open { room: ROOM.into(), meeting: MEETING });
    update(&mut h, GuestUpdate::Snapshot { room: ROOM.into(), lobby: lobby.clone(), code: None });
    assert!(h.query_by_label("Copy guest code").is_none());
    update(&mut h, GuestUpdate::Snapshot { room: ROOM.into(), lobby, code: Some(GuestCode("ABCD".repeat(6))) });
    assert!(h.query_by_label("Copy guest code").is_none());
}

#[test]
fn a_creation_completed_after_discard_announces_without_showing_the_code() {
    let mut h = calendar(true);
    let draft = submit_guest_meeting(&mut h);
    click(&mut h, "Discard changes");
    assert_action(&mut h, GuestCommand::ClosePanel);

    let code = "ABCD".repeat(6);
    let lobby = GuestLobby { entries: Vec::new(), ..snapshot(1, true) };
    update(&mut h, GuestUpdate::Snapshot { room: draft.room, lobby, code: Some(GuestCode(code.clone())) });
    let message =
        "Guest meeting scheduled. Its code was not shown. Close its guest link in Calendar and schedule another guest meeting to get a new code.";
    assert_eq!(h.get_by_label(message).accesskit_node().live(), Live::Polite);
    assert!(h.query_by_label("Copy guest code").is_none());
    assert!(h.query_by_label(code.as_str()).is_none());
}

#[test]
fn a_missing_meeting_closes_only_its_panel_and_the_next_waiting_guest_still_announces() {
    let mut h = calendar(true);
    update(&mut h, GuestUpdate::Waiting { room: ROOM.into(), waiting: 1, notify: false });
    click(&mut h, "Lobby Guest review");
    assert_action(&mut h, GuestCommand::Open { room: ROOM.into(), meeting: MEETING });
    update(
        &mut h,
        GuestUpdate::Refused {
            meeting: Some(MEETING),
            reason: "That meeting is unavailable.".into(),
            conflict: false,
            access_lost: false,
            panel_unavailable: true,
        },
    );
    assert!(h.query_by_label("Lobby").is_none());
    assert_action(&mut h, GuestCommand::ClosePanel);
    click(&mut h, "Chat");
    h.get_by_label_contains("1 waiting");
    update(&mut h, GuestUpdate::Waiting { room: ROOM.into(), waiting: 2, notify: true });
    assert_eq!(h.get_by_label("2 guests waiting in planning.").accesskit_node().live(), Live::Polite);
}

#[test]
fn a_fresh_knock_announces_without_focus_and_access_loss_clears_the_count() {
    let mut h = window();
    update(&mut h, GuestUpdate::Available(true));
    h.get_by_label("Message").focus();
    h.run();
    assert!(h.get_by_label("Message").is_focused());

    update(&mut h, GuestUpdate::Waiting { room: ROOM.into(), waiting: 1, notify: false });
    h.get_by_label_contains("1 waiting");
    assert!(h.state().announcement().is_none());
    update(&mut h, GuestUpdate::Waiting { room: ROOM.into(), waiting: 2, notify: true });
    let notice = h.get_by_label("2 guests waiting in planning.");
    assert_eq!(notice.accesskit_node().live(), Live::Polite);
    assert!(h.get_by_label("Message").is_focused());
    update(&mut h, GuestUpdate::ClearRoom { room: ROOM.into() });
    assert!(h.query_by_label_contains("2 waiting").is_none());
    assert!(h.state().announcement().is_none());

    h.state_mut().apply(Update::RoomSettings { room: ROOM.into(), settings: RoomSettings { muted: true, ..RoomSettings::default() } });
    update(&mut h, GuestUpdate::Waiting { room: ROOM.into(), waiting: 1, notify: false });
    update(&mut h, GuestUpdate::Waiting { room: ROOM.into(), waiting: 2, notify: true });
    h.get_by_label_contains("2 waiting");
    assert!(h.state().announcement().is_none(), "a muted room retains its count without announcing");
}
