//! T305: the desktop window's screens, driven headless through egui's accessibility tree.

use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::{Action, Screen, Update, Window, fonts};
use crewcraft_ui_model::Command;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

fn harness() -> Harness<'static, Window> {
    Harness::builder()
        .with_size([900.0, 600.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new())
}

fn line(cursor: u64, author: &str, html: &str) -> Shown {
    Shown::Line(Line { cursor, author: author.to_owned(), html: html.to_owned(), edited: false })
}

fn type_into(h: &mut Harness<'_, Window>, label: &str, text: &str) {
    h.get_by_label(label).click();
    h.run();
    h.get_by_label(label).type_text(text);
    h.run();
}

#[test]
fn enrollment_moves_the_secrets_into_one_action_and_clears_the_form() {
    let mut h = harness();
    h.run();
    assert_eq!(h.state().screen(), Screen::Enroll);
    type_into(&mut h, "Invitation link", "  crewcraft://enroll?server=chat.example.org:7443&code=ABCD  ");
    type_into(&mut h, "New password", "typed in a test");
    h.get_by_label("Enroll this device").click();
    h.run();
    let actions = h.state_mut().take_actions();
    assert_eq!(actions.len(), 1);
    match &actions[0] {
        Action::Enroll { link, password } => {
            assert_eq!(link.as_str(), "crewcraft://enroll?server=chat.example.org:7443&code=ABCD");
            assert_eq!(password.as_str(), "typed in a test");
        }
        other => panic!("unexpected {other:?}"),
    }
    let debug = format!("{:?}", actions[0]);
    assert!(!debug.contains("ABCD") && !debug.contains("typed in"), "Debug leaked a secret: {debug}");
    // Clicking again sends nothing: the form is empty and the window waits for the app.
    h.get_by_label("Enroll this device").click();
    h.run();
    assert!(h.state_mut().take_actions().is_empty());
}

#[test]
fn authenticator_setup_then_sign_in() {
    let mut h = harness();
    h.state_mut().apply(Update::AuthenticatorSetup { otpauth_uri: "otpauth://totp/CrewCraft:ana%40example.org?marker=SETUPMARKER".to_owned() });
    h.run();
    assert_eq!(h.state().screen(), Screen::Authenticator);
    assert!(!format!("{:?}", Update::AuthenticatorSetup { otpauth_uri: "marker=SETUPMARKER".to_owned() }).contains("SETUPMARKER"));
    type_into(&mut h, "Authenticator code", "12345");
    h.get_by_label("Confirm").click();
    h.run();
    assert!(h.state_mut().take_actions().is_empty(), "five digits is not a code");
    type_into(&mut h, "Authenticator code", "6");
    h.get_by_label("Confirm").click();
    h.run();
    match h.state_mut().take_actions().as_slice() {
        [Action::ConfirmAuthenticator { code }] => assert_eq!(code.as_str(), "123456"),
        other => panic!("unexpected {other:?}"),
    }

    h.state_mut().apply(Update::Enrolled { server: "chat.example.org".to_owned() });
    h.run();
    assert_eq!(h.state().screen(), Screen::SignIn);
    h.get_by_label("Server: chat.example.org");
    type_into(&mut h, "Email", "ana@example.org");
    type_into(&mut h, "Password", "pw");
    type_into(&mut h, "Authenticator code", "654321");
    h.get_by_label("Sign in").click();
    h.run();
    match h.state_mut().take_actions().as_slice() {
        [Action::SignIn { email, password, code }] => {
            assert_eq!(email, "ana@example.org");
            assert_eq!(password.as_str(), "pw");
            assert_eq!(code.as_str(), "654321");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn chat_opens_the_first_room_shows_the_feed_and_sends() {
    let mut h = harness();
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".to_owned(), rooms: vec!["general".to_owned(), "Design".to_owned()] });
    h.run();
    assert_eq!(h.state().screen(), Screen::Chat);
    // Rooms sort ignoring case, so "Design" is first and is opened.
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Sync { room: "Design".to_owned() })]);

    h.state_mut().apply(Update::Snapshot {
        room: "Design".to_owned(),
        shown: vec![
            line(1, "bo@example.org", "<p>Hello <b>crew</b> &amp; friends</p>"),
            Shown::Pending { id: 7, body: "on my way".to_owned(), failed: true },
        ],
    });
    h.run();
    h.get_by_label("bo@example.org");
    h.get_by_label("Hello crew & friends");
    h.get_by_label("on my way  (Not sent)");

    type_into(&mut h, "Message", "  ship it  ");
    h.get_by_label("Send").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Post { room: "Design".to_owned(), text: "ship it".to_owned() })]);

    h.state_mut().apply(Update::Unread { room: "general".to_owned(), unread: 3 });
    h.run();
    h.get_by_label("3 unread");
    h.get_by_label("general  (3)").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Read { room: "general".to_owned() })]);
    assert!(h.query_by_label("3 unread").is_none());

    h.get_by_label("Sign out").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::SignOut]);
    h.state_mut().apply(Update::SignedOut);
    h.run();
    assert_eq!(h.state().screen(), Screen::SignIn);
}

#[test]
fn a_failure_is_shown_until_the_screen_changes() {
    let mut h = harness();
    h.state_mut().apply(Update::Failed("The invitation has expired.".to_owned()));
    h.run();
    h.get_by_label("The invitation has expired.");
    assert_eq!(h.state().notice(), Some("The invitation has expired."));
    h.state_mut().apply(Update::Enrolled { server: "chat.example.org".to_owned() });
    h.run();
    assert!(h.query_by_label("The invitation has expired.").is_none());
}

#[test]
fn enter_sends_and_shift_enter_does_not() {
    let mut h = harness();
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".to_owned(), rooms: vec!["general".to_owned()] });
    h.run();
    let _ = h.state_mut().take_actions();
    type_into(&mut h, "Message", "first line");
    h.key_press_modifiers(egui::Modifiers::SHIFT, egui::Key::Enter);
    h.run();
    assert!(h.state_mut().take_actions().is_empty(), "Shift+Enter must not send");
    h.get_by_label("Message").type_text("second line");
    h.run();
    h.key_press(egui::Key::Enter);
    h.run();
    match h.state_mut().take_actions().as_slice() {
        [Action::Room(Command::Post { room, text })] => {
            assert_eq!(room, "general");
            assert!(text.starts_with("first line") && text.ends_with("second line"), "{text:?}");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn the_last_email_fills_the_sign_in_form_once() {
    let mut h = harness();
    h.state_mut().apply(Update::Enrolled { server: "chat.example.org".to_owned() });
    h.state_mut().apply(Update::LastEmail("ana@example.org".to_owned()));
    h.run();
    assert_eq!(h.get_by_label("Email").value().as_deref(), Some("ana@example.org"));
}
