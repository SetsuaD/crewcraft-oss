//! T611h: the sign-in screen's "Sign in with your organization" button, the wait for the browser and its Cancel,
//! driven headless through egui's accessibility tree.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_desktop_ui::{Action, Screen, Update, Window, fonts};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const BUTTON: &str = "Sign in with your organization";
const WAITING: &str = "Finish signing in on the page that opened in your browser.";

fn sign_in_screen() -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size([900.0, 600.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::Enrolled { server: "chat.example.org".to_owned() });
    h.run();
    assert_eq!(h.state().screen(), Screen::SignIn);
    h
}

fn type_into(h: &mut Harness<'_, Window>, label: &str, text: &str) {
    h.get_by_label(label).click();
    h.run();
    h.get_by_label(label).type_text(text);
    h.run();
}

#[test]
fn the_button_needs_only_the_email_and_sends_one_action() {
    let mut h = sign_in_screen();
    h.get_by_label(BUTTON).click();
    h.run();
    assert!(h.state_mut().take_actions().is_empty(), "no email, no sign-in");

    type_into(&mut h, "Email", "  ana@example.org ");
    h.get_by_label(BUTTON).click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::SignInExternal { email: "ana@example.org".to_owned() }]);
    // While the sign-in runs, neither button starts another.
    h.get_by_label(BUTTON).click();
    h.get_by_label("Sign in").click();
    h.run();
    assert!(h.state_mut().take_actions().is_empty());
    assert_eq!(format!("{:?}", Action::SignInExternal { email: "ana@example.org".to_owned() }), "SignInExternal { email: \"ana@example.org\" }");
}

#[test]
fn waiting_for_the_browser_offers_cancel_until_the_app_answers() {
    let mut h = sign_in_screen();
    type_into(&mut h, "Email", "ana@example.org");
    h.get_by_label(BUTTON).click();
    h.run();
    h.state_mut().take_actions();

    h.state_mut().apply(Update::WaitingForBrowser);
    h.run();
    assert!(h.state().waiting_for_browser());
    h.get_by_label(WAITING);
    assert!(h.query_by_label(BUTTON).is_none());
    h.get_by_label("Cancel").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::CancelSignIn]);

    // The app's answer (here the cancel) ends the wait and gives the button back.
    h.state_mut().apply(Update::Failed("Sign-in cancelled.".to_owned()));
    h.run();
    assert!(!h.state().waiting_for_browser());
    assert!(h.query_by_label(WAITING).is_none());
    h.get_by_label("Sign-in cancelled.");
    h.get_by_label(BUTTON).click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::SignInExternal { email: "ana@example.org".to_owned() }]);
}

#[test]
fn a_stray_waiting_update_changes_nothing() {
    let mut h = sign_in_screen();
    h.state_mut().apply(Update::WaitingForBrowser);
    h.run();
    assert!(!h.state().waiting_for_browser(), "no sign-in is in progress");
    h.get_by_label(BUTTON);
    assert!(h.query_by_label("Cancel").is_none());
    assert_eq!(format!("{:?}", Update::WaitingForBrowser), "WaitingForBrowser");
}
