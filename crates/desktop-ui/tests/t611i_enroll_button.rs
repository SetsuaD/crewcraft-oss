//! T611i: the enrollment screen's "Enroll with your organization" button, which needs only the invitation link, and
//! its wait for the browser with Cancel, driven headless through egui's accessibility tree.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_desktop_ui::{Action, Screen, Update, Window, fonts};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const BUTTON: &str = "Enroll with your organization";
const WAITING: &str = "Finish signing in on the page that opened in your browser.";
const LINK: &str = "crewcraft://enroll?server=chat.example.org:7443&code=ABCD";

fn enroll_screen() -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size([900.0, 600.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.run();
    assert_eq!(h.state().screen(), Screen::Enroll);
    h
}

fn type_into(h: &mut Harness<'_, Window>, label: &str, text: &str) {
    h.get_by_label(label).click();
    h.run();
    h.get_by_label(label).type_text(text);
    h.run();
}

#[test]
fn the_button_needs_only_the_link_and_clears_the_form() {
    let mut h = enroll_screen();
    h.get_by_label(BUTTON).click();
    h.run();
    assert!(h.state_mut().take_actions().is_empty(), "no link, no enrollment");

    type_into(&mut h, "Invitation link", &format!("  {LINK} "));
    type_into(&mut h, "New password", "typed by mistake");
    h.get_by_label(BUTTON).click();
    h.run();
    let actions = h.state_mut().take_actions();
    let [Action::EnrollExternal { link }] = actions.as_slice() else { panic!("unexpected {actions:?}") };
    assert_eq!(link.as_str(), LINK);
    let debug = format!("{actions:?}");
    assert!(!debug.contains("ABCD") && !debug.contains("typed by mistake"), "Debug leaked a secret: {debug}");
    // The form is empty and the window waits for the app: neither button sends anything.
    h.get_by_label(BUTTON).click();
    h.get_by_label("Enroll this device").click();
    h.run();
    assert!(h.state_mut().take_actions().is_empty());
}

#[test]
fn waiting_for_the_browser_offers_cancel_until_the_app_answers() {
    let mut h = enroll_screen();
    type_into(&mut h, "Invitation link", LINK);
    h.get_by_label(BUTTON).click();
    h.run();
    h.state_mut().take_actions();

    h.state_mut().apply(Update::WaitingForBrowser);
    h.run();
    assert!(h.state().waiting_for_browser());
    h.get_by_label(WAITING);
    h.get_by_label("Cancel").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::CancelSignIn]);

    h.state_mut().apply(Update::NeedsEnrollment);
    h.state_mut().apply(Update::Failed("Enrollment cancelled.".to_owned()));
    h.run();
    assert!(!h.state().waiting_for_browser());
    h.get_by_label("Enrollment cancelled.");
    h.get_by_label(BUTTON);
    assert!(h.query_by_label(WAITING).is_none());
}

#[test]
fn a_stray_waiting_update_changes_nothing() {
    let mut h = enroll_screen();
    h.state_mut().apply(Update::WaitingForBrowser);
    h.run();
    assert!(!h.state().waiting_for_browser(), "no enrollment is in progress");
    assert!(h.query_by_label("Cancel").is_none());
}
