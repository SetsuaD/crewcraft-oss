//! T405: an invitation link that opens the app fills in the enrollment form. Only a well-formed CrewCraft invitation
//! link is taken, only while the enrollment screen is showing, and the link (a one-time secret) never shows in
//! `Debug`.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft::app::opened_with_link;
use crewcraft_desktop_ui::{Action, Update, Window, fonts};
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_enroll::{EnrollmentCode, InvitationLink};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

fn link() -> String {
    InvitationLink::new("chat.example.org:7443", EnrollmentCode::from_bytes([0x45; 20]), RootFingerprint::from_der(b"test root")).unwrap().to_string()
}

fn harness() -> Harness<'static, Window> {
    Harness::builder()
        .with_size([390.0, 844.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new())
}

#[test]
fn only_a_crewcraft_invitation_link_is_taken() {
    let link = link();
    assert!(link.starts_with("crewcraft://enroll?"));
    let Some(Update::InvitationLink(taken)) = opened_with_link(&format!("  {link}\n")) else {
        panic!("a well-formed link is taken");
    };
    assert_eq!(taken.as_str(), link, "trimmed");
    assert_eq!(format!("{:?}", opened_with_link(&link).unwrap()), "InvitationLink(..)");
    for other in ["", "https://chat.example.org/", "crewcraft://enroll", "crewcraft://enroll?server=x", "crewcraft://other?x=1", "not a link"] {
        assert_eq!(opened_with_link(other), None, "{other:?}");
    }
}

#[test]
fn the_link_fills_the_enrollment_form() {
    let link = link();
    let mut h = harness();
    h.state_mut().apply(Update::NeedsEnrollment);
    h.state_mut().apply(opened_with_link(&link).unwrap());
    h.run();
    // The person only chooses a password; the link is already there.
    h.get_by_label("New password").click();
    h.run();
    h.get_by_label("New password").type_text("a new password");
    h.run();
    h.get_by_label("Enroll this device").click();
    h.run();
    let actions = h.state_mut().take_actions();
    let [Action::Enroll { link: sent, password }] = actions.as_slice() else {
        panic!("expected one Enroll, got {actions:?}");
    };
    assert_eq!(sent.as_str(), link);
    assert_eq!(password.as_str(), "a new password");
}

#[test]
fn a_link_is_ignored_unless_the_enrollment_screen_shows() {
    let link = link();
    let mut h = harness();
    // Already enrolled: the sign-in screen shows, and the link changes nothing.
    h.state_mut().apply(Update::Enrolled { server: "chat.example.org:7443".to_owned() });
    h.state_mut().apply(opened_with_link(&link).unwrap());
    h.state_mut().apply(Update::NeedsEnrollment);
    h.run();
    h.get_by_label("New password").click();
    h.run();
    h.get_by_label("New password").type_text("a new password");
    h.run();
    h.get_by_label("Enroll this device").click();
    h.run();
    assert!(h.state_mut().take_actions().is_empty(), "the form has no link, so it cannot be sent");
}
