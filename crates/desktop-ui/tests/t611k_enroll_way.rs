//! T611k: the enrollment screen offers the way in an invitation names: a link saying `signin=org` asks for no
//! password and offers only "Enroll with your organization"; `signin=password` offers only the password way; a link
//! that says neither offers both.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_desktop_ui::{Window, fonts};
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::invitation::PREFIX;
use crewcraft_enroll::server_trust::RootFingerprint;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

fn link(signin: &str) -> String {
    let code = EnrollmentCode::from_bytes([7; 20]).to_display();
    let root = RootFingerprint::from_der(b"synthetic root certificate bytes");
    format!("{PREFIX}server=chat.example.org:7443&code={code}&root_sha256={root}{signin}")
}

fn enroll_with(text: &str) -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size([900.0, 700.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.run();
    h.get_by_label("Invitation link").click();
    h.run();
    h.get_by_label("Invitation link").type_text(text);
    h.run();
    h
}

#[test]
fn the_screen_offers_the_way_the_link_names() {
    let h = enroll_with(&link("&signin=org"));
    assert!(h.query_by_label("New password").is_none() && h.query_by_label("Enroll this device").is_none());
    h.get_by_label("Enroll with your organization");
    h.get_by_label("Your organization signs you in: no password is needed here.");

    let h = enroll_with(&link("&signin=password"));
    h.get_by_label("New password");
    assert!(h.query_by_label("Enroll with your organization").is_none());

    let h = enroll_with(&link(""));
    h.get_by_label("New password");
    h.get_by_label("Enroll with your organization");
}
