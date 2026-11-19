//! T401: the Android window. The phone runs the desktop's `Window` (crewcraft-desktop-ui) with the bundled font;
//! this checks, on the build machine and headless, the parts of the phone shell that do not need a phone: the data
//! folder under the activity's private storage, the version line the app logs, and the soft keyboard rule (shown
//! while a text field has the focus, hidden once it has not, and typing reaches the field) on the enrollment
//! screen at a phone's size. The rendering on an emulator is the manual proof in docs/MOBILE.md.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use crewcraft_android::{data_dir, keyboard_change, keyboard_wanted, version_line};
use crewcraft_desktop_ui::{Action, Screen, Update, Window, fonts};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

#[test]
fn data_lives_in_the_activity_private_storage() {
    assert_eq!(
        data_dir(Some(Path::new("/data/user/0/io.github.setsuad.crewcraft/files"))),
        Some(PathBuf::from("/data/user/0/io.github.setsuad.crewcraft/files/crewcraft"))
    );
    assert_eq!(data_dir(None), None);
}

#[test]
fn the_log_names_the_version_like_crewcraft_version() {
    let line = version_line();
    assert!(line.starts_with(&format!("crewcraft {} (protocol ", env!("CARGO_PKG_VERSION"))), "{line}");
    let (major, minor) = crewcraft_client_core::PROTOCOL_VERSION;
    assert!(line.contains(&format!("(protocol {major}.{minor})")), "{line}");
}

#[test]
fn keyboard_is_asked_for_only_when_its_state_changes() {
    assert_eq!(keyboard_change(false, true), Some(true));
    assert_eq!(keyboard_change(true, false), Some(false));
    assert_eq!(keyboard_change(true, true), None);
    assert_eq!(keyboard_change(false, false), None);
}

/// The enrollment screen in a portrait phone window (a 412 by 915 point screen, typical of Android phones).
fn phone() -> Harness<'static, Window> {
    let mut harness = Harness::builder()
        .with_size([412.0, 915.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    harness.state_mut().apply(Update::NeedsEnrollment);
    harness.run();
    harness
}

#[test]
fn a_focused_text_field_wants_the_keyboard_and_typing_reaches_it() {
    let mut h = phone();
    assert_eq!(h.state().screen(), Screen::Enroll);
    assert!(!keyboard_wanted(&h.output().platform_output), "nothing has the focus yet");

    h.get_by_label("Invitation link").click();
    h.run();
    assert!(keyboard_wanted(&h.output().platform_output), "the focused invitation field asks for the keyboard");
    h.get_by_label("Invitation link").type_text("crewcraft://enroll?server=chat.example.org:7443&code=ABCD");
    h.run();
    assert!(keyboard_wanted(&h.output().platform_output));

    h.get_by_label("New password").click();
    h.run();
    h.get_by_label("New password").type_text("typed on a phone");
    h.run();
    assert!(keyboard_wanted(&h.output().platform_output), "moving to the next field keeps the keyboard");

    h.get_by_label("Enroll this device").click();
    h.run();
    assert!(!keyboard_wanted(&h.output().platform_output), "the button took the focus, so the keyboard goes");
    match h.state_mut().take_actions().as_slice() {
        [Action::Enroll { link, password }] => {
            assert_eq!(link.as_str(), "crewcraft://enroll?server=chat.example.org:7443&code=ABCD");
            assert_eq!(password.as_str(), "typed on a phone");
        }
        other => panic!("unexpected {other:?}"),
    }
}
