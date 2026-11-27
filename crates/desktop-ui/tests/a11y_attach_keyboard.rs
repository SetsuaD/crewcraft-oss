//! Attaching a file without dragging, by keyboard only (docs/ACCESSIBILITY.md, gap 2): the composer's Attach file
//! button opens a path entry that takes focus; Enter checks the path and uploads it through the same command a dropped
//! file uses; a wrong path says what is wrong and keeps focus in the entry; Esc closes it and focus goes back to the
//! button. Driven through the accessibility tree and key presses, with no pointer.
#![allow(clippy::unwrap_used)]

use crewcraft_desktop_ui::{Action, Update, Window, attach_path, fonts};
use crewcraft_ui_model::Command;
use egui::Key;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const ROOM: &str = "general";
const ENTRY: &str = "Path of the file to attach";

fn chat() -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size([1100.0, 700.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".to_owned(), rooms: vec![ROOM.to_owned()] });
    h.run();
    h.state_mut().take_actions();
    h
}

/// Press `key` and let the window settle (a focus request lands on the next frame).
fn press(h: &mut Harness<'_, Window>, key: Key) {
    h.key_press(key);
    h.run();
    h.run();
}

#[test]
fn a_file_is_attached_from_the_keyboard_and_focus_comes_back() {
    let mut h = chat();
    assert!(h.query_by_label(ENTRY).is_none(), "the entry opens only when asked for");

    // Reach the button as a screen reader or Tab would, and press Enter: the entry opens with focus in it.
    h.get_by_label("Attach file").focus();
    h.run();
    press(&mut h, Key::Enter);
    assert!(h.get_by_label(ENTRY).is_focused(), "focus did not move into the path entry");

    // A path that is not a full path: nothing is uploaded, the window says why, and focus stays to fix it.
    h.get_by_label(ENTRY).type_text("report.pdf");
    press(&mut h, Key::Enter);
    assert!(h.state_mut().take_actions().is_empty());
    assert!(h.state().notice().is_some_and(|notice| notice.contains("full path")), "{:?}", h.state().notice());
    assert!(h.get_by_label(ENTRY).is_focused(), "focus left the entry after a wrong path");

    // Esc closes the entry; focus is back on the button, so Enter opens it again, empty.
    press(&mut h, Key::Escape);
    assert!(h.query_by_label(ENTRY).is_none());
    assert!(h.get_by_label("Attach file").is_focused(), "focus did not return to Attach file");
    press(&mut h, Key::Enter);
    assert_eq!(h.get_by_label(ENTRY).value().unwrap_or_default(), "");

    // A full path, quoted as a file manager copies it: Enter uploads it to the open room, the same command a drop sends.
    let path = std::env::temp_dir().join("report.pdf");
    h.get_by_label(ENTRY).type_text(&format!("\"{}\"", path.to_str().unwrap()));
    press(&mut h, Key::Enter);
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Attach { room: ROOM.into(), path })]);
    assert_eq!(h.state().notice(), None, "the earlier problem is cleared");
    assert!(h.query_by_label(ENTRY).is_none(), "the entry closes after attaching");
    assert!(h.get_by_label("Attach file").is_focused(), "focus did not return to Attach file");
}

#[test]
fn which_typed_paths_name_a_file() {
    let full = std::env::temp_dir().join("notes.txt");
    let text = full.to_str().unwrap();
    assert_eq!(attach_path(text), Ok(full.clone()));
    assert_eq!(attach_path(&format!("  \"{text}\"  ")), Ok(full), "quotes and space are dropped");
    assert!(attach_path("notes.txt").is_err(), "not a full path");
    assert!(attach_path("   ").is_err() && attach_path("\"\"").is_err(), "nothing typed");
    let folder = std::env::temp_dir();
    assert!(attach_path(&format!("{}/", folder.to_str().unwrap())).is_err(), "a folder separator at the end");
}
