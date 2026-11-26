//! T331b: the Files area in the window, driven headless through egui's accessibility tree: Files in the app bar asks
//! for the list and shows it (name, size, room) with Save; Refresh asks again; Chat returns to the conversation.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_desktop_ui::{Action, Update, Window, fonts};
use crewcraft_proto::request::ListedFile;
use crewcraft_ui_model::Command;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

fn chat() -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size([1100.0, 700.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".to_owned(), rooms: vec!["general".to_owned()] });
    h.run();
    h.state_mut().take_actions();
    h
}

fn listed(n: u8, room: &str, name: &str, size: u64) -> ListedFile {
    ListedFile { file: [n; 16], room: room.into(), cursor: u64::from(n), uploader: "bo@example.org".into(), name: name.into(), size, image: None }
}

#[test]
fn files_lists_every_file_with_save() {
    let mut h = chat();
    h.get_by_label("Files").click();
    h.run();
    assert!(h.state().files_open());
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::ListFiles)]);
    h.get_by_label("Loading files...");

    h.state_mut().apply(Update::Files { files: vec![listed(2, "design", "mockup.png", 2048), listed(1, "general", "plan.pdf", 12)] });
    h.run();
    h.get_by_label("mockup.png (2.0 KB)");
    h.get_by_label("plan.pdf (12 B)");
    h.get_by_label("in design");
    h.get_by_label("Save plan.pdf").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Save { file: [1; 16], size: 12, name: "plan.pdf".into(), to: None })]);
    h.get_by_label("Refresh files").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::ListFiles)]);

    h.get_by_label("Chat").click();
    h.run();
    assert!(!h.state().files_open());
    h.get_by_label("Send");
}

#[test]
fn an_empty_list_says_so() {
    let mut h = chat();
    h.get_by_label("Files").click();
    h.run();
    h.state_mut().apply(Update::Files { files: Vec::new() });
    h.run();
    h.get_by_label("No files in your rooms yet.");
}
