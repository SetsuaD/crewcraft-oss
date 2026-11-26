//! T330e: files in the window, driven headless through egui's accessibility tree: a dropped file asks to be uploaded,
//! an uploaded file waits on the composer (and can be taken off), Send posts it even with no text, and a message's
//! files show under it with Save.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_desktop_ui::{Action, FileChip, Update, Window, fonts, short_size};
use crewcraft_ui_model::Command;
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const ROOM: &str = "general";

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

fn chip(n: u8, name: &str, size: u64) -> FileChip {
    FileChip { file: [n; 16], name: name.into(), size }
}

#[test]
fn a_dropped_file_asks_to_be_uploaded_to_the_open_room() {
    let mut h = chat();
    h.input_mut().dropped_files.push(egui::DroppedFile { path: Some("/tmp/report.pdf".into()), ..Default::default() });
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::Attach { room: ROOM.into(), path: "/tmp/report.pdf".into() })]);
}

#[test]
fn uploaded_files_wait_on_the_composer_and_send_without_text() {
    let mut h = chat();
    h.get_by_label("Drop a file onto the window to attach it.");
    h.state_mut().apply(Update::Uploaded { room: ROOM.into(), file: chip(1, "a.txt", 12) });
    h.state_mut().apply(Update::Uploaded { room: ROOM.into(), file: chip(2, "b.png", 2048) });
    h.run();
    h.get_by_label("\u{1F4CE} a.txt (12 B)");
    h.get_by_label("\u{1F4CE} b.png (2.0 KB)");
    h.get_by_label("Remove a.txt").click();
    h.run();
    assert!(h.query_by_label("\u{1F4CE} a.txt (12 B)").is_none());
    assert_eq!(h.state().pending_files(ROOM), &[chip(2, "b.png", 2048)]);

    h.get_by_label("Send").click();
    h.run();
    assert_eq!(h.state_mut().take_actions(), vec![Action::Room(Command::PostFiles { room: ROOM.into(), text: String::new(), files: vec![[2; 16]] })]);
    assert!(h.state().pending_files(ROOM).is_empty(), "sent files leave the composer");
}

#[test]
fn a_messages_files_show_under_it_with_save() {
    let mut h = chat();
    let line = crewcraft_client_core::room_view::Shown::Line(crewcraft_client_core::timeline::Line {
        cursor: 5,
        author: "bo@example.org".into(),
        html: "<p>the report</p>".into(),
        edited: false,
    });
    h.state_mut().apply(Update::Snapshot { room: ROOM.into(), shown: vec![line] });
    h.state_mut().apply(Update::Attachments { room: ROOM.into(), files: vec![(5, vec![chip(3, "report.pdf", 1_300_000)])] });
    h.run();
    h.get_by_label("\u{1F4CE} report.pdf (1.2 MB)");
    h.get_by_label("Save report.pdf").click();
    h.run();
    assert_eq!(
        h.state_mut().take_actions(),
        vec![Action::Room(Command::Save { file: [3; 16], size: 1_300_000, name: "report.pdf".into(), to: None })]
    );
}

#[test]
fn sizes_read_short() {
    assert_eq!(short_size(0), "0 B");
    assert_eq!(short_size(1023), "1023 B");
    assert_eq!(short_size(1536), "1.5 KB");
    assert_eq!(short_size(5 * 1_048_576), "5.0 MB");
}
