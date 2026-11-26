//! T332b: the Files area shows the person's storage use against their quota (REQUIREMENTS 2.4), in short sizes up to
//! gigabytes.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_desktop_ui::{Update, Window, fonts, short_size};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

#[test]
fn files_shows_storage_against_the_quota() {
    let mut h = Harness::builder()
        .with_size([1100.0, 700.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".to_owned(), rooms: vec!["general".to_owned()] });
    h.run();
    h.get_by_label("Files").click();
    h.run();
    assert!(h.query_by_label_contains("Storage:").is_none(), "not before the server says");
    h.state_mut().apply(Update::Storage { used: 3 * 1_048_576 / 2, quota: 10 * 1_073_741_824 });
    h.run();
    h.get_by_label("Storage: 1.5 MB of 10.0 GB");
}

#[test]
fn sizes_read_short_up_to_gigabytes() {
    assert_eq!(short_size(1_073_741_823), "1024.0 MB");
    assert_eq!(short_size(1_073_741_824), "1.0 GB");
    assert_eq!(short_size(5 * 1_073_741_824 / 2), "2.5 GB");
}
