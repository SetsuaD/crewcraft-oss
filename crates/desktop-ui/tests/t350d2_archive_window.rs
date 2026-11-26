//! T350d2: archive rooms in the window, driven headless through egui's accessibility tree: they are listed under
//! Archive, apart from active rooms (on a phone too); an open archive room reads "Archive: read only" where the
//! composer would be, shows each imported message's original time, and offers nothing to do to a message.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::{Update, Window, fonts, utc_time};
use egui_kittest::Harness;
use egui_kittest::kittest::Queryable;

const ME: &str = "ana@example.org";
/// 2024-03-05 14:07:09 UTC.
const SENT: u64 = 1_709_647_629_123;

fn chat(size: [f32; 2]) -> Harness<'static, Window> {
    let mut h = Harness::builder()
        .with_size(size)
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: ME.to_owned(), rooms: vec!["general".to_owned(), "old-team".to_owned()] });
    h.state_mut().apply(Update::Archive { room: "old-team".into(), times: vec![(4, SENT)] });
    let line = Shown::Line(Line { cursor: 4, author: "bo@example.org".into(), html: "the plan from last year".into(), edited: false });
    h.state_mut().apply(Update::Snapshot { room: "old-team".into(), shown: vec![line] });
    h.run();
    h.state_mut().take_actions();
    h
}

#[test]
fn times_read_in_utc() {
    assert_eq!(utc_time(0), "1970-01-01 00:00 UTC");
    assert_eq!(utc_time(SENT), "2024-03-05 14:07 UTC");
    assert_eq!(utc_time(951_782_400_000), "2000-02-29 00:00 UTC");
    assert_eq!(utc_time(1_704_067_199_000), "2023-12-31 23:59 UTC");
}

#[test]
fn an_archive_room_is_listed_apart_and_reads_only() {
    let mut h = chat([1100.0, 700.0]);
    h.get_by_label("Archive");
    h.get_by_label("old-team").click();
    h.run();
    h.state_mut().take_actions();
    h.get_by_label("Archive: read only");
    assert!(h.query_by_label("Send").is_none(), "no composer");
    h.get_by_label("2024-03-05 14:07 UTC");
    // Nothing to do to a message: no reactions, no Reply.
    h.get_by_label("the plan from last year").click();
    h.run();
    assert!(h.query_by_label("Reply").is_none() && h.query_by_label("Like").is_none());
    assert!(h.state_mut().take_actions().is_empty());

    // An active room keeps its composer.
    h.get_by_label("general").click();
    h.run();
    h.get_by_label("Send");
}

#[test]
fn a_phone_lists_the_archive_too() {
    let mut h = chat([390.0, 844.0]);
    h.get_by_label("Archive");
    h.get_by_label("old-team").click();
    h.run();
    h.get_by_label("Archive: read only");
}
