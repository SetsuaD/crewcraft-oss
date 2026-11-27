//! Image previews (T333) carry their file name as their accessible name, read back from the accessibility tree: a
//! screen reader meets a named image, not an unnamed one (docs/ACCESSIBILITY.md, gap 3).
#![allow(clippy::unwrap_used)]

use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::{FileChip, Update, Window, fonts};
use egui::accesskit::Role;
use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};

const ROOM: &str = "general";

fn png(width: u32, height: u32) -> Vec<u8> {
    let image = image::RgbaImage::from_pixel(width, height, image::Rgba([30, 120, 200, 255]));
    let mut out = std::io::Cursor::new(Vec::new());
    image.write_to(&mut out, image::ImageFormat::Png).unwrap();
    out.into_inner()
}

#[test]
fn each_preview_is_an_image_named_by_its_file() {
    let mut h = Harness::builder()
        .with_size([1100.0, 700.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".to_owned(), rooms: vec![ROOM.to_owned()] });
    let line = Shown::Line(Line { cursor: 5, author: "bo@example.org".into(), html: "two pictures".into(), edited: false });
    h.state_mut().apply(Update::Snapshot { room: ROOM.into(), shown: vec![line] });
    let (first, second) = (png(640, 480), png(40, 30));
    let files = vec![
        FileChip { file: [1; 16], name: "harbour at dawn.png".into(), size: first.len() as u64 },
        FileChip { file: [2; 16], name: "diagram.png".into(), size: second.len() as u64 },
    ];
    h.state_mut().apply(Update::Attachments { room: ROOM.into(), files: vec![(5, files)] });
    h.run();
    assert!(h.query_by_role(Role::Image).is_none(), "no image before its bytes arrive");

    h.state_mut().apply(Update::Preview { file: [1; 16], bytes: first });
    h.state_mut().apply(Update::Preview { file: [2; 16], bytes: second });
    h.run();
    h.run();
    assert!(h.state().previewed(&[1; 16]) && h.state().previewed(&[2; 16]));
    // Each preview is its own image node, named after its own file.
    h.get_by_role_and_label(Role::Image, "harbour at dawn.png");
    h.get_by_role_and_label(Role::Image, "diagram.png");
    let images: Vec<_> = h.query_all_by_role(Role::Image).collect();
    assert_eq!(images.len(), 2, "one node per preview");
    assert!(images.iter().all(|node| node.accesskit_node().label().is_some_and(|name| !name.trim().is_empty())), "no unnamed image");
}
