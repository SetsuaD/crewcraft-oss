//! T333: image previews under messages: an attached PNG, JPEG, GIF or WebP file up to 8 MiB is fetched once and shown
//! scaled to at most 320 pixels wide above its chip; other files, larger ones and files an import could not capture
//! are not fetched; bytes that are not an image (or a fetch that failed) leave the chip as it was, and are not asked for
//! again.
#![allow(clippy::unwrap_used, clippy::panic)]

use crewcraft_client_core::room_view::Shown;
use crewcraft_client_core::timeline::Line;
use crewcraft_desktop_ui::{Action, FileChip, Update, Window, decode_preview, fonts, previewable};
use crewcraft_ui_model::{Command, MAX_PREVIEW_BYTES};
use egui_kittest::Harness;

const ROOM: &str = "general";

fn png(width: u32, height: u32) -> Vec<u8> {
    let image = image::RgbaImage::from_pixel(width, height, image::Rgba([200, 30, 30, 255]));
    let mut out = std::io::Cursor::new(Vec::new());
    image.write_to(&mut out, image::ImageFormat::Png).unwrap();
    out.into_inner()
}

fn chip(n: u8, name: &str, size: u64) -> FileChip {
    FileChip { file: [n; 16], name: name.into(), size }
}

#[test]
fn which_files_get_a_preview() {
    assert!(previewable(&chip(1, "Photo.JPG", 2_000)));
    assert!(previewable(&chip(1, "anim.gif", 2_000)) && previewable(&chip(1, "pic.webp", 2_000)) && previewable(&chip(1, "a.png", 1)));
    assert!(!previewable(&chip(1, "report.pdf", 2_000)), "not an image");
    assert!(!previewable(&chip(1, "huge.png", MAX_PREVIEW_BYTES + 1)), "too large");
    assert!(!previewable(&chip(0, "lost.png", 2_000)), "not archived");
}

#[test]
fn decoding_scales_down_and_refuses_what_is_not_an_image() {
    let image = decode_preview(&png(1000, 500)).unwrap();
    assert_eq!(image.size, [320, 160], "scaled to 320 wide, same shape");
    assert_eq!(decode_preview(&png(40, 30)).unwrap().size, [40, 30], "small images keep their size");
    assert!(decode_preview(b"not an image at all").is_none());
    assert!(decode_preview(&[]).is_none());
}

#[test]
fn an_image_is_fetched_once_and_shown() {
    let mut h = Harness::builder()
        .with_size([1100.0, 700.0])
        .with_context_setup(|ctx| ctx.set_fonts(fonts()))
        .build_ui_state(|ui, window: &mut Window| window.ui(ui), Window::new());
    h.state_mut().apply(Update::SignedIn { email: "ana@example.org".to_owned(), rooms: vec![ROOM.to_owned()] });
    let line = Shown::Line(Line { cursor: 5, author: "bo@example.org".into(), html: "pictures".into(), edited: false });
    h.state_mut().apply(Update::Snapshot { room: ROOM.into(), shown: vec![line] });
    let photo = png(640, 480);
    let files = vec![chip(1, "photo.png", photo.len() as u64), chip(2, "notes.txt", 10), chip(3, "broken.png", 20)];
    h.state_mut().apply(Update::Attachments { room: ROOM.into(), files: vec![(5, files)] });
    h.run();
    let asked: Vec<Action> = h.state_mut().take_actions().into_iter().filter(|a| matches!(a, Action::Room(Command::Preview { .. }))).collect();
    assert_eq!(
        asked,
        vec![Action::Room(Command::Preview { file: [1; 16], size: photo.len() as u64 }), Action::Room(Command::Preview { file: [3; 16], size: 20 })],
        "the two images, not the text file"
    );
    h.state_mut().apply(Update::Preview { file: [1; 16], bytes: photo });
    h.state_mut().apply(Update::Preview { file: [3; 16], bytes: b"garbage".to_vec() });
    h.run();
    h.run();
    assert!(h.state().previewed(&[1; 16]));
    assert!(!h.state().previewed(&[3; 16]), "not an image: the chip stays");
    assert!(h.state_mut().take_actions().iter().all(|a| !matches!(a, Action::Room(Command::Preview { .. }))), "nothing asked for twice");
}
