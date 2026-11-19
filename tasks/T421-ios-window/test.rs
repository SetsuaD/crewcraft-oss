//! T421: the egui window on iOS. The UIKit calls run only on an iPhone or the simulator; what they feed is tested
//! here: the insets egui lays out within (the safe area, raised above the on-screen keyboard), the app's data folder
//! in its container, and the launch option that gives the first text field the keyboard focus on a simulator.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use crewcraft::ios::{self, FOCUS_FIRST_FIELD, FOCUS_TRIES, PhoneApp, Screen};
use crewcraft_desktop_ui::{Update, Window, fonts};
use eframe::App as _;
use eframe::egui::{self, Event, Key, Pos2, RawInput, Rect, vec2};

/// An iPhone 16 in portrait, in points: 393 x 852, a 62-point status bar and Dynamic Island, a 34-point home indicator.
const HEIGHT: f32 = 852.0;
const SAFE_TOP: f32 = 62.0;
const SAFE_BOTTOM: f32 = 34.0;
/// The keyboard's height with its suggestion bar, in points.
const KEYBOARD: f32 = 336.0;

fn screen(keyboard_shown: bool) -> Screen {
    // The keyboard layout guide's top is the keyboard's top edge, or the bottom of the safe area when it is hidden.
    let keyboard_height = if keyboard_shown { KEYBOARD } else { SAFE_BOTTOM };
    Screen {
        height: HEIGHT,
        safe_top: SAFE_TOP,
        safe_left: 0.0,
        safe_right: 0.0,
        safe_bottom: SAFE_BOTTOM,
        keyboard_top: HEIGHT - keyboard_height,
        keyboard_height,
    }
}

fn no_keyboard() -> Option<Screen> {
    Some(screen(false))
}

fn keyboard_up() -> Option<Screen> {
    Some(screen(true))
}

fn no_window() -> Option<Screen> {
    None
}

/// An app with nothing in it, to wrap.
struct Empty;

impl eframe::App for Empty {
    fn ui(&mut self, _ui: &mut egui::Ui, _frame: &mut eframe::Frame) {}
}

fn phone_input() -> RawInput {
    RawInput { screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(393.0, HEIGHT))), ..Default::default() }
}

/// Runs one frame and drops its textures (nothing paints in a test).
fn frame(ctx: &egui::Context, input: RawInput, run_ui: impl FnMut(&mut egui::Ui)) -> egui::FullOutput {
    let mut output = ctx.run_ui(input, run_ui);
    output.textures_delta.clear();
    output
}

fn tabs(input: &RawInput) -> usize {
    input.events.iter().filter(|event| matches!(event, Event::Key { key: Key::Tab, pressed: true, .. })).count()
}

#[test]
fn without_the_keyboard_the_insets_are_the_safe_area() {
    let insets = ios::insets(&screen(false)).0;
    assert_eq!((insets.top, insets.left, insets.right, insets.bottom), (SAFE_TOP, 0.0, 0.0, SAFE_BOTTOM));
}

#[test]
fn the_keyboard_raises_the_bottom_inset_to_its_top_edge() {
    assert_eq!(ios::insets(&screen(true)).0.bottom, KEYBOARD);
    assert_eq!(ios::insets(&screen(true)).0.top, SAFE_TOP, "the top stays the safe area");
    // A keyboard lower than the home indicator (hardware keyboard, only the suggestion bar off screen) never lowers it.
    let low = Screen { keyboard_top: HEIGHT - 10.0, keyboard_height: 10.0, ..screen(false) };
    assert_eq!(ios::insets(&low).0.bottom, SAFE_BOTTOM);
}

#[test]
fn nonsense_from_the_system_never_becomes_a_negative_or_endless_inset() {
    let odd = Screen {
        height: HEIGHT,
        safe_top: f32::NAN,
        safe_left: -5.0,
        safe_right: f32::INFINITY,
        safe_bottom: -1.0,
        keyboard_top: -400.0,
        keyboard_height: 2000.0,
    };
    let insets = ios::insets(&odd).0;
    assert_eq!((insets.top, insets.left, insets.right), (0.0, 0.0, 0.0));
    assert_eq!(insets.bottom, HEIGHT, "a keyboard above the window covers at most the window");
    let lost = Screen { keyboard_top: f32::NAN, ..screen(false) };
    assert_eq!(ios::insets(&lost).0.bottom, SAFE_BOTTOM);
    // Before UIKit lays the keyboard layout guide out, its frame is all zeros: that is no keyboard, not a keyboard
    // covering the whole window.
    let unresolved = Screen { keyboard_top: 0.0, keyboard_height: 0.0, ..screen(false) };
    assert_eq!(ios::insets(&unresolved).0.bottom, SAFE_BOTTOM);
}

#[test]
fn the_data_folder_is_application_support_in_the_app_container() {
    let home = PathBuf::from("/private/var/mobile/Containers/Data/Application/00000000-0000-0000-0000-000000000000");
    assert_eq!(ios::data_dir(Some(home.clone())), Some(home.join("Library").join("Application Support").join("CrewCraft")));
    assert_eq!(ios::data_dir(None), None);
    assert_eq!(ios::data_dir(Some(PathBuf::from("relative/home"))), None, "a relative HOME is not the container");
    assert!(ios::data_dir(Some(home)).unwrap().starts_with(Path::new("/private/var/mobile")));
}

#[test]
fn every_frame_gets_the_insets_from_the_system() {
    let ctx = egui::Context::default();
    let mut app = PhoneApp::with_reader(Empty, false, keyboard_up);
    let mut input = phone_input();
    app.raw_input_hook(&ctx, &mut input);
    assert_eq!(input.safe_area_insets, Some(ios::insets(&screen(true))));
    assert_eq!(app.last_insets(), Some(ios::insets(&screen(true))));
    assert_eq!(tabs(&input), 0, "nothing is pressed without the launch option");

    // Before the window exists UIKit has nothing to say, and egui keeps what it had.
    let mut early = PhoneApp::with_reader(Empty, false, no_window);
    let mut input = phone_input();
    early.raw_input_hook(&ctx, &mut input);
    assert_eq!(input.safe_area_insets, None);
    assert_eq!(early.last_insets(), None);
}

#[test]
fn the_layout_ends_above_the_keyboard() {
    let ctx = egui::Context::default();
    for (read, bottom) in [(no_keyboard as ios::ReadScreen, HEIGHT - SAFE_BOTTOM), (keyboard_up, HEIGHT - KEYBOARD)] {
        let mut app = PhoneApp::with_reader(Empty, false, read);
        let mut given = Rect::NOTHING;
        for _ in 0..2 {
            let mut input = phone_input();
            app.raw_input_hook(&ctx, &mut input);
            // What `PhoneApp::ui` does with the root Ui eframe hands it.
            let _ = frame(&ctx, input, |ui| ios::inside_insets(ui, |ui| given = ui.max_rect()));
        }
        assert_eq!(given.top(), SAFE_TOP, "below the status bar and Dynamic Island");
        assert_eq!(given.bottom(), bottom);
        assert_eq!((given.left(), given.right()), (0.0, 393.0));
    }
}

#[test]
fn the_launch_option_gives_the_first_text_field_of_the_enrollment_screen_the_keyboard_focus() {
    assert_eq!(FOCUS_FIRST_FIELD, "--focus-first-field");
    let ctx = egui::Context::default();
    ctx.set_fonts(fonts());
    let mut window = Window::new();
    window.apply(Update::NeedsEnrollment);
    let mut app = PhoneApp::with_reader(Empty, true, no_keyboard);
    let mut pressed = 0;
    for _ in 0..usize::from(FOCUS_TRIES) + 4 {
        let mut input = phone_input();
        app.raw_input_hook(&ctx, &mut input);
        pressed += tabs(&input);
        let output = frame(&ctx, input, |ui| window.ui(ui));
        // What eframe's iOS backend turns into "show the keyboard": egui asking for text input.
        app.end_frame(&ctx, output.platform_output.ime.is_some());
    }
    assert!(app.typing(), "a text field has the keyboard focus");
    assert!((1..usize::from(FOCUS_TRIES)).contains(&pressed), "Tab was pressed {pressed} times");
    // Once a field has it, nothing more is pressed.
    let mut input = phone_input();
    app.raw_input_hook(&ctx, &mut input);
    assert_eq!(tabs(&input), 0);
}

#[test]
fn without_the_launch_option_the_focus_is_left_to_the_person() {
    let ctx = egui::Context::default();
    ctx.set_fonts(fonts());
    let mut window = Window::new();
    window.apply(Update::NeedsEnrollment);
    let mut app = PhoneApp::with_reader(Empty, false, no_keyboard);
    for _ in 0..4 {
        let mut input = phone_input();
        app.raw_input_hook(&ctx, &mut input);
        assert_eq!(tabs(&input), 0);
        let output = frame(&ctx, input, |ui| window.ui(ui));
        app.end_frame(&ctx, output.platform_output.ime.is_some());
    }
    assert!(!app.typing(), "no keyboard until a field is tapped");
}
