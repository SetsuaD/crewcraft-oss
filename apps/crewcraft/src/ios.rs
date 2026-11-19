//! The iOS shell around the desktop window. Task T421.
//!
//! Owns: how the window lives on an iPhone. eframe opens it through winit's iOS backend, which turns taps into
//! touches and raises the on-screen keyboard when a text field takes focus (egui asks for text input, winit makes its
//! view the first responder, and the typed characters and Backspace arrive as key events). The window and its phone
//! layout are `crewcraft-desktop-ui`'s, with the bundled font, unchanged.
//!
//! What winit 0.30 does not do on iOS is report where the keyboard is, so a field near the bottom of the screen (the
//! composer) would sit under it. `PhoneApp` reads the key window's safe area and its keyboard layout guide from UIKit
//! before every frame and gives egui the larger of the two at the bottom, so the layout ends above the keyboard and
//! clear of the home indicator, the status bar and the Dynamic Island. The keyboard slides in and out without telling
//! winit, so after it moves `PhoneApp` looks again for a moment until it stops.
//!
//! Called by: `main.rs` on iOS (`run`). Calls: `app::DesktopApp`, and UIKit through its Rust bindings
//! (`objc2-ui-kit`, whose calls used here are safe), on iOS only; everything else is plain Rust, tested everywhere.
//! Later tasks slot in beside it: the Secure Enclave key (T422) and the app's storage, lifecycle and `crewcraft://`
//! links (T423).

use std::path::PathBuf;
use std::time::Duration;

use eframe::egui::{self, SafeAreaInsets, epaint::MarginF32};

/// The launch argument that puts the text cursor in the first text field once the window is up, as a tap on it
/// would, so the keyboard comes up. A simulator has nothing that can tap, so this is how the keyboard is checked there:
/// `xcrun simctl launch <device> io.github.setsuad.crewcraft --focus-first-field`.
pub const FOCUS_FIRST_FIELD: &str = "--focus-first-field";

/// How many frames `FOCUS_FIRST_FIELD` tries before giving up. Each presses Tab (which moves the focus to the next
/// widget) or, once a text field has the focus, places its cursor; the enrollment screen needs two.
pub const FOCUS_TRIES: u8 = 8;

/// How often the insets are read again while the keyboard may be moving.
pub const SETTLE_INTERVAL: Duration = Duration::from_millis(50);
/// How many frames, `SETTLE_INTERVAL` apart, the insets are read again after they or the text focus changed: about
/// twice the keyboard's slide.
pub const SETTLE_FRAMES: u8 = 12;

/// The app's data folder on iOS: `Library/Application Support/CrewCraft` in the app's own container, which iOS names
/// in `HOME`. Only this app can read it, and it goes when the app is deleted. `None` without a home folder.
pub fn data_dir(home: Option<PathBuf>) -> Option<PathBuf> {
    home.filter(|home| home.is_absolute()).map(|home| home.join("Library").join("Application Support").join("CrewCraft"))
}

/// What UIKit reports about the key window, in points: its height, its safe-area insets, and the frame of its
/// keyboard layout guide (top edge and height), which is the keyboard when the keyboard is shown and the bottom of the
/// safe area when it is not. Before UIKit has laid the guide out its frame is empty, and it is then ignored.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Screen {
    pub height: f32,
    pub safe_top: f32,
    pub safe_left: f32,
    pub safe_right: f32,
    pub safe_bottom: f32,
    pub keyboard_top: f32,
    pub keyboard_height: f32,
}

fn points(value: f32) -> f32 {
    if value.is_finite() { value.max(0.0) } else { 0.0 }
}

/// The insets egui lays the window out within: the safe area, with the bottom raised to the keyboard's top edge
/// whenever the keyboard covers more of the screen than the safe area does.
pub fn insets(screen: &Screen) -> SafeAreaInsets {
    let height = points(screen.height);
    let laid_out = screen.keyboard_top.is_finite() && screen.keyboard_height.is_finite() && screen.keyboard_height > 0.0;
    let covered = if laid_out { (height - screen.keyboard_top).clamp(0.0, height) } else { 0.0 };
    SafeAreaInsets(MarginF32 {
        top: points(screen.safe_top),
        left: points(screen.safe_left),
        right: points(screen.safe_right),
        bottom: points(screen.safe_bottom).max(covered),
    })
}

/// Reads the key window's [`Screen`]. `None` before the window exists, off the main thread, and on other systems.
pub type ReadScreen = fn() -> Option<Screen>;

/// Wraps the window app for a phone: the insets before every frame, and `FOCUS_FIRST_FIELD`.
pub struct PhoneApp<A> {
    inner: A,
    read: ReadScreen,
    last: Option<SafeAreaInsets>,
    /// Whether a text field had the keyboard focus in the last frame.
    typing: bool,
    /// Frames left to keep reading the insets after the keyboard or the insets moved.
    settle: u8,
    /// Tab presses left for `FOCUS_FIRST_FIELD`.
    focus_tries: u8,
}

impl<A: eframe::App> PhoneApp<A> {
    /// `inner` with the insets read from UIKit. `focus_first_field` is whether the app was launched with
    /// `FOCUS_FIRST_FIELD`.
    pub fn new(inner: A, focus_first_field: bool) -> Self {
        Self::with_reader(inner, focus_first_field, read_uikit)
    }

    /// `new` with another source of the insets (tests pass their own).
    pub fn with_reader(inner: A, focus_first_field: bool, read: ReadScreen) -> Self {
        Self { inner, read, last: None, typing: false, settle: 0, focus_tries: if focus_first_field { FOCUS_TRIES } else { 0 } }
    }

    pub fn inner(&self) -> &A {
        &self.inner
    }

    /// The insets given to egui in the last frame, if UIKit answered.
    pub fn last_insets(&self) -> Option<SafeAreaInsets> {
        self.last
    }
}

impl<A: eframe::App> eframe::App for PhoneApp<A> {
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        self.inner.raw_input_hook(ctx, raw_input);
        if let Some(screen) = (self.read)() {
            let insets = insets(&screen);
            raw_input.safe_area_insets = Some(insets);
            if self.last != Some(insets) {
                self.last = Some(insets);
                self.settle = SETTLE_FRAMES;
            }
        }
        if self.focus_tries > 0 && !self.typing {
            self.focus_tries -= 1;
            focus_step(ctx, raw_input);
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        inside_insets(ui, |ui| self.inner.ui(ui, frame));
        let ctx = ui.ctx().clone();
        // egui asks for text input (`ime`) exactly when a text field has the keyboard focus.
        let typing = ctx.output(|output| output.ime.is_some());
        self.end_frame(&ctx, typing);
    }
}

impl<A> PhoneApp<A> {
    /// After each frame: `typing` is whether a text field has the keyboard focus. Schedules the next looks at the
    /// insets while the keyboard may be moving, and the next Tab for `FOCUS_FIRST_FIELD`.
    pub fn end_frame(&mut self, ctx: &egui::Context, typing: bool) {
        if typing != self.typing {
            self.typing = typing;
            self.settle = SETTLE_FRAMES;
        }
        if typing {
            self.focus_tries = 0;
        }
        if self.focus_tries > 0 {
            ctx.request_repaint();
        } else if self.settle > 0 {
            self.settle -= 1;
            ctx.request_repaint_after(SETTLE_INTERVAL);
        }
    }

    /// Whether a text field had the keyboard focus in the last frame.
    pub fn typing(&self) -> bool {
        self.typing
    }
}

/// Runs `add_contents` in the part of the root `ui` inside the insets (egui's content rect). The root Ui covers the
/// whole screen, so the area outside is painted with the window's background instead of eframe's clear colour.
pub fn inside_insets<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let content = ui.ctx().content_rect().intersect(ui.max_rect());
    ui.painter().rect_filled(ui.max_rect(), 0.0, ui.visuals().panel_fill);
    ui.scope_builder(egui::UiBuilder::new().max_rect(content), add_contents).inner
}

/// One step of `FOCUS_FIRST_FIELD`: when a text field has the focus, place its cursor at the start, which is what
/// makes egui ask for text input (a Tab alone focuses a field without a cursor); otherwise press Tab.
fn focus_step(ctx: &egui::Context, raw_input: &mut egui::RawInput) {
    let field = ctx.memory(|memory| memory.focused()).and_then(|id| egui::text_edit::TextEditState::load(ctx, id).map(|state| (id, state)));
    match field {
        Some((id, mut state)) => {
            let start = egui::text::CCursor::new(0);
            state.cursor.set_char_range(Some(egui::text_selection::CCursorRange::one(start)));
            state.store(ctx, id);
        }
        None => {
            for pressed in [true, false] {
                raw_input.events.push(egui::Event::Key {
                    key: egui::Key::Tab,
                    physical_key: None,
                    pressed,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                });
            }
        }
    }
}

#[cfg(target_os = "ios")]
fn read_uikit() -> Option<Screen> {
    use objc2_foundation::MainThreadMarker;
    use objc2_ui_kit::{UIApplication, UISceneActivationState, UIWindowScene};

    let main_thread = MainThreadMarker::new()?;
    for scene in UIApplication::sharedApplication(main_thread).connectedScenes().iter() {
        let Ok(scene) = scene.downcast::<UIWindowScene>() else { continue };
        if !matches!(scene.activationState(), UISceneActivationState::ForegroundActive | UISceneActivationState::ForegroundInactive) {
            continue;
        }
        let Some(window) = scene.keyWindow() else { continue };
        // The window's content view (winit's view, which egui draws into), or the window itself before it has one.
        let content = window.rootViewController().and_then(|controller| controller.view());
        let view: &objc2_ui_kit::UIView = match &content {
            Some(view) => view,
            None => &window,
        };
        let safe = view.safeAreaInsets();
        let guide = view.keyboardLayoutGuide();
        // Resolve any pending layout, so the guide's frame follows the keyboard in this frame rather than the last.
        view.layoutIfNeeded();
        let keyboard = guide.layoutFrame();
        return Some(Screen {
            height: view.bounds().size.height as f32,
            safe_top: safe.top as f32,
            safe_left: safe.left as f32,
            safe_right: safe.right as f32,
            safe_bottom: safe.bottom as f32,
            keyboard_top: keyboard.origin.y as f32,
            keyboard_height: keyboard.size.height as f32,
        });
    }
    None
}

#[cfg(not(target_os = "ios"))]
fn read_uikit() -> Option<Screen> {
    None
}

/// Writes warnings and errors from the window's libraries (eframe, winit, wgpu) to standard error, the app's log on
/// iOS (`xcrun simctl launch --console-pty`), so a window that cannot open says why instead of the app just ending.
#[cfg(target_os = "ios")]
struct StderrLog;

#[cfg(target_os = "ios")]
impl log::Log for StderrLog {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &log::Record<'_>) {
        if self.enabled(record.metadata()) {
            eprintln!("crewcraft {} {}: {}", record.level(), record.target(), record.args());
        }
    }

    fn flush(&self) {}
}

#[cfg(target_os = "ios")]
static STDERR_LOG: StderrLog = StderrLog;

/// Opens the window on iOS and runs it until the app ends (on iOS the event loop never returns).
#[cfg(target_os = "ios")]
pub fn run(focus_first_field: bool) -> std::io::Result<()> {
    if log::set_logger(&STDERR_LOG).is_ok() {
        log::set_max_level(log::LevelFilter::Warn);
    }
    // eframe asks wgpu for its default limits, which some Metal devices do not reach (the iOS Simulator has 15
    // inter-stage shader variables, not 16, and the window then fails to open). egui needs far less, so the device is
    // asked for exactly what the GPU offers.
    let mut setup = eframe::egui_wgpu::WgpuSetupCreateNew::without_display_handle();
    setup.device_descriptor = std::sync::Arc::new(|adapter| eframe::wgpu::DeviceDescriptor {
        label: Some("crewcraft"),
        required_limits: adapter.limits(),
        ..Default::default()
    });
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("CrewCraft"),
        renderer: eframe::Renderer::Wgpu,
        wgpu_options: eframe::egui_wgpu::WgpuConfiguration { wgpu_setup: eframe::egui_wgpu::WgpuSetup::CreateNew(setup), ..Default::default() },
        ..Default::default()
    };
    let join = crate::app::join_from_link(crate::app::JOIN_TIMEOUT);
    eframe::run_native(
        "CrewCraft",
        options,
        Box::new(move |creation| Ok(Box::new(PhoneApp::new(crate::app::DesktopApp::new(&creation.egui_ctx, join), focus_first_field)))),
    )
    .map_err(|error| std::io::Error::other(format!("the window could not open: {error}")))
}
