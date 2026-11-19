//! The app on the phone (Android only): the entry point Android's `NativeActivity` reaches through
//! `android-activity`, and the eframe app around `crewcraft::app::DesktopApp`. Task T401.
//!
//! Owns: starting the log, the window and the controller with the activity's private data folder, and showing or
//! hiding the soft keyboard as text fields gain and lose the focus. winit also asks for the keyboard when egui
//! wants text input; asking here as well, explicitly, makes it appear on phones where winit's implicit request is
//! ignored. Called by: `android-activity` (`android_main`). Calls: `crewcraft::app`, eframe, the crate root.

use eframe::egui;
use winit::platform::android::activity::AndroidApp;

use crewcraft::app::{DesktopApp, JOIN_TIMEOUT, join_from_link};

/// The app's entry point, called by `android-activity` on its own thread once the activity is created; returning
/// ends the app.
// The only unsafe code in this crate (see Cargo.toml): android-activity finds this function by its symbol name.
#[expect(unsafe_code, reason = "android-activity calls the app through the unmangled symbol android_main")]
#[unsafe(no_mangle)]
fn android_main(app: AndroidApp) {
    android_logger::init_once(android_logger::Config::default().with_max_level(log::LevelFilter::Info).with_tag("CrewCraft"));
    std::panic::set_hook(Box::new(|panic| log::error!("CrewCraft stopped: {panic}")));
    log::info!("{}", crate::version_line());
    let dir = crate::data_dir(app.internal_data_path().as_deref());
    let options = eframe::NativeOptions { android_app: Some(app.clone()), renderer: eframe::Renderer::Glow, ..Default::default() };
    let join = join_from_link(JOIN_TIMEOUT);
    let started = eframe::run_native(
        "CrewCraft",
        options,
        Box::new(move |creation| Ok(Box::new(PhoneApp { inner: DesktopApp::with_data_dir(&creation.egui_ctx, join, dir), app, keyboard: false }))),
    );
    match started {
        Ok(()) => log::info!("CrewCraft closed"),
        Err(error) => log::error!("CrewCraft could not open its window: {error}"),
    }
}

/// The desktop app plus the soft keyboard.
struct PhoneApp {
    inner: DesktopApp,
    app: AndroidApp,
    /// Whether the keyboard was last asked to show.
    keyboard: bool,
}

impl eframe::App for PhoneApp {
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        eframe::App::ui(&mut self.inner, ui, frame);
        let wanted = ui.ctx().output(crate::keyboard_wanted);
        match crate::keyboard_change(self.keyboard, wanted) {
            Some(true) => self.app.show_soft_input(false),
            Some(false) => self.app.hide_soft_input(false),
            None => {}
        }
        self.keyboard = wanted;
    }
}
