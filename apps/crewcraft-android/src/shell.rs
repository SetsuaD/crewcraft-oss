//! The app on the phone (Android only): the entry point Android's `NativeActivity` reaches through
//! `android-activity`, and the eframe app around `crewcraft::app::DesktopApp`. Task T401.
//!
//! Owns: starting the log, the window and the controller with the activity's private data folder, and showing or
//! hiding the soft keyboard as text fields gain and lose the focus. winit also asks for the keyboard when egui
//! wants text input; asking here as well, explicitly, makes it appear on phones where winit's implicit request is
//! ignored. The controller keeps the device key in the Android Keystore (`keystore`, T403). A `selftest` build runs
//! the emulator self-test instead of the window. Called by: `android-activity` (`android_main`). Calls:
//! `crewcraft::app`, eframe, `keystore`, `selftest`, the crate root.

#[cfg(not(feature = "selftest"))]
use std::sync::Arc;

#[cfg(not(feature = "selftest"))]
use eframe::egui;
use winit::platform::android::activity::AndroidApp;

#[cfg(not(feature = "selftest"))]
use crewcraft::app::{DesktopApp, JOIN_TIMEOUT, join_from_link};
#[cfg(not(feature = "selftest"))]
use crewcraft::hardware_key::HardwareKeys;

/// The app's entry point, called by `android-activity` on its own thread once the activity is created; returning
/// ends the app.
// One of the crate's three pieces of unsafe code (see Cargo.toml): android-activity finds this function by its symbol
// name.
#[expect(unsafe_code, reason = "android-activity calls the app through the unmangled symbol android_main")]
#[unsafe(no_mangle)]
fn android_main(app: AndroidApp) {
    android_logger::init_once(android_logger::Config::default().with_max_level(log::LevelFilter::Info).with_tag("CrewCraft"));
    std::panic::set_hook(Box::new(|panic| log::error!("CrewCraft stopped: {panic}")));
    log::info!("{}", crate::version_line());
    let dir = crate::data_dir(app.internal_data_path().as_deref());
    #[cfg(feature = "selftest")]
    self_test(&app, dir);
    #[cfg(not(feature = "selftest"))]
    window(app, dir);
}

/// The app's window, with the device key in the Android Keystore (T403). Without a JVM handle there is no Keystore,
/// and the app says that it cannot keep an enrollment (the desktop key store it falls back to does not exist here).
#[cfg(not(feature = "selftest"))]
fn window(app: AndroidApp, dir: Option<std::path::PathBuf>) {
    let keystore = crate::keystore::AndroidKeystore::new().ok().map(|keys| Arc::new(keys) as Arc<dyn HardwareKeys>);
    let launch_link = crate::jvm::java_vm().and_then(|vm| crate::jvm::launch_link(&vm, app.activity_as_ptr()));
    let options = eframe::NativeOptions { android_app: Some(app.clone()), renderer: eframe::Renderer::Glow, ..Default::default() };
    let join = join_from_link(JOIN_TIMEOUT);
    let started = eframe::run_native(
        "CrewCraft",
        options,
        Box::new(move |creation| {
            let mut inner = match keystore {
                Some(keys) => DesktopApp::with_hardware_keys(&creation.egui_ctx, join, dir, keys),
                None => DesktopApp::with_data_dir(&creation.egui_ctx, join, dir),
            };
            // Opened from a crewcraft://enroll link (T405): the link fills the enrollment form. Never logged.
            if let Some(link) = launch_link {
                if inner.open_link(&link) {
                    log::info!("CrewCraft opened from an invitation link");
                } else {
                    log::info!("CrewCraft opened from a link that is not an invitation link ({} characters)", link.len());
                }
            }
            Ok(Box::new(PhoneApp { inner, app, keyboard: false }))
        }),
    );
    match started {
        Ok(()) => log::info!("CrewCraft closed"),
        Err(error) => log::error!("CrewCraft could not open its window: {error}"),
    }
}

/// The emulator self-test (`selftest`) on its own thread, while this thread keeps answering Android's events so the
/// activity stays responsive; the app ends when the test does.
#[cfg(feature = "selftest")]
fn self_test(app: &AndroidApp, dir: Option<std::path::PathBuf>) {
    let test = std::thread::spawn(move || crate::selftest::run(dir.as_deref()));
    while !test.is_finished() {
        app.poll_events(Some(std::time::Duration::from_millis(200)), |_| {});
    }
    let _ = test.join();
}

/// The desktop app plus the soft keyboard.
#[cfg(not(feature = "selftest"))]
struct PhoneApp {
    inner: DesktopApp,
    app: AndroidApp,
    /// Whether the keyboard was last asked to show.
    keyboard: bool,
}

#[cfg(not(feature = "selftest"))]
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
