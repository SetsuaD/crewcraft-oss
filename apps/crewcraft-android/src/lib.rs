//! The CrewCraft Android app: the same egui window as the desktop (`crewcraft::app::DesktopApp` over
//! `crewcraft-desktop-ui`), run by eframe under Android's own `NativeActivity`, with no Java or Kotlin source.
//! Task T401; `cargo xtask apk` (T400) packages it.
//!
//! Owns: the pieces of the phone shell that do not need a phone, here so they are tested on the build machine
//! (where to keep the app's data, when to show the soft keyboard, the version line in the log), and on Android the
//! entry point (`shell`). Called by: `android-activity` on the phone (through `android_main`) and the T401 test.
//! Calls: `crewcraft` and eframe (on Android only). Later tasks slot in here: the phone layout (T402) is in
//! `crewcraft-desktop-ui` and needs nothing from this crate; the Keystore device key (T403) is `keystore`, the key
//! store the controller is started with, and `selftest` its emulator test; storage and lifecycle (T404) refine [`data_dir`]; links (T405) feed the
//! activity's intent to the enrollment screen.

use std::path::{Path, PathBuf};

#[cfg(target_os = "android")]
mod keystore;
#[cfg(all(target_os = "android", feature = "selftest"))]
mod selftest;
#[cfg(target_os = "android")]
mod shell;

/// The folder under the activity's internal data path (`/data/user/<user>/<package>/files`) where the app keeps
/// its enrollment and settings. `None` when Android gives no internal data path.
pub fn data_dir(internal: Option<&Path>) -> Option<PathBuf> {
    internal.map(|dir| dir.join("crewcraft"))
}

/// Whether the frame that produced `output` wants the soft keyboard: egui asks for text input (IME) while a text
/// field has the focus.
pub fn keyboard_wanted(output: &egui::PlatformOutput) -> bool {
    output.ime.is_some()
}

/// What to do with the soft keyboard: `Some(true)` show it, `Some(false)` hide it, `None` leave it as it is.
pub fn keyboard_change(shown: bool, wanted: bool) -> Option<bool> {
    (shown != wanted).then_some(wanted)
}

/// The line the app writes to the log when it starts, as `crewcraft --version` prints it on the desktop.
pub fn version_line() -> String {
    let (major, minor) = crewcraft_client_core::PROTOCOL_VERSION;
    format!("crewcraft {} (protocol {major}.{minor}) on Android", env!("CARGO_PKG_VERSION"))
}
