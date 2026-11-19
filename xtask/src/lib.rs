//! CrewCraft build tasks. `cargo xtask dist` builds the release packages; docs/RELEASE.md says how to run it.
//!
//! Each package format is a module that turns bytes into bytes, so a test can check the layout from a fake
//! binary without building a release: [`deb`] (Debian package), [`archive`] (`.tar.gz`, `.zip` and the `ar`
//! container), [`appimage`] (AppImage), [`macos`] (the app bundle, icon and disk image), [`windows_msi`] (Windows Installer database), [`icon`] (PNG sizes and the `.ico`), [`linkage`]
//! (what a built binary links), [`sums`] (`SHA256SUMS.txt`), [`names`] (asset names) and [`version`].
//! [`dist`] runs cargo and puts the pieces together. `cargo xtask apk` builds the Android app: [`android`] (the
//! manifest, icons and build) and [`apk`] (the APK zip and its v2 signature).

use std::fmt;
use std::io;

pub mod android;
pub mod apk;
pub mod appimage;
pub mod archive;
pub mod deb;
pub mod dist;
pub mod icon;
pub mod linkage;
pub mod macos;
pub mod names;
pub mod sums;
pub mod version;
pub mod windows_msi;

/// An error with a message for the person running the build.
#[derive(Debug)]
pub struct Error(String);

impl Error {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self(error.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Adds what was being done to an error's message.
pub(crate) trait Context<T> {
    fn context(self, what: impl FnOnce() -> String) -> Result<T>;
}

impl<T, E: fmt::Display> Context<T> for std::result::Result<T, E> {
    fn context(self, what: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|error| Error(format!("{}: {error}", what())))
    }
}
