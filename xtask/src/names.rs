//! Build targets and release asset names: `<app>-<version>-<os>-<arch>.<ext>`.

use crate::version::Version;
use crate::{Error, Result};

/// The desktop client's package and binary name.
pub const CLIENT: &str = "crewcraft";
/// The server's package and binary name.
pub const SERVER: &str = "crewcraft-server";

/// A platform `cargo xtask dist` builds for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    LinuxX86_64,
    WindowsX86_64,
    /// x86_64 and arm64 in one binary; built on macOS only.
    MacosUniversal,
}

impl Target {
    pub const ALL: [Target; 3] = [Target::LinuxX86_64, Target::WindowsX86_64, Target::MacosUniversal];

    /// The targets built when `--target` is not given: macOS on a Mac, Linux and Windows everywhere else.
    pub fn host_default() -> Vec<Target> {
        if cfg!(target_os = "macos") { vec![Target::MacosUniversal] } else { vec![Target::LinuxX86_64, Target::WindowsX86_64] }
    }

    /// Parses the `--target` value, `<os>-<arch>`.
    pub fn parse(text: &str) -> Result<Target> {
        match text {
            "linux-x86_64" => Ok(Target::LinuxX86_64),
            "windows-x86_64" => Ok(Target::WindowsX86_64),
            "macos-universal" => Ok(Target::MacosUniversal),
            "macos-aarch64" | "macos-x86_64" => Err(Error::new(format!("target {text}: macOS is built as one universal package, macos-universal"))),
            _ => Err(Error::new(format!("unknown target {text:?}: expected linux-x86_64, windows-x86_64 or macos-universal"))),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Target::LinuxX86_64 => "linux-x86_64",
            Target::WindowsX86_64 => "windows-x86_64",
            Target::MacosUniversal => "macos-universal",
        }
    }

    /// The Rust target triples the binaries are built for; macOS builds two and joins them.
    pub fn triples(self) -> &'static [&'static str] {
        match self {
            Target::LinuxX86_64 => &["x86_64-unknown-linux-gnu"],
            Target::WindowsX86_64 => &["x86_64-pc-windows-gnu"],
            Target::MacosUniversal => &crate::macos::TRIPLES,
        }
    }

    /// The file name of a binary built for this target.
    pub fn binary(self, name: &str) -> String {
        match self {
            Target::LinuxX86_64 | Target::MacosUniversal => name.to_string(),
            Target::WindowsX86_64 => format!("{name}.exe"),
        }
    }

    /// The assets this target produces, in build order.
    pub fn assets(self) -> &'static [Asset] {
        match self {
            Target::LinuxX86_64 => &[Asset::ClientDeb, Asset::ClientAppImage, Asset::ServerTarGz],
            Target::WindowsX86_64 => &[Asset::ClientMsi, Asset::ServerZip],
            Target::MacosUniversal => &[Asset::ClientDmg, Asset::ServerMacTarGz],
        }
    }
}

/// One release asset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asset {
    /// The desktop client as a Debian package.
    ClientDeb,
    /// The desktop client as an AppImage.
    ClientAppImage,
    /// The Linux server: binary, licenses and a README.
    ServerTarGz,
    /// The desktop client as a Windows Installer package.
    ClientMsi,
    /// The Windows server: the same contents as the Linux archive, as a zip.
    ServerZip,
    /// The desktop client as `CrewCraft.app` in a disk image.
    ClientDmg,
    /// The macOS server (universal binary), as the Linux archive.
    ServerMacTarGz,
}

impl Asset {
    pub fn target(self) -> Target {
        match self {
            Asset::ClientDeb | Asset::ClientAppImage | Asset::ServerTarGz => Target::LinuxX86_64,
            Asset::ClientMsi | Asset::ServerZip => Target::WindowsX86_64,
            Asset::ClientDmg | Asset::ServerMacTarGz => Target::MacosUniversal,
        }
    }

    pub fn app(self) -> &'static str {
        match self {
            Asset::ClientDeb | Asset::ClientAppImage | Asset::ClientMsi | Asset::ClientDmg => CLIENT,
            Asset::ServerTarGz | Asset::ServerZip | Asset::ServerMacTarGz => SERVER,
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Asset::ClientDeb => "deb",
            Asset::ClientAppImage => "AppImage",
            Asset::ServerTarGz | Asset::ServerMacTarGz => "tar.gz",
            Asset::ClientMsi => "msi",
            Asset::ServerZip => "zip",
            Asset::ClientDmg => "dmg",
        }
    }

    /// The asset's base name without the extension, also the top folder inside the server archives.
    pub fn stem(self, version: &Version) -> String {
        format!("{}-{version}-{}", self.app(), self.target().name())
    }

    /// The asset's file name, e.g. `crewcraft-0.1.0-beta.1-linux-x86_64.deb`.
    pub fn file_name(self, version: &Version) -> String {
        format!("{}.{}", self.stem(version), self.extension())
    }
}
