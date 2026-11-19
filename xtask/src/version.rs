//! Release versions, and how each package format writes them.
//!
//! A release version is `MAJOR.MINOR.PATCH` or `MAJOR.MINOR.PATCH-STAGE.N` with STAGE `alpha`, `beta` or `rc`.
//! Asset names use it as written. Debian writes the pre-release with `~` so that it sorts before the release. Windows
//! Installer compares only three numbers (major and minor up to 255, build up to 65535), so the MSI packs the patch
//! and the pre-release into the build number: `PATCH * 1000 + STAGE`, where STAGE is `100 + N` for alpha, `200 + N`
//! for beta, `300 + N` for rc and `900` for the release. `0.1.0-beta.1` becomes `0.1.201` and `0.1.0` becomes
//! `0.1.900`, so a newer release always has a larger MSI version and its installer replaces the older one.

use std::fmt;

use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Alpha,
    Beta,
    Rc,
}

impl Stage {
    fn name(self) -> &'static str {
        match self {
            Stage::Alpha => "alpha",
            Stage::Beta => "beta",
            Stage::Rc => "rc",
        }
    }
}

/// A parsed release version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    /// The pre-release stage and its number, or `None` for a release.
    pub pre: Option<(Stage, u32)>,
}

/// The largest patch number the MSI build number can carry (`64 * 1000 + 900 <= 65535`).
pub const MAX_PATCH: u32 = 64;
/// The largest pre-release number (`N` in `beta.N`).
pub const MAX_PRE: u32 = 99;

fn number(text: &str, what: &str, whole: &str) -> Result<u32> {
    let valid = !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) && (text == "0" || !text.starts_with('0'));
    if !valid {
        return Err(Error::new(format!("version {whole:?}: the {what} must be a number without leading zeros")));
    }
    text.parse::<u32>().map_err(|_| Error::new(format!("version {whole:?}: the {what} is too large")))
}

impl Version {
    /// Parses `MAJOR.MINOR.PATCH` or `MAJOR.MINOR.PATCH-(alpha|beta|rc).N`, within the limits every package
    /// format can carry (major and minor at most 255, patch at most 64, N at most 99).
    pub fn parse(text: &str) -> Result<Version> {
        let (core, pre) = match text.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (text, None),
        };
        let parts: Vec<&str> = core.split('.').collect();
        let [major, minor, patch] = parts.as_slice() else {
            return Err(Error::new(format!("version {text:?}: expected MAJOR.MINOR.PATCH, optionally -alpha.N, -beta.N or -rc.N")));
        };
        let major = number(major, "major number", text)?;
        let minor = number(minor, "minor number", text)?;
        let patch = number(patch, "patch number", text)?;
        if major > 255 || minor > 255 {
            return Err(Error::new(format!("version {text:?}: major and minor must be at most 255 (Windows Installer)")));
        }
        if patch > MAX_PATCH {
            return Err(Error::new(format!("version {text:?}: the patch number must be at most {MAX_PATCH} (Windows Installer)")));
        }
        let pre = match pre {
            None => None,
            Some(pre) => {
                let Some((stage, n)) = pre.split_once('.') else {
                    return Err(Error::new(format!("version {text:?}: the pre-release must be alpha.N, beta.N or rc.N")));
                };
                let stage = match stage {
                    "alpha" => Stage::Alpha,
                    "beta" => Stage::Beta,
                    "rc" => Stage::Rc,
                    _ => return Err(Error::new(format!("version {text:?}: the pre-release must be alpha.N, beta.N or rc.N"))),
                };
                let n = number(n, "pre-release number", text)?;
                if n > MAX_PRE {
                    return Err(Error::new(format!("version {text:?}: the pre-release number must be at most {MAX_PRE}")));
                }
                Some((stage, n))
            }
        };
        Ok(Version { major, minor, patch, pre })
    }

    /// The version as Debian writes it: `0.1.0~beta.1`, which sorts before `0.1.0`.
    pub fn debian(&self) -> String {
        match self.pre {
            None => format!("{}.{}.{}", self.major, self.minor, self.patch),
            Some((stage, n)) => format!("{}.{}.{}~{}.{n}", self.major, self.minor, self.patch, stage.name()),
        }
    }

    /// The stage number the MSI build number and the Android version code end in: `100 + N` for alpha, `200 + N`
    /// for beta, `300 + N` for rc and `900` for the release.
    pub fn stage_number(&self) -> u32 {
        match self.pre {
            None => 900,
            Some((Stage::Alpha, n)) => 100 + n,
            Some((Stage::Beta, n)) => 200 + n,
            Some((Stage::Rc, n)) => 300 + n,
        }
    }

    /// The MSI ProductVersion (see the module comment): `0.1.0-beta.1` is `0.1.201`.
    pub fn msi_product_version(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch * 1000 + self.stage_number())
    }

    /// The Android `versionCode`, the number Android compares to decide whether an APK is an upgrade:
    /// `MAJOR * 10_000_000 + MINOR * 100_000 + PATCH * 1000 + STAGE` (STAGE as in [`Version::stage_number`]), so
    /// `0.1.0-beta.1` is `100201` and `1.2.3` is `10203900`, and a later release always has a larger code. The digits
    /// leave room for a minor number up to 99 and a major number up to 209 (Google Play takes codes up to
    /// 2100000000); a version outside that is refused.
    pub fn android_version_code(&self) -> Result<u32> {
        if self.minor > 99 || self.major > 209 {
            return Err(Error::new(format!("version {self}: an Android version code needs a minor number up to 99 and a major number up to 209")));
        }
        Ok(self.major * 10_000_000 + self.minor * 100_000 + self.patch * 1000 + self.stage_number())
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some((stage, n)) = self.pre {
            write!(f, "-{}.{n}", stage.name())?;
        }
        Ok(())
    }
}
