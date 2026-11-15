//! Update rules shared by the server and every client (REQUIREMENTS 2.21).
//!
//! Owns: release versions and their order, the signed release manifest and its artifacts, artifact verification
//! (size and SHA-256, also streaming), the server's decision whether to install a release, the install state machine
//! with automatic rollback, which clients are offered an update (required updates, pilot group, percentage rollout),
//! and what an open web client should do.
//! Called by: the server (self-update, serving client updates) and every client (accepting an update).
//!
//! Signatures: `open_release` takes a `SignatureCheck`. The Ed25519 implementation over the project's release keys
//! joins in milestone M5 with the release tooling; until then only the rules here exist, and nothing installs anything.

use std::cmp::Ordering;
use std::fmt;

use crewcraft_strict_toml as toml;
use sha2::{Digest, Sha256};

/// The largest release manifest accepted.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// `major.minor.patch`, optionally `-pre` (for example `1.4.0-beta.2`). A pre-release sorts before its release.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub pre: Option<String>,
}

impl Version {
    pub fn parse(s: &str) -> Option<Version> {
        let (core, pre) = match s.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (s, None),
        };
        let mut parts = core.split('.');
        let mut number = || -> Option<u32> {
            let p = parts.next()?;
            if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) || (p.len() > 1 && p.starts_with('0')) {
                return None;
            }
            p.parse().ok()
        };
        let (major, minor, patch) = (number()?, number()?, number()?);
        if parts.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => None,
            Some(p) if !p.is_empty() && p.len() <= 32 && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.') => Some(p.to_string()),
            Some(_) => return None,
        };
        Some(Version { major, minor, patch, pre })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.pre {
            write!(f, "-{pre}")?;
        }
        Ok(())
    }
}

/// Pre-release identifiers compare part by part: numbers numerically and below words, words in ASCII order, and a
/// shorter list first when one is a prefix of the other (`beta` < `beta.2` < `beta.10` < `rc.1`).
fn compare_pre(a: &str, b: &str) -> Ordering {
    let mut left = a.split('.');
    let mut right = b.split('.');
    loop {
        match (left.next(), right.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let order = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(m), Ok(n)) => m.cmp(&n),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if order != Ordering::Equal {
                    return order;
                }
            }
        }
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch)).then_with(|| match (&self.pre, &other.pre) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(a), Some(b)) => compare_pre(a, b),
        })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Stable,
    Beta,
}

impl Channel {
    /// A server on `self` accepts releases from `release`: beta takes beta and stable, stable takes only stable.
    pub fn accepts(self, release: Channel) -> bool {
        self == Channel::Beta || release == Channel::Stable
    }
}

/// What an artifact is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Server,
    Desktop,
    Android,
}

/// Platform names an artifact may carry, per kind.
pub const SERVER_PLATFORMS: &[&str] = &["linux-x64", "linux-arm64", "windows-x64", "macos-universal"];
pub const DESKTOP_PLATFORMS: &[&str] = &["linux-x64", "linux-arm64", "windows-x64", "windows-arm64", "macos-universal"];
pub const ANDROID_PLATFORMS: &[&str] = &["android"];

/// One downloadable file of a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// The manifest's name for it, from `[artifact.<name>]`.
    pub name: String,
    pub kind: Kind,
    pub platform: String,
    pub file: String,
    pub size: u64,
    pub sha256: [u8; 32],
}

/// A release manifest whose signature has been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub product: String,
    pub version: Version,
    pub channel: Channel,
    pub published: String,
    /// The oldest client version this release's server still accepts.
    pub min_client: Version,
    pub artifacts: Vec<Artifact>,
}

impl Release {
    pub fn artifact(&self, kind: Kind, platform: &str) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.kind == kind && a.platform == platform)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    BadSignature,
    NotUtf8,
    Manifest(toml::Error),
    WrongProduct {
        expected: String,
        found: String,
    },
    WrongChannel,
    /// The release is older than the running version: the update path never goes back.
    Downgrade {
        running: Version,
        release: Version,
    },
    SizeMismatch {
        expected: u64,
        actual: u64,
    },
    HashMismatch,
}

impl fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReleaseError::BadSignature => write!(f, "the release manifest is not signed by a trusted release key"),
            ReleaseError::NotUtf8 => write!(f, "the release manifest is not UTF-8 text"),
            ReleaseError::Manifest(e) => write!(f, "release manifest: {e}"),
            ReleaseError::WrongProduct { expected, found } => write!(f, "the release is for `{found}`, not `{expected}`"),
            ReleaseError::WrongChannel => write!(f, "the release is on a channel this server does not follow"),
            ReleaseError::Downgrade { running, release } => write!(f, "release {release} is older than the running {running}"),
            ReleaseError::SizeMismatch { expected, actual } => write!(f, "the file is {actual} bytes; the manifest says {expected}"),
            ReleaseError::HashMismatch => write!(f, "the file's SHA-256 does not match the manifest"),
        }
    }
}

impl std::error::Error for ReleaseError {}

/// Checks a detached signature over the exact manifest bytes against the trusted release keys.
pub trait SignatureCheck {
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
}

fn bad(line: usize, key: &str, reason: &'static str) -> toml::Error {
    toml::Error::BadValue { line, key: key.to_string(), reason }
}

fn version_field(section: &toml::Section, name: &str, key: &str) -> Result<Version, toml::Error> {
    let (value, line) = section.req_str(name, key)?;
    Version::parse(value).ok_or_else(|| bad(line, key, "expected a version like \"1.4.0\" or \"1.4.0-beta.2\""))
}

fn parse_sha256(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
}

fn valid_date(date: &str) -> bool {
    let b = date.as_bytes();
    b.len() == 10 && b[4] == b'-' && b[7] == b'-' && b.iter().enumerate().all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

/// Parse a manifest without checking its signature. Use `open_release`; this exists for tests and release tooling.
pub fn parse_manifest(text: &str) -> Result<Release, toml::Error> {
    let doc = toml::parse(text, MAX_MANIFEST_BYTES)?;
    doc.check_sections(&["release"], &["artifact."])?;
    let release = doc.require("release")?;
    release.check_keys("release", &["product", "version", "channel", "published", "min-client"])?;
    let (product, product_line) = release.req_str("release", "product")?;
    if !toml::valid_key(product) {
        return Err(bad(product_line, "product", "a-z, 0-9 and -"));
    }
    let version = version_field(release, "release", "version")?;
    let channel = match release.req_str("release", "channel")? {
        ("stable", _) => Channel::Stable,
        ("beta", _) => Channel::Beta,
        (_, line) => return Err(bad(line, "channel", "\"stable\" or \"beta\"")),
    };
    let (published, published_line) = release.req_str("release", "published")?;
    if !valid_date(published) {
        return Err(bad(published_line, "published", "expected a date like \"2026-11-14\""));
    }
    let min_client = version_field(release, "release", "min-client")?;
    if min_client > version {
        let line = release.entries.get("min-client").map_or(release.line, |e| e.line);
        return Err(bad(line, "min-client", "cannot be newer than the release itself"));
    }

    let mut artifacts = Vec::new();
    for (section_name, section) in doc.sections.iter().filter(|(n, _)| n.starts_with("artifact.")) {
        let name = section_name.trim_start_matches("artifact.").to_string();
        section.check_keys(section_name, &["kind", "platform", "file", "size", "sha256"])?;
        let (kind, platforms) = match section.req_str(section_name, "kind")? {
            ("server", _) => (Kind::Server, SERVER_PLATFORMS),
            ("desktop", _) => (Kind::Desktop, DESKTOP_PLATFORMS),
            ("android", _) => (Kind::Android, ANDROID_PLATFORMS),
            (_, line) => return Err(bad(line, "kind", "\"server\", \"desktop\" or \"android\"")),
        };
        let (platform, platform_line) = section.req_str(section_name, "platform")?;
        if !platforms.contains(&platform) {
            return Err(bad(platform_line, "platform", "not a platform this kind is built for"));
        }
        let (file, file_line) = section.req_str(section_name, "file")?;
        if !valid_file_name(file) {
            return Err(bad(file_line, "file", "a plain file name: letters, digits, '.', '-' and '_'"));
        }
        let (size, size_line) = section.req_int(section_name, "size")?;
        let size = u64::try_from(size).ok().filter(|s| *s > 0).ok_or_else(|| bad(size_line, "size", "must be more than 0"))?;
        let (hash, hash_line) = section.req_str(section_name, "sha256")?;
        let sha256 = parse_sha256(hash).ok_or_else(|| bad(hash_line, "sha256", "64 hex characters"))?;
        if artifacts.iter().any(|a: &Artifact| a.kind == kind && a.platform == platform) {
            return Err(bad(section.line, "platform", "a release has one artifact per kind and platform"));
        }
        artifacts.push(Artifact { name, kind, platform: platform.to_string(), file: file.to_string(), size, sha256 });
    }

    Ok(Release { product: product.to_string(), version, channel, published: published.to_string(), min_client, artifacts })
}

/// Check the signature over the exact manifest bytes, then parse. Nothing in an unsigned manifest is ever read.
pub fn open_release(manifest: &[u8], signature: &[u8], check: &dyn SignatureCheck) -> Result<Release, ReleaseError> {
    if !check.verify(manifest, signature) {
        return Err(ReleaseError::BadSignature);
    }
    let text = std::str::from_utf8(manifest).map_err(|_| ReleaseError::NotUtf8)?;
    parse_manifest(text).map_err(ReleaseError::Manifest)
}

/// Checks a download as it arrives, so the whole file never has to sit in memory.
pub struct ArtifactVerifier {
    expected_size: u64,
    expected_hash: [u8; 32],
    seen: u64,
    hasher: Sha256,
}

impl ArtifactVerifier {
    pub fn new(artifact: &Artifact) -> Self {
        ArtifactVerifier { expected_size: artifact.size, expected_hash: artifact.sha256, seen: 0, hasher: Sha256::new() }
    }

    /// Feed the next chunk. Fails as soon as the download is longer than the manifest says.
    pub fn update(&mut self, chunk: &[u8]) -> Result<(), ReleaseError> {
        self.seen = self.seen.saturating_add(chunk.len() as u64);
        if self.seen > self.expected_size {
            return Err(ReleaseError::SizeMismatch { expected: self.expected_size, actual: self.seen });
        }
        self.hasher.update(chunk);
        Ok(())
    }

    pub fn finish(self) -> Result<(), ReleaseError> {
        if self.seen != self.expected_size {
            return Err(ReleaseError::SizeMismatch { expected: self.expected_size, actual: self.seen });
        }
        let digest = self.hasher.finalize();
        if digest.as_slice() == self.expected_hash.as_slice() { Ok(()) } else { Err(ReleaseError::HashMismatch) }
    }
}

/// Verify a whole artifact held in memory.
pub fn verify_artifact(artifact: &Artifact, bytes: &[u8]) -> Result<(), ReleaseError> {
    let mut verifier = ArtifactVerifier::new(artifact);
    verifier.update(bytes)?;
    verifier.finish()
}

/// Hours of the day, in UTC, when the server may install automatically. `start == end` means all day; a window
/// may run past midnight (`22` to `4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub start_hour: u8,
    pub end_hour: u8,
}

impl Window {
    pub fn contains(&self, hour: u8) -> bool {
        let (s, e, h) = (self.start_hour % 24, self.end_hour % 24, hour % 24);
        match s.cmp(&e) {
            Ordering::Equal => true,
            Ordering::Less => s <= h && h < e,
            Ordering::Greater => h >= s || h < e,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateMode {
    /// Install on its own, inside the window when one is set.
    Automatic { window: Option<Window> },
    /// Install only a version an administrator approved.
    Approval,
    /// Stay on (or move to) exactly this version.
    Pinned(Version),
}

/// The administrator's update settings for the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerPolicy {
    pub product: String,
    pub channel: Channel,
    pub mode: UpdateMode,
    pub paused: bool,
    /// Versions an administrator has held back.
    pub held_back: Vec<Version>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerDecision {
    UpToDate,
    Install,
    WaitForWindow,
    WaitForApproval,
    Paused,
    HeldBack,
    /// Pinned to another version.
    Pinned,
}

/// Whether the server should install `release` now.
pub fn decide_server(
    running: &Version,
    release: &Release,
    policy: &ServerPolicy,
    hour_utc: u8,
    approved: Option<&Version>,
) -> Result<ServerDecision, ReleaseError> {
    if release.product != policy.product {
        return Err(ReleaseError::WrongProduct { expected: policy.product.clone(), found: release.product.clone() });
    }
    if !policy.channel.accepts(release.channel) {
        return Err(ReleaseError::WrongChannel);
    }
    match release.version.cmp(running) {
        Ordering::Less => return Err(ReleaseError::Downgrade { running: running.clone(), release: release.version.clone() }),
        Ordering::Equal => return Ok(ServerDecision::UpToDate),
        Ordering::Greater => {}
    }
    if policy.paused {
        return Ok(ServerDecision::Paused);
    }
    if policy.held_back.contains(&release.version) {
        return Ok(ServerDecision::HeldBack);
    }
    Ok(match &policy.mode {
        UpdateMode::Pinned(v) if *v == release.version => ServerDecision::Install,
        UpdateMode::Pinned(_) => ServerDecision::Pinned,
        UpdateMode::Approval if approved == Some(&release.version) => ServerDecision::Install,
        UpdateMode::Approval => ServerDecision::WaitForApproval,
        UpdateMode::Automatic { window: Some(w) } if !w.contains(hour_utc) => ServerDecision::WaitForWindow,
        UpdateMode::Automatic { .. } => ServerDecision::Install,
    })
}

/// Where a server self-update stands. The previous version is kept until the new one passes its health check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallState {
    Idle,
    /// Downloaded, verified and in place beside the running version.
    Staged {
        from: Version,
        to: Version,
    },
    /// Restarted on the new version; waiting for the health check.
    AwaitingHealth {
        from: Version,
        to: Version,
    },
    Committed {
        version: Version,
    },
    /// The new version failed; the previous one runs again.
    RolledBack {
        failed: Version,
        restored: Version,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallEvent {
    Staged {
        from: Version,
        to: Version,
    },
    Restarted,
    HealthOk,
    HealthFailed(String),
    /// No passing health check before the deadline.
    HealthTimeout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidTransition {
    pub state: InstallState,
    pub event: InstallEvent,
}

impl fmt::Display for InvalidTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} cannot follow {:?}", self.event, self.state)
    }
}

impl std::error::Error for InvalidTransition {}

/// Advance the install state machine. Any event that does not fit the current state is refused unchanged.
pub fn step(state: InstallState, event: InstallEvent) -> Result<InstallState, Box<InvalidTransition>> {
    match (state, event) {
        (InstallState::Idle | InstallState::Committed { .. } | InstallState::RolledBack { .. }, InstallEvent::Staged { from, to }) if to > from => {
            Ok(InstallState::Staged { from, to })
        }
        (InstallState::Staged { from, to }, InstallEvent::Restarted) => Ok(InstallState::AwaitingHealth { from, to }),
        (InstallState::AwaitingHealth { to, .. }, InstallEvent::HealthOk) => Ok(InstallState::Committed { version: to }),
        (InstallState::AwaitingHealth { from, to }, InstallEvent::HealthFailed(reason)) => {
            Ok(InstallState::RolledBack { failed: to, restored: from, reason })
        }
        (InstallState::AwaitingHealth { from, to }, InstallEvent::HealthTimeout) => {
            Ok(InstallState::RolledBack { failed: to, restored: from, reason: "no passing health check before the deadline".into() })
        }
        (state, event) => Err(Box::new(InvalidTransition { state, event })),
    }
}

/// A client rollout, set by an administrator.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rollout {
    /// Share of devices offered the update, 0 to 100.
    pub percent: u8,
    /// Devices offered the update first, whatever the percentage.
    pub pilot_devices: Vec<String>,
    pub paused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientOffer {
    UpToDate,
    /// `required` when the client is older than the oldest version the server accepts.
    Available {
        version: Version,
        required: bool,
    },
    /// Not this device's turn in the rollout yet.
    NotYet,
    /// The client must update but the release has no build for its platform.
    NoBuild {
        required: bool,
    },
}

/// A device's stable rollout bucket for a release, 0 to 99. The same device and release always give the same bucket.
pub fn rollout_bucket(version: &Version, device_id: &str) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(version.to_string().as_bytes());
    hasher.update(b"\n");
    hasher.update(device_id.as_bytes());
    let digest = hasher.finalize();
    let value = u16::from_be_bytes([digest[0], digest[1]]);
    u8::try_from(value % 100).unwrap_or(0)
}

/// What the server tells a connecting client.
pub fn offer_client(release: &Release, client: &Version, kind: Kind, platform: &str, device_id: &str, rollout: &Rollout) -> ClientOffer {
    if *client >= release.version {
        return ClientOffer::UpToDate;
    }
    let required = *client < release.min_client;
    if release.artifact(kind, platform).is_none() {
        return ClientOffer::NoBuild { required };
    }
    let available = ClientOffer::Available { version: release.version.clone(), required };
    if required {
        return available;
    }
    if rollout.paused {
        return ClientOffer::NotYet;
    }
    if rollout.pilot_devices.iter().any(|d| d == device_id) || rollout_bucket(&release.version, device_id) < rollout.percent.min(100) {
        available
    } else {
        ClientOffer::NotYet
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebClientStatus {
    Current,
    /// Offer a reload; the person chooses when.
    ReloadOffered,
    /// The page's version is no longer accepted: reload now.
    ReloadRequired,
}

/// What an open web page should do, given the version it was loaded at and the server's current release.
pub fn web_client_status(page: &Version, release: &Release) -> WebClientStatus {
    if *page >= release.version {
        WebClientStatus::Current
    } else if *page < release.min_client {
        WebClientStatus::ReloadRequired
    } else {
        WebClientStatus::ReloadOffered
    }
}
