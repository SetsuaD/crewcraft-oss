//! `SHA256SUMS.txt` in the format `sha256sum` writes and `sha256sum -c` checks: one line per asset, the lowercase
//! hex digest, two spaces, the file name, sorted by name.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::names::Target;
use crate::version::Version;
use crate::{Context, Error, Result};

pub const SUMS_FILE: &str = "SHA256SUMS.txt";

/// The SHA-256 of `data` as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data).iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Formats `(file name, contents)` pairs as `SHA256SUMS.txt`. Refuses a name `sha256sum` would have to escape
/// (a backslash or a line break) or one with a path separator, since every asset sits next to the sums file.
pub fn format_sums(files: &[(String, Vec<u8>)]) -> Result<String> {
    let mut lines: Vec<(&str, String)> = Vec::with_capacity(files.len());
    for (name, data) in files {
        if name.is_empty() || name.contains(['\\', '/', '\n', '\r']) {
            return Err(Error::new(format!("asset name {name:?} cannot be listed in {SUMS_FILE}")));
        }
        lines.push((name, sha256_hex(data)));
    }
    lines.sort();
    if lines.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(Error::new(format!("an asset is listed twice in {SUMS_FILE}")));
    }
    Ok(lines.iter().map(|(name, digest)| format!("{digest}  {name}\n")).collect())
}

/// Writes `dir/SHA256SUMS.txt` over every regular file in `dir` except the sums file itself, and returns its text.
/// Subfolders and hidden files (names starting with `.`, such as a half-written asset) are not assets and are left
/// out.
pub fn write_sums(dir: &Path) -> Result<String> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir).context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().into_string().map_err(|name| Error::new(format!("asset name {name:?} is not UTF-8")))?;
        if name == SUMS_FILE || name.starts_with('.') {
            continue;
        }
        let data = fs::read(entry.path()).context(|| format!("reading {name}"))?;
        files.push((name, data));
    }
    let text = format_sums(&files)?;
    fs::write(dir.join(SUMS_FILE), &text).context(|| format!("writing {SUMS_FILE}"))?;
    Ok(text)
}

/// Checks the complete Git revision used by a package build.
pub fn validate_commit(commit: &str) -> Result<()> {
    if !lower_hex(commit, 40) {
        return Err(Error::new("the source revision must be a full 40-character lowercase Git SHA"));
    }
    Ok(())
}

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Records the exact source and the checksums of packages made together by one builder.
pub fn write_build_receipt(path: &Path, commit: &str, version: &Version, checksums: &str) -> Result<()> {
    validate_commit(commit)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path).context(|| format!("creating receipt {}", path.display()))?;
    write!(file, "source {commit}\nversion {version}\n{checksums}").context(|| format!("writing receipt {}", path.display()))?;
    Ok(())
}

/// Verifies a complete desktop and server release against the per-build receipts, then writes canonical checksums.
pub fn preflight(dir: &Path, version: &Version, commit: &str, receipts: &[PathBuf]) -> Result<String> {
    validate_commit(commit)?;
    let names: BTreeSet<_> = Target::ALL.iter().flat_map(|target| target.assets()).map(|asset| asset.file_name(version)).collect();
    let version = version.to_string();
    let mut checksums = BTreeMap::new();
    for receipt in receipts {
        let text = fs::read_to_string(receipt).context(|| format!("reading receipt {}", receipt.display()))?;
        let mut lines = text.lines();
        if lines.next().and_then(|line| line.strip_prefix("source ")) != Some(commit) {
            return Err(Error::new(format!("receipt {} has a different source revision; expected {commit}", receipt.display())));
        }
        if lines.next().and_then(|line| line.strip_prefix("version ")) != Some(version.as_str()) {
            return Err(Error::new(format!("receipt {} has a different package version; expected {version}", receipt.display())));
        }
        let before = checksums.len();
        for line in lines {
            let (digest, name) = line.split_once("  ").ok_or_else(|| Error::new(format!("invalid checksum row in receipt {}", receipt.display())))?;
            if !lower_hex(digest, 64) || !names.contains(name) {
                return Err(Error::new(format!("invalid checksum or unexpected asset {name:?} in receipt {}", receipt.display())));
            }
            if checksums.insert(name.to_owned(), digest.to_owned()).is_some() {
                return Err(Error::new(format!("asset {name} appears more than once in the receipts")));
            }
        }
        if before == checksums.len() {
            return Err(Error::new(format!("receipt {} lists no assets", receipt.display())));
        }
    }
    let missing: Vec<_> = names.iter().filter(|name| !checksums.contains_key(*name)).map(String::as_str).collect();
    if !missing.is_empty() {
        return Err(Error::new(format!("missing build receipts for {}", missing.join(", "))));
    }
    let text: String = checksums.iter().map(|(name, digest)| format!("{digest}  {name}\n")).collect();
    for entry in fs::read_dir(dir).context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().into_string().map_err(|name| Error::new(format!("asset name {name:?} is not UTF-8")))?;
        if !entry.file_type()?.is_file() {
            return Err(Error::new(format!("release entry {name:?} must be a regular file")));
        }
        if name == SUMS_FILE {
            continue;
        }
        let digest = checksums.remove(&name).ok_or_else(|| Error::new(format!("unexpected release asset {name:?}")))?;
        let data = fs::read(entry.path()).context(|| format!("reading {name}"))?;
        if sha256_hex(&data) != digest {
            return Err(Error::new(format!("checksum mismatch for {name}")));
        }
    }
    if !checksums.is_empty() {
        let missing: Vec<_> = checksums.keys().map(String::as_str).collect();
        return Err(Error::new(format!("missing release assets {}", missing.join(", "))));
    }
    let partial = dir.join(format!(".{SUMS_FILE}.partial"));
    let mut file = OpenOptions::new().create_new(true).write(true).open(&partial).context(|| format!("creating {}", partial.display()))?;
    let written = file.write_all(text.as_bytes()).and_then(|()| file.sync_all());
    drop(file);
    let published = written.and_then(|()| fs::rename(&partial, dir.join(SUMS_FILE)));
    if published.is_err() {
        let _ = fs::remove_file(&partial);
    }
    published.context(|| format!("writing {SUMS_FILE}"))?;
    Ok(text)
}
