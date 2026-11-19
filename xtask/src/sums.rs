//! `SHA256SUMS.txt` in the format `sha256sum` writes and `sha256sum -c` checks: one line per asset, the lowercase
//! hex digest, two spaces, the file name, sorted by name.

use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

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
