//! Archive writers: `.tar.gz` (ustar), `.zip` (deflate) and `ar` (the container of a `.deb`).
//!
//! Every writer is reproducible: entries are sorted, every parent folder is listed before its contents, all times
//! are one fixed time (the release's source date), owners are root, and nothing about the machine that ran the
//! build (user, umask, file times) reaches the archive.

use std::collections::BTreeSet;
use std::io::Write;

use flate2::write::DeflateEncoder;
use flate2::{Compression, Crc, GzBuilder};

use crate::{Error, Result};

/// A regular file to put in an archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeFile {
    /// The path inside the archive, `/`-separated, relative, without `.` or `..` parts.
    pub path: String,
    /// Unix permission bits, `0o755` for programs and `0o644` for everything else.
    pub mode: u32,
    pub data: Vec<u8>,
}

impl TreeFile {
    pub fn new(path: impl Into<String>, mode: u32, data: impl Into<Vec<u8>>) -> Self {
        Self { path: path.into(), mode, data: data.into() }
    }
}

/// One archive entry after sorting: a folder (path ends in `/`) or a file.
enum Item<'a> {
    Dir(String),
    File(&'a TreeFile),
}

fn check_path(path: &str) -> Result<()> {
    let bad = path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.split('/').any(|part| part.is_empty() || part == "." || part == "..")
        || !path.bytes().all(|b| b.is_ascii_graphic());
    if bad { Err(Error::new(format!("archive path {path:?} must be relative, plain ASCII and without empty, . or .. parts"))) } else { Ok(()) }
}

/// Sorts the files and adds every parent folder, so that a folder always comes before what it holds.
fn items(files: &[TreeFile]) -> Result<Vec<Item<'_>>> {
    let mut dirs = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for file in files {
        check_path(&file.path)?;
        if !seen.insert(file.path.as_str()) {
            return Err(Error::new(format!("archive path {:?} is listed twice", file.path)));
        }
        let mut end = 0;
        while let Some(slash) = file.path[end..].find('/') {
            end += slash + 1;
            dirs.insert(file.path[..end].to_string());
        }
    }
    if let Some(clash) = files.iter().find(|file| dirs.contains(&format!("{}/", file.path))) {
        return Err(Error::new(format!("archive path {:?} is both a file and a folder", clash.path)));
    }
    let mut all: Vec<(String, Item<'_>)> = dirs.into_iter().map(|dir| (dir.clone(), Item::Dir(dir))).collect();
    all.extend(files.iter().map(|file| (file.path.clone(), Item::File(file))));
    all.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(all.into_iter().map(|(_, item)| item).collect())
}

fn octal(field: &mut [u8], value: u64) -> Result<()> {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    if text.len() > digits {
        return Err(Error::new(format!("{value} does not fit a {}-byte tar field", field.len())));
    }
    field[..digits].copy_from_slice(text.as_bytes());
    field[digits] = 0;
    Ok(())
}

fn tar_header(name: &str, mode: u32, size: u64, mtime: u64, directory: bool) -> Result<[u8; 512]> {
    let mut header = [0u8; 512];
    if name.len() > 100 {
        return Err(Error::new(format!("tar path {name:?} is longer than 100 bytes")));
    }
    header[..name.len()].copy_from_slice(name.as_bytes());
    octal(&mut header[100..108], u64::from(mode))?;
    octal(&mut header[108..116], 0)?;
    octal(&mut header[116..124], 0)?;
    octal(&mut header[124..136], size)?;
    octal(&mut header[136..148], mtime)?;
    header[156] = if directory { b'5' } else { b'0' };
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[265..269].copy_from_slice(b"root");
    header[297..301].copy_from_slice(b"root");
    octal(&mut header[329..337], 0)?;
    octal(&mut header[337..345], 0)?;
    // The checksum is computed with its own field read as eight spaces, then written as six octal digits, NUL, space.
    header[148..156].copy_from_slice(b"        ");
    let sum: u64 = header.iter().map(|&b| u64::from(b)).sum();
    let text = format!("{sum:06o}\0 ");
    header[148..156].copy_from_slice(text.as_bytes());
    Ok(header)
}

/// A ustar archive of `files` (uncompressed). Each path gets `prefix` in front: `./` for a Debian package, or the
/// archive's top folder such as `crewcraft-server-0.1.0-linux-x86_64/`. With the `./` prefix the root `./` itself
/// is listed first, as dpkg does.
pub fn tar(files: &[TreeFile], prefix: &str, mtime: u64) -> Result<Vec<u8>> {
    if !(prefix.is_empty() || prefix.ends_with('/')) {
        return Err(Error::new(format!("tar prefix {prefix:?} must be empty or end in /")));
    }
    let mut out = Vec::new();
    if prefix == "./" {
        out.extend_from_slice(&tar_header("./", 0o755, 0, mtime, true)?);
    } else if !prefix.is_empty() {
        check_path(prefix.trim_end_matches('/'))?;
        out.extend_from_slice(&tar_header(prefix, 0o755, 0, mtime, true)?);
    }
    for item in items(files)? {
        match item {
            Item::Dir(dir) => out.extend_from_slice(&tar_header(&format!("{prefix}{dir}"), 0o755, 0, mtime, true)?),
            Item::File(file) => {
                out.extend_from_slice(&tar_header(&format!("{prefix}{}", file.path), file.mode, file.data.len() as u64, mtime, false)?);
                out.extend_from_slice(&file.data);
                out.resize(out.len().div_ceil(512) * 512, 0);
            }
        }
    }
    out.resize(out.len() + 1024, 0);
    Ok(out)
}

/// gzip with maximum compression, no file name and a zero time in the gzip header, so equal input gives equal output.
pub fn gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzBuilder::new().mtime(0).write(Vec::new(), Compression::best());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// `tar` then `gzip`.
pub fn tar_gz(files: &[TreeFile], prefix: &str, mtime: u64) -> Result<Vec<u8>> {
    gzip(&tar(files, prefix, mtime)?)
}

/// MS-DOS date and time fields for a Unix time (UTC), clamped to 1980, the earliest a zip can hold.
pub fn dos_date_time(unix: u64) -> (u16, u16) {
    let days = unix / 86_400;
    let seconds = unix % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    if year < 1980 {
        return ((1 << 5) | 1, 0);
    }
    let year = year.min(2107);
    let date = (((year - 1980) as u16) << 9) | ((month as u16) << 5) | day as u16;
    let time = (((seconds / 3600) as u16) << 11) | ((((seconds / 60) % 60) as u16) << 5) | ((seconds % 60) / 2) as u16;
    (date, time)
}

fn u32_len(len: usize, what: &str) -> Result<u32> {
    u32::try_from(len).map_err(|_| Error::new(format!("{what} is too large for a zip without zip64")))
}

/// A zip archive of `files` under the folder `prefix` (which ends in `/`), deflate-compressed, with Unix permission
/// bits in the external attributes so that unzip on Linux or macOS restores them.
pub fn zip(files: &[TreeFile], prefix: &str, mtime: u64) -> Result<Vec<u8>> {
    if !prefix.ends_with('/') {
        return Err(Error::new(format!("zip prefix {prefix:?} must end in /")));
    }
    check_path(prefix.trim_end_matches('/'))?;
    let (date, time) = dos_date_time(mtime);
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut count: u16 = 0;
    let mut entries: Vec<(String, u32, Option<&[u8]>)> = vec![(prefix.to_string(), 0o40755, None)];
    for item in items(files)? {
        match item {
            Item::Dir(dir) => entries.push((format!("{prefix}{dir}"), 0o40755, None)),
            Item::File(file) => entries.push((format!("{prefix}{}", file.path), 0o100000 | file.mode, Some(&file.data))),
        }
    }
    for (name, mode, data) in entries {
        let (method, compressed, crc, size): (u16, Vec<u8>, u32, usize) = match data {
            None => (0, Vec::new(), 0, 0),
            Some(data) => {
                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
                encoder.write_all(data)?;
                let mut crc = Crc::new();
                crc.update(data);
                (8, encoder.finish()?, crc.sum(), data.len())
            }
        };
        let offset = u32_len(out.len(), "the archive")?;
        let name_len = u16::try_from(name.len()).map_err(|_| Error::new(format!("zip path {name:?} is too long")))?;
        let csize = u32_len(compressed.len(), &name)?;
        let usize_ = u32_len(size, &name)?;
        let attributes = (mode << 16) | if data.is_none() { 0x10 } else { 0 };
        let mut local = Vec::new();
        local.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        local.extend_from_slice(&20u16.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        local.extend_from_slice(&method.to_le_bytes());
        local.extend_from_slice(&time.to_le_bytes());
        local.extend_from_slice(&date.to_le_bytes());
        local.extend_from_slice(&crc.to_le_bytes());
        local.extend_from_slice(&csize.to_le_bytes());
        local.extend_from_slice(&usize_.to_le_bytes());
        local.extend_from_slice(&name_len.to_le_bytes());
        local.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&local);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&compressed);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        // Made by: Unix (3), spec 2.0, so the external attributes carry Unix modes.
        central.extend_from_slice(&((3u16 << 8) | 20).to_le_bytes());
        central.extend_from_slice(&local[4..30]);
        central.extend_from_slice(&0u16.to_le_bytes()); // comment length
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        central.extend_from_slice(&attributes.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
        count = count.checked_add(1).ok_or_else(|| Error::new("too many zip entries"))?;
    }
    let central_offset = u32_len(out.len(), "the archive")?;
    let central_size = u32_len(central.len(), "the zip directory")?;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&central_size.to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    Ok(out)
}

/// A Unix `ar` archive (the common format that dpkg reads) of `(name, data)` members, in the order given.
pub fn ar(members: &[(&str, &[u8])], mtime: u64) -> Result<Vec<u8>> {
    let mut out = b"!<arch>\n".to_vec();
    for (name, data) in members {
        if name.is_empty() || name.len() > 15 || !name.bytes().all(|b| b.is_ascii_graphic() && b != b'/') {
            return Err(Error::new(format!("ar member name {name:?} must be 1 to 15 plain characters")));
        }
        let header = format!("{name:<16}{mtime:<12}{:<6}{:<6}{:<8o}{:<10}`\n", 0, 0, 0o100644, data.len());
        if header.len() != 60 {
            return Err(Error::new(format!("ar member {name:?} does not fit an ar header")));
        }
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(data);
        if data.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    Ok(out)
}
