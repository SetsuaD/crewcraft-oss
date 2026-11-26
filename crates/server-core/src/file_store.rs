//! The bytes of uploaded files, addressed by their content (docs/FILES.md, task T330a).
//!
//! Owns: the `files/` folder in the data directory. Finished files are named by the lowercase hex SHA-256 of their
//! bytes, under a two-character fan-out (`files/ab/abcd...`), so identical content is stored once. An upload in
//! progress is a file under `files/partial/`, named by its random id; it is never read back as a finished file.
//! Finishing checks the declared length and hash, syncs the bytes to disk and only then renames them into place. The
//! file *records* (who uploaded what, where) are the room journal's (`op::Op::FileStored`, `durable`); this module
//! never decides who may read a file. Called by: the server's upload and download handling. Calls: the standard
//! library and `sha2`.
//!
//! Also here: `image_size`, which reads an image's width and height from its first bytes (PNG, GIF, JPEG, WebP). No
//! type the client claims is trusted.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The folder for uploads in progress, inside the store's root.
const PARTIAL: &str = "partial";
/// How many bytes of a file `image_size` needs at most.
pub const IMAGE_HEADER_BYTES: usize = 64 * 1024;

/// Why a partial upload could not be finished. The partial file is removed in every case.
#[derive(Debug)]
pub enum FinishError {
    /// The bytes written are not the declared length.
    WrongSize {
        declared: u64,
        written: u64,
    },
    /// The bytes do not hash to the declared SHA-256.
    WrongHash,
    Io(io::Error),
}

impl From<io::Error> for FinishError {
    fn from(error: io::Error) -> Self {
        FinishError::Io(error)
    }
}

/// The content store at one root folder.
#[derive(Debug)]
pub struct FileStore {
    root: PathBuf,
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl FileStore {
    /// Open (creating when missing) the store at `root`, and remove every upload left in progress by an earlier run:
    /// a partial file is never finished across a restart.
    pub fn open(root: &Path) -> io::Result<Self> {
        create_private_dir(root)?;
        let partial = root.join(PARTIAL);
        create_private_dir(&partial)?;
        for entry in fs::read_dir(&partial)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(Self { root: root.to_path_buf() })
    }

    fn partial_path(&self, upload: &[u8; 16]) -> PathBuf {
        self.root.join(PARTIAL).join(hex(upload))
    }

    /// Where the bytes with this SHA-256 are kept.
    fn content_path(&self, sha256: &[u8; 32]) -> PathBuf {
        let name = hex(sha256);
        self.root.join(&name[..2]).join(name)
    }

    /// Start upload `upload` (a random id): an empty partial file. `AlreadyExists` if that id is in progress.
    pub fn start(&self, upload: &[u8; 16]) -> io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        private(&mut options);
        options.open(self.partial_path(upload)).map(drop)
    }

    /// Write `bytes` at `offset` of upload `upload`'s partial file, as the chunk arrived (in order or not).
    pub fn write(&self, upload: &[u8; 16], offset: u64, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new().write(true).open(self.partial_path(upload))?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)
    }

    /// Finish upload `upload`: its bytes must be exactly `size` long and hash to `sha256`. They are synced to disk and
    /// renamed to their content name, or, when the store already holds those bytes, the partial file is removed. The
    /// partial file is gone afterwards whatever happens. The caller writes the file record only after `Ok`.
    pub fn finish(&self, upload: &[u8; 16], size: u64, sha256: &[u8; 32]) -> Result<(), FinishError> {
        let partial = self.partial_path(upload);
        let result = self.finish_partial(&partial, size, sha256);
        if partial.exists() {
            let _ = fs::remove_file(&partial);
        }
        result
    }

    fn finish_partial(&self, partial: &Path, size: u64, sha256: &[u8; 32]) -> Result<(), FinishError> {
        let mut file = File::open(partial)?;
        let written = file.metadata()?.len();
        if written != size {
            return Err(FinishError::WrongSize { declared: size, written });
        }
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        if hasher.finalize().as_slice() != sha256 {
            return Err(FinishError::WrongHash);
        }
        File::open(partial)?.sync_all()?;
        let target = self.content_path(sha256);
        if target.exists() {
            return Ok(());
        }
        if let Some(fan) = target.parent() {
            create_private_dir(fan)?;
        }
        fs::rename(partial, &target)?;
        if let Some(fan) = target.parent() {
            sync_dir(fan);
        }
        Ok(())
    }

    /// Give up upload `upload`: its partial file is removed. Nothing happens when there is none.
    pub fn discard(&self, upload: &[u8; 16]) {
        let _ = fs::remove_file(self.partial_path(upload));
    }

    /// Whether the store holds the bytes with this SHA-256.
    pub fn contains(&self, sha256: &[u8; 32]) -> bool {
        self.content_path(sha256).is_file()
    }

    /// Up to `length` bytes of the content `sha256` from `offset` (fewer at the end; none past it).
    pub fn read(&self, sha256: &[u8; 32], offset: u64, length: usize) -> io::Result<Vec<u8>> {
        let mut file = File::open(self.content_path(sha256))?;
        file.seek(SeekFrom::Start(offset))?;
        let mut out = Vec::with_capacity(length.min(1 << 20));
        file.take(length as u64).read_to_end(&mut out)?;
        Ok(out)
    }

    /// The width and height of the content `sha256` if it is a PNG, GIF, JPEG or WebP image (`image_size`).
    pub fn image_size(&self, sha256: &[u8; 32]) -> Option<(u32, u32)> {
        image_size(&self.read(sha256, 0, IMAGE_HEADER_BYTES).ok()?)
    }

    /// Remove every finished file whose hash is not in `keep` (the hashes the journal's records refer to), and return
    /// how many were removed. A name that is not a content name is left alone.
    pub fn sweep(&self, keep: &HashSet<[u8; 32]>) -> io::Result<usize> {
        let keep: HashSet<String> = keep.iter().map(|hash| hex(hash)).collect();
        let mut removed = 0;
        for fan in fs::read_dir(&self.root)? {
            let fan = fan?;
            let fan_name = fan.file_name();
            let Some(fan_name) = fan_name.to_str() else { continue };
            if fan_name == PARTIAL || fan_name.len() != 2 || !fan.file_type()?.is_dir() {
                continue;
            }
            for entry in fs::read_dir(fan.path())? {
                let entry = entry?;
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                let content_name = name.len() == 64 && name.starts_with(fan_name) && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
                if content_name && !keep.contains(name) {
                    fs::remove_file(entry.path())?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
}

/// An image's width and height from its first bytes: PNG (IHDR), GIF (logical screen), JPEG (the first start-of-frame
/// marker), or WebP (VP8, VP8L or VP8X). `None` for anything else, or a header too short or with a zero size.
pub fn image_size(header: &[u8]) -> Option<(u32, u32)> {
    let size = png(header).or_else(|| gif(header)).or_else(|| jpeg(header)).or_else(|| webp(header))?;
    (size.0 > 0 && size.1 > 0).then_some(size)
}

fn be16(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?])))
}

fn le16(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from(u16::from_le_bytes([*b.get(at)?, *b.get(at + 1)?])))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([*b.get(at)?, *b.get(at + 1)?, *b.get(at + 2)?, *b.get(at + 3)?]))
}

fn le24(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([*b.get(at)?, *b.get(at + 1)?, *b.get(at + 2)?, 0]))
}

fn png(b: &[u8]) -> Option<(u32, u32)> {
    (b.starts_with(b"\x89PNG\r\n\x1a\n") && b.get(12..16) == Some(b"IHDR")).then_some(())?;
    Some((be32(b, 16)?, be32(b, 20)?))
}

fn gif(b: &[u8]) -> Option<(u32, u32)> {
    (b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a")).then_some(())?;
    Some((le16(b, 6)?, le16(b, 8)?))
}

fn jpeg(b: &[u8]) -> Option<(u32, u32)> {
    b.starts_with(&[0xFF, 0xD8]).then_some(())?;
    let mut at = 2;
    loop {
        if *b.get(at)? != 0xFF {
            return None;
        }
        let marker = *b.get(at + 1)?;
        if marker == 0xFF {
            at += 1;
            continue;
        }
        // Start-of-frame markers carry the size; DHT (C4), JPG (C8) and DAC (CC) share the range but do not.
        if (0xC0..=0xCF).contains(&marker) && !matches!(marker, 0xC4 | 0xC8 | 0xCC) {
            return Some((be16(b, at + 7)?, be16(b, at + 5)?));
        }
        let length = usize::try_from(be16(b, at + 2)?).ok()?;
        if length < 2 {
            return None;
        }
        at += 2 + length;
    }
}

fn webp(b: &[u8]) -> Option<(u32, u32)> {
    (b.starts_with(b"RIFF") && b.get(8..12) == Some(b"WEBP")).then_some(())?;
    match b.get(12..16)? {
        b"VP8X" => Some((le24(b, 24)? + 1, le24(b, 27)? + 1)),
        b"VP8L" => {
            (*b.get(20)? == 0x2F).then_some(())?;
            let bits = u32::from_le_bytes([*b.get(21)?, *b.get(22)?, *b.get(23)?, *b.get(24)?]);
            Some(((bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1))
        }
        b"VP8 " => {
            (b.get(23..26) == Some(&[0x9D, 0x01, 0x2A])).then_some(())?;
            Some((le16(b, 26)? & 0x3FFF, le16(b, 28)? & 0x3FFF))
        }
        _ => None,
    }
}

fn create_private_dir(dir: &Path) -> io::Result<()> {
    match fs::create_dir(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => return Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(dir)?;
        }
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn private(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn private(_: &mut OpenOptions) {}

/// Make a rename in `dir` durable (Unix); best effort elsewhere.
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}
