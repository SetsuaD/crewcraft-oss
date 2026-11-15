//! The account store's own journal file: the same frame format as `journal` (T140), `u32 len (big-endian) | len
//! bytes | SHA-256 of those bytes`, but with strict recovery, because a dropped record here could bring back a
//! consumed invitation, an old TOTP counter or a revoked device. Issue #35.
//!
//! Owns: reading every frame and refusing the whole file unless each complete frame is valid; the only damage it
//! recovers is an INCOMPLETE FINAL frame (a write torn by a crash), and it cuts that tail off only when asked
//! (`recover_tail`), after the caller has checked the key and replayed the records, so an open that fails changes
//! nothing on disk. Appending, and saying whether a failed append is known to have left the file exactly as before
//! (`AppendError::NotWritten`, safe to retry) or may not have (`Ambiguous`, the caller must stop writing).
//! Called by: `account_store`.
//!
//! Refused at open (`Corrupt`): a complete frame whose hash does not match, a length over `MAX_RECORD`, wherever they
//! are. Honest limit: a filesystem that leaves a zero-filled or garbage tail after a crash makes the last frame look
//! complete and invalid; the store then refuses to start rather than guess, and an operator restores or truncates.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

pub use crate::journal::MAX_RECORD;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// There is no file: the store was never created (see `AccountStore::create`).
    Missing,
    /// `create` found a file already there.
    Exists,
    /// Frame `frame` (0-based) is complete but invalid: refuse to start.
    Corrupt {
        frame: usize,
    },
    Io(std::io::ErrorKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendError {
    /// Larger than `MAX_RECORD`; nothing was written.
    TooLarge,
    /// The write or sync failed, and the file was cut back and synced to its exact size before the call: nothing of the
    /// record remains, so the change did not happen and may be retried.
    NotWritten(std::io::ErrorKind),
    /// The write or sync failed and the cut-back could not be confirmed: the file may or may not hold the record.
    Ambiguous(std::io::ErrorKind),
}

pub struct AccountJournal {
    file: File,
    size: u64,
    /// Bytes after the last complete frame (an incomplete final frame), not yet cut off.
    torn: u64,
}

impl AccountJournal {
    /// Create a NEW, empty journal file. `Exists` if there is one already.
    pub fn create(path: &Path) -> Result<Self, OpenError> {
        let file = match OpenOptions::new().read(true).write(true).create_new(true).open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(OpenError::Exists),
            Err(e) => return Err(OpenError::Io(e.kind())),
        };
        file.sync_all().map_err(|e| OpenError::Io(e.kind()))?;
        Ok(AccountJournal { file, size: 0, torn: 0 })
    }

    /// Open an existing journal and read every record, writing nothing. `Missing` if there is no file.
    pub fn open(path: &Path) -> Result<(Self, Vec<Vec<u8>>), OpenError> {
        let mut file = match OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(OpenError::Missing),
            Err(e) => return Err(OpenError::Io(e.kind())),
        };
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(|e| OpenError::Io(e.kind()))?;
        let (records, valid) = parse(&buf)?;
        Ok((AccountJournal { file, size: valid as u64, torn: (buf.len() - valid) as u64 }, records))
    }

    /// Bytes of an incomplete final frame found at open and not yet cut off.
    pub fn torn_bytes(&self) -> u64 {
        self.torn
    }

    /// Cut off the incomplete final frame found at open (the one disk change recovery makes). Call it only after the
    /// records were accepted. Needed before the first append.
    pub fn recover_tail(&mut self) -> Result<(), OpenError> {
        if self.torn > 0 {
            self.file.set_len(self.size).and_then(|()| self.file.sync_all()).map_err(|e| OpenError::Io(e.kind()))?;
            self.torn = 0;
        }
        Ok(())
    }

    /// Append one record and sync it before returning.
    pub fn append(&mut self, record: &[u8]) -> Result<(), AppendError> {
        if record.len() > MAX_RECORD {
            return Err(AppendError::TooLarge);
        }
        if self.torn > 0 {
            // Appending after an unrecovered torn tail would bury it inside the file, where the next open refuses it.
            return Err(AppendError::NotWritten(std::io::ErrorKind::InvalidInput));
        }
        let mut frame = Vec::with_capacity(4 + record.len() + 32);
        frame.extend_from_slice(&(record.len() as u32).to_be_bytes());
        frame.extend_from_slice(record);
        frame.extend_from_slice(&Sha256::digest(record));
        let written = self.file.seek(SeekFrom::Start(self.size)).and_then(|_| self.file.write_all(&frame)).and_then(|()| self.file.sync_data());
        match written {
            Ok(()) => {
                self.size += frame.len() as u64;
                Ok(())
            }
            Err(e) => {
                let restored = self.file.set_len(self.size).and_then(|()| self.file.sync_all()).and_then(|()| self.file.metadata());
                match restored {
                    Ok(meta) if meta.len() == self.size => Err(AppendError::NotWritten(e.kind())),
                    _ => Err(AppendError::Ambiguous(e.kind())),
                }
            }
        }
    }
}

/// Every record, and the byte length of the complete valid frames. Only an incomplete final frame may follow them.
fn parse(buf: &[u8]) -> Result<(Vec<Vec<u8>>, usize), OpenError> {
    let mut records = Vec::new();
    let mut offset = 0usize;
    while offset < buf.len() {
        let frame = records.len();
        let Some(len_bytes) = buf.get(offset..offset + 4) else {
            break; // fewer than 4 bytes left: an incomplete final frame
        };
        let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        if len > MAX_RECORD {
            return Err(OpenError::Corrupt { frame });
        }
        let end = offset + 4 + len + 32;
        if end > buf.len() {
            break; // the frame runs past the end of the file: an incomplete final frame
        }
        let data = &buf[offset + 4..offset + 4 + len];
        if Sha256::digest(data).as_slice() != &buf[offset + 4 + len..end] {
            return Err(OpenError::Corrupt { frame });
        }
        records.push(data.to_vec());
        offset = end;
    }
    Ok((records, offset))
}
