//! An append-only file of records that survives a crash: after a power cut a reader sees each record whole or not at
//! all. The building block under the server's durable state. Task T140.
//!
//! On disk the file is a sequence of records, each `u32 len (big-endian) | len bytes | the 32-byte SHA-256 of those
//! bytes`. A record is valid when its whole frame is present, `len` is at most `MAX_RECORD`, and the hash matches.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

/// Largest record, in bytes.
pub const MAX_RECORD: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalError {
    /// The file could not be opened, read, written or synced.
    Io(std::io::ErrorKind),
    /// A record longer than `MAX_RECORD` was refused; nothing was written.
    TooLarge,
}

pub struct Journal {
    file: File,
    len: usize,
    size: u64,
}

impl Journal {
    /// Open the journal at `path`, creating an empty file if there is none. Every valid record is read from the start,
    /// in order. At the first record that is incomplete, longer than `MAX_RECORD`, or whose hash does not match (a write
    /// torn by a crash), reading stops and the file is truncated to the end of the last valid record, so later appends
    /// follow it. Returns the journal and the records read.
    pub fn open(path: &Path) -> Result<(Journal, Vec<Vec<u8>>), JournalError> {
        let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path).map_err(|e| JournalError::Io(e.kind()))?;

        let mut buf = Vec::new();
        file.read_to_end(&mut buf).map_err(|e| JournalError::Io(e.kind()))?;

        let mut records: Vec<Vec<u8>> = Vec::new();
        let mut offset: usize = 0;

        while offset < buf.len() {
            // Need at least 4 bytes for the length field.
            if offset + 4 > buf.len() {
                break;
            }
            let len = u32::from_be_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]) as usize;

            // Reject records longer than MAX_RECORD.
            if len > MAX_RECORD {
                break;
            }

            // Compute the end of the full frame (len + data + hash).
            let record_end = offset + 4 + len + 32;

            // The entire frame must be present in the buffer.
            if record_end > buf.len() {
                break;
            }

            let data = &buf[offset + 4..offset + 4 + len];
            let hash = &buf[offset + 4 + len..offset + 4 + len + 32];

            // Verify the SHA-256 hash.
            let mut hasher = Sha256::new();
            hasher.update(data);
            if hasher.finalize().as_slice() != hash {
                break;
            }

            records.push(data.to_vec());
            offset = record_end;
        }

        // Truncate the file to the end of the last valid record.
        if buf.len() > offset {
            file.set_len(offset as u64).map_err(|e| JournalError::Io(e.kind()))?;
            file.sync_data().map_err(|e| JournalError::Io(e.kind()))?;
        }

        // Position the file handle at the end so that subsequent appends are sequential.
        file.seek(SeekFrom::End(0)).map_err(|e| JournalError::Io(e.kind()))?;

        let size: u64 = records.iter().map(|r| (4 + r.len() + 32) as u64).sum();
        let len = records.len();

        Ok((Journal { file, len, size }, records))
    }

    /// Append one record and sync it to disk (`File::sync_data`) before returning. An empty record is allowed.
    /// `TooLarge` above `MAX_RECORD`, and nothing is written. A failed write or sync is `Io`, and the file is cut back to
    /// its size before the call, so the journal stays appendable.
    pub fn append(&mut self, record: &[u8]) -> Result<(), JournalError> {
        if record.len() > MAX_RECORD {
            return Err(JournalError::TooLarge);
        }

        let mut hasher = Sha256::new();
        hasher.update(record);
        let mut frame = Vec::with_capacity(4 + record.len() + 32);
        frame.extend_from_slice(&(record.len() as u32).to_be_bytes());
        frame.extend_from_slice(record);
        frame.extend_from_slice(&hasher.finalize());

        if let Err(e) = self.file.write_all(&frame).and_then(|()| self.file.sync_data()) {
            // Cut off whatever part of the frame reached the file, so the next append does not follow a torn record
            // (which the next open would truncate, taking every later record with it).
            let _ = self.file.set_len(self.size);
            let _ = self.file.seek(SeekFrom::End(0));
            return Err(JournalError::Io(e.kind()));
        }

        self.len += 1;
        self.size += (4 + record.len() + 32) as u64;

        Ok(())
    }

    /// How many records the journal holds (read at open plus appended since).
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The file's size in bytes: the sum over its records of `4 + len + 32`.
    pub fn size(&self) -> u64 {
        self.size
    }
}
