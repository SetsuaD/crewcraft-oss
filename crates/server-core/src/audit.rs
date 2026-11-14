//! Tamper-evident audit log of administrative actions: each entry's hash covers the previous entry's hash, so changing,
//! removing or reordering any entry breaks every hash after it. The chain is unkeyed: it detects edits by anyone who
//! cannot rewrite the whole file, and truncation is detected only against a separately kept latest hash. Task T125.

use sha2::{Digest, Sha256};

/// Longest `actor` and `action`, in bytes.
pub const MAX_FIELD: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// 1 for the first entry, then 2, 3, ...
    pub seq: u64,
    pub at_ms: u64,
    pub actor: String,
    pub action: String,
    /// The previous entry's `hash`; 32 zero bytes for the first entry.
    pub prev: [u8; 32],
    /// `entry_hash(prev, seq, at_ms, actor, action)`.
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    /// `actor` or `action` is empty or longer than `MAX_FIELD` bytes.
    FieldLength,
    /// `at_ms` is earlier than the last entry's (equal is fine).
    ClockBackwards,
}

/// The first entry, by position, that does not check out. `index` is its position in the slice (0-based).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// `seq` is not `index + 1`.
    BadSeq { index: usize },
    /// `prev` is not the previous entry's `hash` (or not 32 zero bytes for index 0).
    BadPrev { index: usize },
    /// `hash` is not `entry_hash` of the entry's own fields.
    BadHash { index: usize },
}

/// SHA-256 of: `prev` (32 bytes) | `seq` (u64 big-endian) | `at_ms` (u64 big-endian) | the byte length of `actor`
/// (u16 big-endian) | `actor` | the byte length of `action` (u16 big-endian) | `action`.
///
/// Vector: prev = 32 zero bytes, seq 1, at_ms 1700000000000, actor "alice", action "room.create general" gives
/// f24c934bc187bec81d14920025babf85285245302ddf48c070f8bc5c70400063.
pub fn entry_hash(prev: &[u8; 32], seq: u64, at_ms: u64, actor: &str, action: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(seq.to_be_bytes());
    hasher.update(at_ms.to_be_bytes());
    hasher.update((actor.len() as u16).to_be_bytes());
    hasher.update(actor.as_bytes());
    hasher.update((action.len() as u16).to_be_bytes());
    hasher.update(action.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Check a whole log from its start. For each entry in order: `BadSeq`, then `BadPrev`, then `BadHash`; the first
/// failure is returned. An empty slice is `Ok`.
pub fn verify(entries: &[Entry]) -> Result<(), VerifyError> {
    for (i, entry) in entries.iter().enumerate() {
        // BadSeq
        if entry.seq != (i as u64) + 1 {
            return Err(VerifyError::BadSeq { index: i });
        }
        // BadPrev
        let expected_prev: [u8; 32] = if i == 0 { [0u8; 32] } else { entries[i - 1].hash };
        if entry.prev != expected_prev {
            return Err(VerifyError::BadPrev { index: i });
        }
        // BadHash
        let expected_hash = entry_hash(&entry.prev, entry.seq, entry.at_ms, &entry.actor, &entry.action);
        if entry.hash != expected_hash {
            return Err(VerifyError::BadHash { index: i });
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct AuditLog {
    entries: Vec<Entry>,
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditLog {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Append an entry. Checks, in order: `FieldLength` (actor, then action), `ClockBackwards`. Nothing is appended on an
    /// error. Returns the new entry.
    pub fn append(&mut self, actor: &str, action: &str, at_ms: u64) -> Result<Entry, AuditError> {
        // FieldLength: actor
        if actor.is_empty() || actor.len() > MAX_FIELD {
            return Err(AuditError::FieldLength);
        }
        // FieldLength: action
        if action.is_empty() || action.len() > MAX_FIELD {
            return Err(AuditError::FieldLength);
        }
        // ClockBackwards
        if self.entries.last().is_some_and(|last| at_ms < last.at_ms) {
            return Err(AuditError::ClockBackwards);
        }

        let seq = self.entries.len() as u64 + 1;
        let prev = match self.entries.last() {
            Some(entry) => entry.hash,
            None => [0u8; 32],
        };
        let hash = entry_hash(&prev, seq, at_ms, actor, action);

        let entry = Entry { seq, at_ms, actor: actor.to_string(), action: action.to_string(), prev, hash };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// Every entry, oldest first.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The newest entry's hash; 32 zero bytes while empty. Publishing it elsewhere pins the whole log.
    pub fn head(&self) -> [u8; 32] {
        match self.entries.last() {
            Some(entry) => entry.hash,
            None => [0u8; 32],
        }
    }
}
