//! The server's audit log on disk (task T611l): administrative actions taken with the command line, as the
//! tamper-evident hash chain of `crewcraft_server_core::audit` (T125), one line per entry in `audit.log` in the data
//! directory, appended and synced, never rewritten.
//!
//! Owns: the file format (`seq TAB at_ms TAB prev_hex TAB hash_hex TAB actor TAB action`), reading it back with the
//! chain checked, and appending one entry. Does not own: what an action is (the commands in `main.rs`).

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use crewcraft_server_core::audit::{Entry, MAX_FIELD, entry_hash, verify};

/// The audit log's file name in the data directory.
pub const AUDIT_FILE: &str = "audit.log";

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// A field fit for the log: 1 to `MAX_FIELD` bytes, no tab, line break or other control character.
fn fit(field: &str) -> bool {
    !field.is_empty() && field.len() <= MAX_FIELD && !field.chars().any(char::is_control)
}

/// Every entry of `dir`'s audit log, in order, with the hash chain checked: a changed, removed or reordered entry is an
/// error that names its line. No log yet is an empty list.
pub fn read(dir: &Path) -> io::Result<Vec<Entry>> {
    let text = match fs::read_to_string(dir.join(AUDIT_FILE)) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut entries = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let bad = || invalid(format!("{AUDIT_FILE} line {} is not an audit entry", n + 1));
        let parts: Vec<&str> = line.splitn(6, '\t').collect();
        let [seq, at_ms, prev, hash, actor, action] = parts.as_slice() else { return Err(bad()) };
        entries.push(Entry {
            seq: seq.parse().map_err(|_| bad())?,
            at_ms: at_ms.parse().map_err(|_| bad())?,
            prev: unhex(prev).ok_or_else(bad)?,
            hash: unhex(hash).ok_or_else(bad)?,
            actor: (*actor).to_owned(),
            action: (*action).to_owned(),
        });
    }
    verify(&entries).map_err(|error| invalid(format!("{AUDIT_FILE} does not check out: {error:?}")))?;
    Ok(entries)
}

/// Append one entry for `actor` doing `action` at `now_ms` (or at the last entry's time, if the clock went back), after
/// checking the log so far; the line is synced to disk before this returns.
pub fn append(dir: &Path, actor: &str, action: &str, now_ms: u64) -> io::Result<Entry> {
    if !fit(actor) || !fit(action) {
        return Err(invalid("an audit actor or action is empty, too long, or has a control character".into()));
    }
    let entries = read(dir)?;
    let (prev, seq, at_ms) = match entries.last() {
        Some(last) => (last.hash, last.seq + 1, now_ms.max(last.at_ms)),
        None => ([0u8; 32], 1, now_ms),
    };
    let hash = entry_hash(&prev, seq, at_ms, actor, action);
    let entry = Entry { seq, at_ms, actor: actor.to_owned(), action: action.to_owned(), prev, hash };
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(dir.join(AUDIT_FILE))?;
    writeln!(file, "{seq}\t{at_ms}\t{}\t{}\t{actor}\t{action}", hex(&prev), hex(&hash))?;
    file.sync_all()?;
    Ok(entry)
}
