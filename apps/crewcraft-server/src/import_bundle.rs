//! Reading an import bundle from disk and writing its report (docs/IMPORT.md "The bundle", task T350b). The engine
//! that imports it is `crewcraft_server_core::import` (T350a); the `import` command in `main.rs` joins the two.
//!
//! Owns: `bundle.json` parsing (strict: every unknown or missing field is refused, with where it was), email
//! normalization, captured-file checks inside the bundle, and `import-report.json`.

use std::fs;
use std::io;
use std::path::{Component, Path};

use crewcraft_accounts::identity::normalize_email;
use crewcraft_server_core::import::{Bundle, BundleFile, BundleMessage, BundleRoom, Report, RoomKind};
use serde_json::{Map, Value, json};

/// The only bundle format this server reads.
pub const FORMAT: &str = "crewcraft-import/1";
/// The largest `bundle.json` read, in bytes.
pub const MAX_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;
/// The report's file name, written inside the bundle directory.
pub const REPORT_FILE: &str = "import-report.json";

/// Read `dir/bundle.json`. Every address is normalized as account addresses are (an address that does not normalize
/// is kept as written, and the engine refuses its part). A file's `path` must stay inside `dir/files/`; a file is
/// captured only when that path is a regular file there.
pub fn read_bundle(dir: &Path) -> io::Result<Bundle> {
    let path = dir.join("bundle.json");
    let size = fs::metadata(&path)?.len();
    if size > MAX_BUNDLE_BYTES {
        return Err(invalid("bundle.json is larger than 512 MB".into()));
    }
    let value: Value = serde_json::from_slice(&fs::read(&path)?).map_err(|error| invalid(format!("bundle.json is not JSON: {error}")))?;
    let top = object(&value, "the bundle", &["format", "source", "rooms", "messages"], &[])?;
    if string(top, "format", "the bundle")? != FORMAT {
        return Err(invalid(format!("the bundle's format is not {FORMAT:?}")));
    }
    let source = string(top, "source", "the bundle")?.to_owned();
    let mut rooms = Vec::new();
    for (index, room) in array(top, "rooms", "the bundle")?.iter().enumerate() {
        let at = format!("room {index}");
        let room = object(room, &at, &["key", "kind", "name", "members"], &[])?;
        let kind = match string(room, "kind", &at)? {
            "direct" => RoomKind::Direct,
            "group" => RoomKind::Group,
            "channel" => RoomKind::Channel,
            other => return Err(invalid(format!("{at}: kind {other:?} is not direct, group or channel"))),
        };
        let mut members = Vec::new();
        for member in array(room, "members", &at)? {
            members.push(address(member.as_str().ok_or_else(|| invalid(format!("{at}: a member is not a string")))?));
        }
        rooms.push(BundleRoom { key: string(room, "key", &at)?.to_owned(), kind, name: string(room, "name", &at)?.to_owned(), members });
    }
    let mut messages = Vec::new();
    for (index, message) in array(top, "messages", "the bundle")?.iter().enumerate() {
        let at = format!("message {index}");
        let message = object(message, &at, &["room", "key", "author", "sent_ms", "text"], &["reply_to", "edited_ms", "deleted", "files"])?;
        let reply_to = match message.get("reply_to") {
            None | Some(Value::Null) => None,
            Some(Value::String(key)) => Some(key.clone()),
            Some(_) => return Err(invalid(format!("{at}: reply_to is not a string"))),
        };
        let edited_ms = match message.get("edited_ms") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_u64().ok_or_else(|| invalid(format!("{at}: edited_ms is not a whole number")))?),
        };
        let deleted = match message.get("deleted") {
            None => false,
            Some(value) => value.as_bool().ok_or_else(|| invalid(format!("{at}: deleted is not true or false")))?,
        };
        let mut files = Vec::new();
        if let Some(listed) = message.get("files") {
            let listed = listed.as_array().ok_or_else(|| invalid(format!("{at}: files is not a list")))?;
            for (n, file) in listed.iter().enumerate() {
                let file_at = format!("{at} file {n}");
                let file = object(file, &file_at, &["name", "size"], &["sha256", "path"])?;
                let source = match file.get("path") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(path)) => {
                        let found = captured(dir, path).map_err(|reason| invalid(format!("{file_at}: {reason}")))?;
                        found.then(|| dir.join("files").join(path))
                    }
                    Some(_) => return Err(invalid(format!("{file_at}: path is not a string"))),
                };
                let sha256 = match file.get("sha256") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(hex)) => Some(parse_sha256(hex).ok_or_else(|| invalid(format!("{file_at}: sha256 is not 64 hex digits")))?),
                    Some(_) => return Err(invalid(format!("{file_at}: sha256 is not a string"))),
                };
                files.push(BundleFile {
                    name: string(file, "name", &file_at)?.to_owned(),
                    size: number(file, "size", &file_at)?,
                    captured: source.is_some(),
                    source,
                    sha256,
                });
            }
        }
        messages.push(BundleMessage {
            room: string(message, "room", &at)?.to_owned(),
            key: string(message, "key", &at)?.to_owned(),
            author: address(string(message, "author", &at)?),
            sent_ms: number(message, "sent_ms", &at)?,
            text: string(message, "text", &at)?.to_owned(),
            reply_to,
            edited_ms,
            deleted,
            files,
        });
    }
    Ok(Bundle { source, rooms, messages })
}

/// `--map-domain old=new`: both sides one domain (no `@`, no spaces), compared case-insensitively.
pub fn parse_domain_map(value: &str) -> Option<(String, String)> {
    let (old, new) = value.split_once('=')?;
    let ok = |d: &str| !d.is_empty() && d.len() <= 253 && !d.contains('@') && !d.chars().any(|c| c.is_whitespace() || c.is_control());
    (ok(old) && ok(new)).then(|| (old.to_ascii_lowercase(), new.to_ascii_lowercase()))
}

/// The report as JSON (docs/IMPORT.md "The report").
pub fn report_json(report: &Report, dry_run: bool) -> String {
    let skipped: Map<String, Value> = report.people_skipped.iter().map(|(room, people)| (room.clone(), json!(people))).collect();
    let refusals: Vec<Value> = report.refusals.iter().map(|r| json!({"at": r.at, "reason": r.reason})).collect();
    let value = json!({
        "dry_run": dry_run,
        "ok": report.ok(),
        "rooms_created": report.rooms_created,
        "rooms_found": report.rooms_found,
        "members_added": report.members_added,
        "messages_added": report.messages_added,
        "messages_updated": report.messages_updated,
        "messages_unchanged": report.messages_unchanged,
        "files_stored": report.files_stored,
        "files_not_archived": report.files_not_archived,
        "people_skipped": skipped,
        "made_top_level": report.made_top_level,
        "refusals": refusals,
    });
    let mut text = serde_json::to_string_pretty(&value).unwrap_or_default();
    text.push('\n');
    text
}

/// A short summary for the terminal, one line per count that is not zero.
pub fn summary(report: &Report, dry_run: bool) -> String {
    let mut lines = vec![if dry_run { "Dry run: nothing was changed. A real run would do this:".to_owned() } else { "Imported:".to_owned() }];
    let skipped: usize = report.people_skipped.values().map(|people| people.len()).sum();
    for (count, what) in [
        (report.rooms_created, "archive rooms created"),
        (report.rooms_found, "archive rooms already there"),
        (report.members_added, "members added"),
        (report.messages_added, "messages added"),
        (report.messages_updated, "messages updated (edited or deleted since)"),
        (report.messages_unchanged, "messages unchanged"),
        (report.files_stored, "files stored"),
        (report.files_not_archived, "files not archived (not captured by the export)"),
        (skipped, "people skipped (no account yet; a later run adds them)"),
        (report.made_top_level.len(), "replies imported as top-level messages"),
        (report.refusals.len(), "parts refused"),
    ] {
        if count > 0 {
            lines.push(format!("  {count} {what}"));
        }
    }
    lines.join("\n") + "\n"
}

/// 64 hex digits as 32 bytes.
fn parse_sha256(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn address(raw: &str) -> String {
    normalize_email(raw).unwrap_or_else(|_| raw.to_owned())
}

/// Whether `path` names a regular file under `dir/files/`. A path that could leave that folder is refused.
fn captured(dir: &Path, path: &str) -> Result<bool, &'static str> {
    let relative = Path::new(path);
    if path.is_empty() || !relative.components().all(|part| matches!(part, Component::Normal(_))) {
        return Err("path must be a plain relative path inside files/");
    }
    Ok(fs::symlink_metadata(dir.join("files").join(relative)).is_ok_and(|meta| meta.is_file()))
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// `value` as an object with exactly the `required` fields and any of the `optional` ones.
fn object<'a>(value: &'a Value, at: &str, required: &[&str], optional: &[&str]) -> io::Result<&'a Map<String, Value>> {
    let map = value.as_object().ok_or_else(|| invalid(format!("{at} is not an object")))?;
    if let Some(unknown) = map.keys().find(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str())) {
        return Err(invalid(format!("{at}: unknown field {unknown:?}")));
    }
    if let Some(missing) = required.iter().find(|key| !map.contains_key(**key)) {
        return Err(invalid(format!("{at}: missing field {missing:?}")));
    }
    Ok(map)
}

fn string<'a>(map: &'a Map<String, Value>, key: &str, at: &str) -> io::Result<&'a str> {
    map.get(key).and_then(Value::as_str).ok_or_else(|| invalid(format!("{at}: {key} is not a string")))
}

fn number(map: &Map<String, Value>, key: &str, at: &str) -> io::Result<u64> {
    map.get(key).and_then(Value::as_u64).ok_or_else(|| invalid(format!("{at}: {key} is not a whole number")))
}

fn array<'a>(map: &'a Map<String, Value>, key: &str, at: &str) -> io::Result<&'a Vec<Value>> {
    map.get(key).and_then(Value::as_array).ok_or_else(|| invalid(format!("{at}: {key} is not a list")))
}
