//! Reading a Microsoft Teams export into an import bundle (docs/IMPORT.md "Reading a Teams export", task T350c).
//! Built only from Microsoft's public Graph API documentation of the `chat`, `channel`, `conversationMember`, `user`
//! and `chatMessage` resources. The reader never talks to Microsoft: the administrator saves what the documented
//! calls return, and this turns those files into a bundle that `crewcraft-server import` reads (T350b).
//!
//! Owns: the export layout below, the mapping to bundle rooms and messages, HTML to plain text, ISO 8601 times, and
//! copying captured attachments into the bundle.
//!
//! The export directory:
//! - `users.json`: `GET /users` pages, `{"value": [user, ...]}` (or a list of such pages): each `id` with its `mail`,
//!   or `userPrincipalName` when there is no mail.
//! - `conversations/*.json`: one file per conversation, `{"chat": chat}` or `{"team": team, "channel": channel}`,
//!   with `"members": [conversationMember, ...]` and `"pages": [{"value": [chatMessage, ...]}, ...]`. A message's
//!   `replies` (as `$expand=replies` returns them) are read as messages too.
//! - `files/<message id>/<attachment name>`: an attachment's bytes, when the export captured them.
//!
//! Fields the reader does not use are ignored: Graph adds fields over time, and this is someone else's format.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::path::Path;

use chrono::{NaiveDate, NaiveTime};
use serde_json::{Value, json};

/// What the reader did, for the terminal and for anyone checking the export.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TeamsReport {
    pub conversations: usize,
    pub messages: usize,
    /// System and event messages (`messageType` other than `message`): left out.
    pub system_messages: usize,
    /// Senders whose user id `users.json` does not map to an address, with how many messages each: left out.
    pub unmapped_senders: BTreeMap<String, usize>,
    pub files_captured: usize,
    pub files_not_captured: usize,
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_json(path: &Path) -> io::Result<Value> {
    serde_json::from_slice(&fs::read(path)?).map_err(|error| invalid(format!("{} is not JSON: {error}", path.display())))
}

/// Every item of a Graph page (`{"value": [...]}`) or of a list of pages.
fn page_items(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(pages) => pages.iter().flat_map(page_items).collect(),
        Value::Object(page) => page.get("value").and_then(Value::as_array).map(|items| items.iter().collect()).unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn text_of<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// Read the export in `export` and write a bundle into the new directory `out` (`bundle.json` and `files/`).
pub fn read_teams(export: &Path, out: &Path) -> io::Result<TeamsReport> {
    let mut report = TeamsReport::default();
    let mut users: HashMap<String, String> = HashMap::new();
    for user in page_items(&read_json(&export.join("users.json"))?) {
        if let Some(id) = text_of(user, "id")
            && let Some(address) = text_of(user, "mail").or_else(|| text_of(user, "userPrincipalName"))
        {
            users.insert(id.to_owned(), address.to_ascii_lowercase());
        }
    }

    let mut names: Vec<_> = fs::read_dir(export.join("conversations"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    names.sort();
    fs::create_dir(out)?;
    fs::create_dir(out.join("files"))?;
    let (mut rooms, mut messages) = (Vec::new(), Vec::new());
    for path in names {
        let conversation = read_json(&path)?;
        let (key, kind, name) = if let Some(chat) = conversation.get("chat") {
            let id = text_of(chat, "id").ok_or_else(|| invalid(format!("{}: the chat has no id", path.display())))?;
            let kind = if text_of(chat, "chatType") == Some("oneOnOne") { "direct" } else { "group" };
            (id.to_owned(), kind, text_of(chat, "topic").unwrap_or("").to_owned())
        } else {
            let team = conversation.get("team").ok_or_else(|| invalid(format!("{}: neither a chat nor a team channel", path.display())))?;
            let channel = conversation.get("channel").ok_or_else(|| invalid(format!("{}: a team without a channel", path.display())))?;
            let (team_id, channel_id) = (text_of(team, "id"), text_of(channel, "id"));
            let (Some(team_id), Some(channel_id)) = (team_id, channel_id) else {
                return Err(invalid(format!("{}: the team or channel has no id", path.display())));
            };
            let name = format!("{} / {}", text_of(team, "displayName").unwrap_or("Team"), text_of(channel, "displayName").unwrap_or("Channel"));
            (format!("{team_id}/{channel_id}"), "channel", name.chars().take(64).collect())
        };
        report.conversations += 1;
        let mut members: Vec<String> = Vec::new();
        for member in conversation.get("members").and_then(Value::as_array).into_iter().flatten() {
            let address =
                text_of(member, "email").map(str::to_ascii_lowercase).or_else(|| text_of(member, "userId").and_then(|id| users.get(id).cloned()));
            if let Some(address) = address
                && !members.contains(&address)
            {
                members.push(address);
            }
        }
        rooms.push(json!({"key": key, "kind": kind, "name": name, "members": members}));

        let pages = conversation.get("pages").cloned().unwrap_or(Value::Null);
        let mut all: Vec<&Value> = Vec::new();
        for message in page_items(&pages) {
            all.push(message);
            all.extend(message.get("replies").and_then(Value::as_array).into_iter().flatten());
        }
        for message in all {
            if text_of(message, "messageType").is_some_and(|t| t != "message") {
                report.system_messages += 1;
                continue;
            }
            let Some(id) = text_of(message, "id") else { continue };
            let sender = message.get("from").and_then(|from| from.get("user")).and_then(|user| text_of(user, "id"));
            let Some(author) = sender.and_then(|id| users.get(id)) else {
                let who = sender.unwrap_or("(no sender)").to_owned();
                *report.unmapped_senders.entry(who).or_insert(0) += 1;
                continue;
            };
            let Some(sent_ms) = text_of(message, "createdDateTime").and_then(iso_ms) else { continue };
            let edited_ms = text_of(message, "lastModifiedDateTime").and_then(iso_ms).filter(|&edited| edited > sent_ms);
            let deleted = message.get("deletedDateTime").is_some_and(|d| !d.is_null());
            let body = message.get("body");
            let content = body.and_then(|b| text_of(b, "content")).unwrap_or("");
            let text = if body.and_then(|b| text_of(b, "contentType")) == Some("html") { html_to_text(content) } else { content.trim().to_owned() };
            let mut files = Vec::new();
            for attachment in message.get("attachments").and_then(Value::as_array).into_iter().flatten() {
                let Some(name) = text_of(attachment, "name").filter(|n| safe_name(n)) else { continue };
                let source = export.join("files").join(safe_dir(id)).join(name);
                let bytes = fs::symlink_metadata(&source).ok().filter(|meta| meta.is_file()).map(|meta| meta.len());
                match bytes {
                    Some(size) => {
                        let relative = format!("{}/{name}", safe_dir(id));
                        fs::create_dir_all(out.join("files").join(safe_dir(id)))?;
                        fs::copy(&source, out.join("files").join(&relative))?;
                        report.files_captured += 1;
                        files.push(json!({"name": name, "size": size, "path": relative}));
                    }
                    None => {
                        report.files_not_captured += 1;
                        files.push(json!({"name": name, "size": 0}));
                    }
                }
            }
            // A message with no words left (only an image or a card) still says what it was.
            let text =
                if text.is_empty() && !deleted { if files.is_empty() { "(no text)".to_owned() } else { "(attachment)".to_owned() } } else { text };
            let mut entry = json!({"room": key, "key": id, "author": author, "sent_ms": sent_ms, "text": text, "deleted": deleted, "files": files});
            if let Some(parent) = text_of(message, "replyToId")
                && parent != id
            {
                entry["reply_to"] = json!(parent);
            }
            if let Some(edited) = edited_ms {
                entry["edited_ms"] = json!(edited);
            }
            messages.push(entry);
            report.messages += 1;
        }
    }
    let bundle = json!({"format": crate::import_bundle::FORMAT, "source": "teams", "rooms": rooms, "messages": messages});
    let mut text = serde_json::to_string_pretty(&bundle).map_err(io::Error::other)?;
    text.push('\n');
    fs::write(out.join("bundle.json"), text)?;
    Ok(report)
}

/// A file name with no path in it.
fn safe_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\']) && !name.chars().any(char::is_control)
}

/// A message id as one directory name (Graph ids are digits; anything else is replaced). The exporter (T351) writes
/// attachments under the same name.
pub fn safe_dir(id: &str) -> String {
    id.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

/// Milliseconds since 1970 of an ISO 8601 / RFC 3339 time as Graph writes it: `2024-03-05T14:07:09.123Z`, fraction
/// optional, `Z` or `+hh:mm` / `-hh:mm`. `None` for anything else, a day its month does not have, or a time before 1970.
pub fn iso_ms(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    let digits = |from: usize, len: usize| -> Option<i64> {
        let part = text.get(from..from + len)?;
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    if bytes.len() < 20 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' || bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let (year, month, day) = (digits(0, 4)?, digits(5, 2)?, digits(8, 2)?);
    let (hour, minute, second) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut pos = 19;
    let mut millis = 0i64;
    if bytes.get(pos) == Some(&b'.') {
        let start = pos + 1;
        let end = (start..bytes.len()).find(|&i| !bytes[i].is_ascii_digit()).unwrap_or(bytes.len());
        if end == start {
            return None;
        }
        let fraction = &text[start..end.min(start + 3)];
        millis = fraction.parse::<i64>().ok()? * 10i64.pow(3 - fraction.len() as u32);
        pos = end;
    }
    let offset_minutes = match bytes.get(pos) {
        Some(b'Z') if pos + 1 == bytes.len() => 0,
        Some(&sign @ (b'+' | b'-')) if pos + 6 == bytes.len() && bytes[pos + 3] == b':' => {
            let minutes = digits(pos + 1, 2)? * 60 + digits(pos + 4, 2)?;
            if sign == b'+' { minutes } else { -minutes }
        }
        _ => return None,
    };
    // The calendar is chrono's (Craft standard time.md): it refuses a day the month does not have. The time of day,
    // a leap second included, and the offset are plain arithmetic.
    let date = NaiveDate::from_ymd_opt(i32::try_from(year).ok()?, u32::try_from(month).ok()?, u32::try_from(day).ok()?)?;
    let midnight = date.and_time(NaiveTime::MIN).and_utc().timestamp();
    let seconds = midnight + hour * 3600 + minute * 60 + second - offset_minutes * 60;
    u64::try_from(seconds * 1000 + millis).ok()
}

/// Plain text from a message's HTML: paragraphs, divisions, line breaks and list items become line breaks (a list item
/// starts with "- "), `script` and `style` contents are dropped, every other tag is removed, and the common entities
/// and numeric character references are decoded. Each line is trimmed, and blank lines are dropped.
pub fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(lt) = rest.find('<') {
        out.push_str(&decode_entities(&rest[..lt]));
        let Some(gt) = rest[lt..].find('>') else {
            out.push_str(&decode_entities(&rest[lt..]));
            rest = "";
            break;
        };
        let tag = rest[lt + 1..lt + gt].trim();
        let closing = tag.starts_with('/');
        let name: String = tag.trim_start_matches('/').chars().take_while(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase();
        rest = &rest[lt + gt + 1..];
        match name.as_str() {
            "script" | "style" if !closing => {
                let end = format!("</{name}");
                let found = rest.to_ascii_lowercase().find(&end);
                rest = match found {
                    Some(at) => rest[at..].find('>').map_or("", |gt| &rest[at + gt + 1..]),
                    None => "",
                };
            }
            "br" => out.push('\n'),
            "p" | "div" | "tr" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "blockquote" | "ul" | "ol" => out.push('\n'),
            "li" if !closing => out.push_str("\n- "),
            _ => {}
        }
    }
    out.push_str(&decode_entities(rest));
    let lines: Vec<&str> = out.lines().map(|line| line.trim_matches([' ', '\u{a0}', '\t'])).filter(|line| !line.is_empty()).collect();
    lines.join("\n")
}

fn decode_entities(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let end = rest.find(';').filter(|&end| end <= 10);
        let decoded = end.and_then(|end| {
            let entity = &rest[1..end];
            let ch = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some(' '),
                _ if entity.starts_with("#x") || entity.starts_with("#X") => u32::from_str_radix(&entity[2..], 16).ok().and_then(char::from_u32),
                _ if entity.starts_with('#') => entity[1..].parse().ok().and_then(char::from_u32),
                _ => None,
            };
            ch.map(|c| (c, end))
        });
        match decoded {
            Some((c, end)) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::iso_ms;

    #[test]
    fn only_days_the_calendar_has_are_read() {
        // Leap years: every fourth year, but not a century unless it divides by 400.
        assert_eq!(iso_ms("2000-02-29T00:00:00Z"), Some(951_782_400_000));
        assert_eq!(iso_ms("2024-02-29T12:00:00Z"), Some(1_709_208_000_000));
        for impossible in ["1900-02-29T00:00:00Z", "2023-02-29T00:00:00Z", "2024-02-30T00:00:00Z", "2024-04-31T00:00:00Z", "2024-00-10T00:00:00Z"] {
            assert_eq!(iso_ms(impossible), None, "{impossible}");
        }
        // A leap second is the next second's time, as before.
        assert_eq!(iso_ms("2016-12-31T23:59:60Z"), Some(1_483_228_800_000));
    }
}
