//! Importing history from another system (docs/IMPORT.md, task T350a): the engine. It works on a bundle as typed
//! values (`Bundle`); reading `bundle.json` and the command line are the server app's (T350b), and each source's
//! reader only ever produces bundles (T350c).
//!
//! Owns: the bundle's types and checks, archive rooms and imported messages by external key (`Imports`), the import
//! records' replay (`replay`, called by `DurableServer::open`), and `DurableServer::import` with its `Report`.
//! Calls: `server::Server` (archive rooms, `import_post`/`import_edit`/`import_delete`), `durable` (records, search
//! index, threads).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;

use crate::durable::{DurableError, DurableServer, index_event};
use crate::import_media::{ImportedFile, merge_files};
use crate::op::Op;
use crate::room::Role;
use crate::room_service::MAX_TEXT_CHARS;
use crate::server::Server;

/// The owner of every archive room. Not an email address, so no account can ever be it.
pub const ARCHIVE_OWNER: &str = "archive";
/// The longest source name, room key or message key, in bytes.
pub const MAX_SOURCE: usize = 32;
pub const MAX_KEY: usize = 200;
/// The longest email address, in bytes.
pub const MAX_EMAIL: usize = 320;

/// What a conversation was in the source system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomKind {
    /// A one-to-one conversation: exactly two members.
    Direct,
    Group,
    Channel,
}

/// One export, in the neutral form every reader produces (docs/IMPORT.md "The bundle").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// The system it came from: 1 to `MAX_SOURCE` lowercase ASCII letters, digits or hyphens. It scopes every key.
    pub source: String,
    pub rooms: Vec<BundleRoom>,
    pub messages: Vec<BundleMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleRoom {
    /// The source's stable id for the conversation.
    pub key: String,
    pub kind: RoomKind,
    /// May be empty for a direct conversation, which is then named after its two people.
    pub name: String,
    /// Email addresses.
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleMessage {
    /// A room's `key`.
    pub room: String,
    /// The source's stable id for the message.
    pub key: String,
    /// An email address; the author need not have an account.
    pub author: String,
    /// The original time, Unix milliseconds.
    pub sent_ms: u64,
    /// Plain text; ignored when `deleted`.
    pub text: String,
    /// A message `key` in the same room this one replies to.
    pub reply_to: Option<String>,
    pub edited_ms: Option<u64>,
    /// The source deleted it: it is kept as redacted, and never comes back.
    pub deleted: bool,
    /// Its files: captured ones are stored and attached, the rest kept by name and size (T350e).
    pub files: Vec<BundleFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFile {
    pub name: String,
    pub size: u64,
    /// Whether the export holds the bytes.
    pub captured: bool,
    /// Where the bytes are, when captured.
    pub source: Option<PathBuf>,
    /// The SHA-256 the bundle gives for the bytes, if any; the stored bytes must match it.
    pub sha256: Option<[u8; 32]>,
}

impl Bundle {
    /// Rewrite the domain of every email address, members and authors, by `map` (old domain, new domain), compared
    /// ASCII case-insensitively. An address whose domain is not in `map` stays as it is.
    pub fn map_domains(&mut self, map: &[(String, String)]) {
        for room in &mut self.rooms {
            for member in &mut room.members {
                *member = map_email(member, map);
            }
        }
        for message in &mut self.messages {
            message.author = map_email(&message.author, map);
        }
    }
}

fn map_email(email: &str, map: &[(String, String)]) -> String {
    let Some((local, domain)) = email.rsplit_once('@') else { return email.to_owned() };
    match map.iter().find(|(old, _)| old.eq_ignore_ascii_case(domain)) {
        Some((_, new)) => format!("{local}@{new}"),
        None => email.to_owned(),
    }
}

/// One email address: one `@` with something on both sides, no whitespace or control characters, at most
/// `MAX_EMAIL` bytes.
pub fn valid_email(email: &str) -> bool {
    let Some((local, domain)) = email.split_once('@') else { return false };
    email.len() <= MAX_EMAIL
        && !local.is_empty()
        && !domain.is_empty()
        && !domain.contains('@')
        && !email.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn valid_source(source: &str) -> bool {
    (1..=MAX_SOURCE).contains(&source.len()) && source.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_key(key: &str) -> bool {
    (1..=MAX_KEY).contains(&key.len()) && !key.chars().any(char::is_control)
}

/// What a run did, or would do (a dry run). `ok` is false when anything was refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Report {
    pub rooms_created: usize,
    pub rooms_found: usize,
    pub members_added: usize,
    pub messages_added: usize,
    /// Edited or deleted since an earlier run.
    pub messages_updated: usize,
    pub messages_unchanged: usize,
    /// Captured files stored by this run (T350e).
    pub files_stored: usize,
    /// Files of the messages this run imported or updated that are not archived (the export did not capture them, or
    /// storing them was refused).
    pub files_not_archived: usize,
    /// Members without an account, by room key: skipped now, added by a later run once they have one.
    pub people_skipped: BTreeMap<String, BTreeSet<String>>,
    /// Message keys whose `reply_to` could not be a thread (a missing parent, a reply, or a deleted message): imported
    /// as top-level messages.
    pub made_top_level: Vec<String>,
    pub refusals: Vec<Refusal>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.refusals.is_empty()
    }
}

/// A part of the bundle that was not imported, and why. `at` is `bundle`, `room <n>` or `message <n>` (0-based, in
/// the bundle's own order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub at: String,
    pub reason: String,
}

/// An imported message, as the import's own bookkeeping keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Imported {
    slug: String,
    cursor: u64,
    sent_ms: u64,
    /// The trimmed text last imported (empty once deleted).
    text: String,
    deleted: bool,
    top_level: bool,
    /// Its files, stored or not archived (T350e).
    files: Vec<ImportedFile>,
}

/// What imports have made, rebuilt from the import records on every start.
#[derive(Debug, Clone, Default)]
pub struct Imports {
    /// Archive room slugs by external key `source:key`.
    rooms: HashMap<String, String>,
    /// Imported messages by external key `source:room:key`.
    messages: HashMap<String, Imported>,
    /// External keys by room and cursor, for the original time.
    by_cursor: HashMap<(String, u64), String>,
}

impl Imports {
    fn insert_message(&mut self, key: String, imported: Imported) {
        self.by_cursor.insert((imported.slug.clone(), imported.cursor), key.clone());
        self.messages.insert(key, imported);
    }
}

/// The result of `replay`: an import record applied (search indexes the message at `cursor` of `slug` when it is not
/// 0), or any other record, handed back untouched.
pub(crate) enum Replayed {
    Done { slug: String, cursor: u64 },
    NotImport(Op),
}

/// Apply an import record at start-up, as `DurableServer::import` did when it wrote it. `Err` means the journal does
/// not match what it rebuilds (corrupt).
pub(crate) fn replay(server: &mut Server, imports: &mut Imports, parents: &mut HashMap<(String, u64), u64>, op: Op) -> Result<Replayed, ()> {
    match op {
        Op::ImportRoom { key, name } => {
            let slug = server.create_archive_room(&name).map_err(|_| ())?;
            imports.rooms.insert(key, slug.clone());
            Ok(Replayed::Done { slug, cursor: 0 })
        }
        Op::ImportMessage { slug, key, author, sent_ms, text, deleted, parent } => {
            let cursor = server.import_post(&slug, &author, &text, deleted).map_err(|_| ())?;
            if parent != 0 {
                parents.insert((slug.clone(), cursor), parent);
            }
            let imported = Imported { slug: slug.clone(), cursor, sent_ms, text, deleted, top_level: parent == 0, files: Vec::new() };
            imports.insert_message(key, imported);
            Ok(Replayed::Done { slug, cursor })
        }
        Op::ImportFiles { slug, key, files } => {
            let imported = imports.messages.get_mut(&key).filter(|m| m.slug == slug).ok_or(())?;
            imported.files = files.into_iter().map(|(name, size, id)| ImportedFile { name, size, id }).collect();
            Ok(Replayed::Done { slug, cursor: 0 })
        }
        Op::ImportEdit { slug, key, text, .. } => {
            let imported = imports.messages.get_mut(&key).filter(|m| m.slug == slug).ok_or(())?;
            let cursor = server.import_edit(&slug, imported.cursor, &text).map_err(|_| ())?;
            imported.text = text;
            Ok(Replayed::Done { slug, cursor })
        }
        Op::ImportDelete { slug, key } => {
            let imported = imports.messages.get_mut(&key).filter(|m| m.slug == slug).ok_or(())?;
            let cursor = server.import_delete(&slug, imported.cursor).map_err(|_| ())?;
            imported.deleted = true;
            imported.text.clear();
            Ok(Replayed::Done { slug, cursor })
        }
        other => Ok(Replayed::NotImport(other)),
    }
}

/// The name an archive room gets: the bundle's, or, for a direct conversation without one, its two people.
fn room_name(room: &BundleRoom) -> String {
    if !room.name.trim().is_empty() || room.kind != RoomKind::Direct {
        return room.name.clone();
    }
    let people: Vec<&str> = room.members.iter().map(|m| m.split('@').next().unwrap_or(m)).collect();
    let name = people.join(" and ");
    name.chars().take(64).collect()
}

/// A new message's place in a thread, decided before it is written.
enum Parent {
    None,
    Cursor(u64),
    /// A parent added earlier in this dry run: it has no cursor yet.
    Planned,
}

impl DurableServer {
    /// Import `bundle` (docs/IMPORT.md "Importing a bundle"). Members for whom `has_account` is false are skipped and
    /// reported. A `dry_run` changes nothing and reports what a real run would do. Every refusal skips that part only
    /// and is reported; `Err` is a storage failure (the journal), after which the server is poisoned as for any
    /// other change.
    pub fn import(&mut self, bundle: &Bundle, has_account: &dyn Fn(&str) -> bool, dry_run: bool) -> Result<Report, DurableError> {
        self.check_alive()?;
        let mut report = Report::default();
        if !valid_source(&bundle.source) {
            report.refusals.push(Refusal { at: "bundle".into(), reason: "the source is not 1 to 32 lowercase letters, digits or hyphens".into() });
            return Ok(report);
        }
        let source = &bundle.source;

        // Rooms: the archive room of each, found or made, by bundle key. `None` is a room a dry run would make.
        let mut rooms: HashMap<&str, Option<String>> = HashMap::new();
        for (index, room) in bundle.rooms.iter().enumerate() {
            let at = format!("room {index}");
            let refuse = |report: &mut Report, reason: &str| report.refusals.push(Refusal { at: at.clone(), reason: reason.into() });
            if !valid_key(&room.key) {
                refuse(&mut report, "the key is not 1 to 200 bytes without control characters");
                continue;
            }
            if rooms.contains_key(room.key.as_str()) {
                refuse(&mut report, "a second room with this key");
                continue;
            }
            if let Some(bad) = room.members.iter().find(|m| !valid_email(m)) {
                refuse(&mut report, &format!("member {bad:?} is not an email address"));
                continue;
            }
            if room.kind == RoomKind::Direct && room.members.len() != 2 {
                refuse(&mut report, "a direct conversation needs exactly two members");
                continue;
            }
            let name = room_name(room);
            if crate::room_name::validate(&name).is_err() {
                refuse(&mut report, "the name is empty, longer than 64 characters or has control characters");
                continue;
            }
            let external = format!("{source}:{}", room.key);
            let slug = match self.imports.rooms.get(&external) {
                Some(slug) => {
                    report.rooms_found += 1;
                    Some(slug.clone())
                }
                None if dry_run => {
                    report.rooms_created += 1;
                    None
                }
                None => {
                    let slug = self.server.create_archive_room(&name).map_err(DurableError::Server)?;
                    self.record(&Op::ImportRoom { key: external.clone(), name: name.clone() })?;
                    self.imports.rooms.insert(external, slug.clone());
                    report.rooms_created += 1;
                    Some(slug)
                }
            };
            for member in &room.members {
                if !has_account(member) {
                    report.people_skipped.entry(room.key.clone()).or_default().insert(member.clone());
                    continue;
                }
                let present = slug.as_ref().is_some_and(|slug| self.server.room(slug).is_ok_and(|r| r.role(member).is_some()));
                if present {
                    continue;
                }
                if let Some(slug) = &slug
                    && !dry_run
                {
                    self.add_member(slug, ARCHIVE_OWNER, member, Role::Member)?;
                }
                report.members_added += 1;
            }
            rooms.insert(&room.key, slug);
        }

        // Messages, oldest first (a reply comes after what it replies to), ties in the bundle's order.
        let mut order: Vec<usize> = (0..bundle.messages.len()).collect();
        order.sort_by_key(|&index| (bundle.messages[index].sent_ms, index));
        let mut seen: HashSet<String> = HashSet::new();
        // Messages a dry run would add, by external key: whether each would be a top-level, live message.
        let mut planned: HashMap<String, bool> = HashMap::new();
        for index in order {
            let message = &bundle.messages[index];
            let at = format!("message {index}");
            let refuse = |report: &mut Report, reason: &str| report.refusals.push(Refusal { at: at.clone(), reason: reason.into() });
            let Some(slug) = rooms.get(message.room.as_str()) else {
                refuse(&mut report, "its room is not in the bundle, or was refused");
                continue;
            };
            if !valid_key(&message.key) {
                refuse(&mut report, "the key is not 1 to 200 bytes without control characters");
                continue;
            }
            let external = format!("{source}:{}:{}", message.room, message.key);
            if !seen.insert(external.clone()) {
                refuse(&mut report, "a second message with this key in its room");
                continue;
            }
            if !valid_email(&message.author) {
                refuse(&mut report, "the author is not an email address");
                continue;
            }
            let text = message.text.trim();
            if !message.deleted && (text.is_empty() || text.chars().count() > MAX_TEXT_CHARS) {
                refuse(&mut report, "the text is empty or longer than 4000 characters");
                continue;
            }

            // Already imported: bring it up to date, never back.
            if let Some(existing) = self.imports.messages.get(&external).cloned() {
                let mut changed = false;
                if !existing.deleted && (message.deleted || existing.text != text) {
                    if !dry_run {
                        self.update_imported(&external, &existing, message, text)?;
                    }
                    changed = true;
                }
                if !existing.deleted && !message.deleted {
                    changed |= self.import_files(&existing.slug, &external, &existing.files, message, index, dry_run, &mut report)?;
                }
                if changed {
                    report.messages_updated += 1;
                } else {
                    report.messages_unchanged += 1;
                }
                continue;
            }

            // A new message: a reply only to a live, top-level message of the same room.
            let parent = match &message.reply_to {
                None => Parent::None,
                Some(reply_to) => {
                    let parent_key = format!("{source}:{}:{reply_to}", message.room);
                    match (self.imports.messages.get(&parent_key), planned.get(&parent_key)) {
                        (Some(p), _) if p.top_level && !p.deleted && Some(&p.slug) == slug.as_ref() => Parent::Cursor(p.cursor),
                        (None, Some(true)) => Parent::Planned,
                        _ => {
                            report.made_top_level.push(message.key.clone());
                            Parent::None
                        }
                    }
                }
            };
            report.messages_added += 1;
            let top_level = matches!(parent, Parent::None);
            match slug {
                Some(slug) if !dry_run => {
                    let parent = match parent {
                        Parent::Cursor(cursor) => cursor,
                        Parent::None | Parent::Planned => 0,
                    };
                    self.add_imported(slug, &external, message, text, parent)?;
                    self.import_files(slug, &external, &[], message, index, false, &mut report)?;
                }
                _ => {
                    self.import_files("", &external, &[], message, index, true, &mut report)?;
                    planned.insert(external, top_level && !message.deleted);
                }
            }
        }
        Ok(report)
    }

    fn add_imported(&mut self, slug: &str, external: &str, message: &BundleMessage, text: &str, parent: u64) -> Result<(), DurableError> {
        let text = if message.deleted { "" } else { text };
        let cursor = self.server.import_post(slug, &message.author, text, message.deleted).map_err(DurableError::Server)?;
        self.record(&Op::ImportMessage {
            slug: slug.to_owned(),
            key: external.to_owned(),
            author: message.author.clone(),
            sent_ms: message.sent_ms,
            text: text.to_owned(),
            deleted: message.deleted,
            parent,
        })?;
        index_event(&self.server, &mut self.search, &mut self.previews, slug, ARCHIVE_OWNER, cursor);
        if parent != 0 {
            self.parents.insert((slug.to_owned(), cursor), parent);
        }
        let imported = Imported {
            slug: slug.to_owned(),
            cursor,
            sent_ms: message.sent_ms,
            text: text.to_owned(),
            deleted: message.deleted,
            top_level: parent == 0,
            files: Vec::new(),
        };
        self.imports.insert_message(external.to_owned(), imported);
        Ok(())
    }

    /// Bring an imported message's files up to date with the bundle (T350e): store what is newly captured, keep what an
    /// earlier run stored, and record the list when it changed. Returns whether it changed. A dry run stores nothing and
    /// counts what a real run would store. A deleted message has no files.
    #[allow(clippy::too_many_arguments)]
    fn import_files(
        &mut self,
        slug: &str,
        external: &str,
        existing: &[ImportedFile],
        message: &BundleMessage,
        index: usize,
        dry_run: bool,
        report: &mut Report,
    ) -> Result<bool, DurableError> {
        if message.deleted || (message.files.is_empty() && existing.is_empty()) {
            return Ok(false);
        }
        if dry_run {
            let mut changed = existing.is_empty();
            for (n, file) in message.files.iter().enumerate() {
                if existing.get(n).is_some_and(|old| old.name == file.name && old.id.is_some()) {
                    continue;
                }
                if file.captured {
                    report.files_stored += 1;
                    changed = true;
                } else {
                    report.files_not_archived += 1;
                }
            }
            return Ok(changed);
        }
        let mut refusals = Vec::new();
        let mut stored = 0;
        let merged = merge_files(existing, &message.files, |n, file| match self.store_imported_file(slug, file)? {
            Ok(id) => {
                stored += 1;
                Ok(Some(id))
            }
            Err(reason) => {
                refusals.push(Refusal { at: format!("message {index} file {n}"), reason: reason.into() });
                Ok(None)
            }
        })?;
        report.files_stored += stored;
        report.refusals.extend(refusals);
        report.files_not_archived += merged.iter().filter(|file| file.id.is_none()).count();
        if merged == existing {
            return Ok(false);
        }
        let files: Vec<(String, u64, Option<[u8; 16]>)> = merged.iter().map(|file| (file.name.clone(), file.size, file.id)).collect();
        self.record(&Op::ImportFiles { slug: slug.to_owned(), key: external.to_owned(), files })?;
        if let Some(imported) = self.imports.messages.get_mut(external) {
            imported.files = merged;
        }
        Ok(true)
    }

    /// Every live imported message's stored files, as `(room, cursor, [(file id, name, size)])` (task T331a).
    pub(crate) fn imported_file_lists(&self) -> Vec<(String, u64, Vec<([u8; 16], String, u64)>)> {
        self.imports
            .messages
            .values()
            .filter(|m| !m.deleted && !m.files.is_empty())
            .map(|m| (m.slug.clone(), m.cursor, m.files.iter().filter_map(|f| f.id.map(|id| (id, f.name.clone(), f.size))).collect()))
            .collect()
    }

    /// The files of the imported message at `cursor` in `slug`, if it has any and is not deleted (T350e).
    pub(crate) fn imported_files(&self, slug: &str, cursor: u64) -> Option<&[ImportedFile]> {
        let key = self.imports.by_cursor.get(&(slug.to_owned(), cursor))?;
        let imported = self.imports.messages.get(key).filter(|m| !m.deleted && !m.files.is_empty())?;
        Some(&imported.files)
    }

    fn update_imported(&mut self, external: &str, existing: &Imported, message: &BundleMessage, text: &str) -> Result<(), DurableError> {
        let (slug, deleted) = (existing.slug.clone(), message.deleted);
        let cursor = if deleted {
            let cursor = self.server.import_delete(&slug, existing.cursor).map_err(DurableError::Server)?;
            self.record(&Op::ImportDelete { slug: slug.clone(), key: external.to_owned() })?;
            cursor
        } else {
            let cursor = self.server.import_edit(&slug, existing.cursor, text).map_err(DurableError::Server)?;
            self.record(&Op::ImportEdit {
                slug: slug.clone(),
                key: external.to_owned(),
                text: text.to_owned(),
                edited_ms: message.edited_ms.unwrap_or(0),
            })?;
            cursor
        };
        index_event(&self.server, &mut self.search, &mut self.previews, &slug, ARCHIVE_OWNER, cursor);
        if let Some(imported) = self.imports.messages.get_mut(external) {
            imported.deleted = deleted;
            imported.text = if deleted { String::new() } else { text.to_owned() };
        }
        Ok(())
    }

    /// The archive room an import made for room `key` of `source`, if any.
    pub fn archive_room(&self, source: &str, key: &str) -> Option<&str> {
        self.imports.rooms.get(&format!("{source}:{key}")).map(String::as_str)
    }

    /// The original time of the imported message at `cursor` in `slug`, if it is one.
    pub fn imported_sent_ms(&self, slug: &str, cursor: u64) -> Option<u64> {
        let key = self.imports.by_cursor.get(&(slug.to_owned(), cursor))?;
        self.imports.messages.get(key).map(|m| m.sent_ms)
    }
}
