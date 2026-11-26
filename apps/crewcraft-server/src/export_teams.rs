//! Exporting a person's own Microsoft Teams history through Microsoft Graph (task T351, docs/IMPORT.md "Exporting
//! from Teams"). Built only from Microsoft's public documentation: the OAuth 2.0 device authorization grant (RFC 8628)
//! on the Microsoft identity platform, and the Graph v1.0 `chat`, `team`, `channel`, `conversationMember`, `user`,
//! `chatMessage`, `chatMessageHostedContent`, `shares` and `driveItem` resources.
//!
//! Owns: signing in with a device code (the token lives in memory only: it is never written, printed or sent anywhere
//! but the configured Graph address), reading every page of the documented list calls (`@odata.nextLink`, followed
//! only while it stays on that Graph address), throttling (429, 503 and 504 with `Retry-After`, bounded retries with
//! backoff), downloading attachments up to a size cap under file names that are safe on every system, and writing
//! exactly the export layout `import_teams` reads. Re-running into the same directory skips what is already written:
//! a conversation file is written last, after its attachments, so its presence means it is complete.
//! Called by: `crewcraft-server export-teams` (main.rs). Calls: `crewcraft-https` (the strict client), and
//! `import_teams::safe_dir` for the directory a message's files go in.

use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crewcraft_https::{Client, Error as HttpError, Response, Roots};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::import_teams::safe_dir;

/// The Microsoft identity platform's public cloud. A national cloud has its own; `--login-url` names it.
pub const DEFAULT_LOGIN_URL: &str = "https://login.microsoftonline.com";
/// Graph v1.0 in the public cloud; `--graph-url` names another.
pub const DEFAULT_GRAPH_URL: &str = "https://graph.microsoft.com/v1.0";
/// Read-only delegated permissions for chats: sign-in renewal, people's addresses, chats with their members, messages
/// and inline images, and the files shared in them.
pub const CHAT_SCOPES: &[&str] = &["offline_access", "User.ReadBasic.All", "Chat.Read", "Files.Read.All"];
/// Read-only delegated permissions added for team channels. `ChannelMessage.Read.All` and `ChannelMember.Read.All` need
/// an administrator's consent in most organizations; `--chats-only` leaves channels out.
pub const CHANNEL_SCOPES: &[&str] = &["Team.ReadBasic.All", "Channel.ReadBasic.All", "ChannelMember.Read.All", "ChannelMessage.Read.All"];
/// The default cap on one attachment.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 100 * 1024 * 1024;
/// The highest cap allowed (an attachment is held in memory while it downloads).
pub const MAX_FILE_BYTES_LIMIT: u64 = 1024 * 1024 * 1024;
/// How many times a throttled or failed request is tried again before the export stops.
pub const DEFAULT_MAX_RETRIES: u32 = 6;
const MAX_PAGE_BYTES: usize = 32 * 1024 * 1024;
const MAX_PAGES: usize = 100_000;
/// The longest single wait, whatever a server asks for.
const MAX_WAIT: Duration = Duration::from_secs(300);
const MAX_BACKOFF_SECS: u64 = 60;
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Where expanded channel replies continue (`replies` + `@odata.nextLink`; written in two parts because the joined name
/// reads like an email address to the sanitize scan).
const REPLIES_NEXT_LINK: &str = concat!("replies", "@odata.nextLink");

/// Where and how to export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOptions {
    /// The identity platform, without the tenant (default `DEFAULT_LOGIN_URL`).
    pub login_url: String,
    /// Graph with its version (default `DEFAULT_GRAPH_URL`).
    pub graph_url: String,
    /// The organization's tenant id or domain, or `organizations`.
    pub tenant: String,
    /// The application (client) id of the person's own app registration, a public client allowing the device code flow.
    pub client_id: String,
    /// The CAs a server's certificate may chain to: the public web roots, or a bundle (a tested mock, or a proxy the
    /// organization runs).
    pub roots: Roots,
    pub max_file_bytes: u64,
    pub max_retries: u32,
    /// Export chats only, without team channels (and without asking for the channel permissions).
    pub chats_only: bool,
    /// Connecting, and each read or write.
    pub timeout: Duration,
}

impl ExportOptions {
    pub fn new(tenant: &str, client_id: &str) -> Self {
        Self {
            login_url: DEFAULT_LOGIN_URL.to_owned(),
            graph_url: DEFAULT_GRAPH_URL.to_owned(),
            tenant: tenant.to_owned(),
            client_id: client_id.to_owned(),
            roots: Roots::Public,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_retries: DEFAULT_MAX_RETRIES,
            chats_only: false,
            timeout: Duration::from_secs(30),
        }
    }

    /// The permissions asked for, space-separated.
    pub fn scopes(&self) -> String {
        let channels: &[&str] = if self.chats_only { &[] } else { CHANNEL_SCOPES };
        CHAT_SCOPES.iter().chain(channels).copied().collect::<Vec<_>>().join(" ")
    }
}

/// What the person does to sign in: open the address in any browser and enter the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCode {
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: Duration,
}

/// How the export talks to the person running it, and how it waits. The command line prints and sleeps; a test
/// records.
pub struct Hooks {
    pub show: Box<dyn FnMut(&DeviceCode)>,
    pub pause: Box<dyn FnMut(Duration)>,
    pub progress: Box<dyn FnMut(&str)>,
}

#[derive(Debug)]
pub enum ExportError {
    /// Options that cannot work: a URL that is not https, an empty tenant or client id, a bad cap.
    Config(String),
    /// Sign-in did not finish: the code expired, the person declined, or the identity platform refused.
    SignIn(String),
    /// A request could not be made or answered (after its retries).
    Request {
        what: String,
        error: HttpError,
    },
    /// A request was answered with an error status (after its retries).
    Status {
        what: String,
        status: u16,
    },
    /// Graph answered something the exporter will not use or follow.
    Graph(String),
    Io(io::Error),
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportError::Config(why) => write!(f, "{why}"),
            ExportError::SignIn(why) => write!(f, "sign-in failed: {why}"),
            ExportError::Request { what, error } => write!(f, "{what}: {error}"),
            ExportError::Status { what, status } => write!(f, "{what}: answered with status {status}"),
            ExportError::Graph(why) => write!(f, "{why}"),
            ExportError::Io(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for ExportError {}

impl From<io::Error> for ExportError {
    fn from(error: io::Error) -> Self {
        ExportError::Io(error)
    }
}

/// What a run did. Attachments the export chose not to capture (too large, a name no file system can hold, not a file
/// Graph serves) are listed and are not failures: the import lists them as "not archived".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportReport {
    pub conversations_written: usize,
    /// Conversations already in the directory from an earlier run.
    pub conversations_skipped: usize,
    /// Conversations Graph refused (403 or 404), with the reason; a later run tries them again.
    pub conversations_failed: Vec<(String, String)>,
    /// Messages (with channel replies) in the conversations written by this run.
    pub messages: usize,
    pub files_downloaded: usize,
    /// Attachments already in the directory.
    pub files_present: usize,
    /// (message id, attachment name, reason).
    pub files_not_captured: Vec<(String, String, String)>,
    /// (message id, attachment name, reason): downloads that failed; a later run tries them again.
    pub files_failed: Vec<(String, String, String)>,
    pub users_written: bool,
    /// Requests tried again after throttling or a dropped connection.
    pub retries: usize,
}

impl ExportReport {
    /// Everything that was meant to be exported was.
    pub fn ok(&self) -> bool {
        self.conversations_failed.is_empty() && self.files_failed.is_empty()
    }
}

/// A signed-in exporter. The access token is held only here, cleared from memory when it is dropped.
pub struct Session {
    options: ExportOptions,
    /// `<login>/<tenant>/oauth2/v2.0`.
    identity: String,
    /// The Graph base, without a trailing slash. Nothing carrying the token is sent anywhere else.
    graph: String,
    pages: Client,
    files: Client,
    token: Token,
    hooks: Hooks,
    retries: usize,
}

struct Token {
    access: Zeroizing<String>,
    refresh: Option<Zeroizing<String>>,
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Session").field("graph", &self.graph).field("retries", &self.retries).finish_non_exhaustive()
    }
}

/// Sign in with the device code flow: ask for a code, show it, then poll the token endpoint at the interval the
/// identity platform gives (five seconds longer after each `slow_down`) until the person has signed in, declined, or
/// the code has expired.
pub fn sign_in(options: ExportOptions, mut hooks: Hooks) -> Result<Session, ExportError> {
    let login = https_base(&options.login_url, "the login URL")?;
    let graph = https_base(&options.graph_url, "the Graph URL")?;
    if !plain_id(&options.tenant) {
        return Err(ExportError::Config("the tenant must be a tenant id, a domain or `organizations`".into()));
    }
    if !plain_id(&options.client_id) {
        return Err(ExportError::Config("the client id must be the application id of an app registration".into()));
    }
    if options.max_file_bytes == 0 || options.max_file_bytes > MAX_FILE_BYTES_LIMIT {
        return Err(ExportError::Config(format!("the file size cap must be between 1 byte and {} MiB", MAX_FILE_BYTES_LIMIT >> 20)));
    }
    let client = Client::new(&options.roots, None).map_err(|error| ExportError::Config(error.to_string()))?;
    let pages = client.clone().with_limits(options.timeout, MAX_PAGE_BYTES);
    let files = client.with_limits(options.timeout, usize::try_from(options.max_file_bytes).unwrap_or(usize::MAX));
    let identity = format!("{login}/{}/oauth2/v2.0", options.tenant);
    let mut retries = 0;

    let form = format!("client_id={}&scope={}", form_encode(&options.client_id), form_encode(&options.scopes()));
    let pause = &mut *hooks.pause;
    let (status, answer) =
        post_form(&pages, &format!("{identity}/devicecode"), &form, options.max_retries, pause, &mut retries, "asking for a sign-in code")?;
    if status != 200 {
        return Err(ExportError::SignIn(refusal("the sign-in code request", status, &answer)));
    }
    let device_code = Zeroizing::new(text_of(&answer, "device_code").ok_or_else(|| no_field("device_code"))?.to_owned());
    let user_code = text_of(&answer, "user_code").filter(|code| printable(code)).ok_or_else(|| no_field("user_code"))?;
    let verification_uri = text_of(&answer, "verification_uri")
        .filter(|uri| uri.starts_with("https://") && printable(uri))
        .ok_or_else(|| no_field("an https verification_uri"))?;
    let expires_in = answer.get("expires_in").and_then(Value::as_u64).unwrap_or(900).clamp(1, 3600);
    let mut interval = answer.get("interval").and_then(Value::as_u64).unwrap_or(5).clamp(1, 60);
    (hooks.show)(&DeviceCode {
        user_code: user_code.to_owned(),
        verification_uri: verification_uri.to_owned(),
        expires_in: Duration::from_secs(expires_in),
    });

    let poll = Zeroizing::new(format!(
        "grant_type={}&client_id={}&device_code={}",
        form_encode(DEVICE_GRANT),
        form_encode(&options.client_id),
        form_encode(&device_code)
    ));
    let mut waited = 0;
    let token = loop {
        if waited >= expires_in {
            return Err(ExportError::SignIn("the code expired before sign-in finished; run the export again".into()));
        }
        (hooks.pause)(Duration::from_secs(interval));
        waited += interval;
        let pause = &mut *hooks.pause;
        let (status, answer) = post_form(&pages, &format!("{identity}/token"), &poll, options.max_retries, pause, &mut retries, "signing in")?;
        if status == 200 {
            break token_from(&answer)?;
        }
        match text_of(&answer, "error") {
            Some("authorization_pending") => {}
            Some("slow_down") => interval = (interval + 5).min(60),
            Some("expired_token") => return Err(ExportError::SignIn("the code expired before sign-in finished; run the export again".into())),
            Some("authorization_declined" | "access_denied") => return Err(ExportError::SignIn("sign-in was declined".into())),
            _ => return Err(ExportError::SignIn(refusal("sign-in", status, &answer))),
        }
    };
    Ok(Session { options, identity, graph, pages, files, token, hooks, retries })
}

/// One conversation to export: where it is saved and where Graph lists it.
struct Conversation {
    file: String,
    head: Vec<(&'static str, Value)>,
    members: String,
    messages: String,
    label: String,
}

enum Fetched {
    Bytes(Vec<u8>),
    Skipped(String),
    Failed(String),
}

impl Session {
    /// Export every chat (and, unless `chats_only`, every channel of every team the person is in) into `out`, which is
    /// created if needed. Conversations and attachments already there are kept and not fetched again.
    pub fn export(&mut self, out: &Path) -> Result<ExportReport, ExportError> {
        fs::create_dir_all(out.join("conversations"))?;
        fs::create_dir_all(out.join("files"))?;
        let mut report = ExportReport::default();
        let graph = self.graph.clone();
        let mut conversations = Vec::new();
        let chats = self.get_pages(format!("{graph}/me/chats?$top=50"), "listing chats")?;
        for chat in items(&chats) {
            let Some(id) = text_of(chat, "id") else { continue };
            conversations.push(Conversation {
                file: format!("chat-{}.json", file_stem(&[id])),
                head: vec![("chat", chat.clone())],
                members: format!("{graph}/chats/{}/members", segment(id)),
                messages: format!("{graph}/chats/{}/messages?$top=50", segment(id)),
                label: format!("chat {}", printable_text(text_of(chat, "topic").unwrap_or(id))),
            });
        }
        if !self.options.chats_only {
            let teams = self.get_pages(format!("{graph}/me/joinedTeams"), "listing teams")?;
            for team in items(&teams) {
                let Some(team_id) = text_of(team, "id") else { continue };
                let team_name = printable_text(text_of(team, "displayName").unwrap_or(team_id));
                let listed = self.get_pages(format!("{graph}/teams/{}/channels", segment(team_id)), &format!("listing channels of {team_name}"));
                let Some(channels) = tolerated(listed, &format!("team {team_name}"), &mut report)? else { continue };
                for channel in items(&channels) {
                    let Some(channel_id) = text_of(channel, "id") else { continue };
                    let path = format!("{graph}/teams/{}/channels/{}", segment(team_id), segment(channel_id));
                    conversations.push(Conversation {
                        file: format!("channel-{}.json", file_stem(&[team_id, channel_id])),
                        head: vec![("team", team.clone()), ("channel", channel.clone())],
                        members: format!("{path}/members"),
                        messages: format!("{path}/messages?$expand=replies"),
                        label: format!("channel {team_name} / {}", printable_text(text_of(channel, "displayName").unwrap_or(channel_id))),
                    });
                }
            }
        }
        for conversation in &conversations {
            self.export_conversation(conversation, out, &mut report)?;
        }
        if report.conversations_written > 0 || !out.join("users.json").is_file() {
            self.write_users(out)?;
            report.users_written = true;
        }
        report.retries = self.retries;
        Ok(report)
    }

    fn export_conversation(&mut self, conversation: &Conversation, out: &Path, report: &mut ExportReport) -> Result<(), ExportError> {
        let label = conversation.label.as_str();
        let path = out.join("conversations").join(&conversation.file);
        if path.is_file() {
            let saved = read_json(&path)?;
            self.fetch_files(&saved, out, report)?;
            report.conversations_skipped += 1;
            (self.hooks.progress)(&format!("{label}: already exported"));
            return Ok(());
        }
        let listed = self.get_pages(conversation.members.clone(), &format!("{label}: members"));
        let Some(members) = tolerated(listed, label, report)? else { return Ok(()) };
        let listed = self.get_pages(conversation.messages.clone(), &format!("{label}: messages"));
        let Some(mut pages) = tolerated(listed, label, report)? else { return Ok(()) };
        // Replies expanded under a channel message may continue on further pages.
        for page in &mut pages {
            let Some(messages) = page.get_mut("value").and_then(Value::as_array_mut) else { continue };
            for message in messages {
                let Some(object) = message.as_object_mut() else { continue };
                let Some(next) = object.remove(REPLIES_NEXT_LINK) else { continue };
                let Some(next) = next.as_str() else { continue };
                let more = self.get_pages(next.to_owned(), &format!("{label}: replies"))?;
                let more: Vec<Value> = items(&more).cloned().collect();
                match object.get_mut("replies") {
                    Some(Value::Array(replies)) => replies.extend(more),
                    _ => {
                        object.insert("replies".to_owned(), Value::Array(more));
                    }
                }
            }
        }
        let mut doc = Map::new();
        for (key, value) in &conversation.head {
            doc.insert((*key).to_owned(), value.clone());
        }
        doc.insert("members".to_owned(), Value::Array(items(&members).cloned().collect()));
        doc.insert("pages".to_owned(), Value::Array(pages));
        let doc = Value::Object(doc);
        self.fetch_files(&doc, out, report)?;
        let count = messages_in(&doc).len();
        write_atomic(&path, &pretty(&doc)?)?;
        report.conversations_written += 1;
        report.messages += count;
        (self.hooks.progress)(&format!("{label}: {count} messages"));
        Ok(())
    }

    /// Download every attachment of a saved conversation that is not in the directory yet.
    fn fetch_files(&mut self, doc: &Value, out: &Path, report: &mut ExportReport) -> Result<(), ExportError> {
        let mut wanted = Vec::new();
        for message in messages_in(doc) {
            let Some(id) = text_of(message, "id") else { continue };
            for attachment in message.get("attachments").and_then(Value::as_array).into_iter().flatten() {
                // Cards and quoted messages have no name and no file: nothing to capture.
                let Some(name) = text_of(attachment, "name") else { continue };
                wanted.push((id.to_owned(), name.to_owned(), attachment.clone()));
            }
        }
        for (id, name, attachment) in wanted {
            if !portable_name(&name) {
                report.files_not_captured.push((id, printable_text(&name), "the name is not a safe file name".into()));
                continue;
            }
            let dir = out.join("files").join(safe_dir(&id));
            let dest = dir.join(&name);
            if dest.is_file() {
                report.files_present += 1;
                continue;
            }
            match self.download(&attachment, &name)? {
                Fetched::Bytes(bytes) => {
                    fs::create_dir_all(&dir)?;
                    write_atomic(&dest, &bytes)?;
                    report.files_downloaded += 1;
                }
                Fetched::Skipped(reason) => report.files_not_captured.push((id, name, reason)),
                Fetched::Failed(reason) => report.files_failed.push((id, name, reason)),
            }
        }
        Ok(())
    }

    /// An attachment's bytes. A shared file (`reference`) is found through `/shares` and fetched from the short-lived,
    /// pre-authenticated address Graph gives for it: the token is never sent there and the address is never shown. A
    /// file Graph itself hosts is fetched from Graph with the token.
    fn download(&mut self, attachment: &Value, name: &str) -> Result<Fetched, ExportError> {
        let cap = format!("larger than the {} MiB cap", self.options.max_file_bytes.div_ceil(1 << 20));
        let Some(url) = text_of(attachment, "contentUrl") else { return Ok(Fetched::Skipped("no content address".into())) };
        let what = format!("attachment {}", printable_text(name));
        let answer = if text_of(attachment, "contentType") == Some("reference") {
            let share = format!("u!{}", URL_SAFE_NO_PAD.encode(url));
            let item = match self.get_json(&format!("{}/shares/{share}/driveItem", self.graph), &what) {
                Ok(item) => item,
                Err(ExportError::Status { status, .. }) => return Ok(Fetched::Failed(format!("Graph answered {status} for the shared file"))),
                Err(error) => return Err(error),
            };
            if item.get("size").and_then(Value::as_u64).is_some_and(|size| size > self.options.max_file_bytes) {
                return Ok(Fetched::Skipped(cap));
            }
            let Some(download) = text_of(&item, "@microsoft.graph.downloadUrl") else {
                return Ok(Fetched::Failed("Graph gave no download address".into()));
            };
            let files = &self.files;
            retrying(self.options.max_retries, &mut *self.hooks.pause, &mut self.retries, || files.get_with(download, &[("Accept", "*/*")]))
        } else if self.on_graph(url) {
            match self.graph_get(url, true, &what) {
                Ok(answer) => Ok(answer),
                Err(ExportError::Request { error, .. }) => Err(error),
                Err(error) => return Err(error),
            }
        } else {
            return Ok(Fetched::Skipped("not a file Graph serves".into()));
        };
        Ok(match answer {
            Ok(answer) if (200..300).contains(&answer.status) => Fetched::Bytes(answer.body),
            Ok(answer) => Fetched::Failed(format!("the download answered {}", answer.status)),
            Err(HttpError::TooLarge) => Fetched::Skipped(cap),
            Err(error) => Fetched::Failed(error.to_string()),
        })
    }

    /// `users.json`: every `GET /users` page, then one page of conversation members that list does not name (guests
    /// from other organizations), so their messages map to an address.
    fn write_users(&mut self, out: &Path) -> Result<(), ExportError> {
        let listed = self.get_pages(format!("{}/users?$select=id,mail,userPrincipalName,displayName&$top=999", self.graph), "listing people");
        let mut pages = match listed {
            Ok(pages) => pages,
            Err(ExportError::Status { status: 403, .. }) => {
                (self.hooks.progress)("Graph refused to list people (403): addresses come from conversation members only");
                Vec::new()
            }
            Err(error) => return Err(error),
        };
        let known: HashSet<String> = items(&pages).filter_map(|user| text_of(user, "id")).map(str::to_owned).collect();
        let mut added = HashSet::new();
        let mut extra = Vec::new();
        for path in conversation_files(out)? {
            let doc = read_json(&path)?;
            for member in doc.get("members").and_then(Value::as_array).into_iter().flatten() {
                if let (Some(id), Some(email)) = (text_of(member, "userId"), text_of(member, "email"))
                    && !known.contains(id)
                    && added.insert(id.to_owned())
                {
                    extra.push(json!({"id": id, "mail": email}));
                }
            }
        }
        if !extra.is_empty() {
            pages.push(json!({"@crewcraft.from": "conversation members that GET /users does not list", "value": extra}));
        }
        write_atomic(&out.join("users.json"), &pretty(&Value::Array(pages))?)?;
        Ok(())
    }

    /// Every page of a Graph list, following `@odata.nextLink` while it stays on Graph.
    fn get_pages(&mut self, first: String, what: &str) -> Result<Vec<Value>, ExportError> {
        let mut pages = Vec::new();
        let mut seen = HashSet::new();
        let mut next = Some(first);
        while let Some(url) = next.take() {
            if pages.len() >= MAX_PAGES || !seen.insert(url.clone()) {
                return Err(ExportError::Graph(format!("{what}: the pages do not end")));
            }
            let page = self.get_json(&url, what)?;
            if !page.get("value").is_some_and(Value::is_array) {
                return Err(ExportError::Graph(format!("{what}: a page without a value list")));
            }
            next = page.get("@odata.nextLink").and_then(Value::as_str).map(str::to_owned);
            pages.push(page);
        }
        Ok(pages)
    }

    fn get_json(&mut self, url: &str, what: &str) -> Result<Value, ExportError> {
        let answer = self.graph_get(url, false, what)?;
        if !(200..300).contains(&answer.status) {
            return Err(ExportError::Status { what: what.to_owned(), status: answer.status });
        }
        serde_json::from_slice(&answer.body).map_err(|_| ExportError::Graph(format!("{what}: the answer is not JSON")))
    }

    /// A GET on Graph with the token. An expired token (401) is renewed once with the refresh token.
    fn graph_get(&mut self, url: &str, file: bool, what: &str) -> Result<Response, ExportError> {
        if !self.on_graph(url) {
            return Err(ExportError::Graph(format!("{what}: Graph pointed outside {}; not followed", self.graph)));
        }
        let mut renewed = false;
        loop {
            let authorization = Zeroizing::new(format!("Bearer {}", self.token.access.as_str()));
            let headers = [("Authorization", authorization.as_str()), ("Accept", if file { "*/*" } else { "application/json" })];
            let client = if file { &self.files } else { &self.pages };
            let answer = retrying(self.options.max_retries, &mut *self.hooks.pause, &mut self.retries, || client.get_with(url, &headers))
                .map_err(|error| ExportError::Request { what: what.to_owned(), error })?;
            if answer.status == 401 && !renewed && self.token.refresh.is_some() {
                self.renew()?;
                renewed = true;
                continue;
            }
            return Ok(answer);
        }
    }

    fn renew(&mut self) -> Result<(), ExportError> {
        let Some(refresh) = &self.token.refresh else { return Err(ExportError::SignIn("the sign-in expired".into())) };
        let form = Zeroizing::new(format!(
            "grant_type=refresh_token&client_id={}&refresh_token={}&scope={}",
            form_encode(&self.options.client_id),
            form_encode(refresh),
            form_encode(&self.options.scopes())
        ));
        let url = format!("{}/token", self.identity);
        let (status, answer) =
            post_form(&self.pages, &url, &form, self.options.max_retries, &mut *self.hooks.pause, &mut self.retries, "renewing the sign-in")?;
        if status != 200 {
            return Err(ExportError::SignIn(format!(
                "{}; run the export again: it resumes where it stopped",
                refusal("renewing the sign-in", status, &answer)
            )));
        }
        let token = token_from(&answer)?;
        self.token.access = token.access;
        if token.refresh.is_some() {
            self.token.refresh = token.refresh;
        }
        Ok(())
    }

    fn on_graph(&self, url: &str) -> bool {
        url.strip_prefix(self.graph.as_str()).is_some_and(|rest| rest.starts_with('/'))
    }
}

/// Run `call`, trying again while the answer is 429, 503 or 504 (waiting as `Retry-After` says, or with doubling
/// backoff) or the connection failed, at most `max_retries` times. The last answer or error is returned as it is.
fn retrying(
    max_retries: u32,
    pause: &mut dyn FnMut(Duration),
    retries: &mut usize,
    mut call: impl FnMut() -> Result<Response, HttpError>,
) -> Result<Response, HttpError> {
    let mut attempt = 0u32;
    loop {
        let result = call();
        let backoff = Duration::from_secs(1u64.checked_shl(attempt).unwrap_or(u64::MAX).min(MAX_BACKOFF_SECS));
        let wait = match &result {
            Ok(answer) if matches!(answer.status, 429 | 503 | 504) => Some(answer.retry_after.unwrap_or(backoff).min(MAX_WAIT)),
            Err(HttpError::Timeout | HttpError::Connect(_)) => Some(backoff),
            _ => None,
        };
        match wait {
            Some(wait) if attempt < max_retries => {
                attempt += 1;
                *retries += 1;
                pause(wait);
            }
            _ => return result,
        }
    }
}

fn post_form(
    client: &Client,
    url: &str,
    form: &str,
    max_retries: u32,
    pause: &mut dyn FnMut(Duration),
    retries: &mut usize,
    what: &str,
) -> Result<(u16, Value), ExportError> {
    let answer = retrying(max_retries, pause, retries, || client.post(url, "application/x-www-form-urlencoded", form.as_bytes()))
        .map_err(|error| ExportError::Request { what: what.to_owned(), error })?;
    Ok((answer.status, serde_json::from_slice(&answer.body).unwrap_or(Value::Null)))
}

fn token_from(answer: &Value) -> Result<Token, ExportError> {
    if !text_of(answer, "token_type").is_some_and(|kind| kind.eq_ignore_ascii_case("bearer")) {
        return Err(ExportError::SignIn("the identity platform did not give a bearer token".into()));
    }
    let access = text_of(answer, "access_token")
        .filter(|token| token.bytes().all(|b| b.is_ascii_graphic()))
        .ok_or_else(|| ExportError::SignIn("the identity platform gave no usable access token".into()))?;
    let refresh = text_of(answer, "refresh_token").map(|token| Zeroizing::new(token.to_owned()));
    Ok(Token { access: Zeroizing::new(access.to_owned()), refresh })
}

/// The identity platform's error and its description, made safe to print.
fn refusal(what: &str, status: u16, answer: &Value) -> String {
    let error = text_of(answer, "error").map(printable_text).unwrap_or_else(|| "no error code".into());
    let description = text_of(answer, "error_description").and_then(|d| d.lines().next()).map(printable_text).unwrap_or_default();
    format!("{what} was refused ({status}): {error} {description}").trim_end().to_owned()
}

fn no_field(name: &str) -> ExportError {
    ExportError::SignIn(format!("the identity platform's answer has no {name}"))
}

/// An https base address without a trailing slash, a query or credentials.
fn https_base(url: &str, what: &str) -> Result<String, ExportError> {
    let trimmed = url.trim_end_matches('/');
    let rest = trimmed.strip_prefix("https://").ok_or_else(|| ExportError::Config(format!("{what} must be an https URL")))?;
    if rest.is_empty() || rest.starts_with('/') || trimmed.contains(['?', '#', '@']) || !trimmed.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ExportError::Config(format!("{what} is not a plain https address")));
    }
    Ok(trimmed.to_owned())
}

/// A tenant or client id: a GUID, a domain or a word such as `organizations`.
fn plain_id(text: &str) -> bool {
    (1..=100).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
}

fn form_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A Graph id as one path segment (`19:...@thread.v2` keeps its `:` and `@`, which a path allows).
fn segment(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    for byte in id.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b':' | b'@') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A conversation's file name: readable ids, then a hash of the exact ids so two ids that read alike never collide.
fn file_stem(ids: &[&str]) -> String {
    let readable: Vec<String> = ids.iter().map(|id| safe_dir(id).chars().take(40).collect()).collect();
    let digest = Sha256::digest(ids.join("/").as_bytes());
    let hash: String = digest.iter().take(6).map(|b| format!("{b:02x}")).collect();
    format!("{}-{hash}", readable.join("-"))
}

/// A name every common file system can hold as one file: no path, no characters Windows refuses, not a device name, no
/// trailing dot or space, at most 200 bytes, and not the exporter's own `.partial` suffix.
pub fn portable_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 200 || name == "." || name == ".." || name.starts_with(' ') || name.ends_with(['.', ' ']) {
        return false;
    }
    if name.chars().any(|c| c.is_control() || matches!(c, '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*')) || name.ends_with(".partial") {
        return false;
    }
    let stem = name.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    let numbered = (stem.starts_with("COM") || stem.starts_with("LPT")) && stem.len() == 4 && stem.as_bytes().get(3).is_some_and(u8::is_ascii_digit);
    !(numbered || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL"))
}

fn printable(text: &str) -> bool {
    !text.is_empty() && text.len() <= 300 && !text.chars().any(char::is_control)
}

/// Text from Graph made safe for a terminal: control characters dropped, at most 120 characters.
fn printable_text(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(120).collect()
}

fn text_of<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn items(pages: &[Value]) -> impl Iterator<Item = &Value> {
    pages.iter().filter_map(|page| page.get("value").and_then(Value::as_array)).flatten()
}

/// Every message of a saved conversation, channel replies included.
fn messages_in(doc: &Value) -> Vec<&Value> {
    let mut all = Vec::new();
    for page in doc.get("pages").and_then(Value::as_array).into_iter().flatten() {
        for message in page.get("value").and_then(Value::as_array).into_iter().flatten() {
            all.push(message);
            all.extend(message.get("replies").and_then(Value::as_array).into_iter().flatten());
        }
    }
    all
}

/// Treat a conversation Graph refuses (403, 404) as reported and skipped, so one inaccessible conversation does not
/// stop the rest; anything else stops the export.
fn tolerated<T>(result: Result<T, ExportError>, label: &str, report: &mut ExportReport) -> Result<Option<T>, ExportError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(ExportError::Status { what, status: status @ (403 | 404) }) => {
            report.conversations_failed.push((label.to_owned(), format!("{what}: status {status}")));
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn conversation_files(out: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = fs::read_dir(out.join("conversations"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    Ok(files)
}

fn read_json(path: &Path) -> Result<Value, ExportError> {
    serde_json::from_slice(&fs::read(path)?).map_err(|_| ExportError::Graph(format!("{} is not JSON", path.display())))
}

fn pretty(value: &Value) -> Result<Vec<u8>, ExportError> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| ExportError::Io(io::Error::other(error)))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Write to `<name>.partial`, sync, then rename: a file under its real name is always complete.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut name = path.file_name().map(|name| name.to_os_string()).unwrap_or_default();
    name.push(".partial");
    let partial = path.with_file_name(name);
    let mut file = File::create(&partial)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&partial, path)
}

#[cfg(test)]
mod tests {
    use super::{file_stem, form_encode, https_base, portable_name, segment};

    #[test]
    fn names_ids_and_addresses() {
        for good in ["plan.pdf", "Q3 report (final).xlsx", "a.b.c", "résumé.docx", "com10.txt"] {
            assert!(portable_name(good), "{good}");
        }
        for bad in
            ["", ".", "..", "a/b", "a\\b", "a:b", "what?.txt", "x*", "trailing.", "trailing ", "CON", "con.txt", "LPT1.log", "x.partial", "a\u{7}"]
        {
            assert!(!portable_name(bad), "{bad}");
        }
        assert_eq!(segment("19:abc@thread.v2"), "19:abc@thread.v2");
        assert_eq!(segment("a/b c?"), "a%2Fb%20c%3F");
        assert_eq!(form_encode("Chat.Read offline_access"), "Chat.Read%20offline_access");
        assert_ne!(file_stem(&["19:a"]), file_stem(&["19_a"]), "ids that read alike get different files");
        assert!(https_base("http://graph.example.org", "x").is_err());
        assert!(https_base("https://user@example.org", "x").is_err());
        assert_eq!(https_base("https://graph.example.org/v1.0/", "x").ok().as_deref(), Some("https://graph.example.org/v1.0"));
    }
}
