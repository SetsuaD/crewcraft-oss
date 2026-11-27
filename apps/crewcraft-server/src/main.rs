//! CrewCraft server binary.
//!
//! `first-run`, `serve`, `invite`, `room` and `add-member` run a network server from one data directory whose recorded
//! settings (`server.conf`) name the server and the address it listens on (task T231). The `lab` commands keep the
//! loopback-only lab, which pins its root from a separate file. While `serve` runs, `invite`, `room` and `add-member`
//! send their request to it over its control socket (Unix, task T238) instead of opening the directory.

use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read, Write};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft_accounts::identity::normalize_email;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::request::{
    FEATURE_ACTIVITY, FEATURE_ARCHIVE, FEATURE_CALLS, FEATURE_CONTINUE, FEATURE_FILE_LIST, FEATURE_FILES, FEATURE_GAP_REPLAY, FEATURE_GUEST_MEETINGS,
    FEATURE_LIST_ROOMS, FEATURE_MEETINGS, FEATURE_PINS_SAVED, FEATURE_REACTIONS, FEATURE_READ_STATE, FEATURE_ROOM_SETTINGS, FEATURE_SEARCH,
    FEATURE_THREADS,
};
#[cfg(unix)]
use crewcraft_server::control::{ControlClient, ControlSocket};
use crewcraft_server::guest_lab;
use crewcraft_server::identity_config;
use crewcraft_server::lab_admin::{self, DisplayFailed, IssuedCode, ProtectedDisplay};
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use crewcraft_server::server_install::{self, ServerConfig};
use crewcraft_server::server_name::ServerName;
use crewcraft_server_core::room::Role;
use sha2::{Digest, Sha256};

const MAX_ROOT_DER: u64 = 16 * 1024;
const PUBLIC_ROOT: &str = server_install::PUBLIC_ROOT;

const USAGE: &str = "\
crewcraft-server first-run <new-data-directory> --name <server-name> --admin <email> [--listen <address:port>] [--public-port <port>]
    Create a server: its certificate authority, settings and public root (trust-root.der), and an invitation for
    the administrator, shown as a crewcraft://enroll link. The server name is the DNS name or IP address clients
    use. The listen address defaults to 127.0.0.1:7443; use 0.0.0.0:7443 or [::]:7443 for every interface.
    Behind port forwarding, --public-port is the port people connect to; invitations carry it.
    Run it in a private interactive terminal, or pass --invitation-file <new-file> for a scripted install: the
    invitation is then written to that new file, readable by its owner only. An existing directory is never changed.
crewcraft-server serve <data-directory>
    Serve with the recorded name and listen address until interrupted.
crewcraft-server invite <data-directory> <email> [--invitation-file <new-file>]
    Invite a person; shows the code and link in a private interactive terminal, or writes them to a new owner-only
    file.
crewcraft-server room <data-directory> <owner> <name>
crewcraft-server add-member <data-directory> <room> <owner> <member>
crewcraft-server import <data-directory> --bundle <bundle-directory> [--map-domain <old>=<new>]... [--dry-run]
    Import history from another system as read-only archive rooms (docs/IMPORT.md), with the server stopped. Safe to
    run again: a second run adds nothing, a later export adds what is new. Writes import-report.json into the bundle
    directory and exits non-zero when any part of the bundle was refused. --dry-run changes nothing.
crewcraft-server export-teams --tenant <tenant> --client-id <application-id> --out <export-directory> [--chats-only]
        [--max-file-mb <n>] [--login-url <https-url>] [--graph-url <https-url>] [--ca-file <pem>]
    Export your own Microsoft Teams chats and channels through Microsoft Graph into the layout import-teams reads
    (docs/IMPORT.md). Sign in with the code it shows; the token stays in memory. Read-only permissions only.
    Running it again into the same directory resumes: what is already written is kept. Exits non-zero when a
    conversation or an attachment could not be exported.
crewcraft-server import-teams --export <teams-export-directory> --out <new-bundle-directory>
    Turn saved Microsoft Graph chat and channel pages into an import bundle (docs/IMPORT.md). Exits non-zero, after
    writing the bundle, when messages were left out because users.json does not name their sender.
crewcraft-server rebind <data-directory> <email> --issuer <issuer> --subject <subject>
    Bind an enrolled person to another identity at the organization's provider (for example after their account there
    was recreated), with the server stopped. Every re-bind is written to the audit log first-hand.
crewcraft-server audit <data-directory>
    Show the audit log of administrative actions and check its hash chain; exits non-zero if it does not check out.
crewcraft-server media-link-cert <data-directory> <media-server-name> <media-output-directory>
    Issue the certificates for the control connection to the media server (docs/CALLS.md): a new link CA of their
    own, the media server's certificate for <media-server-name> and this server's client certificate, good for 30
    days. Writes media-ca.pem, media-client.pem and media-client-key.pem into the data directory, and media.pem,
    media-key.pem and chat-ca.pem into the output directory for the media server, keys owner-only. Run it again to
    rotate: it replaces the files; copy the three new ones to the media server and restart both servers.
crewcraft-server lab init <new-state-directory>
crewcraft-server lab invite <state-directory> <trusted-root.der> <email>
crewcraft-server lab serve <state-directory> <trusted-root.der> <port>
crewcraft-server lab room <state-directory> <trusted-root.der> <owner> <name>
crewcraft-server lab add-member <state-directory> <trusted-root.der> <room> <owner> <member>
";

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crewcraft-server: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[OsString]) -> io::Result<()> {
    match args {
        [] => version(),
        [flag] if flag == "--version" => version(),
        [flag] if flag == "--help" || flag == "help" => print!("{USAGE}"),
        [command, data, rest @ ..] if command == "first-run" => first_run(Path::new(data), rest)?,
        [command, data] if command == "serve" => serve(Path::new(data))?,
        [command, data, email] if command == "invite" => invite(Path::new(data), text_arg(email)?, None)?,
        [command, data, email, flag, path] if command == "invite" && flag == "--invitation-file" => {
            invite(Path::new(data), text_arg(email)?, Some(Path::new(path)))?
        }
        [command, data, rest @ ..] if command == "import" => import(Path::new(data), rest)?,
        [command, data, email, f1, issuer, f2, subject] if command == "rebind" && f1 == "--issuer" && f2 == "--subject" => {
            rebind(Path::new(data), &lab_email(email)?, text_arg(issuer)?, text_arg(subject)?)?
        }
        [command, data] if command == "audit" => show_audit(Path::new(data))?,
        [command, data, name, out] if command == "media-link-cert" => {
            let until = crewcraft_server::media_link::issue_link(Path::new(data), Path::new(out), text_arg(name)?, now_ms())?;
            println!("Media link certificates issued, good until {until} (Unix seconds); rotate before then.");
            println!("Copy media.pem, media-key.pem and chat-ca.pem from {} to the media server.", Path::new(out).display());
        }
        [command, rest @ ..] if command == "export-teams" => export_teams(rest)?,
        [command, f1, export, f2, out] if command == "import-teams" && f1 == "--export" && f2 == "--out" => {
            import_teams(Path::new(export), Path::new(out))?
        }
        [command, data, owner, name] if command == "room" => println!("Room {}", create_room(Path::new(data), owner, name)?),
        [command, data, room, owner, member] if command == "add-member" => {
            add_member(Path::new(data), room, owner, member)?;
            println!("Member added.");
        }
        [lab, init, state] if lab == "lab" && init == "init" => init_lab(Path::new(state))?,
        [lab, invite, state, root, email] if lab == "lab" && invite == "invite" => {
            let email = email.to_str().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid email"))?;
            invite_to_lab(Path::new(state), Path::new(root), email)?;
        }
        [lab, serve, state, root, port] if lab == "lab" && serve == "serve" => {
            let port = port.to_str().and_then(|value| value.parse::<u16>().ok());
            let port = port.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid lab port"))?;
            serve_lab(Path::new(state), Path::new(root), port)?;
        }
        [lab, room, state, root, owner, name] if lab == "lab" && room == "room" => {
            let mut lab = lab_admin::reopen(Path::new(state), root_fingerprint(Path::new(root))?, now_ms()).map_err(lab_error)?;
            let owner = lab_email(owner)?;
            let name = text_arg(name)?;
            let slug = lab.rooms.create_room(&owner, name).map_err(lab_error)?;
            println!("Room {slug}");
        }
        [lab, add, state, root, room, owner, member] if lab == "lab" && add == "add-member" => {
            let mut lab = lab_admin::reopen(Path::new(state), root_fingerprint(Path::new(root))?, now_ms()).map_err(lab_error)?;
            let owner = lab_email(owner)?;
            let member = lab_email(member)?;
            lab.rooms.add_member(text_arg(room)?, &owner, &member, Role::Member).map_err(lab_error)?;
            println!("Member added.");
        }
        _ => {
            eprint!("{USAGE}");
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unknown command"));
        }
    }
    Ok(())
}

fn version() {
    let (major, minor) = crewcraft_server_core::PROTOCOL_VERSION;
    println!("crewcraft-server {} (protocol {major}.{minor})", env!("CARGO_PKG_VERSION"));
}

fn init_lab(state: &Path) -> io::Result<()> {
    let (_installation, root) = lab_admin::init(state, now_ms()).map_err(lab_error)?;
    let root_path = state.join(PUBLIC_ROOT);
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&root_path)?;
    file.write_all(&root.certificate_der)?;
    file.sync_all()?;
    #[cfg(unix)]
    File::open(state)?.sync_all()?;
    println!("Trusted root {}", root_path.display());
    println!("SHA-256 {}", RootFingerprint::from_der(&root.certificate_der));
    Ok(())
}

struct OperatorTerminal(std::io::Stdout);

impl ProtectedDisplay for OperatorTerminal {
    fn show(&mut self, issued: &IssuedCode<'_>) -> Result<(), DisplayFailed> {
        writeln!(self.0, "Private invitation for {}\n{}", issued.email(), issued.code()).map_err(|_| DisplayFailed)?;
        self.0.flush().map_err(|_| DisplayFailed)
    }
}

fn invite_to_lab(state: &Path, trusted_root: &Path, email: &str) -> io::Result<()> {
    let stdout = io::stdout();
    if !io::stdin().is_terminal() || !stdout.is_terminal() {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "show invitations in a private interactive terminal"));
    }
    let mut installation = lab_admin::reopen(state, root_fingerprint(trusted_root)?, now_ms()).map_err(lab_error)?;
    let mut display = OperatorTerminal(stdout);
    lab_admin::invite(&mut installation.accounts, email, None, now_ms(), &mut display).map_err(lab_error)?;
    Ok(())
}

fn lab_error(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

fn text_arg(value: &OsString) -> io::Result<&str> {
    value.to_str().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid text argument"))
}

fn lab_email(input: &OsString) -> io::Result<String> {
    normalize_email(text_arg(input)?).map_err(lab_error)
}

fn root_fingerprint(path: &Path) -> io::Result<[u8; 32]> {
    let mut root_der = Vec::new();
    File::open(path)?.take(MAX_ROOT_DER + 1).read_to_end(&mut root_der)?;
    if root_der.is_empty() || root_der.len() as u64 > MAX_ROOT_DER {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid trusted root certificate size"));
    }
    Ok(Sha256::digest(root_der).into())
}

struct FirstRun {
    name: ServerName,
    admin: String,
    listen: SocketAddr,
    public_port: Option<u16>,
    invitation_file: Option<PathBuf>,
}

fn parse_first_run(flags: &[OsString]) -> io::Result<FirstRun> {
    let (mut name, mut admin, mut listen, mut public_port, mut invitation_file) = (None, None, None, None, None);
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        let value = text_arg(flags.next().ok_or_else(|| usage("every first-run option takes a value"))?)?;
        let given_twice = match text_arg(flag)? {
            "--name" => name.replace(ServerName::parse(value).map_err(|error| usage_owned(error.to_string()))?).is_some(),
            "--admin" => admin.replace(normalize_email(value).map_err(|_| usage("--admin takes an email address"))?).is_some(),
            "--listen" => listen.replace(server_install::parse_listen(value).map_err(|error| usage_owned(error.to_string()))?).is_some(),
            "--public-port" => {
                let port =
                    value.parse::<u16>().ok().filter(|port| *port != 0).ok_or_else(|| usage("--public-port takes a port number (1 to 65535)"))?;
                public_port.replace(port).is_some()
            }
            "--invitation-file" => invitation_file.replace(PathBuf::from(value)).is_some(),
            _ => return Err(usage("first-run takes --name, --admin, --listen, --public-port and --invitation-file")),
        };
        if given_twice {
            return Err(usage("a first-run option was given twice"));
        }
    }
    let name = name.ok_or_else(|| usage("first-run needs --name <server-name>"))?;
    let admin = admin.ok_or_else(|| usage("first-run needs --admin <email>"))?;
    Ok(FirstRun { name, admin, listen: listen.unwrap_or_else(ServerConfig::default_listen), public_port, invitation_file })
}

fn first_run(data: &Path, flags: &[OsString]) -> io::Result<()> {
    let FirstRun { name, admin, listen, public_port, invitation_file } = parse_first_run(flags)?;
    // Creating the directory refuses an existing one atomically; this only refuses before asking for a terminal.
    if fs::symlink_metadata(data).is_ok() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "an installation already exists there; first-run never changes one"));
    }
    let out = match &invitation_file {
        Some(path) => {
            server_install::check_invitation_file(path)?;
            InvitationOut::File(path.clone())
        }
        None => {
            require_private_terminal(
                "run first-run in a private interactive terminal (it shows the administrator's invitation), or pass --invitation-file",
            )?;
            InvitationOut::Terminal(io::stdout())
        }
    };
    let config = ServerConfig { name, listen };
    let (mut installation, root) = server_install::create(data, &config, now_ms())?;
    if let Some(port) = public_port.filter(|port| *port != config.listen.port()) {
        server_install::write_public_port(data, port)?;
    }
    let server = server_install::link_server(&config, public_port);
    println!("Server {server}");
    println!("Listening on {}", config.listen);
    println!("Trusted root {}", data.join(PUBLIC_ROOT).display());
    println!("Root SHA-256 {}", RootFingerprint::from_der(&root.certificate_der));
    // A new server has no identity provider yet: the administrator chooses the way in.
    let mut display = LinkTerminal { out, server, root_sha256: root.sha256, signin: None };
    lab_admin::invite(&mut installation.accounts, &admin, None, now_ms(), &mut display).map_err(|error| {
        io::Error::other(format!("the server was created but the administrator was not invited ({error}); run invite to try again"))
    })?;
    if let Some(path) = invitation_file {
        println!("Invitation for {admin} written to {} (readable by its owner only)", path.display());
    }
    Ok(())
}

fn invite(data: &Path, email: &str, invitation_file: Option<&Path>) -> io::Result<()> {
    let out = match invitation_file {
        Some(path) => {
            server_install::check_invitation_file(path)?;
            InvitationOut::File(path.to_path_buf())
        }
        None => {
            require_private_terminal("show invitations in a private interactive terminal, or pass --invitation-file")?;
            InvitationOut::Terminal(io::stdout())
        }
    };
    // A running server issues the invitation itself (T238); the code comes back over its owner-only socket.
    #[cfg(unix)]
    if let Some(running) = ControlClient::connect(data) {
        let mut display = link_display(data, out)?;
        running.invite(email, |email, code| display.show_text(email, code).is_ok())?;
        if let Some(path) = invitation_file {
            println!("Invitation for {email} written to {} (readable by its owner only)", path.display());
        }
        return Ok(());
    }
    let (mut installation, _) = open_offline(data)?;
    let mut display = link_display(data, out)?;
    lab_admin::invite(&mut installation.accounts, email, None, now_ms(), &mut display).map_err(lab_error)?;
    if let Some(path) = invitation_file {
        println!("Invitation for {email} written to {} (readable by its owner only)", path.display());
    }
    Ok(())
}

/// How a link for this installation is shown: its recorded name and public port, and its root.
fn link_display(data: &Path, out: InvitationOut) -> io::Result<LinkTerminal> {
    let config = server_install::read_config(data)?;
    let root_sha256 = server_install::root_sha256(data)?;
    let server = server_install::link_server(&config, server_install::read_public_port(data)?);
    Ok(LinkTerminal { out, server, root_sha256, signin: invitation_signin(data)? })
}

/// How this installation's invitations say people sign in (T611k): through the organization when `identity.toml`
/// configures a provider (a file that does not parse is an error, as it is for `serve`), else unsaid.
fn invitation_signin(data: &Path) -> io::Result<Option<crewcraft_enroll::SignInWay>> {
    let path = data.join(identity_config::IDENTITY_FILE);
    match fs::read_to_string(&path) {
        Ok(text) => {
            identity_config::parse(&text).map_err(|error| usage_owned(format!("{}: {error}", path.display())))?;
            Ok(Some(crewcraft_enroll::SignInWay::Organization))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn create_room(data: &Path, owner: &OsString, name: &OsString) -> io::Result<String> {
    #[cfg(unix)]
    if let Some(running) = ControlClient::connect(data) {
        return running.create_room(&lab_email(owner)?, text_arg(name)?);
    }
    let (mut installation, _) = open_offline(data)?;
    installation.rooms.create_room(&lab_email(owner)?, text_arg(name)?).map_err(lab_error)
}

/// Who is acting at this terminal, for the audit log (task T611l): the operating system's user name, or "operator".
fn operator_name() -> String {
    let name = env::var("USER").or_else(|_| env::var("USERNAME")).unwrap_or_default();
    let name: String = name.chars().filter(|c| !c.is_control()).take(64).collect();
    if name.is_empty() { "operator".to_owned() } else { format!("operator {name}") }
}

/// `rebind` (task T611l): bind `email`'s person to `(issuer, subject)`, offline, and record it in the audit log.
fn rebind(data: &Path, email: &str, issuer: &str, subject: &str) -> io::Result<()> {
    let (mut installation, _) = open_offline(data)?;
    if installation.accounts.person(email).is_none() {
        return Err(usage_owned(format!("no one has enrolled as {email}")));
    }
    let before = installation.accounts.external_of(email).map(|(i, s)| format!("{i} {s}")).unwrap_or_else(|| "none".to_owned());
    installation.accounts.bind_external(email, issuer, subject).map_err(|error| match error {
        crewcraft_server_core::account_store::StoreError::ExternalInUse => usage_owned("that identity is already bound to another person".to_owned()),
        other => lab_error(other),
    })?;
    let action = crewcraft_server_core::admin::action_text(&["identity.rebind", email, "to", issuer, subject, "was", &before]);
    crewcraft_server::audit_file::append(data, &operator_name(), &action, now_ms())
        .map_err(|error| io::Error::other(format!("{email} was re-bound, but the audit entry could not be written: {error}")))?;
    println!("{email} now signs in as {subject} at {issuer} (was {before}). Recorded in {}.", crewcraft_server::audit_file::AUDIT_FILE);
    Ok(())
}

/// `audit` (task T611l): print the audit log and check its chain.
fn show_audit(data: &Path) -> io::Result<()> {
    let entries = crewcraft_server::audit_file::read(data)?;
    for entry in &entries {
        println!("{} {} {}: {}", entry.seq, entry.at_ms, entry.actor, entry.action);
    }
    match entries.last() {
        Some(last) => println!("{} entries; the chain checks out; head {}", entries.len(), server_install::hex(&last.hash)),
        None => println!("The audit log is empty."),
    }
    Ok(())
}

/// `import-teams` (docs/IMPORT.md, task T350c): read a Teams export into a new bundle directory.
fn import_teams(export: &Path, out: &Path) -> io::Result<()> {
    let report = crewcraft_server::import_teams::read_teams(export, out)?;
    println!("Bundle written to {}", out.display());
    println!("  {} conversations, {} messages", report.conversations, report.messages);
    println!("  {} attachments captured, {} not captured", report.files_captured, report.files_not_captured);
    if report.system_messages > 0 {
        println!("  {} system messages left out", report.system_messages);
    }
    if report.unmapped_senders.is_empty() {
        return Ok(());
    }
    let left_out: usize = report.unmapped_senders.values().sum();
    for (sender, count) in &report.unmapped_senders {
        println!("  sender {sender:?} is not in users.json: {count} messages left out");
    }
    Err(io::Error::other(format!("{left_out} messages were left out: add their senders to users.json and run it again into a new directory")))
}

/// `export-teams` (docs/IMPORT.md "Exporting from Teams", task T351): sign in with a device code and export the
/// person's chats and channels through Microsoft Graph.
fn export_teams(rest: &[OsString]) -> io::Result<()> {
    use crewcraft_server::export_teams::{ExportOptions, Hooks, MAX_FILE_BYTES_LIMIT, sign_in};
    let (mut tenant, mut client_id, mut out, mut ca_file) = (None, None, None::<PathBuf>, None::<PathBuf>);
    let (mut login_url, mut graph_url, mut max_file_mb, mut chats_only) = (None, None, None, false);
    let mut args = rest.iter();
    while let Some(flag) = args.next() {
        let flag = text_arg(flag)?;
        if flag == "--chats-only" {
            chats_only = true;
            continue;
        }
        let value = args.next().ok_or_else(|| usage_owned(format!("{flag} takes a value")))?;
        let slot = match flag {
            "--tenant" => tenant.replace(text_arg(value)?.to_owned()).is_some(),
            "--client-id" => client_id.replace(text_arg(value)?.to_owned()).is_some(),
            "--login-url" => login_url.replace(text_arg(value)?.to_owned()).is_some(),
            "--graph-url" => graph_url.replace(text_arg(value)?.to_owned()).is_some(),
            "--out" => out.replace(PathBuf::from(value)).is_some(),
            "--ca-file" => ca_file.replace(PathBuf::from(value)).is_some(),
            "--max-file-mb" => {
                let mb = text_arg(value)?.parse::<u64>().ok().filter(|mb| (1..=MAX_FILE_BYTES_LIMIT >> 20).contains(mb));
                max_file_mb.replace(mb.ok_or_else(|| usage("--max-file-mb takes a number of MiB from 1 to 1024"))?).is_some()
            }
            other => return Err(usage_owned(format!("unknown export-teams option {other:?}"))),
        };
        if slot {
            return Err(usage_owned(format!("{flag} is given twice")));
        }
    }
    let tenant = tenant.ok_or_else(|| usage("export-teams needs --tenant <tenant id or domain>"))?;
    let client_id = client_id.ok_or_else(|| usage("export-teams needs --client-id <application id of your app registration>"))?;
    let out = out.ok_or_else(|| usage("export-teams needs --out <export directory>"))?;
    let mut options = ExportOptions::new(&tenant, &client_id);
    options.chats_only = chats_only;
    if let Some(url) = login_url {
        options.login_url = url;
    }
    if let Some(url) = graph_url {
        options.graph_url = url;
    }
    if let Some(mb) = max_file_mb {
        options.max_file_bytes = mb << 20;
    }
    if let Some(path) = ca_file {
        options.roots = crewcraft_https::Roots::Pem(fs::read(path)?);
    }
    let hooks = Hooks {
        show: Box::new(|code| {
            println!("To sign in, open {} in a browser and enter the code {}", code.verification_uri, code.user_code);
            println!("(the code expires in {} minutes)", code.expires_in.as_secs().div_ceil(60));
        }),
        pause: Box::new(std::thread::sleep),
        progress: Box::new(|line| println!("  {line}")),
    };
    let failed = |error: crewcraft_server::export_teams::ExportError| io::Error::other(error.to_string());
    let mut session = sign_in(options, hooks).map_err(failed)?;
    println!("Signed in. Exporting to {}", out.display());
    let report = session.export(&out).map_err(failed)?;
    drop(session);
    println!("Export written to {}", out.display());
    println!(
        "  {} conversations written, {} already there, {} messages",
        report.conversations_written, report.conversations_skipped, report.messages
    );
    println!(
        "  {} attachments downloaded, {} already there, {} not captured",
        report.files_downloaded,
        report.files_present,
        report.files_not_captured.len()
    );
    for (message, name, reason) in &report.files_not_captured {
        println!("  not captured: {name:?} (message {message}): {reason}");
    }
    if report.retries > 0 {
        println!("  {} requests were tried again after throttling or a dropped connection", report.retries);
    }
    for (conversation, reason) in &report.conversations_failed {
        println!("  failed: {conversation}: {reason}");
    }
    for (message, name, reason) in &report.files_failed {
        println!("  failed: {name:?} (message {message}): {reason}");
    }
    if !report.ok() {
        let count = report.conversations_failed.len() + report.files_failed.len();
        return Err(io::Error::other(format!("{count} parts could not be exported; run the same command again to retry them")));
    }
    println!("Next: crewcraft-server import-teams --export {} --out <new-bundle-directory>", out.display());
    Ok(())
}

/// `import` (docs/IMPORT.md, task T350b): read the bundle, import it offline, and write the report.
fn import(data: &Path, rest: &[OsString]) -> io::Result<()> {
    use crewcraft_server::import_bundle;
    let mut bundle_dir: Option<PathBuf> = None;
    let mut domains = Vec::new();
    let mut dry_run = false;
    let mut args = rest.iter();
    while let Some(flag) = args.next() {
        match text_arg(flag)? {
            "--dry-run" => dry_run = true,
            "--bundle" => {
                let value = args.next().ok_or_else(|| usage("--bundle takes a directory"))?;
                if bundle_dir.replace(PathBuf::from(value)).is_some() {
                    return Err(usage("--bundle is given twice"));
                }
            }
            "--map-domain" => {
                let value = text_arg(args.next().ok_or_else(|| usage("--map-domain takes old=new"))?)?;
                domains.push(import_bundle::parse_domain_map(value).ok_or_else(|| usage("--map-domain takes old=new, two domains"))?);
            }
            other => return Err(usage_owned(format!("unknown import option {other:?}"))),
        }
    }
    let bundle_dir = bundle_dir.ok_or_else(|| usage("import needs --bundle <directory>"))?;
    let mut bundle = import_bundle::read_bundle(&bundle_dir)?;
    bundle.map_domains(&domains);
    let (mut installation, _) = open_offline(data)?;
    let accounts = &installation.accounts;
    let has_account = |email: &str| accounts.person(email).is_some();
    let report = installation.rooms.import(&bundle, &has_account, dry_run).map_err(lab_error)?;
    let report_path = bundle_dir.join(import_bundle::REPORT_FILE);
    fs::write(&report_path, import_bundle::report_json(&report, dry_run))?;
    print!("{}", import_bundle::summary(&report, dry_run));
    println!("Report: {}", report_path.display());
    if !report.ok() {
        return Err(io::Error::other(format!("{} parts of the bundle were refused; see {}", report.refusals.len(), report_path.display())));
    }
    Ok(())
}

fn add_member(data: &Path, room: &OsString, owner: &OsString, member: &OsString) -> io::Result<()> {
    #[cfg(unix)]
    if let Some(running) = ControlClient::connect(data) {
        return running.add_member(text_arg(room)?, &lab_email(owner)?, &lab_email(member)?);
    }
    let (mut installation, _) = open_offline(data)?;
    installation.rooms.add_member(text_arg(room)?, &lab_email(owner)?, &lab_email(member)?, Role::Member).map_err(lab_error)?;
    Ok(())
}

/// Open the data directory for a command when no running server answers. A directory still in use gets a message that
/// says what to do.
fn open_offline(data: &Path) -> io::Result<(LabInstallation, ServerConfig)> {
    server_install::open(data, now_ms()).map_err(|error| match error.kind() {
        io::ErrorKind::WouldBlock => io::Error::new(io::ErrorKind::WouldBlock, IN_USE),
        _ => error,
    })
}

#[cfg(unix)]
const IN_USE: &str =
    "the data directory is in use by another command, or by a server that does not answer on its control socket; try again, or stop the server";
#[cfg(not(unix))]
const IN_USE: &str = "the data directory is in use by the running server; on Windows, stop the server to run invite, room or add-member";

fn serve(data: &Path) -> io::Result<()> {
    let (installation, config) = server_install::open(data, now_ms())?;
    // identity.toml, if present, adds sign-in through an external identity provider (task T611f). A file that does not
    // check out stops the server with the reason, rather than serving without the sign-in it asks for.
    let external = identity_config::load(data)?;
    // media.toml, if present, adds media credentials to calls and the media server's control connection (tasks
    // T360b2, T360b3). Like identity.toml, a file that does not check out stops the server.
    let media = crewcraft_server::media_link::load(data)?;
    let guest_lab = guest_lab::load(data)?;
    let mut options = config.serve_options();
    if media.is_some() {
        options.protocol.features |= crewcraft_proto::request::FEATURE_MEDIA;
    }
    if external.is_some() {
        // Enrolling through the provider includes the person's sign-in in the browser (task T611i).
        options.timeouts.bootstrap = options.timeouts.bootstrap.max(server_install::EXTERNAL_BOOTSTRAP_TIMEOUT);
    }
    let runtime = LabRuntime::bind_network(installation, options, &config.name, now_ms)?;
    let runtime = match external {
        Some(external) => {
            println!("External sign-in configured ({})", identity_config::IDENTITY_FILE);
            runtime.with_external(external)
        }
        None => runtime,
    };
    let runtime = match media {
        Some((issuer, link)) => {
            println!("Media server configured ({})", crewcraft_server::media_link::MEDIA_FILE);
            runtime.with_media(issuer, link)?
        }
        None => runtime,
    };
    let runtime = match guest_lab {
        Some(guest_lab) => {
            println!("Lab guest lobby listening on {} ({})", guest_lab.local_addr()?, crewcraft_server::guest_lab::CONFIG_FILE);
            runtime.with_guest_lab(guest_lab)
        }
        None => runtime,
    };
    // Ctrl+C, SIGTERM (how service managers stop a server) and SIGHUP end serving cleanly: the listener stops
    // accepting, open connections finish their current request, and the journals close.
    let shutdown = Arc::new(AtomicBool::new(false));
    let flag = shutdown.clone();
    ctrlc::set_handler(move || flag.store(true, Ordering::Release)).map_err(|error| io::Error::other(error.to_string()))?;
    let server = server_install::link_server(&config, server_install::read_public_port(data)?);
    // invite, room and add-member reach the running server here (T238). Without it they wait for the server to stop.
    #[cfg(unix)]
    let control = match ControlSocket::bind(data) {
        Ok(control) => Some(control),
        Err(error) => {
            eprintln!("crewcraft-server: no control socket ({error}); stop the server to run invite, room or add-member");
            None
        }
    };
    println!("CrewCraft listening on {} as {server}", runtime.local_addr()?);
    io::stdout().flush()?;
    #[cfg(unix)]
    let served = match control {
        Some(control) => runtime.serve_enrolled_with_control(&shutdown, control),
        None => runtime.serve_enrolled(&shutdown),
    };
    #[cfg(not(unix))]
    let served = runtime.serve_enrolled(&shutdown);
    println!("CrewCraft stopped.");
    served
}

/// Shows an invitation as the link a client opens, and its parts for typing in by hand.
/// Where an invitation is shown: the private terminal, or a new owner-only file for scripted installs (T237).
enum InvitationOut {
    Terminal(io::Stdout),
    File(PathBuf),
}

struct LinkTerminal {
    out: InvitationOut,
    server: String,
    root_sha256: [u8; 32],
    /// How invitations say people sign in: through the organization when the server has an identity provider (T611k).
    signin: Option<crewcraft_enroll::SignInWay>,
}

impl ProtectedDisplay for LinkTerminal {
    fn show(&mut self, issued: &IssuedCode<'_>) -> Result<(), DisplayFailed> {
        self.show_text(issued.email(), issued.code())
    }
}

impl LinkTerminal {
    /// Show `email`'s invitation with `code`, whether this command issued it or the running server did.
    fn show_text(&mut self, email: &str, code: &str) -> Result<(), DisplayFailed> {
        // Built the way a client reads it, so a link the client would refuse is never shown.
        let link = server_install::invitation(&self.server, code, &self.root_sha256).map_err(|_| DisplayFailed)?.with_signin(self.signin);
        let root = server_install::hex(&self.root_sha256);
        let server = &self.server;
        let text = format!("Private invitation for {email}\n{link}\nServer {server}\nCode {code}\nRoot SHA-256 {root}\n");
        match &mut self.out {
            InvitationOut::Terminal(out) => {
                out.write_all(text.as_bytes()).map_err(|_| DisplayFailed)?;
                out.flush().map_err(|_| DisplayFailed)
            }
            InvitationOut::File(path) => server_install::write_invitation_file(path, &text).map_err(|_| DisplayFailed),
        }
    }
}

fn require_private_terminal(message: &'static str) -> io::Result<()> {
    if io::stdin().is_terminal() && io::stdout().is_terminal() { Ok(()) } else { Err(io::Error::new(io::ErrorKind::PermissionDenied, message)) }
}

fn usage(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn usage_owned(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn serve_lab(state: &Path, trusted_root: &Path, port: u16) -> io::Result<()> {
    let installation = lab_admin::reopen(state, root_fingerprint(trusted_root)?, now_ms()).map_err(lab_error)?;
    let options = LabOptions {
        address: SocketAddr::from(([127, 0, 0, 1], port)),
        capacity: NonZeroUsize::new(8).unwrap_or(NonZeroUsize::MIN),
        timeouts: Timeouts {
            handshake: Duration::from_secs(10),
            sign_in: Duration::from_secs(90),
            signed_in_frame: Duration::from_secs(120),
            bootstrap: Duration::from_secs(120),
        },
        protocol: ServerSide {
            min_version: 1,
            max_version: 1,
            features: FEATURE_LIST_ROOMS
                | FEATURE_SEARCH
                | FEATURE_FILES
                | FEATURE_THREADS
                | FEATURE_REACTIONS
                | FEATURE_ARCHIVE
                | FEATURE_CALLS
                | FEATURE_FILE_LIST
                | FEATURE_PINS_SAVED
                | FEATURE_READ_STATE
                | FEATURE_GAP_REPLAY
                | FEATURE_CONTINUE
                | FEATURE_ROOM_SETTINGS
                | FEATURE_MEETINGS
                | FEATURE_GUEST_MEETINGS
                | FEATURE_ACTIVITY,
            name: "CrewCraft Lab".into(),
        },
    };
    let runtime = LabRuntime::bind(installation, options, now_ms)?;
    println!("CrewCraft lab listening on {}", runtime.local_addr()?);
    runtime.serve_enrolled(&AtomicBool::new(false))
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).ok().and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok()).unwrap_or(0)
}
