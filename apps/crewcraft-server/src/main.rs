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
use crewcraft_proto::request::{FEATURE_FILES, FEATURE_LIST_ROOMS, FEATURE_SEARCH, FEATURE_THREADS};
#[cfg(unix)]
use crewcraft_server::control::{ControlClient, ControlSocket};
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
    let mut display = LinkTerminal { out, server, root_sha256: root.sha256 };
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
    Ok(LinkTerminal { out, server, root_sha256 })
}

fn create_room(data: &Path, owner: &OsString, name: &OsString) -> io::Result<String> {
    #[cfg(unix)]
    if let Some(running) = ControlClient::connect(data) {
        return running.create_room(&lab_email(owner)?, text_arg(name)?);
    }
    let (mut installation, _) = open_offline(data)?;
    installation.rooms.create_room(&lab_email(owner)?, text_arg(name)?).map_err(lab_error)
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
    let mut options = config.serve_options();
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
        let link = server_install::invitation(&self.server, code, &self.root_sha256).map_err(|_| DisplayFailed)?;
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
            features: FEATURE_LIST_ROOMS | FEATURE_SEARCH | FEATURE_FILES | FEATURE_THREADS,
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
