//! CrewCraft server binary.
//!
//! `first-run`, `serve`, `invite`, `room` and `add-member` run a network server from one data directory whose recorded
//! settings (`server.conf`) name the server and the address it listens on (task T231). The `lab` commands keep the
//! loopback-only lab, which pins its root from a separate file.

use std::env;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, IsTerminal, Read, Write};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft_accounts::identity::normalize_email;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::handshake::ServerSide;
use crewcraft_server::lab_admin::{self, DisplayFailed, IssuedCode, ProtectedDisplay};
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use crewcraft_server::server_install::{self, ServerConfig};
use crewcraft_server::server_name::ServerName;
use crewcraft_server_core::room::Role;
use sha2::{Digest, Sha256};

const MAX_ROOT_DER: u64 = 16 * 1024;
const PUBLIC_ROOT: &str = server_install::PUBLIC_ROOT;

const USAGE: &str = "\
crewcraft-server first-run <new-data-directory> --name <server-name> --admin <email> [--listen <address:port>]
    Create a server: its certificate authority, settings and public root (trust-root.der), and an invitation for
    the administrator, shown as a crewcraft://enroll link. The server name is the DNS name or IP address clients
    use. The listen address defaults to 127.0.0.1:7443; use 0.0.0.0:7443 or [::]:7443 for every interface.
    Run it in a private interactive terminal. An existing directory is never changed.
crewcraft-server serve <data-directory>
    Serve with the recorded name and listen address until interrupted.
crewcraft-server invite <data-directory> <email>
    Invite a person; shows the code and link in a private interactive terminal only.
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
        [command, data, email] if command == "invite" => invite(Path::new(data), text_arg(email)?)?,
        [command, data, owner, name] if command == "room" => {
            let (mut installation, _) = server_install::open(Path::new(data), now_ms())?;
            let slug = installation.rooms.create_room(&lab_email(owner)?, text_arg(name)?).map_err(lab_error)?;
            println!("Room {slug}");
        }
        [command, data, room, owner, member] if command == "add-member" => {
            let (mut installation, _) = server_install::open(Path::new(data), now_ms())?;
            installation.rooms.add_member(text_arg(room)?, &lab_email(owner)?, &lab_email(member)?, Role::Member).map_err(lab_error)?;
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
}

fn parse_first_run(flags: &[OsString]) -> io::Result<FirstRun> {
    let (mut name, mut admin, mut listen) = (None, None, None);
    let mut flags = flags.iter();
    while let Some(flag) = flags.next() {
        let value = text_arg(flags.next().ok_or_else(|| usage("every first-run option takes a value"))?)?;
        let given_twice = match text_arg(flag)? {
            "--name" => name.replace(ServerName::parse(value).map_err(|error| usage_owned(error.to_string()))?).is_some(),
            "--admin" => admin.replace(normalize_email(value).map_err(|_| usage("--admin takes an email address"))?).is_some(),
            "--listen" => listen.replace(server_install::parse_listen(value).map_err(|error| usage_owned(error.to_string()))?).is_some(),
            _ => return Err(usage("first-run takes --name, --admin and --listen")),
        };
        if given_twice {
            return Err(usage("a first-run option was given twice"));
        }
    }
    let name = name.ok_or_else(|| usage("first-run needs --name <server-name>"))?;
    let admin = admin.ok_or_else(|| usage("first-run needs --admin <email>"))?;
    Ok(FirstRun { name, admin, listen: listen.unwrap_or_else(ServerConfig::default_listen) })
}

fn first_run(data: &Path, flags: &[OsString]) -> io::Result<()> {
    let FirstRun { name, admin, listen } = parse_first_run(flags)?;
    // Creating the directory refuses an existing one atomically; this only refuses before asking for a terminal.
    if fs::symlink_metadata(data).is_ok() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "an installation already exists there; first-run never changes one"));
    }
    require_private_terminal("run first-run in a private interactive terminal: it shows the administrator's invitation")?;
    let config = ServerConfig { name, listen };
    let (mut installation, root) = server_install::create(data, &config, now_ms())?;
    println!("Server {}", config.public_server());
    println!("Listening on {}", config.listen);
    println!("Trusted root {}", data.join(PUBLIC_ROOT).display());
    println!("Root SHA-256 {}", RootFingerprint::from_der(&root.certificate_der));
    let mut display = LinkTerminal { out: io::stdout(), server: config.public_server(), root_sha256: root.sha256 };
    lab_admin::invite(&mut installation.accounts, &admin, None, now_ms(), &mut display).map_err(|error| {
        io::Error::other(format!("the server was created but the administrator was not invited ({error}); run invite to try again"))
    })?;
    Ok(())
}

fn invite(data: &Path, email: &str) -> io::Result<()> {
    require_private_terminal("show invitations in a private interactive terminal")?;
    let (mut installation, config) = server_install::open(data, now_ms())?;
    let root_sha256 = server_install::root_sha256(data)?;
    let mut display = LinkTerminal { out: io::stdout(), server: config.public_server(), root_sha256 };
    lab_admin::invite(&mut installation.accounts, email, None, now_ms(), &mut display).map_err(lab_error)?;
    Ok(())
}

fn serve(data: &Path) -> io::Result<()> {
    let (installation, config) = server_install::open(data, now_ms())?;
    let runtime = LabRuntime::bind_network(installation, config.serve_options(), &config.name, now_ms)?;
    println!("CrewCraft listening on {} as {}", runtime.local_addr()?, config.public_server());
    io::stdout().flush()?;
    runtime.serve_enrolled(&AtomicBool::new(false))
}

/// Shows an invitation as the link a client opens, and its parts for typing in by hand.
struct LinkTerminal {
    out: io::Stdout,
    server: String,
    root_sha256: [u8; 32],
}

impl ProtectedDisplay for LinkTerminal {
    fn show(&mut self, issued: &IssuedCode<'_>) -> Result<(), DisplayFailed> {
        let link = server_install::enrollment_link(&self.server, issued.code(), &self.root_sha256);
        let root = server_install::hex(&self.root_sha256);
        let (email, server, code) = (issued.email(), &self.server, issued.code());
        writeln!(self.out, "Private invitation for {email}\n{link}\nServer {server}\nCode {code}\nRoot SHA-256 {root}").map_err(|_| DisplayFailed)?;
        self.out.flush().map_err(|_| DisplayFailed)
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
        protocol: ServerSide { min_version: 1, max_version: 1, features: 0, name: "CrewCraft Lab".into() },
    };
    let runtime = LabRuntime::bind(installation, options, now_ms)?;
    println!("CrewCraft lab listening on {}", runtime.local_addr()?);
    runtime.serve_enrolled(&AtomicBool::new(false))
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).ok().and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok()).unwrap_or(0)
}
