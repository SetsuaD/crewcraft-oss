//! CrewCraft server binary. The network command runs only on IPv4 loopback.

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
use crewcraft_server_core::room::Role;
use sha2::{Digest, Sha256};

const MAX_ROOT_DER: u64 = 16 * 1024;
const PUBLIC_ROOT: &str = "trust-root.der";

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("CrewCraft lab: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[OsString]) -> io::Result<()> {
    match args {
        [] => version(),
        [flag] if flag == "--version" => version(),
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
            eprintln!("crewcraft-server lab init <new-state-directory>");
            eprintln!("crewcraft-server lab invite <state-directory> <trusted-root.der> <email>");
            eprintln!("crewcraft-server lab serve <state-directory> <trusted-root.der> <port>");
            eprintln!("crewcraft-server lab room <state-directory> <trusted-root.der> <owner> <name>");
            eprintln!("crewcraft-server lab add-member <state-directory> <trusted-root.der> <room> <owner> <member>");
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
