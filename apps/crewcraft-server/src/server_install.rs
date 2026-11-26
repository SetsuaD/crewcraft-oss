//! A network server's installation: `first-run` creates it and the other server commands open it. Task T231.
//!
//! Owns: the recorded settings (`server.conf`: the server name and the listen address), the public root next to
//! them (`trust-root.der`, which also pins the state when it is opened again) and the serving options. The
//! invitation link format is `crewcraft_enroll::invitation`'s, shared with the client.
//! Does not own: the state itself (`lab_installation`, `lab_admin`), the name rules (`server_name`), serving
//! (`lab_runtime`).
//!
//! The settings file is plain `key = value` lines; `#` starts a comment line. Both keys are required, each once, and
//! any other key is refused, so a typo never silently falls back to a default.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::time::Duration;

use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::invitation::{InvitationLink, LinkError, write_link};
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::request::{FEATURE_FILES, FEATURE_LIST_ROOMS, FEATURE_SEARCH, FEATURE_THREADS};
use sha2::{Digest, Sha256};

use crate::lab_admin::{self, AdminError, LabRoot};
use crate::lab_installation::{InstallationError, LabInstallation};
use crate::lab_server::{LabOptions, Timeouts};
use crate::server_name::ServerName;

/// The settings file in the data directory.
pub const CONFIG_FILE: &str = "server.conf";
/// The public root certificate in the data directory: what clients pin, handed out with invitations.
pub const PUBLIC_ROOT: &str = "trust-root.der";
/// The port `first-run` records when `--listen` is not given.
pub const DEFAULT_PORT: u16 = 7443;
/// How many connections a network server handles at once; more are closed without a byte.
pub const CAPACITY: usize = 64;

const MAX_CONFIG: u64 = 4 * 1024;
const MAX_ROOT_DER: u64 = 16 * 1024;

/// What `first-run` records and `serve` uses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    /// The name clients verify: the server certificate is signed for it and invitations carry it.
    pub name: ServerName,
    /// The local address to listen on. Never port zero: invitations carry this port.
    pub listen: SocketAddr,
}

impl ServerConfig {
    /// The default listen address: IPv4 loopback on `DEFAULT_PORT`.
    pub fn default_listen() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], DEFAULT_PORT))
    }

    /// The server as an invitation writes it: the name with the listen port.
    pub fn public_server(&self) -> String {
        self.name.with_port(self.listen.port())
    }

    pub fn encode(&self) -> String {
        format!("# CrewCraft server settings, written by first-run.\nname = {}\nlisten = {}\n", self.name, self.listen)
    }

    pub fn decode(text: &str) -> io::Result<Self> {
        let (mut name, mut listen) = (None, None);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| invalid("a settings line is not `key = value`"))?;
            let value = value.trim();
            match key.trim() {
                "name" if name.is_none() => name = Some(ServerName::parse(value).map_err(|_| invalid("the recorded server name is not valid"))?),
                "listen" if listen.is_none() => listen = Some(parse_listen(value)?),
                "name" | "listen" => return Err(invalid("a setting is recorded twice")),
                _ => return Err(invalid("unknown setting")),
            }
        }
        match (name, listen) {
            (Some(name), Some(listen)) => Ok(Self { name, listen }),
            _ => Err(invalid("the settings need both `name` and `listen`")),
        }
    }

    /// The options `serve` binds with. With an identity provider, `serve` raises the bootstrap budget to
    /// `EXTERNAL_BOOTSTRAP_TIMEOUT`.
    pub fn serve_options(&self) -> LabOptions {
        LabOptions {
            address: self.listen,
            capacity: NonZeroUsize::new(CAPACITY).unwrap_or(NonZeroUsize::MIN),
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
                name: "CrewCraft".into(),
            },
        }
    }
}

/// The bootstrap budget on a server that enrolls through its identity provider (task T611i): the person signs in in
/// the browser during the enrollment. The app's window is `bootstrap_transport::MAX_EXTERNAL_CONFIRMATION_WINDOW`.
pub const EXTERNAL_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(330);

/// A listen address with a port other than zero.
pub fn parse_listen(text: &str) -> io::Result<SocketAddr> {
    match text.parse::<SocketAddr>() {
        Ok(address) if address.port() != 0 => Ok(address),
        _ => Err(invalid("a listen address is an IP address and a port other than 0, such as 0.0.0.0:7443 or [::]:7443")),
    }
}

/// Create a new installation in `dir`, which must not exist yet: the state, the public root and the settings, each
/// file readable by the owner only on Unix. An existing directory is refused (`io::ErrorKind::AlreadyExists`) and
/// left as it was. A failure part-way leaves the directory for the operator to inspect and remove.
pub fn create(dir: &Path, config: &ServerConfig, now_ms: u64) -> io::Result<(LabInstallation, LabRoot)> {
    let (installation, root) = lab_admin::init(dir, now_ms).map_err(admin_error)?;
    write_new(&dir.join(PUBLIC_ROOT), &root.certificate_der)?;
    write_new(&dir.join(CONFIG_FILE), config.encode().as_bytes())?;
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    Ok((installation, root))
}

/// Open an existing installation with its recorded settings. The state's root must be the one in `trust-root.der`.
pub fn open(dir: &Path, now_ms: u64) -> io::Result<(LabInstallation, ServerConfig)> {
    let config = read_config(dir)?;
    let installation = lab_admin::reopen(dir, root_sha256(dir)?, now_ms).map_err(admin_error)?;
    Ok((installation, config))
}

/// Read the recorded settings. On Unix the file must be a regular file that only its owner can read or write.
pub fn read_config(dir: &Path) -> io::Result<ServerConfig> {
    let text = read_file(&dir.join(CONFIG_FILE), MAX_CONFIG, true)?;
    let text = String::from_utf8(text).map_err(|_| invalid("the settings are not UTF-8"))?;
    ServerConfig::decode(&text)
}

/// SHA-256 of the installation's public root certificate.
pub fn root_sha256(dir: &Path) -> io::Result<[u8; 32]> {
    let der = read_file(&dir.join(PUBLIC_ROOT), MAX_ROOT_DER, false)?;
    if der.is_empty() {
        return Err(invalid("the trusted root certificate is empty"));
    }
    Ok(Sha256::digest(der).into())
}

/// `crewcraft://enroll?server=<name:port>&code=<code>&root_sha256=<hex>`, with each value percent-encoded where a
/// query needs it (an IPv6 server's brackets are written `%5B` and `%5D`). The text comes from the client's own
/// format (`crewcraft_enroll::InvitationLink`, task T234), so the server and the client can never disagree on it.
/// The file that records the port invitations carry when it differs from the listen port (a server behind port
/// forwarding). Absent when they are the same. Task T236.
pub const PUBLIC_PORT_FILE: &str = "public-port";
const MAX_PUBLIC_PORT_FILE: u64 = 16;

/// The recorded public port, or `None` when invitations use the listen port.
pub fn read_public_port(dir: &Path) -> io::Result<Option<u16>> {
    match read_file(&dir.join(PUBLIC_PORT_FILE), MAX_PUBLIC_PORT_FILE, true) {
        Ok(bytes) => {
            let text = std::str::from_utf8(&bytes).map_err(|_| invalid("the recorded public port is not text"))?;
            match text.trim().parse::<u16>() {
                Ok(port) if port != 0 => Ok(Some(port)),
                _ => Err(invalid("the recorded public port is not a port number")),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Record the public port once, at first-run (owner-only on Unix; never overwritten).
pub fn write_public_port(dir: &Path, port: u16) -> io::Result<()> {
    if port == 0 {
        return Err(invalid("the public port cannot be 0"));
    }
    write_new(&dir.join(PUBLIC_PORT_FILE), format!("{port}\n").as_bytes())
}

/// Check, before anything is created, that an invitation can be written to `path` for a scripted install (T237): it
/// must not exist yet (an existing file is never overwritten or appended to) and its folder must exist.
pub fn check_invitation_file(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(io::Error::new(io::ErrorKind::AlreadyExists, "the invitation file already exists; give a new path")),
        Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
        Err(_) => {}
    }
    let folder = path.parent().filter(|folder| !folder.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if !fs::metadata(folder)?.is_dir() {
        return Err(invalid("the invitation file's folder does not exist"));
    }
    Ok(())
}

/// Write an invitation to a new file readable by its owner only (0600 on Unix). It holds a secret enrollment code:
/// hand it over privately and delete it once the person has enrolled.
pub fn write_invitation_file(path: &Path, text: &str) -> io::Result<()> {
    write_new(path, text.as_bytes())
}

/// The server as invitations write it: the recorded name with the public port when one is recorded, else the listen
/// port.
pub fn link_server(config: &ServerConfig, public_port: Option<u16>) -> String {
    config.name.with_port(public_port.unwrap_or(config.listen.port()))
}

pub fn enrollment_link(server: &str, code: &str, root_sha256: &[u8; 32]) -> String {
    write_link(server, code, RootFingerprint::from_bytes(*root_sha256))
}

/// The invitation for an issued code, checked as a client will read it: `server` must be `name:port` and `code` an
/// enrollment code.
pub fn invitation(server: &str, code: &str, root_sha256: &[u8; 32]) -> Result<InvitationLink, LinkError> {
    let code = EnrollmentCode::parse(code).map_err(|_| LinkError::Code)?;
    InvitationLink::new(server, code, RootFingerprint::from_bytes(*root_sha256))
}

/// Lowercase hexadecimal, as `RootFingerprint` prints it.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Read a regular file of at most `limit` bytes. `private` (settings) also requires owner-only permissions on Unix;
/// the public root may be made readable to others so it can be handed out.
fn read_file(path: &Path, limit: u64, private: bool) -> io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(invalid("installation files must be regular files"));
    }
    #[cfg(not(unix))]
    let _ = private;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if private && metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "installation files must be readable by their owner only"));
        }
    }
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("an installation file is too large"));
    }
    Ok(bytes)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn admin_error(error: AdminError) -> io::Error {
    match error {
        AdminError::Installation(InstallationError::Directory(io::ErrorKind::AlreadyExists)) => {
            io::Error::new(io::ErrorKind::AlreadyExists, "an installation already exists there; first-run never changes one")
        }
        AdminError::Installation(InstallationError::Directory(kind)) => {
            io::Error::new(kind, format!("the data directory could not be used: {}", io::Error::from(kind)))
        }
        other => io::Error::other(other.to_string()),
    }
}
