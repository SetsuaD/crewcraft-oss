//! CrewCraft server binary. The current network command runs only on IPv4 loopback.

use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crewcraft_proto::handshake::ServerSide;
use crewcraft_server::lab_installation::LabInstallation;
use crewcraft_server::lab_runtime::LabRuntime;
use crewcraft_server::lab_server::{LabOptions, Timeouts};
use sha2::{Digest, Sha256};

const MAX_ROOT_DER: u64 = 16 * 1024;

fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => version(),
        [flag] if flag == "--version" => version(),
        [lab, serve, state, root, port] if lab == "lab" && serve == "serve" => {
            let port = port.to_str().and_then(|value| value.parse::<u16>().ok());
            match port.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid lab port"))
                .and_then(|port| serve_lab(Path::new(state), Path::new(root), port))
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("CrewCraft lab: {error}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("Usage: crewcraft-server lab serve <state-directory> <trusted-root.der> <port>");
            ExitCode::FAILURE
        }
    }
}

fn version() -> ExitCode {
    let (major, minor) = crewcraft_server_core::PROTOCOL_VERSION;
    println!("crewcraft-server {} (protocol {major}.{minor})", env!("CARGO_PKG_VERSION"));
    ExitCode::SUCCESS
}

fn serve_lab(state: &Path, trusted_root: &Path, port: u16) -> io::Result<()> {
    let mut root_der = Vec::new();
    File::open(trusted_root)?.take(MAX_ROOT_DER + 1).read_to_end(&mut root_der)?;
    if root_der.is_empty() || root_der.len() as u64 > MAX_ROOT_DER {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid trusted root certificate size"));
    }
    let expected_root = Sha256::digest(root_der).into();
    let installation = LabInstallation::open(state, expected_root, now_ms())
        .map_err(|error| io::Error::other(format!("could not open lab state: {error:?}")))?;
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}
