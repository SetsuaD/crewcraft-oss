//! `crewcraft-media-server <media.toml>`: the CrewCraft media server (docs/CALLS.md, tasks T363b and T360b3). Reads the
//! settings and the chat server's key, binds the UDP socket, accepts the chat server's control connection when
//! `[control]` is set, and serves until Ctrl+C or SIGTERM, then closes every session and exits.
//!
//! Joins have no network intake yet: offers and credentials still reach the core only in process.

use std::io;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crewcraft_media::{config, intake, serve};
use crewcraft_media_server::control::{ControlListener, tls_config};

fn start(path: &Path) -> io::Result<()> {
    let config = config::load(path)?;
    let (socket, server) = serve::bind(&config)?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    ctrlc::set_handler(move || flag.store(true, Ordering::Release)).map_err(|error| io::Error::other(error.to_string()))?;
    println!(
        "crewcraft-media-server: {} listening on {} (ICE candidate {})",
        config.settings.server_name,
        socket.local_addr()?,
        server.address()
    );
    match &config.settings.control {
        Some(control) => {
            let dir = path.parent().unwrap_or(Path::new("."));
            let (handle, mut requests) = intake::channel();
            let listener = ControlListener::start(control.listen, tls_config(dir, control)?, handle, stop.clone())?;
            println!("crewcraft-media-server: control connection on {} (mutual TLS)", listener.local_addr());
            let served = serve::run(&socket, server, &mut requests, &stop);
            stop.store(true, Ordering::Release);
            listener.join();
            served?;
        }
        None => {
            println!("crewcraft-media-server: no [control] set; nobody can be dropped by the chat server");
            serve::run(&socket, server, &mut intake::NoIntake, &stop)?;
        }
    }
    println!("crewcraft-media-server: stopped");
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, path] = args.as_slice() else {
        eprintln!("usage: crewcraft-media-server <media.toml>");
        return ExitCode::from(2);
    };
    match start(Path::new(path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crewcraft-media-server: {error}");
            ExitCode::FAILURE
        }
    }
}
