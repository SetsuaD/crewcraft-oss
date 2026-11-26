//! `crewcraft-media <media.toml>`: the CrewCraft media server (docs/CALLS.md, task T363b). Reads the settings and the
//! chat server's key, binds the UDP socket and serves until Ctrl+C or SIGTERM, then closes every session and exits.
//!
//! Admits no one yet: offers and credentials arrive through the chat server's control connection, a later task
//! (the seam is `crewcraft_media::intake`).

use std::io;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crewcraft_media::{config, intake, serve};

fn start(path: &Path) -> io::Result<()> {
    let config = config::load(path)?;
    let (socket, server) = serve::bind(&config)?;
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    ctrlc::set_handler(move || flag.store(true, Ordering::Release)).map_err(|error| io::Error::other(error.to_string()))?;
    println!(
        "crewcraft-media: {} listening on {} (ICE candidate {}); waiting for the chat server's control connection (not built yet)",
        config.settings.server_name,
        socket.local_addr()?,
        server.address()
    );
    serve::run(&socket, server, &mut intake::NoIntake, &stop)?;
    println!("crewcraft-media: stopped");
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, path] = args.as_slice() else {
        eprintln!("usage: crewcraft-media <media.toml>");
        return ExitCode::from(2);
    };
    match start(Path::new(path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("crewcraft-media: {error}");
            ExitCode::FAILURE
        }
    }
}
