//! CrewCraft client executable. The interactive trial is confined to the numeric loopback lab.

use std::env;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufRead, Cursor, IsTerminal, Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use crewcraft::bootstrap_transport::BootstrapEndpoint;
use crewcraft::enroll_client::{FirstTotpCode, TotpSetup};
use crewcraft::lab_device::{LabDevice, LabDeviceKey};
use crewcraft_client_core::room_view::Shown;
use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_proto::message::MAX_BODY;
use crewcraft_proto::signin::{MAX_EMAIL_BYTES, MAX_PASSWORD_BYTES};
use zeroize::Zeroizing;

const MAX_ROOT_DER: u64 = 16 * 1024;

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
        [lab, chat, address, root_path, fingerprint, email, room] if lab == "lab" && chat == "chat" => {
            if !io::stdin().is_terminal() || !io::stdout().is_terminal() || !io::stderr().is_terminal() {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "use a private interactive terminal"));
            }
            let address = text_arg(address)?;
            let pin = RootFingerprint::parse(text_arg(fingerprint)?).ok_or_else(|| invalid("invalid root fingerprint"))?;
            let email = text_arg(email)?;
            let room = text_arg(room)?;
            if email.is_empty() || email.len() > MAX_EMAIL_BYTES || email.chars().any(char::is_control) {
                return Err(invalid("invalid email"));
            }
            let mut root_der = Vec::new();
            File::open(Path::new(root_path))?.take(MAX_ROOT_DER + 1).read_to_end(&mut root_der)?;
            if root_der.is_empty() || root_der.len() as u64 > MAX_ROOT_DER {
                return Err(invalid("invalid trusted root certificate size"));
            }
            let endpoint = BootstrapEndpoint::new(address, "localhost", pin, &root_der).map_err(lab_error)?;
            let code = read_secret("Invitation code: ", 80)?;
            let invitation = EnrollmentCode::parse(&code).map_err(|_| invalid("invalid invitation code"))?;
            drop(code);
            let key = LabDeviceKey::generate().map_err(lab_error)?;
            let password = read_secret("New lab password: ", MAX_PASSWORD_BYTES)?;
            let device =
                key.enroll(&endpoint, &invitation, Duration::from_secs(120), "Loopback lab device", &password, confirm_setup).map_err(lab_error)?;
            drop(password);
            println!("Enrollment complete. Use a newer authenticator code for the first sign-in.");
            println!("Keep this client open to retain its lab device key across server restarts.");
            chat_loop(&device, email, room)?;
        }
        _ => {
            eprintln!("crewcraft lab chat <loopback-address> <root.der> <root-sha256> <email> <room>");
            return Err(invalid("unknown command"));
        }
    }
    Ok(())
}

fn version() {
    let (major, minor) = crewcraft_client_core::PROTOCOL_VERSION;
    println!("crewcraft {} (protocol {major}.{minor})", env!("CARGO_PKG_VERSION"));
}

fn text_arg(arg: &OsString) -> io::Result<&str> {
    arg.to_str().ok_or_else(|| invalid("invalid text argument"))
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

fn lab_error(error: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

#[cfg(unix)]
fn terminal_password(prompt: &str) -> io::Result<String> {
    use signal_hook::consts::SIGINT;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, OnceLock};

    static DEFAULT_INTERRUPT: OnceLock<io::Result<Arc<AtomicBool>>> = OnceLock::new();
    let enabled = DEFAULT_INTERRUPT
        .get_or_init(|| {
            let enabled = Arc::new(AtomicBool::new(true));
            signal_hook::flag::register_conditional_default(SIGINT, Arc::clone(&enabled))?;
            Ok(enabled)
        })
        .as_ref()
        .map_err(|error| io::Error::new(error.kind(), "could not configure credential prompt cancellation"))?;

    // rpassword raises SIGINT before dropping its Unix terminal guard. Let it return
    // and restore the terminal before applying the normal interrupt action.
    enabled.store(false, Ordering::SeqCst);
    let result = rpassword::prompt_password(prompt);
    enabled.store(true, Ordering::SeqCst);
    if matches!(&result, Err(error) if error.kind() == io::ErrorKind::Interrupted) {
        signal_hook::low_level::emulate_default_handler(SIGINT)?;
    }
    result
}

#[cfg(not(unix))]
fn terminal_password(prompt: &str) -> io::Result<String> {
    rpassword::prompt_password(prompt)
}

fn read_secret(prompt: &str, limit: usize) -> io::Result<Zeroizing<String>> {
    let value = Zeroizing::new(terminal_password(prompt)?);
    if value.is_empty() || value.len() > limit || value.chars().any(|c| matches!(c, '\r' | '\n' | '\0')) {
        return Err(invalid("invalid credential length or characters"));
    }
    Ok(value)
}

fn confirm_setup(setup: TotpSetup<'_>, deadline: Instant) -> Option<FirstTotpCode> {
    if Instant::now() >= deadline {
        return None;
    }
    let query = setup.protected_uri().split_once('?')?.1;
    let key = query.split('&').find_map(|item| item.strip_prefix("secret="))?;
    if key.is_empty() || key.len() > 128 || !key.bytes().all(|byte| byte.is_ascii_uppercase() || (b'2'..=b'7').contains(&byte)) {
        return None;
    }
    {
        let mut display = io::stderr().lock();
        writeln!(display, "Add a time-based account in your authenticator. Enter this setup key manually.").ok()?;
        writeln!(display, "{key}").ok()?;
        display.flush().ok()?;
    }
    let code = read_secret("Authenticator confirmation code: ", 6).ok()?;
    if Instant::now() >= deadline {
        return None;
    }
    FirstTotpCode::parse(code.to_string())
}

fn chat_loop(device: &LabDevice<'_>, email: &str, room: &str) -> io::Result<()> {
    let mut session = None;
    println!("Type signin, post followed by a message, sync, or quit.");
    loop {
        print!("crewcraft> ");
        io::stdout().flush()?;
        let mut line = String::new();
        let read = io::stdin().lock().take((MAX_BODY + 16) as u64).read_line(&mut line)?;
        if read == 0 || line.trim_end() == "quit" {
            return Ok(());
        }
        if !line.ends_with('\n') {
            return Err(invalid("command is too long"));
        }
        let command = line.trim_end_matches(['\r', '\n']);
        if command == "signin" {
            let password = read_secret("Lab password: ", MAX_PASSWORD_BYTES)?;
            let code = read_secret("Current authenticator code: ", 6)?;
            let input = Zeroizing::new(format!("{email}\n{}\n{}\n", password.as_str(), code.as_str()).into_bytes());
            match device.open_session(&mut Cursor::new(input.as_slice())) {
                Ok(open) => {
                    session = Some(open);
                    println!("Signed in.");
                }
                Err(error) => eprintln!("Sign-in failed ({error:?}). Try a fresh code."),
            }
        } else if let Some(active) = &mut session {
            if let Some(message) = command.strip_prefix("post ") {
                match active.post(room, message) {
                    Ok(cursor) => println!("Sent at {cursor}."),
                    Err(error) => eprintln!("Post failed ({error:?})."),
                }
            } else if command == "sync" {
                match active.sync(room) {
                    Ok((head, lines)) => {
                        for entry in lines {
                            if let Shown::Line(line) = entry {
                                println!("{} {} {}", line.cursor, printable(&line.author), printable(&line.html));
                            }
                        }
                        println!("History through {head}.");
                    }
                    Err(error) => eprintln!("Sync failed ({error:?})."),
                }
            } else {
                println!("Type post followed by a message, sync, signin, or quit.");
            }
        } else {
            println!("Type signin to connect.");
        }
    }
}

fn printable(text: &str) -> String {
    text.chars().filter(|character| !character.is_control()).collect()
}
