//! `cargo xtask <command>`: CrewCraft's build tasks, in Rust (docs/SPEC.md section 7). See docs/RELEASE.md.

use std::env;
use std::process::ExitCode;

const USAGE: &str = "\
usage: cargo xtask <command>

commands:
  dist    build the release packages (cargo xtask dist --help)";

fn run(args: &[String]) -> xtask::Result<()> {
    match args.split_first() {
        Some((command, rest)) if command == "dist" => {
            if rest.iter().any(|arg| arg == "--help" || arg == "-h") {
                println!("{}", xtask::dist::USAGE);
                return Ok(());
            }
            xtask::dist::run(&xtask::dist::parse_args(rest)?)
        }
        Some((command, _)) if command == "--help" || command == "-h" || command == "help" => {
            println!("{USAGE}");
            Ok(())
        }
        Some((command, _)) => Err(xtask::Error::new(format!("unknown command {command:?}\n\n{USAGE}"))),
        None => Err(xtask::Error::new(USAGE)),
    }
}

fn main() -> ExitCode {
    let mut args = Vec::new();
    for arg in env::args_os().skip(1) {
        match arg.into_string() {
            Ok(arg) => args.push(arg),
            Err(arg) => {
                eprintln!("xtask: argument {arg:?} is not UTF-8");
                return ExitCode::FAILURE;
            }
        }
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}
