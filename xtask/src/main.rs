//! `cargo xtask <command>`: CrewCraft's build tasks, in Rust (docs/SPEC.md section 7). See docs/RELEASE.md.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
usage: cargo xtask <command>

commands:
  dist    build the release packages (cargo xtask dist --help)
  preflight  check the complete release package set against build receipts (cargo xtask preflight --help)
  apk     build the Android app (cargo xtask apk --help)
  ios     build CrewCraft.app for the iOS Simulator, on a Mac (cargo xtask ios --help)
  icons   rewrite assets/icon/crewcraft.ico from assets/icon/crewcraft.svg
  release make a release key, write and sign a release manifest, verify one (cargo xtask release --help)";

const PREFLIGHT_USAGE: &str = "\
usage: cargo xtask preflight --version <version> --commit <40-character Git SHA>
                             --dir <packages-dir> --receipt <build-receipt>...

Checks all desktop and server packages from one source revision, then writes SHA256SUMS.txt into <packages-dir>.";

fn preflight(args: &[String]) -> xtask::Result<()> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{PREFLIGHT_USAGE}");
        return Ok(());
    }
    let (mut version, mut commit, mut dir) = (None, None, None);
    let mut receipts = Vec::new();
    let mut flags = args.iter();
    while let Some(flag) = flags.next() {
        let value = flags.next().ok_or_else(|| xtask::Error::new(format!("{flag} needs a value\n\n{PREFLIGHT_USAGE}")))?;
        match flag.as_str() {
            "--version" if version.is_none() => version = Some(xtask::version::Version::parse(value)?),
            "--commit" if commit.is_none() => commit = Some(value.as_str()),
            "--dir" if dir.is_none() => dir = Some(PathBuf::from(value)),
            "--receipt" => receipts.push(PathBuf::from(value)),
            _ => return Err(xtask::Error::new(format!("unknown or repeated argument {flag:?}\n\n{PREFLIGHT_USAGE}"))),
        }
    }
    let (Some(version), Some(commit), Some(dir)) = (version, commit, dir) else {
        return Err(xtask::Error::new(PREFLIGHT_USAGE));
    };
    if receipts.is_empty() {
        return Err(xtask::Error::new(PREFLIGHT_USAGE));
    }
    let sums = xtask::sums::preflight(&dir, &version, commit, &receipts)?;
    println!("== {} in {}\n{sums}", xtask::sums::SUMS_FILE, dir.display());
    Ok(())
}

fn run(args: &[String]) -> xtask::Result<()> {
    match args.split_first() {
        Some((command, rest)) if command == "dist" => {
            if rest.iter().any(|arg| arg == "--help" || arg == "-h") {
                println!("{}", xtask::dist::USAGE);
                return Ok(());
            }
            xtask::dist::run(&xtask::dist::parse_args(rest)?)
        }
        Some((command, rest)) if command == "preflight" => preflight(rest),
        Some((command, rest)) if command == "apk" => {
            if rest.iter().any(|arg| arg == "--help" || arg == "-h") {
                println!("{}", xtask::android::USAGE);
                return Ok(());
            }
            xtask::android::run(&xtask::android::parse_args(rest)?)
        }
        Some((command, rest)) if command == "ios" => {
            if rest.iter().any(|arg| arg == "--help" || arg == "-h") {
                println!("{}", xtask::ios::USAGE);
                return Ok(());
            }
            xtask::ios::run(&xtask::ios::parse_args(rest)?)
        }
        Some((command, rest)) if command == "release" => {
            if rest.is_empty() || rest.iter().any(|arg| arg == "--help" || arg == "-h") {
                println!("{}", xtask::release::USAGE);
                return Ok(());
            }
            xtask::release::run(&xtask::release::parse_args(rest)?)
        }
        Some((command, _)) if command == "icons" => {
            let root = xtask::dist::workspace_root()?;
            let svg =
                std::fs::read(root.join("assets/icon/crewcraft.svg")).map_err(|error| xtask::Error::new(format!("reading the icon SVG: {error}")))?;
            let path = root.join(xtask::icon::COMMITTED_ICO);
            std::fs::write(&path, xtask::icon::app_ico(&svg)?).map_err(|error| xtask::Error::new(format!("writing {}: {error}", path.display())))?;
            println!("wrote {}", path.display());
            Ok(())
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
