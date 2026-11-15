//! Check theme files the way the server does before installing them.
//!
//!     cargo run -p crewcraft-theme --example theme_check -- my-theme.toml [more.toml ...]
//!
//! Prints each file's result and its SHA-256; exits 1 if any file is refused, 2 if a file cannot be read.

use std::process::ExitCode;

fn main() -> ExitCode {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: theme_check <theme.toml> [more.toml ...]");
        return ExitCode::from(2);
    }
    let mut code = ExitCode::SUCCESS;
    for path in &paths {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("{path}: cannot read: {e}");
                return ExitCode::from(2);
            }
        };
        match crewcraft_theme::load_addon(&bytes) {
            Ok(addon) => {
                let dark = if addon.theme.has_dark() { "light and dark" } else { "light only" };
                println!("{path}: OK  {} {} ({dark})  sha256 {}", addon.theme.id, addon.theme.version, addon.sha256);
            }
            Err(e) => {
                println!("{path}: REFUSED  {e}");
                code = ExitCode::from(1);
            }
        }
    }
    code
}
