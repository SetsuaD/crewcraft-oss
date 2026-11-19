//! Build script for the CrewCraft desktop app: on Windows, embed the app icon and a version resource in
//! `crewcraft.exe`, so Explorer shows the icon and the release version. Other targets: nothing.
//!
//! The resource is written from `windows/crewcraft.rc.in` into `OUT_DIR` with the version and the icon's path filled
//! in (no preprocessor macros, which would have to survive the resource compiler's shell), then compiled by
//! `embed-resource` with the target's resource compiler (MinGW `windres` when cross-building, `rc.exe` with MSVC).

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::exit;

fn fail(message: String) -> ! {
    eprintln!("crewcraft build script: {message}");
    exit(1);
}

fn main() {
    println!("cargo::rerun-if-changed=windows/crewcraft.rc.in");
    println!("cargo::rerun-if-changed=../../assets/icon/crewcraft.ico");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap_or_else(|_| fail("OUT_DIR is not set".to_owned())));
    let template =
        fs::read_to_string(manifest_dir.join("windows/crewcraft.rc.in")).unwrap_or_else(|error| fail(format!("reading crewcraft.rc.in: {error}")));
    let icon = manifest_dir.join("../../assets/icon/crewcraft.ico");
    let icon = fs::canonicalize(&icon).unwrap_or_else(|error| fail(format!("finding {}: {error}", icon.display())));
    // Forward slashes work for both resource compilers and need no escaping inside an .rc string.
    let icon = icon.to_string_lossy().replace('\\', "/");
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let number = |name: &str| env::var(name).ok().and_then(|value| value.parse::<u16>().ok()).unwrap_or(0);
    let numeric = format!("{},{},{},0", number("CARGO_PKG_VERSION_MAJOR"), number("CARGO_PKG_VERSION_MINOR"), number("CARGO_PKG_VERSION_PATCH"));
    let resource = template.replace("@ICON@", &icon).replace("@VERSION_TEXT@", &version).replace("@VERSION_NUMBER@", &numeric);
    let rc = out_dir.join("crewcraft.rc");
    fs::write(&rc, resource).unwrap_or_else(|error| fail(format!("writing {}: {error}", rc.display())));
    let no_macros: [&str; 0] = [];
    if let Err(error) = embed_resource::compile(&rc, no_macros).manifest_optional() {
        fail(format!("could not embed the Windows resource: {error}"));
    }
}
