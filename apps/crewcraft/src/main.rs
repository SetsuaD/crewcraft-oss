//! The CrewCraft desktop client (Windows, macOS, Linux). Calls: `crewcraft-client-core`.
//! Filled in from milestone M3 (docs/ROADMAP.md).

fn main() {
    let (major, minor) = crewcraft_client_core::PROTOCOL_VERSION;
    println!("crewcraft {} (protocol {major}.{minor})", env!("CARGO_PKG_VERSION"));
}
