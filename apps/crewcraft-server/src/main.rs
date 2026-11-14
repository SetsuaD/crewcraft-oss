//! The CrewCraft server binary: TLS listener (mutual TLS only), the web client, the admin console.
//! Calls: `crewcraft-server-core`. Filled in from milestone M1 (ROADMAP.md).

fn main() {
    let (major, minor) = crewcraft_server_core::PROTOCOL_VERSION;
    println!("crewcraft-server {} (protocol {major}.{minor})", env!("CARGO_PKG_VERSION"));
}
