//! Wire types shared by the CrewCraft server and every client (desktop, web, Android, iOS).
//!
//! Owns: the versioned request/response/event shapes. Called by: `crewcraft-server-core`, `crewcraft-client-core`.
//! Filled in by milestone M1 (ROADMAP.md).

/// Protocol version spoken by this build. A server refuses clients whose major version differs.
pub const PROTOCOL_VERSION: (u16, u16) = (0, 1);

pub mod frame;
pub mod handshake;
pub mod message;
pub mod push;
pub mod request;
