//! Client logic shared by every CrewCraft client: connection, sync, local cache, enrollment flow.
//!
//! Owns: behaviour with no UI. Called by: `apps/crewcraft` (desktop), the web client, and the Android/iOS shells
//! (through generated bindings). Calls: `crewcraft-proto`. Filled in from milestone M2 (ROADMAP.md).

pub use crewcraft_proto::PROTOCOL_VERSION;
pub mod calendar;
pub mod client;
pub mod guest;
pub mod inbox;
pub mod notify;
pub mod outbox;
pub mod requests;
pub mod room_view;
pub mod session;
pub mod timeline;
