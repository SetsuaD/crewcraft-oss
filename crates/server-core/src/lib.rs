//! Server domain logic: accounts, devices, rooms, memberships, messages and the access rules over them.
//!
//! Owns: behaviour, not transport or storage (those are traits implemented by `apps/crewcraft-server`).
//! Called by: `apps/crewcraft-server`. Calls: `crewcraft-proto`. Filled in from milestone M1 (ROADMAP.md).

pub use crewcraft_proto::PROTOCOL_VERSION;

pub mod account_journal;
pub mod account_op;
pub mod account_store;
pub mod activation;
pub mod admin;
pub mod audit;
pub mod calls;
pub mod cert_policy;
pub mod connection;
pub mod current;
pub mod cursor_log;
pub mod devices;
pub mod dispatch;
pub mod durable;
pub mod enrollment;
pub mod file_store;
pub mod html_text;
pub mod import;
pub mod import_media;
pub mod invites;
pub mod journal;
pub mod media;
pub mod mentions;
pub mod op;
pub mod presence;
pub mod rate_limit;
pub mod render;
pub mod retention;
pub mod room;
pub mod room_name;
pub mod room_search;
pub mod room_service;
pub mod seal;
pub mod search;
pub mod server;
pub mod session;
pub mod unread;
pub mod upload;
