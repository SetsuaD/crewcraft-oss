//! The CrewCraft media server binary's parts that are not the media path (task T360b3): the chat server's control
//! connection. The media path itself (admission, forwarding, the serving loop) is `crewcraft-media`, which stays pure
//! Rust; this crate adds TLS (rustls with ring, as the chat server uses), decided 2026-11-26 (docs/CALLS.md).

pub mod control;
