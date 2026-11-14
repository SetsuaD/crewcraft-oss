//! The WebSocket opening handshake (RFC 6455 section 4) as the server sees it: find the end of the request head, check
//! that it is a valid upgrade request from an allowed origin, and answer with the 101 response. Live updates ride on a
//! WebSocket per client (docs/SPEC.md section 3). Frames are `ws_frame` (T208), messages `ws_message` (T209). TLS and the
//! client-certificate check happen below this, so this code is only ever reached by an enrolled device.
//! Task T207.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha1::{Digest, Sha1};

/// The fixed string RFC 6455 appends to the client's key before hashing.
pub const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Largest request head accepted, in bytes, including the final blank line.
pub const MAX_HEAD: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpgradeError {
    /// No end of head within `MAX_HEAD` bytes (from `head_len`), or a head longer than that (from `parse_upgrade`).
    TooLarge,
    /// The first line is not `<method> <target> <version>` with a target starting with `/`.
    BadRequestLine,
    NotGet,
    /// Not `HTTP/1.1`.
    BadVersion,
    /// A header line without a colon, one that starts with a space or tab (line folding), or a head that is not UTF-8.
    BadHeader,
    MissingUpgrade,
    MissingConnection,
    /// `Sec-WebSocket-Version` missing or not `13`.
    BadWsVersion,
    /// `Sec-WebSocket-Key` missing, repeated, or not the base64 of 16 bytes.
    BadKey,
    /// An `Origin` header is present but is not the allowed origin (or is repeated).
    OriginRefused,
}

/// A request that passed `parse_upgrade`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upgrade {
    /// The request target as sent, for example `/live`.
    pub path: String,
    /// The client's `Sec-WebSocket-Key`, as sent.
    pub key: String,
}

/// `base64(SHA-1(client_key + GUID))`, the `Sec-WebSocket-Accept` value.
#[allow(clippy::todo, reason = "stubs until task T207 lands; remove this allow with them")]
pub fn accept_key(client_key: &str) -> String {
    let _ = (client_key, GUID, STANDARD.encode(Sha1::digest(b"")));
    todo!("T207: accept_key")
}

/// Where the request head ends in `buf`, for a reader that is collecting bytes: `Some(n)` when the first `\r\n\r\n` ends
/// at byte `n` (the head is `buf[..n]`; it is accepted when `n <= MAX_HEAD`), `None` while the end has not arrived yet,
/// `Err(TooLarge)` when no end appears within the first `MAX_HEAD` bytes.
#[allow(clippy::todo, reason = "stubs until task T207 lands; remove this allow with them")]
pub fn head_len(buf: &[u8]) -> Result<Option<usize>, UpgradeError> {
    let _ = (buf, MAX_HEAD);
    todo!("T207: head_len")
}

/// Check a complete request head (ending in `\r\n\r\n`). Checks, in order:
/// 1. the length (`TooLarge` over `MAX_HEAD`) and UTF-8 (`BadHeader`);
/// 2. the request line: three space-separated parts (`BadRequestLine`), method `GET` (`NotGet`), target starting with `/`
///    (`BadRequestLine`), version `HTTP/1.1` (`BadVersion`);
/// 3. every header line is `name: value` with no leading space or tab (`BadHeader`); names compare ASCII-case-insensitively
///    and values are trimmed of spaces and tabs;
/// 4. `Upgrade` has the token `websocket` (case-insensitive, among comma-separated tokens), else `MissingUpgrade`;
/// 5. `Connection` has the token `upgrade` (same rules; `keep-alive, Upgrade` passes), else `MissingConnection`;
/// 6. `Sec-WebSocket-Version` is exactly `13`, else `BadWsVersion`;
/// 7. exactly one `Sec-WebSocket-Key`, whose standard base64 decodes to exactly 16 bytes, else `BadKey`;
/// 8. if an `Origin` header is present it must be there once and equal `allowed_origin` byte for byte (for example
///    `https://chat.example.org`), else `OriginRefused`. A request with no `Origin` (a desktop or phone client, not a
///    browser) is allowed: a browser always sends one, and that is what stops another website from driving a browser that
///    holds the device certificate.
#[allow(clippy::todo, reason = "stubs until task T207 lands; remove this allow with them")]
pub fn parse_upgrade(head: &[u8], allowed_origin: &str) -> Result<Upgrade, UpgradeError> {
    let _ = (head, allowed_origin);
    todo!("T207: parse_upgrade")
}

/// The 101 response for a request whose key is `key`, exactly:
/// `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: <accept_key>\r\n\r\n`.
#[allow(clippy::todo, reason = "stubs until task T207 lands; remove this allow with them")]
pub fn upgrade_response(key: &str) -> Vec<u8> {
    let _ = key;
    todo!("T207: upgrade_response")
}
