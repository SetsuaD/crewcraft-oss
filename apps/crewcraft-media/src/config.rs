//! The media server's settings (task T363b): `media.toml`, in the strict TOML subset of `crewcraft-strict-toml`, and
//! the chat server's public media key it names.
//!
//! Owns: reading and checking both files. Called by: `main.rs` and [`crate::serve::bind`].
//!
//! ```toml
//! [media]
//! server-name = "media.example.org"   # what credentials must name (the chat server issues them for this name)
//! listen = "0.0.0.0:3478"             # the UDP socket
//! public-address = "203.0.113.10:3478" # the ICE candidate participants reach; optional when `listen` is a
//!                                      # specific address, which is then used
//! chat-server-key = "chat-server.key" # a file next to media.toml: the chat server's Ed25519 media key, 64 hex
//!                                      # characters; owner-only, like the server's other keys
//! max-call-size = 64                  # optional, 1 to MAX_CALL_SIZE (the default)
//! ```

use std::io;
use std::net::SocketAddr;
use std::path::Path;

use crewcraft_strict_toml as toml;

use crate::MAX_CALL_SIZE;

/// The longest `media.toml` read.
pub const MAX_FILE_BYTES: usize = 16 * 1024;
/// The longest key file read (the key, a line ending, and room for nothing else).
const MAX_KEY_FILE_BYTES: u64 = 256;
/// The longest server name: the longest name a credential can carry (`crewcraft_media_auth::MAX_NAME`).
const MAX_SERVER_NAME: usize = crewcraft_media_auth::MAX_NAME;

/// `media.toml`, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub server_name: String,
    pub listen: SocketAddr,
    /// `None`: the address the socket is bound to (only allowed when `listen` names a specific address).
    pub public_address: Option<SocketAddr>,
    /// The key file's name, in the same directory as `media.toml`.
    pub chat_server_key: String,
    pub max_call_size: usize,
}

/// Everything the media server needs to start: the settings and the key they name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaConfig {
    pub settings: Settings,
    pub trusted_key: [u8; 32],
}

fn bad(line: usize, key: &str, reason: &'static str) -> toml::Error {
    toml::Error::BadValue { line, key: key.to_owned(), reason }
}

fn address(text: &str, line: usize, key: &str) -> Result<SocketAddr, toml::Error> {
    text.parse().map_err(|_| bad(line, key, "an IP address and port, such as \"203.0.113.10:3478\""))
}

/// Read `media.toml`.
pub fn parse(text: &str) -> Result<Settings, toml::Error> {
    let doc = toml::parse(text, MAX_FILE_BYTES)?;
    doc.check_sections(&["media"], &[])?;
    let media = doc.require("media")?;
    media.check_keys("media", &["server-name", "listen", "public-address", "chat-server-key", "max-call-size"])?;

    let (server_name, line) = media.req_str("media", "server-name")?;
    let plain_name = !server_name.is_empty()
        && server_name.len() <= MAX_SERVER_NAME
        && server_name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'));
    if !plain_name {
        return Err(bad(line, "server-name", "a host name: lowercase letters, digits, dots and hyphens"));
    }

    let (text, listen_line) = media.req_str("media", "listen")?;
    let listen = address(text, listen_line, "listen")?;
    let public_address = match media.opt_str("public-address")? {
        None => None,
        Some((text, line)) => {
            let public = address(text, line, "public-address")?;
            if public.ip().is_unspecified() || public.port() == 0 {
                return Err(bad(line, "public-address", "a specific address and port participants can reach"));
            }
            Some(public)
        }
    };
    if public_address.is_none() && listen.ip().is_unspecified() {
        return Err(bad(listen_line, "listen", "a specific address, or set public-address (an unspecified address is no ICE candidate)"));
    }

    let (key_file, line) = media.req_str("media", "chat-server-key")?;
    let plain_file = !key_file.is_empty()
        && key_file.len() <= 255
        && !key_file.starts_with('.')
        && key_file.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if !plain_file {
        return Err(bad(line, "chat-server-key", "a plain file name next to media.toml"));
    }

    let max_call_size = match media.opt_int("max-call-size")? {
        None => MAX_CALL_SIZE,
        Some((size, line)) => match usize::try_from(size) {
            Ok(size) if (1..=MAX_CALL_SIZE).contains(&size) => size,
            _ => return Err(bad(line, "max-call-size", "1 to 64")),
        },
    };

    Ok(Settings { server_name: server_name.to_owned(), listen, public_address, chat_server_key: key_file.to_owned(), max_call_size })
}

/// The chat server's media key from a key file's text: 64 hexadecimal characters, then at most one line ending.
pub fn parse_key(text: &str) -> Option<[u8; 32]> {
    let hex = text.strip_suffix("\r\n").or_else(|| text.strip_suffix('\n')).unwrap_or(text);
    if hex.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    let (pairs, _) = hex.as_bytes().as_chunks::<2>();
    for (byte, pair) in key.iter_mut().zip(pairs) {
        let text = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(text, 16).ok()?;
    }
    Some(key)
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// A regular file of at most `max` bytes (a symbolic link is refused). `owner_only` also refuses, on Unix, a file
/// anyone but its owner can read or write, like the server's other keys.
fn read_file(path: &Path, max: u64, owner_only: bool) -> io::Result<String> {
    let shown = path.display();
    let meta = std::fs::symlink_metadata(path).map_err(|e| invalid(format!("{shown}: {e}")))?;
    if !meta.is_file() || meta.len() > max {
        return Err(invalid(format!("{shown} is not a regular file of at most {max} bytes")));
    }
    #[cfg(unix)]
    if owner_only {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(invalid(format!("{shown} can be read or changed by others; make it owner-only (chmod 600)")));
        }
    }
    #[cfg(not(unix))]
    let _ = owner_only;
    std::fs::read_to_string(path).map_err(|e| invalid(format!("{shown}: {e}")))
}

/// Read `media.toml` at `path` and the key file it names.
pub fn load(path: &Path) -> io::Result<MediaConfig> {
    let shown = path.display();
    let text = read_file(path, MAX_FILE_BYTES as u64, false)?;
    let settings = parse(&text).map_err(|e| invalid(format!("{shown}: {e}")))?;
    let key_path = path.parent().unwrap_or(Path::new(".")).join(&settings.chat_server_key);
    let key_text = read_file(&key_path, MAX_KEY_FILE_BYTES, true)?;
    let trusted_key =
        parse_key(&key_text).ok_or_else(|| invalid(format!("{}: not a key (64 hexadecimal characters on one line)", key_path.display())))?;
    Ok(MediaConfig { settings, trusted_key })
}
