//! The invitation link a server writes and a client opens. Task T234.
//!
//! Owns: the one link format both sides use, `crewcraft://enroll?server=<host:port>&code=<code>&root_sha256=<hex>`,
//! its parsing (strict: a malformed link is refused, never repaired) and its writing. Does not own: the code format
//! (`EnrollmentCode`), the fingerprint (`server_trust::RootFingerprint`), or what the client does with a parsed link.
//! Called by: the server's invitation commands (writing) and the client (opening a link).
//!
//! Rules:
//! - The text starts with exactly `crewcraft://enroll?`: the scheme and path are compared byte for byte.
//! - The query holds `server`, `code` and `root_sha256`, each exactly once, in any order, and nothing else: no other
//!   key, no empty parameter, no fragment.
//! - Values may hold unreserved characters (`A-Z a-z 0-9 - . _ ~`), `:` and percent escapes (`%5B`); anything else
//!   is refused. Escapes are decoded once and the result must be UTF-8.
//! - `server` is `host:port`: a DNS name (kept in lowercase), an IPv4 address, or an IPv6 address in brackets; the
//!   port is 1 to 65535 without a sign or leading zeros. Unspecified, multicast and broadcast addresses are refused.
//! - `code` is read by `EnrollmentCode::parse` and written in its display form.
//! - `root_sha256` is 64 hexadecimal digits, written in lowercase.
//!
//! The link carries the one-time code, so `Debug` never prints it and the decoded code text is wiped from memory.

use std::fmt;
use std::net::IpAddr;

use zeroize::Zeroizing;

use crate::EnrollmentCode;
use crate::server_trust::RootFingerprint;

/// The fixed start of every invitation link.
pub const PREFIX: &str = "crewcraft://enroll?";
/// The longest link accepted, in bytes.
pub const MAX_LINK: usize = 1024;
/// The longest code text accepted after decoding, in bytes (a typed code may carry spaces and extra hyphens).
const MAX_CODE_TEXT: usize = 128;
const MAX_DNS_NAME: usize = 253;
const MAX_LABEL: usize = 63;

/// Why a link was refused. Nothing here repeats the link's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkError {
    /// Empty, or longer than `MAX_LINK`.
    Length,
    /// The text does not start with `PREFIX`, or has a fragment.
    Prefix,
    /// A parameter is empty, unknown, repeated or missing, or has no `=`.
    Parameter,
    /// A value holds a character a query value may not, a bad percent escape, or bytes that are not UTF-8.
    Encoding,
    /// `server` is not `host:port` with a valid host and port.
    Server,
    /// `code` is not an enrollment code.
    Code,
    /// `root_sha256` is not 64 hexadecimal digits.
    Fingerprint,
}

impl fmt::Display for LinkError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str(match self {
            Self::Length => "the invitation link is empty or too long",
            Self::Prefix => "this is not a CrewCraft invitation link",
            Self::Parameter => "the invitation link needs server, code and root_sha256, each once",
            Self::Encoding => "the invitation link is not encoded correctly",
            Self::Server => "the invitation's server is not a host name or address with a port",
            Self::Code => "the invitation's code is not valid",
            Self::Fingerprint => "the invitation's root fingerprint is not 64 hexadecimal digits",
        })
    }
}

impl std::error::Error for LinkError {}

/// The host part of an invitation's server.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Host {
    /// Lowercase ASCII.
    Dns(String),
    Ip(IpAddr),
}

/// A parsed invitation: where the server is, the one-time code, and the root fingerprint to pin.
#[derive(Clone, PartialEq, Eq)]
pub struct InvitationLink {
    host: Host,
    port: u16,
    code: EnrollmentCode,
    root: RootFingerprint,
}

impl fmt::Debug for InvitationLink {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.debug_struct("InvitationLink").field("server", &self.server()).field("root_sha256", &self.root).finish_non_exhaustive()
    }
}

impl InvitationLink {
    /// A link for `server` (`host:port`, as `parse` accepts it), `code` and `root`.
    pub fn new(server: &str, code: EnrollmentCode, root: RootFingerprint) -> Result<Self, LinkError> {
        let (host, port) = parse_server(server)?;
        Ok(Self { host, port, code, root })
    }

    /// Read a link. See the module documentation for what is accepted; anything else is refused.
    pub fn parse(text: &str) -> Result<Self, LinkError> {
        if text.is_empty() || text.len() > MAX_LINK {
            return Err(LinkError::Length);
        }
        let query = text.strip_prefix(PREFIX).ok_or(LinkError::Prefix)?;
        if query.contains('#') {
            return Err(LinkError::Prefix);
        }
        let (mut server, mut code, mut root) = (None, None, None);
        for parameter in query.split('&') {
            let (key, value) = parameter.split_once('=').ok_or(LinkError::Parameter)?;
            let slot = match key {
                "server" => &mut server,
                "code" => &mut code,
                "root_sha256" => &mut root,
                _ => return Err(LinkError::Parameter),
            };
            if slot.is_some() || value.is_empty() {
                return Err(LinkError::Parameter);
            }
            *slot = Some(decode(value)?);
        }
        let (Some(server), Some(code), Some(root)) = (server, code, root) else {
            return Err(LinkError::Parameter);
        };
        let (host, port) = parse_server(&server)?;
        if code.len() > MAX_CODE_TEXT {
            return Err(LinkError::Code);
        }
        let code = EnrollmentCode::parse(&code).map_err(|_| LinkError::Code)?;
        let root = RootFingerprint::parse(&root).ok_or(LinkError::Fingerprint)?;
        Ok(Self { host, port, code, root })
    }

    /// The server as the link writes it: `host:port`, or `[address]:port` for IPv6. A client connects here.
    pub fn server(&self) -> String {
        match &self.host {
            Host::Ip(IpAddr::V6(address)) => format!("[{address}]:{}", self.port),
            Host::Ip(address) => format!("{address}:{}", self.port),
            Host::Dns(name) => format!("{name}:{}", self.port),
        }
    }

    /// The name the server's certificate must carry: the DNS name, or the address without brackets.
    pub fn server_name(&self) -> String {
        match &self.host {
            Host::Dns(name) => name.clone(),
            Host::Ip(address) => address.to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The one-time enrollment code. Never log it.
    pub fn code(&self) -> &EnrollmentCode {
        &self.code
    }

    /// The SHA-256 of the server's root certificate, to pin before trusting it.
    pub fn root_sha256(&self) -> RootFingerprint {
        self.root
    }
}

/// Writes the link. This prints the one-time code: show it only to the person it is for.
impl fmt::Display for InvitationLink {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = Zeroizing::new(self.code.to_display());
        let link = Zeroizing::new(write_link(&self.server(), &code, self.root));
        output.write_str(&link)
    }
}

/// The link text for these parts, each value percent-encoded where a query needs it (an IPv6 server's brackets are
/// written `%5B` and `%5D`). `InvitationLink`'s `Display` is this function over validated parts; a caller holding
/// unvalidated text gets the same bytes, which `InvitationLink::parse` then checks.
pub fn write_link(server: &str, code: &str, root: RootFingerprint) -> String {
    let mut out = String::with_capacity(PREFIX.len() + server.len() + code.len() + 96);
    out.push_str(PREFIX);
    out.push_str("server=");
    encode_into(&mut out, server);
    out.push_str("&code=");
    encode_into(&mut out, code);
    out.push_str("&root_sha256=");
    out.push_str(&root.to_string());
    out
}

fn plain(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b':')
}

fn encode_into(out: &mut String, text: &str) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in text.bytes() {
        if plain(byte) {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(byte >> 4)]));
            out.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

/// Percent-decode one value. The decoded bytes are wiped when dropped, since a value may be the code.
fn decode(value: &str) -> Result<Zeroizing<String>, LinkError> {
    let bytes = value.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let high = bytes.get(index + 1).and_then(|digit| char::from(*digit).to_digit(16)).ok_or(LinkError::Encoding)?;
            let low = bytes.get(index + 2).and_then(|digit| char::from(*digit).to_digit(16)).ok_or(LinkError::Encoding)?;
            out.push((high * 16 + low) as u8);
            index += 3;
        } else if plain(byte) {
            out.push(byte);
            index += 1;
        } else {
            return Err(LinkError::Encoding);
        }
    }
    let text = std::str::from_utf8(&out).map_err(|_| LinkError::Encoding)?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn parse_server(server: &str) -> Result<(Host, u16), LinkError> {
    let (host, port) = server.rsplit_once(':').ok_or(LinkError::Server)?;
    let port_ok = !port.is_empty() && port.len() <= 5 && port.bytes().all(|byte| byte.is_ascii_digit()) && !port.starts_with('0');
    let port = port.parse::<u16>().ok().filter(|_| port_ok).ok_or(LinkError::Server)?;
    let host = if let Some(inner) = host.strip_prefix('[') {
        let inner = inner.strip_suffix(']').ok_or(LinkError::Server)?;
        match inner.parse::<IpAddr>() {
            Ok(IpAddr::V6(address)) => address_host(IpAddr::V6(address))?,
            _ => return Err(LinkError::Server),
        }
    } else if let Ok(address) = host.parse::<IpAddr>() {
        // An IPv6 address must be in brackets, or its last group would read as the port.
        match address {
            IpAddr::V4(_) => address_host(address)?,
            IpAddr::V6(_) => return Err(LinkError::Server),
        }
    } else {
        dns_host(host)?
    };
    Ok((host, port))
}

fn address_host(address: IpAddr) -> Result<Host, LinkError> {
    let refused = address.is_unspecified() || address.is_multicast() || matches!(address, IpAddr::V4(v4) if v4.is_broadcast());
    if refused { Err(LinkError::Server) } else { Ok(Host::Ip(address)) }
}

fn dns_host(host: &str) -> Result<Host, LinkError> {
    if host.is_empty() || host.len() > MAX_DNS_NAME || !host.is_ascii() {
        return Err(LinkError::Server);
    }
    let name = host.to_ascii_lowercase();
    let mut last = "";
    for label in name.split('.') {
        let valid = !label.is_empty()
            && label.len() <= MAX_LABEL
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if !valid {
            return Err(LinkError::Server);
        }
        last = label;
    }
    // A name such as `192.0.2` would read as an address to some resolvers.
    if last.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(LinkError::Server);
    }
    Ok(Host::Dns(name))
}
