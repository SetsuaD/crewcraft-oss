//! The name clients use to reach a network server: a DNS name or an IP address literal. Task T230.
//!
//! Owns: which names are accepted (the server certificate is signed for exactly this name, and every invitation link
//! carries it), their canonical spelling, and how a name and a port are written together.
//! Does not own: the certificate itself (`crewcraft_pki`), the listen address (any address, see `listener`).

use std::fmt;
use std::net::IpAddr;

/// The longest DNS name, without a trailing dot (RFC 1035 section 2.3.4).
const MAX_DNS_NAME: usize = 253;
/// The longest DNS label.
const MAX_LABEL: usize = 63;

/// A validated server name. DNS names are kept in lowercase ASCII; addresses in their canonical text form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerName {
    Dns(String),
    Ip(IpAddr),
}

/// The text is not a name a client could verify a server certificate against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadServerName;

impl fmt::Display for BadServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a server name is a DNS name (letters, digits, '-' and '.') or an IP address")
    }
}

impl std::error::Error for BadServerName {}

impl ServerName {
    /// Accept a DNS name (ASCII letters, digits and `-` in dot-separated labels of 1 to 63 characters, at most 253 in
    /// all, no leading or trailing `-`, no trailing dot, and a last label that is not all digits) or an IP address
    /// literal. An IPv6 literal may be written with or without brackets. Wildcards, international names in Unicode
    /// form, unspecified and multicast addresses are refused.
    pub fn parse(text: &str) -> Result<Self, BadServerName> {
        let bare = text.strip_prefix('[').and_then(|rest| rest.strip_suffix(']'));
        if let Some(inner) = bare {
            return match inner.parse::<IpAddr>() {
                Ok(IpAddr::V6(address)) => Self::address(IpAddr::V6(address)),
                _ => Err(BadServerName),
            };
        }
        if let Ok(address) = text.parse::<IpAddr>() {
            return Self::address(address);
        }
        Self::dns(text)
    }

    fn address(address: IpAddr) -> Result<Self, BadServerName> {
        let address = address.to_canonical();
        if address.is_unspecified() || address.is_multicast() || matches!(address, IpAddr::V4(v4) if v4.is_broadcast()) {
            return Err(BadServerName);
        }
        Ok(Self::Ip(address))
    }

    fn dns(text: &str) -> Result<Self, BadServerName> {
        if text.is_empty() || text.len() > MAX_DNS_NAME || !text.is_ascii() {
            return Err(BadServerName);
        }
        let name = text.to_ascii_lowercase();
        let mut last = "";
        for label in name.split('.') {
            let valid = !label.is_empty()
                && label.len() <= MAX_LABEL
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
            if !valid {
                return Err(BadServerName);
            }
            last = label;
        }
        // A name such as `192.0.2` would read as an address to some resolvers.
        if last.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(BadServerName);
        }
        Ok(Self::Dns(name))
    }

    /// The name the server certificate is signed for and a client verifies: the DNS name, or the address text.
    pub fn certificate_name(&self) -> String {
        self.to_string()
    }

    /// The name with a port, as an invitation writes the server: `name:port`, or `[address]:port` for IPv6.
    pub fn with_port(&self, port: u16) -> String {
        match self {
            Self::Ip(IpAddr::V6(address)) => format!("[{address}]:{port}"),
            other => format!("{other}:{port}"),
        }
    }
}

impl fmt::Display for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(name) => f.write_str(name),
            Self::Ip(address) => write!(f, "{address}"),
        }
    }
}
