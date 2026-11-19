//! Where an enrolled client connects: any server address, the server name its certificate must carry, and the one
//! pinned root it must chain to. The loopback-only `lab_client::LabEndpoint` stays as it is for the lab.
//!
//! Owns: address checking and resolution, trust pinning from an invitation's root and fingerprint, and the entry
//! points for enrollment (`open_bootstrap`) and sign-in (`sign_in`). Called by `device` (enrollment and stored
//! devices) and `worker`. Calls `connect` for TLS, `bootstrap_transport` for enrollment and `signed_in` for sign-in.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crewcraft_enroll::EnrollmentCode;
use crewcraft_enroll::server_trust::RootFingerprint;
use rustls::RootCertStore;
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, ServerName};

use crate::bootstrap_transport::{BootstrapConnection, BootstrapTransportError, open_bootstrap};
use crate::connect::{self, Connection, Transport};
use crate::lab_client::LabError;
use crate::signed_in::{Credentials, SignedInSession, sign_in};

/// Longest accepted root certificate.
pub const MAX_ROOT_DER: usize = 16 * 1024;
/// Longest accepted address text, `host:port` or `[v6]:port`.
pub const MAX_ADDRESS: usize = 260;
/// At most this many resolved addresses are tried per connection.
const MAX_RESOLVED: usize = 8;
const CLIENT_NAME: &str = "crewcraft";

/// A server the client trusts through one pinned root. Nothing here holds a secret.
#[derive(Clone)]
pub struct ServerEndpoint {
    address: String,
    server_name: ServerName<'static>,
    server_name_text: String,
    root_der: Vec<u8>,
    fingerprint: RootFingerprint,
    roots: RootCertStore,
}

impl std::fmt::Debug for ServerEndpoint {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.debug_struct("ServerEndpoint").field("address", &self.address).field("server_name", &self.server_name_text).finish_non_exhaustive()
    }
}

impl ServerEndpoint {
    /// `address` is `host:port`, `ipv4:port` or `[ipv6]:port` with a port from 1 to 65535; a host name is looked up
    /// on each connection attempt, but trust never depends on the lookup: the server must present a chain to
    /// `root_der` for `server_name`. `root_der` must match `expected_root`, the fingerprint from the invitation.
    ///
    /// Errors: `LabError::Address` for a malformed address, `LabError::Trust` for a bad name, root or fingerprint.
    pub fn new(address: &str, server_name: &str, expected_root: RootFingerprint, root_der: &[u8]) -> Result<Self, LabError> {
        if !valid_address(address) {
            return Err(LabError::Address);
        }
        let name = ServerName::try_from(server_name.to_owned()).map_err(|_| LabError::Trust)?;
        if root_der.is_empty() || root_der.len() > MAX_ROOT_DER || !expected_root.matches(root_der) {
            return Err(LabError::Trust);
        }
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(root_der.to_vec())).map_err(|_| LabError::Trust)?;
        Ok(Self {
            address: address.to_owned(),
            server_name: name,
            server_name_text: server_name.to_owned(),
            root_der: root_der.to_vec(),
            fingerprint: expected_root,
            roots,
        })
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn server_name(&self) -> &str {
        &self.server_name_text
    }

    /// The pinned root certificate, DER.
    pub fn root_der(&self) -> &[u8] {
        &self.root_der
    }

    /// The pinned root's SHA-256, as the invitation gave it.
    pub fn fingerprint(&self) -> RootFingerprint {
        self.fingerprint
    }

    /// Open an enrollment connection with only the invitation's temporary identity (see
    /// `bootstrap_transport::BootstrapEndpoint::open`, which this matches for any address).
    pub fn open_bootstrap(&self, code: &EnrollmentCode, confirmation_window: Duration) -> Result<BootstrapConnection<'_>, BootstrapTransportError> {
        open_bootstrap(|device| Ok(self.connect(device)?.transport), &self.root_der, code, confirmation_window)
    }

    /// Connect with an enrolled device and sign in with `credentials`. Each call is a new connection, and each needs
    /// a fresh authenticator code: the server refuses a code it has already accepted.
    pub fn sign_in(&self, device: Arc<dyn ResolvesClientCert>, credentials: &Credentials) -> Result<SignedInSession, LabError> {
        sign_in(self.connect(device)?.transport, &credentials.sign_in(), CLIENT_NAME)
    }

    pub(crate) fn connect(&self, device: Arc<dyn ResolvesClientCert>) -> Result<Connection, LabError> {
        let addresses = self.resolve()?;
        connect::connect(&addresses, &self.server_name, &self.roots, device)
    }

    pub(crate) fn sign_in_over(&self, transport: Transport, credentials: &Credentials) -> Result<SignedInSession, LabError> {
        sign_in(transport, &credentials.sign_in(), CLIENT_NAME)
    }

    fn resolve(&self) -> Result<Vec<SocketAddr>, LabError> {
        if let Ok(address) = self.address.parse::<SocketAddr>() {
            return Ok(vec![address]);
        }
        let addresses: Vec<_> = self.address.to_socket_addrs().map_err(|error| LabError::Connect(error.kind()))?.take(MAX_RESOLVED).collect();
        if addresses.is_empty() { Err(LabError::Address) } else { Ok(addresses) }
    }
}

fn valid_address(address: &str) -> bool {
    if address.is_empty() || address.len() > MAX_ADDRESS {
        return false;
    }
    if let Ok(numeric) = address.parse::<SocketAddr>() {
        return numeric.port() != 0 && !numeric.ip().is_unspecified() && !numeric.ip().is_multicast();
    }
    let Some((host, port)) = address.rsplit_once(':') else {
        return false;
    };
    let port_ok = !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) && port.parse::<u16>().is_ok_and(|port| port != 0);
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    port_ok && host_ok
}

#[cfg(test)]
mod tests {
    use super::valid_address;

    #[test]
    fn addresses_need_a_host_and_a_port() {
        for good in ["chat.example.org:443", "192.0.2.10:8443", "[2001:db8::1]:443", "127.0.0.1:1", "localhost:4242"] {
            assert!(valid_address(good), "{good}");
        }
        for bad in [
            "",
            "chat.example.org",
            "chat.example.org:",
            "chat.example.org:0",
            "chat.example.org:65536",
            "chat.example.org:+443",
            "0.0.0.0:443",
            "chat..example.org:443",
            "-chat.example.org:443",
            "chat example.org:443",
            "2001:db8::1:443",
            "user@example.org:443",
        ] {
            assert!(!valid_address(bad), "{bad}");
        }
    }
}
