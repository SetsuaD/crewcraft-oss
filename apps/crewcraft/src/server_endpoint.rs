//! Where an enrolled client connects: any server address, the server name its certificate must carry, and the one
//! pinned root it must chain to. The loopback-only `lab_client::LabEndpoint` stays as it is for the lab.
//!
//! Owns: address checking and resolution, trust pinning from an invitation's root and fingerprint, fetching that
//! root from the server when the invitation carries only its fingerprint (`fetch_root`, task T232), and the entry
//! points for enrollment (`open_bootstrap`) and sign-in (`sign_in`). Called by `device` (enrollment and stored
//! devices) and `worker`. Calls `connect` for TLS, `bootstrap_transport` for enrollment and `signed_in` for sign-in.

use std::fmt;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_enroll::{EnrollmentCode, InvitationLink};
use crewcraft_tls::DeadlineSocket;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ResolvesClientCert, Resumption, WebPkiServerVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::bootstrap_transport::{BootstrapConnection, BootstrapTransportError, open_bootstrap};
use crate::connect::{self, Connection, Transport};
use crate::lab_client::LabError;
use crate::signed_in::{Credentials, ResumeTicket, SignedInSession, sign_in};

/// Longest accepted root certificate.
pub const MAX_ROOT_DER: usize = 16 * 1024;
/// Longest accepted address text, `host:port` or `[v6]:port`.
pub const MAX_ADDRESS: usize = 260;
/// At most this many resolved addresses are tried per connection.
const MAX_RESOLVED: usize = 8;
/// Longest certificate accepted anywhere in the chain `fetch_root` is shown.
pub const MAX_PRESENTED_CERT: usize = 16 * 1024;
/// Most certificates `fetch_root` accepts after the server's own: the issuing authority and the root, with room for
/// one more level.
const MAX_PRESENTED_ISSUERS: usize = 3;
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

    /// Connect as `device` and reopen the session `ticket` names, without a password or code (task T240).
    pub fn resume(&self, device: Arc<dyn ResolvesClientCert>, ticket: &ResumeTicket) -> Result<SignedInSession, LabError> {
        crate::signed_in::resume(self.connect(device)?.transport, ticket, CLIENT_NAME)
    }

    pub(crate) fn resume_over(&self, transport: Transport, ticket: &ResumeTicket) -> Result<SignedInSession, LabError> {
        crate::signed_in::resume(transport, ticket, CLIENT_NAME)
    }

    /// Connect as `device` and begin a sign-in through the server's external identity provider (task T611g). `None`
    /// when the server offers none.
    pub fn begin_external(&self, device: Arc<dyn ResolvesClientCert>) -> Result<Option<crate::chat_session::ExternalStart>, LabError> {
        crate::signed_in::begin_external(self.connect(device)?.transport)
    }

    /// Connect as `device` and finish that sign-in with the provider's code (task T611g). `email` is the person this
    /// device is enrolled for.
    pub fn finish_external(
        &self,
        device: Arc<dyn ResolvesClientCert>,
        email: &str,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<SignedInSession, LabError> {
        crate::signed_in::finish_external(self.connect(device)?.transport, email, code, verifier, redirect_uri, CLIENT_NAME)
    }

    /// Connect as `device` and ask the server to end the session `ticket` names (task T240).
    pub fn end_session(&self, device: Arc<dyn ResolvesClientCert>, ticket: &ResumeTicket) -> Result<(), LabError> {
        crate::signed_in::end(self.connect(device)?.transport, ticket)
    }

    /// `fetch_root`, then `new` with the root it returned: the endpoint for an invitation that carries only the
    /// root's fingerprint.
    pub fn fetch(address: &str, server_name: &str, expected_root: RootFingerprint, timeout: Duration) -> Result<Self, LabError> {
        let root_der = fetch_root(address, server_name, expected_root, timeout)?;
        Self::new(address, server_name, expected_root, &root_der)
    }

    /// `fetch` for a parsed invitation link: its server is the address, its host the server name, its fingerprint
    /// the pin. The code stays in the link, for `open_bootstrap`.
    pub fn from_invitation(link: &InvitationLink, timeout: Duration) -> Result<Self, LabError> {
        Self::fetch(&link.server(), &link.server_name(), link.root_sha256(), timeout)
    }

    fn resolve(&self) -> Result<Vec<SocketAddr>, LabError> {
        resolve(&self.address)
    }
}

fn resolve(address: &str) -> Result<Vec<SocketAddr>, LabError> {
    if let Ok(address) = address.parse::<SocketAddr>() {
        return Ok(vec![address]);
    }
    let addresses: Vec<_> = address.to_socket_addrs().map_err(|error| LabError::Connect(error.kind()))?.take(MAX_RESOLVED).collect();
    if addresses.is_empty() { Err(LabError::Address) } else { Ok(addresses) }
}

/// Fetch the server's root certificate when an invitation gives only its SHA-256 (task T232).
///
/// Opens TLS 1.3 to `address` and reads the chain the server presents, which ends with its root. The root is
/// returned only when its SHA-256 equals `expected_root`, AND the whole chain verifies against that root for
/// `server_name` (webpki, exactly as every later connection checks it), AND the server proves it holds the leaf's key
/// and its handshake finishes. The client presents no certificate and sends no application byte: it stops before
/// writing its own last handshake flight, which a server that admits only enrolled devices would refuse anyway.
///
/// `timeout` bounds the connection and the handshake (a host-name lookup is not bounded by it). Errors:
/// `LabError::Address` for a malformed address; `LabError::Trust` for a bad name, or a refused chain (no root at its
/// end, a fingerprint that does not match, a chain that does not verify for the name, a certificate over
/// `MAX_PRESENTED_CERT` bytes, too many certificates); `LabError::Connect` when no address answers;
/// `LabError::Handshake` when TLS fails otherwise.
pub fn fetch_root(address: &str, server_name: &str, expected_root: RootFingerprint, timeout: Duration) -> Result<Vec<u8>, LabError> {
    if !valid_address(address) {
        return Err(LabError::Address);
    }
    let name = ServerName::try_from(server_name.to_owned()).map_err(|_| LabError::Trust)?;
    let deadline = Instant::now().checked_add(timeout).ok_or(LabError::Handshake)?;
    let addresses = resolve(address)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut last = LabError::Address;
    for address in &addresses {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(LabError::Connect(std::io::ErrorKind::TimedOut));
        }
        let tcp = match TcpStream::connect_timeout(address, left) {
            Ok(tcp) => tcp,
            Err(error) => {
                last = LabError::Connect(error.kind());
                continue;
            }
        };
        // A refused chain is not retried on another address: it would present the same certificates.
        return root_over(tcp, &name, expected_root, &provider, deadline);
    }
    Err(last)
}

fn root_over(
    tcp: TcpStream,
    name: &ServerName<'static>,
    expected_root: RootFingerprint,
    provider: &Arc<CryptoProvider>,
    deadline: Instant,
) -> Result<Vec<u8>, LabError> {
    let verifier = Arc::new(PinnedRoot {
        provider: provider.clone(),
        expected: expected_root,
        candidate: Mutex::new(None),
        refused: AtomicBool::new(false),
        proven: AtomicBool::new(false),
    });
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| LabError::Trust)?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    let mut connection = ClientConnection::new(Arc::new(config), name.clone()).map_err(|_| LabError::Trust)?;
    let mut socket = DeadlineSocket::new(tcp, deadline);
    // Driven by hand, so the client's own final flight is never written.
    while connection.is_handshaking() {
        if connection.wants_write() {
            connection.write_tls(&mut socket).map_err(|_| LabError::Handshake)?;
            continue;
        }
        if connection.read_tls(&mut socket).map_err(|_| LabError::Handshake)? == 0 {
            return Err(LabError::Handshake);
        }
        if connection.process_new_packets().is_err() {
            // The queued alert is dropped with the connection and never written.
            return Err(if verifier.refused.load(Ordering::Acquire) { LabError::Trust } else { LabError::Handshake });
        }
    }
    let root = verifier.candidate.lock().ok().and_then(|mut held| held.take());
    match root {
        Some(root) if verifier.proven.load(Ordering::Acquire) => Ok(root),
        _ => Err(LabError::Trust),
    }
}

/// Accepts a server chain only when it ends with the pinned root and verifies against it, and keeps that root.
struct PinnedRoot {
    provider: Arc<CryptoProvider>,
    expected: RootFingerprint,
    /// The root of the chain that verified.
    candidate: Mutex<Option<Vec<u8>>>,
    /// A presented chain was refused.
    refused: AtomicBool,
    /// The server's handshake signature verified with the leaf's key.
    proven: AtomicBool,
}

impl fmt::Debug for PinnedRoot {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.debug_struct("PinnedRoot").field("expected", &self.expected).finish_non_exhaustive()
    }
}

impl PinnedRoot {
    fn check(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let unknown = || rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer);
        let malformed = || rustls::Error::InvalidCertificate(CertificateError::BadEncoding);
        let (root, issuers) = intermediates.split_last().ok_or_else(unknown)?;
        let oversized = std::iter::once(end_entity).chain(intermediates).any(|certificate| certificate.len() > MAX_PRESENTED_CERT);
        if oversized || intermediates.len() > MAX_PRESENTED_ISSUERS || root.len() > MAX_ROOT_DER {
            return Err(malformed());
        }
        if !self.expected.matches(root) {
            return Err(unknown());
        }
        let mut roots = RootCertStore::empty();
        roots.add(root.clone().into_owned()).map_err(|_| malformed())?;
        let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone()).build().map_err(|_| unknown())?;
        let verified = webpki.verify_server_cert(end_entity, issuers, server_name, ocsp_response, now)?;
        *self.candidate.lock().map_err(|_| unknown())? = Some(root.as_ref().to_vec());
        Ok(verified)
    }
}

impl ServerCertVerifier for PinnedRoot {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let result = self.check(end_entity, intermediates, server_name, ocsp_response, now);
        if result.is_err() {
            self.refused.store(true, Ordering::Release);
        }
        result
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Only TLS 1.3 is offered, so this is never asked.
        Err(rustls::Error::General("TLS 1.2 is not offered".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let valid = verify_tls13_signature(message, certificate, signature, &self.provider.signature_verification_algorithms)?;
        self.proven.store(true, Ordering::Release);
        Ok(valid)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
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
