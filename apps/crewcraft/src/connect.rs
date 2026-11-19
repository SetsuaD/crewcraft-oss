//! Open one verified mutual TLS connection with an enrolled device's certificate. Shared by the loopback lab endpoint
//! (`lab_client`) and the general server endpoint (`server_endpoint`).
//!
//! Owns: the client TLS configuration (TLS 1.3 only, the ring provider, no resumption or early data, only the pinned
//! roots), the bounded TCP connect and handshake, and the check that the server actually asked for and received the
//! device certificate. Holds no account logic and reads no credentials.

use std::fmt;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crewcraft_tls::DeadlineSocket;
use rustls::client::{ResolvesClientCert, Resumption};
use rustls::pki_types::ServerName;
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ClientConnection, RootCertStore, SignatureScheme, StreamOwned};

use crate::lab_client::LabError;

const TCP_TIMEOUT: Duration = Duration::from_secs(3);
const TLS_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) type Transport = StreamOwned<ClientConnection, DeadlineSocket>;

/// A verified connection and a second handle to its socket, so another thread can end blocking I/O on it.
pub(crate) struct Connection {
    pub(crate) transport: Transport,
    pub(crate) interrupt: Option<TcpStream>,
}

/// Close a connection's socket from another thread. Any blocked read or write on it returns at once.
pub(crate) fn interrupt(socket: &TcpStream) {
    let _ = socket.shutdown(Shutdown::Both);
}

/// Try each address in turn until one completes TCP and the TLS handshake, or return the last failure. The server's
/// chain must reach `roots` and name `server_name`; no DNS-derived or platform trust is used.
pub(crate) fn connect(
    addresses: &[SocketAddr],
    server_name: &ServerName<'static>,
    roots: &RootCertStore,
    device: Arc<dyn ResolvesClientCert>,
) -> Result<Connection, LabError> {
    if !device.has_certs() || device.only_raw_public_keys() {
        return Err(LabError::Device);
    }
    let resolver = Arc::new(SelectedDevice { device, selected: AtomicBool::new(false) });
    let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| LabError::Trust)?
        .with_root_certificates(roots.clone())
        .with_client_cert_resolver(resolver.clone());
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    let config = Arc::new(config);

    let mut last = LabError::Address;
    for address in addresses {
        let tcp = match TcpStream::connect_timeout(address, TCP_TIMEOUT) {
            Ok(tcp) => tcp,
            Err(error) => {
                last = LabError::Connect(error.kind());
                continue;
            }
        };
        // Trust failures are not retried on another address: the next one would present the same certificate.
        let mut connection = ClientConnection::new(config.clone(), server_name.clone()).map_err(|_| LabError::Trust)?;
        let interrupt = tcp.try_clone().ok();
        let mut socket = DeadlineSocket::new(tcp, Instant::now() + TLS_TIMEOUT);
        connection.complete_io(&mut socket).map_err(|_| LabError::Handshake)?;
        if connection.is_handshaking() || connection.wants_write() {
            return Err(LabError::Handshake);
        }
        if !resolver.selected.load(Ordering::Relaxed) {
            return Err(LabError::Device);
        }
        return Ok(Connection { transport: StreamOwned::new(connection, socket), interrupt });
    }
    Err(last)
}

struct SelectedDevice {
    device: Arc<dyn ResolvesClientCert>,
    selected: AtomicBool,
}

impl fmt::Debug for SelectedDevice {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("SelectedDevice { .. }")
    }
}

impl ResolvesClientCert for SelectedDevice {
    fn resolve(&self, root_hint_subjects: &[&[u8]], schemes: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        let selected =
            self.device.resolve(root_hint_subjects, schemes).filter(|key| !key.cert.is_empty() && key.key.choose_scheme(schemes).is_some());
        self.selected.store(selected.is_some(), Ordering::Relaxed);
        selected
    }

    fn has_certs(&self) -> bool {
        self.device.has_certs()
    }
}
