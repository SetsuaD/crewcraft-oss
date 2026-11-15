//! Mutual TLS for the staff entrance (docs/SECURITY-DESIGN.md sections 1 and 3).
//!
//! Owns: the rustls server and client configuration (TLS 1.3 only, the `ring` crypto provider, a client
//! certificate required) and `accept`, a handshake that is bounded in time and writes nothing to a client that
//! fails it. Holds no sockets of its own and no account, device or invitation logic: `crewcraft-server-core` decides
//! who a certificate belongs to, this crate only proves the peer holds the key for a certificate the server trusts.
//! Called by: the server binary (the listener) and the client binaries (`client_config`).
//!
//! Why `accept` drives rustls by hand: `ServerConnection::complete_io` flushes the TLS alert it queues when a
//! handshake fails, so a client with no acceptable certificate would be told why. Here a failed handshake returns
//! the error and the caller drops the socket; the alert is never written (docs/SECURITY-DESIGN.md section 1). TLS 1.3
//! still sends its first server flight before it sees the client's certificate, so "zero bytes" holds for
//! application data and alerts, not for the handshake records themselves.

use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::Resumption;
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::{NoServerSessionStorage, VerifierBuilderError, WebPkiClientVerifier};
use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned};

/// A certificate chain (leaf first) and the private key of its leaf.
pub type Identity = (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>);

#[derive(Debug)]
pub enum TlsError {
    /// The certificate, key or protocol settings were refused when building a configuration.
    Config(rustls::Error),
    /// The trusted client roots were unusable (for example an empty list).
    Verifier(VerifierBuilderError),
    /// The peer failed the handshake: no acceptable certificate, a bad signature, or not TLS at all.
    Handshake(rustls::Error),
    /// The handshake did not finish within the deadline.
    Timeout,
    /// The peer closed the connection during the handshake.
    Closed,
    /// The handshake finished without a client certificate (cannot happen with `server_config`; checked anyway).
    NoClientCertificate,
    /// A socket error other than a timeout.
    Io(io::ErrorKind),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsError::Config(e) => write!(f, "tls configuration: {e}"),
            TlsError::Verifier(e) => write!(f, "client verifier: {e}"),
            TlsError::Handshake(e) => write!(f, "tls handshake: {e}"),
            TlsError::Timeout => f.write_str("tls handshake timed out"),
            TlsError::Closed => f.write_str("peer closed during the tls handshake"),
            TlsError::NoClientCertificate => f.write_str("no client certificate"),
            TlsError::Io(kind) => write!(f, "socket error: {kind}"),
        }
    }
}

impl std::error::Error for TlsError {}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

/// The server side: TLS 1.3 only, `identity` as the server certificate, and a client certificate that must chain to
/// `client_roots`. A client without one fails the handshake. Resumption and early data are disabled.
pub fn server_config(identity: Identity, client_roots: RootCertStore) -> Result<Arc<ServerConfig>, TlsError> {
    let provider = provider();
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), Arc::clone(&provider)).build().map_err(TlsError::Verifier)?;
    let (chain, key) = identity;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(TlsError::Config)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(TlsError::Config)?;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// The client side: TLS 1.3 only, the server certificate must chain to `server_roots`, and `identity` is presented
/// when the server asks for a certificate (`None` presents none, which a `server_config` server refuses).
pub fn client_config(server_roots: RootCertStore, identity: Option<Identity>) -> Result<Arc<ClientConfig>, TlsError> {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(TlsError::Config)?
        .with_root_certificates(server_roots);
    let mut config = match identity {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key).map_err(TlsError::Config)?,
        None => builder.with_no_client_auth(),
    };
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

/// Create a client stream for `server_name`. The first I/O drives the handshake using the socket's timeouts.
pub fn connect(
    tcp: TcpStream,
    config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
) -> Result<StreamOwned<ClientConnection, TcpStream>, TlsError> {
    let conn = ClientConnection::new(config, server_name).map_err(TlsError::Config)?;
    Ok(StreamOwned::new(conn, tcp))
}

/// A handshake that succeeded.
#[derive(Debug)]
pub struct Accepted {
    /// Read and write application bytes here.
    pub stream: StreamOwned<ServerConnection, TcpStream>,
    /// The client's leaf certificate, DER encoded. Its SHA-256 or key is what the device registry looks up.
    pub client_certificate: Vec<u8>,
}

fn socket_error(e: io::Error) -> TlsError {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => TlsError::Timeout,
        kind => TlsError::Io(kind),
    }
}

/// Run the server handshake on `tcp` within `deadline`. On any failure the error is returned and nothing further is
/// written; the caller drops the socket. On success the peer has proven possession of a certificate that chains to
/// the configured client roots. The returned socket has no timeout until the caller sets its application deadline.
pub fn accept(mut tcp: TcpStream, config: Arc<ServerConfig>, deadline: Duration) -> Result<Accepted, TlsError> {
    let started = Instant::now();
    let mut conn = ServerConnection::new(config).map_err(TlsError::Config)?;
    while conn.is_handshaking() {
        let left = deadline.checked_sub(started.elapsed()).filter(|d| !d.is_zero()).ok_or(TlsError::Timeout)?;
        tcp.set_read_timeout(Some(left)).map_err(socket_error)?;
        tcp.set_write_timeout(Some(left)).map_err(socket_error)?;
        if conn.wants_write() {
            conn.write_tls(&mut tcp).map_err(socket_error)?;
        } else if conn.wants_read() {
            if conn.read_tls(&mut tcp).map_err(socket_error)? == 0 {
                return Err(TlsError::Closed);
            }
            // An error here leaves an alert queued in `conn`; it is dropped with `conn` and never written.
            conn.process_new_packets().map_err(TlsError::Handshake)?;
        } else {
            return Err(TlsError::Closed);
        }
    }
    while conn.wants_write() {
        let left = deadline.checked_sub(started.elapsed()).filter(|d| !d.is_zero()).ok_or(TlsError::Timeout)?;
        tcp.set_write_timeout(Some(left)).map_err(socket_error)?;
        conn.write_tls(&mut tcp).map_err(socket_error)?;
    }
    let client_certificate =
        conn.peer_certificates().and_then(|certs| certs.first()).map(|leaf| leaf.as_ref().to_vec()).ok_or(TlsError::NoClientCertificate)?;
    tcp.set_read_timeout(None).map_err(socket_error)?;
    tcp.set_write_timeout(None).map_err(socket_error)?;
    Ok(Accepted { stream: StreamOwned::new(conn, tcp), client_certificate })
}
