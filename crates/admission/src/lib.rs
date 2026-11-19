//! Who may complete the staff entrance handshake (docs/SECURITY-DESIGN.md sections 1 and 3): an enrolled device, or a
//! device holding a live invitation, and nobody else.
//!
//! Owns: the rustls client-certificate verifier that decides this during the handshake, and `admit`, which classifies the
//! presented certificate again once the handshake is over. Holds no accounts, invitations or certificate authority: the
//! server answers two questions through the [`Admission`] trait (is this device certificate registered and unrevoked, is
//! this key a live invitation) and this crate asks them at the right moments. Built on `crewcraft-tls::accept`, so a
//! refused peer gets no TLS alert and no application byte. Called by: the server listener.
//!
//! Two kinds of certificate are admitted, and neither path trusts the other:
//! - **Device**: chains to the issuing authority, carries an explicit `clientAuth` extended key usage (a leaf with no
//!   extended key usage is refused even though a plain WebPKI check would accept it), is valid now, and the server says it
//!   is registered and not revoked.
//! - **Bootstrap**: self-signed, valid now, an Ed25519 key, whose signature over the handshake proves the peer holds the
//!   private key, and whose key is exactly a live invitation's bootstrap key. It selects enrollment only: the caller
//!   gives a `Class::Bootstrap` connection nothing but the two enrollment calls.
//!
//! Admission is checked twice. The verifier checks during the handshake; `admit` classifies again immediately after, and
//! `Admitted::recheck` must be called before application I/O so that a revocation or a consumed invitation between the
//! handshake and its use fails closed.

use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crewcraft_tls::{Accepted, Identity, TlsError, accept};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{WebPkiSupportedAlgorithms, ring, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, RootCertStore, ServerConfig, ServerConnection, SignatureScheme, StreamOwned,
};
use x509_parser::prelude::{ASN1Time, FromDer, X509Certificate};

/// The server's answers to the two admission questions.
pub trait Admission: Send + Sync + std::fmt::Debug {
    /// Is this device certificate (DER) registered, not revoked and not expired?
    fn device_ok(&self, certificate: &[u8]) -> bool;
    /// Is this Ed25519 public key the bootstrap key of an invitation that is live (unexpired and unused)?
    fn bootstrap_key_live(&self, public_key: &[u8; 32]) -> bool;
}

/// What an admitted certificate may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// An enrolled device: it may go on to sign in.
    Device,
    /// A live invitation's key: enrollment calls only.
    Bootstrap([u8; 32]),
}

/// Why a certificate was not admitted. Never sent to the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not a certificate, or bytes after it.
    Malformed,
    /// Outside its validity period.
    NotValidNow,
    /// A device certificate without an explicit `clientAuth` extended key usage.
    NoClientAuth,
    /// A self-signed certificate that is not an Ed25519 key, or does not verify against itself.
    BadBootstrap,
    /// The bootstrap key is not a live invitation (unknown, expired or consumed).
    BootstrapNotLive,
    /// The device is not registered, or is revoked.
    DeviceNotAdmitted,
    /// The class changed since the handshake.
    Changed,
}

#[derive(Debug)]
pub enum AdmitError {
    /// The handshake failed (see `crewcraft_tls::TlsError`).
    Tls(TlsError),
    /// The handshake succeeded but the certificate is no longer admitted.
    Refused(Refusal),
}

fn parse(der: &[u8]) -> Result<X509Certificate<'_>, Refusal> {
    match X509Certificate::from_der(der) {
        Ok(([], cert)) => Ok(cert),
        _ => Err(Refusal::Malformed),
    }
}

fn self_signed(cert: &X509Certificate<'_>) -> bool {
    cert.issuer().as_raw() == cert.subject().as_raw() && cert.verify_signature(None).is_ok()
}

fn has_client_auth(cert: &X509Certificate<'_>) -> bool {
    matches!(cert.extended_key_usage(), Ok(Some(eku)) if eku.value.client_auth)
}

/// The class a certificate belongs to, from what the certificate says and what the server answers. It does not build a
/// chain: the handshake already did, and a self-signed certificate has none. `now` is Unix seconds.
pub fn classify(certificate: &[u8], now: i64, admission: &dyn Admission) -> Result<Class, Refusal> {
    let cert = parse(certificate)?;
    let at = ASN1Time::from_timestamp(now).map_err(|_| Refusal::NotValidNow)?;
    if !cert.validity().is_valid_at(at) {
        return Err(Refusal::NotValidNow);
    }
    if self_signed(&cert) {
        // Only an Ed25519 key is a bootstrap key: its raw 32 bytes are what an invitation stores.
        let key = cert.public_key();
        if key.algorithm.algorithm != x509_parser::oid_registry::OID_SIG_ED25519 {
            return Err(Refusal::BadBootstrap);
        }
        let raw: [u8; 32] = key.subject_public_key.data.as_ref().try_into().map_err(|_| Refusal::BadBootstrap)?;
        if !admission.bootstrap_key_live(&raw) {
            return Err(Refusal::BootstrapNotLive);
        }
        return Ok(Class::Bootstrap(raw));
    }
    if !has_client_auth(&cert) {
        return Err(Refusal::NoClientAuth);
    }
    if !admission.device_ok(certificate) {
        return Err(Refusal::DeviceNotAdmitted);
    }
    Ok(Class::Device)
}

#[derive(Debug)]
struct AdmissionVerifier {
    /// Chain validation for device certificates.
    chain: Arc<dyn ClientCertVerifier>,
    admission: Arc<dyn Admission>,
    algorithms: WebPkiSupportedAlgorithms,
}

fn refused() -> Error {
    // One answer for every reason: the peer is told nothing (and gets no alert anyway, see `crewcraft_tls::accept`).
    Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}

impl ClientCertVerifier for AdmissionVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.chain.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let seconds = i64::try_from(now.as_secs()).map_err(|_| refused())?;
        let bootstrap = parse(end_entity.as_ref()).map(|cert| self_signed(&cert)).map_err(|_| refused())?;
        if bootstrap {
            // No chain and no intermediates: the certificate vouches for itself, and the invitation vouches for its key.
            if !intermediates.is_empty() {
                return Err(refused());
            }
        } else {
            self.chain.verify_client_cert(end_entity, intermediates, now)?;
        }
        classify(end_entity.as_ref(), seconds, &*self.admission).map_err(|_| refused())?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // TLS 1.2 is not configured; refuse rather than assume.
        Err(refused())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // This is the proof of possession: the peer signed the handshake with the private key of `cert`. For a bootstrap
        // certificate it is what shows the peer holds the invitation's key, not just a copy of the certificate.
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// The server side: TLS 1.3 only, no resumption, no early data, and a client certificate that `admission` approves.
/// `device_roots` are the authorities device certificates may chain to.
pub fn server_config(identity: Identity, device_roots: RootCertStore, admission: Arc<dyn Admission>) -> Result<Arc<ServerConfig>, TlsError> {
    let provider = Arc::new(ring::default_provider());
    let chain = WebPkiClientVerifier::builder_with_provider(Arc::new(device_roots), Arc::clone(&provider)).build().map_err(TlsError::Verifier)?;
    let verifier = AdmissionVerifier { chain, admission, algorithms: provider.signature_verification_algorithms };
    let (certificates, key) = identity;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(TlsError::Config)?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(certificates, key)
        .map_err(TlsError::Config)?;
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    Ok(Arc::new(config))
}

/// A connection that passed the handshake and the post-handshake classification.
#[derive(Debug)]
pub struct Admitted {
    /// Read and write application bytes here, but only after `recheck`.
    pub stream: StreamOwned<ServerConnection, TcpStream>,
    pub class: Class,
    certificate: Vec<u8>,
}

impl Admitted {
    /// The presented certificate, DER.
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// Ask again whether the peer is still admitted, as the same class. Call it before application I/O, and again
    /// whenever the connection moves to a new phase. `Err` means drop the connection without writing anything.
    pub fn recheck(&self, admission: &dyn Admission, now: i64) -> Result<(), Refusal> {
        if classify(&self.certificate, now, admission)? == self.class { Ok(()) } else { Err(Refusal::Changed) }
    }
}

/// Run the bounded handshake on `tcp` and classify the peer. A peer that fails either step gets nothing further: the
/// error is returned and the caller drops the socket. `now` is Unix seconds.
pub fn admit(tcp: TcpStream, config: Arc<ServerConfig>, deadline: Duration, admission: &dyn Admission, now: i64) -> Result<Admitted, AdmitError> {
    let Accepted { stream, client_certificate } = accept(tcp, config, deadline).map_err(AdmitError::Tls)?;
    let class = classify(&client_certificate, now, admission).map_err(AdmitError::Refused)?;
    Ok(Admitted { stream, class, certificate: client_certificate })
}
