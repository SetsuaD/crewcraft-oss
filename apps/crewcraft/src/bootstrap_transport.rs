//! A pinned loopback TLS connection for a single enrollment. Task T226.

use std::io::{self, Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crewcraft_enroll::server_trust::RootFingerprint;
use crewcraft_enroll::{EnrollmentCode, bootstrap_public_key};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyUsagePurpose, PKCS_ED25519, PublicKeyData};
use rustls::SignatureScheme;
use rustls::client::ResolvesClientCert;
use rustls::crypto::ring::sign::any_eddsa_type;
use rustls::pki_types::{PrivatePkcs8KeyDer, UnixTime};
use rustls::sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey};
use time::OffsetDateTime;
use zeroize::Zeroizing;

use crate::connect::Transport;
use crate::chat_session::ExternalStart;
use crate::enroll_client::{
    BrowserProblem, EnrollmentError, EnrollmentRequest, ExternalEnrollmentRequest, FirstTotpCode, TotpSetup, VerifiedDeviceChain, enroll,
    enroll_external,
};
use crate::external_flow::Redirect;
use crate::lab_client::{LabEndpoint, LabError};

pub const MAX_CONFIRMATION_WINDOW: Duration = Duration::from_secs(120);
/// The longest window for an enrollment through the server's identity provider (task T611i): the browser sign-in
/// (`EXTERNAL_BROWSER_TIMEOUT`) and the exchanges around it. The server keeps its bootstrap connections open as long.
pub const MAX_EXTERNAL_CONFIRMATION_WINDOW: Duration = Duration::from_secs(330);
/// How long the person has in the browser during an enrollment through the provider.
pub const EXTERNAL_BROWSER_TIMEOUT: Duration = Duration::from_secs(300);
const CERT_LIFETIME: time::Duration = time::Duration::minutes(3);
const CLOCK_SKEW: time::Duration = time::Duration::seconds(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapTransportError {
    Endpoint(LabError),
    ConfirmationWindow,
    Identity,
    Connection(LabError),
}

/// The endpoint and root from the same trusted invitation. No root is taken from the handshake.
pub struct BootstrapEndpoint {
    endpoint: LabEndpoint,
    root_der: Vec<u8>,
}

impl BootstrapEndpoint {
    pub fn new(address: &str, server_name: &str, expected_root: RootFingerprint, root_der: &[u8]) -> Result<Self, BootstrapTransportError> {
        let endpoint = LabEndpoint::new(address, server_name, expected_root, root_der).map_err(BootstrapTransportError::Endpoint)?;
        Ok(Self { endpoint, root_der: root_der.to_vec() })
    }

    pub(crate) fn lab_endpoint(&self) -> &LabEndpoint {
        &self.endpoint
    }

    /// Connect with only the invitation's temporary identity. The whole enrollment exchange,
    /// including authenticator setup, shares one absolute deadline after the TLS handshake.
    pub fn open(&self, code: &EnrollmentCode, confirmation_window: Duration) -> Result<BootstrapConnection<'_>, BootstrapTransportError> {
        open_bootstrap(|device| self.endpoint.connect(device), &self.root_der, code, confirmation_window)
    }
}

/// Connect through `connect` with only the invitation's temporary identity and start the enrollment deadline.
/// `root_der` must be the root `connect` already pins.
pub(crate) fn open_bootstrap<'a>(
    connect: impl FnOnce(Arc<dyn ResolvesClientCert>) -> Result<Transport, LabError>,
    root_der: &'a [u8],
    code: &EnrollmentCode,
    confirmation_window: Duration,
) -> Result<BootstrapConnection<'a>, BootstrapTransportError> {
    open_within(connect, root_der, code, confirmation_window, MAX_CONFIRMATION_WINDOW)
}

/// As `open_bootstrap`, for an enrollment through the server's identity provider (task T611i): the window may be up
/// to `MAX_EXTERNAL_CONFIRMATION_WINDOW`.
pub(crate) fn open_bootstrap_external<'a>(
    connect: impl FnOnce(Arc<dyn ResolvesClientCert>) -> Result<Transport, LabError>,
    root_der: &'a [u8],
    code: &EnrollmentCode,
    confirmation_window: Duration,
) -> Result<BootstrapConnection<'a>, BootstrapTransportError> {
    open_within(connect, root_der, code, confirmation_window, MAX_EXTERNAL_CONFIRMATION_WINDOW)
}

fn open_within<'a>(
    connect: impl FnOnce(Arc<dyn ResolvesClientCert>) -> Result<Transport, LabError>,
    root_der: &'a [u8],
    code: &EnrollmentCode,
    confirmation_window: Duration,
    limit: Duration,
) -> Result<BootstrapConnection<'a>, BootstrapTransportError> {
    if confirmation_window.is_zero() || confirmation_window > limit {
        return Err(BootstrapTransportError::ConfirmationWindow);
    }
    let device = bootstrap_identity(code)?;
    let mut stream = connect(device).map_err(BootstrapTransportError::Connection)?;
    let deadline = Instant::now().checked_add(confirmation_window).ok_or(BootstrapTransportError::ConfirmationWindow)?;
    stream.get_mut().set_deadline(deadline);
    Ok(BootstrapConnection { stream: BootstrapStream { stream, deadline }, root_der })
}

/// One verified bootstrap connection. Only the enrollment exchange may use it.
pub struct BootstrapConnection<'a> {
    stream: BootstrapStream,
    root_der: &'a [u8],
}

impl BootstrapConnection<'_> {
    /// Run Redeem and Confirm over this connection. The protected prompt receives the cutoff
    /// so it can stop waiting. A code returned at or after the cutoff is discarded.
    pub fn enroll(
        self,
        request: EnrollmentRequest<'_>,
        prompt: impl FnOnce(TotpSetup<'_>, Instant) -> Option<FirstTotpCode>,
    ) -> Result<VerifiedDeviceChain, EnrollmentError> {
        let deadline = self.stream.deadline;
        enroll(self.stream, request, self.root_der, |setup| {
            if Instant::now() >= deadline {
                return None;
            }
            prompt(setup, deadline).filter(|_| Instant::now() < deadline)
        })
    }

    /// Run `RedeemExternal`, the browser part and `ConfirmExternal` over this connection (task T611i). `browse` is
    /// given the server's start and this connection's cutoff; a redirect that arrives at or after it is not used.
    pub fn enroll_external(
        self,
        request: ExternalEnrollmentRequest<'_>,
        browse: impl FnOnce(&ExternalStart, Instant) -> Result<Redirect, BrowserProblem>,
    ) -> Result<VerifiedDeviceChain, EnrollmentError> {
        let deadline = self.stream.deadline;
        enroll_external(self.stream, request, self.root_der, |start| {
            if Instant::now() >= deadline {
                return Err(BrowserProblem::TimedOut);
            }
            let redirect = browse(start, deadline)?;
            if Instant::now() >= deadline { Err(BrowserProblem::TimedOut) } else { Ok(redirect) }
        })
    }
}

struct BootstrapStream {
    stream: Transport,
    deadline: Instant,
}

impl BootstrapStream {
    fn check_deadline(&self) -> io::Result<()> {
        if Instant::now() < self.deadline { Ok(()) } else { Err(io::ErrorKind::TimedOut.into()) }
    }
}

impl Read for BootstrapStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.check_deadline()?;
        self.stream.read(buffer)
    }
}

impl Write for BootstrapStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.check_deadline()?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check_deadline()?;
        self.stream.flush()
    }
}

fn bootstrap_identity(code: &EnrollmentCode) -> Result<Arc<dyn ResolvesClientCert>, BootstrapTransportError> {
    let seed = Zeroizing::new(code.bootstrap_seed());
    let signing_key = load_signing_key(&seed)?;
    let signer = signing_key.choose_scheme(&[SignatureScheme::ED25519]).ok_or(BootstrapTransportError::Identity)?;
    let certificate_key = CertificateSigner { public: bootstrap_public_key(&seed), signer };
    let now = i64::try_from(UnixTime::now().as_secs()).map_err(|_| BootstrapTransportError::Identity)?;
    let now = OffsetDateTime::from_unix_timestamp(now).map_err(|_| BootstrapTransportError::Identity)?;
    let mut params = CertificateParams::new(Vec::new()).map_err(|_| BootstrapTransportError::Identity)?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, "CrewCraft Bootstrap");
    params.not_before = now.checked_sub(CLOCK_SKEW).ok_or(BootstrapTransportError::Identity)?;
    params.not_after = now.checked_add(CERT_LIFETIME).ok_or(BootstrapTransportError::Identity)?;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let cert = params.self_signed(&certificate_key).map_err(|_| BootstrapTransportError::Identity)?;
    let key = CertifiedKey::new(vec![cert.der().clone()], signing_key);
    key.keys_match().map_err(|_| BootstrapTransportError::Identity)?;
    Ok(Arc::new(SingleCertAndKey::from(key)))
}

fn load_signing_key(seed: &[u8; 32]) -> Result<Arc<dyn SigningKey>, BootstrapTransportError> {
    // RFC 8410 section 7. The Ed25519 seed is an inner OCTET STRING in a version-0 PrivateKeyInfo.
    const PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
    let mut bytes = Zeroizing::new([0; 48]);
    let (prefix, key) = bytes.split_at_mut(PREFIX.len());
    prefix.copy_from_slice(&PREFIX);
    key.copy_from_slice(seed);
    any_eddsa_type(&PrivatePkcs8KeyDer::from(&bytes[..])).map_err(|_| BootstrapTransportError::Identity)
}

struct CertificateSigner {
    public: [u8; 32],
    signer: Box<dyn Signer>,
}

impl PublicKeyData for CertificateSigner {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &PKCS_ED25519
    }
}

impl rcgen::SigningKey for CertificateSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.signer.sign(message).map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::FromDer;
    use x509_parser::x509::SubjectPublicKeyInfo;

    #[test]
    fn rfc_8410_private_key_decodes_to_the_corresponding_public_key() {
        let seed = [
            0xd4, 0xee, 0x72, 0xdb, 0xf9, 0x13, 0x58, 0x4a, 0xd5, 0xb6, 0xd8, 0xf1, 0xf7, 0x69, 0xf8, 0xad, 0x3a, 0xfe, 0x7c, 0x28, 0xcb, 0xf1, 0xd4,
            0xfb, 0xe0, 0x97, 0xa8, 0x8f, 0x44, 0x75, 0x58, 0x42,
        ];
        let expected = [
            0x19, 0xbf, 0x44, 0x09, 0x69, 0x84, 0xcd, 0xfe, 0x85, 0x41, 0xba, 0xc1, 0x67, 0xdc, 0x3b, 0x96, 0xc8, 0x50, 0x86, 0xaa, 0x30, 0xb6, 0xb6,
            0xcb, 0x0c, 0x5c, 0x38, 0xad, 0x70, 0x31, 0x66, 0xe1,
        ];
        let key = load_signing_key(&seed).unwrap();
        let spki = key.public_key().unwrap();
        let (rest, key) = SubjectPublicKeyInfo::from_der(spki.as_ref()).unwrap();
        assert!(rest.is_empty());
        assert_eq!(key.subject_public_key.data.as_ref(), expected);
    }
}
