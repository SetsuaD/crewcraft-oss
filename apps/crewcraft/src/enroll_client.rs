//! One client-side bootstrap exchange on an already verified server connection. Task T221.

use std::fmt;
use std::io::{self, Read, Write};
use std::sync::Arc;

use crewcraft_proto::bootstrap::{self, BootstrapRequest, BootstrapResponse};
use crewcraft_proto::frame;
use crewcraft_proto::message::CodecError;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;
use rustls::{RootCertStore, crypto::ring};
use x509_parser::prelude::{ASN1Time, FromDer, X509Certificate};

const REDEEM_ID: u32 = 1;
const CONFIRM_ID: u32 = 2;
const MAX_SETUP_REPLY: usize = 1 + 4 + 2 + bootstrap::MAX_URI;
const MAX_CONFIRM_REPLY: usize = 1 + 4 + 2 + bootstrap::MAX_CERT + 2 + bootstrap::MAX_CERT;

/// A signing request and the exact DER SubjectPublicKeyInfo supplied by its device signer.
pub struct EnrollmentRequest<'a> {
    pub device_name: &'a str,
    pub csr: &'a [u8],
    pub password: &'a str,
    pub expected_spki: &'a [u8],
}

/// Sensitive setup information for the protected enrollment prompt.
pub struct TotpSetup<'a>(&'a str);

impl TotpSetup<'_> {
    /// Use only to show a protected QR code or authenticator setup view.
    pub fn protected_uri(&self) -> &str {
        self.0
    }
}

impl fmt::Debug for TotpSetup<'_> {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("TotpSetup(..)")
    }
}

pub struct FirstTotpCode(String);

impl FirstTotpCode {
    pub fn parse(code: String) -> Option<Self> {
        (code.len() == bootstrap::CODE_LEN && code.bytes().all(|byte| byte.is_ascii_digit())).then_some(Self(code))
    }
}

impl fmt::Debug for FirstTotpCode {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("FirstTotpCode(..)")
    }
}

/// A verified device certificate and its issuing intermediate, leaf first.
pub struct VerifiedDeviceChain {
    pub leaf: CertificateDer<'static>,
    pub issuer: CertificateDer<'static>,
}

impl fmt::Debug for VerifiedDeviceChain {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("VerifiedDeviceChain(..)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeProblem {
    Io(io::ErrorKind),
    Codec(CodecError),
    UnexpectedReply,
    InvalidSetupUri,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertificateProblem {
    Malformed,
    WrongDeviceKey,
    WrongIssuer,
    ClientAuthentication,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentError {
    InvalidTrust,
    Setup(ExchangeProblem),
    SetupRefused(u16),
    PromptCancelled,
    ConfirmRefused(u16),
    /// Confirmation may have committed. The caller should recover the existing enrollment.
    ConfirmationUnknown(ExchangeProblem),
    /// The server reported activation. Its certificate cannot be installed.
    ActivatedCertificateRejected(CertificateProblem),
}

/// Enroll on a server-authenticated TLS stream. Its caller supplies I/O deadlines and the same root DER that
/// it authenticated against the invitation before establishing TLS. One stream carries Redeem, Setup, Confirm
/// and Activated. The stream is consumed, and this function does not reconnect or save anything.
pub fn enroll(
    mut stream: impl Read + Write,
    request: EnrollmentRequest<'_>,
    pinned_root_der: &[u8],
    prompt: impl FnOnce(TotpSetup<'_>) -> Option<FirstTotpCode>,
) -> Result<VerifiedDeviceChain, EnrollmentError> {
    let root = parse_der(pinned_root_der).map_err(|_| EnrollmentError::InvalidTrust)?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(pinned_root_der)).map_err(|_| EnrollmentError::InvalidTrust)?;
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::new(ring::default_provider()))
        .build()
        .map_err(|_| EnrollmentError::InvalidTrust)?;

    let code = {
        let redeem =
            BootstrapRequest::Redeem { device_name: request.device_name.into(), csr: request.csr.to_vec(), password: request.password.into() };
        send(&mut stream, REDEEM_ID, &redeem).map_err(EnrollmentError::Setup)?;
        let setup = receive(&mut stream, REDEEM_ID, MAX_SETUP_REPLY).map_err(EnrollmentError::Setup)?;
        let uri = match setup {
            BootstrapResponse::Setup { totp_uri } => totp_uri,
            BootstrapResponse::Error { code } => return Err(EnrollmentError::SetupRefused(code)),
            BootstrapResponse::Activated { .. } | BootstrapResponse::ExternalStart { .. } => {
                return Err(EnrollmentError::Setup(ExchangeProblem::UnexpectedReply));
            }
        };
        if uri.strip_prefix("otpauth://totp/").is_none_or(|rest| rest.is_empty()) || uri.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(EnrollmentError::Setup(ExchangeProblem::InvalidSetupUri));
        }
        prompt(TotpSetup(&uri)).ok_or(EnrollmentError::PromptCancelled)?
    };

    send(&mut stream, CONFIRM_ID, &BootstrapRequest::ConfirmTotp { code: code.0 }).map_err(EnrollmentError::ConfirmationUnknown)?;
    match receive(&mut stream, CONFIRM_ID, MAX_CONFIRM_REPLY).map_err(EnrollmentError::ConfirmationUnknown)? {
        BootstrapResponse::Activated { certificate, issuer_certificate } => {
            verify_device_chain(certificate, issuer_certificate, request.expected_spki, &root, &*verifier)
                .map_err(EnrollmentError::ActivatedCertificateRejected)
        }
        BootstrapResponse::Error { code } => Err(EnrollmentError::ConfirmRefused(code)),
        BootstrapResponse::Setup { .. } | BootstrapResponse::ExternalStart { .. } => {
            Err(EnrollmentError::ConfirmationUnknown(ExchangeProblem::UnexpectedReply))
        }
    }
}

fn send(stream: &mut impl Write, id: u32, request: &BootstrapRequest) -> Result<(), ExchangeProblem> {
    let payload = bootstrap::encode_bootstrap_request(id, request).map_err(ExchangeProblem::Codec)?;
    let framed = frame::encode(&payload).map_err(|_| ExchangeProblem::Codec(CodecError::FieldLength))?;
    stream.write_all(&framed).and_then(|()| stream.flush()).map_err(|error| ExchangeProblem::Io(error.kind()))
}

fn receive(stream: &mut impl Read, id: u32, limit: usize) -> Result<BootstrapResponse, ExchangeProblem> {
    let frame = frame::read_frame(stream, limit)
        .map_err(|error| ExchangeProblem::Io(error.kind()))?
        .ok_or(ExchangeProblem::Io(io::ErrorKind::UnexpectedEof))?;
    let (returned_id, response) = bootstrap::decode_bootstrap_response(frame.payload()).map_err(ExchangeProblem::Codec)?;
    if returned_id != id {
        return Err(ExchangeProblem::UnexpectedReply);
    }
    Ok(response)
}

fn parse_der(der: &[u8]) -> Result<X509Certificate<'_>, CertificateProblem> {
    match X509Certificate::from_der(der) {
        Ok(([], certificate)) => Ok(certificate),
        _ => Err(CertificateProblem::Malformed),
    }
}

fn verify_device_chain(
    certificate: Vec<u8>,
    issuer_certificate: Vec<u8>,
    expected_spki: &[u8],
    root: &X509Certificate<'_>,
    verifier: &dyn ClientCertVerifier,
) -> Result<VerifiedDeviceChain, CertificateProblem> {
    let leaf = parse_der(&certificate)?;
    let issuer = parse_der(&issuer_certificate)?;
    let now = UnixTime::now();
    let seconds = i64::try_from(now.as_secs()).map_err(|_| CertificateProblem::WrongIssuer)?;
    let date = ASN1Time::from_timestamp(seconds).map_err(|_| CertificateProblem::WrongIssuer)?;

    if leaf.public_key().raw != expected_spki {
        return Err(CertificateProblem::WrongDeviceKey);
    }
    if !issuer.is_ca()
        || !issuer.validity().is_valid_at(date)
        || !matches!(issuer.key_usage(), Ok(Some(usage)) if usage.value.key_cert_sign())
        || issuer.issuer() != root.subject()
        || issuer.verify_signature(Some(root.public_key())).is_err()
        || leaf.issuer() != issuer.subject()
        || leaf.verify_signature(Some(issuer.public_key())).is_err()
    {
        return Err(CertificateProblem::WrongIssuer);
    }
    if !matches!(leaf.extended_key_usage(), Ok(Some(usage)) if usage.value.client_auth && !usage.value.any && !usage.value.server_auth) {
        return Err(CertificateProblem::ClientAuthentication);
    }
    verifier
        .verify_client_cert(&CertificateDer::from(certificate.as_slice()), &[CertificateDer::from(issuer_certificate.as_slice())], now)
        .map_err(|_| CertificateProblem::ClientAuthentication)?;
    Ok(VerifiedDeviceChain { leaf: certificate.into(), issuer: issuer_certificate.into() })
}
