//! One client-side bootstrap exchange on an already verified server connection. Task T221.
//!
//! `enroll_external` is the same exchange through the server's identity provider (task T611i): `RedeemExternal`, the
//! browser part (`browse`, passed in), `ConfirmExternal`, `Activated`.

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
use zeroize::Zeroizing;

use crate::chat_session::ExternalStart;
use crate::external_flow::{FlowError, Redirect};
use crate::loopback::LoopbackError;

const REDEEM_ID: u32 = 1;
const CONFIRM_ID: u32 = 2;
const MAX_SETUP_REPLY: usize = 1 + 4 + 2 + bootstrap::MAX_URI;
const MAX_CONFIRM_REPLY: usize = 1 + 4 + 2 + bootstrap::MAX_CERT + 2 + bootstrap::MAX_CERT;
/// `ExternalStart`: four length-prefixed texts (task T611i).
const MAX_EXTERNAL_START_REPLY: usize =
    1 + 4 + 4 * 2 + 2 * crewcraft_proto::signin::MAX_URL_BYTES + crewcraft_proto::signin::MAX_CLIENT_ID_BYTES + crewcraft_proto::signin::TOKEN_LEN;
/// The server's code for "this server enrolls the other way" (`crewcraft_bootstrap::ERR_WRONG_PATH`).
const ERR_WRONG_PATH: u16 = 6;

/// A device's signing request for enrolling through the server's identity provider: no password (task T611i).
pub struct ExternalEnrollmentRequest<'a> {
    pub device_name: &'a str,
    pub csr: &'a [u8],
    pub expected_spki: &'a [u8],
}

/// Why the browser part of an enrollment through the provider gave no code (task T611i).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserProblem {
    /// The system browser could not be opened.
    Browser,
    /// The app could not listen for the redirect.
    NoRedirect,
    /// The person did not finish in time.
    TimedOut,
    /// The provider ended the sign-in without a code.
    ProviderRefused,
    /// The person cancelled, or the app is closing.
    Cancelled,
}

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
    /// The server enrolls the other way: through its identity provider, or with a password (task T611i).
    WrongPath,
    /// The browser part of an enrollment through the provider gave no code (task T611i).
    Browser(BrowserProblem),
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
            BootstrapResponse::Error { code: ERR_WRONG_PATH } => return Err(EnrollmentError::WrongPath),
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

/// Enroll through the server's identity provider on a server-authenticated TLS stream (task T611i), as `enroll` does
/// with a password: `RedeemExternal`, then `browse` (the system browser and the loopback redirect, for the start the
/// server gave), then `ConfirmExternal` and `Activated`. A refusal at the start is `SetupRefused` (or `WrongPath`); one
/// at the confirmation is `ConfirmRefused`; a lost reply after sending the confirmation is `ConfirmationUnknown`.
pub fn enroll_external(
    mut stream: impl Read + Write,
    request: ExternalEnrollmentRequest<'_>,
    pinned_root_der: &[u8],
    browse: impl FnOnce(&ExternalStart) -> Result<Redirect, BrowserProblem>,
) -> Result<VerifiedDeviceChain, EnrollmentError> {
    let root = parse_der(pinned_root_der).map_err(|_| EnrollmentError::InvalidTrust)?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(pinned_root_der)).map_err(|_| EnrollmentError::InvalidTrust)?;
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::new(ring::default_provider()))
        .build()
        .map_err(|_| EnrollmentError::InvalidTrust)?;

    let redeem = BootstrapRequest::RedeemExternal { device_name: request.device_name.into(), csr: request.csr.to_vec() };
    send(&mut stream, REDEEM_ID, &redeem).map_err(EnrollmentError::Setup)?;
    let start = match receive(&mut stream, REDEEM_ID, MAX_EXTERNAL_START_REPLY).map_err(EnrollmentError::Setup)? {
        BootstrapResponse::ExternalStart { issuer, client_id, authorization_endpoint, nonce } => {
            ExternalStart { issuer, client_id, authorization_endpoint, nonce: Zeroizing::new(nonce) }
        }
        BootstrapResponse::Error { code: ERR_WRONG_PATH } => return Err(EnrollmentError::WrongPath),
        BootstrapResponse::Error { code } => return Err(EnrollmentError::SetupRefused(code)),
        BootstrapResponse::Setup { .. } | BootstrapResponse::Activated { .. } => {
            return Err(EnrollmentError::Setup(ExchangeProblem::UnexpectedReply));
        }
    };
    let redirect = browse(&start).map_err(EnrollmentError::Browser)?;

    let confirm = BootstrapRequest::ConfirmExternal {
        code: redirect.code.to_string(),
        verifier: redirect.verifier.to_string(),
        redirect_uri: redirect.redirect_uri.clone(),
    };
    send(&mut stream, CONFIRM_ID, &confirm).map_err(EnrollmentError::ConfirmationUnknown)?;
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

/// The browser part's failure, as the enrollment reports it.
pub fn browser_problem(error: &FlowError) -> BrowserProblem {
    match error {
        FlowError::Browser(_) => BrowserProblem::Browser,
        FlowError::Loopback(LoopbackError::Bind(_)) => BrowserProblem::NoRedirect,
        FlowError::Loopback(LoopbackError::TimedOut) => BrowserProblem::TimedOut,
        FlowError::Loopback(LoopbackError::Provider(_)) => BrowserProblem::ProviderRefused,
        FlowError::Loopback(LoopbackError::Cancelled) | FlowError::NotOffered | FlowError::Server(_) => BrowserProblem::Cancelled,
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
