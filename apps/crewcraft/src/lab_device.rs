//! In-process P-256 enrollment identity for a synthetic loopback lab. Task T229.
//!
//! The identity survives a lab server restart while the client stays open and the server
//! retains its address and trust. Ending the client process loses the device key.

use std::io::BufRead;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crewcraft_enroll::EnrollmentCode;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData};
use rustls::client::ResolvesClientCert;
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::sign::{CertifiedKey, SigningKey, SingleCertAndKey};

use crate::bootstrap_transport::{BootstrapEndpoint, BootstrapTransportError};
use crate::enroll_client::{EnrollmentError, EnrollmentRequest, FirstTotpCode, TotpSetup};
use crate::lab_client::{LabEndpoint, LabError, LabSession};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabDeviceError {
    Generate,
    Bootstrap(BootstrapTransportError),
    Enrollment(EnrollmentError),
    KeyMismatch,
}

/// One fresh lab-only device key and its signed enrollment request.
pub struct LabDeviceKey {
    signing_key: Arc<dyn SigningKey>,
    csr: Vec<u8>,
    spki: Vec<u8>,
}

impl LabDeviceKey {
    pub fn generate() -> Result<Self, LabDeviceError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| LabDeviceError::Generate)?;
        let csr = CertificateParams::default().serialize_request(&key).map_err(|_| LabDeviceError::Generate)?;
        let signing_key = any_ecdsa_type(&PrivatePkcs8KeyDer::from(key.serialized_der()).into()).map_err(|_| LabDeviceError::Generate)?;
        Ok(Self { signing_key, csr: csr.der().to_vec(), spki: key.subject_public_key_info() })
    }

    /// Enroll once and keep this key and the verified certificate chain in memory. The resulting
    /// device can only open sessions to the numeric loopback endpoint used for enrollment.
    pub fn enroll<'a>(
        self,
        endpoint: &'a BootstrapEndpoint,
        code: &EnrollmentCode,
        confirmation_window: Duration,
        device_name: &str,
        password: &str,
        prompt: impl FnOnce(TotpSetup<'_>, Instant) -> Option<FirstTotpCode>,
    ) -> Result<LabDevice<'a>, LabDeviceError> {
        let connection = endpoint.open(code, confirmation_window).map_err(LabDeviceError::Bootstrap)?;
        let request = EnrollmentRequest { device_name, csr: &self.csr, password, expected_spki: &self.spki };
        let chain = connection.enroll(request, prompt).map_err(LabDeviceError::Enrollment)?;
        let identity = CertifiedKey::new(vec![chain.leaf, chain.issuer], self.signing_key);
        identity.keys_match().map_err(|_| LabDeviceError::KeyMismatch)?;
        Ok(LabDevice { endpoint: endpoint.lab_endpoint(), resolver: Arc::new(SingleCertAndKey::from(identity)) })
    }
}

/// An enrolled synthetic lab device that stays usable in this process.
pub struct LabDevice<'a> {
    endpoint: &'a LabEndpoint,
    resolver: Arc<dyn ResolvesClientCert>,
}

impl LabDevice<'_> {
    /// Open a new session with a fresh passcode through the original pinned lab endpoint.
    pub fn open_session(&self, protected_input: &mut impl BufRead) -> Result<LabSession, LabError> {
        self.endpoint.open_authenticated(self.resolver.clone(), protected_input)
    }
}
