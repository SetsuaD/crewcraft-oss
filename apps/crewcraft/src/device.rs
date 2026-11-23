//! An enrolled device that outlives the process: a fresh P-256 key, enrollment against any server endpoint, and the
//! record (`StoredDevice`) that `device_store` writes to disk and reads back. Tasks T304 and T403.
//!
//! Owns: device key generation (in software, or inside a hardware key store through `hardware_key`), attaching the
//! issued chain to that exact key, and rebuilding a TLS client identity from a record. Called by the window (enroll
//! once, then load at each start) and by `worker`. Calls `server_endpoint` for the enrollment and sign-in connections.
//! The in-process lab device (`lab_device`, T229) is separate and still never exports its key.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crewcraft_enroll::EnrollmentCode;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData};
use rustls::client::ResolvesClientCert;
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::{CertifiedKey, SigningKey, SingleCertAndKey};
use zeroize::Zeroizing;

use crate::bootstrap_transport::BootstrapTransportError;
use crate::enroll_client::{EnrollmentError, EnrollmentRequest, FirstTotpCode, TotpSetup};
use crate::hardware_key::{HardwareKey, HardwareKeys, RequestSigner, TlsSigningKey, valid_alias};
use crate::lab_client::LabError;
use crate::server_endpoint::ServerEndpoint;
use crate::signed_in::{Credentials, SignedInSession};

/// Longest PKCS#8 device key a record may hold. A P-256 key is about 140 bytes.
pub const MAX_KEY_DER: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceError {
    /// The key or the certificate request could not be made.
    Generate,
    Bootstrap(BootstrapTransportError),
    Enrollment(EnrollmentError),
    /// The issued certificate does not belong to this device's key.
    KeyMismatch,
    /// A record's endpoint, chain or key is unusable.
    Invalid,
}

/// Where a device's private key is: in the record (software, the desktop default), or inside a hardware key store
/// that the record only names.
pub(crate) enum DeviceKey {
    Software(Zeroizing<Vec<u8>>),
    Hardware(Arc<dyn HardwareKey>),
}

impl DeviceKey {
    fn signing_key(&self) -> Option<Arc<dyn SigningKey>> {
        match self {
            Self::Software(pkcs8) => {
                if pkcs8.is_empty() || pkcs8.len() > MAX_KEY_DER {
                    return None;
                }
                load_key(pkcs8)
            }
            Self::Hardware(key) => {
                if !valid_alias(key.alias()) {
                    return None;
                }
                TlsSigningKey::new(key.clone()).ok().map(|key| Arc::new(key) as Arc<dyn SigningKey>)
            }
        }
    }
}

/// A fresh device key and its signed certificate request, before enrollment. Nothing is on disk yet; a hardware key
/// already exists in its key store and is deleted again if enrollment fails.
pub struct NewDevice {
    key: DeviceKey,
    signing_key: Arc<dyn SigningKey>,
    csr: Vec<u8>,
    spki: Vec<u8>,
    store: Option<Arc<dyn HardwareKeys>>,
}

impl fmt::Debug for NewDevice {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.write_str("NewDevice { .. }")
    }
}

impl NewDevice {
    /// A software key, kept in the record (sealed by the device store on the desktop).
    pub fn generate() -> Result<Self, DeviceError> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(|_| DeviceError::Generate)?;
        let csr = CertificateParams::default().serialize_request(&key).map_err(|_| DeviceError::Generate)?;
        let key_pkcs8 = Zeroizing::new(key.serialize_der());
        let signing_key = load_key(&key_pkcs8).ok_or(DeviceError::Generate)?;
        Ok(Self { key: DeviceKey::Software(key_pkcs8), signing_key, csr: csr.der().to_vec(), spki: key.subject_public_key_info(), store: None })
    }

    /// A key generated inside `store` under `alias`. The certificate request is signed there, and the private key
    /// never reaches this process.
    pub fn generate_in(store: Arc<dyn HardwareKeys>, alias: &str) -> Result<Self, DeviceError> {
        if !valid_alias(alias) {
            return Err(DeviceError::Generate);
        }
        let key = store.generate(alias).map_err(|_| DeviceError::Generate)?;
        let made = (|| {
            let request = RequestSigner::new(key.clone()).map_err(|_| DeviceError::Generate)?;
            let csr = CertificateParams::default().serialize_request(&request).map_err(|_| DeviceError::Generate)?;
            let signing_key: Arc<dyn SigningKey> = Arc::new(TlsSigningKey::new(key.clone()).map_err(|_| DeviceError::Generate)?);
            Ok((csr.der().to_vec(), signing_key))
        })();
        match made {
            Ok((csr, signing_key)) => {
                let spki = key.public_key().to_vec();
                Ok(Self { key: DeviceKey::Hardware(key), signing_key, csr, spki, store: Some(store) })
            }
            Err(error) => {
                let _ = store.delete(alias);
                Err(error)
            }
        }
    }

    /// Enroll at `endpoint` with an invitation code and return the record to save. `prompt` shows the authenticator
    /// setup and returns the first code before the deadline it is given (see `BootstrapConnection::enroll`).
    pub fn enroll(
        self,
        endpoint: &ServerEndpoint,
        code: &EnrollmentCode,
        confirmation_window: Duration,
        device_name: &str,
        password: &str,
        prompt: impl FnOnce(TotpSetup<'_>, Instant) -> Option<FirstTotpCode>,
    ) -> Result<StoredDevice, DeviceError> {
        let Self { key, signing_key, csr, spki, store } = self;
        let enrolled = (|| {
            let connection = endpoint.open_bootstrap(code, confirmation_window).map_err(DeviceError::Bootstrap)?;
            let request = EnrollmentRequest { device_name, csr: &csr, password, expected_spki: &spki };
            let chain = connection.enroll(request, prompt).map_err(DeviceError::Enrollment)?;
            let identity = CertifiedKey::new(vec![chain.leaf.clone(), chain.issuer.clone()], signing_key);
            identity.keys_match().map_err(|_| DeviceError::KeyMismatch)?;
            Ok((chain.leaf.to_vec(), chain.issuer.to_vec()))
        })();
        match enrolled {
            Ok((leaf, issuer)) => Ok(StoredDevice { endpoint: endpoint.clone(), leaf, issuer, key }),
            Err(error) => {
                // A key nobody can use any more: remove it from the key store rather than leave it behind.
                if let (DeviceKey::Hardware(key), Some(store)) = (&key, &store) {
                    let _ = store.delete(key.alias());
                }
                Err(error)
            }
        }
    }
}

/// Everything needed to reconnect as an enrolled device: the server endpoint (address, name, pinned root), the
/// device certificate and its issuer, and the device's private key or, for a hardware key, the key store's handle on
/// it. `Debug` shows only the endpoint; there is no `Display`, and software key bytes are wiped when the record is
/// dropped.
pub struct StoredDevice {
    endpoint: ServerEndpoint,
    leaf: Vec<u8>,
    issuer: Vec<u8>,
    key: DeviceKey,
}

impl fmt::Debug for StoredDevice {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        output.debug_struct("StoredDevice").field("endpoint", &self.endpoint).finish_non_exhaustive()
    }
}

impl StoredDevice {
    /// Rebuild a record and check that its parts fit together: a usable endpoint whose root matches its
    /// fingerprint, and a key that matches the device certificate.
    pub(crate) fn from_parts(endpoint: ServerEndpoint, leaf: Vec<u8>, issuer: Vec<u8>, key: DeviceKey) -> Result<Self, DeviceError> {
        let device = Self { endpoint, leaf, issuer, key };
        device.certified_key()?;
        Ok(device)
    }

    pub fn endpoint(&self) -> &ServerEndpoint {
        &self.endpoint
    }

    /// The device certificate, DER. Public: the server sees it in every handshake.
    pub fn certificate(&self) -> &[u8] {
        &self.leaf
    }

    pub(crate) fn issuer_certificate(&self) -> &[u8] {
        &self.issuer
    }

    /// The PKCS#8 private key, for a software key; `None` for a hardware key.
    pub(crate) fn key_pkcs8(&self) -> Option<&[u8]> {
        match &self.key {
            DeviceKey::Software(pkcs8) => Some(pkcs8),
            DeviceKey::Hardware(_) => None,
        }
    }

    /// The key store's alias for a hardware key; `None` for a software key.
    pub fn hardware_alias(&self) -> Option<&str> {
        match &self.key {
            DeviceKey::Software(_) => None,
            DeviceKey::Hardware(key) => Some(key.alias()),
        }
    }

    /// A TLS client identity for this device, for `ServerEndpoint::sign_in` or `worker::Worker::start`.
    pub fn identity(&self) -> Result<Arc<dyn ResolvesClientCert>, DeviceError> {
        Ok(Arc::new(SingleCertAndKey::from(self.certified_key()?)))
    }

    /// Connect to the recorded server as this device and sign in.
    pub fn sign_in(&self, credentials: &Credentials) -> Result<SignedInSession, LabError> {
        let identity = self.identity().map_err(|_| LabError::Device)?;
        self.endpoint.sign_in(identity, credentials)
    }

    fn certified_key(&self) -> Result<CertifiedKey, DeviceError> {
        let key = self.key.signing_key().ok_or(DeviceError::Invalid)?;
        let chain = vec![CertificateDer::from(self.leaf.clone()), CertificateDer::from(self.issuer.clone())];
        let identity = CertifiedKey::new(chain, key);
        identity.keys_match().map_err(|_| DeviceError::Invalid)?;
        Ok(identity)
    }
}

fn load_key(pkcs8: &[u8]) -> Option<Arc<dyn SigningKey>> {
    any_ecdsa_type(&PrivatePkcs8KeyDer::from(pkcs8).into()).ok()
}
