//! Restore a CrewCraft issuing authority from its certificates and a key supplied by server-side custody.

use std::collections::HashMap;
use std::fmt;

use rcgen::{Issuer, KeyPair, PKCS_ECDSA_P256_SHA256, PublicKeyData};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::ParsedExtension;
use x509_parser::parse_x509_certificate;
use x509_parser::time::ASN1Time;

use crate::{Authority, secs};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuingLoadError {
    Certificate,
    Constraints,
    Chain,
    Time,
    PrivateKey,
    KeyMismatch,
}

impl fmt::Display for IssuingLoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Certificate => "invalid authority certificate",
            Self::Constraints => "unexpected authority certificate constraints",
            Self::Chain => "issuing certificate does not chain to the pinned root",
            Self::Time => "authority certificate is outside its validity period",
            Self::PrivateKey => "invalid P-256 PKCS#8 issuing key",
            Self::KeyMismatch => "issuing key does not match its certificate",
        })
    }
}

impl std::error::Error for IssuingLoadError {}

impl Authority {
    /// Restore a CrewCraft issuing authority under the root certificate already trusted by this deployment.
    /// The caller decrypts the signing key in memory and supplies the original DER bytes. The durable device
    /// registry remains responsible for existing certificates and revocations.
    pub fn load_issuing(root_der: &[u8], issuing_der: &[u8], issuing_key_pkcs8: &[u8], now_ms: u64) -> Result<Self, IssuingLoadError> {
        let root = parse_authority(root_der, 1)?;
        let issuing = parse_authority(issuing_der, 0)?;
        let timestamp = secs(now_ms).map_err(|_| IssuingLoadError::Time)?;
        let now = ASN1Time::from_timestamp(timestamp).map_err(|_| IssuingLoadError::Time)?;
        if !root.validity().is_valid_at(now)
            || !issuing.validity().is_valid_at(now)
            || issuing.validity().not_before < root.validity().not_before
            || issuing.validity().not_after > root.validity().not_after
        {
            return Err(IssuingLoadError::Time);
        }
        if root.issuer().as_raw() != root.subject().as_raw()
            || issuing.issuer().as_raw() != root.subject().as_raw()
            || issuing.public_key().raw == root.public_key().raw
        {
            return Err(IssuingLoadError::Chain);
        }
        root.verify_signature(None).map_err(|_| IssuingLoadError::Chain)?;
        issuing.verify_signature(Some(root.public_key())).map_err(|_| IssuingLoadError::Chain)?;

        let key_der = PrivatePkcs8KeyDer::from(issuing_key_pkcs8);
        let key = KeyPair::from_pkcs8_der_and_sign_algo(&key_der, &PKCS_ECDSA_P256_SHA256).map_err(|_| IssuingLoadError::PrivateKey)?;
        if issuing.public_key().raw != key.subject_public_key_info().as_slice() {
            return Err(IssuingLoadError::KeyMismatch);
        }
        let issuer = Issuer::from_ca_cert_der(&CertificateDer::from(issuing_der), key).map_err(|_| IssuingLoadError::Certificate)?;
        Ok(Self { certificate: issuing_der.to_vec(), issuer, ledger: HashMap::new() })
    }

    /// Borrow this issuing authority's PKCS#8 bytes for encrypted custody. A root authority cannot use this method.
    pub fn with_issuing_key<T>(&self, secure: impl FnOnce(&[u8]) -> T) -> Result<T, IssuingLoadError> {
        parse_authority(self.certificate(), 0)?;
        Ok(secure(self.issuer.key().serialized_der()))
    }
}

fn parse_authority(der: &[u8], path_len: u32) -> Result<X509Certificate<'_>, IssuingLoadError> {
    let (remaining, cert) = parse_x509_certificate(der).map_err(|_| IssuingLoadError::Certificate)?;
    if !remaining.is_empty() {
        return Err(IssuingLoadError::Certificate);
    }
    cert.extensions_map().map_err(|_| IssuingLoadError::Certificate)?;
    let constraints = cert.basic_constraints().map_err(|_| IssuingLoadError::Certificate)?.ok_or(IssuingLoadError::Constraints)?;
    let usage = cert.key_usage().map_err(|_| IssuingLoadError::Certificate)?.ok_or(IssuingLoadError::Constraints)?;
    if !constraints.critical
        || !constraints.value.ca
        || constraints.value.path_len_constraint != Some(path_len)
        || !usage.value.key_cert_sign()
        || !usage.value.crl_sign()
        || cert.iter_extensions().any(|ext| {
            !matches!(
                ext.parsed_extension(),
                ParsedExtension::BasicConstraints(_)
                    | ParsedExtension::KeyUsage(_)
                    | ParsedExtension::SubjectKeyIdentifier(_)
                    | ParsedExtension::AuthorityKeyIdentifier(_)
            )
        })
    {
        return Err(IssuingLoadError::Constraints);
    }
    Ok(cert)
}
