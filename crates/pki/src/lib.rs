//! The server's certificate authority (docs/SECURITY-DESIGN.md section 2): a root and an issuing authority, the server's
//! certificate, and device certificates made from validated signing requests.
//!
//! Owns: certificate creation and the ledger of device certificates this authority issued (who each belongs to, its
//! key identifier, whether it is revoked). Everything goes in and out as DER bytes, so no TLS library appears in the
//! API. Holds no network, account or invitation logic: the caller passes the claims from the invitation record, and
//! `crewcraft-tls` decides whether a handshake succeeds. Called by: the server (enrollment and renewal).
//!
//! What a device certificate is. The signing request supplies exactly one thing, its public key, and only after the
//! request's signature proved the sender holds the matching private key and the key is ECDSA P-256 (the algorithm every
//! hardware key store supports). Every other request field (subject, alternative names, key usage, extended key usage,
//! the CA flag) is ignored: the subject, the client-authentication-only usage and the 90-day life come from the server.
//!
//! The caller handles encrypted issuing-key custody. This crate can reload the original issuing authority and its
//! pinned root certificate. The issuance and revocation ledger lives in memory. The server must check its durable
//! device registry for existing devices and revocations.

use std::collections::HashMap;

use rand_core::{OsRng, RngCore};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SerialNumber,
};
use rustls_pki_types::CertificateSigningRequestDer;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use x509_parser::parse_x509_certificate;

mod issuing_state;
pub use issuing_state::IssuingLoadError;
use x509_parser::prelude::{FromDer, X509CertificationRequest};

/// A device certificate's life: 90 days exactly (docs/SECURITY-DESIGN.md section 2). Renewal issues a new one.
pub const DEVICE_LIFETIME_SECS: i64 = 90 * 86_400;
/// The server certificate's life.
pub const SERVER_LIFETIME_SECS: i64 = 365 * 86_400;
/// The root authority's life.
pub const ROOT_LIFETIME_SECS: i64 = 10 * 365 * 86_400;
/// The issuing authority's life.
pub const ISSUING_LIFETIME_SECS: i64 = 5 * 365 * 86_400;
/// Longest person identifier accepted in a claim, in bytes (an email address).
pub const MAX_PERSON: usize = 254;

#[derive(Debug)]
pub enum PkiError {
    /// A time outside the range certificates can hold.
    Time,
    /// The system random source failed.
    Randomness,
    /// The signing request is malformed, or its signature does not match its own public key (no proof of possession).
    Csr(rcgen::Error),
    /// The request's key is not ECDSA P-256.
    NotP256,
    /// The person or device in the claims is empty, too long or has control characters; or the device id is zero.
    BadClaims,
    /// Building or signing a certificate failed.
    Build(rcgen::Error),
    /// A certificate this crate made could not be read back (a bug, reported rather than ignored).
    Parse,
    /// The certificate is not one this authority issued (unknown serial, or the bytes differ from what was issued).
    NotIssuedHere,
    /// The certificate is revoked.
    Revoked,
    /// The certificate has expired.
    Expired,
    /// A renewal request carries a different key than the certificate being renewed.
    KeyMismatch,
}

/// What an invitation record says about a device: the only source of the certificate's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Claims<'a> {
    /// The person's normalised email address.
    pub person: &'a str,
    /// The device id the registry assigned (nonzero).
    pub device_id: u64,
}

/// A certificate this authority issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    /// The leaf certificate, DER.
    pub certificate: Vec<u8>,
    /// The certificate followed by the issuing authority's certificate, which is what a client presents.
    pub chain: Vec<Vec<u8>>,
    /// The serial number (16 random bytes), the handle for revocation.
    pub serial: Vec<u8>,
    /// SHA-256 of the certificate's SubjectPublicKeyInfo: stable across renewals while the device keeps its key.
    pub key_id: [u8; 32],
    pub not_before: i64,
    pub not_after: i64,
}

/// The server's own certificate and key.
pub struct ServerIdentity {
    /// The server certificate followed by the issuing authority's certificate.
    pub chain: Vec<Vec<u8>>,
    /// The private key, PKCS#8 DER.
    pub key_pkcs8: Vec<u8>,
}

impl std::fmt::Debug for ServerIdentity {
    // Never print the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServerIdentity(..)")
    }
}

/// Who a good certificate belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafInfo {
    pub person: String,
    pub device_id: u64,
    pub key_id: [u8; 32],
}

/// The answer to "is this device certificate still good?", asked on every connection and renewal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Good(LeafInfo),
    Revoked,
    Expired,
    /// Not issued by this authority (including a certificate whose serial matches one we issued but whose bytes differ).
    Unknown,
}

#[derive(Debug)]
struct Leaf {
    certificate: Vec<u8>,
    info: LeafInfo,
    not_after: i64,
    revoked: bool,
}

/// A certificate authority: a key, its certificate, and the ledger of device certificates it issued.
pub struct Authority {
    certificate: Vec<u8>,
    issuer: Issuer<'static, KeyPair>,
    ledger: HashMap<Vec<u8>, Leaf>,
}

impl std::fmt::Debug for Authority {
    // Never print the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Authority(.., {} issued)", self.ledger.len())
    }
}

fn secs(now_ms: u64) -> Result<i64, PkiError> {
    i64::try_from(now_ms / 1000).map_err(|_| PkiError::Time)
}

fn at(unix_secs: i64) -> Result<OffsetDateTime, PkiError> {
    OffsetDateTime::from_unix_timestamp(unix_secs).map_err(|_| PkiError::Time)
}

fn name(entries: &[(DnType, String)]) -> DistinguishedName {
    // `DistinguishedName::new()` is empty: rcgen's own default subject is never used.
    let mut dn = DistinguishedName::new();
    for (kind, value) in entries {
        dn.push(kind.clone(), value.clone());
    }
    dn
}

/// A 16-byte serial with the top two bits `01`, so it is positive, never shortened by DER and never zero.
fn random_serial() -> Result<Vec<u8>, PkiError> {
    let mut bytes = [0u8; 16];
    OsRng.try_fill_bytes(&mut bytes).map_err(|_| PkiError::Randomness)?;
    bytes[0] = (bytes[0] & 0x3f) | 0x40;
    Ok(bytes.to_vec())
}

/// SHA-256 of the SubjectPublicKeyInfo of a certificate: the identity of a device's key, stable across renewals.
pub fn key_id_of_certificate(certificate_der: &[u8]) -> Result<[u8; 32], PkiError> {
    let (_, cert) = parse_x509_certificate(certificate_der).map_err(|_| PkiError::Parse)?;
    Ok(Sha256::digest(cert.public_key().raw).into())
}

/// The stable key identifier a signing request will produce: SHA-256 of its SubjectPublicKeyInfo, after the request's
/// signature proved possession and the key was checked to be ECDSA P-256. It equals the `key_id` of any certificate
/// issued for that request, so it can be staged before the certificate exists.
pub fn csr_key_id(csr_der: &[u8]) -> Result<[u8; 32], PkiError> {
    let request = CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(csr_der)).map_err(PkiError::Csr)?;
    if request.public_key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
        return Err(PkiError::NotP256);
    }
    let (_, csr) = X509CertificationRequest::from_der(csr_der).map_err(|_| PkiError::Parse)?;
    Ok(Sha256::digest(csr.certification_request_info.subject_pki.raw).into())
}

/// The serial number of a certificate.
pub fn serial_of_certificate(certificate_der: &[u8]) -> Result<Vec<u8>, PkiError> {
    let (_, cert) = parse_x509_certificate(certificate_der).map_err(|_| PkiError::Parse)?;
    Ok(cert.raw_serial().to_vec())
}

fn valid_claims(claims: &Claims<'_>) -> bool {
    !claims.person.is_empty() && claims.person.len() <= MAX_PERSON && !claims.person.chars().any(char::is_control) && claims.device_id != 0
}

fn ca_params(common_name: &str, path_len: u8, from: i64, lifetime: i64) -> Result<CertificateParams, PkiError> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(PkiError::Build)?;
    params.distinguished_name = name(&[(DnType::CommonName, common_name.to_string())]);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(path_len));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = at(from)?;
    params.not_after = at(from.checked_add(lifetime).ok_or(PkiError::Time)?)?;
    params.serial_number = Some(SerialNumber::from_slice(&random_serial()?));
    Ok(params)
}

impl Authority {
    /// A self-signed root that may sign one level of issuing authority.
    pub fn create_root(common_name: &str, now_ms: u64) -> Result<Authority, PkiError> {
        let from = secs(now_ms)?;
        let params = ca_params(common_name, 1, from, ROOT_LIFETIME_SECS)?;
        let key = KeyPair::generate().map_err(PkiError::Build)?;
        let certificate = params.self_signed(&key).map_err(PkiError::Build)?;
        Ok(Authority { certificate: certificate.der().to_vec(), issuer: Issuer::new(params, key), ledger: HashMap::new() })
    }

    /// An issuing authority signed by this one. It can sign leaf certificates and nothing else.
    pub fn create_issuing(&self, common_name: &str, now_ms: u64) -> Result<Authority, PkiError> {
        let from = secs(now_ms)?;
        let params = ca_params(common_name, 0, from, ISSUING_LIFETIME_SECS)?;
        let key = KeyPair::generate().map_err(PkiError::Build)?;
        let certificate = params.signed_by(&key, &self.issuer).map_err(PkiError::Build)?;
        Ok(Authority { certificate: certificate.der().to_vec(), issuer: Issuer::new(params, key), ledger: HashMap::new() })
    }

    /// This authority's certificate, DER. Clients pin the root's.
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    /// The server's certificate for `dns_name`, with a fresh P-256 key. The subject is the name alone: nothing in it says
    /// what product answers (docs/SECURITY-DESIGN.md section 1).
    pub fn server_certificate(&self, dns_name: &str, now_ms: u64) -> Result<ServerIdentity, PkiError> {
        let from = secs(now_ms)?;
        let mut params = CertificateParams::new(vec![dns_name.to_string()]).map_err(PkiError::Build)?;
        params.distinguished_name = name(&[(DnType::CommonName, dns_name.to_string())]);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = at(from)?;
        params.not_after = at(from.checked_add(SERVER_LIFETIME_SECS).ok_or(PkiError::Time)?)?;
        params.serial_number = Some(SerialNumber::from_slice(&random_serial()?));
        let key = KeyPair::generate().map_err(PkiError::Build)?;
        let certificate = params.signed_by(&key, &self.issuer).map_err(PkiError::Build)?;
        Ok(ServerIdentity { chain: vec![certificate.der().to_vec(), self.certificate.clone()], key_pkcs8: key.serialize_der() })
    }

    /// Build a device certificate for the key in `csr_der` WITHOUT recording it: nothing is added to the ledger, so a
    /// caller that must commit durable state first can build, commit, and only then `record_issued`. The result is not
    /// a valid device until recorded (`status` says `Unknown`).
    pub fn prepare_device(&self, csr_der: &[u8], claims: &Claims<'_>, now_ms: u64) -> Result<Issued, PkiError> {
        if !valid_claims(claims) {
            return Err(PkiError::BadClaims);
        }
        // `from_der` checks the request's signature against its own public key: that is the proof of possession.
        let request = CertificateSigningRequestParams::from_der(&CertificateSigningRequestDer::from(csr_der)).map_err(PkiError::Csr)?;
        if request.public_key.algorithm() != &PKCS_ECDSA_P256_SHA256 {
            return Err(PkiError::NotP256);
        }
        let from = secs(now_ms)?;
        let until = from.checked_add(DEVICE_LIFETIME_SECS).ok_or(PkiError::Time)?;
        // Fresh parameters from the claims. Nothing from `request.params` is used, only `request.public_key`.
        let mut params = CertificateParams::new(Vec::<String>::new()).map_err(PkiError::Build)?;
        params.distinguished_name =
            name(&[(DnType::CommonName, claims.person.to_string()), (DnType::OrganizationalUnitName, format!("device-{}", claims.device_id))]);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        params.not_before = at(from)?;
        params.not_after = at(until)?;
        let serial = random_serial()?;
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        let certificate = params.signed_by(&request.public_key, &self.issuer).map_err(PkiError::Build)?;
        let certificate = certificate.der().to_vec();
        let key_id = key_id_of_certificate(&certificate)?;
        Ok(Issued { chain: vec![certificate.clone(), self.certificate.clone()], certificate, serial, key_id, not_before: from, not_after: until })
    }

    /// Record a certificate from `prepare_device` in the ledger, making it good. Call it only after whatever must be
    /// durable before the device holds the certificate has been committed.
    pub fn record_issued(&mut self, issued: &Issued, claims: &Claims<'_>) {
        let info = LeafInfo { person: claims.person.to_string(), device_id: claims.device_id, key_id: issued.key_id };
        self.ledger
            .insert(issued.serial.clone(), Leaf { certificate: issued.certificate.clone(), info, not_after: issued.not_after, revoked: false });
    }

    /// Issue a device certificate for the key in `csr_der` (a DER PKCS#10 request), with the identity in `claims`.
    pub fn issue_device(&mut self, csr_der: &[u8], claims: &Claims<'_>, now_ms: u64) -> Result<Issued, PkiError> {
        let issued = self.prepare_device(csr_der, claims, now_ms)?;
        self.record_issued(&issued, claims);
        Ok(issued)
    }

    /// Renew `old_certificate`: a new 90-day certificate for the SAME key with the SAME identity. The old one must be
    /// exactly what this authority issued, unrevoked and unexpired, and the request must carry the same key. The old
    /// certificate stays valid until it expires or is revoked.
    pub fn renew(&mut self, old_certificate: &[u8], csr_der: &[u8], now_ms: u64) -> Result<Issued, PkiError> {
        let info = match self.status(old_certificate, now_ms)? {
            Status::Good(info) => info,
            Status::Revoked => return Err(PkiError::Revoked),
            Status::Expired => return Err(PkiError::Expired),
            Status::Unknown => return Err(PkiError::NotIssuedHere),
        };
        let claims = Claims { person: &info.person, device_id: info.device_id };
        let issued = self.prepare_device(csr_der, &claims, now_ms)?;
        if issued.key_id != info.key_id {
            return Err(PkiError::KeyMismatch);
        }
        self.record_issued(&issued, &claims);
        Ok(issued)
    }

    /// Is this device certificate still good? Ask on every connection and before every renewal. A certificate whose
    /// serial is unknown, or whose bytes differ from the one issued under that serial, is `Unknown`.
    pub fn status(&self, certificate_der: &[u8], now_ms: u64) -> Result<Status, PkiError> {
        let serial = serial_of_certificate(certificate_der)?;
        let Some(leaf) = self.ledger.get(&serial) else { return Ok(Status::Unknown) };
        if leaf.certificate != certificate_der {
            return Ok(Status::Unknown);
        }
        if leaf.revoked {
            return Ok(Status::Revoked);
        }
        if secs(now_ms)? >= leaf.not_after {
            return Ok(Status::Expired);
        }
        Ok(Status::Good(leaf.info.clone()))
    }

    /// Revoke one issued certificate. `false` if the serial is not one we issued.
    pub fn revoke(&mut self, serial: &[u8]) -> bool {
        match self.ledger.get_mut(serial) {
            Some(leaf) => {
                leaf.revoked = true;
                true
            }
            None => false,
        }
    }

    /// Revoke every certificate issued for a device key, renewals included. Returns how many.
    pub fn revoke_key(&mut self, key_id: &[u8; 32]) -> usize {
        let mut revoked = 0;
        for leaf in self.ledger.values_mut().filter(|l| &l.info.key_id == key_id && !l.revoked) {
            leaf.revoked = true;
            revoked += 1;
        }
        revoked
    }
}
