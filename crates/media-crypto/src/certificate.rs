//! The DTLS certificate (task T362a): a fresh P-256 key and a self-signed X.509 certificate for it, made with
//! RustCrypto instead of `rcgen`.
//!
//! WebRTC does not trust certificates by issuer: each peer puts its certificate's SHA-256 fingerprint in its
//! session description, and DTLS checks the certificate the other peer presents against that fingerprint. So the
//! certificate carries only what DTLS needs: the public key, a self signature, a random serial and a validity.

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::EncodePrivateKey;
use str0m_proto::crypto::dtls::DtlsCert;
use x509_cert::builder::profile::BuilderProfile;
use x509_cert::builder::{Builder, CertificateBuilder};
use x509_cert::certificate::TbsCertificate;
use x509_cert::der::Encode;
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::time::{Time, Validity};
use zeroize::Zeroizing;

/// The certificate's subject and issuer.
const NAME: &str = "CN=CrewCraft";
/// How long a certificate is valid. A call's certificate lives as long as the media process; peers check the
/// fingerprint, not the dates, but the dates must still parse.
const VALID_FOR: Duration = Duration::from_secs(30 * 24 * 60 * 60);
/// How far the validity starts before now, for peers whose clocks run behind.
const CLOCK_SKEW: Duration = Duration::from_secs(24 * 60 * 60);

/// A new P-256 key and its self-signed certificate, both DER (the key as PKCS#8). `None` when the system has no
/// random numbers or the certificate cannot be encoded.
pub fn self_signed() -> Option<DtlsCert> {
    let key = new_key()?;
    let public = SubjectPublicKeyInfoOwned::from_key(key.verifying_key()).ok()?;
    let mut serial = [0u8; 16];
    getrandom::fill(&mut serial).ok()?;
    // A positive serial with no leading zero byte, as RFC 5280 asks.
    serial[0] = (serial[0] & 0x7f) | 0x40;
    let now = SystemTime::now();
    let validity = Validity::new(Time::try_from(now.checked_sub(CLOCK_SKEW)?).ok()?, Time::try_from(now + VALID_FOR).ok()?);
    let builder = CertificateBuilder::new(SelfSigned(Name::from_str(NAME).ok()?), SerialNumber::new(&serial).ok()?, validity, public).ok()?;
    let certificate = builder.build::<_, DerSignature>(&key).ok()?.to_der().ok()?;
    let private_key = key.to_pkcs8_der().ok()?.as_bytes().to_vec();
    Some(DtlsCert { certificate, private_key })
}

/// A P-256 signing key from the system's random numbers.
fn new_key() -> Option<SigningKey> {
    // A random 32-byte string is a valid scalar except with negligible chance (zero, or not below the group order);
    // a few tries settle it.
    for _ in 0..8 {
        let mut bytes = Zeroizing::new([0u8; 32]);
        getrandom::fill(bytes.as_mut()).ok()?;
        if let Ok(key) = SigningKey::from_slice(bytes.as_ref()) {
            return Some(key);
        }
    }
    None
}

/// The certificate's profile: subject and issuer both [`NAME`], no extensions.
struct SelfSigned(Name);

impl BuilderProfile for SelfSigned {
    fn get_issuer(&self, subject: &Name) -> Name {
        subject.clone()
    }

    fn get_subject(&self) -> Name {
        self.0.clone()
    }

    fn build_extensions(
        &self,
        _spk: SubjectPublicKeyInfoRef<'_>,
        _issuer_spk: SubjectPublicKeyInfoRef<'_>,
        _tbs: &TbsCertificate,
    ) -> x509_cert::builder::Result<Vec<Extension>> {
        Ok(Vec::new())
    }
}
