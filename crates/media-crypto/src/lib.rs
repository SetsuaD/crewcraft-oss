//! CrewCraft's own crypto provider for the str0m WebRTC stack (task T362a, docs/CALLS.md "The media server's
//! crypto"), in pure Rust.
//!
//! str0m does no cryptography itself: it calls a [`CryptoProvider`] for DTLS, SRTP and the hashes ICE and SRTP
//! need. Every backend str0m ships links C (aws-lc, OpenSSL, or `rcgen`'s aws-lc for the DTLS certificate even in
//! its RustCrypto mode), so CrewCraft supplies its own:
//!
//! - DTLS 1.2 and 1.3: `dimpl` in its RustCrypto mode ([`dtls`]);
//! - the DTLS certificate: a fresh P-256 key and a self-signed certificate made with `p256` and `x509-cert`
//!   ([`certificate`]);
//! - SRTP: AES_CM_128_HMAC_SHA1_80, AEAD_AES_128_GCM and AEAD_AES_256_GCM with the `aes`, `ctr` and `aes-gcm`
//!   crates ([`srtp`]);
//! - SHA-1, HMAC-SHA1 and SHA-256 ([`hash`]).
//!
//! No primitive is written here: each one is an audited RustCrypto crate (docs/SECURITY-DESIGN.md). This crate is
//! the wiring between those crates and str0m's interface, and its tests check that wiring against published test
//! vectors and against str0m itself.

pub mod certificate;
pub mod dtls;
pub mod hash;
pub mod srtp;

pub use str0m_proto::crypto::CryptoProvider;

/// The provider to hand str0m: `RtcConfig::set_crypto_provider(Arc::new(crewcraft_media_crypto::provider()))`.
pub fn provider() -> CryptoProvider {
    static SRTP: srtp::Srtp = srtp::Srtp;
    static SHA1_HMAC: hash::Sha1Hmac = hash::Sha1Hmac;
    static SHA1: hash::Sha1 = hash::Sha1;
    static SHA256: hash::Sha256 = hash::Sha256;
    static DTLS: dtls::Dtls = dtls::Dtls;
    CryptoProvider { srtp_provider: &SRTP, sha1_hmac_provider: &SHA1_HMAC, sha1_provider: &SHA1, sha256_provider: &SHA256, dtls_provider: &DTLS }
}
