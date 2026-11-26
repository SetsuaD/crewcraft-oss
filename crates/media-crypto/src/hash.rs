//! SHA-1, HMAC-SHA1 and SHA-256 for str0m (task T362a): STUN message integrity and fingerprints, SRTP
//! authentication (AES_CM_128_HMAC_SHA1_80) and DTLS certificate fingerprints.

use hmac::{KeyInit, Mac};
use sha2::Digest;
use str0m_proto::crypto::{Sha1HmacProvider, Sha1Provider, Sha256Provider};

/// HMAC-SHA1 over several pieces, as if they were one message.
#[derive(Debug)]
pub struct Sha1Hmac;

impl Sha1HmacProvider for Sha1Hmac {
    fn sha1_hmac(&self, key: &[u8], payloads: &[&[u8]]) -> [u8; 20] {
        // HMAC takes a key of any length (a long one is hashed first), so this cannot fail.
        let Ok(mut mac) = hmac::Hmac::<sha1::Sha1>::new_from_slice(key) else { return [0; 20] };
        for payload in payloads {
            mac.update(payload);
        }
        mac.finalize().into_bytes().into()
    }
}

/// SHA-1.
#[derive(Debug)]
pub struct Sha1;

impl Sha1Provider for Sha1 {
    fn sha1(&self, data: &[u8]) -> [u8; 20] {
        sha1::Sha1::digest(data).into()
    }
}

/// SHA-256.
#[derive(Debug)]
pub struct Sha256;

impl Sha256Provider for Sha256 {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        sha2::Sha256::digest(data).into()
    }
}
