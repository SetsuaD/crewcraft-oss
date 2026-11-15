//! Bind an enrollment invitation to the intended self-hosted server's root CA.

use std::fmt;

use sha2::{Digest, Sha256};

/// SHA-256 of the DER-encoded root certificate, communicated in a trusted invitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootFingerprint([u8; 32]);

impl RootFingerprint {
    /// Compute an invitation fingerprint from the server's local root certificate.
    pub fn from_der(root_der: &[u8]) -> Self {
        Self(Sha256::digest(root_der).into())
    }

    /// Parse 64 ASCII hexadecimal characters with either case and no separators.
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() != 64 {
            return None;
        }
        let mut fingerprint = [0; 32];
        let (pairs, _) = text.as_bytes().as_chunks::<2>();
        for (byte, &[high, low]) in fingerprint.iter_mut().zip(pairs) {
            let high = (high as char).to_digit(16)?;
            let low = (low as char).to_digit(16)?;
            *byte = (high * 16 + low) as u8;
        }
        Some(Self(fingerprint))
    }

    /// Confirm the supplied bytes match this fingerprint before adding the certificate as a TLS trust anchor.
    /// TLS must still parse the certificate and verify the chain and server name.
    pub fn matches(self, root_der: &[u8]) -> bool {
        self == Self::from_der(root_der)
    }
}

impl fmt::Display for RootFingerprint {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(output, "{byte:02x}")?;
        }
        Ok(())
    }
}
