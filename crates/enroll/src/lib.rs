//! Enrollment codes: the one-time secret an invited user receives by email.
//!
//! Owns: the code's text format and checksum, parsing what a person retypes, and the bootstrap key seed the
//! code derives. The seed lets an invited device make its FIRST mutual-TLS handshake without any anonymous
//! endpoint existing (docs/SECURITY-DESIGN.md, "Dark enrollment"): server and client both derive the same
//! Ed25519 key from the code, so the server recognises the device's self-signed bootstrap certificate.
//! Called by: `crewcraft-server-core` (issuing invites), `crewcraft-client-core` (redeeming them).
//!
//! Format, version 1: `CC1-` then 32 Crockford base32 characters of a 160-bit random secret in eight groups of
//! four, then `-` and one Crockford check symbol (the secret as a big-endian integer, mod 37):
//! `CC1-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-C`.

/// Crockford base32 alphabet (no I, L, O, U).
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Crockford check symbols: the alphabet, then `*~$=U` for values 32 to 36.
pub const CHECK_SYMBOLS: &[u8; 37] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Missing or unknown `CC<n>-` version prefix.
    BadPrefix,
    /// Wrong number of characters after normalising.
    BadLength,
    /// A character outside Crockford base32.
    BadCharacter,
    /// The check symbol does not match: a typo.
    BadChecksum,
}

/// A 160-bit enrollment secret.
#[derive(Clone, PartialEq, Eq)]
pub struct EnrollmentCode([u8; 20]);

impl std::fmt::Debug for EnrollmentCode {
    // Never print the secret, even in logs or panics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnrollmentCode(..)")
    }
}

impl EnrollmentCode {
    /// Wraps 20 bytes that the caller drew from the OS CSPRNG.
    pub fn from_bytes(secret: [u8; 20]) -> Self {
        EnrollmentCode(secret)
    }

    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// The check symbol: the 160-bit secret, read as a big-endian integer, mod 37, indexed into [`CHECK_SYMBOLS`].
    pub fn check_symbol(&self) -> char {
        let mut v: u64 = 0;
        for &byte in &self.0 {
            v = (v.wrapping_mul(256).wrapping_add(byte as u64)) % 37;
        }
        CHECK_SYMBOLS[v as usize] as char
    }

    /// The display form described in the module docs.
    pub fn to_display(&self) -> String {
        let mut s = String::with_capacity(39);
        s.push_str("CC1-");
        for i in 0..32u32 {
            if i > 0 && i % 4 == 0 {
                s.push('-');
            }
            let bit_start = i * 5;
            let mut val: u8 = 0;
            for j in 0..5 {
                let bit = bit_start + j;
                let b = (self.0[(bit / 8) as usize] >> (7 - (bit % 8))) & 1;
                val = (val << 1) | b;
            }
            s.push(ALPHABET[val as usize] as char);
        }
        s.push('-');
        s.push(self.check_symbol());
        s
    }

    /// Parses what a person typed: case-insensitive; hyphens and whitespace ignored; `O`/`o` read as `0` and
    /// `I`/`i`/`L`/`l` as `1` (Crockford); the prefix must be `CC1`.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let normalized: String = text.chars().filter(|c| !c.is_whitespace() && *c != '-').map(|c| c.to_ascii_uppercase()).collect();

        let bytes = normalized.as_bytes();
        if bytes.len() < 3 || &bytes[0..3] != b"CC1" {
            return Err(Error::BadPrefix);
        }

        let rest = &bytes[3..];

        let mapped: Vec<u8> = rest
            .iter()
            .map(|&c| match c {
                b'O' => b'0',
                b'I' | b'L' => b'1',
                _ => c,
            })
            .collect();

        if mapped.len() != 33 {
            return Err(Error::BadLength);
        }

        let mut data_bits = [0u8; 32];
        for (i, &c) in mapped[..32].iter().enumerate() {
            match ALPHABET.iter().position(|&a| a == c) {
                Some(val) => data_bits[i] = val as u8,
                None => return Err(Error::BadCharacter),
            }
        }

        let check_char = mapped[32];
        let expected_check = match CHECK_SYMBOLS.iter().position(|&a| a == check_char) {
            Some(val) => val,
            None => return Err(Error::BadChecksum),
        };

        let mut secret = [0u8; 20];
        for (i, &val) in data_bits.iter().enumerate() {
            let bit_start = i * 5;
            let byte_idx = bit_start / 8;
            let bit_offset = bit_start % 8;
            if bit_offset <= 3 {
                secret[byte_idx] |= val << (3 - bit_offset);
            } else {
                let spill = bit_offset - 3;
                secret[byte_idx] |= val >> spill;
                secret[byte_idx + 1] |= (val & ((1 << spill) - 1)) << (8 - spill);
            }
        }

        let mut v: u64 = 0;
        for &byte in &secret {
            v = (v.wrapping_mul(256).wrapping_add(byte as u64)) % 37;
        }
        if expected_check != v as usize {
            return Err(Error::BadChecksum);
        }

        Ok(EnrollmentCode(secret))
    }

    /// The 32-byte Ed25519 seed for the bootstrap key: HKDF-SHA256 with the 20 secret bytes as input key
    /// material, salt `crewcraft-enroll-v1`, info `bootstrap-ed25519`.
    pub fn bootstrap_seed(&self) -> [u8; 32] {
        use hkdf::Hkdf;
        use sha2::Sha256;

        let hk = Hkdf::<Sha256>::new(Some(b"crewcraft-enroll-v1"), &self.0);
        let mut okm = [0u8; 32];
        // A failure must never fall through to an all-zero (predictable) key, so this panics rather than ignoring the result.
        #[allow(clippy::expect_used, reason = "HKDF-SHA256 accepts any output up to 8160 bytes; 32 cannot fail")]
        hk.expand(b"bootstrap-ed25519", &mut okm).expect("32-byte HKDF-SHA256 output");
        okm
    }

    /// The Ed25519 public key (RFC 8032) of the bootstrap key pair: `bootstrap_public_key` of `bootstrap_seed`. This is
    /// the only thing the server stores of an invitation (docs/SECURITY-DESIGN.md section 3). Task T200.
    pub fn bootstrap_public_key(&self) -> [u8; 32] {
        bootstrap_public_key(&self.bootstrap_seed())
    }
}

/// The Ed25519 public key (32 bytes, RFC 8032 section 5.1.5) for the key pair whose 32-byte seed (the RFC's "secret key")
/// is `seed`. Task T200.
#[allow(clippy::todo, reason = "stub until task T200 lands; remove this allow with the stub")]
pub fn bootstrap_public_key(seed: &[u8; 32]) -> [u8; 32] {
    let _ = seed;
    todo!("T200: Ed25519 public key from the seed")
}
