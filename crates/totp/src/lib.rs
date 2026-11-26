//! Time-based one-time passwords (RFC 6238) for CrewCraft's mandatory second factor.
//!
//! Owns: the TOTP algorithm, code verification with clock skew and replay protection, the
//! `otpauth://` URI an authenticator app scans, and base32 (RFC 4648) for the shared secret.
//! Called by: `crewcraft-server-core` (enrollment and sign-in). Calls: RustCrypto `hmac`/`sha1`/`sha2`.
//! Never hand-roll a primitive here; compare codes in constant time (`subtle`).

pub mod base32;

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;

/// The HMAC hash a TOTP uses. Authenticator apps universally support `Sha1`; it is the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    /// The name used in an `otpauth://` URI: `SHA1`, `SHA256` or `SHA512`.
    pub fn uri_name(self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The secret is shorter than 16 bytes (128 bits, RFC 4226 section 4 minimum).
    SecretTooShort,
    /// `digits` must be 6, 7 or 8.
    BadDigits,
    /// `step` must be at least 1 second.
    BadStep,
    /// Not valid base32.
    BadBase32,
}

#[expect(clippy::expect_used, reason = "HMAC takes a key of any length (RFC 2104); new_from_slice returns a Result only for its trait")]
fn hmac_for_algorithm(secret: &[u8], algorithm: Algorithm, counter: u64) -> Vec<u8> {
    let counter_bytes = counter.to_be_bytes();

    match algorithm {
        Algorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC key");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC key");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(secret).expect("HMAC key");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// One user's TOTP configuration. CrewCraft issues SHA-1, 6 digits, 30-second steps by default.
#[derive(Clone)]
pub struct Totp {
    secret: Vec<u8>,
    algorithm: Algorithm,
    digits: u32,
    step: u64,
}

impl std::fmt::Debug for Totp {
    // Never print the shared secret, even in logs or panics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &format_args!(".."))
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("step", &self.step)
            .finish()
    }
}

impl Totp {
    /// Validates the parameters (see [`Error`]) and builds the generator.
    pub fn new(secret: Vec<u8>, algorithm: Algorithm, digits: u32, step: u64) -> Result<Self, Error> {
        if secret.len() < 16 {
            return Err(Error::SecretTooShort);
        }
        if !(6..=8).contains(&digits) {
            return Err(Error::BadDigits);
        }
        if step == 0 {
            return Err(Error::BadStep);
        }
        Ok(Totp { secret, algorithm, digits, step })
    }

    /// The defaults CrewCraft enrolls users with: SHA-1, 6 digits, 30 seconds.
    pub fn with_defaults(secret: Vec<u8>) -> Result<Self, Error> {
        Totp::new(secret, Algorithm::Sha1, 6, 30)
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
    pub fn digits(&self) -> u32 {
        self.digits
    }
    pub fn step(&self) -> u64 {
        self.step
    }

    /// The time-step counter for a Unix time: `unix_time / step` (RFC 6238 section 4, T0 = 0).
    pub fn counter(&self, unix_time: u64) -> u64 {
        unix_time / self.step
    }

    /// The code for a given counter (RFC 4226 HOTP with dynamic truncation), zero-padded to `digits`.
    pub fn generate_at_counter(&self, counter: u64) -> String {
        let mac = hmac_for_algorithm(&self.secret, self.algorithm, counter);
        let offset = (mac[mac.len() - 1] & 0x0f) as usize;

        let binary_code =
            ((mac[offset] & 0x7f) as u32) << 24 | (mac[offset + 1] as u32) << 16 | (mac[offset + 2] as u32) << 8 | (mac[offset + 3] as u32);

        let modulus = 10u32.pow(self.digits);
        let code = binary_code % modulus;

        format!("{:0width$}", code, width = self.digits as usize)
    }

    /// The code valid at `unix_time`.
    pub fn generate(&self, unix_time: u64) -> String {
        self.generate_at_counter(self.counter(unix_time))
    }

    /// Checks `code` against the counters `counter(unix_time) - skew ..= counter(unix_time) + skew`.
    ///
    /// Returns the matching counter, or `None`. A counter at or below `last_used` is rejected even if the code
    /// matches (replay protection: the caller stores the returned counter as the new `last_used`). Codes with
    /// the wrong length or non-digit characters never match. The comparison is constant time.
    pub fn verify(&self, code: &str, unix_time: u64, skew: u64, last_used: Option<u64>) -> Option<u64> {
        if code.len() != self.digits as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }

        let center = self.counter(unix_time);
        let low = center.saturating_sub(skew);
        let high = center.saturating_add(skew);

        for counter in low..=high {
            if let Some(last) = last_used
                && counter <= last
            {
                continue;
            }

            let expected = self.generate_at_counter(counter);
            if bool::from(code.as_bytes().ct_eq(expected.as_bytes())) {
                return Some(counter);
            }
        }

        None
    }

    /// The `otpauth://totp/...` URI an authenticator app scans (Key Uri Format).
    ///
    /// Label is `issuer:account`, both percent-encoded; query is `secret` (base32, no padding), `issuer`,
    /// `algorithm`, `digits`, `period`, in that order.
    pub fn otpauth_uri(&self, issuer: &str, account: &str) -> String {
        let issuer = percent_encode(issuer);
        let account = percent_encode(account);
        let secret = base32::encode_nopad(&self.secret);

        format!(
            "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm={}&digits={}&period={}",
            self.algorithm.uri_name(),
            self.digits,
            self.step
        )
    }
}

fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
    out
}
