//! SFrame, RFC 9605: end-to-end encryption of media frames for calls through a forwarding media server (docs/CALLS.md
//! "End-to-end encryption", task T360c). Built from the RFC alone.
//!
//! Owns: the SFrame header (key id and counter, minimally encoded), the key schedule (HKDF from a base key, labelled
//! with the key id and cipher suite), and frame encryption and decryption for the AES-GCM cipher suites. Key
//! management (who gets which base key) is the caller's; `seal` seals a base key to one participant (task T360d1).
//! AES-GCM and HKDF come from `ring`, which the TLS stack already brings; X25519 from `curve25519-dalek`, already
//! in the build through the update signatures.

pub mod seal;

use ring::aead::{AES_128_GCM, AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{HKDF_SHA256, HKDF_SHA512, KeyType, Salt};

/// The cipher suites this crate implements (RFC 9605 section 4.5): AES-GCM with a 128-bit tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// 0x0004: AES-128-GCM, HKDF with SHA-256.
    Aes128GcmSha256,
    /// 0x0005: AES-256-GCM, HKDF with SHA-512.
    Aes256GcmSha512,
}

impl CipherSuite {
    /// The suite's identifier on the wire and in the key labels.
    pub fn id(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x0004,
            Self::Aes256GcmSha512 => 0x0005,
        }
    }

    /// The AEAD key length, Nk.
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => 16,
            Self::Aes256GcmSha512 => 32,
        }
    }
}

/// The nonce length, Nn, of every suite here.
pub const NONCE_LEN: usize = 12;
/// The authentication tag length, Nt, of every suite here.
pub const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The frame ends before its header or tag does.
    Truncated,
    /// The header uses more bytes than needed for its key id or counter (RFC 9605 requires the minimum).
    NotMinimal,
    /// No key for the frame's key id.
    UnknownKey(u64),
    /// The frame was changed, or was encrypted with another key: authentication failed.
    Authentication,
    /// A base key the key schedule cannot use (empty).
    BadKey,
    /// A frame larger than AES-GCM can seal.
    TooLarge,
    /// The sender's counter is used up (2^64 frames): make a new key.
    CounterExhausted,
}

/// The header of a frame: the key id and the counter (RFC 9605 section 4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kid: u64,
    pub ctr: u64,
}

/// The fewest big-endian bytes that hold `value` (at least one).
fn minimal_bytes(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(7);
    bytes[first..].to_vec()
}

impl Header {
    /// The header's bytes: a config byte `X K(3) Y C(3)`, then the key id and the counter when either is 8 or more,
    /// each in as few big-endian bytes as it needs.
    pub fn encode(&self) -> Vec<u8> {
        let mut config = 0u8;
        let mut rest = Vec::new();
        if self.kid < 8 {
            config |= (self.kid as u8) << 4;
        } else {
            let kid = minimal_bytes(self.kid);
            config |= 0x80 | (((kid.len() - 1) as u8) << 4);
            rest.extend_from_slice(&kid);
        }
        if self.ctr < 8 {
            config |= self.ctr as u8;
        } else {
            let ctr = minimal_bytes(self.ctr);
            config |= 0x08 | ((ctr.len() - 1) as u8);
            rest.extend_from_slice(&ctr);
        }
        let mut out = vec![config];
        out.extend_from_slice(&rest);
        out
    }

    /// Read a header from the start of `bytes`; returns it and how many bytes it took. Refuses a value written with
    /// more bytes than it needs, or in the long form when it fits the short one.
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize), Error> {
        let config = *bytes.first().ok_or(Error::Truncated)?;
        let mut at = 1;
        let mut field = |extended: bool, value: u8| -> Result<u64, Error> {
            if !extended {
                return Ok(u64::from(value));
            }
            let len = usize::from(value) + 1;
            let raw = bytes.get(at..at + len).ok_or(Error::Truncated)?;
            at += len;
            let number = raw.iter().fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
            if (len > 1 && raw[0] == 0) || number < 8 {
                return Err(Error::NotMinimal);
            }
            Ok(number)
        };
        let kid = field(config & 0x80 != 0, (config >> 4) & 0x07)?;
        let ctr = field(config & 0x08 != 0, config & 0x07)?;
        Ok((Self { kid, ctr }, at))
    }
}

/// HKDF output of `len` bytes, as `ring` asks for it.
struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// One sender's key for one key id: the AEAD key and the salt the nonces are made from (RFC 9605 section 4.4.2).
pub struct Key {
    suite: CipherSuite,
    kid: u64,
    key: LessSafeKey,
    salt: [u8; NONCE_LEN],
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key").field("suite", &self.suite).field("kid", &self.kid).finish_non_exhaustive()
    }
}

/// The key schedule's two outputs for `base_key`, key id `kid` and `suite`: the AEAD key and the salt.
pub fn derive(suite: CipherSuite, kid: u64, base_key: &[u8]) -> Result<(Vec<u8>, [u8; NONCE_LEN]), Error> {
    if base_key.is_empty() {
        return Err(Error::BadKey);
    }
    let algorithm = match suite {
        CipherSuite::Aes128GcmSha256 => HKDF_SHA256,
        CipherSuite::Aes256GcmSha512 => HKDF_SHA512,
    };
    let secret = Salt::new(algorithm, &[]).extract(base_key);
    let label = |name: &str| {
        let mut label = name.as_bytes().to_vec();
        label.extend_from_slice(&kid.to_be_bytes());
        label.extend_from_slice(&suite.id().to_be_bytes());
        label
    };
    let key_label = label("SFrame 1.0 Secret key ");
    let salt_label = label("SFrame 1.0 Secret salt ");
    let mut key = vec![0u8; suite.key_len()];
    let mut salt = [0u8; NONCE_LEN];
    secret.expand(&[&key_label], Len(key.len())).and_then(|okm| okm.fill(&mut key)).map_err(|_| Error::BadKey)?;
    secret.expand(&[&salt_label], Len(NONCE_LEN)).and_then(|okm| okm.fill(&mut salt)).map_err(|_| Error::BadKey)?;
    Ok((key, salt))
}

impl Key {
    /// The key for `kid` from `base_key`.
    pub fn new(suite: CipherSuite, kid: u64, base_key: &[u8]) -> Result<Self, Error> {
        let (key, salt) = derive(suite, kid, base_key)?;
        let algorithm = match suite {
            CipherSuite::Aes128GcmSha256 => &AES_128_GCM,
            CipherSuite::Aes256GcmSha512 => &AES_256_GCM,
        };
        let key = LessSafeKey::new(UnboundKey::new(algorithm, &key).map_err(|_| Error::BadKey)?);
        Ok(Self { suite, kid, key, salt })
    }

    pub fn kid(&self) -> u64 {
        self.kid
    }

    /// The nonce for counter `ctr`: the salt with the counter's big-endian bytes XORed into its end.
    fn nonce(&self, ctr: u64) -> Nonce {
        let mut nonce = self.salt;
        for (byte, ctr_byte) in nonce[NONCE_LEN - 8..].iter_mut().zip(ctr.to_be_bytes()) {
            *byte ^= ctr_byte;
        }
        Nonce::assume_unique_for_key(nonce)
    }

    /// Encrypt one frame with counter `ctr`: the header, then the ciphertext and tag, authenticating the header and
    /// `metadata`. Each counter must be used once per key: the caller counts (see `Sender`).
    pub fn encrypt(&self, ctr: u64, metadata: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let header = Header { kid: self.kid, ctr }.encode();
        let mut aad = header.clone();
        aad.extend_from_slice(metadata);
        let mut body = plaintext.to_vec();
        // Sealing with a valid key and a 12-byte nonce fails only for inputs larger than AES-GCM allows (64 GiB).
        self.key.seal_in_place_append_tag(self.nonce(ctr), Aad::from(&aad), &mut body).map_err(|_| Error::TooLarge)?;
        let mut out = header;
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Decrypt a frame encrypted under this key; the header must name this key's id.
    pub fn decrypt(&self, metadata: &[u8], frame: &[u8]) -> Result<Vec<u8>, Error> {
        let (header, len) = Header::decode(frame)?;
        if header.kid != self.kid {
            return Err(Error::UnknownKey(header.kid));
        }
        if frame.len() < len + TAG_LEN {
            return Err(Error::Truncated);
        }
        let mut aad = frame[..len].to_vec();
        aad.extend_from_slice(metadata);
        let mut body = frame[len..].to_vec();
        let plain = self.key.open_in_place(self.nonce(header.ctr), Aad::from(&aad), &mut body).map_err(|_| Error::Authentication)?;
        Ok(plain.to_vec())
    }
}

/// Decrypt `frame` with whichever key its header names; `keys` finds a key by id.
pub fn decrypt<'k>(keys: impl Fn(u64) -> Option<&'k Key>, metadata: &[u8], frame: &[u8]) -> Result<Vec<u8>, Error> {
    let (header, _) = Header::decode(frame)?;
    keys(header.kid).ok_or(Error::UnknownKey(header.kid))?.decrypt(metadata, frame)
}

/// A sending participant's key with its counter, so no counter is used twice.
#[derive(Debug)]
pub struct Sender {
    key: Key,
    next: u64,
}

impl Sender {
    pub fn new(key: Key) -> Self {
        Self { key, next: 0 }
    }

    /// Encrypt the next frame. `CounterExhausted` once the counter is used up (2^64 frames): make a new key.
    pub fn encrypt(&mut self, metadata: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let ctr = self.next;
        self.next = self.next.checked_add(1).ok_or(Error::CounterExhausted)?;
        self.key.encrypt(ctr, metadata, plaintext)
    }

    pub fn key(&self) -> &Key {
        &self.key
    }
}
