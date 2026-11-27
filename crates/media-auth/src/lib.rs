//! Media credentials (docs/CALLS.md "Admission: removed means removed", task T360b1): the chat server's signed,
//! short-lived, single-use permission for one device of one person to join one call on one media server. The media
//! server accepts a WebRTC session only with one, and only once.
//!
//! Owns: the credential's bytes, signing (`Issuer`), and checking (`Verifier`, with the single-use record). The chat
//! server issues on `CallJoin`; the media server verifies (later tasks wire both).
//!
//! Wire format, integers big-endian, `str` a `u16` length then UTF-8:
//! `u8 version (1) | u64 call | str room | str person | u64 device | str media server | u64 not_after_ms |
//! 16 nonce | 64 Ed25519 signature over everything before it`.

use std::collections::BTreeMap;

use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

/// How long a credential is good for after it is issued (docs/CALLS.md).
pub const LIFETIME_MS: u64 = 60_000;
/// The longest room, person or media server name, in bytes.
pub const MAX_NAME: usize = 320;
const VERSION: u8 = 1;
const SIGNATURE_LEN: usize = 64;

/// What a credential admits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub call: u64,
    pub room: String,
    pub person: String,
    pub device: u64,
    /// The media server it is for (its server name): another media server refuses it.
    pub media_server: String,
    pub not_after_ms: u64,
    pub nonce: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Not a credential: cut short, too long, an unknown version or a bad name.
    Malformed,
    /// The signature is not the chat server's.
    BadSignature,
    /// Past its `not_after_ms`.
    Expired,
    /// For another media server.
    WrongServer,
    /// Already used once.
    Replayed,
    /// A name too long, or the key could not be made or used.
    Unusable,
}

fn put_str(out: &mut Vec<u8>, text: &str) -> Result<(), Error> {
    if text.is_empty() || text.len() > MAX_NAME {
        return Err(Error::Unusable);
    }
    out.extend_from_slice(&(text.len() as u16).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    Ok(())
}

fn body(grant: &Grant) -> Result<Vec<u8>, Error> {
    let mut out = vec![VERSION];
    out.extend_from_slice(&grant.call.to_be_bytes());
    put_str(&mut out, &grant.room)?;
    put_str(&mut out, &grant.person)?;
    out.extend_from_slice(&grant.device.to_be_bytes());
    put_str(&mut out, &grant.media_server)?;
    out.extend_from_slice(&grant.not_after_ms.to_be_bytes());
    out.extend_from_slice(&grant.nonce);
    Ok(out)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn take(&mut self, len: usize) -> Result<&[u8], Error> {
        let part = self.bytes.get(self.at..self.at.checked_add(len).ok_or(Error::Malformed)?).ok_or(Error::Malformed)?;
        self.at += len;
        Ok(part)
    }

    fn u64(&mut self) -> Result<u64, Error> {
        let mut out = [0u8; 8];
        out.copy_from_slice(self.take(8)?);
        Ok(u64::from_be_bytes(out))
    }

    fn str(&mut self) -> Result<String, Error> {
        let high = self.take(1)?[0];
        let low = self.take(1)?[0];
        let len = usize::from(u16::from_be_bytes([high, low]));
        if len == 0 || len > MAX_NAME {
            return Err(Error::Malformed);
        }
        String::from_utf8(self.take(len)?.to_vec()).map_err(|_| Error::Malformed)
    }
}

/// Read a grant without checking its signature (`Verifier::verify` does both).
fn parse(bytes: &[u8]) -> Result<(Grant, usize), Error> {
    let mut reader = Reader { bytes, at: 0 };
    if reader.take(1)?[0] != VERSION {
        return Err(Error::Malformed);
    }
    let call = reader.u64()?;
    let room = reader.str()?;
    let person = reader.str()?;
    let device = reader.u64()?;
    let media_server = reader.str()?;
    let not_after_ms = reader.u64()?;
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(reader.take(16)?);
    let signed = reader.at;
    if bytes.len() != signed + SIGNATURE_LEN {
        return Err(Error::Malformed);
    }
    Ok((Grant { call, room, person, device, media_server, not_after_ms, nonce }, signed))
}

/// `N` random bytes from the operating system.
fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| Error::Unusable)?;
    Ok(out)
}

/// The chat server's side: signs credentials with its media key.
pub struct Issuer {
    key: SigningKey,
}

impl Issuer {
    /// A new media key, as PKCS#8 bytes (RFC 8410) for the caller to keep (owner-only, like the server's other keys).
    pub fn generate() -> Result<Vec<u8>, Error> {
        let seed = Zeroizing::new(random::<32>()?);
        let key = SigningKey::from_bytes(&seed);
        key.to_pkcs8_der().map(|doc| doc.as_bytes().to_vec()).map_err(|_| Error::Unusable)
    }

    /// The issuer for a media key made by `generate`.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, Error> {
        let key = SigningKey::from_pkcs8_der(pkcs8).map_err(|_| Error::Unusable)?;
        Ok(Self { key })
    }

    /// The public key media servers are configured to trust.
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// A credential for `person`'s `device` to join `call` of `room` on `media_server`, good for `LIFETIME_MS`.
    pub fn issue(&self, call: u64, room: &str, person: &str, device: u64, media_server: &str, now_ms: u64) -> Result<Vec<u8>, Error> {
        self.issue_until(call, room, person, device, media_server, (now_ms, now_ms.saturating_add(LIFETIME_MS)))
    }

    /// Issue within an additional authority deadline, preserving the staff credential format and expiry semantics.
    pub fn issue_until(&self, call: u64, room: &str, person: &str, device: u64, media_server: &str, validity: (u64, u64)) -> Result<Vec<u8>, Error> {
        let (now_ms, deadline) = validity;
        if deadline < now_ms { return Err(Error::Unusable); }
        let nonce = random::<16>()?;
        let grant = Grant {
            call,
            room: room.to_owned(),
            person: person.to_owned(),
            device,
            media_server: media_server.to_owned(),
            not_after_ms: now_ms.saturating_add(LIFETIME_MS).min(deadline),
            nonce,
        };
        let mut out = body(&grant)?;
        let signature = self.key.sign(&out);
        out.extend_from_slice(&signature.to_bytes());
        Ok(out)
    }
}

/// The media server's side: checks credentials against the chat server's public key, and accepts each only once.
pub struct Verifier {
    public_key: [u8; 32],
    server_name: String,
    /// Nonces already used, with their expiry, so a copied credential is refused; forgotten once expired.
    used: BTreeMap<[u8; 16], u64>,
}

impl Verifier {
    pub fn new(public_key: [u8; 32], server_name: &str) -> Self {
        Self { public_key, server_name: server_name.to_owned(), used: BTreeMap::new() }
    }

    /// Check `credential` at `now_ms` and, when it is good, use it up. Checks, in order: its shape, the signature, the
    /// expiry, the media server it names, and that it was not used before.
    pub fn verify(&mut self, credential: &[u8], now_ms: u64) -> Result<Grant, Error> {
        let (grant, signed) = parse(credential)?;
        // Strict verification: refuses non-canonical signatures and weak public keys, so a credential has one valid
        // signature and a copy cannot be disguised by re-encoding it.
        let key = VerifyingKey::from_bytes(&self.public_key).map_err(|_| Error::BadSignature)?;
        let signature = Signature::from_slice(&credential[signed..]).map_err(|_| Error::BadSignature)?;
        key.verify_strict(&credential[..signed], &signature).map_err(|_| Error::BadSignature)?;
        if now_ms > grant.not_after_ms {
            return Err(Error::Expired);
        }
        if grant.media_server != self.server_name {
            return Err(Error::WrongServer);
        }
        self.used.retain(|_, not_after| *not_after >= now_ms);
        if self.used.insert(grant.nonce, grant.not_after_ms).is_some() {
            return Err(Error::Replayed);
        }
        Ok(grant)
    }

    /// How many used credentials are still remembered (they are forgotten once they would have expired anyway).
    pub fn remembered(&self) -> usize {
        self.used.len()
    }
}
