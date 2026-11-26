//! Sealing a sender key to one participant (docs/CALLS.md "End-to-end encryption", task T360d1): each participant's
//! device has a call key pair; a sender seals its per-call base key to each admitted participant's public key, and
//! the chat server relays the sealed boxes without being able to open any of them.
//!
//! Owns: `CallKeyPair` (X25519, the secret wiped when dropped) and `seal` / `open`. The construction, for the
//! security reviewer: a fresh ephemeral X25519 key per box; `shared = X25519(ephemeral, recipient)`, refused when it
//! is all zeros (a low-order public key); `key = HKDF-SHA256(salt = ephemeral public || recipient public, ikm =
//! shared, info = "CrewCraft call key seal 1" || context)`, 32 bytes; AES-256-GCM with that key, a zero nonce (each
//! key seals exactly one box) and `context` as associated data. A box is `ephemeral public (32) | ciphertext | tag
//! (16)`. `context` names what the key is for (the call and the sender's key id), so a box cannot be replayed into
//! another call.

use curve25519_dalek::montgomery::MontgomeryPoint;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{HKDF_SHA256, KeyType, Salt};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use crate::{Error, TAG_LEN};

const INFO: &[u8] = b"CrewCraft call key seal 1";
/// The bytes a box adds to what it seals.
pub const OVERHEAD: usize = 32 + TAG_LEN;

/// A device's call key pair.
pub struct CallKeyPair {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl std::fmt::Debug for CallKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallKeyPair").field("public", &self.public).finish_non_exhaustive()
    }
}

fn random_secret() -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut secret = Zeroizing::new([0u8; 32]);
    SystemRandom::new().fill(&mut secret[..]).map_err(|_| Error::BadKey)?;
    Ok(secret)
}

impl CallKeyPair {
    /// A new key pair from the system's random source.
    pub fn generate() -> Result<Self, Error> {
        Ok(Self::from_secret(random_secret()?))
    }

    /// The key pair for a kept secret (32 bytes, as `secret` gives them).
    pub fn from_secret(secret: Zeroizing<[u8; 32]>) -> Self {
        let public = MontgomeryPoint::mul_base_clamped(*secret).to_bytes();
        Self { secret, public }
    }

    /// The secret, to keep in the device's protected store. Never log it.
    pub fn secret(&self) -> Zeroizing<[u8; 32]> {
        self.secret.clone()
    }

    /// The public key others seal to.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }
}

struct Len32;

impl KeyType for Len32 {
    fn len(&self) -> usize {
        32
    }
}

fn box_key(shared: &[u8; 32], ephemeral: &[u8; 32], recipient: &[u8; 32], context: &[u8]) -> Result<LessSafeKey, Error> {
    if shared.iter().all(|byte| *byte == 0) {
        return Err(Error::BadKey);
    }
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(ephemeral);
    salt.extend_from_slice(recipient);
    let prk = Salt::new(HKDF_SHA256, &salt).extract(shared);
    let mut key = Zeroizing::new([0u8; 32]);
    prk.expand(&[INFO, context], Len32).and_then(|okm| okm.fill(&mut key[..])).map_err(|_| Error::BadKey)?;
    Ok(LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key[..]).map_err(|_| Error::BadKey)?))
}

/// Seal `secret` (a sender's base key) to `recipient`'s public key, bound to `context`.
pub fn seal(recipient: &[u8; 32], context: &[u8], secret: &[u8]) -> Result<Vec<u8>, Error> {
    let ephemeral = random_secret()?;
    let ephemeral_public = MontgomeryPoint::mul_base_clamped(*ephemeral).to_bytes();
    let shared = Zeroizing::new(MontgomeryPoint(*recipient).mul_clamped(*ephemeral).to_bytes());
    let key = box_key(&shared, &ephemeral_public, recipient, context)?;
    let mut body = secret.to_vec();
    key.seal_in_place_append_tag(Nonce::assume_unique_for_key([0; 12]), Aad::from(context), &mut body).map_err(|_| Error::TooLarge)?;
    let mut out = ephemeral_public.to_vec();
    out.extend_from_slice(&body);
    Ok(out)
}

/// Open a box sealed to `pair` with `context`. `Authentication` for a box sealed to someone else, for another
/// context, or changed on the way.
pub fn open(pair: &CallKeyPair, context: &[u8], sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if sealed.len() < OVERHEAD {
        return Err(Error::Truncated);
    }
    let mut ephemeral = [0u8; 32];
    ephemeral.copy_from_slice(&sealed[..32]);
    let shared = Zeroizing::new(MontgomeryPoint(ephemeral).mul_clamped(*pair.secret).to_bytes());
    let key = box_key(&shared, &ephemeral, &pair.public, context).map_err(|_| Error::Authentication)?;
    let mut body = Zeroizing::new(sealed[32..].to_vec());
    let plain = key.open_in_place(Nonce::assume_unique_for_key([0; 12]), Aad::from(context), &mut body).map_err(|_| Error::Authentication)?;
    Ok(Zeroizing::new(plain.to_vec()))
}
