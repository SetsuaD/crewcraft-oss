//! SRTP's ciphers for str0m (task T362a). str0m does the SRTP framing, key derivation and HMAC itself; it asks the
//! provider only for the block cipher steps:
//!
//! - AES_CM_128_HMAC_SHA1_80 (RFC 3711): AES-128 in counter mode, the 16-byte counter block given;
//! - AEAD_AES_128_GCM and AEAD_AES_256_GCM (RFC 7714): AES-GCM, the 16-byte tag after the ciphertext;
//! - one AES-128 or AES-256 block encryption, for the key derivation of RFC 3711 section 4.3.
//!
//! Keys are wiped when a cipher is dropped (`zeroize`).

use aes::cipher::{BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher};
use aes_gcm::aead::AeadInOut;
use str0m_proto::crypto::{AeadAes128GcmCipher, AeadAes256GcmCipher, Aes128CmSha1_80Cipher, CryptoError, SrtpProvider};
use str0m_proto::crypto::{SupportedAeadAes128Gcm, SupportedAeadAes256Gcm, SupportedAes128CmSha1_80};
use zeroize::Zeroizing;

/// The SRTP provider.
#[derive(Debug)]
pub struct Srtp;

impl SrtpProvider for Srtp {
    fn aes_128_cm_sha1_80(&self) -> &'static dyn SupportedAes128CmSha1_80 {
        &CounterMode
    }

    fn aead_aes_128_gcm(&self) -> &'static dyn SupportedAeadAes128Gcm {
        &Gcm128
    }

    fn aead_aes_256_gcm(&self) -> &'static dyn SupportedAeadAes256Gcm {
        &Gcm256
    }

    fn srtp_aes_128_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        match aes::Aes128::new_from_slice(key) {
            Ok(cipher) => encrypt_blocks(&cipher, input, output),
            // str0m always passes a 16-byte key; any other leaves no key material behind.
            Err(_) => output.fill(0),
        }
    }

    fn srtp_aes_256_ecb_round(&self, key: &[u8], input: &[u8], output: &mut [u8]) {
        match aes::Aes256::new_from_slice(key) {
            Ok(cipher) => encrypt_blocks(&cipher, input, output),
            Err(_) => output.fill(0),
        }
    }
}

/// Encrypt each whole 16-byte block of `input` into `output`, one block at a time (ECB). str0m derives SRTP's session
/// keys this way; `output` may be longer than `input`, and its extra bytes are left alone.
fn encrypt_blocks(cipher: &impl BlockCipherEncrypt<BlockSize = aes::cipher::consts::U16>, input: &[u8], output: &mut [u8]) {
    for (from, to) in input.chunks_exact(16).zip(output.chunks_exact_mut(16)) {
        let mut block = aes::Block::default();
        block.copy_from_slice(from);
        cipher.encrypt_block(&mut block);
        to.copy_from_slice(&block);
    }
}

/// AES_CM_128_HMAC_SHA1_80's cipher factory.
#[derive(Debug)]
struct CounterMode;

impl SupportedAes128CmSha1_80 for CounterMode {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn Aes128CmSha1_80Cipher> {
        Box::new(CounterModeCipher { key: Zeroizing::new(key) })
    }
}

/// AES-128 in counter mode; encrypting and decrypting are the same keystream.
struct CounterModeCipher {
    key: Zeroizing<[u8; 16]>,
}

impl std::fmt::Debug for CounterModeCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CounterModeCipher")
    }
}

impl CounterModeCipher {
    fn apply(&self, iv: &[u8; 16], input: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        let out = output.get_mut(..input.len()).ok_or_else(|| CryptoError::Other("SRTP output buffer too small".into()))?;
        out.copy_from_slice(input);
        let mut stream = ctr::Ctr128BE::<aes::Aes128>::new(&(*self.key).into(), iv.into());
        stream.apply_keystream(out);
        Ok(())
    }
}

impl Aes128CmSha1_80Cipher for CounterModeCipher {
    fn encrypt(&mut self, iv: &[u8; 16], input: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        self.apply(iv, input, output)
    }

    fn decrypt(&mut self, iv: &[u8; 16], input: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        self.apply(iv, input, output)
    }
}

/// AEAD_AES_128_GCM's cipher factory.
#[derive(Debug)]
struct Gcm128;

impl SupportedAeadAes128Gcm for Gcm128 {
    fn create_cipher(&self, key: [u8; 16], _encrypt: bool) -> Box<dyn AeadAes128GcmCipher> {
        let key = Zeroizing::new(key);
        Box::new(GcmCipher(aes_gcm::Aes128Gcm::new(&(*key).into())))
    }
}

/// AEAD_AES_256_GCM's cipher factory.
#[derive(Debug)]
struct Gcm256;

impl SupportedAeadAes256Gcm for Gcm256 {
    fn create_cipher(&self, key: [u8; 32], _encrypt: bool) -> Box<dyn AeadAes256GcmCipher> {
        let key = Zeroizing::new(key);
        Box::new(GcmCipher(aes_gcm::Aes256Gcm::new(&(*key).into())))
    }
}

/// The length of an AES-GCM tag, which follows the ciphertext.
const TAG_LEN: usize = 16;

/// AES-GCM with either key size.
struct GcmCipher<C>(C);

impl<C> std::fmt::Debug for GcmCipher<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GcmCipher")
    }
}

impl<C: AeadInOut<NonceSize = aes::cipher::consts::U12, TagSize = aes::cipher::consts::U16>> GcmCipher<C> {
    /// `input` encrypted into `output`, the tag after it.
    fn seal(&self, iv: &[u8; 12], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        let out = output.get_mut(..input.len() + TAG_LEN).ok_or_else(|| CryptoError::Other("SRTP output buffer too small".into()))?;
        let (body, tag_out) = out.split_at_mut(input.len());
        body.copy_from_slice(input);
        let tag =
            self.0.encrypt_inout_detached(&(*iv).into(), aad, body.into()).map_err(|_| CryptoError::Other("AES-GCM encryption failed".into()))?;
        tag_out.copy_from_slice(&tag);
        Ok(())
    }

    /// `input` (ciphertext then tag) checked and decrypted into `output`; the plaintext's length. The associated data
    /// is the pieces in `aads` one after another.
    fn open(&self, iv: &[u8; 12], aads: &[&[u8]], input: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        let body_len = input.len().checked_sub(TAG_LEN).ok_or_else(|| CryptoError::Other("SRTP packet shorter than its tag".into()))?;
        let (body, tag) = input.split_at(body_len);
        let out = output.get_mut(..body_len).ok_or_else(|| CryptoError::Other("SRTP output buffer too small".into()))?;
        out.copy_from_slice(body);
        let joined;
        let aad = match aads {
            [one] => *one,
            many => {
                joined = many.concat();
                &joined
            }
        };
        let tag = aes_gcm::Tag::try_from(tag).map_err(|_| CryptoError::Other("SRTP tag length".into()))?;
        match self.0.decrypt_inout_detached(&(*iv).into(), aad, (&mut *out).into(), &tag) {
            Ok(()) => Ok(body_len),
            Err(_) => {
                // A packet that fails authentication leaves nothing of itself behind.
                out.fill(0);
                Err(CryptoError::Other("SRTP packet failed authentication".into()))
            }
        }
    }
}

impl AeadAes128GcmCipher for GcmCipher<aes_gcm::Aes128Gcm> {
    fn encrypt(&mut self, iv: &[u8; 12], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        self.seal(iv, aad, input, output)
    }

    fn decrypt(&mut self, iv: &[u8; 12], aads: &[&[u8]], input: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        self.open(iv, aads, input, output)
    }
}

impl AeadAes256GcmCipher for GcmCipher<aes_gcm::Aes256Gcm> {
    fn encrypt(&mut self, iv: &[u8; 12], aad: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), CryptoError> {
        self.seal(iv, aad, input, output)
    }

    fn decrypt(&mut self, iv: &[u8; 12], aads: &[&[u8]], input: &[u8], output: &mut [u8]) -> Result<usize, CryptoError> {
        self.open(iv, aads, input, output)
    }
}
