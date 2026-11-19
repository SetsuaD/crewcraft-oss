//! The APK container, in Rust: a zip laid out the way Android installs it, signed with APK Signature Scheme v2.
//! Task T400.
//!
//! Layout. Entries are written in the order given, with no folder entries. An entry is either deflated or stored;
//! a stored entry starts at a multiple of its alignment, padded with the alignment extra field (ID `0xd935`, the
//! one Android's own tools write): 4 bytes for `resources.arsc` and images, 16 KiB for native libraries, which
//! Android maps straight from the APK (`extractNativeLibs="false"`) on phones with 4 KiB or 16 KiB pages. That is
//! what `zipalign -p 4` does (with 16 KiB instead of 4 KiB pages), so no zipalign pass is needed.
//!
//! Signing. The v2 scheme (Android 7 and later, so every phone CrewCraft supports, API 29+) puts an APK Signing Block
//! between the entries and the central directory. It holds one signer: the SHA-256 chunk digest of the entries, the
//! central directory and the end record, the certificate, and an ECDSA P-256 signature (`ring`) over those. No v1
//! (JAR) signature is written: Android 7 and later do not need one. [`verify_v2`] checks a signed APK the way the
//! platform does (digest, signature, certificate matches the key) and `cargo xtask apk` runs it on every APK it
//! writes; `apksigner verify` from the Android build-tools is an independent check (docs/RELEASE.md).
//!
//! Called by: `android` (`cargo xtask apk`). Calls: `flate2`, `sha2`, `ring`, `rcgen` (the test key's certificate)
//! and `x509-parser` (reading a certificate's key).

use std::collections::BTreeSet;
use std::io::Write;

use flate2::write::DeflateEncoder;
use flate2::{Compression, Crc};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair, UnparsedPublicKey};
use sha2::{Digest, Sha256};

use crate::archive::dos_date_time;
use crate::{Error, Result};

/// Where a stored native library starts: a multiple of 16 KiB, which serves 4 KiB and 16 KiB page sizes.
pub const LIBRARY_ALIGN: u16 = 16384;
/// Where other stored entries start (`resources.arsc` must be 4-byte aligned on Android 11 and later).
pub const STORED_ALIGN: u16 = 4;
/// The zip extra field Android's tools use to pad an entry to its alignment.
pub const ALIGNMENT_EXTRA_ID: u16 = 0xd935;
/// The ID of the APK Signature Scheme v2 block in the APK Signing Block.
pub const V2_BLOCK_ID: u32 = 0x7109_871a;
/// The v2 signature algorithm ID for ECDSA with SHA-256.
pub const ECDSA_SHA256: u32 = 0x0201;
/// The magic at the end of an APK Signing Block.
pub const SIGNING_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
/// The size of the pieces the v2 digest hashes one by one.
pub const CHUNK: usize = 1 << 20;

/// How an entry is put in the APK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Storage {
    Deflated,
    /// Uncompressed, starting at a multiple of `align` bytes.
    Stored {
        align: u16,
    },
}

/// One file in the APK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApkEntry {
    /// The path inside the APK, `/`-separated, relative, plain ASCII.
    pub path: String,
    pub data: Vec<u8>,
    pub storage: Storage,
}

impl ApkEntry {
    pub fn new(path: impl Into<String>, data: impl Into<Vec<u8>>, storage: Storage) -> Self {
        Self { path: path.into(), data: data.into(), storage }
    }
}

/// An APK before signing, in the three parts the v2 digest covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unsigned {
    /// The local headers and contents of every entry.
    pub entries: Vec<u8>,
    pub central_directory: Vec<u8>,
    /// The end of central directory record, pointing at the central directory right after `entries`.
    pub end_record: Vec<u8>,
}

impl Unsigned {
    /// The unsigned APK as one file (for a signer outside xtask, such as `apksigner` with a keystore).
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.entries.as_slice(), &self.central_directory, &self.end_record].concat()
    }
}

fn check_path(path: &str) -> Result<()> {
    let bad = path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.split('/').any(|part| part.is_empty() || part == "." || part == "..")
        || !path.bytes().all(|b| b.is_ascii_graphic() && b != b'\\');
    if bad { Err(Error::new(format!("APK path {path:?} must be relative, plain ASCII and without empty, . or .. parts"))) } else { Ok(()) }
}

fn u32_of(len: usize, what: &str) -> Result<u32> {
    u32::try_from(len).map_err(|_| Error::new(format!("{what} is too large for an APK without zip64")))
}

/// Writes the entries, in order, into an unsigned APK whose entries carry the time `mtime`.
pub fn zip(entries: &[ApkEntry], mtime: u64) -> Result<Unsigned> {
    let (date, time) = dos_date_time(mtime);
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut count: u16 = 0;
    for entry in entries {
        check_path(&entry.path)?;
        if !seen.insert(entry.path.as_str()) {
            return Err(Error::new(format!("APK path {:?} is listed twice", entry.path)));
        }
        let mut crc = Crc::new();
        crc.update(&entry.data);
        let (method, body) = match entry.storage {
            Storage::Deflated => {
                let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
                encoder.write_all(&entry.data)?;
                (8u16, encoder.finish()?)
            }
            Storage::Stored { .. } => (0u16, entry.data.clone()),
        };
        let name = entry.path.as_bytes();
        let name_len = u16::try_from(name.len()).map_err(|_| Error::new(format!("APK path {:?} is too long", entry.path)))?;
        let offset = out.len();
        let mut extra = Vec::new();
        if let Storage::Stored { align } = entry.storage {
            if align == 0 {
                return Err(Error::new(format!("APK entry {:?}: an alignment of 0", entry.path)));
            }
            let align = usize::from(align);
            let unpadded = offset + 30 + name.len() + 6;
            let padding = (align - unpadded % align) % align;
            let size = u16::try_from(2 + padding).map_err(|_| Error::new("alignment padding too large"))?;
            extra.extend_from_slice(&ALIGNMENT_EXTRA_ID.to_le_bytes());
            extra.extend_from_slice(&size.to_le_bytes());
            extra.extend_from_slice(&u16::try_from(align).map_err(|_| Error::new("alignment too large"))?.to_le_bytes());
            extra.resize(6 + padding, 0);
        }
        let extra_len = u16::try_from(extra.len()).map_err(|_| Error::new("extra field too large"))?;
        let mut fixed = Vec::with_capacity(26);
        fixed.extend_from_slice(&if method == 0 { 10u16 } else { 20u16 }.to_le_bytes());
        fixed.extend_from_slice(&0u16.to_le_bytes());
        fixed.extend_from_slice(&method.to_le_bytes());
        fixed.extend_from_slice(&time.to_le_bytes());
        fixed.extend_from_slice(&date.to_le_bytes());
        fixed.extend_from_slice(&crc.sum().to_le_bytes());
        fixed.extend_from_slice(&u32_of(body.len(), &entry.path)?.to_le_bytes());
        fixed.extend_from_slice(&u32_of(entry.data.len(), &entry.path)?.to_le_bytes());
        fixed.extend_from_slice(&name_len.to_le_bytes());

        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&fixed);
        out.extend_from_slice(&extra_len.to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&extra);
        out.extend_from_slice(&body);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes()); // made by: MS-DOS, spec 2.0
        central.extend_from_slice(&fixed);
        central.extend_from_slice(&0u16.to_le_bytes()); // extra length
        central.extend_from_slice(&0u16.to_le_bytes()); // comment length
        central.extend_from_slice(&0u16.to_le_bytes()); // disk number
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        central.extend_from_slice(&0u32.to_le_bytes()); // external attributes
        central.extend_from_slice(&u32_of(offset, "the APK")?.to_le_bytes());
        central.extend_from_slice(name);
        count = count.checked_add(1).ok_or_else(|| Error::new("too many APK entries"))?;
    }
    let end_record = end_record(count, u32_of(central.len(), "the zip directory")?, u32_of(out.len(), "the APK")?);
    Ok(Unsigned { entries: out, central_directory: central, end_record })
}

fn end_record(count: u16, central_size: u32, central_offset: u32) -> Vec<u8> {
    let mut end = Vec::with_capacity(22);
    end.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    end.extend_from_slice(&0u16.to_le_bytes());
    end.extend_from_slice(&0u16.to_le_bytes());
    end.extend_from_slice(&count.to_le_bytes());
    end.extend_from_slice(&count.to_le_bytes());
    end.extend_from_slice(&central_size.to_le_bytes());
    end.extend_from_slice(&central_offset.to_le_bytes());
    end.extend_from_slice(&0u16.to_le_bytes());
    end
}

/// The v2 content digest of `sections` (the entries, the central directory, and the end record pointing at the
/// signing block): SHA-256 over `0x5a`, the chunk count and each 1 MiB chunk's digest, where a chunk's digest is
/// SHA-256 over `0xa5`, its length and its bytes.
pub fn v2_digest(sections: &[&[u8]]) -> Result<[u8; 32]> {
    let mut digests = Vec::new();
    let mut count: u32 = 0;
    for section in sections {
        for chunk in section.chunks(CHUNK) {
            let mut hash = Sha256::new();
            hash.update([0xa5]);
            hash.update(u32_of(chunk.len(), "a chunk")?.to_le_bytes());
            hash.update(chunk);
            digests.extend_from_slice(&hash.finalize());
            count = count.checked_add(1).ok_or_else(|| Error::new("too many chunks"))?;
        }
    }
    let mut top = Sha256::new();
    top.update([0x5a]);
    top.update(count.to_le_bytes());
    top.update(&digests);
    Ok(top.finalize().into())
}

/// A signing key: an ECDSA P-256 private key and its X.509 certificate.
pub struct SigningKey {
    pkcs8: Vec<u8>,
    pair: EcdsaKeyPair,
    certificate: Vec<u8>,
    spki: Vec<u8>,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey").field("certificate_bytes", &self.certificate.len()).finish_non_exhaustive()
    }
}

/// The SubjectPublicKeyInfo and the public key bytes in a DER certificate.
fn certificate_key(certificate: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let (rest, parsed) =
        x509_parser::parse_x509_certificate(certificate).map_err(|error| Error::new(format!("reading the signing certificate: {error}")))?;
    if !rest.is_empty() {
        return Err(Error::new("the signing certificate has trailing bytes"));
    }
    let spki = &parsed.tbs_certificate.subject_pki;
    Ok((spki.raw.to_vec(), spki.subject_public_key.data.to_vec()))
}

impl SigningKey {
    /// A new key with a self-signed certificate naming `common_name`. Each call makes a different key.
    pub fn generate(common_name: &str) -> Result<SigningKey> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|error| Error::new(format!("generating a key: {error}")))?;
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).map_err(|error| Error::new(format!("certificate: {error}")))?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
        let certificate = params.self_signed(&key).map_err(|error| Error::new(format!("signing the certificate: {error}")))?;
        SigningKey::from_parts(&key.serialize_der(), certificate.der())
    }

    /// The key in `pkcs8` (DER) with its `certificate` (DER), which must hold the same public key.
    pub fn from_parts(pkcs8: &[u8], certificate: &[u8]) -> Result<SigningKey> {
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &SystemRandom::new())
            .map_err(|_| Error::new("the signing key is not an ECDSA P-256 PKCS#8 key"))?;
        let (spki, public) = certificate_key(certificate)?;
        if public != pair.public_key().as_ref() {
            return Err(Error::new("the signing certificate is not for the signing key"));
        }
        Ok(SigningKey { pkcs8: pkcs8.to_vec(), pair, certificate: certificate.to_vec(), spki })
    }

    /// The private key as PKCS#8 DER, to keep it for the next build.
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The certificate (DER).
    pub fn certificate(&self) -> &[u8] {
        &self.certificate
    }
}

/// `data` with its length in front, as a 32-bit little-endian number.
fn prefixed(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = u32_of(data.len(), "a signing block field")?.to_le_bytes().to_vec();
    out.extend_from_slice(data);
    Ok(out)
}

/// Signs `apk` with `key` and returns the signed APK: the entries, the APK Signing Block with one v2 signer, the
/// central directory, and the end record moved to point past the signing block.
pub fn sign_v2(apk: &Unsigned, key: &SigningKey) -> Result<Vec<u8>> {
    let digest = v2_digest(&[&apk.entries, &apk.central_directory, &apk.end_record])?;
    let mut algorithm_digest = ECDSA_SHA256.to_le_bytes().to_vec();
    algorithm_digest.extend(prefixed(&digest)?);
    let mut signed_data = prefixed(&prefixed(&algorithm_digest)?)?;
    signed_data.extend(prefixed(&prefixed(&key.certificate)?)?);
    signed_data.extend(prefixed(&[])?);
    let signature = key.pair.sign(&SystemRandom::new(), &signed_data).map_err(|_| Error::new("signing the APK failed"))?;
    let mut algorithm_signature = ECDSA_SHA256.to_le_bytes().to_vec();
    algorithm_signature.extend(prefixed(signature.as_ref())?);
    let mut signer = prefixed(&signed_data)?;
    signer.extend(prefixed(&prefixed(&algorithm_signature)?)?);
    signer.extend(prefixed(&key.spki)?);
    let value = prefixed(&prefixed(&signer)?)?;

    let pair_len = u64::try_from(4 + value.len()).map_err(|_| Error::new("signing block too large"))?;
    let mut pairs = pair_len.to_le_bytes().to_vec();
    pairs.extend_from_slice(&V2_BLOCK_ID.to_le_bytes());
    pairs.extend_from_slice(&value);
    let block_size = u64::try_from(pairs.len() + 8 + 16).map_err(|_| Error::new("signing block too large"))?;
    let mut block = block_size.to_le_bytes().to_vec();
    block.extend_from_slice(&pairs);
    block.extend_from_slice(&block_size.to_le_bytes());
    block.extend_from_slice(SIGNING_BLOCK_MAGIC);

    let central_offset = u32_of(apk.entries.len() + block.len(), "the APK")?;
    let mut end = apk.end_record.clone();
    end[16..20].copy_from_slice(&central_offset.to_le_bytes());
    Ok([apk.entries.as_slice(), &block, &apk.central_directory, &end].concat())
}

/// Reads a little-endian number of `N` bytes at `at`.
fn le<const N: usize>(data: &[u8], at: usize) -> Result<[u8; N]> {
    data.get(at..at.checked_add(N).ok_or_else(|| Error::new("APK offset overflow"))?)
        .and_then(|bytes| <[u8; N]>::try_from(bytes).ok())
        .ok_or_else(|| Error::new("the APK is truncated"))
}

/// Splits a length-prefixed field off the front of `data`.
fn take_prefixed(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let len = u32::from_le_bytes(le::<4>(data, 0)?) as usize;
    let end = 4usize.checked_add(len).filter(|end| *end <= data.len()).ok_or_else(|| Error::new("a signing block field overruns"))?;
    Ok((&data[4..end], &data[end..]))
}

/// Checks the v2 signature of `apk` the way Android does, and returns the signer's certificate (DER). Fails on a
/// missing signing block, more than one signer, a digest that does not match the contents, a bad signature, or a
/// certificate whose key is not the signing key.
pub fn verify_v2(apk: &[u8]) -> Result<Vec<u8>> {
    if apk.len() < 22 {
        return Err(Error::new("too short to be an APK"));
    }
    let end_at = apk.len() - 22;
    if le::<4>(apk, end_at)? != 0x0605_4b50u32.to_le_bytes() {
        return Err(Error::new("no end of central directory record at the end (a zip comment is not expected)"));
    }
    let central_offset = u32::from_le_bytes(le::<4>(apk, end_at + 16)?) as usize;
    if central_offset < 32 || central_offset > end_at || apk.get(central_offset - 16..central_offset) != Some(SIGNING_BLOCK_MAGIC.as_slice()) {
        return Err(Error::new("no APK Signing Block before the central directory"));
    }
    let size = usize::try_from(u64::from_le_bytes(le::<8>(apk, central_offset - 24)?)).map_err(|_| Error::new("signing block size"))?;
    let block_at = central_offset.checked_sub(size).and_then(|at| at.checked_sub(8)).ok_or_else(|| Error::new("signing block size overruns"))?;
    if u64::from_le_bytes(le::<8>(apk, block_at)?) as usize != size {
        return Err(Error::new("the signing block's two sizes differ"));
    }
    let mut pairs = &apk[block_at + 8..central_offset - 24];
    let mut v2 = None;
    while !pairs.is_empty() {
        let len = usize::try_from(u64::from_le_bytes(le::<8>(pairs, 0)?)).map_err(|_| Error::new("signing block pair size"))?;
        let pair = pairs.get(8..8usize.checked_add(len).ok_or_else(|| Error::new("pair overruns"))?).ok_or_else(|| Error::new("pair overruns"))?;
        if u32::from_le_bytes(le::<4>(pair, 0)?) == V2_BLOCK_ID {
            v2 = Some(&pair[4..]);
        }
        pairs = &pairs[8 + len..];
    }
    let v2 = v2.ok_or_else(|| Error::new("the signing block has no v2 signature"))?;
    let (signers, rest) = take_prefixed(v2)?;
    let (signer, others) = take_prefixed(signers)?;
    if !rest.is_empty() || !others.is_empty() {
        return Err(Error::new("expected exactly one v2 signer"));
    }
    let (signed_data, rest) = take_prefixed(signer)?;
    let (signatures, rest) = take_prefixed(rest)?;
    let (spki, rest) = take_prefixed(rest)?;
    if !rest.is_empty() {
        return Err(Error::new("unexpected bytes after the v2 signer's public key"));
    }
    let (algorithm_signature, more) = take_prefixed(signatures)?;
    if !more.is_empty() || u32::from_le_bytes(le::<4>(algorithm_signature, 0)?) != ECDSA_SHA256 {
        return Err(Error::new("expected one ECDSA SHA-256 signature"));
    }
    let (signature, rest) = take_prefixed(&algorithm_signature[4..])?;
    if !rest.is_empty() {
        return Err(Error::new("unexpected bytes after the signature"));
    }
    let (digests, rest) = take_prefixed(signed_data)?;
    let (certificates, _attributes) = take_prefixed(rest)?;
    let (certificate, _) = take_prefixed(certificates)?;
    let (cert_spki, public) = certificate_key(certificate)?;
    if cert_spki != spki {
        return Err(Error::new("the v2 signer's public key is not its certificate's"));
    }
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public)
        .verify(signed_data, signature)
        .map_err(|_| Error::new("the v2 signature does not verify"))?;
    let (algorithm_digest, more) = take_prefixed(digests)?;
    if !more.is_empty() || u32::from_le_bytes(le::<4>(algorithm_digest, 0)?) != ECDSA_SHA256 {
        return Err(Error::new("expected one ECDSA SHA-256 digest"));
    }
    let (signed_digest, _) = take_prefixed(&algorithm_digest[4..])?;
    let mut end = apk[end_at..].to_vec();
    end[16..20].copy_from_slice(&u32_of(block_at, "the APK")?.to_le_bytes());
    let digest = v2_digest(&[&apk[..block_at], &apk[central_offset..end_at], &end])?;
    if signed_digest != digest {
        return Err(Error::new("the APK's contents do not match its v2 digest"));
    }
    Ok(certificate.to_vec())
}
