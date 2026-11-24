//! T503: signing a release with a key held on a hardware security key (a YubiKey or similar): `release sign --signer
//! <program> --public <hex>` takes the signature the owner's signer prints, only if it verifies, and `release public
//! --pem` turns the device's exported public key into the hex that is pinned. No hardware is needed: the "device" here
//! is a test key, and on Unix a small shell script plays the signer.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use xtask::release::{self, Command, ManifestOptions};
use xtask::version::Version;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("crewcraft-t503-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|arg| (*arg).to_owned()).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut block = [0u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let bits = u32::from_be_bytes([0, block[0], block[1], block[2]]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((bits >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The device's key: RFC 8032 test 1's seed, so its public half is a published value.
fn device() -> SigningKey {
    let seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let bytes: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&seed[2 * i..2 * i + 2], 16).unwrap()).collect();
    SigningKey::from_bytes(&bytes.try_into().unwrap())
}

const DEVICE_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// A manifest for a fake 0.2.0 Linux server package, written to `dir`.
fn manifest(dir: &Path) -> (PathBuf, Vec<u8>) {
    fs::write(dir.join("crewcraft-server-0.2.0-linux-x86_64.tar.gz"), b"server archive").unwrap();
    let out = dir.join("release.toml");
    let options = ManifestOptions {
        version: Version::parse("0.2.0").unwrap(),
        channel: "beta".to_owned(),
        published: "2026-12-31".to_owned(),
        min_client: Version::parse("0.1.0").unwrap(),
        dir: dir.to_path_buf(),
        out: out.clone(),
    };
    release::run(&Command::Manifest(options)).unwrap();
    let bytes = fs::read(&out).unwrap();
    (out, bytes)
}

#[test]
fn the_command_line_is_checked() {
    assert_eq!(
        release::parse_args(&args(&["sign", "--manifest", "m", "--signer", "s", "--public", "aa", "--out", "o"])).unwrap(),
        Command::SignWith { manifest: "m".into(), signer: "s".into(), public: "aa".to_owned(), out: "o".into() }
    );
    assert_eq!(release::parse_args(&args(&["public", "--pem", "p.pem"])).unwrap(), Command::PublicPem { pem: "p.pem".into() });
    assert_eq!(release::parse_args(&args(&["public", "--key", "k"])).unwrap(), Command::Public { key: "k".into() });
    for bad in [
        &["sign", "--manifest", "m", "--signer", "s", "--out", "o"][..],
        &["sign", "--manifest", "m", "--key", "k", "--signer", "s", "--public", "aa", "--out", "o"],
        &["sign", "--manifest", "m", "--key", "k", "--public", "aa", "--out", "o"],
        &["sign", "--manifest", "m", "--out", "o"],
        &["public", "--key", "k", "--pem", "p"],
        &["public"],
    ] {
        assert!(release::parse_args(&args(bad)).is_err(), "{bad:?}");
    }
}

#[test]
fn a_device_public_key_in_pem_gives_the_pinned_hex() {
    assert_eq!(hex(device().verifying_key().as_bytes()), DEVICE_PUBLIC);
    let mut der = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    der.extend_from_slice(device().verifying_key().as_bytes());
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", base64(&der));
    assert_eq!(release::public_key_from_pem(&pem).unwrap(), DEVICE_PUBLIC);
    assert_eq!(release::public_key_from_pem(&pem.replace('\n', "\r\n")).unwrap(), DEVICE_PUBLIC, "Windows line ends");

    // Not a public key, broken base64, or another algorithm (here an X25519 key's identifier): refused.
    assert!(release::public_key_from_pem("-----BEGIN CERTIFICATE-----\nMC4=\n-----END CERTIFICATE-----").is_err());
    assert!(release::public_key_from_pem("-----BEGIN PUBLIC KEY-----\nMCow*QYDK2VwAyEA\n-----END PUBLIC KEY-----").is_err());
    let mut x25519 = der.clone();
    x25519[8] = 0x6e;
    let other = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", base64(&x25519));
    assert!(release::public_key_from_pem(&other).is_err());
}

#[test]
fn only_a_signature_that_verifies_is_taken() {
    let scratch = Scratch::new("take");
    let (_, bytes) = manifest(&scratch.0);
    let signature = device().sign(&bytes).to_bytes();

    // Raw bytes, or hex with a line end: both are taken, as the same 64 bytes.
    assert_eq!(release::sign_with(&bytes, &signature, DEVICE_PUBLIC).unwrap(), signature);
    let printed = format!("{}\n", hex(&signature));
    assert_eq!(release::sign_with(&bytes, printed.as_bytes(), DEVICE_PUBLIC).unwrap(), signature);

    // Another key's signature, the wrong --public, a signature over other bytes, a short one, and an invalid manifest.
    let other = SigningKey::from_bytes(&[7u8; 32]);
    assert!(release::sign_with(&bytes, &other.sign(&bytes).to_bytes(), DEVICE_PUBLIC).is_err());
    assert!(release::sign_with(&bytes, &signature, &hex(other.verifying_key().as_bytes())).is_err());
    assert!(release::sign_with(&bytes, &device().sign(b"something else").to_bytes(), DEVICE_PUBLIC).is_err());
    assert!(release::sign_with(&bytes, &signature[..63], DEVICE_PUBLIC).is_err());
    assert!(release::sign_with(&bytes, b"not a signature\n", DEVICE_PUBLIC).is_err());
    assert!(release::sign_with(&bytes, &signature, "not hex").is_err());
    let invalid = b"[release]\nproduct = \"crewcraft\"\n";
    assert!(release::sign_with(invalid, &device().sign(invalid).to_bytes(), DEVICE_PUBLIC).is_err());
}

#[cfg(unix)]
fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[cfg(unix)]
#[test]
fn a_signer_program_signs_and_the_result_verifies() {
    let scratch = Scratch::new("signer");
    let (manifest, bytes) = manifest(&scratch.0);
    // The "device": prints the signature in hex, as a wrapper around a hardware key's tool would, but only when it is
    // given the manifest's path.
    let printed = scratch.0.join("device-output.txt");
    fs::write(&printed, format!("{}\n", hex(&device().sign(&bytes).to_bytes()))).unwrap();
    let signer = script(&scratch.0, "signer.sh", &format!("[ \"$1\" = '{}' ] || exit 3\ncat '{}'", manifest.display(), printed.display()));
    let out = scratch.0.join("release.toml.sig");
    let sign = |out: &Path, signer: &Path, public: &str| {
        release::run(&Command::SignWith {
            manifest: manifest.clone(),
            signer: signer.to_path_buf(),
            public: public.to_owned(),
            out: out.to_path_buf(),
        })
    };
    sign(&out, &signer, DEVICE_PUBLIC).unwrap();
    assert_eq!(fs::read(&out).unwrap().len(), 64);
    release::verify(&manifest, &out, &[DEVICE_PUBLIC.to_owned()], Some(&scratch.0)).unwrap();

    // The file is never overwritten; a signer that fails, prints nothing, or is missing writes nothing.
    assert!(sign(&out, &signer, DEVICE_PUBLIC).is_err(), "the signature file exists");
    let failed = scratch.0.join("failed.sig");
    assert!(sign(&failed, &script(&scratch.0, "fails.sh", "echo 'PIN refused' >&2\nexit 1"), DEVICE_PUBLIC).is_err());
    assert!(sign(&failed, &script(&scratch.0, "silent.sh", "exit 0"), DEVICE_PUBLIC).is_err());
    assert!(sign(&failed, &scratch.0.join("no-such-signer"), DEVICE_PUBLIC).is_err());
    // A signature that verifies with a different key than --public names is refused.
    assert!(sign(&failed, &signer, &hex(SigningKey::from_bytes(&[7u8; 32]).verifying_key().as_bytes())).is_err());
    assert!(!failed.exists());
}
