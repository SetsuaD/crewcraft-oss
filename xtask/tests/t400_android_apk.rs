//! T400: the Android APK. Checks the pure parts of `cargo xtask apk` without the Android SDK: the version code, the
//! manifest, the launcher icons, the APK's zip layout and alignment, and its APK Signature Scheme v2 signature. The
//! zip and the signing block are read back with readers written for this test, and the v2 digest is computed here
//! independently from the scheme's definition; the signature is checked with ring and the certificate's key.
//! Synthetic data only; the signing key is made when the test runs.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::Read;

use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use sha2::{Digest, Sha256};
use xtask::android::{self, Abi};
use xtask::apk::{self, ApkEntry, SigningKey, Storage};
use xtask::version::Version;

/// 2026-01-01T00:00:00Z.
const MTIME: u64 = 1_767_225_600;
const SVG: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../assets/icon/crewcraft.svg"));

fn version(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn u16_at(data: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([data[at], data[at + 1]])
}

fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

fn u64_at(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

#[test]
fn version_codes_grow_with_every_release() {
    assert_eq!(version("0.1.0-beta.1").android_version_code().unwrap(), 100_201);
    assert_eq!(version("1.2.3").android_version_code().unwrap(), 10_203_900);
    assert_eq!(version("209.99.64").android_version_code().unwrap(), 2_099_964_900);
    let ordered = ["0.1.0-alpha.1", "0.1.0-alpha.12", "0.1.0-beta.1", "0.1.0-rc.2", "0.1.0", "0.1.1-beta.1", "0.1.1", "0.2.0", "1.0.0", "1.99.64"];
    let codes: Vec<u32> = ordered.iter().map(|text| version(text).android_version_code().unwrap()).collect();
    assert!(codes.windows(2).all(|pair| pair[0] < pair[1]), "{codes:?}");
    assert!(version("0.100.0").android_version_code().is_err());
    assert!(version("210.0.0").android_version_code().is_err());
    assert!(android::parse_args(&["--version".into(), "0.100.0".into(), "--out".into(), "dist".into()]).is_err());
}

#[test]
fn command_line_defaults_to_phones_and_keeps_the_keystore_pair_together() {
    let args = |list: &[&str]| list.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
    let options = android::parse_args(&args(&["--version", "0.1.0-beta.1", "--out", "dist"])).unwrap();
    assert_eq!((options.abi, options.keystore), (Abi::Aarch64, None));
    let options =
        android::parse_args(&args(&["--version", "0.1.0", "--out", "dist", "--target", "x86_64", "--keystore", "k.p12", "--key-alias", "app"]))
            .unwrap();
    assert_eq!(options.abi, Abi::X86_64);
    assert_eq!(options.keystore, Some(("k.p12".into(), "app".to_owned())));
    assert!(android::parse_args(&args(&["--version", "0.1.0", "--out", "dist", "--keystore", "k.p12"])).is_err());
    assert!(android::parse_args(&args(&["--version", "0.1.0", "--out", "dist", "--target", "armv7"])).is_err());
    assert!(android::parse_args(&args(&["--out", "dist"])).is_err());
    assert_eq!(android::file_name(&version("0.1.0-beta.1"), Abi::Aarch64), "crewcraft-0.1.0-beta.1-android-aarch64.apk");
    assert_eq!(android::file_name(&version("0.1.0"), Abi::X86_64), "crewcraft-0.1.0-android-x86_64.apk");
    assert_eq!(android::library_path(Abi::Aarch64), "lib/arm64-v8a/libcrewcraft_android.so");
    assert_eq!((Abi::Aarch64.triple(), Abi::X86_64.triple()), ("aarch64-linux-android", "x86_64-linux-android"));
}

#[test]
fn manifest_is_one_native_activity_with_internet_only_and_no_code() {
    let text = android::manifest(&version("0.1.0-beta.1")).unwrap();
    for expected in [
        r#"package="io.github.setsuad.crewcraft""#,
        r#"android:versionCode="100201""#,
        r#"android:versionName="0.1.0-beta.1""#,
        r#"android:minSdkVersion="29""#,
        r#"<uses-permission android:name="android.permission.INTERNET" />"#,
        r#"android:hasCode="false""#,
        r#"android:allowBackup="false""#,
        r#"android:label="CrewCraft""#,
        r#"android:icon="@mipmap/crewcraft""#,
        r#"android:name="android.app.NativeActivity""#,
        r#"<meta-data android:name="android.app.lib_name" android:value="crewcraft_android" />"#,
        r#"android:windowSoftInputMode="adjustResize""#,
        r#"<action android:name="android.intent.action.MAIN" />"#,
        r#"<category android:name="android.intent.category.LAUNCHER" />"#,
    ] {
        assert!(text.contains(expected), "manifest lacks {expected}:\n{text}");
    }
    assert_eq!(text.matches("<uses-permission").count(), 1);
    assert_eq!(text.matches("<activity").count(), 1);
    assert!(!text.contains("<service") && !text.contains("<receiver") && !text.contains("<provider"));
    // The library the manifest names is the app crate's library.
    let cargo = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../apps/crewcraft-android/Cargo.toml")).unwrap();
    assert!(cargo.contains(&format!("name = \"{}\"", android::APP_CRATE)));
    assert_eq!(android::APP_CRATE.replace('-', "_"), android::LIB_NAME);
    assert!(cargo.contains("\"cdylib\""));
}

#[test]
fn launcher_icon_comes_in_every_density() {
    let icons = android::icon_resources(SVG).unwrap();
    let expected = [("mdpi", 48), ("hdpi", 72), ("xhdpi", 96), ("xxhdpi", 144), ("xxxhdpi", 192)];
    assert_eq!(icons.len(), expected.len());
    for ((path, png), (density, size)) in icons.iter().zip(expected) {
        assert_eq!(path, &format!("res/mipmap-{density}/crewcraft.png"));
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(&png[12..16], b"IHDR");
        assert_eq!((u32::from_be_bytes(png[16..20].try_into().unwrap()), u32::from_be_bytes(png[20..24].try_into().unwrap())), (size, size));
    }
}

/// One entry as this test's zip reader sees it.
#[derive(Debug)]
struct ZipEntry {
    name: String,
    method: u16,
    data_at: usize,
    data: Vec<u8>,
    extra: Vec<u8>,
}

/// Reads every local entry of a zip through its central directory, which the end record locates.
fn read_zip(zip: &[u8]) -> Vec<ZipEntry> {
    let end = zip.len() - 22;
    assert_eq!(u32_at(zip, end), 0x0605_4b50);
    let count = usize::from(u16_at(zip, end + 10));
    let mut at = u32_at(zip, end + 16) as usize;
    let mut out = Vec::new();
    for _ in 0..count {
        assert_eq!(u32_at(zip, at), 0x0201_4b50);
        let method = u16_at(zip, at + 10);
        let crc = u32_at(zip, at + 16);
        let (csize, size) = (u32_at(zip, at + 20) as usize, u32_at(zip, at + 24) as usize);
        let name_len = usize::from(u16_at(zip, at + 28));
        let skip = name_len + usize::from(u16_at(zip, at + 30)) + usize::from(u16_at(zip, at + 32));
        let offset = u32_at(zip, at + 42) as usize;
        let name = String::from_utf8(zip[at + 46..at + 46 + name_len].to_vec()).unwrap();
        at += 46 + skip;

        assert_eq!(u32_at(zip, offset), 0x0403_4b50);
        assert_eq!(u16_at(zip, offset + 8), method);
        let local_name = usize::from(u16_at(zip, offset + 26));
        let local_extra = usize::from(u16_at(zip, offset + 28));
        assert_eq!(&zip[offset + 30..offset + 30 + local_name], name.as_bytes());
        let extra = zip[offset + 30 + local_name..offset + 30 + local_name + local_extra].to_vec();
        let data_at = offset + 30 + local_name + local_extra;
        let raw = &zip[data_at..data_at + csize];
        let data = match method {
            0 => raw.to_vec(),
            8 => {
                let mut inflated = Vec::new();
                flate2::read::DeflateDecoder::new(raw).read_to_end(&mut inflated).unwrap();
                inflated
            }
            other => panic!("method {other}"),
        };
        assert_eq!(data.len(), size);
        let mut hasher = flate2::Crc::new();
        hasher.update(&data);
        assert_eq!(hasher.sum(), crc, "{name}");
        out.push(ZipEntry { name, method, data_at, data, extra });
    }
    out
}

/// A fake aapt2 output, licenses and library, put together as `cargo xtask apk` does.
fn fake_apk_entries() -> Vec<ApkEntry> {
    let linked = vec![
        ("res/mipmap-hdpi/crewcraft.png".to_owned(), b"png-hdpi".to_vec()),
        ("resources.arsc".to_owned(), vec![3; 777]),
        ("AndroidManifest.xml".to_owned(), b"binary manifest".to_vec()),
        ("res/mipmap-mdpi/crewcraft.png".to_owned(), b"png".to_vec()),
    ];
    let licenses = vec![("LICENSE-MIT".to_owned(), b"MIT text ".repeat(50)), ("OFL.txt".to_owned(), b"OFL text".to_vec())];
    let library: Vec<u8> = (0..100_000u32).map(|n| (n % 251) as u8).collect();
    android::apk_entries(&linked, &licenses, Abi::X86_64, &library).unwrap()
}

#[test]
fn apk_layout_stores_the_library_page_aligned_and_the_resources_word_aligned() {
    let entries = fake_apk_entries();
    let names: Vec<&str> = entries.iter().map(|entry| entry.path.as_str()).collect();
    assert_eq!(
        names,
        [
            "AndroidManifest.xml",
            "resources.arsc",
            "res/mipmap-hdpi/crewcraft.png",
            "res/mipmap-mdpi/crewcraft.png",
            "assets/licenses/LICENSE-MIT",
            "assets/licenses/OFL.txt",
            "lib/x86_64/libcrewcraft_android.so",
        ]
    );
    let unsigned = apk::zip(&entries, MTIME).unwrap();
    let read = read_zip(&unsigned.to_bytes());
    assert_eq!(read.len(), entries.len());
    for (entry, got) in entries.iter().zip(&read) {
        assert_eq!(entry.path, got.name);
        assert_eq!(entry.data, got.data, "{}", got.name);
        match entry.storage {
            Storage::Deflated => assert_eq!(got.method, 8, "{}", got.name),
            Storage::Stored { align } => {
                assert_eq!(got.method, 0, "{}", got.name);
                assert_eq!(got.data_at % usize::from(align), 0, "{} at {}", got.name, got.data_at);
                // The padding is one well-formed alignment extra field.
                assert_eq!(u16_at(&got.extra, 0), 0xd935);
                assert_eq!(usize::from(u16_at(&got.extra, 2)) + 4, got.extra.len());
                assert_eq!(u16_at(&got.extra, 4), align);
            }
        }
    }
    let library = read.iter().find(|entry| entry.name.starts_with("lib/")).unwrap();
    assert_eq!(library.data_at % 16384, 0);
    let arsc = read.iter().find(|entry| entry.name == "resources.arsc").unwrap();
    assert_eq!((arsc.method, arsc.data_at % 4), (0, 0));
    assert!(read.iter().filter(|entry| entry.name.ends_with(".png")).all(|entry| entry.method == 0));
    // The same input gives the same bytes.
    assert_eq!(apk::zip(&entries, MTIME).unwrap(), unsigned);
    assert!(apk::zip(&[ApkEntry::new("../escape", b"x".to_vec(), Storage::Deflated)], MTIME).is_err());
    let twice = [ApkEntry::new("a", b"x".to_vec(), Storage::Deflated), ApkEntry::new("a", b"y".to_vec(), Storage::Deflated)];
    assert!(apk::zip(&twice, MTIME).is_err());
    // aapt2 output without the manifest is refused, and so is a dex file (the app has no Java code).
    assert!(android::apk_entries(&[("resources.arsc".to_owned(), vec![0])], &[], Abi::X86_64, b"so").is_err());
    let with_dex = [("AndroidManifest.xml".to_owned(), vec![0]), ("resources.arsc".to_owned(), vec![0]), ("classes.dex".to_owned(), vec![0])];
    assert!(android::apk_entries(&with_dex, &[], Abi::X86_64, b"so").is_err());
}

/// The v2 digest, from the scheme's definition: 1 MiB chunks of each section, each hashed as
/// `0xa5 || len || chunk`, then `0x5a || count || digests`.
fn independent_digest(sections: &[&[u8]]) -> Vec<u8> {
    let mut digests = Vec::new();
    let mut count = 0u32;
    for section in sections {
        let mut at = 0;
        while at < section.len() {
            let end = (at + 1_048_576).min(section.len());
            let mut hash = Sha256::new();
            hash.update([0xa5]);
            hash.update(((end - at) as u32).to_le_bytes());
            hash.update(&section[at..end]);
            digests.extend(hash.finalize());
            count += 1;
            at = end;
        }
    }
    let mut hash = Sha256::new();
    hash.update([0x5a]);
    hash.update(count.to_le_bytes());
    hash.update(&digests);
    hash.finalize().to_vec()
}

/// Splits a 32-bit length-prefixed field off `data`.
fn field(data: &[u8]) -> (&[u8], &[u8]) {
    let len = u32_at(data, 0) as usize;
    (&data[4..4 + len], &data[4 + len..])
}

#[test]
fn v2_signature_covers_the_whole_apk_and_verifies() {
    // Big enough for several digest chunks.
    let mut entries = fake_apk_entries();
    entries.push(ApkEntry::new("assets/big.bin", (0..2_500_000u32).map(|n| (n % 253) as u8).collect::<Vec<u8>>(), Storage::Stored { align: 4 }));
    let unsigned = apk::zip(&entries, MTIME).unwrap();
    let key = SigningKey::generate("CrewCraft test signing key (not for release)").unwrap();
    let signed = apk::sign_v2(&unsigned, &key).unwrap();

    // Entries, then the signing block, then the central directory and the end record, which points past the block.
    assert_eq!(&signed[..unsigned.entries.len()], unsigned.entries.as_slice());
    let end = signed.len() - 22;
    let central = u32_at(&signed, end + 16) as usize;
    assert_eq!(&signed[central..end], unsigned.central_directory.as_slice());
    assert_eq!(&signed[central - 16..central], b"APK Sig Block 42");
    let size = u64_at(&signed, central - 24) as usize;
    let block = central - size - 8;
    assert_eq!(block, unsigned.entries.len());
    assert_eq!(u64_at(&signed, block) as usize, size);
    let pair_len = u64_at(&signed, block + 8) as usize;
    assert_eq!(block + 8 + 8 + pair_len, central - 24, "one ID-value pair");
    assert_eq!(u32_at(&signed, block + 16), 0x7109_871a);
    let value = &signed[block + 20..block + 16 + pair_len];

    // One signer: signed data (digests, certificates, attributes), signatures, public key.
    let (signers, rest) = field(value);
    assert!(rest.is_empty());
    let (signer, rest) = field(signers);
    assert!(rest.is_empty());
    let (signed_data, rest) = field(signer);
    let (signatures, rest) = field(rest);
    let (public_key, rest) = field(rest);
    assert!(rest.is_empty());
    let (digests, rest) = field(signed_data);
    let (certificates, rest) = field(rest);
    let (attributes, rest) = field(rest);
    assert!(rest.is_empty() && attributes.is_empty());
    let (digest, rest) = field(digests);
    assert!(rest.is_empty());
    assert_eq!(u32_at(digest, 0), 0x0201, "ECDSA with SHA-256");
    let (digest, _) = field(&digest[4..]);
    let (certificate, rest) = field(certificates);
    assert!(rest.is_empty());
    assert_eq!(certificate, key.certificate());

    // The digest is over the APK with the end record pointing at the signing block.
    let mut end_record = signed[end..].to_vec();
    end_record[16..20].copy_from_slice(&(block as u32).to_le_bytes());
    assert_eq!(digest, independent_digest(&[&signed[..block], &signed[central..end], &end_record]).as_slice());

    // The signature verifies with the certificate's key, which is also the signer's public key.
    let (_, cert) = x509_parser::parse_x509_certificate(certificate).unwrap();
    assert_eq!(cert.tbs_certificate.subject_pki.raw, public_key);
    let (signature, rest) = field(signatures);
    assert!(rest.is_empty());
    assert_eq!(u32_at(signature, 0), 0x0201);
    let (signature, _) = field(&signature[4..]);
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &cert.tbs_certificate.subject_pki.subject_public_key.data[..])
        .verify(signed_data, signature)
        .unwrap();

    // xtask's own check (run on every APK it writes) agrees, and catches a change anywhere.
    assert_eq!(apk::verify_v2(&signed).unwrap(), key.certificate());
    for at in [10, unsigned.entries.len() - 1, central + 5, signed.len() - 3, block + 200] {
        let mut tampered = signed.clone();
        tampered[at] ^= 1;
        assert!(apk::verify_v2(&tampered).is_err(), "a change at {at} went unnoticed");
    }
    assert!(apk::verify_v2(&unsigned.to_bytes()).is_err(), "an unsigned APK");
    // The stored key reloads, and a certificate for another key is refused.
    let again = SigningKey::from_parts(key.pkcs8(), key.certificate()).unwrap();
    assert_eq!(apk::verify_v2(&apk::sign_v2(&unsigned, &again).unwrap()).unwrap(), key.certificate());
    let other = SigningKey::generate("other").unwrap();
    assert!(SigningKey::from_parts(key.pkcs8(), other.certificate()).is_err());
}

#[test]
fn a_library_that_is_not_an_android_elf_is_refused() {
    assert!(android::check_library(b"not an ELF file", Abi::Aarch64).is_err());
    // The release binary of this machine is an ELF, but not an Android shared object exporting the entry point.
    let me = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    assert!(android::check_library(&me, Abi::X86_64).is_err());
    assert!(android::check_library(&me, Abi::Aarch64).is_err());
}
