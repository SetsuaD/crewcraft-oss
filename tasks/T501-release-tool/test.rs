//! T501: the release tool (`cargo xtask release`): a release key in a new owner-only file, the manifest for the
//! packages in a folder, a signature checked before it is written, and verification against pinned public keys and
//! the files themselves. Test keys only, made in a scratch folder.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crewcraft_update::{Kind, parse_manifest};
use xtask::release::{self, Command, ManifestOptions};
use xtask::version::Version;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("crewcraft-t501-{tag}-{}-{nanos}", std::process::id()));
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

fn version(text: &str) -> Version {
    Version::parse(text).unwrap()
}

fn options(dir: &Path, out: &Path) -> ManifestOptions {
    ManifestOptions {
        version: version("0.2.0"),
        channel: "beta".to_owned(),
        published: "2026-12-31".to_owned(),
        min_client: version("0.1.0-beta.1"),
        dir: dir.to_path_buf(),
        out: out.to_path_buf(),
    }
}

/// Fake packages for 0.2.0: the Linux server and desktop, and the phone APK.
fn packages(dir: &Path) {
    fs::write(dir.join("crewcraft-server-0.2.0-linux-x86_64.tar.gz"), b"server archive").unwrap();
    fs::write(dir.join("crewcraft-0.2.0-linux-x86_64.AppImage"), b"desktop appimage").unwrap();
    fs::write(dir.join("crewcraft-0.2.0-linux-x86_64.deb"), b"not in the manifest").unwrap();
    fs::write(dir.join("crewcraft-0.2.0-android-aarch64.apk"), b"phone app").unwrap();
    fs::write(dir.join("crewcraft-0.1.0-linux-x86_64.AppImage"), b"another version").unwrap();
}

#[test]
fn the_command_line_is_checked() {
    assert_eq!(release::parse_args(&args(&["key", "--out", "k"])).unwrap(), Command::Key { out: "k".into() });
    assert!(matches!(
        release::parse_args(&args(&["verify", "--manifest", "m", "--signature", "s", "--public", "aa,bb"])).unwrap(),
        Command::Verify { public, dir: None, .. } if public == ["aa", "bb"]
    ));
    let manifest = |extra: &[&str]| {
        let mut list = vec!["manifest", "--version", "0.2.0", "--published", "2026-12-31", "--min-client", "0.1.0", "--dir", "d", "--out", "o"];
        list.extend_from_slice(extra);
        release::parse_args(&args(&list))
    };
    assert!(manifest(&["--channel", "beta"]).is_ok());
    assert!(manifest(&["--channel", "nightly"]).is_err());
    assert!(manifest(&[]).is_err(), "--channel is required");
    assert!(release::parse_args(&args(&["manifest", "--published", "31/12/2026"])).is_err());
    assert!(release::parse_args(&args(&["key", "--out", "a", "--out", "b"])).is_err(), "a flag given twice");
    assert!(release::parse_args(&args(&["key", "--key", "a"])).is_err(), "a flag the command does not take");
    assert!(release::parse_args(&args(&["publish"])).is_err());
}

#[test]
fn a_new_key_is_owner_only_and_never_overwritten() {
    let scratch = Scratch::new("key");
    let path = scratch.0.join("release.key");
    let public = release::new_key(&path).unwrap();
    assert_eq!(public.len(), 64);
    assert_eq!(release::public_key(&path).unwrap(), public);
    let text = fs::read_to_string(&path).unwrap();
    assert_eq!(text.trim().len(), 64);
    assert!(!text.contains(&public), "the file holds the private seed, not the public key");
    assert!(release::new_key(&path).is_err(), "an existing key file is never replaced");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(release::public_key(&path).is_err(), "a key file others can read is refused");
    }
}

#[test]
fn the_manifest_lists_the_packages_that_are_there() {
    let scratch = Scratch::new("manifest");
    packages(&scratch.0);
    let text = release::manifest_text(&options(&scratch.0, &scratch.0.join("release.toml"))).unwrap();
    let release = parse_manifest(&text).unwrap();
    assert_eq!(release.product, "crewcraft");
    assert_eq!(release.version.to_string(), "0.2.0");
    let mut listed: Vec<(Kind, &str, &str, u64)> = release.artifacts.iter().map(|a| (a.kind, a.platform.as_str(), a.file.as_str(), a.size)).collect();
    listed.sort_by_key(|entry| entry.2.to_owned());
    assert_eq!(
        listed,
        [
            (Kind::Android, "android", "crewcraft-0.2.0-android-aarch64.apk", 9),
            (Kind::Desktop, "linux-x64", "crewcraft-0.2.0-linux-x86_64.AppImage", 16),
            (Kind::Server, "linux-x64", "crewcraft-server-0.2.0-linux-x86_64.tar.gz", 14),
        ]
    );
    // Nothing for this version: refused. A minimum client newer than the release: refused.
    let empty = Scratch::new("empty");
    assert!(release::manifest_text(&options(&empty.0, &empty.0.join("r"))).is_err());
    let mut newer = options(&scratch.0, &scratch.0.join("r"));
    newer.min_client = version("0.3.0");
    assert!(release::manifest_text(&newer).is_err());
}

#[test]
fn a_signed_manifest_verifies_and_any_change_is_caught() {
    let scratch = Scratch::new("sign");
    packages(&scratch.0);
    let key = scratch.0.join("release.key");
    let public = release::new_key(&key).unwrap();
    let other = release::new_key(&scratch.0.join("other.key")).unwrap();
    let manifest = scratch.0.join("release.toml");
    let signature = scratch.0.join("release.toml.sig");
    release::run(&Command::Manifest(options(&scratch.0, &manifest))).unwrap();
    release::run(&Command::Sign { manifest: manifest.clone(), key: key.clone(), out: signature.clone() }).unwrap();
    assert_eq!(fs::read(&signature).unwrap().len(), 64);

    let checked = release::verify(&manifest, &signature, std::slice::from_ref(&public), Some(&scratch.0)).unwrap();
    assert_eq!(checked.artifacts.len(), 3);
    // Rotation: any pinned key is enough.
    assert!(release::verify(&manifest, &signature, &[other.clone(), public.clone()], None).is_ok());
    assert!(release::verify(&manifest, &signature, std::slice::from_ref(&other), None).is_err(), "another key's pin");

    // A changed package: the signature still verifies, the file does not.
    fs::write(scratch.0.join("crewcraft-0.2.0-android-aarch64.apk"), b"phone apP").unwrap();
    let error = release::verify(&manifest, &signature, std::slice::from_ref(&public), Some(&scratch.0)).unwrap_err().to_string();
    assert!(error.contains("android"), "{error}");

    // A changed manifest: the signature no longer verifies.
    let text = fs::read_to_string(&manifest).unwrap().replace("channel = \"beta\"", "channel = \"stable\"");
    let changed = scratch.0.join("changed.toml");
    fs::write(&changed, text).unwrap();
    assert!(release::verify(&changed, &signature, std::slice::from_ref(&public), None).is_err());

    // An invalid manifest is never signed, and no output file is overwritten.
    assert!(release::sign(b"[release]\nproduct = \"crewcraft\"\n", &key).is_err());
    assert!(release::run(&Command::Sign { manifest, key, out: signature }).is_err(), "the signature file exists");
}
