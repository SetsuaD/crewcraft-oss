//! Signed release manifests (milestone M5, task T501): `cargo xtask release <key|public|manifest|sign|verify>`.
//!
//! Owns: making a release key (an Ed25519 seed in a new owner-only file; only its public half is ever printed),
//! writing the release manifest for the packages `dist` and `apk` built (`crewcraft_update`'s format: one artifact per
//! kind and platform, with its size and SHA-256), signing a manifest with a release key (a detached 64-byte
//! signature, checked against the key's public half before it is written), and verifying a signed manifest and its
//! files against pinned public keys, as a server or client will (`crewcraft_update::open_release` with
//! `ed25519::ReleaseKeys`). Called by: `main.rs`. Calls: `crewcraft-update`, `ed25519-dalek`, `names`, `android`.
//!
//! The release key never goes into the repository or a build machine's log; where it is kept is the release owner's
//! decision (docs/RELEASE.md).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crewcraft_update::ed25519::ReleaseKeys;
use crewcraft_update::{Release, open_release, parse_manifest, verify_artifact};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::android::{self, Abi};
use crate::names::Asset;
use crate::version::Version;
use crate::{Context, Error, Result};

pub const USAGE: &str = "\
usage: cargo xtask release key --out <new-key-file>
       cargo xtask release public --key <key-file>
       cargo xtask release manifest --version <version> --channel beta|stable --published <YYYY-MM-DD>
                                    --min-client <version> --dir <packages-dir> --out <manifest>
       cargo xtask release sign --manifest <manifest> --key <key-file> --out <signature>
       cargo xtask release verify --manifest <manifest> --signature <signature> --public <hex>[,<hex>...]
                                  [--dir <packages-dir>]

Signed release manifests (milestone M5, docs/RELEASE.md):
  key       makes a new release key in a new, owner-only file and prints its public key (hex). The file holds the
            private key: keep it off build machines and out of the repository.
  public    prints the public key of a key file.
  manifest  writes the release manifest for the packages in <packages-dir> (the server and desktop packages from
            `cargo xtask dist` and the phone APK from `cargo xtask apk`), with each file's size and SHA-256.
  sign      signs a manifest: a detached 64-byte Ed25519 signature, checked before it is written.
  verify    checks a signed manifest against the pinned public keys, as a server or client will, and with --dir
            also each listed file's size and SHA-256.";

/// The product name every CrewCraft manifest carries.
pub const PRODUCT: &str = "crewcraft";

/// The `release` command line.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Key { out: PathBuf },
    Public { key: PathBuf },
    Manifest(ManifestOptions),
    Sign { manifest: PathBuf, key: PathBuf, out: PathBuf },
    Verify { manifest: PathBuf, signature: PathBuf, public: Vec<String>, dir: Option<PathBuf> },
}

/// What `release manifest` writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestOptions {
    pub version: Version,
    pub channel: String,
    pub published: String,
    pub min_client: Version,
    pub dir: PathBuf,
    pub out: PathBuf,
}

/// Parses the arguments after `release`.
pub fn parse_args(args: &[String]) -> Result<Command> {
    let (command, rest) = args.split_first().ok_or_else(|| Error::new(USAGE))?;
    let mut flags: Vec<(String, String)> = Vec::new();
    let mut items = rest.iter();
    while let Some(flag) = items.next() {
        if !flag.starts_with("--") {
            return Err(Error::new(format!("unexpected argument {flag:?}\n\n{USAGE}")));
        }
        let value = items.next().ok_or_else(|| Error::new(format!("{flag} needs a value\n\n{USAGE}")))?;
        if flags.iter().any(|(seen, _)| seen == flag) {
            return Err(Error::new(format!("{flag} is given twice\n\n{USAGE}")));
        }
        flags.push((flag.clone(), value.clone()));
    }
    let allowed: &[&str] = match command.as_str() {
        "key" => &["--out"],
        "public" => &["--key"],
        "manifest" => &["--version", "--channel", "--published", "--min-client", "--dir", "--out"],
        "sign" => &["--manifest", "--key", "--out"],
        "verify" => &["--manifest", "--signature", "--public", "--dir"],
        _ => return Err(Error::new(format!("unknown release command {command:?}\n\n{USAGE}"))),
    };
    if let Some((flag, _)) = flags.iter().find(|(flag, _)| !allowed.contains(&flag.as_str())) {
        return Err(Error::new(format!("release {command} does not take {flag}\n\n{USAGE}")));
    }
    let get = |name: &str| flags.iter().find(|(flag, _)| flag == name).map(|(_, value)| value.clone());
    let need = |name: &str| get(name).ok_or_else(|| Error::new(format!("release {command} needs {name}\n\n{USAGE}")));
    Ok(match command.as_str() {
        "key" => Command::Key { out: need("--out")?.into() },
        "public" => Command::Public { key: need("--key")?.into() },
        "manifest" => {
            let channel = need("--channel")?;
            if channel != "beta" && channel != "stable" {
                return Err(Error::new(format!("--channel is beta or stable\n\n{USAGE}")));
            }
            let published = need("--published")?;
            let date = published.as_bytes();
            let date_ok =
                date.len() == 10 && date.iter().enumerate().all(|(i, byte)| if i == 4 || i == 7 { *byte == b'-' } else { byte.is_ascii_digit() });
            if !date_ok {
                return Err(Error::new(format!("--published is a date like 2026-12-31\n\n{USAGE}")));
            }
            Command::Manifest(ManifestOptions {
                version: Version::parse(&need("--version")?)?,
                channel,
                published,
                min_client: Version::parse(&need("--min-client")?)?,
                dir: need("--dir")?.into(),
                out: need("--out")?.into(),
            })
        }
        "sign" => Command::Sign { manifest: need("--manifest")?.into(), key: need("--key")?.into(), out: need("--out")?.into() },
        _ => Command::Verify {
            manifest: need("--manifest")?.into(),
            signature: need("--signature")?.into(),
            public: need("--public")?.split(',').map(str::to_owned).collect(),
            dir: get("--dir").map(PathBuf::from),
        },
    })
}

/// Runs a `release` command, printing what it did.
pub fn run(command: &Command) -> Result<()> {
    match command {
        Command::Key { out } => {
            let public = new_key(out)?;
            println!("wrote a new release key to {} (keep it private)", out.display());
            println!("public key: {public}");
        }
        Command::Public { key } => println!("{}", public_key(key)?),
        Command::Manifest(options) => {
            let text = manifest_text(options)?;
            write_new(&options.out, text.as_bytes())?;
            let release = parse_manifest(&text).map_err(|error| Error::new(format!("the manifest written is not valid: {error}")))?;
            println!("wrote {} ({} artifacts)", options.out.display(), release.artifacts.len());
        }
        Command::Sign { manifest, key, out } => {
            let bytes = fs::read(manifest).context(|| format!("reading {}", manifest.display()))?;
            let signature = sign(&bytes, key)?;
            write_new(out, &signature)?;
            println!("wrote {} (signed by {})", out.display(), public_key(key)?);
        }
        Command::Verify { manifest, signature, public, dir } => {
            let release = verify(manifest, signature, public, dir.as_deref())?;
            println!(
                "{} {} ({:?}): signature good, {} artifacts{}",
                release.product,
                release.version,
                release.channel,
                release.artifacts.len(),
                if dir.is_some() { ", every file matches" } else { "" }
            );
        }
    }
    Ok(())
}

/// The manifest's artifacts: each release package, its kind and platform in the manifest, and its file name.
pub fn packages(version: &Version) -> Vec<(&'static str, &'static str, String)> {
    let mut list: Vec<(&'static str, &'static str, String)> = [
        (Asset::ServerTarGz, "server", "linux-x64"),
        (Asset::ServerZip, "server", "windows-x64"),
        (Asset::ServerMacTarGz, "server", "macos-universal"),
        // The AppImage, not the .deb: an AppImage replaces itself in place; a .deb is updated by the package manager.
        (Asset::ClientAppImage, "desktop", "linux-x64"),
        (Asset::ClientMsi, "desktop", "windows-x64"),
        (Asset::ClientDmg, "desktop", "macos-universal"),
    ]
    .into_iter()
    .map(|(asset, kind, platform)| (kind, platform, asset.file_name(version)))
    .collect();
    list.push(("android", "android", android::file_name(version, Abi::Aarch64)));
    list
}

/// The manifest for the packages found in `options.dir`; a package that is missing is left out, and at least one
/// must be there.
pub fn manifest_text(options: &ManifestOptions) -> Result<String> {
    if !older_or_equal(&options.min_client, &options.version) {
        return Err(Error::new("--min-client cannot be newer than --version"));
    }
    let mut text = format!(
        "[release]\nproduct = \"{PRODUCT}\"\nversion = \"{}\"\nchannel = \"{}\"\npublished = \"{}\"\nmin-client = \"{}\"\n",
        options.version, options.channel, options.published, options.min_client
    );
    let mut found = 0;
    for (kind, platform, file) in packages(&options.version) {
        let path = options.dir.join(&file);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(Error::new(format!("reading {}: {error}", path.display()))),
        };
        let digest: String = Sha256::digest(&bytes).iter().map(|byte| format!("{byte:02x}")).collect();
        text.push_str(&format!(
            "\n[artifact.{kind}-{platform}]\nkind = \"{kind}\"\nplatform = \"{platform}\"\nfile = \"{file}\"\nsize = {}\nsha256 = \"{digest}\"\n",
            bytes.len()
        ));
        found += 1;
    }
    if found == 0 {
        return Err(Error::new(format!("no release package for {} in {}", options.version, options.dir.display())));
    }
    Ok(text)
}

fn older_or_equal(a: &Version, b: &Version) -> bool {
    match (crewcraft_update::Version::parse(&a.to_string()), crewcraft_update::Version::parse(&b.to_string())) {
        (Some(a), Some(b)) => a <= b,
        _ => false,
    }
}

/// Makes a new release key in a new owner-only file at `out` and returns its public key as hex.
pub fn new_key(out: &Path) -> Result<String> {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut seed[..]);
    let text = Zeroizing::new(format!("{}\n", hex(&seed[..])));
    write_new(out, text.as_bytes())?;
    Ok(hex(SigningKey::from_bytes(&seed).verifying_key().as_bytes()))
}

/// The public key, as hex, of the release key in `key`.
pub fn public_key(key: &Path) -> Result<String> {
    Ok(hex(read_key(key)?.verifying_key().as_bytes()))
}

/// Signs `manifest` (which must be a valid manifest) with the release key in `key`, and checks the signature with
/// the key's public half before returning it.
pub fn sign(manifest: &[u8], key: &Path) -> Result<Vec<u8>> {
    let text = std::str::from_utf8(manifest).map_err(|_| Error::new("the manifest is not UTF-8 text"))?;
    parse_manifest(text).map_err(|error| Error::new(format!("refusing to sign an invalid manifest: {error}")))?;
    let key = read_key(key)?;
    let signature = key.sign(manifest).to_bytes().to_vec();
    let pinned = ReleaseKeys::new(&[key.verifying_key().to_bytes()]).map_err(|error| Error::new(format!("the release key: {error}")))?;
    open_release(manifest, &signature, &pinned).map_err(|error| Error::new(format!("the new signature does not verify: {error}")))?;
    Ok(signature)
}

/// Checks the signed manifest against the public keys (hex) and, with `dir`, each listed file.
pub fn verify(manifest: &Path, signature: &Path, public: &[String], dir: Option<&Path>) -> Result<Release> {
    let keys: Vec<&str> = public.iter().map(String::as_str).collect();
    let pinned = ReleaseKeys::from_hex(&keys).map_err(|error| Error::new(format!("--public: {error}")))?;
    let bytes = fs::read(manifest).context(|| format!("reading {}", manifest.display()))?;
    let signature = fs::read(signature).context(|| format!("reading {}", signature.display()))?;
    let release = open_release(&bytes, &signature, &pinned).map_err(|error| Error::new(error.to_string()))?;
    if release.product != PRODUCT {
        return Err(Error::new(format!("the manifest is for {}, not {PRODUCT}", release.product)));
    }
    if let Some(dir) = dir {
        for artifact in &release.artifacts {
            let path = dir.join(&artifact.file);
            let file = fs::read(&path).context(|| format!("reading {}", path.display()))?;
            verify_artifact(artifact, &file).map_err(|error| Error::new(format!("{}: {error}", artifact.file)))?;
        }
    }
    Ok(release)
}

/// The signing key in a key file: 64 hex characters (and a line end). On Unix the file must be owner-only.
fn read_key(path: &Path) -> Result<SigningKey> {
    check_private(path)?;
    let text = Zeroizing::new(fs::read_to_string(path).context(|| format!("reading {}", path.display()))?);
    let text = text.trim();
    if text.len() != 64 {
        return Err(Error::new(format!("{} is not a release key file", path.display())));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    for (byte, pair) in seed.iter_mut().zip(pairs) {
        let pair = std::str::from_utf8(&pair[..]).ok().and_then(|pair| u8::from_str_radix(pair, 16).ok());
        *byte = pair.ok_or_else(|| Error::new(format!("{} is not a release key file", path.display())))?;
    }
    Ok(SigningKey::from_bytes(&seed))
}

#[cfg(unix)]
fn check_private(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path).context(|| format!("reading {}", path.display()))?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(Error::new(format!("{} can be read by others (mode {:o}); make it owner-only (chmod 600)", path.display(), mode & 0o777)));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private(_: &Path) -> Result<()> {
    Ok(())
}

/// Writes `bytes` to a new file (never over an existing one), owner-only on Unix.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).context(|| format!("creating {} (it must not exist yet)", path.display()))?;
    file.write_all(bytes).context(|| format!("writing {}", path.display()))?;
    file.sync_all().context(|| format!("writing {}", path.display()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
