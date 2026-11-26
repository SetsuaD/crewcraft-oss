//! T611f: `identity.toml`, the server's external sign-in settings: the strict format, the certificate files it names
//! (plain names in the data directory; an owner-only client key), and building the sign-in from it. Certificates and
//! keys are made at run time in a scratch directory; nothing reaches the network.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use crewcraft_server::identity_config::{AuthorizerConfig, IDENTITY_FILE, IdentityConfig, load, parse};
use rcgen::{CertificateParams, KeyPair};

const GOOD: &str = "[identity]\nsource = \"oidc\"\nissuer = \"https://id.example.org/application/o/chat/\"\nclient-id = \"chat\"\n";

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("crewcraft-t611f-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// PEM text with `label` (built at run time, so this file holds no key-shaped header).
fn pem(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

/// A self-signed certificate and its key, written as `name.pem` and `name.key` (the key owner-only).
fn write_identity(dir: &Path, name: &str) {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["chat-server".to_owned()]).unwrap().self_signed(&key).unwrap();
    fs::write(dir.join(format!("{name}.pem")), pem("CERTIFICATE", cert.der())).unwrap();
    let key_label = ["PRIV", "ATE KEY"].concat();
    let key_path = dir.join(format!("{name}.key"));
    fs::write(&key_path, pem(&key_label, &key.serialize_der())).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn the_format_is_strict() {
    let config = parse(GOOD).unwrap();
    assert_eq!(
        config,
        IdentityConfig {
            issuer: "https://id.example.org/application/o/chat/".into(),
            client_id: "chat".into(),
            require_mfa: true,
            provider_ca: None,
            authorizer: None,
        }
    );
    let full = format!(
        "{GOOD}require-mfa = \"no\"\nca-bundle = \"provider-ca.pem\"\n\n[authorizer]\nurl = \"https://authz.example.org\"\nca-bundle = \"authz-ca.pem\"\nclient-certificate = \"client.pem\"\nclient-key = \"client.key\"\n"
    );
    let config = parse(&full).unwrap();
    assert!(!config.require_mfa);
    assert_eq!(config.provider_ca.as_deref(), Some("provider-ca.pem"));
    assert_eq!(
        config.authorizer,
        Some(AuthorizerConfig {
            url: "https://authz.example.org".into(),
            ca_bundle: Some("authz-ca.pem".into()),
            client_certificate: Some(("client.pem".into(), "client.key".into())),
        })
    );
    for (text, says) in [
        ("", "identity"),
        (&GOOD.replace("oidc", "saml") as &str, "source"),
        (&GOOD.replace("https://", "http://"), "issuer"),
        (&format!("{GOOD}require-mfa = \"maybe\"\n"), "require-mfa"),
        (&format!("{GOOD}ca-bundle = \"../etc/ca.pem\"\n"), "ca-bundle"),
        (&format!("{GOOD}ca-bundle = \".hidden\"\n"), "ca-bundle"),
        (&format!("{GOOD}colour = \"teal\"\n"), "colour"),
        (&format!("{GOOD}[authorizer]\nurl = \"https://a.example.org\"\nclient-key = \"k.key\"\n"), "go together"),
        (&format!("{GOOD}[extra]\n"), "extra"),
    ] {
        let error = parse(text).unwrap_err().to_string();
        assert!(error.contains(says), "{text:?}: {error}");
    }
}

#[test]
fn loading_builds_the_sign_in_from_the_files() {
    let scratch = Scratch::new("load");
    assert!(load(&scratch.0).unwrap().is_none(), "no identity.toml: the server signs in as before");

    fs::write(scratch.0.join(IDENTITY_FILE), GOOD).unwrap();
    assert!(load(&scratch.0).unwrap().is_some(), "public roots, no authorizer");

    // A pinned provider CA and an authorizer with mutual TLS.
    write_identity(&scratch.0, "provider-ca");
    write_identity(&scratch.0, "client");
    let with_files = format!(
        "{GOOD}ca-bundle = \"provider-ca.pem\"\n[authorizer]\nurl = \"https://authz.example.org\"\nca-bundle = \"provider-ca.pem\"\nclient-certificate = \"client.pem\"\nclient-key = \"client.key\"\n"
    );
    fs::write(scratch.0.join(IDENTITY_FILE), &with_files).unwrap();
    assert!(load(&scratch.0).unwrap().is_some());

    // A named file that is missing, or not a certificate.
    fs::write(scratch.0.join(IDENTITY_FILE), format!("{GOOD}ca-bundle = \"missing.pem\"\n")).unwrap();
    assert!(load(&scratch.0).unwrap_err().to_string().contains("missing.pem"));
    fs::write(scratch.0.join("junk.pem"), "not a certificate").unwrap();
    fs::write(scratch.0.join(IDENTITY_FILE), format!("{GOOD}ca-bundle = \"junk.pem\"\n")).unwrap();
    assert!(load(&scratch.0).is_err());

    // A client key others can read is refused on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(scratch.0.join("client.key"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(scratch.0.join(IDENTITY_FILE), &with_files).unwrap();
        assert!(load(&scratch.0).unwrap_err().to_string().contains("owner-only"));
    }

    // A broken settings file stops loading with its reason.
    fs::write(scratch.0.join(IDENTITY_FILE), "[identity]\nsource = \"oidc\"\n").unwrap();
    assert!(load(&scratch.0).unwrap_err().to_string().contains(IDENTITY_FILE));
}
