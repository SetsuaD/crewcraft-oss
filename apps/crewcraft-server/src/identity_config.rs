//! The server's external sign-in settings, `identity.toml` in the data directory (SECURITY-DESIGN.md section 9; task
//! T611f).
//!
//! Owns: the file's format (strict TOML: unknown sections or keys, and bad values, are refused with their line),
//! reading the certificate files it names (plain file names inside the data directory only; a client key must be
//! owner-only on Unix), and building `ExternalSignIn` with its HTTPS provider and optional authorizer. Called by:
//! `main` (`serve`). Calls: `crewcraft-strict-toml`, `crewcraft-https`, `external_signin`.
//!
//! Without the file, the server signs people in with its own passwords and codes, exactly as before.
//!
//! ```toml
//! [identity]
//! source = "oidc"
//! issuer = "https://id.example.org/application/o/chat/"
//! client-id = "chat"
//! require-mfa = "yes"                 # "yes" (default) or "no"
//! ca-bundle = "provider-ca.pem"       # optional: trust only these CAs for the provider (default: public roots)
//!
//! [authorizer]                        # optional: an external authorizer (docs/AUTHORIZER.md)
//! url = "https://authz.example.org"
//! ca-bundle = "authorizer-ca.pem"     # optional
//! client-certificate = "authorizer-client.pem"   # optional, with client-key: mutual TLS
//! client-key = "authorizer-client.key"
//! ```

use std::io;
use std::path::Path;
use std::sync::Arc;

use crewcraft_https::{Client, Identity, Roots};
use crewcraft_strict_toml as toml;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::external_signin::{Authorizer, ExternalSignIn, HttpsAuthorizer, HttpsProvider};

/// The settings file's name in the data directory.
pub const IDENTITY_FILE: &str = "identity.toml";
const MAX_FILE_BYTES: usize = 16 * 1024;
const MAX_PEM_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityConfig {
    pub issuer: String,
    pub client_id: String,
    pub require_mfa: bool,
    /// A PEM bundle in the data directory; `None` trusts the public roots.
    pub provider_ca: Option<String>,
    pub authorizer: Option<AuthorizerConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizerConfig {
    pub url: String,
    pub ca_bundle: Option<String>,
    /// Both or neither: a PEM certificate chain and its PEM private key, for mutual TLS.
    pub client_certificate: Option<(String, String)>,
}

fn bad(line: usize, key: &str, reason: &'static str) -> toml::Error {
    toml::Error::BadValue { line, key: key.to_owned(), reason }
}

fn https_url(section: &toml::Section, name: &str, key: &str) -> Result<String, toml::Error> {
    let (url, line) = section.req_str(name, key)?;
    if !url.starts_with("https://") || url.len() <= 8 || url.len() > 2048 || !url.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(bad(line, key, "an https URL"));
    }
    Ok(url.to_owned())
}

/// A file named in the settings: a plain name (no directories, not hidden), so it can only be in the data directory.
fn file_name(section: &toml::Section, key: &str) -> Result<Option<String>, toml::Error> {
    match section.opt_str(key)? {
        None => Ok(None),
        Some((name, line)) => {
            let plain = !name.is_empty()
                && name.len() <= 128
                && !name.starts_with('.')
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
            if plain { Ok(Some(name.to_owned())) } else { Err(bad(line, key, "a plain file name in the data directory")) }
        }
    }
}

/// Read `identity.toml`.
pub fn parse(text: &str) -> Result<IdentityConfig, toml::Error> {
    let doc = toml::parse(text, MAX_FILE_BYTES)?;
    doc.check_sections(&["identity", "authorizer"], &[])?;
    let identity = doc.require("identity")?;
    identity.check_keys("identity", &["source", "issuer", "client-id", "require-mfa", "ca-bundle"])?;
    let (source, line) = identity.req_str("identity", "source")?;
    if source != "oidc" {
        return Err(bad(line, "source", "\"oidc\" (the only external source so far)"));
    }
    let issuer = https_url(identity, "identity", "issuer")?;
    let (client_id, line) = identity.req_str("identity", "client-id")?;
    if client_id.is_empty() || client_id.len() > 256 || !client_id.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(bad(line, "client-id", "1 to 256 printable characters"));
    }
    let require_mfa = match identity.opt_str("require-mfa")? {
        None | Some(("yes", _)) => true,
        Some(("no", _)) => false,
        Some((_, line)) => return Err(bad(line, "require-mfa", "\"yes\" or \"no\"")),
    };
    let provider_ca = file_name(identity, "ca-bundle")?;
    let authorizer = match doc.sections.get("authorizer") {
        None => None,
        Some(section) => {
            section.check_keys("authorizer", &["url", "ca-bundle", "client-certificate", "client-key"])?;
            let url = https_url(section, "authorizer", "url")?;
            let ca_bundle = file_name(section, "ca-bundle")?;
            let client_certificate = match (file_name(section, "client-certificate")?, file_name(section, "client-key")?) {
                (Some(cert), Some(key)) => Some((cert, key)),
                (None, None) => None,
                _ => return Err(bad(section.line, "client-certificate", "client-certificate and client-key go together")),
            };
            Some(AuthorizerConfig { url, ca_bundle, client_certificate })
        }
    };
    Ok(IdentityConfig { issuer, client_id: client_id.to_owned(), require_mfa, provider_ca, authorizer })
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_pem(dir: &Path, name: &str, private: bool) -> io::Result<Vec<u8>> {
    let path = dir.join(name);
    let meta = std::fs::symlink_metadata(&path).map_err(|e| invalid(format!("{IDENTITY_FILE}: {name}: {e}")))?;
    if !meta.is_file() || meta.len() > MAX_PEM_BYTES {
        return Err(invalid(format!("{IDENTITY_FILE}: {name} is not a regular file of at most 1 MiB")));
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(invalid(format!("{IDENTITY_FILE}: {name} can be read by others; make it owner-only (chmod 600)")));
        }
    }
    #[cfg(not(unix))]
    let _ = private;
    std::fs::read(&path)
}

fn roots(dir: &Path, bundle: &Option<String>) -> io::Result<Roots> {
    Ok(match bundle {
        Some(name) => Roots::Pem(read_pem(dir, name, false)?),
        None => Roots::Public,
    })
}

/// The external sign-in the data directory `dir` configures, or `None` without `identity.toml`.
pub fn load(dir: &Path) -> io::Result<Option<Arc<ExternalSignIn>>> {
    let path = dir.join(IDENTITY_FILE);
    let text = match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
        Ok(meta) if !meta.is_file() || meta.len() > MAX_FILE_BYTES as u64 => {
            return Err(invalid(format!("{IDENTITY_FILE} is not a regular file of at most 16 KiB")));
        }
        Ok(_) => std::fs::read_to_string(&path).map_err(|e| invalid(format!("{IDENTITY_FILE}: {e}")))?,
    };
    let config = parse(&text).map_err(|e| invalid(format!("{IDENTITY_FILE}: {e}")))?;
    let provider_client = Client::new(&roots(dir, &config.provider_ca)?, None).map_err(|e| invalid(format!("{IDENTITY_FILE}: {e}")))?;
    let provider = Arc::new(HttpsProvider::new(provider_client, &config.issuer, &config.client_id));
    let authorizer: Option<Arc<dyn Authorizer>> = match &config.authorizer {
        None => None,
        Some(a) => {
            let identity: Option<Identity> = match &a.client_certificate {
                None => None,
                Some((cert, key)) => {
                    let chain = CertificateDer::pem_slice_iter(&read_pem(dir, cert, false)?)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| invalid(format!("{IDENTITY_FILE}: {cert}: {e}")))?;
                    if chain.is_empty() {
                        return Err(invalid(format!("{IDENTITY_FILE}: {cert} holds no certificate")));
                    }
                    let key =
                        PrivateKeyDer::from_pem_slice(&read_pem(dir, key, true)?).map_err(|e| invalid(format!("{IDENTITY_FILE}: {key}: {e}")))?;
                    Some((chain, key))
                }
            };
            let client = Client::new(&roots(dir, &a.ca_bundle)?, identity).map_err(|e| invalid(format!("{IDENTITY_FILE}: {e}")))?;
            Some(Arc::new(HttpsAuthorizer::new(client, &a.url)))
        }
    };
    Ok(Some(Arc::new(ExternalSignIn::new(provider, authorizer, config.require_mfa))))
}
