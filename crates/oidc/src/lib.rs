//! Sign-in through an external OpenID Connect provider: the checks, with no network and no clock. Task T610.
//!
//! Owns: reading a provider's discovery document (the issuer must match exactly; every endpoint must be https), PKCE
//! (RFC 7636, S256), the state and nonce, the authorization URL, reading the provider's signing keys (JWKS), and
//! verifying an ID token: RS256 or ES256 only (never `none` or a shared-secret algorithm), the key chosen by `kid`,
//! then `iss`, `aud`/`azp`, `exp`, `nbf` and `iat` with a small leeway, the nonce (constant-time), and optionally that
//! the provider used more than one factor (`amr` contains `mfa`). The result is an `Identity` (issuer and subject;
//! email and name as information) that the server then hands to its authorizer (crate `crewcraft-authz`).
//! Called by: the sign-in flow (next task: fetching, the browser hand-off and the server wiring). Calls: `ring` for
//! signatures, `sha2` for PKCE, `serde_json` for the JSON documents.
//!
//! An ID token proves who the person is to the client that asked for it. It is never a password, and an identity alone
//! grants nothing (REQUIREMENTS.md section 4).

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The largest discovery document, JWKS or ID token accepted.
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;
/// Allowed clock difference between the provider and this server, in seconds.
pub const LEEWAY_SECS: u64 = 60;

/// Why a document or token was refused. The text says what was wrong, never a token's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    /// Not the expected JSON shape; the text names the field.
    Malformed(&'static str),
    /// The discovery document names a different issuer than the one configured.
    IssuerMismatch,
    /// An endpoint is not an `https://` URL.
    NotHttps(&'static str),
    /// The token's algorithm is not RS256 or ES256.
    Algorithm(String),
    /// No signing key matches the token.
    UnknownKey,
    BadSignature,
    /// A claim failed its check; the text names the claim.
    Claim(&'static str),
    /// The provider did not report a second factor and one is required.
    MfaRequired,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooLarge => write!(f, "the document is larger than {MAX_DOCUMENT_BYTES} bytes"),
            Error::Malformed(what) => write!(f, "malformed: {what}"),
            Error::IssuerMismatch => f.write_str("the provider's issuer is not the configured one"),
            Error::NotHttps(what) => write!(f, "{what} is not an https URL"),
            Error::Algorithm(alg) => write!(f, "signature algorithm {alg:?} is not accepted (RS256 or ES256 only)"),
            Error::UnknownKey => f.write_str("no signing key of the provider matches the token"),
            Error::BadSignature => f.write_str("the token's signature does not verify"),
            Error::Claim(claim) => write!(f, "the token's {claim} claim is not acceptable"),
            Error::MfaRequired => f.write_str("the provider did not report a second factor for this sign-in"),
        }
    }
}

impl std::error::Error for Error {}

fn json(text: &[u8]) -> Result<Value, Error> {
    if text.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::TooLarge);
    }
    serde_json::from_slice(text).map_err(|_| Error::Malformed("not JSON"))
}

fn https(value: &Value, field: &'static str) -> Result<String, Error> {
    let url = value.get(field).and_then(Value::as_str).ok_or(Error::Malformed(field))?;
    if !url.starts_with("https://") || url.len() <= "https://".len() {
        return Err(Error::NotHttps(field));
    }
    Ok(url.to_owned())
}

/// What the client and server need from a provider's discovery document (`/.well-known/openid-configuration`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provider {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// Read a discovery document. Its `issuer` must equal `expected_issuer` exactly (OpenID Connect Discovery 1.0 section
/// 4.3), and every endpoint must be https.
pub fn parse_discovery(document: &[u8], expected_issuer: &str) -> Result<Provider, Error> {
    let doc = json(document)?;
    let issuer = https(&doc, "issuer")?;
    if issuer != expected_issuer {
        return Err(Error::IssuerMismatch);
    }
    Ok(Provider {
        issuer,
        authorization_endpoint: https(&doc, "authorization_endpoint")?,
        token_endpoint: https(&doc, "token_endpoint")?,
        jwks_uri: https(&doc, "jwks_uri")?,
    })
}

/// A PKCE pair (RFC 7636): the verifier stays with whoever exchanges the code; the challenge goes in the URL.
#[derive(Clone, PartialEq, Eq)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

impl fmt::Debug for Pkce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkce").field("challenge", &self.challenge).finish_non_exhaustive()
    }
}

/// The PKCE pair for 32 random bytes: a 43-character verifier and its S256 challenge.
pub fn pkce(random: [u8; 32]) -> Pkce {
    let verifier = URL_SAFE_NO_PAD.encode(random);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    Pkce { verifier, challenge }
}

/// A state or nonce value from 32 random bytes.
pub fn random_value(random: [u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(random)
}

fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// What goes into the authorization request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<'a> {
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub state: &'a str,
    pub nonce: &'a str,
    pub code_challenge: &'a str,
}

/// The URL the person's browser opens: authorization code flow with PKCE (S256), scope `openid email profile`.
pub fn authorization_url(provider: &Provider, request: &Request<'_>) -> String {
    let params = [
        ("response_type", "code"),
        ("client_id", request.client_id),
        ("redirect_uri", request.redirect_uri),
        ("scope", "openid email profile"),
        ("state", request.state),
        ("nonce", request.nonce),
        ("code_challenge", request.code_challenge),
        ("code_challenge_method", "S256"),
    ];
    let query: Vec<String> = params.iter().map(|(k, v)| format!("{k}={}", percent_encode(v))).collect();
    let sep = if provider.authorization_endpoint.contains('?') { '&' } else { '?' };
    format!("{}{sep}{}", provider.authorization_endpoint, query.join("&"))
}

/// One of the provider's signing keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    /// RSA: modulus and exponent, big-endian.
    Rsa { kid: Option<String>, n: Vec<u8>, e: Vec<u8> },
    /// EC P-256: the uncompressed point (0x04, x, y).
    P256 { kid: Option<String>, point: Vec<u8> },
}

impl Key {
    fn kid(&self) -> Option<&str> {
        match self {
            Key::Rsa { kid, .. } | Key::P256 { kid, .. } => kid.as_deref(),
        }
    }
}

fn b64(value: &Value, field: &'static str) -> Result<Vec<u8>, Error> {
    let text = value.get(field).and_then(Value::as_str).ok_or(Error::Malformed(field))?;
    URL_SAFE_NO_PAD.decode(text).map_err(|_| Error::Malformed(field))
}

/// The provider's signing keys from its JWKS. Keys for other uses (`"use": "enc"`), other types and other curves are
/// skipped; a JWKS with no usable key is refused.
pub fn parse_jwks(document: &[u8]) -> Result<Vec<Key>, Error> {
    let doc = json(document)?;
    let keys = doc.get("keys").and_then(Value::as_array).ok_or(Error::Malformed("keys"))?;
    let mut out = Vec::new();
    for key in keys {
        if key.get("use").and_then(Value::as_str).is_some_and(|u| u != "sig") {
            continue;
        }
        let kid = key.get("kid").and_then(Value::as_str).map(str::to_owned);
        match (key.get("kty").and_then(Value::as_str), key.get("crv").and_then(Value::as_str)) {
            (Some("RSA"), _) => out.push(Key::Rsa { kid, n: b64(key, "n")?, e: b64(key, "e")? }),
            (Some("EC"), Some("P-256")) => {
                let (x, y) = (b64(key, "x")?, b64(key, "y")?);
                if x.len() != 32 || y.len() != 32 {
                    return Err(Error::Malformed("x/y"));
                }
                let mut point = Vec::with_capacity(65);
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                out.push(Key::P256 { kid, point });
            }
            _ => {}
        }
    }
    if out.is_empty() {
        return Err(Error::Malformed("keys: no RSA or P-256 signing key"));
    }
    Ok(out)
}

/// The parts of a compact JWS: header JSON, payload bytes, the signed input, and the signature.
struct Parts {
    header: Value,
    payload: Vec<u8>,
    signed: Vec<u8>,
    signature: Vec<u8>,
}

fn split(token: &str) -> Result<Parts, Error> {
    if token.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::TooLarge);
    }
    let mut pieces = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (pieces.next(), pieces.next(), pieces.next(), pieces.next()) else {
        return Err(Error::Malformed("token: not three parts"));
    };
    let decode = |part: &str, what| URL_SAFE_NO_PAD.decode(part).map_err(|_| Error::Malformed(what));
    let header = json(&decode(h, "token header")?)?;
    Ok(Parts { header, payload: decode(p, "token payload")?, signed: format!("{h}.{p}").into_bytes(), signature: decode(s, "token signature")? })
}

/// Check a compact JWS's signature against the provider's keys and return its payload. RS256 needs an RSA key and
/// ES256 a P-256 key; with a `kid` in the header only that key is tried, without one every key of the right type is.
pub fn verify_signature(token: &str, keys: &[Key]) -> Result<Vec<u8>, Error> {
    let parts = split(token)?;
    let alg = parts.header.get("alg").and_then(Value::as_str).unwrap_or("");
    let kid = parts.header.get("kid").and_then(Value::as_str);
    let candidates = keys.iter().filter(|key| kid.is_none() || key.kid() == kid);
    let mut tried = false;
    for key in candidates {
        let ok = match (alg, key) {
            ("RS256", Key::Rsa { n, e, .. }) => {
                tried = true;
                RsaPublicKeyComponents { n, e }.verify(&signature::RSA_PKCS1_2048_8192_SHA256, &parts.signed, &parts.signature).is_ok()
            }
            ("ES256", Key::P256 { point, .. }) => {
                tried = true;
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point).verify(&parts.signed, &parts.signature).is_ok()
            }
            ("RS256" | "ES256", _) => false,
            (other, _) => return Err(Error::Algorithm(other.to_owned())),
        };
        if ok {
            return Ok(parts.payload);
        }
    }
    if !matches!(alg, "RS256" | "ES256") {
        return Err(Error::Algorithm(alg.to_owned()));
    }
    Err(if tried { Error::BadSignature } else { Error::UnknownKey })
}

/// What an ID token must match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
    /// Now, in seconds since the Unix epoch.
    pub now: u64,
    /// Refuse a sign-in the provider did not complete with more than one factor (`amr` must contain `mfa`).
    pub require_mfa: bool,
}

/// The person an ID token names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub issuer: String,
    pub subject: String,
    /// Informational; never used to identify the person (the subject does that).
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    /// The authentication methods the provider reports, such as `pwd`, `otp`, `mfa`.
    pub amr: Vec<String>,
}

fn time_claim(claims: &Value, name: &'static str) -> Result<Option<u64>, Error> {
    match claims.get(name) {
        None => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or(Error::Claim(name)),
    }
}

/// Verify an ID token: the signature (`verify_signature`), then the claims against `expected`.
pub fn verify_id_token(token: &str, keys: &[Key], expected: &Expected<'_>) -> Result<Identity, Error> {
    let payload = verify_signature(token, keys)?;
    let claims = json(&payload)?;
    if claims.get("iss").and_then(Value::as_str) != Some(expected.issuer) {
        return Err(Error::Claim("iss"));
    }
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
        _ => return Err(Error::Claim("aud")),
    };
    if !audiences.contains(&expected.client_id) {
        return Err(Error::Claim("aud"));
    }
    let azp = claims.get("azp").and_then(Value::as_str);
    if (audiences.len() > 1 || azp.is_some()) && azp != Some(expected.client_id) {
        return Err(Error::Claim("azp"));
    }
    let exp = time_claim(&claims, "exp")?.ok_or(Error::Claim("exp"))?;
    if exp + LEEWAY_SECS <= expected.now {
        return Err(Error::Claim("exp"));
    }
    if time_claim(&claims, "nbf")?.is_some_and(|nbf| nbf > expected.now + LEEWAY_SECS) {
        return Err(Error::Claim("nbf"));
    }
    let iat = time_claim(&claims, "iat")?.ok_or(Error::Claim("iat"))?;
    if iat > expected.now + LEEWAY_SECS {
        return Err(Error::Claim("iat"));
    }
    let nonce = claims.get("nonce").and_then(Value::as_str).ok_or(Error::Claim("nonce"))?;
    if !bool::from(nonce.as_bytes().ct_eq(expected.nonce.as_bytes())) {
        return Err(Error::Claim("nonce"));
    }
    let subject = claims.get("sub").and_then(Value::as_str).filter(|s| !s.is_empty() && s.len() <= 255).ok_or(Error::Claim("sub"))?;
    let amr: Vec<String> =
        claims.get("amr").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default();
    if expected.require_mfa && !amr.iter().any(|m| m == "mfa") {
        return Err(Error::MfaRequired);
    }
    Ok(Identity {
        issuer: expected.issuer.to_owned(),
        subject: subject.to_owned(),
        email: claims.get("email").and_then(Value::as_str).map(str::to_owned),
        email_verified: claims.get("email_verified").and_then(Value::as_bool).unwrap_or(false),
        name: claims.get("name").and_then(Value::as_str).map(str::to_owned),
        amr,
    })
}
