//! The two calls a bootstrap connection may make, and the server's answers (docs/SECURITY-DESIGN.md section 3): redeem
//! an invitation with a certificate signing request, then confirm the first TOTP code. These tags are disjoint from
//! `request` (T124), so a bootstrap connection cannot reach any ordinary call and an ordinary connection cannot make
//! these: each side's decoder refuses the other's tags with `BadKind`, and the connection is closed without a reply.
//! Task T204.
//!
//! Wire format, integers big-endian; `str` is a `u16` byte length then UTF-8 (as in `request`); `bytes` is a `u16`
//! length then raw bytes.
//!
//! A request is `u8 tag | u32 id | fields`:
//! - tag 32 `Redeem`: `str device_name (1 to MAX_DEVICE_NAME bytes) | bytes csr (1 to MAX_CSR) | str password (1 to MAX_PASSWORD)`
//! - tag 33 `ConfirmTotp`: `str code` (exactly `CODE_LEN` bytes)
//! - tag 39 `RedeemExternal` (task T611i): `str device_name (1 to MAX_DEVICE_NAME bytes) | bytes csr (1 to MAX_CSR)`
//! - tag 40 `ConfirmExternal` (task T611i): `str code (1 to signin::MAX_AUTH_CODE_BYTES) | str verifier
//!   (signin::MIN_VERIFIER_LEN to signin::MAX_VERIFIER_LEN) | str redirect_uri (1 to signin::MAX_REDIRECT_BYTES)`, each
//!   printable ASCII
//!
//! A response is `u8 tag | u32 id | fields`, where `id` repeats the request's:
//! - tag 160 `Setup`: `str totp_uri (1 to MAX_URI)`
//! - tag 161 `Activated`: `bytes certificate (1 to MAX_CERT) | bytes issuer_certificate (1 to MAX_CERT)`
//! - tag 162 `Error`: `u16 code`
//! - tag 167 `ExternalStart` (task T611i): `str issuer (1 to signin::MAX_URL_BYTES) | str client_id (1 to
//!   signin::MAX_CLIENT_ID_BYTES) | str authorization_endpoint (1 to signin::MAX_URL_BYTES) | str nonce (43 base64url
//!   characters, 32 bytes, as a session token)`
//!
//! Tags 34 to 38 and 163 to 166 are the sign-in openings and replies (`signin`): a bootstrap decoder refuses them.
//!
//! On a server that signs people in through an organization's identity provider (docs/SECURITY-DESIGN.md section 9),
//! enrollment is `RedeemExternal`, answered `ExternalStart`, then `ConfirmExternal` with the provider's code, answered
//! `Activated`; `Redeem` and `ConfirmTotp` are the path for every other server.
//!
//! Send `Setup` after staging the signing request and password. Send `Activated` only after committing the
//! exact issued certificate and activation state. Its two DER certificates form the device chain, leaf first.
//! The client's server trust anchor comes from the invitation.
//!
//! Decoding checks, in the order the bytes are read: the tag (`Truncated` if there is none, `BadKind(tag)` for a tag
//! this module does not decode), the id (`Truncated`), then each field (`Truncated` when bytes run out, `FieldLength`
//! when a length prefix is outside its range, checked before the bytes are read, `BadUtf8`), then `TrailingBytes`.
//! Encoding refuses out-of-range fields with `FieldLength`.

use crate::message::CodecError;
use crate::signin::{
    MAX_AUTH_CODE_BYTES, MAX_CLIENT_ID_BYTES, MAX_REDIRECT_BYTES, MAX_URL_BYTES, MAX_VERIFIER_LEN, MIN_VERIFIER_LEN, TOKEN_LEN, check_token,
};

pub const MAX_DEVICE_NAME: usize = 64;
pub const MAX_CSR: usize = 4096;
pub const MAX_PASSWORD: usize = 1024;
/// A TOTP code is six digits; the codec checks only the length.
pub const CODE_LEN: usize = 6;
pub const MAX_CERT: usize = 4096;
pub const MAX_URI: usize = 512;

#[derive(Clone, PartialEq, Eq)]
pub enum BootstrapRequest {
    Redeem {
        device_name: String,
        csr: Vec<u8>,
        password: String,
    },
    ConfirmTotp {
        code: String,
    },
    /// Redeem the invitation through the server's identity provider instead of a password (task T611i).
    RedeemExternal {
        device_name: String,
        csr: Vec<u8>,
    },
    /// Finish that redemption with the provider's code, the PKCE verifier and the loopback redirect URI.
    ConfirmExternal {
        code: String,
        verifier: String,
        redirect_uri: String,
    },
}

// A password and a code are secrets: they never reach logs or panics.
impl std::fmt::Debug for BootstrapRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootstrapRequest::Redeem { device_name, csr, .. } => {
                write!(f, "Redeem {{ device_name: {device_name:?}, csr: <{} bytes>, password: .. }}", csr.len())
            }
            BootstrapRequest::ConfirmTotp { .. } => f.write_str("ConfirmTotp { code: .. }"),
            BootstrapRequest::RedeemExternal { device_name, csr } => {
                write!(f, "RedeemExternal {{ device_name: {device_name:?}, csr: <{} bytes> }}", csr.len())
            }
            BootstrapRequest::ConfirmExternal { redirect_uri, .. } => {
                write!(f, "ConfirmExternal {{ code: .., verifier: .., redirect_uri: {redirect_uri:?} }}")
            }
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum BootstrapResponse {
    Setup {
        totp_uri: String,
    },
    Activated {
        certificate: Vec<u8>,
        issuer_certificate: Vec<u8>,
    },
    Error {
        code: u16,
    },
    /// What the app needs to open the provider's sign-in page (task T611i); `nonce` is bound to this bootstrap key.
    ExternalStart {
        issuer: String,
        client_id: String,
        authorization_endpoint: String,
        nonce: String,
    },
}

impl std::fmt::Debug for BootstrapResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setup { .. } => f.write_str("Setup { totp_uri: .. }"),
            Self::Activated { .. } => f.write_str("Activated { certificate: .., issuer_certificate: .. }"),
            Self::Error { code } => f.debug_struct("Error").field("code", code).finish(),
            Self::ExternalStart { issuer, client_id, authorization_endpoint, .. } => f
                .debug_struct("ExternalStart")
                .field("issuer", issuer)
                .field("client_id", client_id)
                .field("authorization_endpoint", authorization_endpoint)
                .finish_non_exhaustive(),
        }
    }
}

const REDEEM: u8 = 32;
const CONFIRM_TOTP: u8 = 33;
const SETUP: u8 = 160;
const ACTIVATED: u8 = 161;
const ERROR: u8 = 162;
const REDEEM_EXTERNAL: u8 = 39;
const CONFIRM_EXTERNAL: u8 = 40;
const EXTERNAL_START: u8 = 167;

fn header(tag: u8, id: u32) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&id.to_be_bytes());
    out
}

fn put_field(out: &mut Vec<u8>, field: &[u8], min: usize, max: usize) -> Result<(), CodecError> {
    if !(min..=max).contains(&field.len()) {
        return Err(CodecError::FieldLength);
    }
    out.extend_from_slice(&(field.len() as u16).to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

fn take_array<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], CodecError> {
    let (head, rest) = input.split_first_chunk().ok_or(CodecError::Truncated)?;
    *input = rest;
    Ok(*head)
}

fn read_header(input: &mut &[u8], tags: &[u8]) -> Result<(u8, u32), CodecError> {
    let [tag] = take_array(input)?;
    if !tags.contains(&tag) {
        return Err(CodecError::BadKind(tag));
    }
    let id = u32::from_be_bytes(take_array(input)?);
    Ok((tag, id))
}

fn read_field<'a>(input: &mut &'a [u8], min: usize, max: usize) -> Result<&'a [u8], CodecError> {
    let len = usize::from(u16::from_be_bytes(take_array(input)?));
    if !(min..=max).contains(&len) {
        return Err(CodecError::FieldLength);
    }
    let (field, rest) = input.split_at_checked(len).ok_or(CodecError::Truncated)?;
    *input = rest;
    Ok(field)
}

fn read_string(input: &mut &[u8], min: usize, max: usize) -> Result<String, CodecError> {
    let field = read_field(input, min, max)?;
    let text = std::str::from_utf8(field).map_err(|_| CodecError::BadUtf8)?;
    Ok(text.to_owned())
}

/// A field that must be printable ASCII (a code, a verifier, a redirect URI): anything else is `FieldLength`.
fn read_ascii(input: &mut &[u8], min: usize, max: usize) -> Result<String, CodecError> {
    let text = read_string(input, min, max)?;
    if !text.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(CodecError::FieldLength);
    }
    Ok(text)
}

fn put_ascii(out: &mut Vec<u8>, text: &str, min: usize, max: usize) -> Result<(), CodecError> {
    if !text.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(CodecError::FieldLength);
    }
    put_field(out, text.as_bytes(), min, max)
}

pub fn encode_bootstrap_request(id: u32, request: &BootstrapRequest) -> Result<Vec<u8>, CodecError> {
    let mut out;
    match request {
        BootstrapRequest::Redeem { device_name, csr, password } => {
            out = header(REDEEM, id);
            put_field(&mut out, device_name.as_bytes(), 1, MAX_DEVICE_NAME)?;
            put_field(&mut out, csr, 1, MAX_CSR)?;
            put_field(&mut out, password.as_bytes(), 1, MAX_PASSWORD)?;
        }
        BootstrapRequest::ConfirmTotp { code } => {
            out = header(CONFIRM_TOTP, id);
            put_field(&mut out, code.as_bytes(), CODE_LEN, CODE_LEN)?;
        }
        BootstrapRequest::RedeemExternal { device_name, csr } => {
            out = header(REDEEM_EXTERNAL, id);
            put_field(&mut out, device_name.as_bytes(), 1, MAX_DEVICE_NAME)?;
            put_field(&mut out, csr, 1, MAX_CSR)?;
        }
        BootstrapRequest::ConfirmExternal { code, verifier, redirect_uri } => {
            out = header(CONFIRM_EXTERNAL, id);
            put_ascii(&mut out, code, 1, MAX_AUTH_CODE_BYTES)?;
            put_ascii(&mut out, verifier, MIN_VERIFIER_LEN, MAX_VERIFIER_LEN)?;
            put_ascii(&mut out, redirect_uri, 1, MAX_REDIRECT_BYTES)?;
        }
    }
    Ok(out)
}

pub fn decode_bootstrap_request(mut input: &[u8]) -> Result<(u32, BootstrapRequest), CodecError> {
    let (tag, id) = read_header(&mut input, &[REDEEM, CONFIRM_TOTP, REDEEM_EXTERNAL, CONFIRM_EXTERNAL])?;
    let request = match tag {
        REDEEM => BootstrapRequest::Redeem {
            device_name: read_string(&mut input, 1, MAX_DEVICE_NAME)?,
            csr: read_field(&mut input, 1, MAX_CSR)?.to_vec(),
            password: read_string(&mut input, 1, MAX_PASSWORD)?,
        },
        CONFIRM_TOTP => BootstrapRequest::ConfirmTotp { code: read_string(&mut input, CODE_LEN, CODE_LEN)? },
        REDEEM_EXTERNAL => BootstrapRequest::RedeemExternal {
            device_name: read_string(&mut input, 1, MAX_DEVICE_NAME)?,
            csr: read_field(&mut input, 1, MAX_CSR)?.to_vec(),
        },
        CONFIRM_EXTERNAL => BootstrapRequest::ConfirmExternal {
            code: read_ascii(&mut input, 1, MAX_AUTH_CODE_BYTES)?,
            verifier: read_ascii(&mut input, MIN_VERIFIER_LEN, MAX_VERIFIER_LEN)?,
            redirect_uri: read_ascii(&mut input, 1, MAX_REDIRECT_BYTES)?,
        },
        _ => return Err(CodecError::BadKind(tag)),
    };
    if !input.is_empty() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, request))
}

pub fn encode_bootstrap_response(id: u32, response: &BootstrapResponse) -> Result<Vec<u8>, CodecError> {
    let mut out;
    match response {
        BootstrapResponse::Setup { totp_uri } => {
            out = header(SETUP, id);
            put_field(&mut out, totp_uri.as_bytes(), 1, MAX_URI)?;
        }
        BootstrapResponse::Activated { certificate, issuer_certificate } => {
            out = header(ACTIVATED, id);
            put_field(&mut out, certificate, 1, MAX_CERT)?;
            put_field(&mut out, issuer_certificate, 1, MAX_CERT)?;
        }
        BootstrapResponse::Error { code } => {
            out = header(ERROR, id);
            out.extend_from_slice(&code.to_be_bytes());
        }
        BootstrapResponse::ExternalStart { issuer, client_id, authorization_endpoint, nonce } => {
            check_token(nonce)?;
            out = header(EXTERNAL_START, id);
            put_field(&mut out, issuer.as_bytes(), 1, MAX_URL_BYTES)?;
            put_field(&mut out, client_id.as_bytes(), 1, MAX_CLIENT_ID_BYTES)?;
            put_field(&mut out, authorization_endpoint.as_bytes(), 1, MAX_URL_BYTES)?;
            put_field(&mut out, nonce.as_bytes(), TOKEN_LEN, TOKEN_LEN)?;
        }
    }
    Ok(out)
}

pub fn decode_bootstrap_response(mut input: &[u8]) -> Result<(u32, BootstrapResponse), CodecError> {
    let (tag, id) = read_header(&mut input, &[SETUP, ACTIVATED, ERROR, EXTERNAL_START])?;
    let response = match tag {
        SETUP => BootstrapResponse::Setup { totp_uri: read_string(&mut input, 1, MAX_URI)? },
        ACTIVATED => BootstrapResponse::Activated {
            certificate: read_field(&mut input, 1, MAX_CERT)?.to_vec(),
            issuer_certificate: read_field(&mut input, 1, MAX_CERT)?.to_vec(),
        },
        ERROR => BootstrapResponse::Error { code: u16::from_be_bytes(take_array(&mut input)?) },
        EXTERNAL_START => {
            let issuer = read_string(&mut input, 1, MAX_URL_BYTES)?;
            let client_id = read_string(&mut input, 1, MAX_CLIENT_ID_BYTES)?;
            let authorization_endpoint = read_string(&mut input, 1, MAX_URL_BYTES)?;
            let nonce = read_string(&mut input, TOKEN_LEN, TOKEN_LEN)?;
            check_token(&nonce)?;
            BootstrapResponse::ExternalStart { issuer, client_id, authorization_endpoint, nonce }
        }
        _ => return Err(CodecError::BadKind(tag)),
    };
    if !input.is_empty() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, response))
}
