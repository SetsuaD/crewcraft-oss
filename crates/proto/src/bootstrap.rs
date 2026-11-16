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
//!
//! A response is `u8 tag | u32 id | fields`, where `id` repeats the request's:
//! - tag 160 `Setup`: `str totp_uri (1 to MAX_URI)`
//! - tag 161 `Activated`: `bytes certificate (1 to MAX_CERT) | bytes issuer_certificate (1 to MAX_CERT)`
//! - tag 162 `Error`: `u16 code`
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

pub const MAX_DEVICE_NAME: usize = 64;
pub const MAX_CSR: usize = 4096;
pub const MAX_PASSWORD: usize = 1024;
/// A TOTP code is six digits; the codec checks only the length.
pub const CODE_LEN: usize = 6;
pub const MAX_CERT: usize = 4096;
pub const MAX_URI: usize = 512;

#[derive(Clone, PartialEq, Eq)]
pub enum BootstrapRequest {
    Redeem { device_name: String, csr: Vec<u8>, password: String },
    ConfirmTotp { code: String },
}

// A password and a code are secrets: they never reach logs or panics.
impl std::fmt::Debug for BootstrapRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootstrapRequest::Redeem { device_name, csr, .. } => {
                write!(f, "Redeem {{ device_name: {device_name:?}, csr: <{} bytes>, password: .. }}", csr.len())
            }
            BootstrapRequest::ConfirmTotp { .. } => f.write_str("ConfirmTotp { code: .. }"),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum BootstrapResponse {
    Setup { totp_uri: String },
    Activated { certificate: Vec<u8>, issuer_certificate: Vec<u8> },
    Error { code: u16 },
}

impl std::fmt::Debug for BootstrapResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setup { .. } => f.write_str("Setup { totp_uri: .. }"),
            Self::Activated { .. } => f.write_str("Activated { certificate: .., issuer_certificate: .. }"),
            Self::Error { code } => f.debug_struct("Error").field("code", code).finish(),
        }
    }
}

const REDEEM: u8 = 32;
const CONFIRM_TOTP: u8 = 33;
const SETUP: u8 = 160;
const ACTIVATED: u8 = 161;
const ERROR: u8 = 162;

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

fn read_header(input: &mut &[u8], tags: std::ops::RangeInclusive<u8>) -> Result<(u8, u32), CodecError> {
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
    }
    Ok(out)
}

pub fn decode_bootstrap_request(mut input: &[u8]) -> Result<(u32, BootstrapRequest), CodecError> {
    let (tag, id) = read_header(&mut input, REDEEM..=CONFIRM_TOTP)?;
    let request = match tag {
        REDEEM => BootstrapRequest::Redeem {
            device_name: read_string(&mut input, 1, MAX_DEVICE_NAME)?,
            csr: read_field(&mut input, 1, MAX_CSR)?.to_vec(),
            password: read_string(&mut input, 1, MAX_PASSWORD)?,
        },
        CONFIRM_TOTP => BootstrapRequest::ConfirmTotp { code: read_string(&mut input, CODE_LEN, CODE_LEN)? },
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
    }
    Ok(out)
}

pub fn decode_bootstrap_response(mut input: &[u8]) -> Result<(u32, BootstrapResponse), CodecError> {
    let (tag, id) = read_header(&mut input, SETUP..=ERROR)?;
    let response = match tag {
        SETUP => BootstrapResponse::Setup { totp_uri: read_string(&mut input, 1, MAX_URI)? },
        ACTIVATED => BootstrapResponse::Activated {
            certificate: read_field(&mut input, 1, MAX_CERT)?.to_vec(),
            issuer_certificate: read_field(&mut input, 1, MAX_CERT)?.to_vec(),
        },
        ERROR => BootstrapResponse::Error { code: u16::from_be_bytes(take_array(&mut input)?) },
        _ => return Err(CodecError::BadKind(tag)),
    };
    if !input.is_empty() {
        return Err(CodecError::TrailingBytes);
    }
    Ok((id, response))
}
