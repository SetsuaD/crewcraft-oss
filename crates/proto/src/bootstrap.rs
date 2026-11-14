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
//! - tag 160 `Redeemed`: `bytes certificate (1 to MAX_CERT) | str totp_uri (1 to MAX_URI)`
//! - tag 161 `Activated`: no fields
//! - tag 162 `Error`: `u16 code`
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapResponse {
    Redeemed { certificate: Vec<u8>, totp_uri: String },
    Activated,
    Error { code: u16 },
}

#[allow(clippy::todo, reason = "stubs until task T204 lands; remove this allow with them")]
pub fn encode_bootstrap_request(id: u32, request: &BootstrapRequest) -> Result<Vec<u8>, CodecError> {
    let _ = (id, request);
    todo!("T204: encode_bootstrap_request")
}

#[allow(clippy::todo, reason = "stubs until task T204 lands; remove this allow with them")]
pub fn decode_bootstrap_request(bytes: &[u8]) -> Result<(u32, BootstrapRequest), CodecError> {
    let _ = bytes;
    todo!("T204: decode_bootstrap_request")
}

#[allow(clippy::todo, reason = "stubs until task T204 lands; remove this allow with them")]
pub fn encode_bootstrap_response(id: u32, response: &BootstrapResponse) -> Result<Vec<u8>, CodecError> {
    let _ = (id, response);
    todo!("T204: encode_bootstrap_response")
}

#[allow(clippy::todo, reason = "stubs until task T204 lands; remove this allow with them")]
pub fn decode_bootstrap_response(bytes: &[u8]) -> Result<(u32, BootstrapResponse), CodecError> {
    let _ = bytes;
    todo!("T204: decode_bootstrap_response")
}
