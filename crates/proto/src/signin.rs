//! Sign-in payloads for a connection with an already verified enrolled device certificate. Task T152.
//!
//! Request: tag 34, email and password as `u16` big-endian byte lengths followed by UTF-8, then six ASCII
//! decimal digits. A reply is tag 163 followed by a 43-byte unpadded base64url token, or tag 164 alone.
//! Exactly one frame contains each payload. Device identity and authentication are supplied by the server.
//! Codec errors describe malformed payloads. A well-formed request that fails authentication always gets the
//! same `Refused` reply, with no reason field.

use std::fmt;

use crate::message::CodecError;

pub const MAX_EMAIL_BYTES: usize = 320;
pub const MAX_PASSWORD_BYTES: usize = 1024;
pub const CODE_LEN: usize = 6;
pub const TOKEN_LEN: usize = 43;

const SIGN_IN: u8 = 34;
const ACCEPTED: u8 = 163;
const REFUSED: u8 = 164;

#[derive(PartialEq, Eq)]
pub struct SignIn<'a> {
    pub email: &'a str,
    pub password: &'a str,
    pub code: &'a str,
}

impl fmt::Debug for SignIn<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignIn { .. }")
    }
}

#[derive(PartialEq, Eq)]
pub enum Reply<'a> {
    Accepted { token: &'a str },
    Refused,
}

impl fmt::Debug for Reply<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted { .. } => f.write_str("Accepted { token: .. }"),
            Self::Refused => f.write_str("Refused"),
        }
    }
}

/// Encode the sign-in payload. An empty password is representable so the verifier can refuse it uniformly.
pub fn encode_request(request: &SignIn<'_>) -> Result<Vec<u8>, CodecError> {
    check_length(request.email.len(), 1, MAX_EMAIL_BYTES)?;
    check_length(request.password.len(), 0, MAX_PASSWORD_BYTES)?;
    check_code(request.code)?;

    let mut out = vec![SIGN_IN];
    for field in [request.email, request.password] {
        out.extend_from_slice(&(field.len() as u16).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out.extend_from_slice(request.code.as_bytes());
    Ok(out)
}

/// Decode exactly one sign-in payload, borrowing the fields from the caller-owned frame.
pub fn decode_request(input: &[u8]) -> Result<SignIn<'_>, CodecError> {
    let (&tag, mut input) = input.split_first().ok_or(CodecError::Truncated)?;
    if tag != SIGN_IN {
        return Err(CodecError::BadKind(tag));
    }
    let email = read_text(&mut input, 1, MAX_EMAIL_BYTES)?;
    let password = read_text(&mut input, 0, MAX_PASSWORD_BYTES)?;
    let code = utf8(take_bytes(&mut input, CODE_LEN)?)?;
    check_code(code)?;
    if !input.is_empty() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(SignIn { email, password, code })
}

pub fn encode_reply(reply: &Reply<'_>) -> Result<Vec<u8>, CodecError> {
    match reply {
        Reply::Refused => Ok(vec![REFUSED]),
        Reply::Accepted { token } => {
            check_token(token)?;
            let mut out = vec![ACCEPTED];
            out.extend_from_slice(token.as_bytes());
            Ok(out)
        }
    }
}

/// Decode exactly one reply without making a second copy of the token.
pub fn decode_reply(input: &[u8]) -> Result<Reply<'_>, CodecError> {
    let (&tag, mut input) = input.split_first().ok_or(CodecError::Truncated)?;
    let reply = match tag {
        ACCEPTED => {
            let token = utf8(take_bytes(&mut input, TOKEN_LEN)?)?;
            check_token(token)?;
            Reply::Accepted { token }
        }
        REFUSED => Reply::Refused,
        _ => return Err(CodecError::BadKind(tag)),
    };
    if !input.is_empty() {
        return Err(CodecError::TrailingBytes);
    }
    Ok(reply)
}

fn check_length(length: usize, min: usize, max: usize) -> Result<(), CodecError> {
    if (min..=max).contains(&length) { Ok(()) } else { Err(CodecError::FieldLength) }
}

fn check_code(code: &str) -> Result<(), CodecError> {
    if code.len() != CODE_LEN || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CodecError::FieldLength);
    }
    Ok(())
}

fn check_token(token: &str) -> Result<(), CodecError> {
    // After 42 full sextets, a 32-byte token has four remaining bits. The last sextet's two padding bits must be zero.
    const TOKEN_ENDINGS: &[u8] = b"AEIMQUYcgkosw048";
    let Some((last, prefix)) = token.as_bytes().split_last() else {
        return Err(CodecError::FieldLength);
    };
    if prefix.len() != TOKEN_LEN - 1
        || !prefix.iter().all(|&byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || !TOKEN_ENDINGS.contains(last)
    {
        return Err(CodecError::FieldLength);
    }
    Ok(())
}

fn take_bytes<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], CodecError> {
    let (field, rest) = input.split_at_checked(length).ok_or(CodecError::Truncated)?;
    *input = rest;
    Ok(field)
}

fn read_text<'a>(input: &mut &'a [u8], min: usize, max: usize) -> Result<&'a str, CodecError> {
    let (length, rest) = input.split_first_chunk().ok_or(CodecError::Truncated)?;
    *input = rest;
    let length = usize::from(u16::from_be_bytes(*length));
    check_length(length, min, max)?;
    utf8(take_bytes(input, length)?)
}

fn utf8(bytes: &[u8]) -> Result<&str, CodecError> {
    str::from_utf8(bytes).map_err(|_| CodecError::BadUtf8)
}
