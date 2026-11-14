//! RFC 4648 base32 (the standard alphabet `A-Z2-7`), as authenticator apps expect TOTP secrets.

use crate::Error;

const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encodes with `=` padding to a multiple of 8 characters (RFC 4648 section 6).
pub fn encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;

    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let value = ((buffer >> bits) & 31) as usize;
            out.push(BASE32_ALPHABET[value] as char);
        }
        buffer &= (1u64 << bits) - 1;
    }

    if bits > 0 {
        let value = ((buffer << (5 - bits)) & 31) as usize;
        out.push(BASE32_ALPHABET[value] as char);
    }

    while !out.len().is_multiple_of(8) {
        out.push('=');
    }

    out
}

/// Encodes without padding: the form put in an `otpauth://` URI.
pub fn encode_nopad(data: &[u8]) -> String {
    encode(data).trim_end_matches('=').to_string()
}

/// Decodes, accepting upper or lower case, with or without `=` padding, and ignoring spaces and hyphens
/// (people retype secrets in groups). Anything else, or a length no encoder could produce, is [`Error::BadBase32`].
pub fn decode(text: &str) -> Result<Vec<u8>, Error> {
    let mut normalized = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            ' ' | '-' => {}
            'A'..='Z' => normalized.push(c),
            'a'..='z' => normalized.push(c.to_ascii_uppercase()),
            '2'..='7' => normalized.push(c),
            '=' => normalized.push(c),
            _ => return Err(Error::BadBase32),
        }
    }

    let (data, padding) = match normalized.find('=') {
        Some(idx) => (&normalized[..idx], &normalized[idx..]),
        None => (&normalized[..], ""),
    };
    if padding.bytes().any(|b| b != b'=') {
        return Err(Error::BadBase32);
    }

    let data_len = data.len();
    if matches!(data_len % 8, 1 | 3 | 6) {
        return Err(Error::BadBase32);
    }

    if !padding.is_empty() && padding.len() != (8 - (data_len % 8)) % 8 {
        return Err(Error::BadBase32);
    }

    let mut bits: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut decoded = Vec::new();

    for c in data.chars() {
        let value = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return Err(Error::BadBase32),
        };
        bits = (bits << 5) | u64::from(value);
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            decoded.push(((bits >> bit_count) & 0xff) as u8);
            bits &= (1u64 << bit_count) - 1;
        }
    }

    Ok(decoded)
}
