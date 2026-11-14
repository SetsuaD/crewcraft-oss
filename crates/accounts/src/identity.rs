//! The sign-in identity: one normalised email address per person.
//!
//! The same address is the person's identity in CrewCraft and in a companion mail app, so both must reduce what a
//! person types to the same string. Version 1 accepts plain ASCII addresses only (no quoted local parts, no IP
//! literals, no internationalised domains) and lowercases the whole address, because the mail server a deployment
//! uses treats the local part case-insensitively.

use crate::Error;

/// Longest local part (the RFC 5321 local-part size limit).
pub const MAX_LOCAL: usize = 64;
/// Longest domain (the RFC 5321 domain size limit).
pub const MAX_DOMAIN: usize = 253;

/// Normalise an address to CrewCraft's identity form, or `Err(BadEmail)`.
///
/// Rules: surrounding whitespace is trimmed; exactly one `@`; the local part is 1 to [`MAX_LOCAL`] characters from
/// `A-Z a-z 0-9` and ``!#$%&'*+-/=?^_`{|}~.``, with no leading, trailing or doubled `.`; the domain is 1 to
/// [`MAX_DOMAIN`] characters, at least two dot-separated labels, each label 1 to 63 characters of `A-Z a-z 0-9 -`
/// not starting or ending with `-`; any other character (including non-ASCII and inner whitespace) is refused. The
/// result is lowercased.
pub fn normalize_email(input: &str) -> Result<String, Error> {
    let trimmed = input.trim();

    // Refuse any byte that is not an ASCII graphic character (0x21..=0x7E).
    for b in trimmed.bytes() {
        if !(0x21..=0x7E).contains(&b) {
            return Err(Error::BadEmail);
        }
    }

    // Exactly one '@'.
    if trimmed.matches('@').count() != 1 {
        return Err(Error::BadEmail);
    }

    let (local, domain) = match trimmed.split_once('@') {
        Some(pair) => pair,
        None => return Err(Error::BadEmail),
    };

    // ---- Local part ----
    if local.is_empty() || local.len() > MAX_LOCAL {
        return Err(Error::BadEmail);
    }

    for c in local.chars() {
        if !is_local_allowed(c) {
            return Err(Error::BadEmail);
        }
    }

    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(Error::BadEmail);
    }

    // ---- Domain ----
    if domain.is_empty() || domain.len() > MAX_DOMAIN {
        return Err(Error::BadEmail);
    }

    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err(Error::BadEmail);
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::BadEmail);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::BadEmail);
        }
        for c in label.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' {
                return Err(Error::BadEmail);
            }
        }
    }

    Ok(trimmed.to_ascii_lowercase())
}

fn is_local_allowed(c: char) -> bool {
    matches!(
        c,
        'A'..='Z'
            | 'a'..='z'
            | '0'..='9'
            | '!'
            | '#'
            | '$'
            | '%'
            | '&'
            | '\''
            | '*'
            | '+'
            | '-'
            | '/'
            | '='
            | '?'
            | '^'
            | '_'
            | '`'
            | '{'
            | '|'
            | '}'
            | '~'
            | '.'
    )
}
