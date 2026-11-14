//! Room display names and the URL slugs made from them. Task T106.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameError {
    Empty,
    TooLong,
    ControlCharacter,
}

/// The cleaned display name. Any control character (`char::is_control`) anywhere is `ControlCharacter`. Otherwise
/// trim, collapse every run of whitespace to one ASCII space, and require 1 to 64 characters (chars, not bytes).
pub fn validate(name: &str) -> Result<String, NameError> {
    if name.chars().any(|c| c.is_control()) {
        return Err(NameError::ControlCharacter);
    }

    let cleaned = name.split_whitespace().collect::<Vec<_>>().join(" ");
    let char_count = cleaned.chars().count();

    if char_count == 0 {
        return Err(NameError::Empty);
    }
    if char_count > 64 {
        return Err(NameError::TooLong);
    }

    Ok(cleaned)
}

/// A URL slug: ASCII letters (lowercased) and digits are kept, every run of any other characters becomes one `-`, with
/// no `-` at either end. Cut to at most 48 characters, trimming a `-` the cut leaves at the end. Empty becomes `room`.
pub fn slug(name: &str) -> String {
    let mut result = String::new();
    let mut pending_separator = false;

    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            if pending_separator && !result.is_empty() {
                result.push('-');
            }
            result.push(c.to_ascii_lowercase());
            pending_separator = false;
        } else {
            pending_separator = true;
        }
    }

    let normalized = result.trim_end_matches('-').to_string();
    if normalized.is_empty() {
        return "room".to_string();
    }

    if normalized.chars().count() > 48 {
        let truncated: String = normalized.chars().take(48).collect();
        let trimmed = truncated.trim_end_matches('-').to_string();
        if trimmed.is_empty() {
            return "room".to_string();
        }
        return trimmed;
    }

    normalized
}
