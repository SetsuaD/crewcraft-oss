//! A strict subset of TOML for small, human-edited files: theme addons and release manifests.
//!
//! Owns: reading `[section]` headers and `key = value` lines, where a value is a basic `"string"` or a whole number,
//! and refusing everything else with the line number. Every file it accepts is valid TOML, so ordinary editors and
//! tools work on it; the subset is small enough to read completely and has no dependencies.
//! Called by: `crewcraft-theme` (theme addons), `crewcraft-update` (release manifests).
//!
//! Refused on purpose: arrays, inline tables, multi-line and literal strings, floats, dates, dotted keys, keys before the
//! first section, duplicate sections or keys, escapes other than `\"` and `\\`, and control characters in strings.

use std::collections::BTreeMap;
use std::fmt;

/// A value: a basic string or a whole number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Int(i64),
}

/// One `key = value` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// 1-based line number, for error messages.
    pub line: usize,
    pub value: Value,
}

/// One `[section]` and its keys.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Section {
    /// 1-based line number of the header.
    pub line: usize,
    pub entries: BTreeMap<String, Entry>,
}

/// A parsed file: sections by name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Document {
    pub sections: BTreeMap<String, Section>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The file is larger than the caller allows.
    TooLarge {
        bytes: usize,
        max: usize,
    },
    /// A line that is not a header, a `key = value`, a comment or blank.
    Syntax {
        line: usize,
        reason: &'static str,
    },
    DuplicateSection {
        line: usize,
        section: String,
    },
    DuplicateKey {
        line: usize,
        key: String,
    },
    /// A section the caller's schema does not know.
    UnknownSection {
        line: usize,
        section: String,
    },
    /// A key the caller's schema does not know.
    UnknownKey {
        line: usize,
        section: String,
        key: String,
    },
    MissingSection {
        section: String,
    },
    MissingKey {
        section: String,
        key: String,
    },
    /// A key whose value has the wrong type or is out of range.
    BadValue {
        line: usize,
        key: String,
        reason: &'static str,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::TooLarge { bytes, max } => write!(f, "file is {bytes} bytes; the limit is {max}"),
            Error::Syntax { line, reason } => write!(f, "line {line}: {reason}"),
            Error::DuplicateSection { line, section } => write!(f, "line {line}: section [{section}] appears twice"),
            Error::DuplicateKey { line, key } => write!(f, "line {line}: key `{key}` appears twice in its section"),
            Error::UnknownSection { line, section } => write!(f, "line {line}: unknown section [{section}]"),
            Error::UnknownKey { line, section, key } => write!(f, "line {line}: unknown key `{key}` in [{section}]"),
            Error::MissingSection { section } => write!(f, "missing section [{section}]"),
            Error::MissingKey { section, key } => write!(f, "missing key `{key}` in [{section}]"),
            Error::BadValue { line, key, reason } => write!(f, "line {line}: `{key}`: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

/// Section names: one or more dot-separated parts of `[a-z0-9-]`, each 1 to 64 characters.
fn valid_section_name(name: &str) -> bool {
    !name.is_empty() && name.split('.').all(valid_key)
}

/// Keys: 1 to 64 characters of `[a-z0-9-]`.
pub fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 64 && key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_comment_or_empty(s: &str) -> bool {
    let t = s.trim();
    t.is_empty() || t.starts_with('#')
}

fn parse_value(s: &str, line: usize) -> Result<Value, Error> {
    if let Some(body) = s.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = body.chars();
        loop {
            match chars.next() {
                None => return Err(Error::Syntax { line, reason: "the string has no closing quote" }),
                Some('"') => break,
                Some('\\') => match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    _ => return Err(Error::Syntax { line, reason: "only the escapes \\\" and \\\\ are allowed" }),
                },
                Some(c) if c.is_control() => {
                    return Err(Error::Syntax { line, reason: "control characters are not allowed in a string" });
                }
                Some(c) => out.push(c),
            }
        }
        let tail: String = chars.collect();
        if !is_comment_or_empty(&tail) {
            return Err(Error::Syntax { line, reason: "unexpected text after the value" });
        }
        return Ok(Value::Str(out));
    }
    let number = s.split('#').next().unwrap_or_default().trim();
    if number.is_empty() || number.len() > 18 || !number.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Syntax { line, reason: "a value is a \"string\" or a whole number" });
    }
    if number.len() > 1 && number.starts_with('0') {
        return Err(Error::Syntax { line, reason: "a number may not start with 0" });
    }
    number.parse::<i64>().map(Value::Int).map_err(|_| Error::Syntax { line, reason: "the number is too large" })
}

/// Parse `text`, refusing files over `max_bytes`.
pub fn parse(text: &str, max_bytes: usize) -> Result<Document, Error> {
    if text.len() > max_bytes {
        return Err(Error::TooLarge { bytes: text.len(), max: max_bytes });
    }
    let mut doc = Document::default();
    let mut current: Option<String> = None;
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim();
        if is_comment_or_empty(trimmed) {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix('[') {
            let (name, tail) = rest.split_once(']').ok_or(Error::Syntax { line, reason: "a section header needs a closing ]" })?;
            if !is_comment_or_empty(tail) {
                return Err(Error::Syntax { line, reason: "unexpected text after the section header" });
            }
            let name = name.trim();
            if !valid_section_name(name) {
                return Err(Error::Syntax { line, reason: "section names use a-z, 0-9, - and dots" });
            }
            if doc.sections.contains_key(name) {
                return Err(Error::DuplicateSection { line, section: name.to_string() });
            }
            doc.sections.insert(name.to_string(), Section { line, entries: BTreeMap::new() });
            current = Some(name.to_string());
            continue;
        }
        let (key, rest) = trimmed.split_once('=').ok_or(Error::Syntax { line, reason: "expected key = value" })?;
        let key = key.trim();
        if !valid_key(key) {
            return Err(Error::Syntax { line, reason: "keys use a-z, 0-9 and -" });
        }
        let value = parse_value(rest.trim(), line)?;
        let section = current
            .as_ref()
            .and_then(|name| doc.sections.get_mut(name))
            .ok_or(Error::Syntax { line, reason: "a key must follow a [section] header" })?;
        if section.entries.contains_key(key) {
            return Err(Error::DuplicateKey { line, key: key.to_string() });
        }
        section.entries.insert(key.to_string(), Entry { line, value });
    }
    Ok(doc)
}

impl Document {
    /// Refuse any section that is not named exactly in `allowed` or does not start with one of `allowed_prefixes`.
    pub fn check_sections(&self, allowed: &[&str], allowed_prefixes: &[&str]) -> Result<(), Error> {
        for (name, section) in &self.sections {
            let known = allowed.contains(&name.as_str()) || allowed_prefixes.iter().any(|p| name.starts_with(p));
            if !known {
                return Err(Error::UnknownSection { line: section.line, section: name.clone() });
            }
        }
        Ok(())
    }

    /// The section, or `MissingSection`.
    pub fn require(&self, name: &str) -> Result<&Section, Error> {
        self.sections.get(name).ok_or_else(|| Error::MissingSection { section: name.to_string() })
    }
}

impl Section {
    /// Refuse any key not in `allowed`; `section` is the name used in the error.
    pub fn check_keys(&self, section: &str, allowed: &[&str]) -> Result<(), Error> {
        for (key, entry) in &self.entries {
            if !allowed.contains(&key.as_str()) {
                return Err(Error::UnknownKey { line: entry.line, section: section.to_string(), key: key.clone() });
            }
        }
        Ok(())
    }

    /// An optional string key: `Ok(None)` when absent, `BadValue` when it is a number.
    pub fn opt_str(&self, key: &str) -> Result<Option<(&str, usize)>, Error> {
        match self.entries.get(key) {
            None => Ok(None),
            Some(Entry { line, value: Value::Str(s) }) => Ok(Some((s.as_str(), *line))),
            Some(Entry { line, value: Value::Int(_) }) => Err(Error::BadValue { line: *line, key: key.to_string(), reason: "expected a \"string\"" }),
        }
    }

    /// A required string key.
    pub fn req_str(&self, section: &str, key: &str) -> Result<(&str, usize), Error> {
        self.opt_str(key)?.ok_or_else(|| Error::MissingKey { section: section.to_string(), key: key.to_string() })
    }

    /// An optional whole-number key: `Ok(None)` when absent, `BadValue` when it is a string.
    pub fn opt_int(&self, key: &str) -> Result<Option<(i64, usize)>, Error> {
        match self.entries.get(key) {
            None => Ok(None),
            Some(Entry { line, value: Value::Int(n) }) => Ok(Some((*n, *line))),
            Some(Entry { line, value: Value::Str(_) }) => {
                Err(Error::BadValue { line: *line, key: key.to_string(), reason: "expected a whole number" })
            }
        }
    }

    /// A required whole-number key.
    pub fn req_int(&self, section: &str, key: &str) -> Result<(i64, usize), Error> {
        self.opt_int(key)?.ok_or_else(|| Error::MissingKey { section: section.to_string(), key: key.to_string() })
    }
}
