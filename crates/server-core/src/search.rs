//! A small in-memory full-text index over a room's messages. Task T112.

use std::collections::HashMap;

/// The search terms of `text`, in order with duplicates kept: split on every character that is not
/// `char::is_alphanumeric` (so non-ASCII letters belong to terms), lowercase each term (`str::to_lowercase`), and drop
/// terms shorter than 2 characters.
pub fn terms(text: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();

    for ch in text.chars() {
        if ch.is_alphanumeric() {
            current.push(ch);
        } else if !current.is_empty() {
            let term = current.to_lowercase();
            if term.chars().count() >= 2 {
                result.push(term);
            }
            current.clear();
        }
    }
    if !current.is_empty() {
        let term = current.to_lowercase();
        if term.chars().count() >= 2 {
            result.push(term);
        }
    }

    result
}

#[derive(Debug, Default)]
pub struct Index {
    entries: HashMap<u64, Vec<String>>,
}

impl Index {
    pub fn new() -> Self {
        Self::default()
    }

    /// Index a message under its cursor. Inserting a cursor again replaces its old text.
    pub fn insert(&mut self, cursor: u64, text: &str) {
        self.entries.insert(cursor, terms(text));
    }

    /// Forget a cursor (no effect if it was never indexed).
    pub fn remove(&mut self, cursor: u64) {
        self.entries.remove(&cursor);
    }

    /// Cursors whose text matches EVERY term of `query` (AND), newest (highest cursor) first, at most `limit` of them.
    /// A query term matches a message term that starts with it (prefix search). A query with no terms matches nothing.
    pub fn search(&self, query: &str, limit: usize) -> Vec<u64> {
        let query_terms = terms(query);
        if query_terms.is_empty() {
            return Vec::new();
        }

        let mut cursors: Vec<u64> = self.entries.keys().copied().collect();
        cursors.sort_unstable_by(|a, b| b.cmp(a));

        let mut matches = Vec::new();
        for cursor in cursors {
            if matches.len() >= limit {
                break;
            }
            let text_terms = &self.entries[&cursor];
            let all = query_terms.iter().all(|q| text_terms.iter().any(|t| t.starts_with(q.as_str())));
            if all {
                matches.push(cursor);
            }
        }
        matches
    }
}
