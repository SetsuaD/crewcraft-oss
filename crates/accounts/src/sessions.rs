//! Server-side sign-in sessions. The server keeps only the SHA-256 of each token, so a copy of the session table cannot
//! be replayed as sign-ins (docs/SECURITY-DESIGN.md: server-side sessions). Task T114.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A session ends after this long without a request...
pub const IDLE_MS: u64 = 30 * 60 * 1000;
/// ...and at this age however busy it is.
pub const ABSOLUTE_MS: u64 = 12 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub user: String,
    pub device: String,
    pub created_ms: u64,
    pub last_seen_ms: u64,
}

#[derive(Debug, Default)]
pub struct Sessions {
    sessions: HashMap<String, Session>,
}

impl Sessions {
    pub fn new() -> Self {
        Self { sessions: HashMap::new() }
    }

    /// Start a session from 32 bytes the caller drew from the operating system's RNG. Returns the token the client keeps:
    /// those bytes in base64url without padding (43 characters). Only SHA-256 of the token string is stored.
    pub fn create(&mut self, random: [u8; 32], user: &str, device: &str, now_ms: u64) -> String {
        let token = URL_SAFE_NO_PAD.encode(random.as_slice());
        let key = token_key(&token);
        self.sessions.insert(key, Session { user: user.to_string(), device: device.to_string(), created_ms: now_ms, last_seen_ms: now_ms });
        token
    }

    /// The session for a token if it is live: less than `IDLE_MS` since it was last seen and less than `ABSOLUTE_MS`
    /// since it was created. A live lookup sets `last_seen_ms = now_ms` and returns the updated session; a dead one is
    /// removed and gives `None`, as does an unknown token.
    pub fn validate(&mut self, token: &str, now_ms: u64) -> Option<Session> {
        self.validate_matching(token, now_ms, |_| true)
    }

    /// Validate a token against the user and device identified by the verified client certificate.
    /// A mismatched identity leaves the owner's session untouched.
    pub fn validate_for(&mut self, token: &str, user: &str, device: &str, now_ms: u64) -> Option<Session> {
        self.validate_matching(token, now_ms, |session| session.user == user && session.device == device)
    }

    fn validate_matching(&mut self, token: &str, now_ms: u64, matches_identity: impl FnOnce(&Session) -> bool) -> Option<Session> {
        let key = token_key(token);
        let session = self.sessions.get_mut(&key)?;
        if !matches_identity(session) {
            return None;
        }
        if now_ms.saturating_sub(session.last_seen_ms) < IDLE_MS && now_ms.saturating_sub(session.created_ms) < ABSOLUTE_MS {
            session.last_seen_ms = now_ms;
            return Some(session.clone());
        }
        self.sessions.remove(&key);
        None
    }

    /// End one session; false if the token is unknown.
    pub fn revoke(&mut self, token: &str) -> bool {
        let key = token_key(token);
        self.sessions.remove(&key).is_some()
    }

    /// End every session of `user` on `device`; returns how many.
    pub fn revoke_device(&mut self, user: &str, device: &str) -> usize {
        let keys: Vec<String> =
            self.sessions.iter().filter(|(_, session)| session.user == user && session.device == device).map(|(key, _)| key.clone()).collect();
        let count = keys.len();
        for key in keys {
            self.sessions.remove(&key);
        }
        count
    }

    /// End every session of `user`; returns how many.
    pub fn revoke_user(&mut self, user: &str) -> usize {
        let keys: Vec<String> = self.sessions.iter().filter(|(_, session)| session.user == user).map(|(key, _)| key.clone()).collect();
        let count = keys.len();
        for key in keys {
            self.sessions.remove(&key);
        }
        count
    }

    /// What the table is keyed by, sorted: the lowercase hex SHA-256 of each live token. (Lets a test prove no raw
    /// token is kept.)
    pub fn stored_keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self.sessions.keys().cloned().collect();
        keys.sort();
        keys
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

fn token_key(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let bytes: &[u8] = digest.as_ref();
    let mut key = String::with_capacity(64);
    for byte in bytes {
        key.push_str(&format!("{:02x}", *byte));
    }
    key
}
