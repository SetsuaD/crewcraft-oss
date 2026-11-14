//! Slowing down and locking out wrong guesses at a person's password or TOTP code (docs/SECURITY-DESIGN.md sections 4
//! and 8): each consecutive failure doubles the wait before the next attempt, and the tenth locks sign-in attempts for
//! `LOCK_MS`. The account is never locked for good: the lock expires, and an administrator can `reset` it at once.
//! The key is whatever the caller counts failures against (a normalised email, including addresses that do not exist,
//! so unknown addresses behave like known ones). Task T202.

use std::collections::HashMap;

/// The first failure makes the person wait this long; each further failure doubles it (1 s, 2 s, 4 s, ... 256 s).
pub const BASE_DELAY_MS: u64 = 1_000;
/// The failure that locks: the tenth in a row.
pub const LOCK_AFTER: u32 = 10;
/// How long the lock lasts from the failure that caused it.
pub const LOCK_MS: u64 = 15 * 60 * 1000;

/// Why an attempt may not be made yet. `retry_after_ms` is how long from the `now_ms` asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocked {
    Wait { retry_after_ms: u64 },
    Locked { retry_after_ms: u64 },
}

#[derive(Debug, Default)]
pub struct Throttle {
    // key -> (consecutive failures, time of the latest one)
    state: HashMap<String, (u32, u64)>,
}

#[allow(clippy::todo, reason = "stubs until task T202 lands; remove this allow with them")]
impl Throttle {
    pub fn new() -> Self {
        Self { state: HashMap::new() }
    }

    /// May `key` attempt at `now_ms`? After the n-th consecutive failure (1 to 9) at time `t`, attempts are blocked
    /// until `t + BASE_DELAY_MS * 2^(n-1)` (`Wait`); at that instant they are allowed again. The `LOCK_AFTER`-th
    /// failure blocks until `t + LOCK_MS` (`Locked`); once the lock has expired the key starts again from zero failures.
    /// A key with no failures is allowed. `retry_after_ms` is the blocked-until instant minus `now_ms`.
    pub fn check(&self, key: &str, now_ms: u64) -> Result<(), Blocked> {
        let _ = (key, now_ms, &self.state);
        todo!("T202: check")
    }

    /// Record a wrong password or code at `now_ms`. A failure made while the key is `Locked` does not extend the lock
    /// or raise the count; otherwise the count goes up by one and the latest-failure time becomes `now_ms`. If the lock
    /// had already expired, the count restarts at one.
    pub fn fail(&mut self, key: &str, now_ms: u64) {
        let _ = (key, now_ms);
        todo!("T202: fail")
    }

    /// A correct sign-in: forget the key's failures.
    pub fn succeed(&mut self, key: &str) {
        let _ = key;
        todo!("T202: succeed")
    }

    /// An administrator's reset: as `succeed`.
    pub fn reset(&mut self, key: &str) {
        let _ = key;
        todo!("T202: reset")
    }

    /// The consecutive failures held for the key (0 when none; a lock that has expired still reports its count until
    /// the next `fail`, `succeed` or `reset`).
    pub fn failures(&self, key: &str) -> u32 {
        let _ = key;
        todo!("T202: failures")
    }
}
