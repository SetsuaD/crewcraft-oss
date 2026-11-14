//! Messages typed while offline wait here until the server acknowledges them. Task T113.

use std::collections::BTreeMap;

/// The first retry waits `BASE_DELAY_MS`; each further failure doubles the wait, capped at `MAX_DELAY_MS`. After
/// `MAX_ATTEMPTS` failed sends a message is `Dead`: it stays for the user to see but is never due again.
pub const BASE_DELAY_MS: u64 = 1_000;
pub const MAX_DELAY_MS: u64 = 60_000;
pub const MAX_ATTEMPTS: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Pending,
    Dead,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub id: u64,
    pub body: String,
    /// Failed sends so far.
    pub attempts: u32,
    pub state: State,
}

#[derive(Debug)]
pub struct Outbox {
    entries: BTreeMap<u64, Entry>,
    next_due: BTreeMap<u64, u64>,
    next_id: u64,
}

impl Default for Outbox {
    fn default() -> Self {
        Self { entries: BTreeMap::new(), next_due: BTreeMap::new(), next_id: 1 }
    }
}

impl Outbox {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a message, due at once. Ids start at 1 and are never reused, even after an ack.
    pub fn push(&mut self, body: &str, now_ms: u64) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let entry = Entry { id, body: body.to_string(), attempts: 0, state: State::Pending };
        self.entries.insert(id, entry);
        self.next_due.insert(id, now_ms);
        id
    }

    /// Ids of the `Pending` entries whose next try is at or before `now_ms`, lowest id first.
    pub fn due(&self, now_ms: u64) -> Vec<u64> {
        self.entries
            .iter()
            .filter(|(id, e)| e.state == State::Pending && self.next_due.get(id).copied().unwrap_or(u64::MAX) <= now_ms)
            .map(|(id, _)| *id)
            .collect()
    }

    /// The server has it: remove the entry. False if the id is unknown.
    pub fn ack(&mut self, id: u64) -> bool {
        let removed = self.entries.remove(&id).is_some();
        if removed {
            self.next_due.remove(&id);
        }
        removed
    }

    /// A send failed at `now_ms`: count it, then schedule the next try or, at `MAX_ATTEMPTS` failures, mark it `Dead`.
    /// False if the id is unknown or already `Dead`.
    pub fn fail(&mut self, id: u64, now_ms: u64) -> bool {
        let entry = match self.entries.get_mut(&id) {
            Some(e) => e,
            None => return false,
        };
        if entry.state == State::Dead {
            return false;
        }
        entry.attempts += 1;
        if entry.attempts >= MAX_ATTEMPTS {
            entry.state = State::Dead;
        } else {
            let delay = Self::backoff_delay(entry.attempts);
            let next = now_ms.saturating_add(delay);
            self.next_due.insert(id, next);
        }
        true
    }

    /// When the entry is next due; `None` if it is `Dead` or unknown.
    pub fn next_try(&self, id: u64) -> Option<u64> {
        let entry = self.entries.get(&id)?;
        if entry.state == State::Dead { None } else { self.next_due.get(&id).copied() }
    }

    pub fn get(&self, id: u64) -> Option<Entry> {
        self.entries.get(&id).cloned()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// After the `n`-th failure the delay is `min(BASE_DELAY_MS * 2^(n-1), MAX_DELAY_MS)`.
    fn backoff_delay(attempts: u32) -> u64 {
        let shift = attempts.saturating_sub(1);
        BASE_DELAY_MS.saturating_mul(1u64 << shift).min(MAX_DELAY_MS)
    }
}
