//! Token-bucket rate limiting (sign-in attempts, enrollment redemptions, messages). The clock is injected as
//! milliseconds so behaviour is exact and testable. Task T102.

use std::collections::HashMap;
use std::hash::Hash;

/// A bucket of `capacity` tokens refilling `refill_per_sec` tokens a second, counted in thousandths of a token so a
/// partial refill is exact (no floating point). A new bucket is full.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity_milli: u64,
    tokens_milli: u64,
    last_refill_ms: u64,
    refill_per_milli_ms: u64,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_per_sec: u32, now_ms: u64) -> Self {
        let capacity_milli = capacity as u64 * 1000;
        Self { capacity_milli, tokens_milli: capacity_milli, last_refill_ms: now_ms, refill_per_milli_ms: refill_per_sec as u64 }
    }

    /// Refill for the time since the bucket's clock, then take one whole token if there is one. A `now_ms` earlier than
    /// the bucket's clock refills nothing and does not move the clock back.
    pub fn try_take(&mut self, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.last_refill_ms);
        let refill = elapsed.saturating_mul(self.refill_per_milli_ms);
        self.tokens_milli = self.tokens_milli.saturating_add(refill).min(self.capacity_milli);
        self.last_refill_ms = now_ms.max(self.last_refill_ms);
        if self.tokens_milli >= 1000 {
            self.tokens_milli -= 1000;
            true
        } else {
            false
        }
    }

    /// Whole tokens there would be at `now_ms`, without taking any or changing the bucket.
    pub fn available(&self, now_ms: u64) -> u32 {
        let elapsed = now_ms.saturating_sub(self.last_refill_ms);
        let refill = elapsed.saturating_mul(self.refill_per_milli_ms);
        let total = self.tokens_milli.saturating_add(refill).min(self.capacity_milli);
        (total / 1000) as u32
    }
}

/// One `TokenBucket` per key, created full on a key's first use.
#[derive(Debug)]
pub struct Limiter<K> {
    buckets: HashMap<K, TokenBucket>,
    capacity: u32,
    refill_per_sec: u32,
}

impl<K: Eq + Hash + Clone> Limiter<K> {
    pub fn new(capacity: u32, refill_per_sec: u32) -> Self {
        Self { buckets: HashMap::new(), capacity, refill_per_sec }
    }

    /// `try_take` on the key's bucket.
    pub fn check(&mut self, key: &K, now_ms: u64) -> bool {
        let bucket = self.buckets.entry(key.clone()).or_insert_with(|| TokenBucket::new(self.capacity, self.refill_per_sec, now_ms));
        bucket.try_take(now_ms)
    }

    /// Drop the buckets that are full again at `now_ms` (they carry no state); returns how many were dropped.
    pub fn prune(&mut self, now_ms: u64) -> usize {
        let full_capacity = self.capacity;
        let before = self.buckets.len();
        self.buckets.retain(|_, b| b.available(now_ms) < full_capacity);
        before - self.buckets.len()
    }

    /// Buckets held.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}
