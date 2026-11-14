//! Which messages a room's retention rules remove. The server applies its own policy and the room's together; a legal
//! hold stops all removal. The clock is passed in as milliseconds. Task T134.

/// One day in milliseconds.
pub const DAY_MS: u64 = 86_400_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Keep everything.
    Forever,
    /// Remove a message once it is at least this many whole days old (`posted_ms + days * DAY_MS <= now_ms`). A message
    /// posted after `now_ms` has not reached any age, so it is kept; `MaxAgeDays(0)` removes every message posted at or
    /// before `now_ms`.
    MaxAgeDays(u32),
    /// Keep the newest this many messages (highest cursors) and remove the rest. `MaxCount(0)` removes all of them.
    MaxCount(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Msg {
    pub cursor: u64,
    pub posted_ms: u64,
    /// A pinned message is never removed and does not count toward `MaxCount`.
    pub pinned: bool,
}

/// The cursors `policy` alone removes from `messages` at `now_ms`, in ascending order. Pinned messages are skipped, and
/// the order of `messages` does not matter.
pub fn removed_by(policy: Policy, messages: &[Msg], now_ms: u64) -> Vec<u64> {
    let mut removed: Vec<u64> = Vec::new();

    match policy {
        Policy::Forever => {}
        Policy::MaxAgeDays(days) => {
            let threshold = (days as u64) * DAY_MS;
            for msg in messages {
                if msg.pinned {
                    continue;
                }
                if msg.posted_ms.saturating_add(threshold) <= now_ms {
                    removed.push(msg.cursor);
                }
            }
        }
        Policy::MaxCount(max) => {
            let mut candidates: Vec<&Msg> = messages.iter().filter(|m| !m.pinned).collect();
            candidates.sort_by_key(|m| m.cursor);
            let keep = max.min(candidates.len());
            let to_remove = candidates.len() - keep;
            for msg in candidates.iter().take(to_remove) {
                removed.push(msg.cursor);
            }
        }
    }

    removed.sort_unstable();
    removed
}

/// The cursors to remove from a room, in ascending order without duplicates: those the server's policy removes plus
/// those the room's policy removes (so a room can only keep less than the server allows, never more). Nothing at all
/// while `legal_hold` is set. `room` is `None` when the room has no policy of its own.
pub fn to_remove(server: Policy, room: Option<Policy>, legal_hold: bool, messages: &[Msg], now_ms: u64) -> Vec<u64> {
    if legal_hold {
        return Vec::new();
    }
    let mut removed = removed_by(server, messages, now_ms);
    if let Some(room_policy) = room {
        for cursor in removed_by(room_policy, messages, now_ms) {
            if !removed.contains(&cursor) {
                removed.push(cursor);
            }
        }
    }
    removed.sort_unstable();
    removed.dedup();
    removed
}
