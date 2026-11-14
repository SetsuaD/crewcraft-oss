//! Who is online, from client heartbeats. The clock is injected as milliseconds. Task T108.

/// A user is `Online` while their last heartbeat is less than `ONLINE_MS` old, `Away` while less than `AWAY_MS`, then
/// `Offline`. A clock reading earlier than the heartbeat counts as age 0.
pub const ONLINE_MS: u64 = 60_000;
pub const AWAY_MS: u64 = 600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Online,
    Away,
    Offline,
}

#[derive(Debug, Default)]
pub struct Presence {
    users: std::collections::HashMap<String, u64>,
}

impl Presence {
    pub fn new() -> Self {
        Self { users: std::collections::HashMap::new() }
    }

    /// Record a heartbeat. A timestamp older than the one held for that user is ignored.
    pub fn heartbeat(&mut self, user: &str, now_ms: u64) {
        match self.users.get_mut(user) {
            Some(held) => {
                if now_ms > *held {
                    *held = now_ms;
                }
            }
            None => {
                self.users.insert(user.to_string(), now_ms);
            }
        }
    }

    /// A user never seen is `Offline`.
    pub fn status(&self, user: &str, now_ms: u64) -> Status {
        match self.users.get(user) {
            None => Status::Offline,
            Some(&last) => {
                let age = now_ms.saturating_sub(last);
                if age < ONLINE_MS {
                    Status::Online
                } else if age < AWAY_MS {
                    Status::Away
                } else {
                    Status::Offline
                }
            }
        }
    }

    /// The users `Online` at `now_ms`, sorted.
    pub fn online(&self, now_ms: u64) -> Vec<String> {
        let mut result: Vec<String> =
            self.users.iter().filter(|&(_, last)| now_ms.saturating_sub(*last) < ONLINE_MS).map(|(user, _)| user.clone()).collect();
        result.sort();
        result
    }

    /// Forget the users `Offline` at `now_ms`; returns how many.
    pub fn prune(&mut self, now_ms: u64) -> usize {
        let to_remove: Vec<String> =
            self.users.iter().filter(|&(_, last)| now_ms.saturating_sub(*last) >= AWAY_MS).map(|(user, _)| user.clone()).collect();
        let count = to_remove.len();
        for user in to_remove {
            self.users.remove(&user);
        }
        count
    }
}
