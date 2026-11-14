//! The per-room event log that clients sync from with a cursor (docs/SPEC.md: WebSocket with a cursor log). Task T101.
use std::collections::VecDeque;

/// What `EventLog::since` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Since<T> {
    /// Every event after the cursor, oldest first, each with its cursor.
    Events(Vec<(u64, T)>),
    /// An event the client has not seen was already dropped; it must resync. `oldest` is the oldest cursor still held.
    Gap { oldest: u64 },
}

/// An append-only log that keeps the newest `capacity` events. Cursors start at 1 and only grow.
#[derive(Debug)]
pub struct EventLog<T> {
    events: VecDeque<(u64, T)>,
    head: u64,
    capacity: usize,
}

impl<T: Clone> EventLog<T> {
    /// A log keeping at most `capacity` events (a capacity of 0 is treated as 1).
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self { events: VecDeque::new(), head: 0, capacity }
    }

    /// Append an event and return its cursor: 1 for the first event, then 2, 3, ...
    pub fn append(&mut self, event: T) -> u64 {
        self.head += 1;
        self.events.push_back((self.head, event));
        while self.events.len() > self.capacity {
            self.events.pop_front();
        }
        self.head
    }

    /// The newest cursor; 0 while nothing has been appended.
    pub fn head(&self) -> u64 {
        self.head
    }

    /// Events after `cursor`, the last one the client already has. A cursor at or past `head` gets `Events(vec![])`.
    pub fn since(&self, cursor: u64) -> Since<T> {
        if self.events.is_empty() || cursor >= self.head {
            return Since::Events(vec![]);
        }
        let oldest = match self.events.front() {
            Some((c, _)) => *c,
            None => return Since::Events(vec![]),
        };
        if cursor + 1 < oldest {
            return Since::Gap { oldest };
        }
        let events: Vec<(u64, T)> = self.events.iter().skip_while(|(c, _)| *c <= cursor).cloned().collect();
        Since::Events(events)
    }

    /// Visit every event held, oldest first, with its cursor, and let `f` change it in place. Cursors, `head` and `len`
    /// are untouched: the log's shape stays, only the events' contents change (used to redact deleted messages). Task T206.
    #[allow(clippy::todo, reason = "stub until task T206 lands; remove this allow with the stub")]
    pub fn for_each_mut(&mut self, f: impl FnMut(u64, &mut T)) {
        let _ = (f, &mut self.events);
        todo!("T206: for_each_mut")
    }

    /// Events held now.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}
