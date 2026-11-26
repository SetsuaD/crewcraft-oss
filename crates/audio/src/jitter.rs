//! A jitter buffer for one audio stream, keyed by RTP-style sequence numbers (16 bits, wrapping) and timestamps.
//!
//! Packets go in with [`JitterBuffer::push`] as they arrive, in any order. The playout clock calls
//! [`JitterBuffer::pop`] once per packet interval (20 ms) and gets the next [`Slot`] in sequence order:
//!
//! - it first waits until `depth` packets are here (the delay that absorbs reordering and jitter);
//! - a packet that arrived in time comes out in order, whatever order it arrived in;
//! - a packet whose turn comes while later packets are already here is reported [`Slot::Lost`], with the next packet
//!   attached so the decoder can try its FEC copy; if the lost packet turns up afterwards it is [`Arrival::Late`] and
//!   dropped;
//! - when nothing at all is here the slot is an [`Slot::Underrun`]: the decoder conceals, and the buffer waits for the
//!   packet instead of skipping it. After a few underruns in a row it stops and buffers up again;
//! - a packet more than `window` packets ahead of the playout point means the stream jumped: the buffer starts again
//!   from it ([`Arrival::Resynced`]). Memory is bounded by `window` packets.

use std::collections::BTreeMap;

use crate::Error;
use crate::codec::{FRAME_SAMPLES, MAX_PACKET_SAMPLES};

/// Underruns in a row after which the buffer stops concealing and waits to fill up again (100 ms at 20 ms frames).
pub const MAX_UNDERRUNS: u32 = 5;
/// The largest `window` a buffer accepts (one minute of 20 ms packets).
pub const MAX_WINDOW: usize = 3000;

/// What happened to a pushed packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arrival {
    /// Held for its turn.
    Queued,
    /// Its sequence number is already held; ignored.
    Duplicate,
    /// Its turn has passed (it was played as lost, or it was already played); dropped.
    Late,
    /// It was more than `window` packets ahead: the buffer dropped what it held and starts again from it. `skipped`
    /// is the number of sequence numbers jumped over.
    Resynced {
        /// Sequence numbers between the old playout point and this packet.
        skipped: u64,
    },
}

/// The next thing to play.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Slot {
    /// The packet for this turn.
    Packet {
        /// Its sequence number.
        seq: u16,
        /// Its RTP timestamp.
        timestamp: u32,
        /// The packet.
        payload: Vec<u8>,
    },
    /// This turn's packet is missing while later ones are here: it is lost.
    Lost {
        /// The missing sequence number.
        seq: u16,
        /// Its expected timestamp (the previous one plus the stream's packet interval).
        timestamp: u32,
        /// The next packet, when it is here, for FEC recovery.
        next: Option<Vec<u8>>,
    },
    /// Nothing is here at all; conceal and wait for this packet.
    Underrun {
        /// The sequence number still awaited.
        seq: u16,
        /// Its expected timestamp.
        timestamp: u32,
    },
}

/// Counters since the buffer was made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JitterStats {
    /// Packets queued for playout.
    pub received: u64,
    /// Packets played in their turn.
    pub played: u64,
    /// Turns played without their packet because later ones were here.
    pub lost: u64,
    /// Packets that arrived after their turn and were dropped.
    pub late: u64,
    /// Packets that arrived twice.
    pub duplicates: u64,
    /// Turns with nothing to play.
    pub underruns: u64,
    /// Sequence numbers jumped over by a resync.
    pub skipped: u64,
}

/// A jitter buffer for one stream; see the module documentation.
#[derive(Debug, Clone)]
pub struct JitterBuffer {
    depth: u64,
    window: u64,
    /// Extended (no longer wrapping) sequence number of the next turn.
    next: Option<u64>,
    /// Highest extended sequence number held or played.
    highest: Option<u64>,
    playing: bool,
    held: BTreeMap<u64, (u32, Vec<u8>)>,
    /// Timestamp of the last turn played, and the stream's packet interval in timestamp units.
    last_timestamp: Option<u32>,
    interval: u32,
    underruns_in_row: u32,
    stats: JitterStats,
}

/// Extended sequence numbers start here, so a packet that arrives before the first one never goes below zero.
const START: u64 = 1 << 32;

impl JitterBuffer {
    /// A buffer that starts playing once `depth` packets are here (at least 1) and holds at most
    /// `window` packets ahead of the playout point (more than `depth`, at most [`MAX_WINDOW`]).
    pub fn new(depth: usize, window: usize) -> Result<Self, Error> {
        if depth == 0 {
            return Err(Error::BadSetting("jitter depth (at least 1 packet)"));
        }
        if window <= depth || window > MAX_WINDOW {
            return Err(Error::BadSetting("jitter window (more than the depth, at most 3000 packets)"));
        }
        Ok(Self {
            depth: depth as u64,
            window: window as u64,
            next: None,
            highest: None,
            playing: false,
            held: BTreeMap::new(),
            last_timestamp: None,
            interval: FRAME_SAMPLES as u32,
            underruns_in_row: 0,
            stats: JitterStats::default(),
        })
    }

    /// The counters so far.
    pub fn stats(&self) -> JitterStats {
        self.stats
    }

    /// Packets held now.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether no packet is held.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    /// Takes in one packet.
    pub fn push(&mut self, seq: u16, timestamp: u32, payload: Vec<u8>) -> Arrival {
        let ext = self.extend(seq);
        let Some(next) = self.next else {
            self.next = Some(ext);
            return self.hold(ext, timestamp, payload);
        };
        if ext < next {
            // Before the first turn, an earlier packet moves the start back (within the window); afterwards it is
            // late.
            if !self.playing && next - ext < self.window && self.highest.is_some_and(|h| h - ext < self.window) {
                self.next = Some(ext);
                return self.hold(ext, timestamp, payload);
            }
            self.stats.late += 1;
            return Arrival::Late;
        }
        if ext - next >= self.window {
            let skipped = ext - next;
            self.held.clear();
            self.next = Some(ext);
            self.highest = Some(ext);
            self.playing = false;
            self.underruns_in_row = 0;
            self.stats.skipped += skipped;
            let _ = self.hold(ext, timestamp, payload);
            return Arrival::Resynced { skipped };
        }
        self.hold(ext, timestamp, payload)
    }

    fn hold(&mut self, ext: u64, timestamp: u32, payload: Vec<u8>) -> Arrival {
        if self.held.contains_key(&ext) {
            self.stats.duplicates += 1;
            return Arrival::Duplicate;
        }
        self.held.insert(ext, (timestamp, payload));
        self.highest = Some(self.highest.map_or(ext, |h| h.max(ext)));
        self.stats.received += 1;
        Arrival::Queued
    }

    /// The next turn, or `None` while the buffer is filling up (play silence then).
    pub fn pop(&mut self) -> Option<Slot> {
        let next = self.next?;
        if !self.playing {
            if (self.held.len() as u64) < self.depth {
                return None;
            }
            self.playing = true;
        }
        if let Some((timestamp, payload)) = self.held.remove(&next) {
            self.learn_interval(timestamp);
            self.advance(next, timestamp);
            self.stats.played += 1;
            return Some(Slot::Packet { seq: low16(next), timestamp, payload });
        }
        let timestamp = self.expected_timestamp(next);
        if self.held.is_empty() {
            self.stats.underruns += 1;
            self.underruns_in_row += 1;
            if self.underruns_in_row > MAX_UNDERRUNS {
                self.playing = false;
                self.underruns_in_row = 0;
                return None;
            }
            return Some(Slot::Underrun { seq: low16(next), timestamp });
        }
        let following = self.held.get(&(next + 1)).map(|(_, payload)| payload.clone());
        self.advance(next, timestamp);
        self.stats.lost += 1;
        Some(Slot::Lost { seq: low16(next), timestamp, next: following })
    }

    fn advance(&mut self, played: u64, timestamp: u32) {
        self.next = Some(played + 1);
        self.highest = Some(self.highest.map_or(played, |h| h.max(played)));
        self.last_timestamp = Some(timestamp);
        self.underruns_in_row = 0;
    }

    /// Learns the packet interval from two turns in a row that both had their packet.
    fn learn_interval(&mut self, timestamp: u32) {
        if let Some(last) = self.last_timestamp {
            let step = timestamp.wrapping_sub(last);
            if (1..=MAX_PACKET_SAMPLES as u32).contains(&step) {
                self.interval = step;
            }
        }
    }

    fn expected_timestamp(&self, next: u64) -> u32 {
        match self.last_timestamp {
            Some(last) => last.wrapping_add(self.interval),
            // Nothing played yet: count back from the earliest packet held.
            None => self.held.iter().next().map_or(0, |(&ext, (timestamp, _))| {
                let turns = u32::try_from(ext.saturating_sub(next)).unwrap_or(u32::MAX);
                timestamp.wrapping_sub(self.interval.wrapping_mul(turns))
            }),
        }
    }

    /// Maps a 16-bit sequence number to the extended one nearest the highest seen (RFC 3550 appendix A.1 style).
    fn extend(&self, seq: u16) -> u64 {
        let Some(reference) = self.highest.or(self.next) else { return START + u64::from(seq) };
        let candidate = (reference & !0xffff) | u64::from(seq);
        [candidate.saturating_sub(1 << 16), candidate, candidate + (1 << 16)].into_iter().min_by_key(|c| c.abs_diff(reference)).unwrap_or(candidate)
    }
}

fn low16(ext: u64) -> u16 {
    (ext & 0xffff) as u16
}
