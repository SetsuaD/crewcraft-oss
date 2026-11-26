//! One incoming audio stream: a [`JitterBuffer`] feeding a [`VoiceDecoder`].
//!
//! Push packets as they arrive; call [`Receiver::next_frame`] once per 20 ms tick. A packet that is there is decoded;
//! a lost one is recovered from the next packet's in-band FEC when that packet is here and carries a copy, and
//! concealed otherwise; an underrun is concealed too. A packet that does not decode is concealed and counted, never a
//! panic: everything here comes from the network.

use crate::Error;
use crate::codec::{FRAME_SAMPLES, VoiceDecoder};
use crate::jitter::{Arrival, JitterBuffer, JitterStats, Slot};

/// How a frame was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// Decoded from its own packet.
    Decoded,
    /// Rebuilt from the next packet's in-band FEC copy.
    Recovered,
    /// Made up by packet-loss concealment (its packet was lost, late, broken or not here yet).
    Concealed,
}

/// One frame of 48 kHz mono audio to play.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    /// The sequence number of the turn it fills.
    pub seq: u16,
    /// Its RTP timestamp (expected, for a frame whose packet is missing).
    pub timestamp: u32,
    /// How it was made.
    pub kind: FrameKind,
    /// The samples, nominally -1 to 1.
    pub pcm: Vec<f32>,
}

impl Frame {
    /// The samples as 16-bit PCM, rounded and clamped.
    pub fn to_i16(&self) -> Vec<i16> {
        self.pcm.iter().map(|&x| (x * 32768.0).round().clamp(-32768.0, 32767.0) as i16).collect()
    }
}

/// Counters since the receiver was made.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReceiverStats {
    /// The jitter buffer's counters (packets received, played, lost, late, duplicated, underruns, skipped).
    pub jitter: JitterStats,
    /// Lost packets rebuilt from FEC.
    pub recovered: u64,
    /// Frames made by concealment (lost packets without FEC, underruns and packets that did not decode).
    pub concealed: u64,
    /// Packets that were there but did not decode.
    pub decode_errors: u64,
}

/// One incoming stream; see the module documentation.
pub struct Receiver {
    jitter: JitterBuffer,
    decoder: VoiceDecoder,
    recovered: u64,
    concealed: u64,
    decode_errors: u64,
}

impl Receiver {
    /// Packets of delay before playout starts by default (60 ms).
    pub const DEFAULT_DEPTH: usize = 3;
    /// Packets held ahead of the playout point at most by default (1 s).
    pub const DEFAULT_WINDOW: usize = 50;

    /// A receiver with [`JitterBuffer::new`]'s `depth` and `window`.
    pub fn new(depth: usize, window: usize) -> Result<Self, Error> {
        Ok(Self { jitter: JitterBuffer::new(depth, window)?, decoder: VoiceDecoder::new()?, recovered: 0, concealed: 0, decode_errors: 0 })
    }

    /// A receiver with [`Self::DEFAULT_DEPTH`] and [`Self::DEFAULT_WINDOW`].
    pub fn with_defaults() -> Result<Self, Error> {
        Self::new(Self::DEFAULT_DEPTH, Self::DEFAULT_WINDOW)
    }

    /// Takes in one packet as it arrives.
    pub fn push(&mut self, seq: u16, timestamp: u32, payload: &[u8]) -> Arrival {
        self.jitter.push(seq, timestamp, payload.to_vec())
    }

    /// The frame for this tick, or `None` while the buffer fills up (play silence).
    pub fn next_frame(&mut self) -> Option<Frame> {
        let frame = match self.jitter.pop()? {
            Slot::Packet { seq, timestamp, payload } => match self.decoder.decode_f32(&payload) {
                Ok(pcm) => Frame { seq, timestamp, kind: FrameKind::Decoded, pcm },
                Err(_) => {
                    self.decode_errors += 1;
                    self.concealed_frame(seq, timestamp)
                }
            },
            Slot::Lost { seq, timestamp, next: Some(next) } => match self.decoder.recover_f32(&next) {
                Ok((pcm, true)) => {
                    self.recovered += 1;
                    Frame { seq, timestamp, kind: FrameKind::Recovered, pcm }
                }
                Ok((pcm, false)) => {
                    self.concealed += 1;
                    Frame { seq, timestamp, kind: FrameKind::Concealed, pcm }
                }
                Err(_) => self.concealed_frame(seq, timestamp),
            },
            Slot::Lost { seq, timestamp, next: None } | Slot::Underrun { seq, timestamp } => self.concealed_frame(seq, timestamp),
        };
        Some(frame)
    }

    fn concealed_frame(&mut self, seq: u16, timestamp: u32) -> Frame {
        self.concealed += 1;
        // Concealment of a fresh decoder can only fail if the codec itself is broken; play silence then.
        let pcm = self.decoder.conceal_f32().unwrap_or_else(|_| vec![0.0; FRAME_SAMPLES]);
        Frame { seq, timestamp, kind: FrameKind::Concealed, pcm }
    }

    /// The counters so far.
    pub fn stats(&self) -> ReceiverStats {
        ReceiverStats { jitter: self.jitter.stats(), recovered: self.recovered, concealed: self.concealed, decode_errors: self.decode_errors }
    }
}
