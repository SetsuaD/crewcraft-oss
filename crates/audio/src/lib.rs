//! CrewCraft's call audio (task T360e2, docs/CALLS.md "Opus: the crate, chosen by the conformance vectors").
//!
//! - [`codec`]: an Opus voice encoder and decoder for 48 kHz mono in 20 ms frames, on `opus-pure`, with in-band FEC
//!   on and DTX off by default. Frames go in and come out as `f32` or `i16` PCM.
//! - [`jitter`]: a jitter buffer keyed by RTP-style sequence numbers and timestamps. It reorders within a bounded
//!   window, drops late packets and reports every slot that had to be played without its packet.
//! - [`receiver`]: the two together. Each 20 ms tick asks for the next frame; a missing packet is recovered from the
//!   next packet's in-band FEC when it carries a copy, and concealed otherwise.
//!
//! There is no audio device code here: capture and playback are a separate decision (the usual Rust audio crates
//! compile C on some platforms), so this crate only ever sees PCM frames.

pub mod codec;
pub mod jitter;
pub mod receiver;

pub use codec::{EncoderSettings, FRAME_SAMPLES, MAX_PACKET_BYTES, SAMPLE_RATE, VoiceDecoder, VoiceEncoder};
pub use jitter::{Arrival, JitterBuffer, JitterStats, Slot};
pub use receiver::{Frame, FrameKind, Receiver, ReceiverStats};

use std::fmt;

/// Anything that can go wrong in this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A setting is outside its allowed range; the text names it.
    BadSetting(&'static str),
    /// A PCM frame has the wrong number of samples.
    FrameLength {
        /// Samples a frame must have.
        expected: usize,
        /// Samples it had.
        got: usize,
    },
    /// A packet does not decode as Opus.
    BadPacket(String),
    /// The codec failed for another reason.
    Codec(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadSetting(what) => write!(f, "setting out of range: {what}"),
            Error::FrameLength { expected, got } => write!(f, "a frame has {expected} samples, not {got}"),
            Error::BadPacket(why) => write!(f, "not an Opus packet: {why}"),
            Error::Codec(why) => write!(f, "codec error: {why}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<opus_pure::Error> for Error {
    fn from(error: opus_pure::Error) -> Self {
        match error {
            opus_pure::Error::InvalidPacket(_) => Error::BadPacket(error.to_string()),
            other => Error::Codec(other.to_string()),
        }
    }
}
