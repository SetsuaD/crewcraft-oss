//! The Opus voice codec: 48 kHz mono, 20 ms frames, the VoIP application, on `opus-pure`.
//!
//! [`VoiceEncoder`] turns one frame of PCM into one packet; [`VoiceDecoder`] turns a packet back into PCM, conceals a
//! lost packet, or recovers it from the next packet's in-band FEC. Both take and return `f32` (nominally -1 to 1) or
//! `i16` PCM. Decoding a packet from the network never panics: anything that is not Opus is an [`Error`].

use opus_pure::{Application, OpusDecoder, OpusEncoder, Signal};

use crate::Error;

/// The sample rate of every frame, in hertz.
pub const SAMPLE_RATE: u32 = 48_000;
/// Samples in one 20 ms mono frame at [`SAMPLE_RATE`].
pub const FRAME_SAMPLES: usize = 960;
/// The largest packet one frame can produce (RFC 6716 section 3.2.1).
pub const MAX_PACKET_BYTES: usize = 1275;
/// The longest a received packet may decode to: 120 ms.
pub(crate) const MAX_PACKET_SAMPLES: usize = 5760;

/// How the encoder codes. [`Default`] is 32 kbit/s, complexity 9, in-band FEC on for an expected 10 % loss, DTX off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderSettings {
    /// Target bit rate in bits per second, [`Self::MIN_BITRATE`] to [`Self::MAX_BITRATE`].
    pub bitrate: u32,
    /// 0 (fastest) to 10 (best).
    pub complexity: u8,
    /// In-band forward error correction: a packet may carry a low-rate copy of the frame before it.
    pub fec: bool,
    /// Expected packet loss, 0 to 100 percent. The encoder only spends bits on FEC when this is above 0.
    pub expected_loss_percent: u8,
    /// Discontinuous transmission: send almost nothing during silence.
    pub dtx: bool,
}

impl EncoderSettings {
    /// The lowest bit rate Opus codes at.
    pub const MIN_BITRATE: u32 = 6_000;
    /// The highest bit rate Opus codes at.
    pub const MAX_BITRATE: u32 = 510_000;

    /// Checks every setting is in range.
    pub fn validate(&self) -> Result<(), Error> {
        if !(Self::MIN_BITRATE..=Self::MAX_BITRATE).contains(&self.bitrate) {
            return Err(Error::BadSetting("bitrate (6000 to 510000 bit/s)"));
        }
        if self.complexity > 10 {
            return Err(Error::BadSetting("complexity (0 to 10)"));
        }
        if self.expected_loss_percent > 100 {
            return Err(Error::BadSetting("expected loss (0 to 100 percent)"));
        }
        Ok(())
    }
}

impl Default for EncoderSettings {
    fn default() -> Self {
        Self { bitrate: 32_000, complexity: 9, fec: true, expected_loss_percent: 10, dtx: false }
    }
}

/// Encodes 20 ms frames of 48 kHz mono speech into Opus packets.
pub struct VoiceEncoder {
    inner: OpusEncoder,
    settings: EncoderSettings,
    packet: Vec<u8>,
}

impl VoiceEncoder {
    /// A new encoder with these settings.
    pub fn new(settings: EncoderSettings) -> Result<Self, Error> {
        settings.validate()?;
        let inner = OpusEncoder::new(SAMPLE_RATE as i32, 1, Application::Voip)?;
        let mut encoder = Self { inner, settings, packet: vec![0; MAX_PACKET_BYTES] };
        encoder.apply();
        Ok(encoder)
    }

    /// The settings in use.
    pub fn settings(&self) -> EncoderSettings {
        self.settings
    }

    /// Changes the settings from the next frame on; refused (and nothing changed) when one is out of range.
    pub fn set_settings(&mut self, settings: EncoderSettings) -> Result<(), Error> {
        settings.validate()?;
        self.settings = settings;
        self.apply();
        Ok(())
    }

    fn apply(&mut self) {
        let s = self.settings;
        // Both fit: validate keeps the bit rate at most 510000 and the rest at most 100.
        self.inner.bitrate_bps = i32::try_from(s.bitrate).unwrap_or(i32::MAX);
        self.inner.complexity = i32::from(s.complexity);
        self.inner.use_inband_fec = s.fec;
        self.inner.packet_loss_perc = i32::from(s.expected_loss_percent);
        self.inner.use_dtx = s.dtx;
        // A voice encoder: keep the speech layer (SILK, or hybrid), which is also the layer that carries FEC.
        self.inner.signal_type = Some(Signal::Voice);
    }

    /// Encodes one frame of [`FRAME_SAMPLES`] float samples.
    pub fn encode_f32(&mut self, frame: &[f32]) -> Result<Vec<u8>, Error> {
        check_frame(frame.len())?;
        let n = self.inner.encode(frame, FRAME_SAMPLES, &mut self.packet)?;
        self.take(n)
    }

    /// Encodes one frame of [`FRAME_SAMPLES`] 16-bit samples.
    pub fn encode_i16(&mut self, frame: &[i16]) -> Result<Vec<u8>, Error> {
        check_frame(frame.len())?;
        let n = self.inner.encode_s16(frame, FRAME_SAMPLES, &mut self.packet)?;
        self.take(n)
    }

    fn take(&self, n: usize) -> Result<Vec<u8>, Error> {
        self.packet.get(..n).map(<[u8]>::to_vec).ok_or_else(|| Error::Codec("packet longer than its buffer".into()))
    }
}

fn check_frame(got: usize) -> Result<(), Error> {
    if got == FRAME_SAMPLES { Ok(()) } else { Err(Error::FrameLength { expected: FRAME_SAMPLES, got }) }
}

/// Decodes Opus packets to 48 kHz mono PCM, conceals lost packets and recovers them from in-band FEC.
pub struct VoiceDecoder {
    inner: OpusDecoder,
    float: Vec<f32>,
    int: Vec<i16>,
}

impl VoiceDecoder {
    /// A new decoder.
    pub fn new() -> Result<Self, Error> {
        let inner = OpusDecoder::new(SAMPLE_RATE as i32, 1)?;
        Ok(Self { inner, float: vec![0.0; MAX_PACKET_SAMPLES], int: vec![0; MAX_PACKET_SAMPLES] })
    }

    /// Decodes one packet (any duration up to 120 ms) to float samples.
    pub fn decode_f32(&mut self, packet: &[u8]) -> Result<Vec<f32>, Error> {
        check_packet(packet)?;
        let n = self.inner.decode(packet, MAX_PACKET_SAMPLES, &mut self.float)?;
        take(&self.float, n)
    }

    /// Decodes one packet to 16-bit samples (soft-clipped, so a loud peak does not wrap or crack).
    pub fn decode_i16(&mut self, packet: &[u8]) -> Result<Vec<i16>, Error> {
        check_packet(packet)?;
        let n = self.inner.decode_s16(packet, MAX_PACKET_SAMPLES, &mut self.int)?;
        take(&self.int, n)
    }

    /// Conceals one lost packet: as long as the last packet that arrived, made up from what came before.
    pub fn conceal_f32(&mut self) -> Result<Vec<f32>, Error> {
        let samples = self.lost_samples();
        let n = self.inner.decode(&[], samples, &mut self.float)?;
        take(&self.float, n)
    }

    /// [`Self::conceal_f32`] as 16-bit samples.
    pub fn conceal_i16(&mut self) -> Result<Vec<i16>, Error> {
        let samples = self.lost_samples();
        let n = self.inner.decode_s16(&[], samples, &mut self.int)?;
        take(&self.int, n)
    }

    /// Rebuilds the lost packet before `next` from `next`'s in-band FEC. The flag says whether `next` carried a copy
    /// (see [`has_fec`]); without one the frame is concealed instead.
    pub fn recover_f32(&mut self, next: &[u8]) -> Result<(Vec<f32>, bool), Error> {
        check_packet(next)?;
        let samples = self.lost_samples();
        let n = self.inner.decode_fec(next, samples, &mut self.float)?;
        Ok((take(&self.float, n)?, has_fec(next)))
    }

    /// [`Self::recover_f32`] as 16-bit samples.
    pub fn recover_i16(&mut self, next: &[u8]) -> Result<(Vec<i16>, bool), Error> {
        check_packet(next)?;
        let samples = self.lost_samples();
        let n = self.inner.decode_fec_s16(next, samples, &mut self.int)?;
        Ok((take(&self.int, n)?, has_fec(next)))
    }

    /// A lost packet is taken to be as long as the last one that arrived (one frame before any did).
    fn lost_samples(&self) -> usize {
        match self.inner.last_packet_duration() {
            0 => FRAME_SAMPLES,
            n => n.min(MAX_PACKET_SAMPLES),
        }
    }
}

fn check_packet(packet: &[u8]) -> Result<(), Error> {
    if packet.is_empty() { Err(Error::BadPacket("empty packet".into())) } else { Ok(()) }
}

fn take<T: Copy>(buffer: &[T], n: usize) -> Result<Vec<T>, Error> {
    buffer.get(..n).map(<[T]>::to_vec).ok_or_else(|| Error::Codec("decoded more samples than its buffer".into()))
}

/// Whether a packet carries in-band FEC: a low-rate copy of the frame before it (RFC 6716 section 4.2.4).
///
/// Only the speech layer (SILK-only and hybrid packets) has one. Its first frame begins with one voice-activity flag
/// per 20 ms SILK frame and then the FEC ("LBRR") flag, each coded with probability one half at the very start of the
/// range coder, so they are the leading bits of the frame's first byte; a stereo packet repeats both for the side
/// channel.
pub fn has_fec(packet: &[u8]) -> bool {
    let Some(&toc) = packet.first() else { return false };
    let config = toc >> 3;
    if config >= 16 {
        return false; // CELT-only
    }
    // SILK frames per Opus frame: 10 and 20 ms carry one, 40 ms two, 60 ms three. Hybrid is 10 or 20 ms.
    let silk_frames: u32 = if config < 12 {
        match config & 3 {
            2 => 2,
            3 => 3,
            _ => 1,
        }
    } else {
        1
    };
    let Some(&first) = first_frame(packet).and_then(<[u8]>::first) else { return false };
    let mid = (first >> (7 - silk_frames)) & 1 == 1;
    let stereo = toc & 0x04 != 0;
    let side = stereo && (first >> (6 - 2 * silk_frames)) & 1 == 1;
    mid || side
}

/// The bytes of a packet's first Opus frame (RFC 6716 section 3.2), or `None` when the packet is malformed.
fn first_frame(packet: &[u8]) -> Option<&[u8]> {
    let (&toc, rest) = packet.split_first()?;
    match toc & 3 {
        0 => Some(rest),
        1 => rest.get(..rest.len() / 2),
        2 => {
            let (len, header) = frame_length(rest)?;
            rest.get(header..header.checked_add(len)?)
        }
        _ => {
            let (&count, mut rest) = rest.split_first()?;
            let frames = usize::from(count & 0x3f);
            if frames == 0 {
                return None;
            }
            let mut padding = 0usize;
            if count & 0x40 != 0 {
                loop {
                    let (&byte, after) = rest.split_first()?;
                    rest = after;
                    if byte == 255 {
                        padding = padding.checked_add(254)?;
                    } else {
                        padding = padding.checked_add(usize::from(byte))?;
                        break;
                    }
                }
            }
            if count & 0x80 != 0 {
                // VBR: frames - 1 length fields come first, then the frames.
                let mut offset = 0usize;
                let mut first_len = None;
                for _ in 1..frames {
                    let (len, header) = frame_length(rest.get(offset..)?)?;
                    first_len.get_or_insert(len);
                    offset = offset.checked_add(header)?;
                }
                let data = rest.get(offset..)?;
                let len = match first_len {
                    Some(len) => len,
                    None => data.len().checked_sub(padding)?,
                };
                data.get(..len)
            } else {
                let len = rest.len().checked_sub(padding)? / frames;
                rest.get(..len)
            }
        }
    }
}

/// A frame length field: one byte below 252, otherwise two (RFC 6716 section 3.2.1). Returns the length and the
/// field's size.
fn frame_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = usize::from(*bytes.first()?);
    if first < 252 {
        Some((first, 1))
    } else {
        let second = usize::from(*bytes.get(1)?);
        Some((first + 4 * second, 2))
    }
}
