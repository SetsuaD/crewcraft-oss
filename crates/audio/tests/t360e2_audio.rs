//! T360e2: call audio on opus-pure (docs/CALLS.md). A tone survives the voice codec with its frequency and level; the
//! jitter buffer plays reordered packets in order, conceals a lost one or rebuilds it from the next packet's in-band
//! FEC, drops a late one, follows a sequence number that wraps; and nothing a network can send makes the decoder or
//! the receiver panic. Expectations are relations (frequency within 1 %, level within 3 dB, FEC closer to the real
//! frame than concealment), never sample values copied from the implementation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crewcraft_audio::codec::has_fec;
use crewcraft_audio::{Arrival, EncoderSettings, Error, FRAME_SAMPLES, FrameKind, JitterBuffer, Receiver, SAMPLE_RATE, VoiceDecoder, VoiceEncoder};

const RATE: f64 = SAMPLE_RATE as f64;

/// `frames` frames of a sine tone, phase-continuous from frame `first` on.
fn tone(freq: f64, amplitude: f64, first: usize, frames: usize) -> Vec<Vec<f32>> {
    (first..first + frames)
        .map(|f| {
            (0..FRAME_SAMPLES)
                .map(|i| {
                    let n = (f * FRAME_SAMPLES + i) as f64;
                    (amplitude * (2.0 * std::f64::consts::PI * freq * n / RATE).sin()) as f32
                })
                .collect()
        })
        .collect()
}

fn encode_all(settings: EncoderSettings, frames: &[Vec<f32>]) -> Vec<Vec<u8>> {
    let mut encoder = VoiceEncoder::new(settings).unwrap();
    frames.iter().map(|f| encoder.encode_f32(f).unwrap()).collect()
}

fn rms(x: &[f32]) -> f64 {
    (x.iter().map(|&s| f64::from(s) * f64::from(s)).sum::<f64>() / x.len() as f64).sqrt()
}

/// Power of `x` at `freq` (one DFT bin at an arbitrary frequency).
fn power_at(x: &[f32], freq: f64) -> f64 {
    let w = 2.0 * std::f64::consts::PI * freq / RATE;
    let (mut re, mut im) = (0.0f64, 0.0f64);
    for (n, &s) in x.iter().enumerate() {
        re += f64::from(s) * (w * n as f64).cos();
        im -= f64::from(s) * (w * n as f64).sin();
    }
    re * re + im * im
}

/// The frequency between `lo` and `hi` (half-hertz steps) with the most power.
fn peak_frequency(x: &[f32], lo: f64, hi: f64) -> f64 {
    let mut best = (lo, 0.0);
    let mut f = lo;
    while f <= hi {
        let p = power_at(x, f);
        if p > best.1 {
            best = (f, p);
        }
        f += 0.5;
    }
    best.0
}

fn energy_of_difference(a: &[f32], b: &[f32]) -> f64 {
    a.iter().zip(b).map(|(&x, &y)| (f64::from(x) - f64::from(y)).powi(2)).sum()
}

/// Feeds `arrivals` (sequence number, packet) to a receiver one per tick, taking one frame per tick, then keeps
/// ticking until `wanted` frames have come out.
fn play(receiver: &mut Receiver, arrivals: &[(u16, &[u8])], wanted: usize) -> Vec<crewcraft_audio::Frame> {
    let mut frames = Vec::new();
    for &(seq, packet) in arrivals {
        assert_eq!(receiver.push(seq, u32::from(seq) * FRAME_SAMPLES as u32, packet), Arrival::Queued, "seq {seq}");
        frames.extend(receiver.next_frame());
    }
    while frames.len() < wanted {
        frames.push(receiver.next_frame().expect("the buffer still holds packets"));
    }
    frames
}

#[test]
fn a_tone_keeps_its_frequency_and_level() {
    let input = tone(440.0, 0.3, 0, 50);
    let packets = encode_all(EncoderSettings::default(), &input);
    assert!(packets.iter().all(|p| !p.is_empty() && p.len() <= crewcraft_audio::MAX_PACKET_BYTES));
    let mut decoder = VoiceDecoder::new().unwrap();
    let output: Vec<f32> = packets.iter().flat_map(|p| decoder.decode_f32(p).unwrap()).collect();
    assert_eq!(output.len(), 50 * FRAME_SAMPLES, "one 20 ms frame out for every frame in");
    // Skip the first 200 ms (codec delay and the encoder settling), analyse the next 800 ms.
    let decoded = &output[10 * FRAME_SAMPLES..];
    let original: Vec<f32> = input[10..].concat();
    let peak = peak_frequency(decoded, 400.0, 480.0);
    assert!((peak - 440.0).abs() <= 4.4, "decoded peak at {peak} Hz, sent 440 Hz");
    let ratio = rms(decoded) / rms(&original);
    assert!((0.708..=1.413).contains(&ratio), "level changed by a factor of {ratio} (more than 3 dB)");
    assert!(power_at(decoded, 440.0) > 100.0 * power_at(decoded, 880.0), "the tone dominates its own harmonic");

    // The same through the 16-bit calls.
    let mut encoder = VoiceEncoder::new(EncoderSettings::default()).unwrap();
    let mut decoder = VoiceDecoder::new().unwrap();
    let mut output = Vec::new();
    for frame in &input {
        let pcm: Vec<i16> = frame.iter().map(|&s| (s * 32767.0) as i16).collect();
        let packet = encoder.encode_i16(&pcm).unwrap();
        output.extend(decoder.decode_i16(&packet).unwrap().into_iter().map(|s| f32::from(s) / 32768.0));
    }
    let decoded = &output[10 * FRAME_SAMPLES..];
    let peak = peak_frequency(decoded, 400.0, 480.0);
    assert!((peak - 440.0).abs() <= 4.4, "16-bit: decoded peak at {peak} Hz");
    let ratio = rms(decoded) / rms(&original);
    assert!((0.708..=1.413).contains(&ratio), "16-bit: level changed by a factor of {ratio}");
}

#[test]
fn reordered_packets_come_out_in_order() {
    let packets = encode_all(EncoderSettings::default(), &tone(300.0, 0.2, 0, 30));
    // Neighbours swapped in three places, and packet 15 two places late.
    let mut order: Vec<u16> = (0..30).collect();
    order.swap(1, 2);
    order.swap(5, 6);
    order.swap(10, 11);
    let fifteen = order.remove(15);
    order.insert(17, fifteen);
    assert_ne!(order, (0..30).collect::<Vec<u16>>());
    let arrivals: Vec<(u16, &[u8])> = order.iter().map(|&s| (s, packets[usize::from(s)].as_slice())).collect();
    let mut receiver = Receiver::new(3, 50).unwrap();
    let frames = play(&mut receiver, &arrivals, 30);
    let seqs: Vec<u16> = frames.iter().map(|f| f.seq).collect();
    assert_eq!(seqs, (0..30).collect::<Vec<u16>>(), "played in sequence order");
    assert!(frames.iter().all(|f| f.kind == FrameKind::Decoded && f.pcm.len() == FRAME_SAMPLES));
    let timestamps: Vec<u32> = frames.iter().map(|f| f.timestamp).collect();
    assert!(timestamps.windows(2).all(|w| w[1] == w[0] + FRAME_SAMPLES as u32), "timestamps follow the sequence");
    let stats = receiver.stats();
    assert_eq!((stats.jitter.received, stats.jitter.played, stats.jitter.lost, stats.jitter.late), (30, 30, 0, 0));
}

#[test]
fn a_lost_packet_is_concealed_or_recovered_from_fec() {
    // A quiet low tone, then from frame 20 a louder higher one: concealment can only guess the new sound, while the
    // FEC copy in packet 21 carries it.
    let lost = 20;
    let mut input = tone(300.0, 0.1, 0, lost);
    input.extend(tone(600.0, 0.4, lost, 20));

    // Without FEC: concealed.
    let plain = EncoderSettings { fec: false, ..EncoderSettings::default() };
    let packets = encode_all(plain, &input);
    assert!(!has_fec(&packets[lost + 1]));
    let arrivals: Vec<(u16, &[u8])> = (0..40u16).filter(|&s| usize::from(s) != lost).map(|s| (s, packets[usize::from(s)].as_slice())).collect();
    let mut receiver = Receiver::new(3, 50).unwrap();
    let frames = play(&mut receiver, &arrivals, 40);
    assert_eq!(frames.iter().map(|f| f.seq).collect::<Vec<u16>>(), (0..40).collect::<Vec<u16>>());
    for f in &frames {
        let expected = if usize::from(f.seq) == lost { FrameKind::Concealed } else { FrameKind::Decoded };
        assert_eq!(f.kind, expected, "seq {}", f.seq);
        assert_eq!(f.pcm.len(), FRAME_SAMPLES);
    }
    let stats = receiver.stats();
    assert_eq!((stats.jitter.lost, stats.concealed, stats.recovered), (1, 1, 0));

    // With FEC (the default): recovered from the next packet.
    let packets = encode_all(EncoderSettings::default(), &input);
    assert!(has_fec(&packets[lost + 1]), "the default settings put an FEC copy in the packet after");
    let arrivals: Vec<(u16, &[u8])> = (0..40u16).filter(|&s| usize::from(s) != lost).map(|s| (s, packets[usize::from(s)].as_slice())).collect();
    let mut receiver = Receiver::new(3, 50).unwrap();
    let frames = play(&mut receiver, &arrivals, 40);
    let recovered = &frames[lost];
    assert_eq!((recovered.seq, recovered.kind), (lost as u16, FrameKind::Recovered));
    assert!(frames.iter().filter(|f| f.kind != FrameKind::Decoded).count() == 1);
    let stats = receiver.stats();
    assert_eq!((stats.jitter.lost, stats.concealed, stats.recovered), (1, 0, 1));

    // The FEC frame is closer to what the lost packet held than concealment of the same gap is.
    let mut clean = VoiceDecoder::new().unwrap();
    let reference: Vec<Vec<f32>> = packets.iter().map(|p| clean.decode_f32(p).unwrap()).collect();
    let mut guessing = VoiceDecoder::new().unwrap();
    for p in &packets[..lost] {
        guessing.decode_f32(p).unwrap();
    }
    let concealed = guessing.conceal_f32().unwrap();
    let wrong_recovered = energy_of_difference(&recovered.pcm, &reference[lost]);
    let wrong_concealed = energy_of_difference(&concealed, &reference[lost]);
    assert!(wrong_recovered < wrong_concealed, "FEC error {wrong_recovered} vs concealment error {wrong_concealed}");
    let ratio = rms(&recovered.pcm) / rms(&reference[lost]);
    assert!((0.5..=2.0).contains(&ratio), "the recovered frame's level is within 6 dB of the real one ({ratio})");
}

#[test]
fn a_late_packet_is_dropped() {
    let plain = EncoderSettings { fec: false, ..EncoderSettings::default() };
    let packets = encode_all(plain, &tone(300.0, 0.2, 0, 8));
    let mut receiver = Receiver::new(3, 50).unwrap();
    for seq in [0u16, 1, 2, 4, 5] {
        assert_eq!(receiver.push(seq, u32::from(seq) * 960, &packets[usize::from(seq)]), Arrival::Queued);
    }
    for seq in 0..3u16 {
        let f = receiver.next_frame().unwrap();
        assert_eq!((f.seq, f.kind), (seq, FrameKind::Decoded));
    }
    let gap = receiver.next_frame().unwrap();
    assert_eq!((gap.seq, gap.kind, gap.timestamp), (3, FrameKind::Concealed, 3 * 960));
    assert_eq!(receiver.push(3, 3 * 960, &packets[3]), Arrival::Late, "its turn has passed");
    assert_eq!(receiver.push(1, 960, &packets[1]), Arrival::Late, "an old packet again is late too");
    for seq in [4u16, 5] {
        let f = receiver.next_frame().unwrap();
        assert_eq!((f.seq, f.kind), (seq, FrameKind::Decoded));
    }
    let stats = receiver.stats();
    assert_eq!((stats.jitter.lost, stats.jitter.late, stats.jitter.played), (1, 2, 5));
}

#[test]
fn sequence_numbers_wrap_and_duplicates_are_ignored() {
    let packets = encode_all(EncoderSettings::default(), &tone(300.0, 0.2, 0, 6));
    let seqs = [65533u16, 65534, 65535, 0, 1, 2];
    let mut buffer = JitterBuffer::new(2, 10).unwrap();
    for (i, &seq) in seqs.iter().enumerate() {
        let timestamp = 1000u32.wrapping_add(i as u32 * 960);
        assert_eq!(buffer.push(seq, timestamp, packets[i].clone()), Arrival::Queued);
    }
    assert_eq!(buffer.push(65535, 0, packets[2].clone()), Arrival::Duplicate);
    let mut played = Vec::new();
    while let Some(slot) = buffer.pop() {
        match slot {
            crewcraft_audio::Slot::Packet { seq, .. } => played.push(seq),
            crewcraft_audio::Slot::Underrun { .. } => break,
            other => panic!("unexpected {other:?}"),
        }
    }
    assert_eq!(played, seqs, "in order across the wrap");
    assert_eq!(buffer.stats().duplicates, 1);
    // A packet far beyond the window means the stream jumped: start again from it.
    assert_eq!(buffer.push(500, 0, packets[0].clone()), Arrival::Resynced { skipped: 497 });
}

/// A small deterministic generator, so a failure reproduces.
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn check_decoded(len: usize) {
    assert!(len <= 5760 && len.is_multiple_of(120), "a decode is whole 2.5 ms steps up to 120 ms, got {len}");
}

#[test]
fn garbage_never_panics() {
    let mut rng = XorShift(0x5eed_1234_abcd_0001);
    let mut decoder = VoiceDecoder::new().unwrap();
    assert!(matches!(decoder.decode_f32(&[]), Err(Error::BadPacket(_))));
    // Random packets of every length and every TOC byte.
    for i in 0..20_000 {
        let len = 1 + (rng.next() % 1500) as usize;
        let packet: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        match i % 4 {
            0 => {
                if let Ok(pcm) = decoder.decode_f32(&packet) {
                    check_decoded(pcm.len());
                }
            }
            1 => {
                if let Ok(pcm) = decoder.decode_i16(&packet) {
                    check_decoded(pcm.len());
                }
            }
            2 => {
                if let Ok((pcm, _)) = decoder.recover_f32(&packet) {
                    check_decoded(pcm.len());
                }
            }
            _ => {
                let _ = has_fec(&packet);
                if let Ok(pcm) = decoder.conceal_i16() {
                    check_decoded(pcm.len());
                }
            }
        }
    }
    // Every single-bit change and every truncation of real packets.
    let packets = encode_all(EncoderSettings::default(), &tone(500.0, 0.3, 0, 12));
    let mut decoder = VoiceDecoder::new().unwrap();
    for packet in &packets {
        for bit in 0..packet.len() * 8 {
            let mut changed = packet.clone();
            changed[bit / 8] ^= 1 << (bit % 8);
            if let Ok(pcm) = decoder.decode_f32(&changed) {
                check_decoded(pcm.len());
            }
        }
        for cut in 1..packet.len() {
            if let Ok(pcm) = decoder.decode_f32(&packet[..cut]) {
                check_decoded(pcm.len());
            }
        }
    }
    // A receiver fed garbage with random sequence numbers keeps producing frames.
    let mut receiver = Receiver::new(2, 20).unwrap();
    for _ in 0..5_000 {
        let len = 1 + (rng.next() % 200) as usize;
        let packet: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let seq = (rng.next() % 40) as u16;
        let _ = receiver.push(seq, rng.next() as u32, &packet);
        if let Some(frame) = receiver.next_frame() {
            assert!(!frame.pcm.is_empty() && frame.pcm.len() <= 5760);
            let _ = frame.to_i16();
        }
    }
}

#[test]
fn settings_are_checked() {
    let ok = EncoderSettings::default();
    assert_eq!((ok.bitrate, ok.fec, ok.dtx), (32_000, true, false), "FEC on, DTX off by default");
    for bad in [
        EncoderSettings { bitrate: EncoderSettings::MIN_BITRATE - 1, ..ok },
        EncoderSettings { bitrate: EncoderSettings::MAX_BITRATE + 1, ..ok },
        EncoderSettings { complexity: 11, ..ok },
        EncoderSettings { expected_loss_percent: 101, ..ok },
    ] {
        assert!(matches!(VoiceEncoder::new(bad), Err(Error::BadSetting(_))), "{bad:?}");
    }
    let mut encoder = VoiceEncoder::new(ok).unwrap();
    let low = EncoderSettings { bitrate: 12_000, complexity: 5, ..ok };
    encoder.set_settings(low).unwrap();
    assert_eq!(encoder.settings(), low);
    assert!(encoder.set_settings(EncoderSettings { complexity: 11, ..ok }).is_err());
    assert_eq!(encoder.settings(), low, "a refused change leaves the settings as they were");
    assert_eq!(encoder.encode_f32(&[0.0; 480]), Err(Error::FrameLength { expected: FRAME_SAMPLES, got: 480 }));
    assert!(JitterBuffer::new(0, 10).is_err());
    assert!(JitterBuffer::new(3, 3).is_err());
    assert!(Receiver::new(3, 4).is_ok());
}
