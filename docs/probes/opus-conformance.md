# Probe: Opus crates against the RFC 8251 conformance vectors

This is the program and the commands behind the Opus crate choice in [CALLS.md](../CALLS.md) ("Opus: the crate, chosen
by the conformance vectors"). It is documentation, not part of the build: nothing here is compiled by `ci/validate.sh`.

For each candidate crate the probe decodes the 12 test vectors of RFC 8251 at 48 kHz, once as mono and once as stereo,
the way libopus tests itself (`tests/run_vectors.sh` with `opus_demo -d` and `opus_compare`). It

- checks every packet's final range against the encoder's value stored in the `.bit` file;
- scores the output with a Rust port of libopus's `opus_compare.c` against `testvectorNN.dec` and `testvectorNNm.dec`
  (a score of at least 0 against either passes, as in `run_vectors.sh`);
- times 48 kHz mono 20 ms encoding at complexity 10 and 5 (VoIP application, 32 kbit/s), and writes each encoder's
  complexity-10 stream in the `.bit` format so the other decoders can check its final ranges.

## Running it

Any Linux machine with Docker (about 40 minutes on one core, most of it in the quality metric):

```sh
mkdir opus-probe && cd opus-probe
curl -fsSLO https://opus-codec.org/static/testvectors/opus_testvectors-rfc8251.tar.gz
echo "6b26a22f9ba87b2b836906a9bb7afec5f8e54d49553b1200382520ee6fedfa55  opus_testvectors-rfc8251.tar.gz" | sha256sum -c
tar xzf opus_testvectors-rfc8251.tar.gz                 # gives opus_newvectors/
mkdir -p probe/src res dump encout                      # probe/Cargo.toml and probe/src/main.rs: below
docker run --rm -u "$(id -u):$(id -g)" -e CARGO_HOME=/w/.cargo -v "$PWD":/w -w /w rust:1.95-bookworm sh -c '
  (cd probe && cargo build --release) &&
  for c in opus-pure ruopus opus-rs rusty-opus mousiki; do
    probe/target/release/opusprobe conf $c opus_newvectors dump > res/conf_$c.txt
  done &&
  MOUSIKI_I16=1 probe/target/release/opusprobe conf mousiki opus_newvectors > res/conf_mousiki_i16.txt &&
  for c in opus-pure ruopus opus-rs rusty-opus mousiki; do
    probe/target/release/opusprobe enc $c opus_newvectors encout/$c.bit
  done &&
  for e in opus-pure ruopus opus-rs rusty-opus mousiki; do
    for d in opus-pure ruopus opus-rs; do probe/target/release/opusprobe rng $d encout/$e.bit; done
  done'
grep SUMMARY res/conf_*.txt                             # per-vector lines are above each summary
# unsafe sites, per crate (registry sources are under .cargo/registry/src/*/):
grep -rhwE unsafe .cargo/registry/src/*/opus-pure-0.2.5/src --include=*.rs \
  | grep -vE '^\s*(//|\*|/\*)' | grep -cwE 'unsafe\s*(\{|fn|impl|extern)'
```

## Cross-checking the port

The port was checked against the original: compile libopus's own `opus_compare.c` and score every decode in `dump/`
(`<crate>_vNN_1.pcm` is the mono output, `<crate>_vNN_2.pcm` the stereo one) as `run_vectors.sh` does. On the run
recorded in CALLS.md the two agreed on all 240 verdicts (120 decodes, two references each) and on every error value
to six decimals. The C file is only compiled on the side for this check; it is not part of CrewCraft.

```sh
curl -fsSLO https://raw.githubusercontent.com/xiph/opus/v1.5.2/src/opus_compare.c
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/w -w /w rust:1.95-bookworm sh -c '
  gcc -O2 -o opus_compare_c opus_compare.c -lm &&
  for c in opus-pure ruopus opus-rs rusty-opus mousiki; do
    for v in 01 02 03 04 05 06 07 08 09 10 11 12; do
      ./opus_compare_c    -r 48000 opus_newvectors/testvector$v.dec  dump/${c}_v${v}_1.pcm
      ./opus_compare_c    -r 48000 opus_newvectors/testvector${v}m.dec dump/${c}_v${v}_1.pcm
      ./opus_compare_c -s -r 48000 opus_newvectors/testvector$v.dec  dump/${c}_v${v}_2.pcm
      ./opus_compare_c -s -r 48000 opus_newvectors/testvector${v}m.dec dump/${c}_v${v}_2.pcm
    done
  done' 2>&1 | grep -E "PASSES|FAILS|error is"
```

The probe's own scores for a pair of files: `probe/target/release/opusprobe cmp [-s] <reference.dec> <output.pcm>`.

## probe/Cargo.toml

```toml
[package]
name = "opusprobe"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
opus-rs = "=0.1.42"
rusty-opus = "=1.2.1"
mousiki = "=0.2.1"
opus-pure = "=0.2.5"
ruopus = { version = "=0.1.2", default-features = false, features = ["std"] }
```

## probe/src/main.rs

The `opus_compare` functions in this program are a port of libopus's `src/opus_compare.c` (tag v1.5.2,
https://github.com/xiph/opus/blob/v1.5.2/src/opus_compare.c), used under its BSD license; it is listed in
[ATTRIBUTION.md](../../ATTRIBUTION.md). The original notice:

```text
Copyright (c) 2011-2012 Xiph.Org Foundation, Mozilla Corporation
Written by Jean-Marc Valin and Timothy B. Terriberry

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

- Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

- Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

```rust
// Throwaway probe: decode the RFC 8251 Opus test vectors with each pure-Rust candidate, check every packet's final
// range against the value stored in the .bit file, and score the output with a Rust port of libopus's opus_compare
// (ported from src/opus_compare.c at libopus v1.5.2; its BSD notice is above that section). Also times 48 kHz mono
// 20 ms encoding.
//
//   opusprobe conf <crate> <vector-dir> [dump-dir]   conformance: 12 vectors, mono and stereo decode
//   opusprobe enc  <crate> <vector-dir> <out.bit>    encode timing at complexity 10 and 5; writes the c10 stream
//   opusprobe rng  <crate> <file.bit>                decode a .bit file, count final-range mismatches only
//   opusprobe cmp  [-s] <ref.dec> <test.pcm>         the opus_compare port on two files (for cross-checking)

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

const MAXF: usize = 5760; // 120 ms at 48 kHz

trait Dec {
    fn decode(&mut self, pkt: &[u8], out: &mut [f32]) -> Result<usize, String>;
    fn rng(&mut self) -> u32;
}
trait Enc {
    fn encode(&mut self, pcm: &[f32], out: &mut [u8]) -> Result<usize, String>;
    fn rng(&mut self) -> u32;
}

// ---------- opus-rs ----------
struct OrD(opus_rs::OpusDecoder);
impl Dec for OrD {
    fn decode(&mut self, p: &[u8], o: &mut [f32]) -> Result<usize, String> {
        self.0.decode(p, MAXF, o).map_err(|e| e.to_string())
    }
    fn rng(&mut self) -> u32 {
        self.0.final_range()
    }
}
struct OrE(opus_rs::OpusEncoder);
impl Enc for OrE {
    fn encode(&mut self, p: &[f32], o: &mut [u8]) -> Result<usize, String> {
        self.0.encode(p, p.len(), o).map_err(|e| e.to_string())
    }
    fn rng(&mut self) -> u32 {
        self.0.final_range()
    }
}

// ---------- rusty-opus ----------
struct RoD(rusty_opus::OpusDecoder);
impl Dec for RoD {
    fn decode(&mut self, p: &[u8], o: &mut [f32]) -> Result<usize, String> {
        self.0.decode(p, MAXF, o).map_err(|e| format!("{e:?}"))
    }
    fn rng(&mut self) -> u32 {
        self.0.last_range // rusty-opus exposes the decoder's final range as a field
    }
}
struct RoE(rusty_opus::OpusEncoder);
impl Enc for RoE {
    fn encode(&mut self, p: &[f32], o: &mut [u8]) -> Result<usize, String> {
        self.0.encode(p, p.len(), o).map_err(|e| format!("{e:?}"))
    }
    fn rng(&mut self) -> u32 {
        self.0.final_range()
    }
}

// ---------- opus-pure ----------
struct OpD(opus_pure::OpusDecoder);
impl Dec for OpD {
    fn decode(&mut self, p: &[u8], o: &mut [f32]) -> Result<usize, String> {
        self.0.decode(p, MAXF, o).map_err(|e| format!("{e:?}"))
    }
    fn rng(&mut self) -> u32 {
        self.0.final_range()
    }
}
struct OpE(opus_pure::OpusEncoder);
impl Enc for OpE {
    fn encode(&mut self, p: &[f32], o: &mut [u8]) -> Result<usize, String> {
        self.0.encode(p, p.len(), o).map_err(|e| format!("{e:?}"))
    }
    fn rng(&mut self) -> u32 {
        self.0.final_range()
    }
}

// ---------- mousiki ----------
struct MkD(mousiki::Decoder, usize);
impl Dec for MkD {
    fn decode(&mut self, p: &[u8], o: &mut [f32]) -> Result<usize, String> {
        let n = MAXF * self.1;
        if std::env::var_os("MOUSIKI_I16").is_some() {
            // mousiki's 16-bit path (opus_decode); converted back to float exactly.
            let mut b = vec![0i16; n];
            let k = self.0.decode(p, &mut b, false).map_err(|e| format!("{e:?}"))?;
            for (d, s) in o.iter_mut().zip(&b[..k * self.1]) {
                *d = *s as f32 / 32768.0;
            }
            return Ok(k);
        }
        self.0.decode_float(p, &mut o[..n], false).map_err(|e| format!("{e:?}"))
    }
    fn rng(&mut self) -> u32 {
        self.0.final_range().unwrap_or(0)
    }
}
struct MkE(mousiki::Encoder);
impl Enc for MkE {
    fn encode(&mut self, p: &[f32], o: &mut [u8]) -> Result<usize, String> {
        self.0.encode_float(p, o).map_err(|e| format!("{e:?}"))
    }
    fn rng(&mut self) -> u32 {
        self.0.final_range().unwrap_or(0)
    }
}

// ---------- ruopus (default features off, std on) ----------
struct RuD(ruopus::OpusDecoder, usize);
impl Dec for RuD {
    fn decode(&mut self, p: &[u8], o: &mut [f32]) -> Result<usize, String> {
        let v = self.0.decode_packet(p).map_err(|e| format!("{e:?}"))?;
        o[..v.len()].copy_from_slice(&v);
        Ok(v.len() / self.1)
    }
    fn rng(&mut self) -> u32 {
        self.0.final_range()
    }
}
struct RuE(ruopus::OpusEncoder);
impl Enc for RuE {
    fn encode(&mut self, p: &[f32], o: &mut [u8]) -> Result<usize, String> {
        let v = self.0.encode_auto(p, 1275).map_err(|e| format!("{e:?}"))?;
        o[..v.len()].copy_from_slice(&v);
        Ok(v.len())
    }
    fn rng(&mut self) -> u32 {
        self.0.final_range()
    }
}

fn mk_dec(name: &str, ch: usize) -> Box<dyn Dec> {
    match name {
        "opus-rs" => Box::new(OrD(opus_rs::OpusDecoder::new(48000, ch).unwrap())),
        "rusty-opus" => Box::new(RoD(rusty_opus::OpusDecoder::new(48000, ch).unwrap())),
        "opus-pure" => Box::new(OpD(opus_pure::OpusDecoder::new(48000, ch).unwrap())),
        "mousiki" => {
            let c = if ch == 1 { mousiki::Channels::Mono } else { mousiki::Channels::Stereo };
            Box::new(MkD(mousiki::Decoder::new(48000, c).unwrap(), ch))
        }
        "ruopus" => Box::new(RuD(ruopus::OpusDecoder::new(ch), ch)),
        _ => panic!("unknown crate {name}"),
    }
}

fn mk_enc(name: &str, cx: i32) -> Box<dyn Enc> {
    const BR: i32 = 32000;
    match name {
        "opus-rs" => {
            let mut e = opus_rs::OpusEncoder::new(48000, 1, opus_rs::Application::Voip).unwrap();
            e.bitrate_bps = BR;
            e.complexity = cx;
            Box::new(OrE(e))
        }
        "rusty-opus" => {
            let mut e = rusty_opus::OpusEncoder::new(48000, 1, rusty_opus::Application::Voip).unwrap();
            e.bitrate_bps = BR;
            e.complexity = cx;
            Box::new(RoE(e))
        }
        "opus-pure" => {
            let mut e = opus_pure::OpusEncoder::new(48000, 1, opus_pure::Application::Voip).unwrap();
            e.bitrate_bps = BR;
            e.complexity = cx;
            Box::new(OpE(e))
        }
        "mousiki" => {
            let mut e =
                mousiki::Encoder::new(48000, mousiki::Channels::Mono, mousiki::Application::Voip).unwrap();
            e.set_complexity(cx).unwrap();
            e.set_bitrate(mousiki::Bitrate::Bits(BR)).unwrap();
            Box::new(MkE(e))
        }
        "ruopus" => {
            let mut e = ruopus::OpusEncoder::new(1);
            e.set_application(ruopus::Application::Voip);
            e.set_bitrate(Some(BR as u32));
            e.set_complexity(cx as u8);
            Box::new(RuE(e))
        }
        _ => panic!("unknown crate {name}"),
    }
}

// ---------- files ----------
fn read_bit(path: &str) -> Vec<(Vec<u8>, u32)> {
    let d = std::fs::read(path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut i = 0;
    let mut v = Vec::new();
    while i + 8 <= d.len() {
        let len = u32::from_be_bytes(d[i..i + 4].try_into().unwrap()) as usize;
        let rng = u32::from_be_bytes(d[i + 4..i + 8].try_into().unwrap());
        i += 8;
        v.push((d[i..i + len].to_vec(), rng));
        i += len;
    }
    v
}
fn read_pcm16(path: &str) -> Vec<i16> {
    std::fs::read(path)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .chunks_exact(2)
        .map(|b| i16::from_le_bytes([b[0], b[1]]))
        .collect()
}
fn toc_samples(p: &[u8]) -> Option<usize> {
    let toc = *p.first()?;
    let cfg = toc >> 3;
    let fs = if cfg < 12 {
        [480, 960, 1920, 2880][(cfg & 3) as usize]
    } else if cfg < 16 {
        [480, 960][(cfg & 1) as usize]
    } else {
        [120, 240, 480, 960][(cfg & 3) as usize]
    };
    let frames = match toc & 3 {
        0 => 1,
        1 | 2 => 2,
        _ => (*p.get(1)? & 0x3f) as usize,
    };
    Some(fs * frames)
}
// libopus FLOAT2INT16: scale, clamp, round half to even (lrintf).
fn f2i16(x: f32) -> i16 {
    (x * 32768.0).clamp(-32768.0, 32767.0).round_ties_even() as i16
}

struct DecodeResult {
    pcm: Vec<i16>,
    packets: usize,
    rng_bad: usize,
    first_bad: Option<usize>,
    len_bad: usize,
    errors: usize,
    first_err: Option<String>,
    secs: f64,
}

fn decode_stream(name: &str, ch: usize, pkts: &[(Vec<u8>, u32)]) -> DecodeResult {
    let mut d = mk_dec(name, ch);
    let mut out = vec![0f32; MAXF * 2];
    let mut r = DecodeResult {
        pcm: Vec::new(),
        packets: pkts.len(),
        rng_bad: 0,
        first_bad: None,
        len_bad: 0,
        errors: 0,
        first_err: None,
        secs: 0.0,
    };
    let t = Instant::now();
    for (i, (p, rng)) in pkts.iter().enumerate() {
        match d.decode(p, &mut out) {
            Ok(n) => {
                if Some(n) != toc_samples(p) {
                    r.len_bad += 1;
                }
                r.pcm.extend(out[..n * ch].iter().map(|&x| f2i16(x)));
                if d.rng() != *rng {
                    r.rng_bad += 1;
                    r.first_bad.get_or_insert(i);
                }
            }
            Err(e) => {
                r.errors += 1;
                r.rng_bad += 1;
                r.first_bad.get_or_insert(i);
                r.first_err.get_or_insert(format!("packet {i}: {e}"));
            }
        }
    }
    r.secs = t.elapsed().as_secs_f64();
    r
}

// ---------- opus_compare, ported from libopus src/opus_compare.c (v1.5.2) ----------
// The constants and functions from here up to `fmt_cmp` are a Rust port of opus_compare.c, whose notice follows.
//
// Copyright (c) 2011-2012 Xiph.Org Foundation, Mozilla Corporation
// Written by Jean-Marc Valin and Timothy B. Terriberry
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
// - Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//
// - Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
// OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

const NBANDS: usize = 21;
const NFREQS: usize = 240;
const BANDS: [usize; NBANDS + 1] = [0, 2, 4, 6, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 68, 80, 96, 120, 156, 200];
const TEST_WIN_SIZE: usize = 480;
const TEST_WIN_STEP: usize = 120;
const OPUS_PI: f32 = 3.14159265;

#[allow(clippy::too_many_arguments)]
fn band_energy(
    out: Option<&mut [f32]>,
    ps: &mut [f32],
    bands: &[usize],
    nbands: usize,
    inp: &[f32],
    nch: usize,
    nframes: usize,
    win: usize,
    step: usize,
    downsample: usize,
) {
    let mut out = out;
    let window: Vec<f32> = (0..win)
        .map(|j| 0.5f32 - 0.5f32 * (((2.0 * OPUS_PI / (win - 1) as f32) * j as f32) as f64).cos() as f32)
        .collect();
    let c: Vec<f32> = (0..win).map(|j| (((2.0 * OPUS_PI / win as f32) * j as f32) as f64).cos() as f32).collect();
    let s: Vec<f32> = (0..win).map(|j| (((2.0 * OPUS_PI / win as f32) * j as f32) as f64).sin() as f32).collect();
    let mut x = vec![0f32; nch * win];
    let ps_sz = win / 2;
    for xi in 0..nframes {
        for ci in 0..nch {
            for xk in 0..win {
                x[ci * win + xk] = window[xk] * inp[(xi * step + xk) * nch + ci];
            }
        }
        let mut xj = 0;
        for bi in 0..nbands {
            let mut p = [0f32; 2];
            while xj < bands[bi + 1] {
                for ci in 0..nch {
                    let mut ti = 0;
                    let (mut re, mut im) = (0f32, 0f32);
                    for xk in 0..win {
                        re += c[ti] * x[ci * win + xk];
                        im -= s[ti] * x[ci * win + xk];
                        ti += xj;
                        if ti >= win {
                            ti -= win;
                        }
                    }
                    re *= downsample as f32;
                    im *= downsample as f32;
                    let v = re * re + im * im + 100000.0;
                    ps[(xi * ps_sz + xj) * nch + ci] = v;
                    p[ci] += v;
                }
                xj += 1;
            }
            if let Some(o) = out.as_deref_mut() {
                let w = (bands[bi + 1] - bands[bi]) as f32;
                o[(xi * nbands + bi) * nch] = p[0] / w;
                if nch == 2 {
                    o[(xi * nbands + bi) * nch + 1] = p[1] / w;
                }
            }
        }
    }
}

/// `reference` is always a stereo file (as in opus_compare); `test` has `nch` channels. 48 kHz only.
fn opus_compare(reference: &[i16], test: &[i16], nch: usize) -> Result<(f32, f64), String> {
    let xlength = reference.len() / 2;
    let mut x: Vec<f32> = reference.iter().map(|&s| s as f32).collect();
    if nch == 1 {
        for xi in 0..xlength {
            x[xi] = (0.5 * (x[2 * xi] as f64 + x[2 * xi + 1] as f64)) as f32;
        }
        x.truncate(xlength);
    }
    let ylength = test.len() / nch;
    let y: Vec<f32> = test.iter().map(|&s| s as f32).collect();
    if xlength != ylength {
        return Err(format!("Sample counts do not match ({xlength}!={ylength})"));
    }
    if xlength < TEST_WIN_SIZE {
        return Err("Insufficient sample data".into());
    }
    let nframes = (xlength - TEST_WIN_SIZE + TEST_WIN_STEP) / TEST_WIN_STEP;
    let (ybands, yfreqs) = (NBANDS, NFREQS);
    let mut xb = vec![0f32; nframes * NBANDS * nch];
    let mut xs = vec![0f32; nframes * NFREQS * nch];
    let mut ys = vec![0f32; nframes * yfreqs * nch];
    band_energy(Some(&mut xb), &mut xs, &BANDS, NBANDS, &x, nch, nframes, TEST_WIN_SIZE, TEST_WIN_STEP, 1);
    band_energy(None, &mut ys, &BANDS, ybands, &y, nch, nframes, TEST_WIN_SIZE, TEST_WIN_STEP, 1);
    for xi in 0..nframes {
        for bi in 1..NBANDS {
            for ci in 0..nch {
                xb[(xi * NBANDS + bi) * nch + ci] += 0.1 * xb[(xi * NBANDS + bi - 1) * nch + ci];
            }
        }
        for bi in (0..NBANDS - 1).rev() {
            for ci in 0..nch {
                xb[(xi * NBANDS + bi) * nch + ci] += 0.03 * xb[(xi * NBANDS + bi + 1) * nch + ci];
            }
        }
        if xi > 0 {
            for bi in 0..NBANDS {
                for ci in 0..nch {
                    xb[(xi * NBANDS + bi) * nch + ci] += 0.5 * xb[((xi - 1) * NBANDS + bi) * nch + ci];
                }
            }
        }
        if nch == 2 {
            for bi in 0..NBANDS {
                let l = xb[(xi * NBANDS + bi) * nch];
                let r = xb[(xi * NBANDS + bi) * nch + 1];
                xb[(xi * NBANDS + bi) * nch] += 0.01 * r;
                xb[(xi * NBANDS + bi) * nch + 1] += 0.01 * l;
            }
        }
        for bi in 0..ybands {
            for xj in BANDS[bi]..BANDS[bi + 1] {
                for ci in 0..nch {
                    let m = 0.1 * xb[(xi * NBANDS + bi) * nch + ci];
                    xs[(xi * NFREQS + xj) * nch + ci] += m;
                    ys[(xi * yfreqs + xj) * nch + ci] += m;
                }
            }
        }
    }
    for bi in 0..ybands {
        for xj in BANDS[bi]..BANDS[bi + 1] {
            for ci in 0..nch {
                let mut xtmp = xs[xj * nch + ci];
                let mut ytmp = ys[xj * nch + ci];
                for xi in 1..nframes {
                    let xtmp2 = xs[(xi * NFREQS + xj) * nch + ci];
                    let ytmp2 = ys[(xi * yfreqs + xj) * nch + ci];
                    xs[(xi * NFREQS + xj) * nch + ci] += xtmp;
                    ys[(xi * yfreqs + xj) * nch + ci] += ytmp;
                    xtmp = xtmp2;
                    ytmp = ytmp2;
                }
            }
        }
    }
    let max_compare = BANDS[NBANDS];
    let mut err = 0f64;
    for xi in 0..nframes {
        let mut ef = 0f64;
        for bi in 0..ybands {
            let mut eb = 0f64;
            let mut xj = BANDS[bi];
            while xj < BANDS[bi + 1] && xj < max_compare {
                for ci in 0..nch {
                    let re: f32 = ys[(xi * yfreqs + xj) * nch + ci] / xs[(xi * NFREQS + xj) * nch + ci];
                    let mut im: f32 = (re as f64 - (re as f64).ln() - 1.0) as f32;
                    if (79..=81).contains(&xj) {
                        im *= 0.1;
                    }
                    if xj == 80 {
                        im *= 0.1;
                    }
                    eb += im as f64;
                }
                xj += 1;
            }
            eb /= ((BANDS[bi + 1] - BANDS[bi]) * nch) as f64;
            ef += eb * eb;
        }
        ef /= NBANDS as f64;
        ef *= ef;
        err += ef * ef;
    }
    let err = (err / nframes as f64).powf(1.0 / 16.0);
    let q = (100.0 * (1.0 - 0.5 * (1.0 + err).ln() / 1.13f64.ln())) as f32;
    Ok((q, err))
}

fn fmt_cmp(r: &Result<(f32, f64), String>) -> String {
    match r {
        Ok((q, e)) => format!("{}{:.1}% (err {:.6})", if *q >= 0.0 { "PASS " } else { "FAIL " }, q, e),
        Err(e) => format!("FAIL {e}"),
    }
}
fn passes(r: &Result<(f32, f64), String>) -> bool {
    matches!(r, Ok((q, _)) if *q >= 0.0)
}

fn conf(name: &str, vdir: &str, dump: Option<&String>) {
    let mut n_rng = 0;
    let mut n_cmp = 0;
    let mut n_both = 0;
    let mut dec_secs = 0.0;
    let mut audio_secs = 0.0;
    for v in 1..=12 {
        let base = format!("{vdir}/testvector{v:02}");
        let pkts = read_bit(&format!("{base}.bit"));
        let rs = read_pcm16(&format!("{base}.dec"));
        let rm = read_pcm16(&format!("{base}m.dec"));
        let mut rng_ok = true;
        let mut cmp_ok = true;
        for ch in [1usize, 2] {
            let tag = if ch == 1 { "mono  " } else { "stereo" };
            let res = catch_unwind(AssertUnwindSafe(|| decode_stream(name, ch, &pkts)));
            let Ok(r) = res else {
                println!("{name} v{v:02} {tag} PANIC");
                rng_ok = false;
                cmp_ok = false;
                continue;
            };
            if let Some(dir) = dump {
                let bytes: Vec<u8> = r.pcm.iter().flat_map(|s| s.to_le_bytes()).collect();
                std::fs::write(format!("{dir}/{name}_v{v:02}_{ch}.pcm"), bytes).unwrap();
            }
            dec_secs += r.secs;
            audio_secs += r.pcm.len() as f64 / ch as f64 / 48000.0;
            let c1 = opus_compare(&rs, &r.pcm, ch);
            let c2 = opus_compare(&rm, &r.pcm, ch);
            let ok_cmp = passes(&c1) || passes(&c2);
            let ok_rng = r.rng_bad == 0 && r.errors == 0;
            rng_ok &= ok_rng;
            cmp_ok &= ok_cmp;
            println!(
                "{name} v{v:02} {tag} packets {} range-mismatch {} (first {:?}) errors {} {} len-mismatch {} | vs .dec: {} | vs m.dec: {}",
                r.packets,
                r.rng_bad,
                r.first_bad,
                r.errors,
                r.first_err.as_deref().unwrap_or(""),
                r.len_bad,
                fmt_cmp(&c1),
                fmt_cmp(&c2)
            );
        }
        n_rng += rng_ok as u32;
        n_cmp += cmp_ok as u32;
        n_both += (rng_ok && cmp_ok) as u32;
    }
    println!(
        "SUMMARY {name}: final range {n_rng}/12, opus_compare {n_cmp}/12, both {n_both}/12; decode {:.2} s for {:.0} s of audio ({:.0}x real time)",
        dec_secs,
        audio_secs,
        audio_secs / dec_secs
    );
}

fn enc(name: &str, vdir: &str, out_bit: &str) {
    // Input: the mono downmix of the 12 reference decodes (speech and music, ~320 s).
    let mut pcm = Vec::new();
    for v in 1..=12 {
        let r = read_pcm16(&format!("{vdir}/testvector{v:02}.dec"));
        pcm.extend(r.chunks_exact(2).map(|s| (s[0] as f32 + s[1] as f32) * 0.5 / 32768.0));
    }
    let frames = pcm.len() / 960;
    let audio = frames as f64 * 0.02;
    for cx in [10, 5] {
        let mut best = f64::MAX;
        let mut bytes = 0usize;
        let mut stream = Vec::new();
        for run in 0..3 {
            let mut e = mk_enc(name, cx);
            let mut out = vec![0u8; 1500];
            let mut s = Vec::new();
            bytes = 0;
            let t = Instant::now();
            for f in 0..frames {
                let n = e.encode(&pcm[f * 960..(f + 1) * 960], &mut out).unwrap();
                bytes += n;
                if run == 0 && cx == 10 {
                    s.extend_from_slice(&(n as u32).to_be_bytes());
                    s.extend_from_slice(&e.rng().to_be_bytes());
                    s.extend_from_slice(&out[..n]);
                }
            }
            best = best.min(t.elapsed().as_secs_f64());
            if run == 0 && cx == 10 {
                stream = s;
            }
        }
        if cx == 10 {
            std::fs::write(out_bit, &stream).unwrap();
        }
        println!(
            "ENC {name} complexity {cx}: {frames} frames ({audio:.0} s) best of 3 {:.3} s = {:.1} us/frame, {:.0}x real time, {:.1} kbit/s",
            best,
            best / frames as f64 * 1e6,
            audio / best,
            bytes as f64 * 8.0 / audio / 1000.0
        );
    }
}

fn rng_only(name: &str, path: &str) {
    let pkts = read_bit(path);
    let res = catch_unwind(AssertUnwindSafe(|| decode_stream(name, 1, &pkts)));
    match res {
        Ok(r) => println!(
            "RNG decoder {name} file {path}: packets {} range-mismatch {} errors {}",
            r.packets, r.rng_bad, r.errors
        ),
        Err(_) => println!("RNG decoder {name} file {path}: PANIC"),
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("conf") => conf(&a[2], &a[3], a.get(4)),
        Some("enc") => enc(&a[2], &a[3], &a[4]),
        Some("rng") => rng_only(&a[2], &a[3]),
        Some("cmp") => {
            let (nch, i) = if a[2] == "-s" { (2, 3) } else { (1, 2) };
            let r = opus_compare(&read_pcm16(&a[i]), &read_pcm16(&a[i + 1]), nch);
            println!("{}", fmt_cmp(&r));
        }
        _ => eprintln!("usage: opusprobe conf|enc|rng|cmp ..."),
    }
}
```
