//! T362a: two str0m peers that use only CrewCraft's provider connect over an in-memory network (ICE, DTLS, SRTP) and
//! carry an audio stream; what crosses the network is encrypted. str0m is built with no crypto backend of its own,
//! so every DTLS, SRTP and hash step here is the provider's.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use str0m::format::Codec;
use str0m::media::{Direction, MediaKind};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc};

/// The simulated time between steps.
const TICK: Duration = Duration::from_millis(5);

/// A datagram on the in-memory network: from, to, bytes.
type Datagram = (SocketAddr, SocketAddr, Vec<u8>);

struct Peer {
    rtc: Rtc,
    events: Vec<Event>,
}

impl Peer {
    fn new(address: SocketAddr, now: Instant) -> Self {
        let mut rtc = Rtc::builder().set_crypto_provider(Arc::new(crewcraft_media_crypto::provider())).build(now);
        rtc.add_local_candidate(Candidate::host(address, "udp").unwrap());
        Peer { rtc, events: Vec::new() }
    }

    /// Everything the peer has to send, onto `wire`; its events kept.
    fn drain(&mut self, wire: &mut Vec<Datagram>) {
        loop {
            match self.rtc.poll_output().unwrap() {
                Output::Timeout(_) => return,
                Output::Transmit(sent) => wire.push((sent.source, sent.destination, sent.contents.to_vec())),
                Output::Event(event) => self.events.push(event),
            }
        }
    }

    fn receive(&mut self, now: Instant, datagrams: Vec<Datagram>) {
        for (source, destination, bytes) in datagrams {
            let contents = bytes.as_slice().try_into().unwrap();
            self.rtc.handle_input(Input::Receive(now, Receive { proto: Protocol::Udp, source, destination, contents })).unwrap();
        }
    }
}

/// One step: each peer sends what it has, the other receives it, and the clock moves on. Every datagram that went
/// from `l` to `r` is also returned.
fn step(l: &mut Peer, r: &mut Peer, now: &mut Instant) -> Vec<Datagram> {
    let (mut to_r, mut to_l) = (Vec::new(), Vec::new());
    l.drain(&mut to_r);
    r.drain(&mut to_l);
    r.receive(*now, to_r.clone());
    l.receive(*now, to_l);
    *now += TICK;
    l.rtc.handle_input(Input::Timeout(*now)).unwrap();
    r.rtc.handle_input(Input::Timeout(*now)).unwrap();
    to_r
}

#[test]
fn two_str0m_peers_on_the_provider_carry_encrypted_audio() {
    let start = Instant::now();
    let mut now = start;
    let mut l = Peer::new((Ipv4Addr::new(10, 0, 0, 1), 1000).into(), now);
    let mut r = Peer::new((Ipv4Addr::new(10, 0, 0, 2), 2000).into(), now);
    let mut change = l.rtc.sdp_api();
    let mid = change.add_media(MediaKind::Audio, Direction::SendRecv, None, None, None);
    let (offer, pending) = change.apply().unwrap();
    let answer = r.rtc.sdp_api().accept_offer(offer).unwrap();
    l.rtc.sdp_api().accept_answer(pending, answer).unwrap();

    // ICE, then DTLS with the provider's certificates and the fingerprints in the session descriptions.
    for _ in 0..2000 {
        if l.rtc.is_connected() && r.rtc.is_connected() {
            break;
        }
        step(&mut l, &mut r, &mut now);
    }
    assert!(l.rtc.is_connected() && r.rtc.is_connected(), "the peers did not connect");
    assert!(l.events.iter().any(|event| matches!(event, Event::Connected)));

    // One second of audio frames, every 20 ms, that say what they are in plain text.
    let pt = l.rtc.codec_config().find(|params| params.spec().codec == Codec::Opus).unwrap().pt();
    let frame = b"crewcraft plain audio frame ".repeat(3);
    let mut wire = Vec::new();
    for n in 0..50u32 {
        let at = now;
        l.rtc.writer(mid).unwrap().write(pt, at, Duration::from_millis(20 * u64::from(n)).into(), frame.clone()).unwrap();
        for _ in 0..4 {
            wire.extend(step(&mut l, &mut r, &mut now));
        }
    }
    for _ in 0..40 {
        wire.extend(step(&mut l, &mut r, &mut now));
    }

    // They arrive whole at the other peer...
    let arrived = r.events.iter().filter(|event| matches!(event, Event::MediaData(data) if *data.data == frame[..])).count();
    assert!(arrived >= 45, "only {arrived} of 50 frames arrived");
    // ...and none of them crossed the network readable: SRTP encrypted every one.
    let needle = b"crewcraft plain audio";
    let readable = wire.iter().filter(|(_, _, bytes)| bytes.windows(needle.len()).any(|w| w == needle)).count();
    assert_eq!(readable, 0, "a datagram carried the frame in the clear");
    assert!(wire.len() >= 50, "the frames went over the network");
}
