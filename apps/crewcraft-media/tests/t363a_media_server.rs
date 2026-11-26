//! T363a: the media server (docs/CALLS.md "The shape" and "Admission"). Three str0m clients on CrewCraft's own
//! crypto provider connect to the server over an in-memory network, each with a media credential: two in one call
//! and one in another. A participant's audio reaches the others of its call byte for byte and never another call;
//! expired, replayed, misdirected and forged credentials are refused; a participant who is dropped stops receiving.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crewcraft_media::{Config, CredentialError, Datagram, JoinError, MediaServer, ParticipantId};
use crewcraft_media_auth::{Issuer, LIFETIME_MS};
use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::format::Codec;
use str0m::media::{Direction, MediaKind, Mid};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, Input, Output, Rtc};

const MEDIA: &str = "media.example.org";
/// Wall-clock milliseconds the credentials are issued at.
const T0: u64 = 1_800_000_000_000;
const CALL_A: u64 = 7;
const CALL_B: u64 = 8;
/// The simulated time between steps.
const TICK: Duration = Duration::from_millis(5);
/// Receiving sections each client offers.
const SLOTS: usize = 2;

fn server_address() -> SocketAddr {
    (Ipv4Addr::new(203, 0, 113, 10), 3478).into()
}

struct Client {
    address: SocketAddr,
    rtc: Rtc,
    /// The section the client sends its audio on.
    mic: Mid,
    pending: Option<SdpPendingOffer>,
    events: Vec<Event>,
}

impl Client {
    /// A client at 198.51.100.`n` and its offer: one audio section it sends, `SLOTS` it only receives.
    fn new(n: u8, now: Instant) -> (Client, String) {
        let address: SocketAddr = (Ipv4Addr::new(198, 51, 100, n), 5000).into();
        let mut rtc = Rtc::builder().set_crypto_provider(Arc::new(crewcraft_media_crypto::provider())).build(now);
        rtc.add_local_candidate(Candidate::host(address, "udp").unwrap());
        let mut change = rtc.sdp_api();
        let mic = change.add_media(MediaKind::Audio, Direction::SendOnly, None, None, None);
        for _ in 0..SLOTS {
            change.add_media(MediaKind::Audio, Direction::RecvOnly, None, None, None);
        }
        let (offer, pending) = change.apply().unwrap();
        (Client { address, rtc, mic, pending: Some(pending), events: Vec::new() }, offer.to_sdp_string())
    }

    fn accept(&mut self, answer: &str) {
        let pending = self.pending.take().unwrap();
        self.rtc.sdp_api().accept_answer(pending, SdpAnswer::from_sdp_string(answer).unwrap()).unwrap();
    }

    fn drain(&mut self, wire: &mut Vec<(SocketAddr, SocketAddr, Vec<u8>)>) {
        loop {
            match self.rtc.poll_output().unwrap() {
                Output::Timeout(_) => return,
                Output::Transmit(sent) => wire.push((sent.source, sent.destination, sent.contents.to_vec())),
                Output::Event(event) => self.events.push(event),
            }
        }
    }

    /// Send one 20 ms audio frame.
    fn send(&mut self, n: u32, frame: &[u8], now: Instant) {
        let pt = self.rtc.codec_config().find(|params| params.spec().codec == Codec::Opus).unwrap().pt();
        let time = Duration::from_millis(20 * u64::from(n)).into();
        self.rtc.writer(self.mic).unwrap().write(pt, now, time, frame.to_vec()).unwrap();
    }

    /// Every audio frame this client has received, in order.
    fn received(&self) -> Vec<Vec<u8>> {
        self.events.iter().filter_map(|event| if let Event::MediaData(data) = event { Some(data.data.to_vec()) } else { None }).collect()
    }
}

/// The server, its clients and the simulated clock.
struct Net {
    server: MediaServer,
    issuer: Issuer,
    clients: Vec<Client>,
    now: Instant,
}

impl Net {
    fn new() -> Net {
        let issuer = Issuer::from_pkcs8(&Issuer::generate().unwrap()).unwrap();
        let server = MediaServer::new(Config { server_name: MEDIA.to_owned(), trusted_key: issuer.public_key(), address: server_address() });
        Net { server, issuer, clients: Vec::new(), now: Instant::now() }
    }

    fn credential(&self, call: u64, person: &str, device: u64) -> Vec<u8> {
        self.issuer.issue(call, "general", person, device, MEDIA, T0).unwrap()
    }

    /// A new client joins `call` with a fresh credential; returns its index and participant.
    fn join(&mut self, n: u8, call: u64, person: &str) -> (usize, ParticipantId) {
        let (mut client, offer) = Client::new(n, self.now);
        let credential = self.credential(call, person, u64::from(n));
        let joined = self.server.join(call, &credential, &offer, self.now, T0 + 1_000).unwrap();
        client.accept(&joined.answer);
        self.clients.push(client);
        (self.clients.len() - 1, joined.id)
    }

    /// One step: the server and every client send what they have, it is delivered, and the clock moves on.
    fn step(&mut self) {
        let mut from_server: Vec<Datagram> = Vec::new();
        self.server.poll(self.now, &mut from_server);
        let mut from_clients = Vec::new();
        for client in &mut self.clients {
            client.drain(&mut from_clients);
        }
        for (source, destination, bytes) in from_clients {
            if destination == server_address() {
                self.server.receive(self.now, source, &bytes);
            }
        }
        for datagram in from_server {
            if let Some(client) = self.clients.iter_mut().find(|client| client.address == datagram.to) {
                let contents = datagram.bytes.as_slice().try_into().unwrap();
                let receive = Receive { proto: Protocol::Udp, source: server_address(), destination: client.address, contents };
                client.rtc.handle_input(Input::Receive(self.now, receive)).unwrap();
            }
        }
        self.now += TICK;
        for client in &mut self.clients {
            client.rtc.handle_input(Input::Timeout(self.now)).unwrap();
        }
    }

    fn connect(&mut self) {
        for _ in 0..2000 {
            if self.clients.iter().all(|client| client.rtc.is_connected()) {
                break;
            }
            self.step();
        }
        assert!(self.clients.iter().all(|client| client.rtc.is_connected()), "a client did not connect");
        // A little longer, so the server sees every client's media sections and the DTLS handshakes settle.
        for _ in 0..20 {
            self.step();
        }
    }

    /// `client` sends `count` frames, numbered from `first`, saying who sent them; the network runs meanwhile.
    fn talk(&mut self, client: usize, who: &str, first: u32, count: u32) -> Vec<Vec<u8>> {
        let mut sent = Vec::new();
        for n in first..first + count {
            let frame = format!("{who} opaque frame {n:04}").into_bytes();
            let now = self.now;
            self.clients[client].send(n, &frame, now);
            sent.push(frame);
            for _ in 0..4 {
                self.step();
            }
        }
        for _ in 0..40 {
            self.step();
        }
        sent
    }
}

#[test]
fn media_reaches_its_own_call_only() {
    let mut net = Net::new();
    let (a1, _) = net.join(1, CALL_A, "ana@example.org");
    let (a2, _) = net.join(2, CALL_A, "ben@example.org");
    let (b1, _) = net.join(3, CALL_B, "cleo@example.org");
    net.connect();
    assert_eq!(net.server.participants(CALL_A).len(), 2);
    assert_eq!(net.server.participants(CALL_B).len(), 1);

    let from_a1 = net.talk(a1, "a1", 0, 50);
    let from_b1 = net.talk(b1, "b1", 0, 50);

    // A2 gets A1's frames byte for byte, in order, and nothing else.
    let at_a2 = net.clients[a2].received();
    assert!(at_a2.len() >= 45, "only {} of A1's 50 frames reached A2", at_a2.len());
    assert!(at_a2.iter().all(|frame| from_a1.contains(frame)), "A2 received something A1 did not send");
    let mut in_order = at_a2.clone();
    in_order.sort();
    assert_eq!(at_a2, in_order, "A1's frames reached A2 out of order");
    // B1, in another call, gets none of them; A1 does not get its own back, nor B1's.
    assert!(net.clients[b1].received().is_empty(), "a frame crossed into another call");
    assert!(net.clients[a1].received().is_empty(), "A1 received its own frames or another call's");
    assert!(from_b1.iter().all(|frame| !at_a2.contains(frame)));
}

#[test]
fn bad_credentials_are_refused() {
    let mut net = Net::new();
    let (_, offer) = Client::new(1, net.now);
    let now = net.now;

    // Expired: past the credential's minute.
    let credential = net.credential(CALL_A, "ana@example.org", 1);
    assert_eq!(net.server.join(CALL_A, &credential, &offer, now, T0 + LIFETIME_MS + 1).unwrap_err(), JoinError::Credential(CredentialError::Expired));

    // A bad offer uses nothing up: the same credential then admits once, and a copy of it is refused.
    let credential = net.credential(CALL_A, "ana@example.org", 1);
    assert_eq!(net.server.join(CALL_A, &credential, "not an offer", now, T0).unwrap_err(), JoinError::Offer);
    assert!(net.server.join(CALL_A, &credential, &offer, now, T0).is_ok());
    let (_, offer2) = Client::new(2, net.now);
    assert_eq!(net.server.join(CALL_A, &credential, &offer2, now, T0).unwrap_err(), JoinError::Credential(CredentialError::Replayed));

    // For call A, asked for call B.
    let credential = net.credential(CALL_A, "ben@example.org", 2);
    assert_eq!(net.server.join(CALL_B, &credential, &offer2, now, T0).unwrap_err(), JoinError::WrongCall);
    // For another media server, or signed by another key.
    let elsewhere = net.issuer.issue(CALL_A, "general", "ben@example.org", 2, "other.example.org", T0).unwrap();
    assert_eq!(net.server.join(CALL_A, &elsewhere, &offer2, now, T0).unwrap_err(), JoinError::Credential(CredentialError::WrongServer));
    let forged = Issuer::from_pkcs8(&Issuer::generate().unwrap()).unwrap().issue(CALL_A, "general", "ben@example.org", 2, MEDIA, T0).unwrap();
    assert_eq!(net.server.join(CALL_A, &forged, &offer2, now, T0).unwrap_err(), JoinError::Credential(CredentialError::BadSignature));

    // Only the one good credential admitted anyone.
    assert_eq!(net.server.participants(CALL_A).len(), 1);
    assert!(net.server.participants(CALL_B).is_empty());
}

#[test]
fn a_dropped_participant_stops_receiving() {
    let mut net = Net::new();
    let (a1, _) = net.join(1, CALL_A, "ana@example.org");
    let (a2, a2_id) = net.join(2, CALL_A, "ben@example.org");
    net.connect();

    let before = net.talk(a1, "a1", 0, 10);
    let at_a2 = net.clients[a2].received();
    assert!(at_a2.len() >= 8 && at_a2.iter().all(|frame| before.contains(frame)), "A2 did not receive A1 before leaving");

    // The chat server says Ben is out (left, removed, or lost permission): his session goes at once.
    assert_eq!(net.server.drop_person(CALL_A, "ben@example.org"), 1);
    assert!(!net.server.participants(CALL_A).contains(&a2_id));
    net.talk(a1, "a1", 10, 20);
    assert_eq!(net.clients[a2].received(), at_a2, "A2 kept receiving after it was dropped");
    // The server said goodbye (DTLS close), so A2's client knows at once rather than at an ICE timeout.
    assert!(net.clients[a2].events.iter().any(|event| matches!(event, Event::Closed)), "A2 was not told its session closed");
    assert_eq!(net.server.participants(CALL_A).len(), 1);
}
