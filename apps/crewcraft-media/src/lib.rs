//! The CrewCraft media server (docs/CALLS.md "The shape", task T363a): a selective forwarding unit. It forwards each
//! participant's audio to the other participants of the same call and to no one else, and does nothing else with it:
//! media is end-to-end encrypted with SFrame on top of WebRTC's own encryption, so the server never decodes it.
//!
//! Owns: admission (a WebRTC offer plus the chat server's media credential, checked with `crewcraft-media-auth`),
//! the participants of each call, and the forwarding between them. WebRTC itself is str0m on CrewCraft's own crypto
//! provider (`crewcraft-media-crypto`).
//!
//! Sans-I/O, like str0m: the caller owns the UDP socket and the clock. It hands received datagrams to
//! [`MediaServer::receive`], calls [`MediaServer::poll`] at the time it returns, and sends the datagrams `poll` gives
//! back. Tests run the whole server in memory.
//!
//! Receiving without renegotiation: a participant's offer has one audio section it sends (its microphone) and some
//! audio sections it only receives. The server gives each receiving section to one other participant of the call,
//! the earliest joiner first, so forwarding a new participant never needs a new offer. Who is in which section
//! is not announced yet; each frame's SFrame key id already says who sent it.
//!
//! Around this core (T363b): [`config`] reads `media.toml` and the chat server's key, [`serve`] drives the core from a
//! UDP socket until told to stop, and [`intake`] is the seam requests come in through (joins, drops, ended calls). The
//! binary, `apps/crewcraft-media-server` (T360b3), adds the chat server's control connection (mutual TLS), which feeds
//! [`intake`]; it lives apart so this crate, the media path, stays pure Rust.

pub mod config;
pub mod intake;
pub mod serve;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crewcraft_media_auth::Verifier;
use str0m::change::SdpOffer;
use str0m::media::{MediaAdded, MediaData, MediaKind, Mid};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};

pub use crewcraft_media_auth::Error as CredentialError;

/// The most participants one call holds.
pub const MAX_CALL_SIZE: usize = 64;
/// The most media sections (sending and receiving) one participant's offer may have.
pub const MAX_MEDIA: usize = 64;
/// The longest offer accepted, in bytes.
pub const MAX_OFFER_BYTES: usize = 64 * 1024;
/// How long `poll` lets the caller wait when no participant asks for an earlier wake-up.
const IDLE: Duration = Duration::from_millis(100);
/// Rounds of drain-and-forward in one `poll`; anything left over goes out on the next.
const MAX_ROUNDS: usize = 8;
/// Outputs taken from one participant in one round; the rest wait for the next round.
const MAX_OUTPUTS: usize = 4096;

/// The media server's own settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// The server name credentials must name (`Grant::media_server`).
    pub server_name: String,
    /// The chat server's media key: only credentials it signed are accepted.
    pub trusted_key: [u8; 32],
    /// The UDP address participants reach the server at; it is the server's ICE candidate.
    pub address: SocketAddr,
}

/// One admitted WebRTC session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParticipantId(u64);

/// A datagram for the caller to send from the server's socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    pub to: SocketAddr,
    pub bytes: Vec<u8>,
}

/// An admission: the participant and the SDP answer to give back.
#[derive(Debug, Clone)]
pub struct Joined {
    pub id: ParticipantId,
    pub answer: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinError {
    /// Not a usable offer: too big, too many media sections, unreadable or not acceptable. The credential is not
    /// used up.
    Offer,
    /// The credential was refused (forged, changed, expired, for another media server, or already used).
    Credential(CredentialError),
    /// A good credential, but for another call than the one asked for. It is used up.
    WrongCall,
    /// The call already has as many participants as the server allows (at most `MAX_CALL_SIZE`). The credential is
    /// used up.
    CallFull,
    /// The server is not running (an intake answer when the serving loop has stopped).
    Stopped,
}

/// A media section the server sends on: it carries one other participant's section, or nothing yet.
#[derive(Debug)]
struct Slot {
    mid: Mid,
    kind: MediaKind,
    source: Option<(ParticipantId, Mid)>,
}

struct Participant {
    call: u64,
    person: String,
    device: u64,
    rtc: Rtc,
    /// Media sections the participant sends on.
    inputs: Vec<(Mid, MediaKind)>,
    /// Media sections the participant only receives on.
    slots: Vec<Slot>,
    /// False once its connection is gone (ICE disconnected, closed by the peer, or failed).
    alive: bool,
}

impl Participant {
    fn add_media(&mut self, added: &MediaAdded) {
        if self.inputs.len() + self.slots.len() >= MAX_MEDIA {
            return;
        }
        if added.direction.is_receiving() {
            self.inputs.push((added.mid, added.kind));
        } else if added.direction.is_sending() {
            self.slots.push(Slot { mid: added.mid, kind: added.kind, source: None });
        }
    }

    /// Everything the participant's session has to send goes onto `out`, its media onto `media`. Returns when it next
    /// wants to be woken, and whether its media sections changed.
    fn drain(&mut self, id: ParticipantId, now: Instant, out: &mut Vec<Datagram>, media: &mut Vec<(ParticipantId, MediaData)>) -> (Instant, bool) {
        let mut changed = false;
        for _ in 0..MAX_OUTPUTS {
            if !self.alive {
                return (now, changed);
            }
            match self.rtc.poll_output() {
                Ok(Output::Timeout(at)) => return (at, changed),
                Ok(Output::Transmit(sent)) => out.push(Datagram { to: sent.destination, bytes: sent.contents.to_vec() }),
                Ok(Output::Event(Event::MediaAdded(added))) => {
                    self.add_media(&added);
                    changed = true;
                }
                Ok(Output::Event(Event::MediaData(data))) => media.push((id, data)),
                Ok(Output::Event(Event::IceConnectionStateChange(IceConnectionState::Disconnected) | Event::Closed)) => self.alive = false,
                Ok(Output::Event(_)) => {}
                Err(_) => self.alive = false,
            }
        }
        (now, changed)
    }
}

/// The selective forwarding unit: every participant of every call on this server.
pub struct MediaServer {
    config: Config,
    verifier: Verifier,
    crypto: Arc<crewcraft_media_crypto::CryptoProvider>,
    participants: BTreeMap<ParticipantId, Participant>,
    next_id: u64,
    /// Goodbyes (DTLS close_notify) of removed participants, sent on the next `poll`.
    outbox: Vec<Datagram>,
    max_call_size: usize,
}

impl MediaServer {
    pub fn new(config: Config) -> Self {
        let verifier = Verifier::new(config.trusted_key, &config.server_name);
        let crypto = Arc::new(crewcraft_media_crypto::provider());
        Self { config, verifier, crypto, participants: BTreeMap::new(), next_id: 1, outbox: Vec::new(), max_call_size: MAX_CALL_SIZE }
    }

    /// Allow at most `size` participants per call, between 1 and `MAX_CALL_SIZE` (the default). Calls already larger
    /// keep who they have; only new joins are refused.
    pub fn set_max_call_size(&mut self, size: usize) {
        self.max_call_size = size.clamp(1, MAX_CALL_SIZE);
    }

    /// The address the server gives participants as its ICE candidate.
    pub fn address(&self) -> SocketAddr {
        self.config.address
    }

    /// Admit a participant to `call` with its WebRTC `offer` (SDP) and the chat server's `credential`, at `now` and
    /// wall-clock `now_ms` (milliseconds since the Unix epoch, what credentials expire by).
    ///
    /// The offer is read before the credential is checked, so a bad offer uses nothing up. A credential that checks
    /// out is used up, even if the join is refused for another reason after it. A new session from the same device
    /// in the same call replaces the old one.
    pub fn join(&mut self, call: u64, credential: &[u8], offer: &str, now: Instant, now_ms: u64) -> Result<Joined, JoinError> {
        if offer.len() > MAX_OFFER_BYTES || offer.lines().filter(|line| line.starts_with("m=")).count() > MAX_MEDIA {
            return Err(JoinError::Offer);
        }
        let offer = SdpOffer::from_sdp_string(offer).map_err(|_| JoinError::Offer)?;
        let grant = self.verifier.verify(credential, now_ms).map_err(JoinError::Credential)?;
        if grant.call != call {
            return Err(JoinError::WrongCall);
        }
        let replaced =
            self.participants.iter().find(|(_, p)| p.call == call && p.person == grant.person && p.device == grant.device).map(|(id, _)| *id);
        let others = self.participants.values().filter(|p| p.call == call).count() - usize::from(replaced.is_some());
        if others >= self.max_call_size {
            return Err(JoinError::CallFull);
        }

        // Audio only for now (Opus); video comes with its own task. ICE lite: the server answers connectivity checks
        // on its one address and starts none.
        let mut rtc = Rtc::builder().set_crypto_provider(self.crypto.clone()).set_ice_lite(true).clear_codecs().enable_opus(true, false).build(now);
        let candidate = Candidate::host(self.config.address, "udp").map_err(|_| JoinError::Offer)?;
        rtc.add_local_candidate(candidate);
        let answer = rtc.sdp_api().accept_offer(offer).map_err(|_| JoinError::Offer)?;

        if let Some(old) = replaced {
            self.remove(old);
        }
        let id = ParticipantId(self.next_id);
        self.next_id += 1;
        let participant = Participant { call, person: grant.person, device: grant.device, rtc, inputs: Vec::new(), slots: Vec::new(), alive: true };
        self.participants.insert(id, participant);
        Ok(Joined { id, answer: answer.to_sdp_string() })
    }

    /// A datagram that arrived on the server's socket from `source`. Returns whether a participant took it.
    pub fn receive(&mut self, now: Instant, source: SocketAddr, bytes: &[u8]) -> bool {
        let Ok(contents) = bytes.try_into() else {
            return false;
        };
        let input = Input::Receive(now, Receive { proto: Protocol::Udp, source, destination: self.config.address, contents });
        for participant in self.participants.values_mut() {
            if participant.alive && participant.rtc.accepts(&input) {
                if participant.rtc.handle_input(input).is_err() {
                    participant.alive = false;
                }
                return true;
            }
        }
        false
    }

    /// Move time to `now`, forward the media that arrived, and put everything to send onto `out`. Returns when to
    /// call again (sooner if a datagram arrives). Participants whose connection is gone are removed here.
    pub fn poll(&mut self, now: Instant, out: &mut Vec<Datagram>) -> Instant {
        out.append(&mut self.outbox);
        for participant in self.participants.values_mut() {
            if participant.alive && participant.rtc.handle_input(Input::Timeout(now)).is_err() {
                participant.alive = false;
            }
        }
        // When every session is drained and nothing is left to forward, the soonest wake-up any session asked for;
        // otherwise at once.
        let mut settled = None;
        for _ in 0..MAX_ROUNDS {
            let mut media = Vec::new();
            let mut changed = false;
            let mut soonest = now + IDLE;
            for (id, participant) in &mut self.participants {
                let (at, media_changed) = participant.drain(*id, now, out, &mut media);
                soonest = soonest.min(at);
                changed |= media_changed;
            }
            if changed {
                self.assign();
            }
            if media.is_empty() && !changed {
                settled = Some(soonest);
                break;
            }
            for (from, data) in &media {
                self.forward(*from, data);
            }
        }
        let mut next = settled.unwrap_or(now);
        let gone: Vec<ParticipantId> = self.participants.iter().filter(|(_, p)| !p.alive).map(|(id, _)| *id).collect();
        for id in gone {
            self.remove(id);
        }
        if !self.outbox.is_empty() {
            next = now;
        }
        next.max(now)
    }

    /// Remove a participant at once: its tracks stop reaching the others, and it receives nothing more. Its session
    /// is closed (the goodbye goes out on the next `poll`). Returns whether it was here.
    pub fn remove(&mut self, id: ParticipantId) -> bool {
        let Some(mut participant) = self.participants.remove(&id) else {
            return false;
        };
        if participant.alive && participant.rtc.close().is_ok() {
            for _ in 0..MAX_OUTPUTS {
                match participant.rtc.poll_output() {
                    Ok(Output::Transmit(sent)) => self.outbox.push(Datagram { to: sent.destination, bytes: sent.contents.to_vec() }),
                    Ok(Output::Event(_)) => {}
                    Ok(Output::Timeout(_)) | Err(_) => break,
                }
            }
        }
        self.assign();
        true
    }

    /// Drop every session of `person` in `call` (the chat server's word when they leave, are removed or lose
    /// permission). Returns how many were dropped.
    pub fn drop_person(&mut self, call: u64, person: &str) -> usize {
        let ids: Vec<ParticipantId> = self.participants.iter().filter(|(_, p)| p.call == call && p.person == person).map(|(id, _)| *id).collect();
        ids.into_iter().filter(|id| self.remove(*id)).count()
    }

    /// Drop everyone in `call` (the call ended). Returns how many were dropped.
    pub fn end_call(&mut self, call: u64) -> usize {
        let ids: Vec<ParticipantId> = self.participants.iter().filter(|(_, p)| p.call == call).map(|(id, _)| *id).collect();
        ids.into_iter().filter(|id| self.remove(*id)).count()
    }

    /// Drop everyone on the server (it is shutting down). Their goodbyes go out on the next `poll`. Returns how many
    /// were dropped.
    pub fn close_all(&mut self) -> usize {
        let ids: Vec<ParticipantId> = self.participants.keys().copied().collect();
        ids.into_iter().filter(|id| self.remove(*id)).count()
    }

    /// The participants of `call`, earliest joiner first.
    pub fn participants(&self, call: u64) -> Vec<ParticipantId> {
        self.participants.iter().filter(|(_, p)| p.call == call).map(|(id, _)| *id).collect()
    }

    /// Give every participant's sending sections to the receiving sections of the others in the same call, keeping
    /// what is already given and freeing what belonged to someone gone.
    fn assign(&mut self) {
        let inputs: Vec<(ParticipantId, u64, Mid, MediaKind)> = self
            .participants
            .iter()
            .filter(|(_, p)| p.alive)
            .flat_map(|(id, p)| p.inputs.iter().map(move |(mid, kind)| (*id, p.call, *mid, *kind)))
            .collect();
        for (id, participant) in &mut self.participants {
            let call = participant.call;
            for slot in &mut participant.slots {
                if let Some((source, mid)) = slot.source
                    && !inputs.iter().any(|(from, from_call, from_mid, _)| *from == source && *from_mid == mid && *from_call == call)
                {
                    slot.source = None;
                }
            }
            for (from, from_call, mid, kind) in &inputs {
                if from == id || *from_call != call || participant.slots.iter().any(|slot| slot.source == Some((*from, *mid))) {
                    continue;
                }
                if let Some(free) = participant.slots.iter_mut().find(|slot| slot.source.is_none() && slot.kind == *kind) {
                    free.source = Some((*from, *mid));
                }
            }
        }
    }

    /// Send `data`, which `from` sent, to every other participant of its call that has a section for it. The bytes
    /// are passed on as they came: the server never looks inside them.
    fn forward(&mut self, from: ParticipantId, data: &MediaData) {
        let Some(call) = self.participants.get(&from).map(|p| p.call) else {
            return;
        };
        for (id, participant) in &mut self.participants {
            if *id == from || participant.call != call || !participant.alive {
                continue;
            }
            let Some(mid) = participant.slots.iter().find(|slot| slot.source == Some((from, data.mid))).map(|slot| slot.mid) else {
                continue;
            };
            let Some(writer) = participant.rtc.writer(mid) else {
                continue;
            };
            let Some(pt) = writer.match_params(data.params) else {
                continue;
            };
            // A refused write (not connected yet, or a payload type it cannot carry) loses this frame for this
            // participant only; the others still get it.
            let _ = writer.write(pt, data.network_time, data.time, data.data.clone());
        }
    }
}
