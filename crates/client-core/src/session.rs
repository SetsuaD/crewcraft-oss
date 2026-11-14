//! The client's connection from its first byte: it sends the handshake (`proto::handshake`, T133), and only after the
//! server's `Welcome` do frames reach `client::Client` (T136). Task T139.

use crewcraft_proto::frame::{FrameError, MAX_FRAME, encode as frame_encode};
use crewcraft_proto::handshake::{Hello, Reply, decode_reply, encode_hello};
use crewcraft_proto::message::CodecError;

use crate::client::{Client, ClientError, ClientEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// `start` has not been called.
    New,
    /// The `Hello` was sent; waiting for the server's reply.
    Waiting,
    /// Welcomed at this protocol version, with these shared features.
    Open { version: u16, features: u32 },
    /// The server refused this range of versions (the server speaks `min_version` to `max_version`).
    Refused { min_version: u16, max_version: u16 },
    /// A fatal error closed the session.
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// The frame layer refused the bytes.
    Frame(FrameError),
    /// The first frame from the server is not a handshake reply (`decode_reply` failed).
    Reply(CodecError),
    /// A fatal error from the open client.
    Client(ClientError),
    /// `start` was called twice, or the session is not in a phase that accepts this call.
    WrongPhase,
}

pub struct ClientSession {
    hello: Hello,
    client: Client,
    phase: Phase,
    buffer: Vec<u8>,
}

impl ClientSession {
    /// A session that will say `hello` and then drive `client`.
    pub fn new(hello: Hello, client: Client) -> Self {
        Self { hello, client, phase: Phase::New, buffer: Vec::new() }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// The bytes to send first: the `Hello`, encoded and framed. Moves `New` to `Waiting`. `WrongPhase` in any other
    /// phase; an encoding error is `Reply(e)` and the session stays `New`.
    pub fn start(&mut self) -> Result<Vec<u8>, SessionError> {
        if self.phase != Phase::New {
            return Err(SessionError::WrongPhase);
        }
        let payload = encode_hello(&self.hello).map_err(SessionError::Reply)?;
        let frame = frame_encode(&payload).map_err(|_| SessionError::Reply(CodecError::FieldLength))?;
        self.phase = Phase::Waiting;
        Ok(frame)
    }

    /// Feed bytes received from the server.
    ///
    /// In `Waiting`: bytes are buffered until the first whole frame, which must decode as a reply (`Reply(e)` and
    /// `Closed` otherwise; a frame header over `frame::MAX_FRAME` is `Frame(e)` and `Closed` too). `Welcome` opens the session; any bytes after that frame in the same call go to
    /// `Client::receive`, and its events are returned. `Refuse` moves to `Refused`, and any further bytes are ignored.
    ///
    /// In `Open`: `Client::receive`; a fatal error is `Client(e)` and the session is `Closed`.
    ///
    /// In `New`, `Refused` or `Closed`: `WrongPhase`, nothing changes.
    pub fn receive(&mut self, bytes: &[u8], now_ms: u64, local_minute: u16) -> Result<Vec<ClientEvent>, SessionError> {
        match self.phase {
            Phase::New | Phase::Refused { .. } | Phase::Closed => Err(SessionError::WrongPhase),
            Phase::Waiting => self.receive_waiting(bytes, now_ms, local_minute),
            Phase::Open { .. } => self.receive_open(bytes, now_ms, local_minute),
        }
    }

    fn receive_waiting(&mut self, bytes: &[u8], now_ms: u64, local_minute: u16) -> Result<Vec<ClientEvent>, SessionError> {
        self.buffer.extend_from_slice(bytes);

        if self.buffer.len() < 4 {
            return Ok(Vec::new());
        }
        let header = u32::from_be_bytes([self.buffer[0], self.buffer[1], self.buffer[2], self.buffer[3]]) as usize;
        if header > MAX_FRAME {
            self.buffer.clear();
            self.phase = Phase::Closed;
            return Err(SessionError::Frame(FrameError::TooLarge(header)));
        }
        if self.buffer.len() < 4 + header {
            return Ok(Vec::new());
        }

        let payload = self.buffer[4..4 + header].to_vec();
        let remaining = self.buffer[4 + header..].to_vec();
        self.buffer.clear();

        match decode_reply(&payload) {
            Ok(Reply::Welcome { version, features, server: _ }) => {
                self.phase = Phase::Open { version, features };
                if remaining.is_empty() {
                    Ok(Vec::new())
                } else {
                    match self.client.receive(&remaining, now_ms, local_minute) {
                        Ok(events) => Ok(events),
                        Err(e) => {
                            self.phase = Phase::Closed;
                            Err(SessionError::Client(e))
                        }
                    }
                }
            }
            Ok(Reply::Refuse { min_version, max_version }) => {
                self.phase = Phase::Refused { min_version, max_version };
                Ok(Vec::new())
            }
            Err(e) => {
                self.phase = Phase::Closed;
                Err(SessionError::Reply(e))
            }
        }
    }

    fn receive_open(&mut self, bytes: &[u8], now_ms: u64, local_minute: u16) -> Result<Vec<ClientEvent>, SessionError> {
        match self.client.receive(bytes, now_ms, local_minute) {
            Ok(events) => Ok(events),
            Err(e) => {
                self.phase = Phase::Closed;
                Err(SessionError::Client(e))
            }
        }
    }

    /// The client, to send requests once the session is `Open` (`Client::send`) and to follow rooms.
    pub fn client_mut(&mut self) -> &mut Client {
        &mut self.client
    }
}
