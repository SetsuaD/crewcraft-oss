//! A connection from its first byte: the handshake (`proto::handshake`, T133) must come first, and only a client the
//! server welcomed reaches `connection::Connection` (T135). Task T138.

use crewcraft_proto::frame::{FrameError, MAX_FRAME, encode};
use crewcraft_proto::handshake::{Reply, ServerSide, decode_hello, encode_reply, negotiate};
use crewcraft_proto::message::CodecError;

use crate::connection::{ConnError, Connection};
use crate::server::Server;

/// Where the session is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Waiting for the client's `Hello`.
    Hello,
    /// Welcomed at this protocol version; frames are requests.
    Open { version: u16, features: u32 },
    /// The session has ended (refused, or a fatal error); every later `receive` is `Closed`.
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// The frame layer refused the bytes.
    Frame(FrameError),
    /// The first frame is not a `Hello` (`decode_hello` failed).
    Hello(CodecError),
    /// A fatal error from the open connection.
    Conn(ConnError),
    /// The session is already closed.
    Closed,
}

pub struct Session {
    user: String,
    server_side: ServerSide,
    phase: Phase,
    buf: Vec<u8>,
    connection: Option<Connection>,
}

impl Session {
    /// A session for `user` (already authenticated by its client certificate), speaking `server_side`.
    pub fn new(user: &str, server_side: ServerSide) -> Self {
        Self { user: user.to_string(), server_side, phase: Phase::Hello, buf: Vec::new(), connection: None }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Feed received bytes; returns the bytes to send.
    ///
    /// In `Hello`: bytes are buffered until the first whole frame. It must decode as a `Hello` (`SessionError::Hello`
    /// and the session closes otherwise). The reply is `negotiate(hello, server_side)`, encoded and framed. A `Welcome`
    /// opens the session at its version and features; a `Refuse` closes it after the reply is sent. Bytes after the
    /// `Hello` frame in the same call are handled as `Open` would handle them (if the session opened) or ignored (if it
    /// closed).
    ///
    /// In `Open`: `Connection::receive` for this user. Its fatal error is `SessionError::Conn`, and the session closes.
    ///
    /// In `Closed`: `SessionError::Closed`, nothing sent.
    ///
    /// On any error the session is `Closed` afterwards and no bytes from that call are sent.
    pub fn receive(&mut self, server: &mut Server, bytes: &[u8], now_ms: u64) -> Result<Vec<u8>, SessionError> {
        match self.phase {
            Phase::Closed => Err(SessionError::Closed),
            Phase::Hello => self.receive_hello(server, bytes, now_ms),
            Phase::Open { .. } => self.receive_open(server, bytes, now_ms),
        }
    }

    fn receive_hello(&mut self, server: &mut Server, bytes: &[u8], now_ms: u64) -> Result<Vec<u8>, SessionError> {
        self.buf.extend_from_slice(bytes);

        // Need at least 4 bytes for the frame header.
        if self.buf.len() < 4 {
            return Ok(Vec::new());
        }

        let header = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if header > MAX_FRAME {
            self.buf.clear();
            self.phase = Phase::Closed;
            return Err(SessionError::Frame(FrameError::TooLarge(header)));
        }
        if self.buf.len() < 4 + header {
            return Ok(Vec::new());
        }

        let payload = self.buf[4..4 + header].to_vec();
        self.buf.drain(..4 + header);

        // Decode the Hello.
        let hello = decode_hello(&payload).map_err(|e| {
            self.phase = Phase::Closed;
            SessionError::Hello(e)
        })?;

        // Negotiate.
        let reply = negotiate(&hello, &self.server_side);

        // Encode and frame the reply.
        let reply_bytes = encode_reply(&reply).map_err(|e| {
            self.phase = Phase::Closed;
            SessionError::Hello(e)
        })?;
        let mut out = encode(&reply_bytes).map_err(|e| {
            self.phase = Phase::Closed;
            SessionError::Frame(e)
        })?;

        match reply {
            Reply::Welcome { version, features, server: _ } => {
                self.phase = Phase::Open { version, features };
                let mut conn = Connection::new(&self.user);
                // Feed any remaining bytes (from the same call) to the now-open connection.
                if !self.buf.is_empty() {
                    let remaining = std::mem::take(&mut self.buf);
                    match conn.receive(server, &remaining, now_ms) {
                        Ok(conn_out) => out.extend_from_slice(&conn_out),
                        Err(e) => {
                            self.phase = Phase::Closed;
                            self.connection = Some(conn);
                            return Err(SessionError::Conn(e));
                        }
                    }
                }
                self.connection = Some(conn);
                Ok(out)
            }
            Reply::Refuse { .. } => {
                self.phase = Phase::Closed;
                Ok(out)
            }
        }
    }

    fn receive_open(&mut self, server: &mut Server, bytes: &[u8], now_ms: u64) -> Result<Vec<u8>, SessionError> {
        match self.connection.as_mut() {
            Some(conn) => match conn.receive(server, bytes, now_ms) {
                Ok(out) => Ok(out),
                Err(e) => {
                    self.phase = Phase::Closed;
                    Err(SessionError::Conn(e))
                }
            },
            None => {
                self.phase = Phase::Closed;
                Err(SessionError::Closed)
            }
        }
    }
}
