//! The media server's end of the chat server's control connection (docs/CALLS.md "Admission", task T360b3): a TCP
//! listener behind mutual TLS that accepts only a client certificate from the configured chat-server CA, reads
//! `crewcraft_proto::media_control` messages, hands each to the serving loop through its intake and acknowledges it.
//!
//! Owns: building the TLS configuration from `[control]` ([`tls_config`]) and the listener ([`ControlListener`]).
//! Calls: `crewcraft-tls` (rustls with ring: the control channel's stack, decided 2026-11-26; the media path stays pure
//! Rust in `crewcraft-media`) and `crewcraft_media::intake::Handle`.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crewcraft_media::config::{ControlSettings, read_file};
use crewcraft_media::intake::Handle;
use crewcraft_proto::frame::{Decoder, encode};
use crewcraft_proto::media_control::{ControlMessage, MAX_CONTROL_MESSAGE, decode_control, encode_control};
use rustls::ServerConfig;

/// The largest certificate or key file read.
const MAX_PEM_BYTES: u64 = 1024 * 1024;
/// How long a TLS handshake may take.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// How often an idle listener or connection looks at the stop flag.
const TICK: Duration = Duration::from_millis(50);
/// Control connections open at once (the chat server keeps one; a reconnect may briefly overlap).
const MAX_CONNECTIONS: usize = 4;

/// The TLS configuration `[control]` describes: this server's certificate and key, and the chat-server CA every client
/// certificate must chain to. Files are read next to `media.toml` (`dir`); the key must be owner-only.
pub fn tls_config(dir: &Path, control: &ControlSettings) -> io::Result<Arc<ServerConfig>> {
    let chain = read_file(&dir.join(&control.certificate), MAX_PEM_BYTES, false)?;
    let key = read_file(&dir.join(&control.key), MAX_PEM_BYTES, true)?;
    let ca = read_file(&dir.join(&control.chat_server_ca), MAX_PEM_BYTES, false)?;
    let identity = crewcraft_tls::pem::identity(chain.as_bytes(), key.as_bytes())?;
    let roots = crewcraft_tls::pem::roots(ca.as_bytes())?;
    crewcraft_tls::server_config(identity, roots).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// The listening control connection, on its own thread until `stop` is set.
pub struct ControlListener {
    local: SocketAddr,
    thread: JoinHandle<()>,
}

impl ControlListener {
    /// Listen on `listen`, accept chat servers that pass `config`, and hand their messages to `handle`.
    pub fn start(listen: SocketAddr, config: Arc<ServerConfig>, handle: Handle, stop: Arc<AtomicBool>) -> io::Result<Self> {
        let listener = TcpListener::bind(listen)?;
        listener.set_nonblocking(true)?;
        let local = listener.local_addr()?;
        let thread = thread::Builder::new().name("control".into()).spawn(move || listen_until(&listener, &config, &handle, &stop))?;
        Ok(Self { local, thread })
    }

    /// The address it listens on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Wait for the listener to stop (after `stop` is set). Open connections end on their own within a tick.
    pub fn join(self) {
        let _ = self.thread.join();
    }
}

fn listen_until(listener: &TcpListener, config: &Arc<ServerConfig>, handle: &Handle, stop: &Arc<AtomicBool>) {
    let open = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((tcp, _)) => {
                if open.load(Ordering::Acquire) >= MAX_CONNECTIONS {
                    continue; // dropped unanswered
                }
                open.fetch_add(1, Ordering::AcqRel);
                let (config, handle, stop, open) = (config.clone(), handle.clone(), stop.clone(), open.clone());
                let spawned = thread::Builder::new().name("control-connection".into()).spawn(move || {
                    // A connection that fails its handshake or breaks is simply closed; the chat server reconnects.
                    let _ = serve_connection(tcp, config, &handle, &stop);
                    open.fetch_sub(1, Ordering::AcqRel);
                });
                if spawned.is_err() {
                    open.fetch_sub(1, Ordering::AcqRel);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(TICK),
            Err(_) => thread::sleep(TICK),
        }
    }
}

fn serve_connection(tcp: TcpStream, config: Arc<ServerConfig>, handle: &Handle, stop: &AtomicBool) -> io::Result<()> {
    tcp.set_nonblocking(false)?;
    let accepted = crewcraft_tls::accept(tcp, config, HANDSHAKE).map_err(|e| io::Error::other(e.to_string()))?;
    let mut stream = accepted.stream;
    stream.sock.set_read_timeout(Some(TICK))?;
    let mut decoder = Decoder::new();
    let mut buffer = [0u8; 4096];
    while !stop.load(Ordering::Acquire) {
        let read = match stream.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => read,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted) => continue,
            Err(e) => return Err(e),
        };
        decoder.push(buffer.get(..read).unwrap_or_default());
        while let Some(payload) = decoder.next_frame().map_err(|_| io::Error::from(io::ErrorKind::InvalidData))? {
            if payload.len() > MAX_CONTROL_MESSAGE {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let message = decode_control(&payload).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            let (seq, taken) = match message {
                ControlMessage::DropPerson { seq, call, person } => (seq, handle.drop_person(call, &person)),
                ControlMessage::EndCall { seq, call } => (seq, handle.end_call(call)),
                ControlMessage::Ack { .. } => return Err(io::ErrorKind::InvalidData.into()),
            };
            if !taken {
                return Ok(()); // the serving loop stopped: no acknowledgement, the chat server sends it again later
            }
            let ack = encode_control(&ControlMessage::Ack { seq }).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            stream.write_all(&encode(&ack).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?)?;
            stream.flush()?;
        }
    }
    Ok(())
}
