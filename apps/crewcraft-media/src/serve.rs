//! The serving loop (task T363b): one UDP socket drives the Sans-I/O [`MediaServer`] until told to stop.
//!
//! Owns: binding the socket from the settings ([`bind`]), the loop itself ([`run`]): requests from the intake,
//! datagrams in, str0m's timeouts through [`MediaServer::poll`], datagrams out, and the clean shutdown (every session
//! closed, its goodbye sent). Called by: `main.rs`, and the T363b test on loopback.

use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::config::MediaConfig;
use crate::intake::{Intake, Request};
use crate::{Config, Datagram, MediaServer};

/// The longest the loop waits on its socket, so requests and a stop are seen promptly while it is idle.
const MAX_WAIT: Duration = Duration::from_millis(20);
/// The shortest wait (a zero read timeout is an error on some systems).
const MIN_WAIT: Duration = Duration::from_millis(1);
/// The receive buffer: larger than any datagram str0m sends or expects.
const BUFFER: usize = 2048;

/// Bind the socket `config` names and make the server for it. With no `public-address`, the bound address (with the
/// port the system chose, if `listen` asked for port 0) is the server's ICE candidate.
pub fn bind(config: &MediaConfig) -> io::Result<(UdpSocket, MediaServer)> {
    let settings = &config.settings;
    let socket = UdpSocket::bind(settings.listen)?;
    let address: SocketAddr = match settings.public_address {
        Some(public) => public,
        None => socket.local_addr()?,
    };
    let mut server = MediaServer::new(Config { server_name: settings.server_name.clone(), trusted_key: config.trusted_key, address });
    server.set_max_call_size(settings.max_call_size);
    Ok((socket, server))
}

/// Milliseconds since the Unix epoch, what credentials expire by. A clock before 1970 refuses every credential.
fn wall_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(u64::MAX, |since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
}

fn handle(server: &mut MediaServer, request: Request, now: Instant) {
    match request {
        Request::Join { call, credential, offer, reply } => {
            // The asker may have given up waiting; the answer is then dropped.
            let _ = reply.send(server.join(call, &credential, &offer, now, wall_ms()));
        }
        Request::DropPerson { call, person } => {
            server.drop_person(call, &person);
        }
        Request::EndCall { call } => {
            server.end_call(call);
        }
    }
}

fn send(socket: &UdpSocket, out: &mut Vec<Datagram>) {
    for datagram in out.drain(..) {
        // A datagram that cannot be sent (an address gone unreachable) is lost like any other on UDP; the session's
        // own timeouts deal with a participant who is gone.
        let _ = socket.send_to(&datagram.bytes, datagram.to);
    }
}

/// Serve on `socket` until `stop` is set, taking requests from `intake`. On stop every session is closed and its
/// goodbye sent before this returns. Fails only if the socket fails.
pub fn run(socket: &UdpSocket, mut server: MediaServer, intake: &mut dyn Intake, stop: &AtomicBool) -> io::Result<()> {
    let mut buffer = vec![0u8; BUFFER];
    let mut requests = Vec::new();
    let mut out = Vec::new();
    loop {
        let now = Instant::now();
        intake.take(&mut requests);
        for request in requests.drain(..) {
            handle(&mut server, request, now);
        }
        if stop.load(Ordering::Acquire) {
            server.close_all();
            server.poll(Instant::now(), &mut out);
            send(socket, &mut out);
            return Ok(());
        }

        let next = server.poll(now, &mut out);
        send(socket, &mut out);

        let wait = next.saturating_duration_since(Instant::now()).clamp(MIN_WAIT, MAX_WAIT);
        socket.set_read_timeout(Some(wait))?;
        match socket.recv_from(&mut buffer) {
            Ok((len, source)) => {
                if let Some(bytes) = buffer.get(..len) {
                    server.receive(Instant::now(), source, bytes);
                }
            }
            // Nothing arrived in time, or an earlier datagram bounced (an ICMP error some systems report on the next
            // read): neither is the socket failing.
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
}
