//! Compose the listener (loopback for the lab, any address for a network server), TLS admission and the separate
//! device and bootstrap handlers. Tasks T219 and T230.

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crewcraft_admission::{Admission, Class, admit, server_config};
use crewcraft_proto::handshake::ServerSide;
use crewcraft_proto::signin::SignIn;
use crewcraft_server_core::durable::DurableServer;
use crewcraft_tls::{DeadlineSocket, Identity};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use crate::device_session::{self, AuthError, CommittedSignIn, DeviceAuth};
use crate::listener::Listener;

#[derive(Clone, Copy)]
pub struct Timeouts {
    pub handshake: Duration,
    /// One absolute budget through the initial credential check. A refusal uses the remaining budget.
    pub sign_in: Duration,
    /// A separate budget for each frame's I/O once authentication succeeds.
    pub signed_in_frame: Duration,
    /// One absolute budget for all bootstrap I/O.
    pub bootstrap: Duration,
}

pub struct LabOptions {
    pub address: SocketAddr,
    pub capacity: NonZeroUsize,
    pub timeouts: Timeouts,
    pub protocol: ServerSide,
}

/// The bootstrap adapter can read and write, using the connection's existing absolute deadline.
pub struct BootstrapStream {
    stream: StreamOwned<ServerConnection, DeadlineSocket>,
    deadline: Instant,
    peer: IpAddr,
}

impl BootstrapStream {
    /// The peer's IP address, read from the TCP socket before the TLS handshake, never from anything the peer sent.
    /// An IPv4 address that arrived on an IPv6 socket (`::ffff:a.b.c.d`) is given as the IPv4 address.
    pub fn peer_ip(&self) -> IpAddr {
        self.peer
    }

    fn check_deadline(&self) -> io::Result<()> {
        if Instant::now() < self.deadline { Ok(()) } else { Err(io::ErrorKind::TimedOut.into()) }
    }
}

impl Read for BootstrapStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.check_deadline()?;
        let received = self.stream.read(buf)?;
        self.check_deadline()?;
        Ok(received)
    }
}

impl Write for BootstrapStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check_deadline()?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check_deadline()?;
        self.stream.flush()
    }
}

pub struct LabServer {
    listener: Listener,
    timeouts: Timeouts,
    protocol: ServerSide,
    config: Arc<ServerConfig>,
    admission: Arc<dyn Admission>,
    rooms: Arc<Mutex<DurableServer>>,
    /// Where participants' WebRTC offers are relayed, when a media server is configured (task T360b6).
    relay: Option<Arc<dyn device_session::MediaRelay>>,
}

impl LabServer {
    /// Bind to loopback. The same policy controls the TLS verifier and the checks before application I/O.
    pub fn bind(
        options: LabOptions,
        identity: Identity,
        device_roots: RootCertStore,
        admission: Arc<dyn Admission>,
        rooms: DurableServer,
    ) -> io::Result<Self> {
        Self::bind_with(options, identity, device_roots, admission, rooms, Listener::bind)
    }

    /// Bind to any local address (task T230). Everything else is as `bind`: a peer gets application bytes only after
    /// the same TLS admission and checks.
    pub fn bind_network(
        options: LabOptions,
        identity: Identity,
        device_roots: RootCertStore,
        admission: Arc<dyn Admission>,
        rooms: DurableServer,
    ) -> io::Result<Self> {
        Self::bind_with(options, identity, device_roots, admission, rooms, Listener::bind_network)
    }

    fn bind_with(
        options: LabOptions,
        identity: Identity,
        device_roots: RootCertStore,
        admission: Arc<dyn Admission>,
        rooms: DurableServer,
        listen: fn(SocketAddr, NonZeroUsize) -> io::Result<Listener>,
    ) -> io::Result<Self> {
        let Timeouts { handshake, sign_in, signed_in_frame, bootstrap } = options.timeouts;
        if [handshake, sign_in, signed_in_frame, bootstrap].iter().any(|&timeout| timeout.is_zero() || cutoff(timeout).is_err()) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid connection deadline"));
        }
        let config = server_config(identity, device_roots, admission.clone()).map_err(io::Error::other)?;
        let listener = listen(options.address, options.capacity)?;
        Ok(Self { listener, timeouts: options.timeouts, protocol: options.protocol, config, admission, rooms: Arc::new(Mutex::new(rooms)), relay: None })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// The room journal the device sessions use, for changes made beside them (the control socket, task T238).
    pub(crate) fn rooms(&self) -> Arc<Mutex<DurableServer>> {
        self.rooms.clone()
    }

    /// Relay participants' WebRTC offers through `relay` (task T360b6).
    pub(crate) fn set_relay(&mut self, relay: Arc<dyn device_session::MediaRelay>) {
        self.relay = Some(relay);
    }

    /// The server supplies the trusted Unix clock (milliseconds). Device auth is bound to the verified leaf's DER.
    /// The bootstrap callback receives only the verified invitation key, on a separate stream with its own I/O limit.
    /// It must enforce live invitation and permitted calls before mutating enrollment state.
    /// A failed handshake, admission recheck, or device binding closes the socket without application bytes.
    pub fn serve<A: DeviceAuth>(
        self,
        shutdown: &AtomicBool,
        now_ms: impl Fn() -> u64 + Send + Sync + 'static,
        device_auth: impl Fn(&[u8], u64) -> Result<A, AuthError> + Send + Sync + 'static,
        bootstrap: impl Fn([u8; 32], &mut BootstrapStream) + Send + Sync + 'static,
    ) -> io::Result<()> {
        let Self { listener, timeouts, protocol, config, admission, rooms, relay } = self;
        listener.serve(shutdown, move |tcp: TcpStream| {
            // From the socket, before admission: nothing the peer sends can choose the address its limits count against.
            let Ok(peer) = tcp.peer_addr() else { return };
            let peer = peer.ip().to_canonical();
            let now_secs = || (now_ms() / 1000) as i64;
            let Ok(admitted) = admit(tcp, config.clone(), timeouts.handshake, &*admission, now_secs()) else { return };
            if admitted.recheck(&*admission, now_secs()).is_err() {
                return;
            }
            match admitted.class {
                Class::Device => {
                    let Ok(deadline) = cutoff(timeouts.sign_in) else { return };
                    let Ok(auth) = device_auth(admitted.certificate(), now_ms()) else { return };
                    if admitted.recheck(&*admission, now_secs()).is_err() {
                        return;
                    }
                    let auth = BeforeSignIn { inner: auth, deadline, signed_in: Cell::new(false) };
                    let mut stream = StreamOwned::new(admitted.stream.conn, DeadlineSocket::new(admitted.stream.sock, deadline));
                    let _ = device_session::serve_with_media(
                        &mut stream,
                        &auth,
                        &rooms,
                        relay.as_deref(),
                        protocol.clone(),
                        |stream| {
                            let deadline = if auth.signed_in.get() { cutoff(timeouts.signed_in_frame)? } else { auth.deadline };
                            stream.sock.set_deadline(deadline);
                            Ok(())
                        },
                        &now_ms,
                    );
                }
                Class::Bootstrap(public_key) => {
                    let Ok(deadline) = cutoff(timeouts.bootstrap) else { return };
                    let stream = StreamOwned::new(admitted.stream.conn, DeadlineSocket::new(admitted.stream.sock, deadline));
                    bootstrap(public_key, &mut BootstrapStream { stream, deadline, peer });
                }
            }
        })
    }
}

fn cutoff(timeout: Duration) -> io::Result<Instant> {
    Instant::now().checked_add(timeout).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid connection deadline"))
}

struct BeforeSignIn<A> {
    inner: A,
    deadline: Instant,
    signed_in: Cell<bool>,
}

impl<A: DeviceAuth> DeviceAuth for BeforeSignIn<A> {
    type Session = A::Session;

    fn device(&self) -> Option<u64> {
        self.inner.device()
    }

    fn revoked(&self) -> bool {
        self.inner.revoked()
    }

    fn sign_in(&self, credentials: SignIn<'_>, now_ms: u64) -> Result<Option<CommittedSignIn<Self::Session>>, AuthError> {
        if Instant::now() >= self.deadline {
            return Err(AuthError::Unavailable);
        }
        let result = self.inner.sign_in(credentials, now_ms)?;
        if Instant::now() >= self.deadline {
            return Err(AuthError::Unavailable);
        }
        self.signed_in.set(result.is_some());
        Ok(result)
    }

    fn resume(&self, token: &str, now_ms: u64) -> Result<Option<CommittedSignIn<Self::Session>>, AuthError> {
        if Instant::now() >= self.deadline {
            return Err(AuthError::Unavailable);
        }
        let result = self.inner.resume(token, now_ms)?;
        if Instant::now() >= self.deadline {
            return Err(AuthError::Unavailable);
        }
        self.signed_in.set(result.is_some());
        Ok(result)
    }

    fn end(&self, token: &str, now_ms: u64) -> Result<bool, AuthError> {
        if Instant::now() >= self.deadline {
            return Err(AuthError::Unavailable);
        }
        self.inner.end(token, now_ms)
    }

    // The external sign-in (task T611e) must be forwarded like the others: the trait's defaults refuse, so without
    // these a server with an identity provider would never offer it (found by the T611i end-to-end test).
    fn begin_external(&self, now_ms: u64) -> Result<Option<crate::external_signin::Start>, AuthError> {
        if Instant::now() >= self.deadline {
            return Err(AuthError::Unavailable);
        }
        self.inner.begin_external(now_ms)
    }

    fn finish_external(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        now_ms: u64,
    ) -> Result<Option<CommittedSignIn<Self::Session>>, AuthError> {
        if Instant::now() >= self.deadline {
            return Err(AuthError::Unavailable);
        }
        let result = self.inner.finish_external(code, verifier, redirect_uri, now_ms)?;
        if Instant::now() >= self.deadline {
            return Err(AuthError::Unavailable);
        }
        self.signed_in.set(result.is_some());
        Ok(result)
    }

    fn with_live_session<T>(&self, session: &Self::Session, now_ms: u64, action: impl FnOnce() -> T) -> Result<Option<T>, AuthError> {
        self.inner.with_live_session(session, now_ms, action)
    }
}
