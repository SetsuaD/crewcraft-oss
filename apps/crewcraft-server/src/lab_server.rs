//! Compose the loopback listener, TLS admission and the separate device and bootstrap handlers. Task T219.

use std::cell::Cell;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
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
}

impl BootstrapStream {
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
    rooms: Mutex<DurableServer>,
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
        let Timeouts { handshake, sign_in, signed_in_frame, bootstrap } = options.timeouts;
        if [handshake, sign_in, signed_in_frame, bootstrap].iter().any(|&timeout| timeout.is_zero() || cutoff(timeout).is_err()) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid connection deadline"));
        }
        let config = server_config(identity, device_roots, admission.clone()).map_err(io::Error::other)?;
        let listener = Listener::bind(options.address, options.capacity)?;
        Ok(Self { listener, timeouts: options.timeouts, protocol: options.protocol, config, admission, rooms: Mutex::new(rooms) })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
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
        let Self { listener, timeouts, protocol, config, admission, rooms } = self;
        listener.serve(shutdown, move |tcp: TcpStream| {
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
                    let _ = device_session::serve(
                        &mut stream,
                        &auth,
                        &rooms,
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
                    bootstrap(public_key, &mut BootstrapStream { stream, deadline });
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

    fn with_live_session<T>(&self, session: &Self::Session, now_ms: u64, action: impl FnOnce() -> T) -> Result<Option<T>, AuthError> {
        self.inner.with_live_session(session, now_ms, action)
    }
}
