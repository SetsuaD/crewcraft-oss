//! A TCP listener with a bounded number of active handlers: loopback-only for the lab (`bind`), any address for a
//! network server (`bind_network`, task T230).

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const IDLE_POLL: Duration = Duration::from_millis(10);

pub struct Listener {
    socket: TcpListener,
    capacity: NonZeroUsize,
}

impl Listener {
    /// Bind an IPv4 or IPv6 loopback address. Port zero lets the operating system choose a port.
    pub fn bind(address: SocketAddr, capacity: NonZeroUsize) -> io::Result<Self> {
        if !address.ip().is_loopback() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "listener address must be loopback"));
        }
        Self::bind_network(address, capacity)
    }

    /// Bind any local address, including every interface (`0.0.0.0`, or `::`, which on most systems also accepts
    /// IPv4). Port zero lets the operating system choose a port. The listener does not filter peers by address: only
    /// a peer that passes TLS admission ever receives application bytes.
    pub fn bind_network(address: SocketAddr, capacity: NonZeroUsize) -> io::Result<Self> {
        let socket = TcpListener::bind(address)?;
        socket.set_nonblocking(true)?;
        Ok(Self { socket, capacity })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Accept until `shutdown` becomes true or accepting a peer fails. At capacity,
    /// drop new sockets without writing to them. Join active handlers before returning.
    ///
    /// The handler receives a blocking socket and owns its handshake and application deadlines.
    pub fn serve<F>(self, shutdown: &AtomicBool, handler: F) -> io::Result<()>
    where
        F: Fn(TcpStream) + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        let mut workers = Vec::new();
        let outcome = self.accept_until(shutdown, &handler, &mut workers);
        drop(self.socket);
        for worker in workers {
            let _ = worker.join();
        }
        outcome
    }

    fn accept_until<F>(&self, shutdown: &AtomicBool, handler: &Arc<F>, workers: &mut Vec<JoinHandle<()>>) -> io::Result<()>
    where
        F: Fn(TcpStream) + Send + Sync + 'static,
    {
        while !shutdown.load(Ordering::Acquire) {
            match self.socket.accept() {
                Ok((peer, _)) => {
                    reap_finished(workers);
                    if workers.len() == self.capacity.get() || shutdown.load(Ordering::Acquire) {
                        continue;
                    }
                    let handler = Arc::clone(handler);
                    workers.push(thread::Builder::new().spawn(move || {
                        if peer.set_nonblocking(false).is_ok() {
                            handler(peer);
                        }
                    })?);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(IDLE_POLL),
                Err(error) if matches!(error.kind(), io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}

fn reap_finished(workers: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let _ = workers.swap_remove(index).join();
        } else {
            index += 1;
        }
    }
}
